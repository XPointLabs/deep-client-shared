using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.GroupV1;

public sealed class SqliteGroupFanoutStoreOptions : IDisposable
{
    private readonly byte[] key;
    private readonly object gate = new();
    private bool disposed;

    public SqliteGroupFanoutStoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        GroupStoreScope scope,
        bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(scope);
        if (encryptionKey.Length != 32 || encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        StatePath = Path.GetFullPath(statePath);
        key = encryptionKey.ToArray();
        Scope = scope;
        AllowCreate = allowCreate;
    }

    public string StatePath { get; }
    public GroupStoreScope Scope { get; }
    public bool AllowCreate { get; }

    internal void CopyKey(Span<byte> destination)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            key.CopyTo(destination);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            CryptographicOperations.ZeroMemory(key);
            disposed = true;
        }
    }
}

public sealed class SqliteGroupFanoutStore : IGroupFanoutStore, IDisposable
{
    private const int ApplicationId = 0x4752464A;
    private const int SchemaGeneration = 1;
    private const string Ddl = """
        CREATE TABLE fanout_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            account_id BLOB NOT NULL CHECK(length(account_id)=32),
            account_generation BLOB NOT NULL CHECK(length(account_generation)=8),
            store_generation INTEGER NOT NULL CHECK(store_generation=1));
        CREATE TABLE fanout_batches(
            batch_id BLOB PRIMARY KEY CHECK(length(batch_id)=32),
            transition_operation_id BLOB NOT NULL CHECK(length(transition_operation_id)=32),
            group_id BLOB NOT NULL CHECK(length(group_id)=32),
            package_hash BLOB NOT NULL CHECK(length(package_hash)=32),
            verified_package_hash BLOB NOT NULL CHECK(length(verified_package_hash)=32),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            member_count INTEGER NOT NULL CHECK(member_count BETWEEN 1 AND 100),
            verified_device_count INTEGER NOT NULL CHECK(verified_device_count BETWEEN 1 AND 500),
            target_count INTEGER NOT NULL CHECK(target_count BETWEEN 1 AND 500),
            conflict_latched INTEGER NOT NULL CHECK(conflict_latched IN (0,1)),
            staged_at INTEGER NOT NULL);
        CREATE TABLE fanout_targets(
            batch_id BLOB NOT NULL,
            target_id BLOB NOT NULL CHECK(length(target_id)=32),
            canonical_envelope BLOB NOT NULL CHECK(length(canonical_envelope) BETWEEN 1 AND 50705),
            current_attempt INTEGER NOT NULL CHECK(current_attempt BETWEEN 1 AND 2147483647),
            state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
            lease_owner BLOB NULL CHECK(lease_owner IS NULL OR length(lease_owner)=16),
            lease_generation BLOB NOT NULL CHECK(length(lease_generation)=8),
            lease_expires INTEGER NULL,
            PRIMARY KEY(batch_id,target_id),
            FOREIGN KEY(batch_id) REFERENCES fanout_batches(batch_id) ON DELETE CASCADE,
            CHECK((lease_owner IS NULL)=(lease_expires IS NULL)));
        CREATE TABLE fanout_attempts(
            batch_id BLOB NOT NULL,
            target_id BLOB NOT NULL,
            attempt_number INTEGER NOT NULL CHECK(attempt_number BETWEEN 1 AND 2147483647),
            network_operation_id BLOB NOT NULL CHECK(length(network_operation_id)=32),
            state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 6),
            released_lease_generation BLOB NULL CHECK(released_lease_generation IS NULL OR length(released_lease_generation)=8),
            last_outcome INTEGER NULL CHECK(last_outcome IS NULL OR last_outcome BETWEEN 1 AND 3),
            reject_rule INTEGER NULL CHECK(reject_rule IS NULL OR reject_rule BETWEEN 1 AND 2),
            next_network_operation_id BLOB NULL CHECK(next_network_operation_id IS NULL OR length(next_network_operation_id)=32),
            PRIMARY KEY(batch_id,target_id,attempt_number),
            UNIQUE(batch_id,network_operation_id),
            FOREIGN KEY(batch_id,target_id) REFERENCES fanout_targets(batch_id,target_id) ON DELETE CASCADE);
        CREATE INDEX fanout_ready ON fanout_targets(batch_id,state,lease_expires,target_id);
        """;

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key = new byte[32];
    private readonly string path;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteGroupFanoutStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteGroupFanoutStore(SqliteGroupFanoutStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Scope.StoreGeneration != GroupStoreScope.CurrentStoreGeneration)
            throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration, "Unsupported GroupV1 fanout store generation.");
        Scope = new GroupStoreScope(options.Scope.AccountId, options.Scope.AccountGeneration, options.Scope.StoreGeneration);
        path = options.StatePath;
        options.CopyKey(key);
        var exists = File.Exists(path);
        if (!exists && !options.AllowCreate)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey, "GroupV1 fanout database does not exist.");
        }
        if (exists && new FileInfo(path).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout database is empty.");
        }

        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

        try
        {
            using (var opened = Open())
            {
                if (exists) ValidateExisting(opened);
                else Create(opened);
            }
            ValidateEncryptedFile();
            connection = Open();
            ValidateAll(connection);
        }
        catch (GroupStateStoreOpenException)
        {
            FailedOpen();
            throw;
        }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            FailedOpen();
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey,
                "GroupV1 fanout SQLCipher state cannot be opened.", error);
        }
        catch
        {
            FailedOpen();
            throw;
        }
    }

    public GroupStoreScope Scope { get; }

    public async ValueTask<GroupFanoutStageResult> StageAsync(
        GroupFanoutBatchPlan plan,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(plan);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var existing = ReadBatchRow(db, tx, plan.BatchId);
            if (existing is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Fingerprint, plan.Fingerprint))
                {
                    using var latch = db.CreateCommand();
                    latch.Transaction = tx;
                    latch.CommandText = "UPDATE fanout_batches SET conflict_latched=1 WHERE batch_id=$batch;";
                    latch.Parameters.AddWithValue("$batch", plan.BatchId.ToArray());
                    latch.ExecuteNonQuery();
                    existing.ConflictLatched = true;
                }
                var disposition = existing.ConflictLatched
                    ? GroupFanoutStageDisposition.ConflictLatched
                    : GroupFanoutStageDisposition.Idempotent;
                var replay = ReadSnapshot(db, tx, plan.BatchId) ?? throw new FormatException("Fanout batch vanished.");
                tx.Commit();
                return new(disposition, replay);
            }

            InsertBatch(db, tx, plan);
            foreach (var target in plan.TargetRows.OrderBy(
                         static value => Convert.ToHexString(value.TargetId.Bytes.Span), StringComparer.Ordinal))
                InsertTarget(db, tx, plan.BatchId, target);
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = ReadSnapshot(db, tx, plan.BatchId) ?? throw new FormatException("Fanout batch was not stored.");
            tx.Commit();
            return new(GroupFanoutStageDisposition.Staged, snapshot);
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout staging failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutBatchSnapshot?> ReadAsync(
        GroupFanoutBatchId32 batchId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return ReadSnapshot(GetConnection(), null, batchId)?.Copy();
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "Persisted GroupV1 fanout state is invalid.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<IReadOnlyList<GroupFanoutDispatchLease>> ClaimReadyAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        int maximumTargets,
        CancellationToken cancellationToken = default)
    {
        GroupFanoutContractValidation.ValidateClaim(batchId, leaseOwner, now, leaseDuration, maximumTargets);
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        var until = GroupFanoutBatchPlan.CanonicalTime(now + leaseDuration);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var batch = ReadBatchRow(db, tx, batchId);
            if (batch is null || batch.ConflictLatched)
            {
                tx.Commit();
                return [];
            }

            Recover(db, tx, batchId, now);
            var result = ReadOwnedLeases(db, tx, batchId, leaseOwner, maximumTargets);
            var active = CountActiveLeases(db, tx, batchId);
            var available = Math.Min(maximumTargets - result.Count,
                GroupFanoutLimits.MaximumConcurrentLeases - active);
            if (available <= 0)
            {
                tx.Commit();
                return result;
            }

            using var query = db.CreateCommand();
            query.Transaction = tx;
            query.CommandText = """
                SELECT target_id,current_attempt,state,lease_generation
                FROM fanout_targets
                WHERE batch_id=$batch AND state IN (1,3) AND lease_owner IS NULL
                ORDER BY target_id LIMIT $limit;
                """;
            query.Parameters.AddWithValue("$batch", batchId.ToArray());
            query.Parameters.AddWithValue("$limit", available);
            using var reader = query.ExecuteReader();
            var selected = new List<(byte[] TargetId, uint Attempt, bool Unknown, ulong Generation)>();
            while (reader.Read())
                selected.Add(((byte[])reader[0], checked((uint)reader.GetInt64(1)),
                    reader.GetInt32(2) == (int)GroupFanoutTargetState.OutcomeUnknown,
                    ReadU64((byte[])reader[3])));
            reader.Close();

            foreach (var selectedTarget in selected)
            {
                var generation = checked(selectedTarget.Generation + 1);
                using var update = db.CreateCommand();
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_targets
                    SET lease_owner=$owner,lease_generation=$generation,lease_expires=$expires
                    WHERE batch_id=$batch AND target_id=$target AND lease_owner IS NULL AND state IN (1,3);
                    """;
                update.Parameters.AddWithValue("$owner", leaseOwner.ToArray());
                update.Parameters.AddWithValue("$generation", U64(generation));
                update.Parameters.AddWithValue("$expires", until.ToUnixTimeMilliseconds());
                update.Parameters.AddWithValue("$batch", batchId.ToArray());
                update.Parameters.AddWithValue("$target", selectedTarget.TargetId);
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout lease CAS failed.");
                result.Add(new(
                    Scope,
                    batchId,
                    GroupFanoutTargetId32.FromOpaqueBytes(selectedTarget.TargetId),
                    selectedTarget.Attempt,
                    leaseOwner,
                    generation,
                    until,
                    selectedTarget.Unknown));
            }

            cancellationToken.ThrowIfCancellationRequested();
            tx.Commit();
            return result;
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout claim failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutNetworkWorkResult> BeginNetworkWorkAsync(
        GroupFanoutDispatchLease lease,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateScope(lease.Scope, nameof(lease));
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            Recover(db, tx, lease.BatchId, now);
            var row = ReadTargetRow(db, tx, lease.BatchId, lease.TargetId);
            if (row is null) return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.NotFound, null));
            if (row.BatchConflict) return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.ConflictLatched, null));
            var attempt = ReadAttemptRow(db, tx, lease.BatchId, lease.TargetId, lease.AttemptNumber);
            if (attempt is null) return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.LeaseLost, null));
            if (row.State == GroupFanoutTargetState.RevokedBeforeSend)
                return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.RevokedBeforeSend, null));
            if (row.State is GroupFanoutTargetState.Accepted or GroupFanoutTargetState.DefiniteRejected)
                return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.AlreadyTerminal, null));
            if (row.State == GroupFanoutTargetState.NetworkWorkReleased
                && attempt.ReleasedLeaseGeneration == lease.LeaseGeneration
                && LeaseMatches(row, lease))
                return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.Idempotent, Work(lease, row, attempt)));
            if (!LeaseMatches(row, lease))
                return Finish(tx, new GroupFanoutNetworkWorkResult(GroupFanoutMutationDisposition.LeaseLost, null));

            using (var update = db.CreateCommand())
            {
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_targets SET state=2
                    WHERE batch_id=$batch AND target_id=$target AND current_attempt=$attempt
                      AND lease_owner=$owner AND lease_generation=$generation AND state IN (1,3);
                    """;
                BindLease(update, lease);
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout release CAS failed.");
            }
            using (var update = db.CreateCommand())
            {
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_attempts SET state=2,released_lease_generation=$generation
                    WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
                    """;
                BindLease(update, lease);
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout attempt release failed.");
            }
            attempt.State = GroupFanoutTargetState.NetworkWorkReleased;
            attempt.ReleasedLeaseGeneration = lease.LeaseGeneration;
            cancellationToken.ThrowIfCancellationRequested();
            tx.Commit();
            return new(GroupFanoutMutationDisposition.Applied, Work(lease, row, attempt));
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 network-work fence failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutMutationDisposition> RecordOutcomeAsync(
        GroupFanoutNetworkWork work,
        GroupFanoutAttemptOutcome outcome,
        GroupFanoutDefiniteRejectRule rejectRule = GroupFanoutDefiniteRejectRule.Terminal,
        GroupFanoutNetworkOperationId32? nextNetworkOperationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(work);
        var lease = work.Lease;
        ValidateScope(lease.Scope, nameof(work));
        GroupFanoutContractValidation.ValidateOutcome(outcome, rejectRule, nextNetworkOperationId, work);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var row = ReadTargetRow(db, tx, lease.BatchId, lease.TargetId);
            if (row is null) return Finish(tx, GroupFanoutMutationDisposition.NotFound);
            if (row.BatchConflict) return Finish(tx, GroupFanoutMutationDisposition.ConflictLatched);
            var attempt = ReadAttemptRow(db, tx, lease.BatchId, lease.TargetId, lease.AttemptNumber);
            if (attempt is null
                || !attempt.NetworkOperationId.AsSpan().SequenceEqual(work.NetworkOperationId.Span)
                || !row.Envelope.AsSpan().SequenceEqual(work.EnvelopeSpan))
                return Finish(tx, GroupFanoutMutationDisposition.LeaseLost);
            var canRecordReleasedAttempt = row.CurrentAttempt == lease.AttemptNumber
                && attempt.ReleasedLeaseGeneration is not null
                && lease.LeaseGeneration <= attempt.ReleasedLeaseGeneration
                && row.State is GroupFanoutTargetState.NetworkWorkReleased
                    or GroupFanoutTargetState.OutcomeUnknown;

            if (attempt.LastOutcome == outcome
                && attempt.RejectRule == rejectRule
                && Equal(attempt.NextNetworkOperationId, nextNetworkOperationId))
            {
                if (outcome == GroupFanoutAttemptOutcome.OutcomeUnknown
                    && row.State == GroupFanoutTargetState.NetworkWorkReleased
                    && canRecordReleasedAttempt)
                {
                    ApplyOutcomeUnknown(db, tx, lease);
                    tx.Commit();
                    return GroupFanoutMutationDisposition.Applied;
                }
                return Finish(tx, GroupFanoutMutationDisposition.Idempotent);
            }

            if (attempt.LastOutcome is GroupFanoutAttemptOutcome.Accepted
                or GroupFanoutAttemptOutcome.DefiniteRejected)
            {
                if (outcome == GroupFanoutAttemptOutcome.OutcomeUnknown)
                    return Finish(tx, GroupFanoutMutationDisposition.AlreadyTerminal);
                LatchConflict(db, tx, lease.BatchId);
                tx.Commit();
                return GroupFanoutMutationDisposition.ConflictLatched;
            }
            if (!canRecordReleasedAttempt)
                return Finish(tx, GroupFanoutMutationDisposition.LeaseLost);

            switch (outcome)
            {
                case GroupFanoutAttemptOutcome.OutcomeUnknown:
                    ApplyOutcomeUnknown(db, tx, lease);
                    break;
                case GroupFanoutAttemptOutcome.Accepted:
                    ApplyTerminal(db, tx, lease, GroupFanoutTargetState.Accepted,
                        outcome, rejectRule, null);
                    break;
                case GroupFanoutAttemptOutcome.DefiniteRejected
                    when rejectRule == GroupFanoutDefiniteRejectRule.Terminal:
                    ApplyTerminal(db, tx, lease, GroupFanoutTargetState.DefiniteRejected,
                        outcome, rejectRule, null);
                    break;
                case GroupFanoutAttemptOutcome.DefiniteRejected:
                    if (OperationExists(db, tx, lease.BatchId, nextNetworkOperationId!))
                    {
                        LatchConflict(db, tx, lease.BatchId);
                        tx.Commit();
                        return GroupFanoutMutationDisposition.ConflictLatched;
                    }
                    ApplyRejectedRetry(db, tx, lease, nextNetworkOperationId!);
                    break;
                default:
                    throw new InvalidOperationException("Unsupported GroupV1 fanout outcome.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            tx.Commit();
            return GroupFanoutMutationDisposition.Applied;
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout outcome transaction failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutMutationDisposition> RevokeBeforeSendAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(targetId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var row = ReadTargetRow(db, tx, batchId, targetId);
            if (row is null) return Finish(tx, GroupFanoutMutationDisposition.NotFound);
            if (row.BatchConflict) return Finish(tx, GroupFanoutMutationDisposition.ConflictLatched);
            if (row.State == GroupFanoutTargetState.RevokedBeforeSend)
                return Finish(tx, GroupFanoutMutationDisposition.Idempotent);
            if (row.State is GroupFanoutTargetState.NetworkWorkReleased or GroupFanoutTargetState.OutcomeUnknown)
                return Finish(tx, GroupFanoutMutationDisposition.MayHaveForwarded);
            if (row.State is GroupFanoutTargetState.Accepted or GroupFanoutTargetState.DefiniteRejected)
                return Finish(tx, GroupFanoutMutationDisposition.AlreadyTerminal);

            using (var update = db.CreateCommand())
            {
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_targets SET state=6,lease_owner=NULL,lease_expires=NULL
                    WHERE batch_id=$batch AND target_id=$target AND state=1;
                    """;
                update.Parameters.AddWithValue("$batch", batchId.ToArray());
                update.Parameters.AddWithValue("$target", targetId.ToArray());
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout revoke fence CAS failed.");
            }
            using (var update = db.CreateCommand())
            {
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_attempts SET state=6
                    WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
                    """;
                update.Parameters.AddWithValue("$batch", batchId.ToArray());
                update.Parameters.AddWithValue("$target", targetId.ToArray());
                update.Parameters.AddWithValue("$attempt", row.CurrentAttempt);
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout revoked attempt is absent.");
            }
            tx.Commit();
            return GroupFanoutMutationDisposition.Applied;
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout revoke transaction failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutRecoveryResult> RecoverStaleLeasesAsync(
        GroupFanoutBatchId32 batchId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var result = Recover(db, tx, batchId, now);
            tx.Commit();
            return result;
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 stale lease recovery failed closed.", error);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        gate.Wait();
        try
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            connection?.Dispose();
            connection = null;
            CryptographicOperations.ZeroMemory(key);
        }
        finally
        {
            gate.Release();
        }
    }

    private void ValidatePlan(GroupFanoutBatchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ValidateScope(plan.Scope, nameof(plan));
    }

    private void ValidateScope(GroupStoreScope scope, string parameter)
    {
        if (!Scope.Equals(scope))
            throw new ArgumentException("Fanout operation belongs to another account store scope.", parameter);
    }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try
        {
            db.Open();
            var result = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected key.", result);
            Execute(db, null, "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;");
            return db;
        }
        catch
        {
            db.Dispose();
            throw;
        }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        using var tx = db.BeginTransaction(deferred: false);
        Execute(db, tx, Ddl);
        using var insert = db.CreateCommand();
        insert.Transaction = tx;
        insert.CommandText = "INSERT INTO fanout_meta VALUES(1,$account,$accountGeneration,$storeGeneration);";
        insert.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray());
        insert.Parameters.AddWithValue("$accountGeneration", U64(Scope.AccountGeneration));
        insert.Parameters.AddWithValue("$storeGeneration", Scope.StoreGeneration);
        insert.ExecuteNonQuery();
        tx.Commit();
        ValidateCipher(db);
    }

    private void ValidateExisting(SqliteConnection db)
    {
        try
        {
            if (Scalar(db, "PRAGMA application_id;") != ApplicationId
                || Scalar(db, "PRAGMA user_version;") != SchemaGeneration)
                throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration, "Unsupported GroupV1 fanout schema.");
            ValidateCipher(db);
            using var query = db.CreateCommand();
            query.CommandText = "SELECT account_id,account_generation,store_generation FROM fanout_meta WHERE singleton=1;";
            using var reader = query.ExecuteReader();
            if (!reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout scope metadata is absent.");
            var account = (byte[])reader[0];
            var generation = ReadU64((byte[])reader[1]);
            var storeGeneration = reader.GetInt32(2);
            if (reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout scope metadata is duplicated.");
            if (!Scope.AccountId.Matches(account) || generation != Scope.AccountGeneration
                || storeGeneration != Scope.StoreGeneration)
                throw Failure(GroupStateStoreOpenFailure.ScopeMismatch,
                    "GroupV1 fanout database belongs to another account generation.");
            ValidateAll(db);
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (SqliteException error)
        {
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey,
                "GroupV1 fanout metadata is unreadable.", error);
        }
        catch (Exception error) when (error is FormatException or ArgumentException
            or InvalidOperationException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt,
                "GroupV1 fanout state violates its sealed contract.", error);
        }
    }

    private void ValidateAll(SqliteConnection db)
    {
        using var query = db.CreateCommand();
        query.CommandText = "SELECT batch_id FROM fanout_batches ORDER BY batch_id;";
        using var reader = query.ExecuteReader();
        var batches = new List<GroupFanoutBatchId32>();
        while (reader.Read()) batches.Add(GroupFanoutBatchId32.FromBytes((byte[])reader[0]));
        reader.Close();
        foreach (var batch in batches)
            _ = ReadSnapshot(db, null, batch) ?? throw new FormatException("Fanout batch vanished during validation.");
    }

    private GroupFanoutBatchSnapshot? ReadSnapshot(
        SqliteConnection db,
        SqliteTransaction? tx,
        GroupFanoutBatchId32 batchId)
    {
        var batch = ReadBatchRow(db, tx, batchId);
        if (batch is null) return null;
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT target_id,canonical_envelope,current_attempt,state,lease_owner,lease_generation,lease_expires
            FROM fanout_targets WHERE batch_id=$batch ORDER BY target_id;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        using var reader = query.ExecuteReader();
        var rows = new List<TargetRow>();
        while (reader.Read()) rows.Add(ReadTarget(reader, batch.ConflictLatched));
        reader.Close();
        if (rows.Count != batch.TargetCount) throw new FormatException("Fanout target count is inconsistent.");

        var snapshots = new List<GroupFanoutTargetSnapshot>(rows.Count);
        var fingerprintTargets = new List<GroupFanoutTargetEnvelope>(rows.Count);
        foreach (var row in rows)
        {
            var attempts = ReadAttempts(db, tx, batchId, GroupFanoutTargetId32.FromOpaqueBytes(row.TargetId));
            ValidateTarget(row, attempts);
            fingerprintTargets.Add(new(
                GroupFanoutTargetId32.FromOpaqueBytes(row.TargetId),
                GroupFanoutNetworkOperationId32.FromBytes(attempts[0].NetworkOperationId),
                row.Envelope));
            snapshots.Add(new(
                GroupFanoutTargetId32.FromOpaqueBytes(row.TargetId),
                row.State,
                row.CurrentAttempt,
                row.LeaseOwner is null ? null : GroupFanoutLeaseOwnerId16.FromBytes(row.LeaseOwner),
                row.LeaseGeneration,
                row.LeaseExpires,
                attempts.Select(static attempt => new GroupFanoutAttemptSnapshot(
                    attempt.Number,
                    attempt.State,
                    attempt.NextNetworkOperationId is not null))));
        }

        var computed = GroupFanoutBatchPlan.ComputeFingerprint(
            Scope,
            batchId,
            GroupOperationId32.FromBytes(batch.TransitionOperationId),
            GroupId32.FromBytes(batch.GroupId),
            batch.PackageHash,
            batch.VerifiedPackageHash,
            batch.MemberCount,
            batch.VerifiedDeviceCount,
            fingerprintTargets);
        if (!CryptographicOperations.FixedTimeEquals(computed, batch.Fingerprint))
            throw new FormatException("Fanout batch fingerprint does not bind its exact target set.");

        return new(
            Scope,
            batchId,
            GroupOperationId32.FromBytes(batch.TransitionOperationId),
            GroupId32.FromBytes(batch.GroupId),
            batch.MemberCount,
            batch.VerifiedDeviceCount,
            batch.ConflictLatched,
            batch.StagedAt,
            snapshots);
    }

    private static void ValidateTarget(TargetRow row, IReadOnlyList<AttemptRow> attempts)
    {
        if (attempts.Count == 0 || attempts.Count != row.CurrentAttempt) throw new FormatException("Fanout attempt sequence has a gap.");
        for (var index = 0; index < attempts.Count; index++)
            if (attempts[index].Number != checked((uint)index + 1)) throw new FormatException("Fanout attempts are not contiguous.");
        var current = attempts[^1];
        if (current.State != row.State) throw new FormatException("Fanout target and current attempt states differ.");
        if ((row.LeaseOwner is null) != (row.LeaseExpires is null)) throw new FormatException("Fanout lease is incomplete.");
        if (row.State is GroupFanoutTargetState.Accepted
            or GroupFanoutTargetState.DefiniteRejected
            or GroupFanoutTargetState.RevokedBeforeSend
            && row.LeaseOwner is not null)
            throw new FormatException("Terminal fanout target retains a lease.");
        foreach (var attempt in attempts)
        {
            if ((attempt.LastOutcome is null) != (attempt.RejectRule is null))
                throw new FormatException("Fanout attempt outcome policy is incomplete.");
            if ((attempt.NextNetworkOperationId is not null)
                != (attempt.LastOutcome == GroupFanoutAttemptOutcome.DefiniteRejected
                    && attempt.RejectRule == GroupFanoutDefiniteRejectRule.RetryWithNewOperation))
                throw new FormatException("Fanout retry identity is not exactly authorized.");
        }
    }

    private static BatchRow? ReadBatchRow(
        SqliteConnection db,
        SqliteTransaction? tx,
        GroupFanoutBatchId32 batchId)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT transition_operation_id,group_id,package_hash,verified_package_hash,fingerprint,
                   member_count,verified_device_count,target_count,conflict_latched,staged_at
            FROM fanout_batches WHERE batch_id=$batch;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        using var reader = query.ExecuteReader();
        if (!reader.Read()) return null;
        var result = new BatchRow(
            (byte[])reader[0], (byte[])reader[1], (byte[])reader[2], (byte[])reader[3], (byte[])reader[4],
            checked((ushort)reader.GetInt32(5)), checked((ushort)reader.GetInt32(6)), reader.GetInt32(7),
            reader.GetInt32(8) == 1, DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(9)));
        if (reader.Read()) throw new FormatException("Duplicate fanout batch.");
        _ = GroupOperationId32.FromBytes(result.TransitionOperationId);
        _ = GroupId32.FromBytes(result.GroupId);
        ValidateHash(result.PackageHash);
        ValidateHash(result.VerifiedPackageHash);
        ValidateHash(result.Fingerprint);
        return result;
    }

    private static TargetRow? ReadTargetRow(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT t.target_id,t.canonical_envelope,t.current_attempt,t.state,t.lease_owner,
                   t.lease_generation,t.lease_expires,b.conflict_latched
            FROM fanout_targets t JOIN fanout_batches b ON b.batch_id=t.batch_id
            WHERE t.batch_id=$batch AND t.target_id=$target;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$target", targetId.ToArray());
        using var reader = query.ExecuteReader();
        if (!reader.Read()) return null;
        var result = ReadTarget(reader, reader.GetInt32(7) == 1);
        if (reader.Read()) throw new FormatException("Duplicate fanout target.");
        return result;
    }

    private static TargetRow ReadTarget(SqliteDataReader reader, bool batchConflict)
    {
        var target = (byte[])reader[0];
        var envelope = (byte[])reader[1];
        var attempt = checked((uint)reader.GetInt64(2));
        var state = (GroupFanoutTargetState)reader.GetInt32(3);
        var owner = reader.IsDBNull(4) ? null : (byte[])reader[4];
        var generation = ReadU64((byte[])reader[5]);
        DateTimeOffset? expires = reader.IsDBNull(6)
            ? null
            : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(6));
        _ = GroupFanoutTargetId32.FromOpaqueBytes(target);
        if (envelope.Length is < 1 or > GroupFanoutLimits.MaximumCanonicalEnvelopeBytes || !Enum.IsDefined(state))
            throw new FormatException("Invalid fanout target row.");
        if (owner is not null) _ = GroupFanoutLeaseOwnerId16.FromBytes(owner);
        return new(target, envelope, attempt, state, owner, generation, expires, batchConflict);
    }

    private static List<AttemptRow> ReadAttempts(
        SqliteConnection db,
        SqliteTransaction? tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT attempt_number,network_operation_id,state,released_lease_generation,last_outcome,
                   reject_rule,next_network_operation_id
            FROM fanout_attempts WHERE batch_id=$batch AND target_id=$target ORDER BY attempt_number;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$target", targetId.ToArray());
        using var reader = query.ExecuteReader();
        var result = new List<AttemptRow>();
        while (reader.Read()) result.Add(ReadAttempt(reader));
        return result;
    }

    private static AttemptRow? ReadAttemptRow(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId,
        uint attemptNumber)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT attempt_number,network_operation_id,state,released_lease_generation,last_outcome,
                   reject_rule,next_network_operation_id
            FROM fanout_attempts WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$target", targetId.ToArray());
        query.Parameters.AddWithValue("$attempt", attemptNumber);
        using var reader = query.ExecuteReader();
        if (!reader.Read()) return null;
        var result = ReadAttempt(reader);
        if (reader.Read()) throw new FormatException("Duplicate fanout attempt.");
        return result;
    }

    private static AttemptRow ReadAttempt(SqliteDataReader reader)
    {
        var result = new AttemptRow(
            checked((uint)reader.GetInt64(0)),
            (byte[])reader[1],
            (GroupFanoutTargetState)reader.GetInt32(2),
            reader.IsDBNull(3) ? null : ReadU64((byte[])reader[3]),
            reader.IsDBNull(4) ? null : (GroupFanoutAttemptOutcome)reader.GetInt32(4),
            reader.IsDBNull(5) ? null : (GroupFanoutDefiniteRejectRule)reader.GetInt32(5),
            reader.IsDBNull(6) ? null : (byte[])reader[6]);
        _ = GroupFanoutNetworkOperationId32.FromBytes(result.NetworkOperationId);
        if (!Enum.IsDefined(result.State)
            || result.LastOutcome is not null && !Enum.IsDefined(result.LastOutcome.Value)
            || result.RejectRule is not null && !Enum.IsDefined(result.RejectRule.Value))
            throw new FormatException("Invalid fanout attempt row.");
        if (result.NextNetworkOperationId is not null)
            _ = GroupFanoutNetworkOperationId32.FromBytes(result.NextNetworkOperationId);
        return result;
    }

    private static GroupFanoutRecoveryResult Recover(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        DateTimeOffset now)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT target_id,current_attempt,state FROM fanout_targets
            WHERE batch_id=$batch AND lease_owner IS NOT NULL AND lease_expires<=$now;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$now", now.ToUnixTimeMilliseconds());
        using var reader = query.ExecuteReader();
        var stale = new List<(byte[] Target, uint Attempt, GroupFanoutTargetState State)>();
        while (reader.Read()) stale.Add(((byte[])reader[0], checked((uint)reader.GetInt64(1)),
            (GroupFanoutTargetState)reader.GetInt32(2)));
        reader.Close();
        var before = 0;
        var unknown = 0;
        foreach (var item in stale)
        {
            var promoted = item.State == GroupFanoutTargetState.NetworkWorkReleased;
            using (var update = db.CreateCommand())
            {
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_targets SET state=$state,lease_owner=NULL,lease_expires=NULL
                    WHERE batch_id=$batch AND target_id=$target;
                    """;
                update.Parameters.AddWithValue("$state", promoted
                    ? (int)GroupFanoutTargetState.OutcomeUnknown
                    : (int)item.State);
                update.Parameters.AddWithValue("$batch", batchId.ToArray());
                update.Parameters.AddWithValue("$target", item.Target);
                update.ExecuteNonQuery();
            }
            if (promoted)
            {
                using var update = db.CreateCommand();
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE fanout_attempts SET state=3,last_outcome=1,reject_rule=1
                    WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
                    """;
                update.Parameters.AddWithValue("$batch", batchId.ToArray());
                update.Parameters.AddWithValue("$target", item.Target);
                update.Parameters.AddWithValue("$attempt", item.Attempt);
                update.ExecuteNonQuery();
                unknown++;
            }
            else
            {
                before++;
            }
        }
        return new(before, unknown);
    }

    private static int CountActiveLeases(SqliteConnection db, SqliteTransaction tx, GroupFanoutBatchId32 batchId)
    {
        using var command = db.CreateCommand();
        command.Transaction = tx;
        command.CommandText = "SELECT COUNT(*) FROM fanout_targets WHERE batch_id=$batch AND lease_owner IS NOT NULL;";
        command.Parameters.AddWithValue("$batch", batchId.ToArray());
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private List<GroupFanoutDispatchLease> ReadOwnedLeases(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        int maximumTargets)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = """
            SELECT target_id,current_attempt,state,lease_generation,lease_expires
            FROM fanout_targets
            WHERE batch_id=$batch AND lease_owner=$owner AND state IN (1,3)
            ORDER BY target_id LIMIT $limit;
            """;
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$owner", leaseOwner.ToArray());
        query.Parameters.AddWithValue("$limit", maximumTargets);
        using var reader = query.ExecuteReader();
        var result = new List<GroupFanoutDispatchLease>();
        while (reader.Read())
        {
            result.Add(new(
                Scope,
                batchId,
                GroupFanoutTargetId32.FromOpaqueBytes((byte[])reader[0]),
                checked((uint)reader.GetInt64(1)),
                leaseOwner,
                ReadU64((byte[])reader[3]),
                DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(4)),
                reader.GetInt32(2) == (int)GroupFanoutTargetState.OutcomeUnknown));
        }
        return result;
    }

    private static void InsertBatch(SqliteConnection db, SqliteTransaction tx, GroupFanoutBatchPlan plan)
    {
        using var insert = db.CreateCommand();
        insert.Transaction = tx;
        insert.CommandText = """
            INSERT INTO fanout_batches VALUES(
                $batch,$operation,$group,$package,$verified,$fingerprint,$members,$devices,$targets,0,$staged);
            """;
        insert.Parameters.AddWithValue("$batch", plan.BatchId.ToArray());
        insert.Parameters.AddWithValue("$operation", plan.TransitionOperationId.ToArray());
        insert.Parameters.AddWithValue("$group", plan.GroupId.ToArray());
        insert.Parameters.AddWithValue("$package", plan.PackageHash.ToArray());
        insert.Parameters.AddWithValue("$verified", plan.VerifiedPackageHash.ToArray());
        insert.Parameters.AddWithValue("$fingerprint", plan.Fingerprint.ToArray());
        insert.Parameters.AddWithValue("$members", plan.MemberCount);
        insert.Parameters.AddWithValue("$devices", plan.VerifiedDeviceCount);
        insert.Parameters.AddWithValue("$targets", plan.TargetRows.Count);
        insert.Parameters.AddWithValue("$staged", plan.StagedAt.ToUnixTimeMilliseconds());
        if (insert.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout batch insert failed.");
    }

    private static void InsertTarget(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetEnvelope target)
    {
        using (var insert = db.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = "INSERT INTO fanout_targets VALUES($batch,$target,$envelope,1,1,NULL,$generation,NULL);";
            insert.Parameters.AddWithValue("$batch", batchId.ToArray());
            insert.Parameters.AddWithValue("$target", target.TargetId.ToArray());
            insert.Parameters.AddWithValue("$envelope", target.ExactCanonicalEnvelope.ToArray());
            insert.Parameters.AddWithValue("$generation", U64(0));
            if (insert.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout target insert failed.");
        }
        using (var insert = db.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = "INSERT INTO fanout_attempts VALUES($batch,$target,1,$operation,1,NULL,NULL,NULL,NULL);";
            insert.Parameters.AddWithValue("$batch", batchId.ToArray());
            insert.Parameters.AddWithValue("$target", target.TargetId.ToArray());
            insert.Parameters.AddWithValue("$operation", target.InitialNetworkOperationId.ToArray());
            if (insert.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout attempt insert failed.");
        }
    }

    private static void ApplyOutcomeUnknown(SqliteConnection db, SqliteTransaction tx, GroupFanoutDispatchLease lease)
    {
        UpdateTargetState(db, tx, lease, GroupFanoutTargetState.OutcomeUnknown, clearLease: true);
        using var update = db.CreateCommand();
        update.Transaction = tx;
        update.CommandText = """
            UPDATE fanout_attempts SET state=3,last_outcome=1,reject_rule=1,next_network_operation_id=NULL
            WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
            """;
        BindLease(update, lease);
        if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout unknown outcome update failed.");
    }

    private static void ApplyTerminal(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutDispatchLease lease,
        GroupFanoutTargetState state,
        GroupFanoutAttemptOutcome outcome,
        GroupFanoutDefiniteRejectRule rule,
        GroupFanoutNetworkOperationId32? next)
    {
        UpdateTargetState(db, tx, lease, state, clearLease: true);
        using var update = db.CreateCommand();
        update.Transaction = tx;
        update.CommandText = """
            UPDATE fanout_attempts SET state=$state,last_outcome=$outcome,reject_rule=$rule,
                next_network_operation_id=$next
            WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
            """;
        BindLease(update, lease);
        update.Parameters.AddWithValue("$state", (int)state);
        update.Parameters.AddWithValue("$outcome", (int)outcome);
        update.Parameters.AddWithValue("$rule", (int)rule);
        update.Parameters.AddWithValue("$next", next is null ? DBNull.Value : next.ToArray());
        if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout terminal outcome update failed.");
    }

    private static void ApplyRejectedRetry(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutDispatchLease lease,
        GroupFanoutNetworkOperationId32 next)
    {
        var nextAttempt = checked(lease.AttemptNumber + 1);
        using (var old = db.CreateCommand())
        {
            old.Transaction = tx;
            old.CommandText = """
                UPDATE fanout_attempts SET state=5,last_outcome=3,reject_rule=2,next_network_operation_id=$next
                WHERE batch_id=$batch AND target_id=$target AND attempt_number=$attempt;
                """;
            BindLease(old, lease);
            old.Parameters.AddWithValue("$next", next.ToArray());
            if (old.ExecuteNonQuery() != 1) throw new InvalidOperationException("Rejected fanout attempt update failed.");
        }
        using (var insert = db.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = "INSERT INTO fanout_attempts VALUES($batch,$target,$attempt,$operation,1,NULL,NULL,NULL,NULL);";
            insert.Parameters.AddWithValue("$batch", lease.BatchId.ToArray());
            insert.Parameters.AddWithValue("$target", lease.TargetId.ToArray());
            insert.Parameters.AddWithValue("$attempt", nextAttempt);
            insert.Parameters.AddWithValue("$operation", next.ToArray());
            insert.ExecuteNonQuery();
        }
        using (var target = db.CreateCommand())
        {
            target.Transaction = tx;
            target.CommandText = """
                UPDATE fanout_targets SET current_attempt=$nextAttempt,state=1,lease_owner=NULL,lease_expires=NULL
                WHERE batch_id=$batch AND target_id=$target AND current_attempt=$attempt;
                """;
            BindLease(target, lease);
            target.Parameters.AddWithValue("$nextAttempt", nextAttempt);
            if (target.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout retry activation failed.");
        }
    }

    private static void UpdateTargetState(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutDispatchLease lease,
        GroupFanoutTargetState state,
        bool clearLease)
    {
        using var update = db.CreateCommand();
        update.Transaction = tx;
        update.CommandText = clearLease
            ? "UPDATE fanout_targets SET state=$state,lease_owner=NULL,lease_expires=NULL WHERE batch_id=$batch AND target_id=$target AND current_attempt=$attempt;"
            : "UPDATE fanout_targets SET state=$state WHERE batch_id=$batch AND target_id=$target AND current_attempt=$attempt;";
        BindLease(update, lease);
        update.Parameters.AddWithValue("$state", (int)state);
        if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout target state update failed.");
    }

    private static void BindLease(SqliteCommand command, GroupFanoutDispatchLease lease)
    {
        command.Parameters.AddWithValue("$batch", lease.BatchId.ToArray());
        command.Parameters.AddWithValue("$target", lease.TargetId.ToArray());
        command.Parameters.AddWithValue("$attempt", lease.AttemptNumber);
        command.Parameters.AddWithValue("$owner", lease.LeaseOwner.ToArray());
        command.Parameters.AddWithValue("$generation", U64(lease.LeaseGeneration));
    }

    private static bool LeaseMatches(TargetRow row, GroupFanoutDispatchLease lease) =>
        row.CurrentAttempt == lease.AttemptNumber
        && row.LeaseOwner is not null
        && row.LeaseOwner.AsSpan().SequenceEqual(lease.LeaseOwner.Span)
        && row.LeaseGeneration == lease.LeaseGeneration;

    private static GroupFanoutNetworkWork Work(
        GroupFanoutDispatchLease lease,
        TargetRow target,
        AttemptRow attempt) =>
        new(lease, GroupFanoutNetworkOperationId32.FromBytes(attempt.NetworkOperationId), target.Envelope);

    private static bool Equal(byte[]? stored, GroupFanoutNetworkOperationId32? supplied) =>
        (stored is null) == (supplied is null)
        && (stored is null || stored.AsSpan().SequenceEqual(supplied!.Span));

    private static bool OperationExists(
        SqliteConnection db,
        SqliteTransaction tx,
        GroupFanoutBatchId32 batchId,
        GroupFanoutNetworkOperationId32 operationId)
    {
        using var query = db.CreateCommand();
        query.Transaction = tx;
        query.CommandText = "SELECT 1 FROM fanout_attempts WHERE batch_id=$batch AND network_operation_id=$operation LIMIT 1;";
        query.Parameters.AddWithValue("$batch", batchId.ToArray());
        query.Parameters.AddWithValue("$operation", operationId.ToArray());
        return query.ExecuteScalar() is not null;
    }

    private static void LatchConflict(SqliteConnection db, SqliteTransaction tx, GroupFanoutBatchId32 batchId)
    {
        using var update = db.CreateCommand();
        update.Transaction = tx;
        update.CommandText = "UPDATE fanout_batches SET conflict_latched=1 WHERE batch_id=$batch;";
        update.Parameters.AddWithValue("$batch", batchId.ToArray());
        if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fanout conflict latch failed.");
    }

    private static T Finish<T>(SqliteTransaction tx, T result)
    {
        tx.Commit();
        return result;
    }

    private static void ValidateCipher(SqliteConnection db)
    {
        if (string.IsNullOrWhiteSpace(ScalarText(db, "PRAGMA cipher_version;")))
            throw new InvalidOperationException("SQLCipher is unavailable.");
        if (!string.Equals(ScalarText(db, "PRAGMA integrity_check;"), "ok", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("GroupV1 fanout integrity check failed.");
    }

    private void ValidateEncryptedFile()
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) == 16 && header.SequenceEqual("SQLite format 3\0"u8))
            throw Failure(GroupStateStoreOpenFailure.Corrupt, "GroupV1 fanout database is plaintext.");
    }

    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteGroupFanoutStore));
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private void FailedOpen() { connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); }
    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql)
    { using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static long Scalar(SqliteConnection db, string sql)
    { using var command = db.CreateCommand(); command.CommandText = sql; return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture); }
    private static string ScalarText(SqliteConnection db, string sql)
    { using var command = db.CreateCommand(); command.CommandText = sql; return Convert.ToString(command.ExecuteScalar(), CultureInfo.InvariantCulture) ?? string.Empty; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static ulong ReadU64(ReadOnlySpan<byte> value)
    { if (value.Length != 8) throw new FormatException("Invalid fanout u64."); return BinaryPrimitives.ReadUInt64BigEndian(value); }
    private static void ValidateHash(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new FormatException("Invalid fanout hash."); }
    private static GroupStateStoreOpenException Failure(GroupStateStoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);

    private sealed class BatchRow(
        byte[] transitionOperationId,
        byte[] groupId,
        byte[] packageHash,
        byte[] verifiedPackageHash,
        byte[] fingerprint,
        ushort memberCount,
        ushort verifiedDeviceCount,
        int targetCount,
        bool conflictLatched,
        DateTimeOffset stagedAt)
    {
        internal byte[] TransitionOperationId { get; } = transitionOperationId;
        internal byte[] GroupId { get; } = groupId;
        internal byte[] PackageHash { get; } = packageHash;
        internal byte[] VerifiedPackageHash { get; } = verifiedPackageHash;
        internal byte[] Fingerprint { get; } = fingerprint;
        internal ushort MemberCount { get; } = memberCount;
        internal ushort VerifiedDeviceCount { get; } = verifiedDeviceCount;
        internal int TargetCount { get; } = targetCount;
        internal bool ConflictLatched { get; set; } = conflictLatched;
        internal DateTimeOffset StagedAt { get; } = stagedAt;
    }

    private sealed record TargetRow(
        byte[] TargetId,
        byte[] Envelope,
        uint CurrentAttempt,
        GroupFanoutTargetState State,
        byte[]? LeaseOwner,
        ulong LeaseGeneration,
        DateTimeOffset? LeaseExpires,
        bool BatchConflict);

    private sealed class AttemptRow(
        uint number,
        byte[] networkOperationId,
        GroupFanoutTargetState state,
        ulong? releasedLeaseGeneration,
        GroupFanoutAttemptOutcome? lastOutcome,
        GroupFanoutDefiniteRejectRule? rejectRule,
        byte[]? nextNetworkOperationId)
    {
        internal uint Number { get; } = number;
        internal byte[] NetworkOperationId { get; } = networkOperationId;
        internal GroupFanoutTargetState State { get; set; } = state;
        internal ulong? ReleasedLeaseGeneration { get; set; } = releasedLeaseGeneration;
        internal GroupFanoutAttemptOutcome? LastOutcome { get; } = lastOutcome;
        internal GroupFanoutDefiniteRejectRule? RejectRule { get; } = rejectRule;
        internal byte[]? NextNetworkOperationId { get; } = nextNetworkOperationId;
    }
}
