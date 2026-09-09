using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Protocol.GroupV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.GroupV1;

public sealed class SqliteGroupInvitationActivationStoreOptions : IDisposable
{
    private readonly byte[] key;
    private readonly object gate = new();
    private bool disposed;

    public SqliteGroupInvitationActivationStoreOptions(
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

/// <summary>SQLCipher journal for exact invitation activation artifacts and at-least-once GSW1 delivery.</summary>
public sealed class SqliteGroupInvitationActivationStore : IGroupInvitationActivationStore, IDisposable
{
    private const int ApplicationId = 0x4749414A;
    private const int SchemaGeneration = 1;
    private const string Ddl = """
        CREATE TABLE activation_meta(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            account_id BLOB NOT NULL CHECK(length(account_id)=32),
            account_generation BLOB NOT NULL CHECK(length(account_generation)=8),
            store_generation INTEGER NOT NULL CHECK(store_generation=1));
        CREATE TABLE invitation_activations(
            activation_id BLOB PRIMARY KEY CHECK(length(activation_id)=32),
            group_id BLOB NOT NULL CHECK(length(group_id)=32),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            transition_fingerprint BLOB NOT NULL CHECK(length(transition_fingerprint)=32),
            exact_giv1 BLOB NOT NULL,
            exact_gia1 BLOB NOT NULL,
            control_count INTEGER NOT NULL CHECK(control_count BETWEEN 1 AND 64),
            state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4));
        CREATE TABLE invitation_activation_controls(
            activation_id BLOB NOT NULL,
            ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 63),
            control_sequence BLOB NOT NULL CHECK(length(control_sequence)=8),
            operation_id BLOB NOT NULL CHECK(length(operation_id)=32),
            exact_gsw1 BLOB NOT NULL CHECK(length(exact_gsw1) BETWEEN 1 AND 65536),
            exact_gcf1 BLOB NOT NULL CHECK(length(exact_gcf1) BETWEEN 1 AND 65536),
            attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 2147483647),
            accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
            exact_gss1 BLOB NULL,
            PRIMARY KEY(activation_id,ordinal),
            UNIQUE(activation_id,operation_id),
            FOREIGN KEY(activation_id) REFERENCES invitation_activations(activation_id) ON DELETE CASCADE,
            CHECK((accepted=0 AND exact_gss1 IS NULL) OR (accepted=1 AND exact_gss1 IS NOT NULL)));
        """;

    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key = new byte[32];
    private readonly string path;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteGroupInvitationActivationStore() => SQLitePCL.Batteries_V2.Init();

    public SqliteGroupInvitationActivationStore(SqliteGroupInvitationActivationStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Scope.StoreGeneration != GroupStoreScope.CurrentStoreGeneration)
            throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration,
                "Unsupported GroupV1 invitation activation store generation.");
        Scope = new GroupStoreScope(
            options.Scope.AccountId, options.Scope.AccountGeneration, options.Scope.StoreGeneration);
        path = options.StatePath;
        options.CopyKey(key);
        var exists = File.Exists(path);
        if (!exists && !options.AllowCreate)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey,
                "GroupV1 invitation activation database does not exist.");
        }
        if (exists && new FileInfo(path).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(GroupStateStoreOpenFailure.Corrupt,
                "GroupV1 invitation activation database is empty.");
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
        catch (GroupStateStoreOpenException) { FailedOpen(); throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            FailedOpen();
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey,
                "GroupV1 invitation activation SQLCipher state cannot be opened.", error);
        }
        catch { FailedOpen(); throw; }
    }

    public GroupStoreScope Scope { get; }

    public async ValueTask<GroupInvitationActivationStageResult> StageAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default)
    {
        Validate(plan);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var current = ReadRow(db, tx, plan.ActivationId);
            GroupInvitationActivationStageDisposition disposition;
            if (current is not null)
            {
                if (!GroupInvitationActivationPlan.Fixed(current.Fingerprint, plan.Fingerprint))
                {
                    using var conflict = db.CreateCommand();
                    conflict.Transaction = tx;
                    conflict.CommandText = "UPDATE invitation_activations SET state=4 WHERE activation_id=$id;";
                    conflict.Parameters.AddWithValue("$id", plan.ActivationId.ToArray());
                    if (conflict.ExecuteNonQuery() != 1) throw new InvalidOperationException("Activation conflict latch failed.");
                    disposition = GroupInvitationActivationStageDisposition.ConflictLatched;
                }
                else disposition = current.State == 4
                    ? GroupInvitationActivationStageDisposition.ConflictLatched
                    : GroupInvitationActivationStageDisposition.Idempotent;
            }
            else
            {
                Insert(db, tx, plan);
                disposition = GroupInvitationActivationStageDisposition.Staged;
            }
            tx.Commit();
            var snapshot = ReadSnapshot(db, null, plan.ActivationId)
                ?? throw new InvalidDataException("Staged activation vanished.");
            return new(disposition, snapshot);
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (Exception error) when (error is SqliteException or FormatException
            or InvalidOperationException or ArgumentException or OverflowException)
        {
            throw Failure(GroupStateStoreOpenFailure.Corrupt,
                "GroupV1 invitation activation staging failed closed.", error);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<GroupInvitationActivationSnapshot?> ReadAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); return ReadSnapshot(GetConnection(), null, activationId); }
        finally { gate.Release(); }
    }

    public async ValueTask<GroupInvitationControlDispatchLease?> ClaimNextAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var row = ReadRow(db, tx, activationId)
                ?? throw new InvalidOperationException("The activation journal entry is absent.");
            if (row.State is 3 or 4) { tx.Commit(); return null; }
            using var query = db.CreateCommand();
            query.Transaction = tx;
            query.CommandText = """
                SELECT ordinal,control_sequence,operation_id,exact_gsw1,attempts
                FROM invitation_activation_controls
                WHERE activation_id=$id AND accepted=0 ORDER BY ordinal LIMIT 1;
                """;
            query.Parameters.AddWithValue("$id", activationId.ToArray());
            using var reader = query.ExecuteReader();
            if (!reader.Read()) { reader.Close(); tx.Commit(); return null; }
            var ordinal = reader.GetInt32(0);
            var sequence = ReadU64((byte[])reader[1]);
            var operation = (byte[])reader[2];
            var gsw = (byte[])reader[3];
            var attempt = checked(reader.GetInt32(4) + 1);
            reader.Close();
            using var update = db.CreateCommand();
            update.Transaction = tx;
            update.CommandText = """
                UPDATE invitation_activation_controls SET attempts=$attempt
                WHERE activation_id=$id AND ordinal=$ordinal AND accepted=0;
                """;
            update.Parameters.AddWithValue("$attempt", attempt);
            update.Parameters.AddWithValue("$id", activationId.ToArray());
            update.Parameters.AddWithValue("$ordinal", ordinal);
            if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Activation claim CAS failed.");
            tx.Commit();
            return new(activationId, ordinal, sequence, operation, gsw, attempt);
        }
        finally { gate.Release(); }
    }

    public async ValueTask RecordVerifiedAsync(
        GroupInvitationControlDispatchLease lease,
        VerifiedGroupControlResult verifiedResult,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(verifiedResult);
        var independentlyVerified = GroupControlProductionClient.VerifyResult(
            verifiedResult.Request, verifiedResult.CanonicalBytes);
        if (independentlyVerified.Status is not (GroupControlResultStatus.Committed
                or GroupControlResultStatus.ExactReplay))
            throw new InvalidDataException("Only a verified terminal GSS1 write result may advance activation.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var db = GetConnection();
            await using var tx = db.BeginTransaction(deferred: false);
            var activation = ReadRow(db, tx, lease.ActivationId)
                ?? throw new InvalidOperationException("The activation journal entry is absent.");
            if (activation.State is 3 or 4) throw new InvalidOperationException("The activation journal is terminal.");
            using var query = db.CreateCommand();
            query.Transaction = tx;
            query.CommandText = """
                SELECT operation_id,exact_gsw1,accepted FROM invitation_activation_controls
                WHERE activation_id=$id AND ordinal=$ordinal;
                """;
            query.Parameters.AddWithValue("$id", lease.ActivationId.ToArray());
            query.Parameters.AddWithValue("$ordinal", lease.Ordinal);
            using var reader = query.ExecuteReader();
            if (!reader.Read()) throw new InvalidDataException("The activation control is absent.");
            var operation = (byte[])reader[0]; var gsw = (byte[])reader[1]; var alreadyAccepted = reader.GetBoolean(2);
            reader.Close();
            if (!GroupInvitationActivationPlan.Fixed(operation, lease.OperationId)
                || !GroupInvitationActivationPlan.Fixed(gsw, lease.ExactGsw1)
                || !GroupInvitationActivationPlan.Fixed(operation, independentlyVerified.Request.OperationId.Span)
                || !GroupInvitationActivationPlan.Fixed(gsw, independentlyVerified.Request.CanonicalBytes.Span))
                throw new InvalidDataException("GSS1 does not acknowledge the exact durable GSW1 operation.");
            using (var earlier = db.CreateCommand())
            {
                earlier.Transaction = tx;
                earlier.CommandText = """
                    SELECT COUNT(*) FROM invitation_activation_controls
                    WHERE activation_id=$id AND ordinal<$ordinal AND accepted=0;
                    """;
                earlier.Parameters.AddWithValue("$id", lease.ActivationId.ToArray());
                earlier.Parameters.AddWithValue("$ordinal", lease.Ordinal);
                if (Convert.ToInt32(earlier.ExecuteScalar()) != 0)
                    throw new InvalidDataException("A GroupControl result arrived out of order.");
            }
            if (!alreadyAccepted)
            {
                using var update = db.CreateCommand();
                update.Transaction = tx;
                update.CommandText = """
                    UPDATE invitation_activation_controls SET accepted=1,exact_gss1=$gss
                    WHERE activation_id=$id AND ordinal=$ordinal AND accepted=0;
                    """;
                update.Parameters.AddWithValue("$gss", independentlyVerified.CanonicalBytes.ToArray());
                update.Parameters.AddWithValue("$id", lease.ActivationId.ToArray());
                update.Parameters.AddWithValue("$ordinal", lease.Ordinal);
                if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Activation acknowledgement CAS failed.");
            }
            using (var ready = db.CreateCommand())
            {
                ready.Transaction = tx;
                ready.CommandText = """
                    UPDATE invitation_activations SET state=2
                    WHERE activation_id=$id AND state=1 AND NOT EXISTS(
                        SELECT 1 FROM invitation_activation_controls
                        WHERE activation_id=$id AND accepted=0);
                    """;
                ready.Parameters.AddWithValue("$id", lease.ActivationId.ToArray());
                ready.ExecuteNonQuery();
            }
            tx.Commit();
        }
        finally { gate.Release(); }
    }

    public async ValueTask MarkStateCommittedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var db = GetConnection();
            using var update = db.CreateCommand();
            update.CommandText = """
                UPDATE invitation_activations SET state=3
                WHERE activation_id=$id AND state IN (2,3) AND NOT EXISTS(
                    SELECT 1 FROM invitation_activation_controls
                    WHERE activation_id=$id AND accepted=0);
                """;
            update.Parameters.AddWithValue("$id", activationId.ToArray());
            if (update.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("GroupClientState cannot commit before all exact GSS1 acknowledgements.");
        }
        finally { gate.Release(); }
    }

    public async ValueTask MarkConflictLatchedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var db = GetConnection();
            using var update = db.CreateCommand();
            update.CommandText = """
                UPDATE invitation_activations SET state=4
                WHERE activation_id=$id AND state<>3;
                """;
            update.Parameters.AddWithValue("$id", activationId.ToArray());
            if (update.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("The activation conflict latch is absent or already committed.");
        }
        finally { gate.Release(); }
    }

    public void Dispose()
    {
        gate.Wait();
        try
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            connection?.Dispose(); connection = null;
            CryptographicOperations.ZeroMemory(key);
        }
        finally { gate.Release(); }
    }

    private void Insert(SqliteConnection db, SqliteTransaction tx, GroupInvitationActivationPlan plan)
    {
        using (var insert = db.CreateCommand())
        {
            insert.Transaction = tx;
            insert.CommandText = """
                INSERT INTO invitation_activations(
                    activation_id,group_id,fingerprint,transition_fingerprint,
                    exact_giv1,exact_gia1,control_count,state)
                VALUES($id,$group,$fingerprint,$transition,$giv,$gia,$count,1);
                """;
            insert.Parameters.AddWithValue("$id", plan.ActivationId.ToArray());
            insert.Parameters.AddWithValue("$group", plan.GroupId.ToArray());
            insert.Parameters.AddWithValue("$fingerprint", plan.Fingerprint.ToArray());
            insert.Parameters.AddWithValue("$transition", plan.TransitionFingerprint.ToArray());
            insert.Parameters.AddWithValue("$giv", plan.ExactInvitation.ToArray());
            insert.Parameters.AddWithValue("$gia", plan.ExactAcceptance.ToArray());
            insert.Parameters.AddWithValue("$count", plan.ControlCount);
            insert.ExecuteNonQuery();
        }
        foreach (var control in plan.Controls)
        {
            using var insert = db.CreateCommand();
            insert.Transaction = tx;
            insert.CommandText = """
                INSERT INTO invitation_activation_controls(
                    activation_id,ordinal,control_sequence,operation_id,exact_gsw1,
                    exact_gcf1,attempts,accepted,exact_gss1)
                VALUES($id,$ordinal,$sequence,$operation,$gsw,$gcf,0,0,NULL);
                """;
            insert.Parameters.AddWithValue("$id", plan.ActivationId.ToArray());
            insert.Parameters.AddWithValue("$ordinal", control.Ordinal);
            insert.Parameters.AddWithValue("$sequence", U64(control.ControlSequence));
            insert.Parameters.AddWithValue("$operation", control.OperationId.ToArray());
            insert.Parameters.AddWithValue("$gsw", control.ExactGsw1.ToArray());
            insert.Parameters.AddWithValue("$gcf", control.ExactGcf1.ToArray());
            insert.ExecuteNonQuery();
        }
    }

    private GroupInvitationActivationSnapshot? ReadSnapshot(
        SqliteConnection db,
        SqliteTransaction? tx,
        GroupOperationId32 activationId)
    {
        var row = ReadRow(db, tx, activationId);
        if (row is null) return null;
        using var query = db.CreateCommand(); query.Transaction = tx;
        query.CommandText = """
            SELECT COUNT(*),COALESCE(SUM(accepted),0),COALESCE(SUM(attempts),0)
            FROM invitation_activation_controls WHERE activation_id=$id;
            """;
        query.Parameters.AddWithValue("$id", activationId.ToArray());
        using var reader = query.ExecuteReader();
        if (!reader.Read()) throw new FormatException("Activation control summary is absent.");
        var count = reader.GetInt32(0); var accepted = reader.GetInt32(1); var attempts = reader.GetInt32(2);
        if (count != row.ControlCount) throw new FormatException("Activation control count is inconsistent.");
        var state = (GroupInvitationActivationJournalState)row.State;
        if ((state == GroupInvitationActivationJournalState.Sending && accepted == count)
            || (state is GroupInvitationActivationJournalState.ReadyToCommit
                or GroupInvitationActivationJournalState.Committed && accepted != count))
            throw new FormatException("Activation state is inconsistent with its exact acknowledgements.");
        return new(GroupOperationId32.FromBytes(row.ActivationId), GroupId32.FromBytes(row.GroupId),
            state, count, accepted, attempts);
    }

    private static ActivationRow? ReadRow(
        SqliteConnection db,
        SqliteTransaction? tx,
        GroupOperationId32 activationId)
    {
        using var query = db.CreateCommand(); query.Transaction = tx;
        query.CommandText = """
            SELECT activation_id,group_id,fingerprint,transition_fingerprint,
                   exact_giv1,exact_gia1,control_count,state
            FROM invitation_activations WHERE activation_id=$id;
            """;
        query.Parameters.AddWithValue("$id", activationId.ToArray());
        using var reader = query.ExecuteReader();
        if (!reader.Read()) return null;
        return new((byte[])reader[0], (byte[])reader[1], (byte[])reader[2], (byte[])reader[3],
            (byte[])reader[4], (byte[])reader[5], reader.GetInt32(6), reader.GetInt32(7));
    }

    private void Validate(GroupInvitationActivationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!Scope.Equals(plan.Scope))
            throw new ArgumentException("Activation belongs to another account store scope.", nameof(plan));
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
        catch { db.Dispose(); throw; }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        using var tx = db.BeginTransaction(deferred: false);
        Execute(db, tx, Ddl);
        using var insert = db.CreateCommand(); insert.Transaction = tx;
        insert.CommandText = "INSERT INTO activation_meta VALUES(1,$account,$generation,$store);";
        insert.Parameters.AddWithValue("$account", Scope.AccountId.Bytes.ToArray());
        insert.Parameters.AddWithValue("$generation", U64(Scope.AccountGeneration));
        insert.Parameters.AddWithValue("$store", Scope.StoreGeneration);
        insert.ExecuteNonQuery(); tx.Commit(); ValidateCipher(db);
    }

    private void ValidateExisting(SqliteConnection db)
    {
        try
        {
            if (Scalar(db, "PRAGMA application_id;") != ApplicationId
                || Scalar(db, "PRAGMA user_version;") != SchemaGeneration)
                throw Failure(GroupStateStoreOpenFailure.UnsupportedGeneration,
                    "Unsupported GroupV1 invitation activation schema.");
            ValidateCipher(db);
            using var query = db.CreateCommand();
            query.CommandText = "SELECT account_id,account_generation,store_generation FROM activation_meta WHERE singleton=1;";
            using var reader = query.ExecuteReader();
            if (!reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "Activation scope metadata is absent.");
            var account = (byte[])reader[0]; var generation = ReadU64((byte[])reader[1]); var store = reader.GetInt32(2);
            if (reader.Read()) throw Failure(GroupStateStoreOpenFailure.Corrupt, "Activation scope metadata is duplicated.");
            if (!Scope.AccountId.Matches(account) || generation != Scope.AccountGeneration || store != Scope.StoreGeneration)
                throw Failure(GroupStateStoreOpenFailure.ScopeMismatch,
                    "GroupV1 invitation activation database belongs to another account generation.");
        }
        catch (GroupStateStoreOpenException) { throw; }
        catch (SqliteException error)
        {
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey,
                "GroupV1 invitation activation metadata is unreadable.", error);
        }
    }

    private void ValidateAll(SqliteConnection db)
    {
        using var query = db.CreateCommand();
        query.CommandText = "SELECT activation_id,exact_giv1,exact_gia1 FROM invitation_activations ORDER BY activation_id;";
        using var reader = query.ExecuteReader();
        var rows = new List<(byte[] Id, byte[] Invitation, byte[] Acceptance)>();
        while (reader.Read()) rows.Add(((byte[])reader[0], (byte[])reader[1], (byte[])reader[2]));
        reader.Close();
        foreach (var row in rows)
        {
            _ = GroupCodec.Decode("GIV1", row.Invitation);
            _ = GroupCodec.Decode("GIA1", row.Acceptance);
            var id = GroupOperationId32.FromBytes(row.Id);
            _ = ReadSnapshot(db, null, id) ?? throw new FormatException("Activation vanished during validation.");
            using var controls = db.CreateCommand();
            controls.CommandText = "SELECT control_sequence,operation_id,exact_gsw1,exact_gcf1,accepted,exact_gss1 FROM invitation_activation_controls WHERE activation_id=$id ORDER BY ordinal;";
            controls.Parameters.AddWithValue("$id", row.Id);
            using var controlReader = controls.ExecuteReader();
            ulong? priorSequence = null; byte[]? priorHash = null;
            while (controlReader.Read())
            {
                var sequence = ReadU64((byte[])controlReader[0]); var operation = (byte[])controlReader[1];
                var write = (GroupControlWriteRecord)GroupCodec.Decode("GSW1", (byte[])controlReader[2]);
                _ = GroupCodec.Decode("GCF1", (byte[])controlReader[3]);
                if (!GroupInvitationActivationPlan.Fixed(operation, write.Field(2).Span)
                    || sequence != BinaryPrimitives.ReadUInt64BigEndian(write.Field(18).Span)
                    || priorSequence.HasValue && (sequence != priorSequence.Value + 1
                        || priorHash is null || !GroupInvitationActivationPlan.Fixed(write.Field(19).Span, priorHash)))
                    throw new FormatException("Persisted activation control chain is invalid.");
                if (controlReader.GetBoolean(4)) _ = GroupCodec.Decode("GSS1", (byte[])controlReader[5]);
                priorSequence = sequence; priorHash = write.ArtifactHash.ToArray();
            }
        }
    }

    private void ValidateEncryptedFile()
    {
        var header = new byte[16];
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Read(header, 0, header.Length) != header.Length
            || header.AsSpan().SequenceEqual("SQLite format 3\0"u8))
            throw Failure(GroupStateStoreOpenFailure.Corrupt,
                "GroupV1 invitation activation database is not SQLCipher-encrypted.");
    }

    private static void ValidateCipher(SqliteConnection db)
    {
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA cipher_version;";
        if (string.IsNullOrWhiteSpace(Convert.ToString(command.ExecuteScalar())))
            throw Failure(GroupStateStoreOpenFailure.UnreadableOrWrongKey, "SQLCipher is unavailable.");
    }

    private static int Scalar(SqliteConnection db, string sql)
    { using var command = db.CreateCommand(); command.CommandText = sql; return Convert.ToInt32(command.ExecuteScalar()); }
    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql)
    { using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); }
    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqliteGroupInvitationActivationStore));
    private void ThrowIfDisposed() { if (Volatile.Read(ref disposed) != 0) throw new ObjectDisposedException(nameof(SqliteGroupInvitationActivationStore)); }
    private void FailedOpen() { connection?.Dispose(); connection = null; CryptographicOperations.ZeroMemory(key); }
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }
    private static ulong ReadU64(ReadOnlySpan<byte> value) { if (value.Length != 8) throw new FormatException("Invalid u64."); return BinaryPrimitives.ReadUInt64BigEndian(value); }
    private static GroupStateStoreOpenException Failure(GroupStateStoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);

    private sealed record ActivationRow(
        byte[] ActivationId,
        byte[] GroupId,
        byte[] Fingerprint,
        byte[] TransitionFingerprint,
        byte[] ExactInvitation,
        byte[] ExactAcceptance,
        int ControlCount,
        int State);
}
