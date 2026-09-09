using System.Globalization;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.MessagingV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.MessagingV1;

internal enum MessageStoreResetRequiredReason
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    CorruptCurrentGeneration = 4,
    AuthorityMismatch = 5
}

internal sealed class MessageStoreResetRequiredException : IOException
{
    internal MessageStoreResetRequiredException(
        MessageStoreResetRequiredReason reason, string message, Exception? inner = null)
        : base(message, inner) => Reason = reason;

    internal MessageStoreResetRequiredReason Reason { get; }
}
internal sealed class SqliteMessageStoreOptions
{
    internal SqliteMessageStoreOptions(
        string statePath,
        ReadOnlyMemory<byte> encryptionKey,
        MessageStoreScope scope,
        Msg01VerifiedSessionAuthority evidenceAuthority,
        bool allowCreate = true, IMessageStoreFailpoint? failpoint = null)
    {
        StatePath = statePath;
        EncryptionKey = encryptionKey;
        Scope = scope;
        EvidenceAuthority = evidenceAuthority ?? throw new ArgumentNullException(nameof(evidenceAuthority));
        AllowCreate = allowCreate;
        Failpoint = failpoint;
    }

    internal string StatePath { get; }
    internal ReadOnlyMemory<byte> EncryptionKey { get; }
    internal MessageStoreScope Scope { get; }
    internal Msg01VerifiedSessionAuthority EvidenceAuthority { get; }
    internal bool AllowCreate { get; }
    internal IMessageStoreFailpoint? Failpoint { get; }
}

internal static class SqliteMessageStoreBootstrap
{
    internal static SqliteMessageTransactionStore Open(SqliteMessageStoreOptions options) => new(options);

    internal static Task ResetAsync(string statePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        cancellationToken.ThrowIfCancellationRequested();
        var fullPath = Path.GetFullPath(statePath);
        foreach (var path in new[] { fullPath, fullPath + "-wal", fullPath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        return Task.CompletedTask;
    }
}

internal sealed class SqliteMessageTransactionStore : IMessageTransactionStore
{
    private const int ApplicationId = 0x444D5331; // DMS1
    private const int SchemaGeneration = 4;
    private const string ExpectedSchemaFingerprint =
        "FD392DC46EB75060EFCB9CDE3D00ECDE701DCE9FE6C323EDA76BF4C32C8B79EA";
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly MessageStoreAuthorityBinding authorityBinding;
    private readonly string statePath;
    private readonly string connectionString;
    private readonly byte[] encryptionKey;
    private readonly byte[] evidenceAuthorityFingerprint;
    private readonly IMessageStoreFailpoint? failpoint;
    private readonly TaskCompletionSource<bool> disposalCompletion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private SqliteConnection? persistentConnection;
    private int disposed;

    static SqliteMessageTransactionStore() => SQLitePCL.Batteries_V2.Init();

    internal SqliteMessageTransactionStore(SqliteMessageStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.StatePath);
        ArgumentNullException.ThrowIfNull(options.Scope);
        if (options.EncryptionKey.Length != 32
            || options.EncryptionKey.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(options));
        }
        _ = options.EvidenceAuthority.Fingerprint;

        var path = Path.GetFullPath(options.StatePath);
        var exists = File.Exists(path);
        if (!exists && !options.AllowCreate)
        {
            throw Reset(MessageStoreResetRequiredReason.UnreadableOrWrongKey,
                "The current MSG-01 database generation does not exist.");
        }
        if (exists && new FileInfo(path).Length == 0)
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 database is empty and must be reset.");
        }
        if (exists && HasPlaintextSqliteHeader(path))
        {
            throw Reset(MessageStoreResetRequiredReason.UnreadableOrWrongKey,
                "MSG-01 refuses a plaintext SQLite database.");
        }
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        Scope = new(options.Scope.LocalAccountId, options.Scope.DatabaseGeneration,
            options.Scope.StoreInstanceId);
        statePath = path;
        encryptionKey = options.EncryptionKey.ToArray();
        evidenceAuthorityFingerprint = options.EvidenceAuthority.Fingerprint.ToArray();
        authorityBinding = new MessageStoreAuthorityBinding(options.EvidenceAuthority);
        failpoint = options.Failpoint;
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString();
        SqliteConnection? openedConnection = null;
        try
        {
            Initialize(exists);
            openedConnection = Open();
            Inject("constructor.before-encrypted-file-validation");
            ValidateEncryptedFiles(openedConnection);
            persistentConnection = openedConnection;
            openedConnection = null;
        }
        catch
        {
            try
            {
                openedConnection?.Dispose();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(evidenceAuthorityFingerprint);
                authorityBinding?.Dispose();
            }
            throw;
        }
    }

    public MessageStoreScope Scope { get; }
    public IMessageVerifiedTransportHandoff ClaimVerifiedTransportHandoff() =>
        authorityBinding.ClaimHandoff();
    public IMessageGroupDispatchSafetyHandoff ClaimGroupDispatchSafetyHandoff() =>
        authorityBinding.ClaimGroupSafetyHandoff();
    internal string ConnectionString => connectionString;
    internal bool EncryptionKeyIsZeroized =>
        encryptionKey.AsSpan().IndexOfAnyExcept((byte)0) < 0;

    public async ValueTask<SemanticClaimResult> ClaimSemanticAsync(
        SemanticClaimCandidate claim, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = GetConnection();
            await using var transaction = connection.BeginTransaction(deferred: false);
            var stored = ReadClaim(connection, transaction, claim.Key);
            SemanticClaimResult result;
            if (stored is null)
            {
                InsertClaim(connection, transaction, claim, false);
                result = SemanticClaimResult.First;
            }
            else if (stored.ForkLatched)
            {
                UpsertClaimDevice(connection, transaction, claim);
                result = SemanticClaimResult.ForkLatched;
            }
            else if (stored.EventHash.Equals(claim.EventHash))
            {
                UpsertClaimDevice(connection, transaction, claim);
                result = SemanticClaimResult.ExactDuplicate;
            }
            else
            {
                UpsertClaimDevice(connection, transaction, claim);
                LatchFork(connection, transaction, claim.Key, claim.EventHash);
                result = SemanticClaimResult.ForkLatched;
            }
            transaction.Commit();
            return result;
        }
        catch (MessageStoreResetRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or ArgumentException or InvalidOperationException)
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 claim transaction failed and local message state must be reset.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<BeginMessageResult> BeginOutboundAsync(
        MessageMutationId32 operationId,
        SemanticClaimCandidate claim,
        LogicalOutboxSeed seed,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(seed);
        ValidateOutboundBinding(claim, seed);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = GetConnection();
            await using var transaction = connection.BeginTransaction(deferred: false);
            var storedClaim = ReadClaim(connection, transaction, claim.Key);
            if (storedClaim?.ForkLatched == true)
            {
                UpsertClaimDevice(connection, transaction, claim);
                transaction.Commit();
                return new(SemanticClaimResult.ForkLatched, MessageCommitResult.ForkLatched, null);
            }
            if (storedClaim is not null && !storedClaim.EventHash.Equals(claim.EventHash))
            {
                UpsertClaimDevice(connection, transaction, claim);
                LatchFork(connection, transaction, claim.Key, claim.EventHash);
                transaction.Commit();
                return new(SemanticClaimResult.ForkLatched, MessageCommitResult.ForkLatched, null);
            }
            if (storedClaim is not null)
            {
                UpsertClaimDevice(connection, transaction, claim);
            }

            var fingerprint = BeginFingerprint(claim, seed);
            var previous = ReadOperation(connection, transaction, operationId);
            var existing = ReadSnapshot(connection, transaction, seed.ClaimKey);
            if (previous is not null)
            {
                BeginMessageResult replay = previous == fingerprint && existing is not null
                    ? new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Idempotent, existing)
                    : new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Conflict, null);
                transaction.Commit();
                return replay;
            }
            if (existing is not null)
            {
                BeginMessageResult replay = SameSeed(existing, seed)
                    ? new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Idempotent, existing)
                    : new(SemanticClaimResult.ExactDuplicate, MessageCommitResult.Conflict, null);
                transaction.Commit();
                return replay;
            }

            if (storedClaim is null)
            {
                InsertClaim(connection, transaction, claim, false);
            }
            var queued = LogicalOutboxStateMachine.Queued(seed);
            InsertOutbox(connection, transaction, queued);
            InsertOperation(connection, transaction, operationId, fingerprint);
            Inject("begin.before-commit"); transaction.Commit(); Inject("begin.after-commit-before-return");
            return new(storedClaim is null ? SemanticClaimResult.First : SemanticClaimResult.ExactDuplicate,
                MessageCommitResult.Applied, queued);
        }
        catch (MessageStoreResetRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or ArgumentException or InvalidOperationException)
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 begin transaction failed and local message state must be reset.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<ApplyMessageResult> ApplyAsync(
        PreparedMessageMutation plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ThrowIfDisposed();
        plan.DemandTrustedAuthorityIfRequired(authorityBinding);
        if (!plan.Scope.Equals(Scope))
        {
            return new(MessageCommitResult.Conflict, null, null);
        }
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = GetConnection();
            await using var transaction = connection.BeginTransaction(deferred: false);
            var current = ReadSnapshot(connection, transaction, plan.ClaimKey);
            if (current is null)
            {
                return new(MessageCommitResult.Missing, null, null);
            }
            var claim = ReadClaim(connection, transaction, current.ClaimKey);
            if (claim is null)
            {
                throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                    "An MSG-01 outbox has no semantic claim.");
            }
            if (claim.ForkLatched)
            {
                return new(MessageCommitResult.ForkLatched, current, null);
            }

            var fingerprint = PlanFingerprint(plan);
            var previous = ReadOperation(connection, transaction, plan.OperationId);
            if (previous is not null)
            {
                return previous == fingerprint
                    ? new(MessageCommitResult.Idempotent, current,
                        ReadTombstone(connection, transaction, current.ClaimKey))
                    : new(MessageCommitResult.Conflict, current, null);
            }
            if (plan.ExpectedRevision != current.Revision)
            {
                return new(MessageCommitResult.StaleRevision, current, null);
            }

            LogicalOutboxSnapshot candidate;
            try { candidate = LogicalOutboxStateMachine.Apply(current, plan); }
            catch (InvalidOperationException exception) when (exception is not MessageRevisionExhaustedException)
            { return new(MessageCommitResult.Conflict,current,null); }
            try { RecordAttempt(connection, transaction, candidate, plan); }
            catch (MessageAttemptConflictException) { return new(MessageCommitResult.Conflict,current,null); }
            if (!UpdateOutboxCas(connection, transaction, current.Revision, candidate))
            {
                return new(MessageCommitResult.StaleRevision,
                    ReadSnapshot(connection, transaction, plan.ClaimKey), null);
            }
            ReplaceTargets(connection, transaction, candidate);
            InsertOperation(connection, transaction, plan.OperationId, fingerprint);
            MessageTombstone? tombstone = null;
            if (candidate.State is LogicalOutboxState.Expired
                or LogicalOutboxState.Cancelled
                or LogicalOutboxState.TerminalRejected)
            {
                var existingTombstone = ReadTombstone(connection, transaction,
                    candidate.ClaimKey);
                tombstone = new(candidate, existingTombstone?.RetainedAt ?? plan.OccurredAt);
                UpsertTombstone(connection, transaction, tombstone);
            }
            Inject("apply.before-commit"); transaction.Commit(); Inject("apply.after-commit-before-return");
            return new(MessageCommitResult.Applied, candidate, tombstone);
        }
        catch (MessageStoreResetRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or ArgumentException or InvalidOperationException)
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 CAS transaction failed and local message state must be reset.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<LogicalOutboxSnapshot?> ReadAsync(
        SemanticClaimKey claimKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claimKey);
        ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = GetConnection();
            await using var transaction = connection.BeginTransaction(deferred: true);
            var result = ReadSnapshot(connection, transaction, claimKey);
            transaction.Commit();
            return result;
        }
        catch (MessageStoreResetRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or ArgumentException or InvalidOperationException)
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "Persisted MSG-01 state is invalid and must be reset.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<InboxEventSnapshot?> ReadInboxAsync(
        SemanticClaimKey claimKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claimKey); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var connection=GetConnection();
            await using var transaction=connection.BeginTransaction(deferred:true);
            var result=ReadInbox(connection,transaction,claimKey);
            transaction.Commit(); return result;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<MessageRatchetSnapshot?> ReadRatchetAsync(
        RatchetSessionId32 sessionId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionId); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var connection=GetConnection();
            await using var transaction=connection.BeginTransaction(deferred:true);
            using var command=connection.CreateCommand(); command.Transaction=transaction;
            command.CommandText=$"SELECT before_hash,after_hash,sealed_state,applied_at FROM ratchet_transitions WHERE {ScopeWhere} AND session_id=$session;";
            BindScope(command); command.Parameters.AddWithValue("$session",sessionId.ToArray());
            using var reader=command.ExecuteReader();
            if(!reader.Read()) { transaction.Commit(); return null; }
            var result=new MessageRatchetSnapshot(sessionId,
                RatchetStateHash32.FromBytes((byte[])reader[0]),
                RatchetStateHash32.FromBytes((byte[])reader[1]),
                (byte[])reader[2], DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3)));
            if(reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "Duplicate MSG-01 ratchet rows were found.");
            reader.Close(); transaction.Commit(); return result;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<InboxEventSnapshot?> MaterializeInboundAsync(InboxMaterializationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ThrowIfDisposed();
        request.DemandIssuedBy(authorityBinding);
        if (!request.Scope.Equals(Scope))
            throw new InvalidOperationException("MSG-01 inbound capability has the wrong store scope.");
        if (request.CanonicalEvent.Length is 0 or > MessagingV1Limits.MaxCanonicalEventBytes
            || request.AuthenticatedReceipt.Length is 0 or > MessagingV1Limits.MaxAuthenticatedEvidenceBytes)
            throw new ArgumentOutOfRangeException(nameof(request));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var connection = GetConnection();
            await using var transaction = connection.BeginTransaction(deferred: false);
            var operationFingerprint = InboundFingerprint(request);
            var priorOperation = ReadOperation(connection, transaction, request.OperationId);
            if (priorOperation is not null
                && !string.Equals(priorOperation, operationFingerprint, StringComparison.Ordinal))
                throw new CryptographicException(
                    "MSG-01 authenticated evidence replay identity was reused for changed inbound context.");
            using (var existing = connection.CreateCommand())
            {
                existing.Transaction = transaction;
                existing.CommandText = $"SELECT event_hash,canonical_event,materialized_at,receipt_id FROM inbox_events WHERE {ScopeWhere} AND {SemanticWhere};";
                BindScope(existing); BindSemantic(existing, request.Claim.Key);
                using var reader = existing.ExecuteReader();
                if (reader.Read())
                {
                    var hash = MessageEventHash32.FromBytes((byte[])reader[0]);
                    if (!hash.Equals(request.Claim.EventHash))
                    {
                        reader.Close();
                        UpsertClaimDevice(connection, transaction, request.Claim);
                        LatchFork(connection, transaction, request.Claim.Key, request.Claim.EventHash);
                        transaction.Commit();
                        throw new InvalidOperationException("MSG-01 semantic fork is latched.");
                    }
                    var body = (byte[])reader[1];
                    var materializedAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2));
                    var originalReceiptId = MessageReceiptId32.FromBytes((byte[])reader[3]);
                    reader.Close();
                    var ratchetWritten = ApplyRatchetTransition(
                        connection, transaction, request);
                    UpsertClaimDevice(connection, transaction, request.Claim);
                    UpsertInboxDevice(connection, transaction, request.Claim);
                    EnsurePendingReceipt(connection, transaction, request);
                    var devices = ReadInboxDevices(connection, transaction, request.Claim.Key);
                    if (priorOperation is null)
                        InsertOperation(connection, transaction, request.OperationId, operationFingerprint);
                    if (ratchetWritten) Inject("inbox-duplicate.after-ratchet-write");
                    Inject("inbox-duplicate.before-commit");
                    transaction.Commit();
                    Inject("inbox-duplicate.after-commit-before-return");
                    return new InboxEventSnapshot(Scope, request.Claim.Key, hash, body,
                        materializedAt, originalReceiptId, devices);
                }
            }

            if (priorOperation is not null)
                throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                    "MSG-01 inbound replay ledger is inconsistent with the materialized event.");

            var claim = ReadClaim(connection, transaction, request.Claim.Key);
            if (claim is not null && !claim.EventHash.Equals(request.Claim.EventHash))
            {
                UpsertClaimDevice(connection, transaction, request.Claim);
                LatchFork(connection, transaction, request.Claim.Key, request.Claim.EventHash);
                transaction.Commit();
                throw new InvalidOperationException("MSG-01 semantic fork is latched.");
            }
            var wroteRatchet = ApplyRatchetTransition(connection, transaction, request);
            if (claim is null) InsertClaim(connection, transaction, request.Claim, false);
            else UpsertClaimDevice(connection, transaction, request.Claim);

            EnsurePendingReceipt(connection, transaction, request);
            using (var put = connection.CreateCommand())
            {
                put.Transaction = transaction;
                put.CommandText = "INSERT INTO inbox_events VALUES($la,$dg,$si,$aa,$ci,$sm,$eh,$event,$at,$receipt);";
                BindScope(put); BindSemantic(put, request.Claim.Key);
                put.Parameters.AddWithValue("$eh", request.Claim.EventHash.ToArray());
                put.Parameters.AddWithValue("$event", request.CanonicalEvent.ToArray());
                put.Parameters.AddWithValue("$at", request.OccurredAt.ToUnixTimeMilliseconds());
                put.Parameters.AddWithValue("$receipt", request.ReceiptId.ToArray());
                put.ExecuteNonQuery();
            }
            UpsertInboxDevice(connection, transaction, request.Claim);
            InsertOperation(connection, transaction, request.OperationId, operationFingerprint);
            if (wroteRatchet) Inject("inbox.after-ratchet-write");
            Inject("inbox.before-commit");
            transaction.Commit();
            Inject("inbox.after-commit-before-return");
            return new InboxEventSnapshot(Scope, request.Claim.Key, request.Claim.EventHash,
                request.CanonicalEvent.Span, request.OccurredAt, request.ReceiptId,
                [request.Claim.AuthorDeviceId]);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<MessageStoreRecoveryItem>> ClaimRecoveryAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(owner); if(maxItems is < 1 or > MessagingV1Limits.MaxRecoveryBatch) throw new ArgumentOutOfRangeException(nameof(maxItems)); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed(); now=LogicalOutboxSeed.Canonical(now); var until=now+MessagingV1Limits.MaxRecoveryLease; var c=GetConnection(); await using var tx=c.BeginTransaction(deferred:false); using var q=c.CreateCommand(); q.Transaction=tx; q.CommandText=$"SELECT author_account,author_device,conversation_id,semantic_id FROM logical_outbox WHERE {ScopeWhere} AND state IN(1,2,3,4,6) AND (lease_expires IS NULL OR lease_expires<=$now OR lease_owner=$owner) ORDER BY created_at,author_account,conversation_id,semantic_id LIMIT $limit;"; BindScope(q); q.Parameters.AddWithValue("$now",now.ToUnixTimeMilliseconds());q.Parameters.AddWithValue("$owner",owner.ToArray()); q.Parameters.AddWithValue("$limit",maxItems); using var r=q.ExecuteReader(); var keys=new List<SemanticClaimKey>(); while(r.Read()) keys.Add(new(MessagingAccountId32.FromBytes((byte[])r[0]),MessagingDeviceId32.FromBytes((byte[])r[1]),ConversationId32.FromBytes((byte[])r[2]),SemanticMessageId32.FromBytes((byte[])r[3]))); r.Close(); foreach(var k in keys) { using var u=c.CreateCommand(); u.Transaction=tx; u.CommandText=$"UPDATE logical_outbox SET lease_owner=$owner,lease_expires=$until WHERE {ScopeWhere} AND {ClaimWhere};"; BindScope(u); BindClaim(u,k); u.Parameters.AddWithValue("$owner",owner.ToArray()); u.Parameters.AddWithValue("$until",until.ToUnixTimeMilliseconds()); u.ExecuteNonQuery(); } var result=keys.Select(k=>new MessageStoreRecoveryItem(ReadSnapshot(c,tx,k)!,[])).ToArray(); tx.Commit(); return result; }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<PendingMessageReceipt>> ClaimPendingReceiptsAsync(MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(owner); if(maxItems is < 1 or > MessagingV1Limits.MaxRecoveryBatch) throw new ArgumentOutOfRangeException(nameof(maxItems)); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { ThrowIfDisposed();now=LogicalOutboxSeed.Canonical(now);var until=now+MessagingV1Limits.MaxRecoveryLease; var c=GetConnection(); await using var tx=c.BeginTransaction(deferred:false); using var q=c.CreateCommand(); q.Transaction=tx; q.CommandText=$"SELECT receipt_id,author_account,conversation_id,semantic_id,evidence_hash,body,created_at FROM message_receipts WHERE {ScopeWhere} AND sent_at IS NULL AND (lease_expires IS NULL OR lease_expires<=$now OR lease_owner=$owner) ORDER BY created_at,receipt_id LIMIT $limit;"; BindScope(q);q.Parameters.AddWithValue("$now",now.ToUnixTimeMilliseconds());q.Parameters.AddWithValue("$owner",owner.ToArray()); q.Parameters.AddWithValue("$limit",maxItems); using var r=q.ExecuteReader(); var x=new List<PendingMessageReceipt>(); while(r.Read()) x.Add(new(MessageReceiptId32.FromBytes((byte[])r[0]),new(MessagingAccountId32.FromBytes((byte[])r[1]),ConversationId32.FromBytes((byte[])r[2]),SemanticMessageId32.FromBytes((byte[])r[3])),MessageEvidenceHash32.FromBytes((byte[])r[4]),(byte[])r[5],DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)),new(owner,until)));r.Close();foreach(var item in x){using var u=c.CreateCommand();u.Transaction=tx;u.CommandText=$"UPDATE message_receipts SET lease_owner=$owner,lease_expires=$until WHERE {ScopeWhere} AND receipt_id=$receipt;";BindScope(u);u.Parameters.AddWithValue("$owner",owner.ToArray());u.Parameters.AddWithValue("$until",until.ToUnixTimeMilliseconds());u.Parameters.AddWithValue("$receipt",item.ReceiptId.ToArray());u.ExecuteNonQuery();} tx.Commit(); return x; }
        finally { gate.Release(); }
    }

    public async ValueTask<PendingMessageReceipt?> ClaimPendingReceiptAsync(
        MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receiptId); ArgumentNullException.ThrowIfNull(owner);
        ThrowIfDisposed(); now=LogicalOutboxSeed.Canonical(now);
        var until=now+MessagingV1Limits.MaxRecoveryLease;
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var c=GetConnection(); await using var tx=c.BeginTransaction(deferred:false);
            using var q=c.CreateCommand(); q.Transaction=tx;
            q.CommandText=$"SELECT author_account,conversation_id,semantic_id,evidence_hash,body,created_at,lease_owner,lease_expires FROM message_receipts WHERE {ScopeWhere} AND receipt_id=$receipt AND sent_at IS NULL;";
            BindScope(q); q.Parameters.AddWithValue("$receipt",receiptId.ToArray());
            using var r=q.ExecuteReader(); if(!r.Read()){tx.Commit();return null;}
            var leaseOwner=r.IsDBNull(6)?null:MessageRecoveryOwnerId16.FromBytes((byte[])r[6]);
            var leaseExpires=r.IsDBNull(7)?(DateTimeOffset?)null:DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(7));
            if(leaseOwner is not null&&leaseExpires>now&&!leaseOwner.Equals(owner)){r.Close();tx.Commit();return null;}
            var item=new PendingMessageReceipt(receiptId,
                new(MessagingAccountId32.FromBytes((byte[])r[0]),ConversationId32.FromBytes((byte[])r[1]),SemanticMessageId32.FromBytes((byte[])r[2])),
                MessageEvidenceHash32.FromBytes((byte[])r[3]),(byte[])r[4],
                DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(5)),new(owner,until));
            r.Close(); using var u=c.CreateCommand();u.Transaction=tx;
            u.CommandText=$"UPDATE message_receipts SET lease_owner=$owner,lease_expires=$until WHERE {ScopeWhere} AND receipt_id=$receipt AND sent_at IS NULL;";
            BindScope(u);u.Parameters.AddWithValue("$owner",owner.ToArray());u.Parameters.AddWithValue("$until",until.ToUnixTimeMilliseconds());u.Parameters.AddWithValue("$receipt",receiptId.ToArray());
            if(u.ExecuteNonQuery()!=1)throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,"MSG-01 targeted receipt lease update failed.");
            tx.Commit();return item;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<MessageCommitResult> CompletePendingReceiptAsync(MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner, DateTimeOffset completedAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receiptId); ArgumentNullException.ThrowIfNull(owner);
        completedAt = LogicalOutboxSeed.Canonical(completedAt); ThrowIfDisposed();
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var connection=GetConnection();
            await using var transaction=connection.BeginTransaction(deferred:false);
            using var update=connection.CreateCommand(); update.Transaction=transaction;
            update.CommandText=$"UPDATE message_receipts SET sent_at=$at WHERE {ScopeWhere} AND receipt_id=$receipt AND sent_at IS NULL AND lease_owner=$owner AND lease_expires>=$at;";
            BindScope(update);
            update.Parameters.AddWithValue("$at",completedAt.ToUnixTimeMilliseconds());
            update.Parameters.AddWithValue("$receipt",receiptId.ToArray());
            update.Parameters.AddWithValue("$owner",owner.ToArray());
            if(update.ExecuteNonQuery()==1)
            {
                Inject("receipt-complete.before-commit");
                transaction.Commit();
                Inject("receipt-complete.after-commit-before-return");
                return MessageCommitResult.Applied;
            }
            using var read=connection.CreateCommand(); read.Transaction=transaction;
            read.CommandText=$"SELECT sent_at,lease_owner,lease_expires FROM message_receipts WHERE {ScopeWhere} AND receipt_id=$receipt;";
            BindScope(read); read.Parameters.AddWithValue("$receipt",receiptId.ToArray());
            using var reader=read.ExecuteReader();
            if(!reader.Read()) { transaction.Commit(); return MessageCommitResult.Missing; }
            var result = !reader.IsDBNull(0)
                ? MessageCommitResult.Idempotent : MessageCommitResult.Conflict;
            if(reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "Duplicate MSG-01 receipt rows were found.");
            reader.Close(); transaction.Commit(); return result;
        }
        finally { gate.Release(); }
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
        {
            return new(disposalCompletion.Task);
        }

        return new(DisposeCoreAsync());
    }

    private async Task DisposeCoreAsync()
    {
        try
        {
            authorityBinding.Dispose();
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                var connection = persistentConnection;
                persistentConnection = null;
                if (connection is not null)
                {
                    try { Checkpoint(connection); }
                    finally { await connection.DisposeAsync().ConfigureAwait(false); }
                    ValidateEncryptedFiles();
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encryptionKey);
                CryptographicOperations.ZeroMemory(evidenceAuthorityFingerprint);
                gate.Release();
            }
            disposalCompletion.TrySetResult(true);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
    }

    private void Initialize(bool existed)
    {
        try
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction(deferred: false);
            if (!existed)
            {
                CreateSchema(connection, transaction);
            }
            ValidateSchema(connection, transaction);
            transaction.Commit();
            VerifyCipherIntegrity(connection);
            ValidateEncryptedFiles(connection);
        }
        catch (MessageStoreResetRequiredException)
        {
            throw;
        }
        catch (Exception exception) when (exception is SqliteException or InvalidOperationException or IOException)
        {
            throw Reset(MessageStoreResetRequiredReason.UnreadableOrWrongKey,
                "The MSG-01 database is unreadable, corrupt, or uses another key.", exception);
        }
    }

    private void CreateSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE message_store_meta(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                local_account BLOB NOT NULL CHECK(length(local_account)=32),
                database_generation BLOB NOT NULL CHECK(length(database_generation)=8),
                store_instance BLOB NOT NULL CHECK(length(store_instance)=32),
                authority_key_hash BLOB NOT NULL CHECK(length(authority_key_hash)=32),
                schema_generation INTEGER NOT NULL CHECK(schema_generation=4),
                schema_fingerprint TEXT NOT NULL);
            CREATE TABLE semantic_claims(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, conversation_id BLOB NOT NULL,
                semantic_id BLOB NOT NULL, event_hash BLOB NOT NULL, fork_latched INTEGER NOT NULL CHECK(fork_latched IN(0,1)), fork_evidence BLOB NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(event_hash)=32),
                CHECK((fork_latched=0 AND fork_evidence IS NULL) OR (fork_latched=1 AND length(fork_evidence)=32 AND fork_evidence<>event_hash)),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,conversation_id,semantic_id));
            CREATE TABLE semantic_claim_devices(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, conversation_id BLOB NOT NULL, semantic_id BLOB NOT NULL,
                author_device BLOB NOT NULL CHECK(length(author_device)=32),
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(conversation_id)=32 AND length(semantic_id)=32),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,conversation_id,semantic_id,author_device));
            CREATE TABLE logical_outbox(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, author_device BLOB NOT NULL, conversation_id BLOB NOT NULL,
                semantic_id BLOB NOT NULL, event_hash BLOB NOT NULL, payload_kind INTEGER NOT NULL CHECK(payload_kind BETWEEN 1 AND 4), canonical_payload BLOB NOT NULL, created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL, state INTEGER NOT NULL, revision BLOB NOT NULL CHECK(length(revision)=8),
                lease_owner BLOB NULL CHECK(lease_owner IS NULL OR length(lease_owner)=16), lease_expires INTEGER NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(author_device)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(event_hash)=32),
                CHECK(length(canonical_payload) BETWEEN 1 AND 32768),
                CHECK(created_at>0 AND expires_at>created_at AND state BETWEEN 1 AND 10),
                CHECK((lease_owner IS NULL)=(lease_expires IS NULL)),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,author_device,conversation_id,semantic_id),
                UNIQUE(local_account,database_generation,store_instance,author_account,conversation_id,semantic_id));
            CREATE TABLE logical_outbox_targets(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, author_device BLOB NOT NULL, conversation_id BLOB NOT NULL,
                semantic_id BLOB NOT NULL, ordinal INTEGER NOT NULL, target_account BLOB NOT NULL,
                target_device BLOB NOT NULL, directory_head BLOB NOT NULL CHECK(length(directory_head)=32),
                state INTEGER NOT NULL, active_attempt BLOB NULL CHECK(active_attempt IS NULL OR length(active_attempt)=16), last_attempt BLOB NULL, unresolved_attempt BLOB NULL,
                request_hash BLOB NULL CHECK(request_hash IS NULL OR length(request_hash)=32), ratchet_before BLOB NULL CHECK(ratchet_before IS NULL OR length(ratchet_before)=32), ratchet_transition BLOB NULL CHECK(ratchet_transition IS NULL OR length(ratchet_transition)=32), ciphertext BLOB NULL CHECK(ciphertext IS NULL OR length(ciphertext) BETWEEN 1 AND 65536), outcome_unknown INTEGER NOT NULL CHECK(outcome_unknown IN(0,1)), target_operation BLOB NOT NULL CHECK(length(target_operation)=32), binding_hash BLOB NOT NULL CHECK(length(binding_hash)=32),
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(author_device)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(target_account)=32 AND length(target_device)=32 AND ordinal BETWEEN 0 AND 499 AND state BETWEEN 1 AND 6),
                CHECK(last_attempt IS NULL OR length(last_attempt)=16),
                CHECK(unresolved_attempt IS NULL OR length(unresolved_attempt)=16),
                CHECK((active_attempt IS NULL AND unresolved_attempt IS NULL) OR (active_attempt IS NOT NULL AND unresolved_attempt IS NOT NULL AND active_attempt=unresolved_attempt)),
                CHECK(outcome_unknown=0 OR active_attempt IS NOT NULL),
                CHECK((request_hash IS NULL)=(ratchet_before IS NULL) AND (request_hash IS NULL)=(ratchet_transition IS NULL) AND (request_hash IS NULL)=(ciphertext IS NULL)),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,author_device,conversation_id,semantic_id,ordinal),
                UNIQUE(local_account,database_generation,store_instance,author_account,author_device,conversation_id,semantic_id,target_account,target_device));
            CREATE TABLE transport_attempts(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, author_device BLOB NOT NULL, conversation_id BLOB NOT NULL,
                semantic_id BLOB NOT NULL, attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
                target_account BLOB NOT NULL, target_device BLOB NOT NULL, fingerprint TEXT NOT NULL,
                state INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(author_device)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(target_account)=32 AND length(target_device)=32 AND state=1 AND updated_at>0),
                PRIMARY KEY(local_account,database_generation,store_instance,attempt_id));
            CREATE TABLE message_operations(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                operation_id BLOB NOT NULL CHECK(length(operation_id)=32), fingerprint TEXT NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32),
                PRIMARY KEY(local_account,database_generation,store_instance,operation_id));
            CREATE TABLE message_tombstones(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, author_device BLOB NOT NULL, conversation_id BLOB NOT NULL,
                semantic_id BLOB NOT NULL, event_hash BLOB NOT NULL, terminal_state INTEGER NOT NULL,
                retained_at INTEGER NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(author_device)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(event_hash)=32),
                CHECK(terminal_state IN(8,9,10) AND retained_at>0),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,author_device,conversation_id,semantic_id));
            CREATE TABLE inbox_events(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL, conversation_id BLOB NOT NULL, semantic_id BLOB NOT NULL,
                event_hash BLOB NOT NULL, canonical_event BLOB NOT NULL, materialized_at INTEGER NOT NULL,
                receipt_id BLOB NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(event_hash)=32 AND length(receipt_id)=32),
                CHECK(length(canonical_event) BETWEEN 1 AND 32768 AND materialized_at>0),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,conversation_id,semantic_id));
            CREATE TABLE inbox_event_devices(
                local_account BLOB NOT NULL,database_generation BLOB NOT NULL,store_instance BLOB NOT NULL,
                author_account BLOB NOT NULL,conversation_id BLOB NOT NULL,semantic_id BLOB NOT NULL,author_device BLOB NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(conversation_id)=32 AND length(semantic_id)=32 AND length(author_device)=32),
                PRIMARY KEY(local_account,database_generation,store_instance,author_account,conversation_id,semantic_id,author_device));
            CREATE TABLE message_receipts(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                receipt_id BLOB NOT NULL CHECK(length(receipt_id)=32), author_account BLOB NOT NULL, conversation_id BLOB NOT NULL, semantic_id BLOB NOT NULL,
                evidence_hash BLOB NOT NULL CHECK(length(evidence_hash)=32), body BLOB NOT NULL, created_at INTEGER NOT NULL, lease_owner BLOB NULL, lease_expires INTEGER NULL, sent_at INTEGER NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(author_account)=32 AND length(conversation_id)=32 AND length(semantic_id)=32),
                CHECK(length(body) BETWEEN 1 AND 65536 AND created_at>0),
                CHECK((lease_owner IS NULL AND lease_expires IS NULL) OR (length(lease_owner)=16 AND lease_expires IS NOT NULL)),
                PRIMARY KEY(local_account,database_generation,store_instance,receipt_id));
            CREATE TABLE ratchet_transitions(
                local_account BLOB NOT NULL, database_generation BLOB NOT NULL, store_instance BLOB NOT NULL,
                session_id BLOB NOT NULL CHECK(length(session_id)=32), before_hash BLOB NOT NULL CHECK(length(before_hash)=32), after_hash BLOB NOT NULL CHECK(length(after_hash)=32), sealed_state BLOB NOT NULL, applied_at INTEGER NOT NULL,
                CHECK(length(local_account)=32 AND length(database_generation)=8 AND length(store_instance)=32 AND length(sealed_state) BETWEEN 1 AND 65536 AND applied_at>0),
                PRIMARY KEY(local_account,database_generation,store_instance,session_id));
            PRAGMA application_id=1145918257;
            PRAGMA user_version=4;
            """;
        command.ExecuteNonQuery();
        var actualFingerprint = ComputeSchemaFingerprint(connection, transaction);
        if (!string.Equals(actualFingerprint, ExpectedSchemaFingerprint,
            StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"The compiled MSG-01 schema fingerprint is stale: {actualFingerprint}.");
        using var meta = connection.CreateCommand();
        meta.Transaction = transaction;
        meta.CommandText = "INSERT INTO message_store_meta VALUES(1,$la,$dg,$si,$ak,4,$fp);";
        BindScope(meta);
        meta.Parameters.AddWithValue("$ak", evidenceAuthorityFingerprint);
        meta.Parameters.AddWithValue("$fp", ExpectedSchemaFingerprint);
        meta.ExecuteNonQuery();
    }

    private void ValidateSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        if (ReadPragma(connection, transaction, "application_id") != ApplicationId
            || ReadPragma(connection, transaction, "user_version") != SchemaGeneration)
        {
            throw Reset(MessageStoreResetRequiredReason.UnsupportedGeneration,
                "Only the current clean-break MSG-01 schema generation is supported.");
        }
        using var names = connection.CreateCommand();
        names.Transaction = transaction;
        names.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
        using var reader = names.ExecuteReader();
        var actual = new List<string>();
        while (reader.Read()) actual.Add(reader.GetString(0));
        string[] expected = ["inbox_event_devices", "inbox_events", "logical_outbox", "logical_outbox_targets", "message_operations",
            "message_receipts", "message_store_meta", "message_tombstones", "ratchet_transitions", "semantic_claim_devices", "semantic_claims", "transport_attempts"];
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
        {
            throw Reset(MessageStoreResetRequiredReason.UnsupportedGeneration,
                "The MSG-01 schema is not the exact current generation.");
        }
        using var meta = connection.CreateCommand();
        meta.Transaction = transaction;
        meta.CommandText = "SELECT local_account,database_generation,store_instance,authority_key_hash,schema_generation,schema_fingerprint FROM message_store_meta WHERE singleton=1;";
        using var metaReader = meta.ExecuteReader();
        if (!metaReader.Read()
            || !Fixed((byte[])metaReader[0], Scope.LocalAccountId.Span)
            || ReadU64((byte[])metaReader[1]) != Scope.DatabaseGeneration
            || !Fixed((byte[])metaReader[2], Scope.StoreInstanceId.Span)
            || metaReader.GetInt32(4) != SchemaGeneration)
        {
            throw Reset(MessageStoreResetRequiredReason.ScopeMismatch,
                "The MSG-01 database belongs to another account or database generation.");
        }
        if (!Fixed((byte[])metaReader[3], evidenceAuthorityFingerprint))
        {
            throw Reset(MessageStoreResetRequiredReason.AuthorityMismatch,
                "The MSG-01 database is bound to another verified session authority.");
        }
        var storedFingerprint = metaReader.GetString(5);
        if (metaReader.Read())
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 database has duplicate store identity rows.");
        }
        metaReader.Close();
        var actualFingerprint = ComputeSchemaFingerprint(connection, transaction);
        if (storedFingerprint.Length != 64 || actualFingerprint.Length != 64
            || !storedFingerprint.All(Uri.IsHexDigit)
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(storedFingerprint),
                Convert.FromHexString(actualFingerprint))
            || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualFingerprint),
                Convert.FromHexString(ExpectedSchemaFingerprint)))
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "The MSG-01 schema fingerprint does not match the exact clean-break layout.");
        }
    }

    private StoredClaim? ReadClaim(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimKey key)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT event_hash,fork_latched,fork_evidence FROM semantic_claims WHERE {ScopeWhere} AND {SemanticWhere};";
        BindScope(command); BindSemantic(command, key);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var eventHash = MessageEventHash32.FromBytes((byte[])reader[0]);
        var forkLatched = reader.GetInt32(1) == 1;
        var forkEvidence = reader.IsDBNull(2)
            ? null : MessageEventHash32.FromBytes((byte[])reader[2]);
        if (forkLatched != (forkEvidence is not null)
            || forkEvidence is not null && forkEvidence.Equals(eventHash))
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "Semantic fork evidence is corrupt.");
        var result = new StoredClaim(eventHash, forkLatched, forkEvidence);
        if (reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Duplicate semantic claim.");
        return result;
    }

    private void InsertClaim(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimCandidate claim, bool fork)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO semantic_claims VALUES($la,$dg,$si,$aa,$ci,$sm,$eh,$fork,NULL);";
        BindScope(command); BindSemantic(command, claim.Key);
        command.Parameters.AddWithValue("$eh", claim.EventHash.ToArray());
        command.Parameters.AddWithValue("$fork", fork ? 1 : 0); command.ExecuteNonQuery();
        using var device = connection.CreateCommand(); device.Transaction=transaction;
        device.CommandText="INSERT OR IGNORE INTO semantic_claim_devices VALUES($la,$dg,$si,$aa,$ci,$sm,$ad);";
        BindScope(device); BindSemantic(device,claim.Key); device.Parameters.AddWithValue("$ad",claim.AuthorDeviceId.ToArray()); device.ExecuteNonQuery();
    }

    private void LatchFork(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimKey key, MessageEventHash32 conflictingHash)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"UPDATE semantic_claims SET fork_latched=1,fork_evidence=COALESCE(fork_evidence,$fork) WHERE {ScopeWhere} AND {SemanticWhere};";
        BindScope(command); BindSemantic(command, key); command.Parameters.AddWithValue("$fork", conflictingHash.ToArray());
        if (command.ExecuteNonQuery() != 1) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Semantic claim disappeared.");
    }

    private LogicalOutboxSnapshot? ReadSnapshot(
        SqliteConnection connection, SqliteTransaction transaction, SemanticClaimKey key)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"SELECT author_device,event_hash,payload_kind,canonical_payload,created_at,expires_at,state,revision,lease_owner,lease_expires FROM logical_outbox WHERE {ScopeWhere} AND {SemanticWhere};";
        BindScope(command); BindSemantic(command, key);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var authorDevice = MessagingDeviceId32.FromBytes((byte[])reader[0]);
        var hash = MessageEventHash32.FromBytes((byte[])reader[1]);
        var payloadKind = (MessagePayloadKind)reader.GetInt32(2);
        var canonicalPayload = (byte[])reader[3];
        var created = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(4));
        var expires = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(5));
        var state = (LogicalOutboxState)reader.GetInt32(6);
        var revision = ReadU64((byte[])reader[7]);
        var lease = reader.IsDBNull(8) || reader.IsDBNull(9) ? null : new MessageRecoveryLease(MessageRecoveryOwnerId16.FromBytes((byte[])reader[8]), DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(9)));
        if (reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Duplicate logical outbox.");
        reader.Close();

        using var targetsCommand = connection.CreateCommand(); targetsCommand.Transaction = transaction;
        targetsCommand.CommandText = $"SELECT ordinal,target_account,target_device,state,directory_head,active_attempt,last_attempt,unresolved_attempt,request_hash,ratchet_before,ratchet_transition,ciphertext,outcome_unknown,target_operation,binding_hash FROM logical_outbox_targets WHERE {ScopeWhere} AND {SemanticWhere} ORDER BY ordinal;";
        BindScope(targetsCommand); BindSemantic(targetsCommand, key);
        using var targetReader = targetsCommand.ExecuteReader();
        var targets = new List<LogicalTargetSnapshot>(); var ordinal = 0;
        while (targetReader.Read())
        {
            if (targetReader.GetInt32(0) != ordinal++) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Target ordinal is corrupt.");
            targets.Add(new(new(
                    MessagingAccountId32.FromBytes((byte[])targetReader[1]), MessagingDeviceId32.FromBytes((byte[])targetReader[2])),
                DirectoryHeadHash32.FromBytes((byte[])targetReader[4]), (LogicalTargetState)targetReader.GetInt32(3),
                targetReader.IsDBNull(5)?null:TransportAttemptId16.FromBytes((byte[])targetReader[5]), targetReader.IsDBNull(6)?null:TransportAttemptId16.FromBytes((byte[])targetReader[6]), targetReader.IsDBNull(7)?null:TransportAttemptId16.FromBytes((byte[])targetReader[7]),
                targetReader.IsDBNull(8)?null:TransportRequestHash32.FromBytes((byte[])targetReader[8]), targetReader.IsDBNull(10)?null:RatchetTransitionHash32.FromBytes((byte[])targetReader[10]), targetReader.GetInt32(12)==1,
                MessageTargetOperationId32.FromBytes((byte[])targetReader[13]), MessageBindingHash32.FromBytes((byte[])targetReader[14]),
                targetReader.IsDBNull(11) ? Array.Empty<byte>() : (byte[])targetReader[11],
                targetReader.IsDBNull(9) ? null : RatchetStateHash32.FromBytes((byte[])targetReader[9])));
        }
        var boundKey = new SemanticClaimKey(key.AuthorAccountId, authorDevice, key.ConversationId, key.SemanticMessageId);
        var snapshot = new LogicalOutboxSnapshot(Scope, boundKey, authorDevice, hash, canonicalPayload, created, expires, state, revision, targets, lease, payloadKind);
        LogicalOutboxStateMachine.Validate(snapshot);
        return snapshot;
    }

    private void InsertOutbox(SqliteConnection connection, SqliteTransaction transaction, LogicalOutboxSnapshot snapshot)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO logical_outbox VALUES($la,$dg,$si,$aa,$ad,$ci,$sm,$eh,$kind,$payload,$created,$expires,$state,$revision,NULL,NULL);";
        BindScope(command); BindClaim(command, snapshot.ClaimKey);
        command.Parameters.AddWithValue("$eh", snapshot.EventHash.ToArray());
        command.Parameters.AddWithValue("$kind", (int)snapshot.PayloadKind);
        command.Parameters.AddWithValue("$payload", snapshot.CanonicalPayload.ToArray());
        command.Parameters.AddWithValue("$created", snapshot.CreatedAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$expires", snapshot.ExpiresAt.ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$state", (int)snapshot.State);
        command.Parameters.AddWithValue("$revision", U64(snapshot.Revision));
        command.ExecuteNonQuery();
    }

    private bool UpdateOutboxCas(
        SqliteConnection connection, SqliteTransaction transaction, ulong expectedRevision, LogicalOutboxSnapshot snapshot)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"UPDATE logical_outbox SET state=$state,revision=$next WHERE {ScopeWhere} AND {ClaimWhere} AND revision=$expected;";
        BindScope(command); BindClaim(command, snapshot.ClaimKey);
        command.Parameters.AddWithValue("$state", (int)snapshot.State);
        command.Parameters.AddWithValue("$next", U64(snapshot.Revision));
        command.Parameters.AddWithValue("$expected", U64(expectedRevision));
        return command.ExecuteNonQuery() == 1;
    }

    private void ReplaceTargets(SqliteConnection connection, SqliteTransaction transaction, LogicalOutboxSnapshot snapshot)
    {
        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = $"DELETE FROM logical_outbox_targets WHERE {ScopeWhere} AND {ClaimWhere};";
            BindScope(delete); BindClaim(delete, snapshot.ClaimKey); delete.ExecuteNonQuery();
        }
        for (var ordinal = 0; ordinal < snapshot.Targets.Count; ordinal++)
        {
            var target = snapshot.Targets[ordinal];
            var directoryHead = target.DirectoryHeadHash.ToArray();
            if (directoryHead.Length != 32)
            {
                throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                    "A materialized target has an invalid directory-head hash.");
            }
            using var insert = connection.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO logical_outbox_targets(local_account,database_generation,store_instance,author_account,author_device,conversation_id,semantic_id,ordinal,target_account,target_device,directory_head,state,active_attempt,last_attempt,unresolved_attempt,request_hash,ratchet_before,ratchet_transition,ciphertext,outcome_unknown,target_operation,binding_hash) VALUES($la,$dg,$si,$aa,$ad,$ci,$sm,$ordinal,$ta,$td,$dir,$state,$active,$last,$unresolved,$request,$before,$ratchet,$ciphertext,$unknown,$operation,$binding);";
            BindScope(insert); BindClaim(insert, snapshot.ClaimKey);
            insert.Parameters.AddWithValue("$ordinal", ordinal);
            insert.Parameters.AddWithValue("$ta", target.Target.AccountId.ToArray());
            insert.Parameters.AddWithValue("$td", target.Target.DeviceId.ToArray());
            insert.Parameters.Add("$dir", SqliteType.Blob).Value = directoryHead;
            insert.Parameters.AddWithValue("$state", (int)target.State);
            insert.Parameters.AddWithValue("$active", (object?)target.ActiveAttemptId?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$last", (object?)target.LastAttemptId?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$unresolved", (object?)target.UnresolvedAttemptId?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$request", (object?)target.RequestHash?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$before", (object?)target.RatchetBeforeHash?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$ratchet", (object?)target.RatchetTransitionHash?.ToArray() ?? DBNull.Value);
            insert.Parameters.AddWithValue("$ciphertext", (object?)target.Ciphertext ?? DBNull.Value);
            insert.Parameters.AddWithValue("$unknown", target.OutcomeUnknown?1:0);
            insert.Parameters.AddWithValue("$operation", target.OperationId!.ToArray());
            insert.Parameters.AddWithValue("$binding", target.BindingHash!.ToArray());
            insert.ExecuteNonQuery();
        }
    }

    private void RecordAttempt(
        SqliteConnection connection, SqliteTransaction transaction,
        LogicalOutboxSnapshot after, PreparedMessageMutation plan)
    {
        // The operation journal handles exact mutation replay before this
        // method. Any attempt ID already present here is therefore reuse by a
        // distinct operation and must fail, even if every other byte matches.
        foreach (var attempt in plan.Attempts)
        {
            using(var read=connection.CreateCommand()) { read.Transaction=transaction;
                read.CommandText=$"SELECT fingerprint FROM transport_attempts WHERE {ScopeWhere} AND attempt_id=$attempt;";
                BindScope(read);read.Parameters.AddWithValue("$attempt",attempt.AttemptId.ToArray());
                if(read.ExecuteScalar() is string) throw new MessageAttemptConflictException();}
            var fingerprint=AttemptFingerprint(after.ClaimKey,attempt);
            using var insert = connection.CreateCommand(); insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO transport_attempts VALUES($la,$dg,$si,$aa,$ad,$ci,$sm,$attempt,$ta,$td,$fp,1,$at);";
            BindScope(insert); BindClaim(insert, after.ClaimKey);
            insert.Parameters.AddWithValue("$attempt", attempt.AttemptId.ToArray());
            insert.Parameters.AddWithValue("$ta",attempt.Target.AccountId.ToArray()); insert.Parameters.AddWithValue("$td",attempt.Target.DeviceId.ToArray()); insert.Parameters.AddWithValue("$fp",fingerprint);
            insert.Parameters.AddWithValue("$at", plan.OccurredAt.ToUnixTimeMilliseconds()); insert.ExecuteNonQuery();
        }
    }

    private string? ReadOperation(SqliteConnection connection, SqliteTransaction transaction, MessageMutationId32 operationId)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"SELECT fingerprint FROM message_operations WHERE {ScopeWhere} AND operation_id=$op;";
        BindScope(command); command.Parameters.AddWithValue("$op", operationId.ToArray());
        return command.ExecuteScalar() as string;
    }

    private void InsertOperation(SqliteConnection connection, SqliteTransaction transaction, MessageMutationId32 operationId, string fingerprint)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT INTO message_operations VALUES($la,$dg,$si,$op,$fp);";
        BindScope(command); command.Parameters.AddWithValue("$op", operationId.ToArray());
        command.Parameters.AddWithValue("$fp", fingerprint); command.ExecuteNonQuery();
    }

    private void UpsertTombstone(SqliteConnection connection, SqliteTransaction transaction, MessageTombstone tombstone)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "INSERT OR REPLACE INTO message_tombstones VALUES($la,$dg,$si,$aa,$ad,$ci,$sm,$eh,$state,$at);";
        BindScope(command); BindClaim(command, tombstone.ClaimKey);
        command.Parameters.AddWithValue("$eh", tombstone.EventHash.ToArray());
        command.Parameters.AddWithValue("$state", (int)tombstone.TerminalState);
        command.Parameters.AddWithValue("$at", tombstone.RetainedAt.ToUnixTimeMilliseconds()); command.ExecuteNonQuery();
    }

    private MessageTombstone? ReadTombstone(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimKey key)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"SELECT event_hash,terminal_state,retained_at FROM message_tombstones WHERE {ScopeWhere} AND {ClaimWhere};";
        BindScope(command); BindClaim(command, key); using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var eventHash = MessageEventHash32.FromBytes((byte[])reader[0]);
        var terminalState = (LogicalOutboxState)reader.GetInt32(1);
        var retainedAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2));
        reader.Close();
        var snapshot = ReadSnapshot(connection, transaction, key)
            ?? throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Tombstone outbox is missing.");
        if (!eventHash.Equals(snapshot.EventHash) || terminalState != snapshot.State
            || terminalState is not (LogicalOutboxState.Expired
                or LogicalOutboxState.Cancelled or LogicalOutboxState.TerminalRejected))
        {
            throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                "Persisted MSG-01 tombstone does not match its terminal outbox.");
        }
        return new MessageTombstone(snapshot, retainedAt);
    }

    private void ValidateOutboundBinding(SemanticClaimCandidate claim, LogicalOutboxSeed seed)
    {
        if (!seed.StoreScope.Equals(Scope) || !claim.Key.Equals(seed.ClaimKey)
            || !claim.AuthorDeviceId.Equals(seed.AuthorDeviceId)
            || !claim.EventHash.Equals(seed.EventHash)
            || !claim.AuthorAccountId.Equals(Scope.LocalAccountId))
        {
            throw new ArgumentException("Outbound claim, database scope, and outbox seed are not exactly bound.");
        }
    }

    private static bool SameSeed(LogicalOutboxSnapshot snapshot, LogicalOutboxSeed seed) =>
        snapshot.StoreScope.Equals(seed.StoreScope) && snapshot.ClaimKey.Equals(seed.ClaimKey)
        && snapshot.AuthorDeviceId.Equals(seed.AuthorDeviceId)
        && snapshot.EventHash.Equals(seed.EventHash) && snapshot.CreatedAt == seed.CreatedAt
        && snapshot.ExpiresAt == seed.ExpiresAt;

    private void BindScope(SqliteCommand command)
    {
        command.Parameters.AddWithValue("$la", Scope.LocalAccountId.ToArray());
        command.Parameters.AddWithValue("$dg", U64(Scope.DatabaseGeneration));
        command.Parameters.AddWithValue("$si", Scope.StoreInstanceId.ToArray());
    }

    private static void BindClaim(SqliteCommand command, SemanticClaimKey key)
    {
        command.Parameters.AddWithValue("$aa", key.AuthorAccountId.ToArray());
        command.Parameters.AddWithValue("$ad", (key.AuthorDeviceId ?? throw new InvalidOperationException("Outbound record lacks author-device evidence.")).ToArray());
        command.Parameters.AddWithValue("$ci", key.ConversationId.ToArray());
        command.Parameters.AddWithValue("$sm", key.SemanticMessageId.ToArray());
    }
    private static void BindSemantic(SqliteCommand command, SemanticClaimKey key)
    {
        command.Parameters.AddWithValue("$aa", key.AuthorAccountId.ToArray());
        command.Parameters.AddWithValue("$ci", key.ConversationId.ToArray());
        command.Parameters.AddWithValue("$sm", key.SemanticMessageId.ToArray());
    }

    private void UpsertClaimDevice(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimCandidate claim)
    {
        using var command=connection.CreateCommand();command.Transaction=transaction;
        command.CommandText="INSERT OR IGNORE INTO semantic_claim_devices VALUES($la,$dg,$si,$aa,$ci,$sm,$ad);";
        BindScope(command);BindSemantic(command,claim.Key);command.Parameters.AddWithValue("$ad",claim.AuthorDeviceId.ToArray());command.ExecuteNonQuery();
    }
    private void UpsertInboxDevice(SqliteConnection connection, SqliteTransaction transaction, SemanticClaimCandidate claim)
    {
        using var command=connection.CreateCommand();command.Transaction=transaction;
        command.CommandText="INSERT OR IGNORE INTO inbox_event_devices VALUES($la,$dg,$si,$aa,$ci,$sm,$ad);";
        BindScope(command);BindSemantic(command,claim.Key);command.Parameters.AddWithValue("$ad",claim.AuthorDeviceId.ToArray());command.ExecuteNonQuery();
    }
    private IReadOnlyList<MessagingDeviceId32> ReadInboxDevices(SqliteConnection connection,SqliteTransaction transaction,SemanticClaimKey key)
    {
        using var command=connection.CreateCommand();command.Transaction=transaction;
        command.CommandText=$"SELECT author_device FROM inbox_event_devices WHERE {ScopeWhere} AND {SemanticWhere} ORDER BY author_device;";
        BindScope(command);BindSemantic(command,key);using var reader=command.ExecuteReader();var result=new List<MessagingDeviceId32>();while(reader.Read())result.Add(MessagingDeviceId32.FromBytes((byte[])reader[0]));return result;
    }

    private InboxEventSnapshot? ReadInbox(SqliteConnection connection,
        SqliteTransaction transaction, SemanticClaimKey key)
    {
        using var command=connection.CreateCommand(); command.Transaction=transaction;
        command.CommandText=$"SELECT event_hash,canonical_event,materialized_at,receipt_id FROM inbox_events WHERE {ScopeWhere} AND {SemanticWhere};";
        BindScope(command); BindSemantic(command,key);
        using var reader=command.ExecuteReader();
        if(!reader.Read()) return null;
        var eventHash=MessageEventHash32.FromBytes((byte[])reader[0]);
        var canonicalEvent=(byte[])reader[1];
        var materializedAt=DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2));
        var receiptId=MessageReceiptId32.FromBytes((byte[])reader[3]);
        if(reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
            "Duplicate MSG-01 inbox rows were found.");
        reader.Close();
        return new InboxEventSnapshot(Scope,key,eventHash,canonicalEvent,
            materializedAt,receiptId,ReadInboxDevices(connection,transaction,key));
    }

    private bool ApplyRatchetTransition(SqliteConnection connection,
        SqliteTransaction transaction, InboxMaterializationRequest request)
    {
        using (var read=connection.CreateCommand())
        {
            read.Transaction=transaction;
            read.CommandText=$"SELECT before_hash,after_hash,sealed_state FROM ratchet_transitions WHERE {ScopeWhere} AND session_id=$session;";
            BindScope(read); read.Parameters.AddWithValue("$session",request.SessionId.ToArray());
            using var reader=read.ExecuteReader();
            if(reader.Read())
            {
                var before=(byte[])reader[0]; var after=(byte[])reader[1];
                var sealedState=(byte[])reader[2];
                if(reader.Read()) throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration,
                    "Duplicate MSG-01 ratchet rows were found.");
                reader.Close();
                if(Fixed(after,request.AfterHash.Span))
                {
                    if(!Fixed(before,request.BeforeHash.Span)
                        || !Fixed(sealedState,request.SealedRatchetState.Span))
                        throw new InvalidOperationException(
                            "MSG-01 exact ratchet replay has changed bytes.");
                    return false;
                }
                if(!Fixed(after,request.BeforeHash.Span))
                    throw new InvalidOperationException(
                        "MSG-01 ratchet predecessor does not match.");
            }
        }
        using var write=connection.CreateCommand(); write.Transaction=transaction;
        write.CommandText="INSERT OR REPLACE INTO ratchet_transitions VALUES($la,$dg,$si,$session,$before,$after,$state,$at);";
        BindScope(write);
        write.Parameters.AddWithValue("$session",request.SessionId.ToArray());
        write.Parameters.AddWithValue("$before",request.BeforeHash.ToArray());
        write.Parameters.AddWithValue("$after",request.AfterHash.ToArray());
        write.Parameters.AddWithValue("$state",request.SealedRatchetState.ToArray());
        write.Parameters.AddWithValue("$at",request.OccurredAt.ToUnixTimeMilliseconds());
        write.ExecuteNonQuery(); return true;
    }

    private void EnsurePendingReceipt(SqliteConnection connection,
        SqliteTransaction transaction, InboxMaterializationRequest request)
    {
        using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = $"SELECT author_account,conversation_id,semantic_id,evidence_hash,body FROM message_receipts WHERE {ScopeWhere} AND receipt_id=$receipt;";
            BindScope(read);
            read.Parameters.AddWithValue("$receipt", request.ReceiptId.ToArray());
            using var reader = read.ExecuteReader();
            if (reader.Read())
            {
                var exact = Fixed((byte[])reader[0], request.Claim.AuthorAccountId.Span)
                    && Fixed((byte[])reader[1], request.Claim.Key.ConversationId.Span)
                    && Fixed((byte[])reader[2], request.Claim.Key.SemanticMessageId.Span)
                    && Fixed((byte[])reader[3], request.EvidenceHash.Span)
                    && Fixed((byte[])reader[4], request.AuthenticatedReceipt.Span);
                if (reader.Read() || !exact)
                    throw new InvalidOperationException(
                        "MSG-01 receipt id is already bound to different evidence.");
                return;
            }
        }

        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO message_receipts VALUES($la,$dg,$si,$receipt,$aa,$ci,$sm,$eh,$body,$at,NULL,NULL,NULL);";
        BindScope(insert); BindSemantic(insert, request.Claim.Key);
        insert.Parameters.AddWithValue("$receipt", request.ReceiptId.ToArray());
        insert.Parameters.AddWithValue("$eh", request.EvidenceHash.ToArray());
        insert.Parameters.AddWithValue("$body", request.AuthenticatedReceipt.ToArray());
        insert.Parameters.AddWithValue("$at", request.OccurredAt.ToUnixTimeMilliseconds());
        insert.ExecuteNonQuery();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        try { connection.Open(); ApplyKey(connection); Configure(connection); VerifyCipherProvider(connection); return connection; }
        catch { connection.Dispose(); throw; }
    }

    private SqliteConnection GetConnection() => persistentConnection
        ?? throw new ObjectDisposedException(nameof(SqliteMessageTransactionStore));

    private void ApplyKey(SqliteConnection connection)
    {
        var result = SQLitePCL.raw.sqlite3_key(connection.Handle, encryptionKey);
        if (result != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected the MSG-01 key.", result);
    }

    private static void Configure(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA cipher_memory_security=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;";
        command.ExecuteNonQuery();
        using var journal = connection.CreateCommand();
        journal.CommandText = "PRAGMA journal_mode=WAL;";
        if (!string.Equals(journal.ExecuteScalar() as string, "wal", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("MSG-01 requires SQLCipher WAL journaling.");
    }

    private static void VerifyCipherProvider(SqliteConnection connection)
    {
        using var version = connection.CreateCommand(); version.CommandText="PRAGMA cipher_version;";
        if (version.ExecuteScalar() is not string value || !value.StartsWith("4.", StringComparison.Ordinal)) throw new InvalidOperationException("SQLCipher v4 provider is unavailable.");
    }

    private static void VerifyCipherIntegrity(SqliteConnection connection)
    {
        using var integrity = connection.CreateCommand(); integrity.CommandText="PRAGMA cipher_integrity_check;";
        using var reader=integrity.ExecuteReader();var failures=new List<string>();
        while(reader.Read()) { var value=reader.GetString(0);if(!string.Equals(value,"ok",StringComparison.OrdinalIgnoreCase))failures.Add(value); }
        if(failures.Count!=0) throw new InvalidOperationException("SQLCipher integrity check failed.");
    }

    private static bool HasPlaintextSqliteHeader(string path)
    {
        Span<byte> header=stackalloc byte[16]; using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite); if(stream.Read(header)!=header.Length) return false;
        return header.SequenceEqual("SQLite format 3\0"u8);
    }

    internal void ValidateEncryptedFilesForTesting() => ValidateEncryptedFiles(GetConnection());

    private void ValidateEncryptedFiles(SqliteConnection? connection = null)
    {
        ValidateEncryptedMainDatabase(statePath);
        var pageSize = connection is null ? 4096 : ReadPragma(connection, null, "page_size");
        ValidateEncryptedSidecars(statePath, pageSize);
    }

    private static void ValidateEncryptedMainDatabase(string path)
    {
        using var stream = OpenSharedRead(path);
        if (stream.Length < 16) throw new InvalidOperationException("The encrypted MSG-01 main database is truncated.");
        Span<byte> header = stackalloc byte[16]; ReadExactHeader(stream, header, "The encrypted MSG-01 main database is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8)) throw new InvalidOperationException("MSG-01 main state must never expose a plaintext SQLite header.");
    }

    private static void ValidateEncryptedSidecars(string path, int pageSize)
    {
        var wal = path + "-wal";
        if (File.Exists(wal)) ValidateWalSidecar(wal, pageSize);
        var shm = path + "-shm";
        if (File.Exists(shm)) ValidateSharedMemorySidecar(shm);
    }

    private static void ValidateWalSidecar(string path, int pageSize)
    {
        using var stream = OpenSharedRead(path);
        // A checkpoint may retain an empty WAL. Nonempty WAL files must contain a complete
        // encrypted WAL header and complete frames; they are never SQLite main-db bytes.
        if (stream.Length == 0) return;
        if (pageSize is < 512 or > 65536 || (pageSize & (pageSize - 1)) != 0
            || stream.Length < 32 || (stream.Length - 32) % (pageSize + 24L) != 0)
            throw new InvalidOperationException("The MSG-01 SQLCipher WAL is truncated or has an invalid page size.");
        Span<byte> header = stackalloc byte[16]; ReadExactHeader(stream, header, "The MSG-01 SQLCipher WAL is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8)) throw new InvalidOperationException("The MSG-01 WAL must never contain a plaintext SQLite header.");
    }

    private static void ValidateSharedMemorySidecar(string path)
    {
        using var stream = OpenSharedRead(path);
        // The WAL-index SHM sidecar is metadata, allocated in 32 KiB regions. Zero is valid
        // while SQLite creates/removes it and after clean checkpoint/dispose transitions.
        if (stream.Length != 0 && (stream.Length < 32 * 1024 || stream.Length % (32 * 1024) != 0))
            throw new InvalidOperationException("The MSG-01 WAL shared-memory sidecar has an invalid size.");
    }

    private static FileStream OpenSharedRead(string path) => new(path, FileMode.Open, FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete);

    private static void ReadExactHeader(Stream stream, Span<byte> header, string failure)
    {
        var read = 0;
        while (read != header.Length)
        {
            var count = stream.Read(header[read..]);
            if (count == 0) throw new InvalidOperationException(failure);
            read += count;
        }
    }

    private static void Checkpoint(SqliteConnection connection)
    {
        using var checkpoint = connection.CreateCommand();
        checkpoint.CommandText = "PRAGMA wal_checkpoint(PASSIVE);";
        using var reader = checkpoint.ExecuteReader();
        if (!reader.Read() || reader.IsDBNull(0) || reader.GetInt32(0) != 0)
            throw new InvalidOperationException("MSG-01 SQLCipher checkpoint did not complete safely.");
    }

    private static int ReadPragma(SqliteConnection connection, SqliteTransaction? transaction, string name)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = $"PRAGMA {name};";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static string ComputeSchemaFingerprint(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command=connection.CreateCommand(); command.Transaction=transaction;
        command.CommandText="SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name;";
        using var reader=command.ExecuteReader(); var rows=new List<string>();
        while(reader.Read()) rows.Add(string.Join('|', reader.GetString(0), reader.GetString(1), reader.GetString(2), string.Concat(reader.GetString(3).Where(static c=>!char.IsWhiteSpace(c)))));
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n',rows))));
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8]; System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }
    private static ulong ReadU64(byte[] bytes) => bytes.Length == 8
        ? System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes)
        : throw Reset(MessageStoreResetRequiredReason.CorruptCurrentGeneration, "Persisted UInt64 is malformed.");
    private static bool Fixed(byte[] actual, ReadOnlySpan<byte> expected) =>
        actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);

    private static string ClaimKeyText(SemanticClaimKey key) => string.Concat(
        Key(key.AuthorAccountId), Key(key.ConversationId), Key(key.SemanticMessageId));
    private static string ScopeKey(MessageStoreScope scope) => string.Concat(
        Key(scope.LocalAccountId), scope.DatabaseGeneration.ToString("X16"), Key(scope.StoreInstanceId));
    private static string BeginFingerprint(SemanticClaimCandidate claim, LogicalOutboxSeed seed) => string.Concat(
        "B", ScopeKey(seed.StoreScope), ClaimKeyText(claim.Key), Key(claim.AuthorDeviceId), Key(claim.EventHash), ((int)seed.PayloadKind).ToString("X2"), Convert.ToHexString(SHA256.HashData(seed.CanonicalPayload)),
        seed.CreatedAt.ToUnixTimeMilliseconds().ToString("X16"), seed.ExpiresAt.ToUnixTimeMilliseconds().ToString("X16"));
    private static string PlanFingerprint(PreparedMessageMutation plan) => string.Concat(
        "M", ScopeKey(plan.Scope), ClaimKeyText(plan.ClaimKey), ((int)plan.Kind).ToString("X2"),
        plan.ExpectedRevision.ToString("X16"), plan.OccurredAt.ToUnixTimeMilliseconds().ToString("X16"),
        plan.Target is null ? "" : Key(plan.Target.AccountId) + Key(plan.Target.DeviceId),
        plan.AttemptId is null ? "" : Key(plan.AttemptId),
        string.Concat(plan.Fanout.Select(static target => Key(target.AccountId)+Key(target.DeviceId)+Key(target.DirectoryHeadHash)+Key(target.OperationId)+Key(target.BindingHash))),
        string.Concat(plan.Attempts.Select(static a=>AttemptFingerprint(null,a))),
        plan.Outcome is null?"":Key(plan.Outcome.AttemptId)+Key(plan.Outcome.EvidenceHash)+((int)plan.Outcome.Kind).ToString("X2")+Key(plan.Outcome.TargetOperationId)+Key(plan.Outcome.BindingHash)+Replay(plan.Outcome.ReplayCounter,plan.Outcome.ReplayNonce.Span),
        plan.Uncertainty is null?"":Key(plan.Uncertainty.AttemptId)+Key(plan.Uncertainty.EvidenceHash)+Key(plan.Uncertainty.TargetOperationId)+Key(plan.Uncertainty.BindingHash)+Replay(plan.Uncertainty.ReplayCounter,plan.Uncertainty.ReplayNonce.Span),
        plan.Reconciliation is null?"":Key(plan.Reconciliation.Target.AccountId)+Key(plan.Reconciliation.Target.DeviceId)+Key(plan.Reconciliation.AttemptId)+((int)plan.Reconciliation.Kind).ToString("X2")+Key(plan.Reconciliation.TargetOperationId)+Key(plan.Reconciliation.BindingHash)+Key(plan.Reconciliation.EvidenceHash)+Replay(plan.Reconciliation.ReplayCounter,plan.Reconciliation.ReplayNonce.Span),
        plan.LateReceipt is null?"":Key(plan.LateReceipt.AcceptedAttemptId)+Key(plan.LateReceipt.ReceiptId)+Key(plan.LateReceipt.EvidenceHash)+Key(plan.LateReceipt.TargetOperationId)+Key(plan.LateReceipt.BindingHash)+Replay(plan.LateReceipt.ReplayCounter,plan.LateReceipt.ReplayNonce.Span),
        plan.GroupDispatchBlock is null?"":GroupBlockFingerprint(plan.GroupDispatchBlock));
    private static string GroupBlockFingerprint(VerifiedLocalGroupDispatchBlock block) => string.Concat(
        Key(block.ClaimKey.AuthorDeviceId!),Key(block.EventHash),Key(block.Target.AccountId),Key(block.Target.DeviceId),
        Key(block.DirectoryHeadHash),Key(block.TargetOperationId),Key(block.BindingHash),Key(block.AttemptId),
        Key(block.RequestHash),Key(block.RatchetBeforeHash),Key(block.RatchetTransitionHash),
        Convert.ToHexString(block.GroupId.Span),block.OutboxRevision.ToString("X16"),
        (block.GroupHeadRevision??0).ToString("X16"),((int)block.Disposition).ToString("X2"),
        Convert.ToHexString(SHA256.HashData(block.ExactDgm1.Span)),
        Convert.ToHexString(block.GroupHeadFingerprint.Span));
    private static string AttemptFingerprint(SemanticClaimKey? key, TargetAttemptPlan a)=>string.Concat(
        key is null?"":ClaimKeyText(key),Key(a.Target.AccountId),Key(a.Target.DeviceId),Key(a.AttemptId),Key(a.RequestHash),Key(a.RatchetBeforeHash),Key(a.RatchetTransitionHash),Key(a.DirectoryHeadHash),Key(a.OperationId),Key(a.BindingHash),Convert.ToHexString(SHA256.HashData(a.Ciphertext.Span)));
    private static string InboundFingerprint(InboxMaterializationRequest request)=>string.Concat(
        "I",ScopeKey(request.Scope),ClaimKeyText(request.Claim.Key),Key(request.Claim.AuthorDeviceId),
        Key(request.Claim.EventHash),Key(request.SessionId),Key(request.BeforeHash),Key(request.AfterHash),
        Convert.ToHexString(SHA256.HashData(request.CanonicalEvent.Span)),
        Convert.ToHexString(SHA256.HashData(request.SealedRatchetState.Span)),
        Key(request.ReceiptId),Key(request.EvidenceHash),
        Convert.ToHexString(SHA256.HashData(request.AuthenticatedReceipt.Span)),
        Replay(request.ReplayCounter,request.ReplayNonce.Span));
    private static string Replay(ulong counter,ReadOnlySpan<byte> nonce)=>
        string.Concat(counter.ToString("X16"),Convert.ToHexString(nonce));
    private static string Key(MessagingBinaryValue value) => Convert.ToHexString(value.Span);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private void Inject(string point) => failpoint?.Hit(point);
    private static MessageStoreResetRequiredException Reset(
        MessageStoreResetRequiredReason reason, string message, Exception? inner = null) => new(reason, message, inner);

    private const string ScopeWhere = "local_account=$la AND database_generation=$dg AND store_instance=$si";
    private const string ClaimWhere = "author_account=$aa AND author_device=$ad AND conversation_id=$ci AND semantic_id=$sm";
    private const string SemanticWhere = "author_account=$aa AND conversation_id=$ci AND semantic_id=$sm";
    private sealed record StoredClaim(MessageEventHash32 EventHash, bool ForkLatched,
        MessageEventHash32? ForkEvidence);
    private sealed class MessageAttemptConflictException : Exception { }
}
