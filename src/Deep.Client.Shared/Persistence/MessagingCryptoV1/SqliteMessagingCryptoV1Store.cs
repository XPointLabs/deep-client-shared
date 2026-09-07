using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

/// <summary>
/// The sole durable authority for one account/device/conversation/session TRS1
/// chain. It commits state, replay evidence, deletion evidence, and the journal
/// head in one SQLCipher transaction. Protocol capabilities are minted only by
/// <see cref="ExactDpe2SqliteDurableTransactionAuthority"/> after this authority
/// returns a durable result.
/// </summary>
internal sealed class SqliteMessagingCryptoV1Store : IAsyncDisposable
{
    private const int ApplicationId = 0x4D435231; // MCR1
    private const int SchemaGeneration = 2;
    private const string SchemaDdl = """
        CREATE TABLE messaging_crypto_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),account_id BLOB NOT NULL CHECK(length(account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),local_device_id BLOB NOT NULL CHECK(length(local_device_id)=32),device_generation BLOB NOT NULL CHECK(length(device_generation)=8),conversation_id BLOB NOT NULL CHECK(length(conversation_id)=32),session_id BLOB NOT NULL CHECK(length(session_id)=32));
        CREATE TABLE ratchet_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),state_generation BLOB NOT NULL CHECK(length(state_generation)=8),state_commitment BLOB NOT NULL CHECK(length(state_commitment)=32),state_hash BLOB NOT NULL CHECK(length(state_hash)=32),exact_trs1 BLOB NOT NULL CHECK(length(exact_trs1) BETWEEN 600 AND 2097152),journal_generation BLOB NOT NULL CHECK(length(journal_generation)=8),journal_head BLOB NOT NULL CHECK(length(journal_head)=32),fork_latched INTEGER NOT NULL CHECK(fork_latched IN(0,1)),terminal_latched INTEGER NOT NULL CHECK(terminal_latched IN(0,1)),initialization_operation_id BLOB NOT NULL CHECK(length(initialization_operation_id)=32),initialization_fingerprint BLOB NOT NULL CHECK(length(initialization_fingerprint)=32),initial_generation BLOB NOT NULL CHECK(length(initial_generation)=8),initial_commitment BLOB NOT NULL CHECK(length(initial_commitment)=32),initial_state_hash BLOB NOT NULL CHECK(length(initial_state_hash)=32));
        CREATE TABLE ratchet_journal(journal_generation BLOB PRIMARY KEY CHECK(length(journal_generation)=8),operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=32),replay_token BLOB NOT NULL UNIQUE CHECK(length(replay_token)=32),transition_fingerprint BLOB NOT NULL CHECK(length(transition_fingerprint)=32),direction INTEGER NOT NULL CHECK(direction BETWEEN 1 AND 3),prior_generation BLOB NOT NULL CHECK(length(prior_generation)=8),prior_commitment BLOB NOT NULL CHECK(length(prior_commitment)=32),prior_state_hash BLOB NOT NULL CHECK(length(prior_state_hash)=32),next_generation BLOB NOT NULL CHECK(length(next_generation)=8),next_commitment BLOB NOT NULL CHECK(length(next_commitment)=32),next_state_hash BLOB NOT NULL CHECK(length(next_state_hash)=32),envelope_hash BLOB NOT NULL CHECK(length(envelope_hash)=32),prior_journal_head BLOB NOT NULL CHECK(length(prior_journal_head)=32),next_journal_head BLOB NOT NULL CHECK(length(next_journal_head)=32),deletion_manifest_commitment BLOB NOT NULL CHECK(length(deletion_manifest_commitment)=32),message_key_deletion_evidence BLOB NOT NULL CHECK(length(message_key_deletion_evidence)=32),replay_evidence_commitment BLOB NOT NULL CHECK(length(replay_evidence_commitment)=32),pq_fence_mutation_commitment BLOB NULL CHECK(pq_fence_mutation_commitment IS NULL OR length(pq_fence_mutation_commitment)=32),terminal_state_commitment BLOB NULL CHECK(terminal_state_commitment IS NULL OR length(terminal_state_commitment)=32));
        CREATE TABLE ratchet_fork_latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),collision_kind INTEGER NOT NULL CHECK(collision_kind IN(1,2)),incumbent_fingerprint BLOB NOT NULL CHECK(length(incumbent_fingerprint)=32),conflicting_fingerprint BLOB NOT NULL CHECK(length(conflicting_fingerprint)=32),incumbent_operation_id BLOB NOT NULL CHECK(length(incumbent_operation_id)=32),conflicting_operation_id BLOB NOT NULL CHECK(length(conflicting_operation_id)=32),incumbent_replay_token BLOB NOT NULL CHECK(length(incumbent_replay_token)=32),conflicting_replay_token BLOB NOT NULL CHECK(length(conflicting_replay_token)=32),incumbent_envelope_hash BLOB NOT NULL CHECK(length(incumbent_envelope_hash)=32),conflicting_envelope_hash BLOB NOT NULL CHECK(length(conflicting_envelope_hash)=32),CHECK(incumbent_fingerprint<>conflicting_fingerprint));
        CREATE TABLE exact_dpe2_plan_journal(journal_generation BLOB PRIMARY KEY CHECK(length(journal_generation)=8),plan_fingerprint BLOB NOT NULL CHECK(length(plan_fingerprint)=32),exact_header_hash BLOB NOT NULL CHECK(length(exact_header_hash)=32),exact_envelope_hash BLOB NOT NULL CHECK(length(exact_envelope_hash)=32),exact_envelope_digest BLOB NOT NULL CHECK(length(exact_envelope_digest)=32),checkpoint_prior_generation BLOB NOT NULL CHECK(length(checkpoint_prior_generation)=8),checkpoint_prior_commitment BLOB NOT NULL CHECK(length(checkpoint_prior_commitment)=32),deduplication_mutation_commitment BLOB NULL CHECK(deduplication_mutation_commitment IS NULL OR length(deduplication_mutation_commitment)=32),has_state_mutation INTEGER NOT NULL CHECK(has_state_mutation=1),FOREIGN KEY(journal_generation) REFERENCES ratchet_journal(journal_generation) ON DELETE RESTRICT);
        """;

    private static readonly byte[] ExpectedSchemaFingerprint = HashSchemaObjects(ExpectedSchemaObjects());
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key;
    private readonly MessagingCryptoV1StoreScope scope;
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqliteMessagingCryptoV1Store() => SQLitePCL.Batteries_V2.Init();

    internal SqliteMessagingCryptoV1Store(MessagingCryptoV1StoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        key = options.CopyEncryptionKey();
        scope = options.Scope;
        statePath = options.StatePath;
        var exists = File.Exists(statePath);
        if (!exists && !options.AllowCreate)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(MessagingCryptoV1StoreOpenFailure.UnreadableOrWrongKey,
                "The protected messaging-crypto store does not exist.");
        }
        if (exists && new FileInfo(statePath).Length == 0)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(MessagingCryptoV1StoreOpenFailure.Corrupt,
                "The protected messaging-crypto store is empty.");
        }
        var parent = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();

        try
        {
            using (var opened = Open())
            {
                if (exists) Validate(opened);
                else Create(opened);
            }
            ValidateEncryptedHeader();
            connection = Open();
        }
        catch (MessagingCryptoV1StoreOpenException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        catch (SqliteException exception)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(MessagingCryptoV1StoreOpenFailure.UnreadableOrWrongKey,
                "The protected messaging-crypto store cannot be opened with this key.", exception);
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException or OverflowException)
        {
            CryptographicOperations.ZeroMemory(key);
            throw Failure(MessagingCryptoV1StoreOpenFailure.Corrupt,
                "The protected messaging-crypto store is corrupt.", exception);
        }
    }

    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);

    internal async ValueTask<MessagingCryptoV1CommitResult> InitializeAsync(
        MessagingCryptoV1PreparedInitialization initialization,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initialization);
        using var payload = initialization.Consume();
        var facts = MessagingCryptoV1Trs1.Validate(payload.ExactTrs1, scope);
        if (facts.TerminallyLatched)
            throw new InvalidOperationException("A verified handshake cannot initialize a terminal TRS1 state.");
        var fingerprint = ComputeInitializationFingerprint(payload.OperationId, facts);
        var initialHead = ComputeInitialJournalHead(scope);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var transaction = GetConnection().BeginTransaction(deferred: false);
            using var current = ReadCurrent(GetConnection(), transaction);
            if (current is not null)
            {
                if (MessagingCryptoV1Trs1.Fixed(current.InitializationOperationId, payload.OperationId) &&
                    MessagingCryptoV1Trs1.Fixed(current.InitializationFingerprint, fingerprint) &&
                    MessagingCryptoV1Trs1.Fixed(current.ExactTrs1, payload.ExactTrs1))
                    return Result(MessagingCryptoV1CommitDisposition.ExactReplay, current);
                return Result(current.ForkLatched
                    ? MessagingCryptoV1CommitDisposition.AlreadyForkLatched
                    : MessagingCryptoV1CommitDisposition.CasConflict, current);
            }

            using var command = GetConnection().CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ratchet_state VALUES(1,$generation,$commitment,$hash,$trs1,$journalGeneration,$journalHead,0,0,$operation,$fingerprint,$generation,$commitment,$hash);";
            Add(command, "$generation", U64(facts.Generation));
            Add(command, "$commitment", facts.StateCommitment);
            Add(command, "$hash", facts.ExactHash);
            Add(command, "$trs1", payload.ExactTrs1);
            Add(command, "$journalGeneration", U64(0));
            Add(command, "$journalHead", initialHead);
            Add(command, "$operation", payload.OperationId);
            Add(command, "$fingerprint", fingerprint);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("TRS1 initialization CAS failed.");
            transaction.Commit();
            return new MessagingCryptoV1CommitResult(
                MessagingCryptoV1CommitDisposition.Initialized, facts.Generation,
                facts.StateCommitment.ToArray(), 0, initialHead.ToArray(), false, false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
            CryptographicOperations.ZeroMemory(fingerprint);
            CryptographicOperations.ZeroMemory(initialHead);
            gate.Release();
        }
    }

    internal async ValueTask<MessagingCryptoV1CommitResult> CommitAsync(
        MessagingCryptoV1PreparedTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transition);
        using var payload = transition.Consume();
        var prior = MessagingCryptoV1Trs1.Validate(payload.PriorTrs1, scope);
        var next = MessagingCryptoV1Trs1.Validate(payload.NextTrs1, scope);
        ValidateTransition(payload, prior, next);
        var fingerprint = ComputeTransitionFingerprint(payload, prior, next);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeTransaction);
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            using var current = ReadCurrent(db, transaction) ??
                throw new InvalidOperationException("The TRS1 store must be initialized by the verified handshake producer.");

            if (current.ForkLatched)
                return Result(MessagingCryptoV1CommitDisposition.AlreadyForkLatched, current);

            using var operation = ReadCollision(db, transaction, "operation_id", payload.OperationId);
            if (operation is not null)
            {
                if (MessagingCryptoV1Trs1.Fixed(operation.Fingerprint, fingerprint))
                    return ExactReplayResult(operation);
                return LatchFork(db, transaction, current, operation, payload, fingerprint, 1);
            }
            using var replay = ReadCollision(db, transaction, "replay_token", payload.ReplayToken);
            if (replay is not null)
            {
                if (MessagingCryptoV1Trs1.Fixed(replay.Fingerprint, fingerprint) &&
                    MessagingCryptoV1Trs1.Fixed(replay.OperationId, payload.OperationId))
                    return ExactReplayResult(replay);
                return LatchFork(db, transaction, current, replay, payload, fingerprint, 2);
            }

            if (!MatchesCurrent(current, payload, prior))
                return Result(MessagingCryptoV1CommitDisposition.CasConflict, current);
            if (current.JournalGeneration >= (ulong)MessagingCryptoV1StoreTestHooks.MaximumJournalEntries)
                return Result(MessagingCryptoV1CommitDisposition.CapacityExceeded, current);

            var journalGeneration = checked(current.JournalGeneration + 1);
            var nextJournalHead = ComputeNextJournalHead(current.JournalHead, journalGeneration, fingerprint);
            InsertJournal(db, transaction, journalGeneration, nextJournalHead, payload, prior, next, fingerprint);
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterJournalInsert);
            UpdateState(db, transaction, current, journalGeneration, nextJournalHead, payload, next);
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterStateUpdate);
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeCommit);
            transaction.Commit();
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterCommit);
            return new MessagingCryptoV1CommitResult(
                MessagingCryptoV1CommitDisposition.Committed, next.Generation,
                next.StateCommitment.ToArray(), journalGeneration, nextJournalHead.ToArray(),
                false, next.TerminallyLatched);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prior.StateCommitment);
            CryptographicOperations.ZeroMemory(prior.ExactHash);
            CryptographicOperations.ZeroMemory(next.StateCommitment);
            CryptographicOperations.ZeroMemory(next.ExactHash);
            CryptographicOperations.ZeroMemory(fingerprint);
            gate.Release();
        }
    }

    internal async ValueTask<MessagingCryptoV1CommitResult> CommitExactDpe2Async(
        ExactDpe2ProtocolPlanSnapshot plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ValidateExactDpe2Shape(plan);
        var prior = MessagingCryptoV1Trs1.Validate(plan.PriorTrs1, scope);
        MessagingCryptoV1Trs1Facts? next = null;
        byte[]? transitionFingerprint = null;
        byte[]? planFingerprint = null;
        byte[]? envelopeDigest = null;
        try
        {
            ValidateExactDpe2Prior(plan, prior);
            if (plan.HasStateMutation)
            {
                next = MessagingCryptoV1Trs1.Validate(plan.NextTrs1, scope);
                ValidateExactDpe2Next(plan, prior, next);
                transitionFingerprint = ComputeTransitionFingerprint(
                    plan.Direction, plan.OperationId, plan.ReplayToken, plan.ExactEnvelopeHash,
                    prior.Generation, prior.StateCommitment, prior.ExactHash,
                    next.Generation, next.StateCommitment, next.ExactHash,
                    plan.JournalPredecessor, plan.DeletionManifestCommitment,
                    plan.MessageKeyDeletionEvidence, plan.ReplayEvidenceCommitment,
                    plan.PqFenceMutationCommitment, plan.TerminalStateCommitment);
            }
            planFingerprint = ComputeExactDpe2PlanFingerprint(plan);
            envelopeDigest = SHA256.HashData(plan.ExactEnvelope);

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfDisposed();
                cancellationToken.ThrowIfCancellationRequested();
                MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeTransaction);
                var db = GetConnection();
                using var transaction = db.BeginTransaction(deferred: false);
                using var current = ReadCurrent(db, transaction) ??
                    throw new InvalidOperationException(
                        "The TRS1 store must be initialized by the verified handshake producer.");

                if (current.ForkLatched)
                    return Result(MessagingCryptoV1CommitDisposition.AlreadyForkLatched, current);
                if (current.TerminallyLatched)
                    return Result(MessagingCryptoV1CommitDisposition.RollbackLatched, current);

                using var operation = ReadCollision(db, transaction, "operation_id", plan.OperationId);
                using var replay = operation is null
                    ? ReadCollision(db, transaction, "replay_token", plan.ReplayToken)
                    : null;
                var incumbent = operation ?? replay;
                if (incumbent is not null)
                {
                    if (IsExactDpe2Retry(db, transaction, incumbent, planFingerprint, envelopeDigest) ||
                        !plan.HasStateMutation && IsAuthenticatedReceiveReplay(
                            db, transaction, incumbent, plan, current, prior, envelopeDigest))
                        return ExactReplayResult(incumbent);

                    var collisionKind = operation is not null ? 1 : 2;
                    return LatchFork(db, transaction, current, incumbent,
                        plan.OperationId, plan.ReplayToken, plan.ExactEnvelopeHash,
                        planFingerprint, collisionKind);
                }

                if (!plan.HasStateMutation ||
                    !MatchesCurrent(current, plan, prior))
                    return Result(MessagingCryptoV1CommitDisposition.CasConflict, current);
                if (current.JournalGeneration >= (ulong)MessagingCryptoV1StoreTestHooks.MaximumJournalEntries)
                    return Result(MessagingCryptoV1CommitDisposition.CapacityExceeded, current);

                var journalGeneration = checked(current.JournalGeneration + 1);
                var nextJournalHead = ComputeNextJournalHead(
                    current.JournalHead, journalGeneration, transitionFingerprint!);
                try
                {
                    InsertJournal(db, transaction, journalGeneration, nextJournalHead,
                        plan, prior, next!, transitionFingerprint!);
                    InsertExactDpe2Journal(db, transaction, journalGeneration, plan,
                        planFingerprint, envelopeDigest);
                    MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterJournalInsert);
                    UpdateState(db, transaction, current, journalGeneration, nextJournalHead, plan, next!);
                    MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterStateUpdate);
                    MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeCommit);
                    cancellationToken.ThrowIfCancellationRequested();
                    transaction.Commit();
                    MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterCommit);
                    return new MessagingCryptoV1CommitResult(
                        MessagingCryptoV1CommitDisposition.Committed, next!.Generation,
                        next.StateCommitment.ToArray(), journalGeneration, nextJournalHead.ToArray(),
                        false, next.TerminallyLatched);
                }
                finally { CryptographicOperations.ZeroMemory(nextJournalHead); }
            }
            finally { gate.Release(); }
        }
        finally
        {
            Zero(prior.StateCommitment, prior.ExactHash);
            if (next is not null) Zero(next.StateCommitment, next.ExactHash);
            if (transitionFingerprint is not null) CryptographicOperations.ZeroMemory(transitionFingerprint);
            if (planFingerprint is not null) CryptographicOperations.ZeroMemory(planFingerprint);
            if (envelopeDigest is not null) CryptographicOperations.ZeroMemory(envelopeDigest);
        }
    }

    internal async ValueTask<MessagingCryptoV1HeadSnapshot?> ReadHeadAsync(
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var current = ReadCurrent(GetConnection(), null);
            return current is null ? null : new MessagingCryptoV1HeadSnapshot(
                current.Generation, current.StateCommitment.ToArray(), current.JournalGeneration,
                current.JournalHead.ToArray(), current.ForkLatched, current.TerminallyLatched);
        }
        finally { gate.Release(); }
    }

    internal ValueTask<MessagingCryptoV1PreparationLease> AcquireSendPreparationLeaseAsync(
        CancellationToken cancellationToken = default)
        => AcquirePreparationLeaseAsync(
            MessagingCryptoV1PreparationKind.Send,
            [], [], [], [], [],
            cancellationToken);

    internal async ValueTask<MessagingCryptoV1PreparationLease> AcquireReceivePreparationLeaseAsync(
        ReadOnlyMemory<byte> exactDpe2,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var envelope = exactDpe2.ToArray();
        byte[]? canonical = null;
        byte[]? sessionId = null;
        byte[]? recipientDeviceId = null;
        byte[]? operationId = null;
        byte[]? headerHash = null;
        byte[]? envelopeHash = null;
        byte[]? envelopeDigest = null;
        try
        {
            var record = Dpe2Codec.Decode(envelope);
            canonical = Dpe2Codec.Encode(record);
            if (!MessagingCryptoV1Trs1.Fixed(canonical, envelope))
                throw new CryptographicException("The receive DPE2 snapshot is not canonical.");
            sessionId = record.SessionId.ToArray();
            recipientDeviceId = record.RecipientDeviceId.ToArray();
            if (!MessagingCryptoV1Trs1.Fixed(sessionId, scope.SessionId) ||
                !MessagingCryptoV1Trs1.Fixed(recipientDeviceId, scope.LocalDeviceId))
                throw new CryptographicException(
                    "The receive DPE2 session or recipient is outside this durable scope.");
            operationId = record.OperationId.ToArray();
            headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(record);
            envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
            envelopeDigest = SHA256.HashData(envelope);
            return await AcquirePreparationLeaseAsync(
                MessagingCryptoV1PreparationKind.Receive,
                envelope, operationId, headerHash, envelopeHash, envelopeDigest,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Zero(envelope);
            if (canonical is not null) Zero(canonical);
            if (sessionId is not null) Zero(sessionId);
            if (recipientDeviceId is not null) Zero(recipientDeviceId);
            if (operationId is not null) Zero(operationId);
            if (headerHash is not null) Zero(headerHash);
            if (envelopeHash is not null) Zero(envelopeHash);
            if (envelopeDigest is not null) Zero(envelopeDigest);
        }
    }

    private async ValueTask<MessagingCryptoV1PreparationLease> AcquirePreparationLeaseAsync(
        MessagingCryptoV1PreparationKind kind,
        byte[] exactReceiveEnvelope,
        byte[] operationId,
        byte[] exactHeaderHash,
        byte[] exactEnvelopeHash,
        byte[] exactEnvelopeDigest,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: true);
            using var current = ReadCurrent(db, transaction) ??
                throw new InvalidOperationException("The TRS1 store is not initialized.");
            if (current.ForkLatched || current.TerminallyLatched)
                throw new InvalidOperationException("The TRS1 session is latched and cannot release state.");

            var replayDisposition = kind == MessagingCryptoV1PreparationKind.Receive
                ? DetermineReceiveReplayDisposition(
                    db, transaction, operationId, exactHeaderHash,
                    exactEnvelopeHash, exactEnvelopeDigest)
                : ExactDpe2ReceiveReplayDisposition.Fresh;
            var retentionCommitment = ComputeReplayRetentionCommitment(db, transaction, current);
            try
            {
                var lease = new MessagingCryptoV1PreparationLease(
                    kind,
                    current.ExactTrs1,
                    current.Generation,
                    current.StateCommitment,
                    current.Generation,
                    current.StateCommitment,
                    current.JournalGeneration,
                    current.JournalHead,
                    retentionCommitment,
                    replayDisposition,
                    exactReceiveEnvelope);
                transaction.Commit();
                return lease;
            }
            finally { CryptographicOperations.ZeroMemory(retentionCommitment); }
        }
        finally { gate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            connection?.Dispose();
            connection = null;
            CryptographicOperations.ZeroMemory(key);
        }
        finally { gate.Release(); }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(db, null, SchemaDdl);
        using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO messaging_crypto_meta VALUES(1,$database,$account,$accountGeneration,$device,$deviceGeneration,$conversation,$session);";
        Add(command, "$database", U64(scope.DatabaseGeneration));
        Add(command, "$account", scope.AccountId.ToArray());
        Add(command, "$accountGeneration", U64(scope.AccountGeneration));
        Add(command, "$device", scope.LocalDeviceId.ToArray());
        Add(command, "$deviceGeneration", U64(scope.DeviceGeneration));
        Add(command, "$conversation", scope.ConversationId.ToArray());
        Add(command, "$session", scope.SessionId.ToArray());
        command.ExecuteNonQuery();
        Execute(db, null, "PRAGMA wal_checkpoint(FULL);");
        Validate(db);
    }

    private void Validate(SqliteConnection db)
    {
        if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId)
            throw Failure(MessagingCryptoV1StoreOpenFailure.Corrupt, "Unexpected messaging-crypto application ID.");
        if (ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration)
            throw Failure(MessagingCryptoV1StoreOpenFailure.UnsupportedGeneration,
                "Unsupported messaging-crypto schema generation.");
        ValidateCipher(db);
        if (!string.Equals(Convert.ToString(Scalar(db, "PRAGMA quick_check;"), CultureInfo.InvariantCulture),
                "ok", StringComparison.OrdinalIgnoreCase))
            throw Failure(MessagingCryptoV1StoreOpenFailure.Corrupt, "Messaging-crypto quick check failed.");
        var actualSchema = HashSchemaObjects(ReadSchemaObjects(db));
        try
        {
            if (!MessagingCryptoV1Trs1.Fixed(ExpectedSchemaFingerprint, actualSchema))
                throw Failure(MessagingCryptoV1StoreOpenFailure.Corrupt,
                    "Messaging-crypto DDL differs from the sealed generation-2 schema.");
        }
        finally { CryptographicOperations.ZeroMemory(actualSchema); }

        using (var command = db.CreateCommand())
        {
            command.CommandText = "SELECT database_generation,account_id,account_generation,local_device_id,device_generation,conversation_id,session_id FROM messaging_crypto_meta WHERE singleton=1;";
            using var reader = command.ExecuteReader();
            if (!reader.Read() || !FixedColumn(reader, 0, U64(scope.DatabaseGeneration)) ||
                !FixedColumn(reader, 1, scope.AccountId) || !FixedColumn(reader, 2, U64(scope.AccountGeneration)) ||
                !FixedColumn(reader, 3, scope.LocalDeviceId) || !FixedColumn(reader, 4, U64(scope.DeviceGeneration)) ||
                !FixedColumn(reader, 5, scope.ConversationId) || !FixedColumn(reader, 6, scope.SessionId) || reader.Read())
                throw Failure(MessagingCryptoV1StoreOpenFailure.ScopeMismatch,
                    "Messaging-crypto account/device/conversation/session scope differs from the requested scope.");
        }

        ValidateRows(db);
    }

    private void ValidateRows(SqliteConnection db)
    {
        using var current = ReadCurrent(db, null);
        var journalCount = ScalarLong(db, "SELECT count(*) FROM ratchet_journal;");
        var exactDpe2Count = ScalarLong(db, "SELECT count(*) FROM exact_dpe2_plan_journal;");
        var forkCount = ScalarLong(db, "SELECT count(*) FROM ratchet_fork_latch;");
        if (current is null)
        {
            if (journalCount != 0 || exactDpe2Count != 0 || forkCount != 0)
                throw new FormatException("Orphan ratchet evidence exists.");
            return;
        }
        if (journalCount < 0 || journalCount > MessagingCryptoV1Limits.MaximumJournalEntries ||
            exactDpe2Count < 0 || exactDpe2Count > journalCount ||
            current.JournalGeneration != checked((ulong)journalCount) ||
            (current.ForkLatched ? forkCount != 1 : forkCount != 0))
            throw new FormatException("Ratchet journal/fork cardinality is inconsistent.");

        var facts = MessagingCryptoV1Trs1.Validate(current.ExactTrs1, scope);
        try
        {
            if (facts.Generation != current.Generation ||
                !MessagingCryptoV1Trs1.Fixed(facts.StateCommitment, current.StateCommitment) ||
                !MessagingCryptoV1Trs1.Fixed(facts.ExactHash, current.StateHash) ||
                facts.TerminallyLatched != current.TerminallyLatched)
                throw new FormatException("Persisted TRS1 metadata differs from its exact bytes.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
        }

        var expectedInitialization = ComputeInitializationFingerprint(
            current.InitializationOperationId,
            new MessagingCryptoV1Trs1Facts(current.InitialGeneration,
                current.InitialCommitment.ToArray(), current.InitialStateHash.ToArray(), false));
        try
        {
            if (!MessagingCryptoV1Trs1.Fixed(expectedInitialization, current.InitializationFingerprint))
                throw new FormatException("TRS1 initialization evidence is corrupt.");
        }
        finally { CryptographicOperations.ZeroMemory(expectedInitialization); }

        ValidateJournalChain(db, current);
        ValidateForkLatch(db, current);
    }

    private static void ValidateForkLatch(SqliteConnection db, CurrentRow current)
    {
        if (!current.ForkLatched) return;
        using var command = db.CreateCommand();
        command.CommandText = "SELECT collision_kind,incumbent_fingerprint,conflicting_fingerprint,incumbent_operation_id,conflicting_operation_id,incumbent_replay_token,conflicting_replay_token,incumbent_envelope_hash,conflicting_envelope_hash FROM ratchet_fork_latch WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new FormatException("Fork latch evidence is absent.");
        var kind = reader.GetInt32(0);
        var incumbentFingerprint = (byte[])reader[1];
        var conflictingFingerprint = (byte[])reader[2];
        var incumbentOperation = (byte[])reader[3];
        var conflictingOperation = (byte[])reader[4];
        var incumbentReplay = (byte[])reader[5];
        var conflictingReplay = (byte[])reader[6];
        var incumbentEnvelope = (byte[])reader[7];
        var conflictingEnvelope = (byte[])reader[8];
        try
        {
            if (reader.Read() || kind is < 1 or > 2 ||
                MessagingCryptoV1Trs1.Fixed(incumbentFingerprint, conflictingFingerprint) ||
                kind == 1 && !MessagingCryptoV1Trs1.Fixed(incumbentOperation, conflictingOperation) ||
                kind == 2 && !MessagingCryptoV1Trs1.Fixed(incumbentReplay, conflictingReplay))
                throw new FormatException("Fork latch collision evidence is invalid.");
            reader.Close();
            using var lookup = db.CreateCommand();
            lookup.CommandText = "SELECT count(*) FROM ratchet_journal WHERE transition_fingerprint=$fingerprint AND operation_id=$operation AND replay_token=$replay AND envelope_hash=$envelope;";
            Add(lookup, "$fingerprint", incumbentFingerprint); Add(lookup, "$operation", incumbentOperation);
            Add(lookup, "$replay", incumbentReplay); Add(lookup, "$envelope", incumbentEnvelope);
            if (Convert.ToInt64(lookup.ExecuteScalar(), CultureInfo.InvariantCulture) != 1)
                throw new FormatException("Fork latch incumbent has no exact journal evidence.");
        }
        finally
        {
            Zero(incumbentFingerprint, conflictingFingerprint, incumbentOperation, conflictingOperation,
                incumbentReplay, conflictingReplay, incumbentEnvelope, conflictingEnvelope);
        }
    }

    private void ValidateJournalChain(SqliteConnection db, CurrentRow current)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT journal_generation,operation_id,replay_token,transition_fingerprint,direction,prior_generation,prior_commitment,prior_state_hash,next_generation,next_commitment,next_state_hash,envelope_hash,prior_journal_head,next_journal_head,deletion_manifest_commitment,message_key_deletion_evidence,replay_evidence_commitment,pq_fence_mutation_commitment,terminal_state_commitment FROM ratchet_journal ORDER BY journal_generation;";
        using var reader = command.ExecuteReader();
        var expectedGeneration = current.InitialGeneration;
        var expectedCommitment = current.InitialCommitment.ToArray();
        var expectedStateHash = current.InitialStateHash.ToArray();
        var expectedHead = ComputeInitialJournalHead(scope);
        ulong expectedJournal = 0;
        try
        {
            while (reader.Read())
            {
                expectedJournal++;
                var row = JournalRow.Read(reader);
                using (row)
                {
                    if (row.JournalGeneration != expectedJournal || row.PriorGeneration != expectedGeneration ||
                        row.NextGeneration != checked(row.PriorGeneration + 1) ||
                        !MessagingCryptoV1Trs1.Fixed(row.PriorCommitment, expectedCommitment) ||
                        !MessagingCryptoV1Trs1.Fixed(row.PriorStateHash, expectedStateHash) ||
                        !MessagingCryptoV1Trs1.Fixed(row.PriorJournalHead, expectedHead))
                        throw new FormatException("Ratchet journal predecessor chain is corrupt.");
                    var fingerprint = ComputeTransitionFingerprint(row);
                    var head = ComputeNextJournalHead(expectedHead, expectedJournal, fingerprint);
                    try
                    {
                        if (!MessagingCryptoV1Trs1.Fixed(fingerprint, row.Fingerprint) ||
                            !MessagingCryptoV1Trs1.Fixed(head, row.NextJournalHead))
                            throw new FormatException("Ratchet journal commitment chain is corrupt.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(fingerprint);
                        CryptographicOperations.ZeroMemory(head);
                    }
                    expectedGeneration = row.NextGeneration;
                    Replace(ref expectedCommitment, row.NextCommitment);
                    Replace(ref expectedStateHash, row.NextStateHash);
                    Replace(ref expectedHead, row.NextJournalHead);
                }
            }
            if (expectedJournal != current.JournalGeneration || expectedGeneration != current.Generation ||
                !MessagingCryptoV1Trs1.Fixed(expectedCommitment, current.StateCommitment) ||
                !MessagingCryptoV1Trs1.Fixed(expectedStateHash, current.StateHash) ||
                !MessagingCryptoV1Trs1.Fixed(expectedHead, current.JournalHead))
                throw new FormatException("Ratchet current head is not the journal terminal state.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedCommitment);
            CryptographicOperations.ZeroMemory(expectedStateHash);
            CryptographicOperations.ZeroMemory(expectedHead);
        }
    }

    private MessagingCryptoV1CommitResult LatchFork(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        CollisionRow incumbent,
        MessagingCryptoV1PreparedTransition.TransitionPayload conflicting,
        byte[] conflictingFingerprint,
        int kind)
    {
        using (incumbent)
        using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ratchet_fork_latch VALUES(1,$kind,$incumbentFingerprint,$conflictingFingerprint,$incumbentOperation,$conflictingOperation,$incumbentReplay,$conflictingReplay,$incumbentEnvelope,$conflictingEnvelope);";
            Add(command, "$kind", kind);
            Add(command, "$incumbentFingerprint", incumbent.Fingerprint);
            Add(command, "$conflictingFingerprint", conflictingFingerprint);
            Add(command, "$incumbentOperation", incumbent.OperationId);
            Add(command, "$conflictingOperation", conflicting.OperationId);
            Add(command, "$incumbentReplay", incumbent.ReplayToken);
            Add(command, "$conflictingReplay", conflicting.ReplayToken);
            Add(command, "$incumbentEnvelope", incumbent.EnvelopeHash);
            Add(command, "$conflictingEnvelope", conflicting.EnvelopeHash);
            command.ExecuteNonQuery();
        }
        using (var update = db.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE ratchet_state SET fork_latched=1 WHERE singleton=1 AND fork_latched=0;";
            if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fork latch CAS failed.");
        }
        transaction.Commit();
        return new MessagingCryptoV1CommitResult(
            MessagingCryptoV1CommitDisposition.ForkLatched, current.Generation,
            current.StateCommitment.ToArray(), current.JournalGeneration,
            current.JournalHead.ToArray(), true, current.TerminallyLatched);
    }

    private MessagingCryptoV1CommitResult LatchFork(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        CollisionRow incumbent,
        byte[] conflictingOperation,
        byte[] conflictingReplay,
        byte[] conflictingEnvelope,
        byte[] conflictingFingerprint,
        int kind)
    {
        using (incumbent)
        using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ratchet_fork_latch VALUES(1,$kind,$incumbentFingerprint,$conflictingFingerprint,$incumbentOperation,$conflictingOperation,$incumbentReplay,$conflictingReplay,$incumbentEnvelope,$conflictingEnvelope);";
            Add(command, "$kind", kind);
            Add(command, "$incumbentFingerprint", incumbent.Fingerprint);
            Add(command, "$conflictingFingerprint", conflictingFingerprint);
            Add(command, "$incumbentOperation", incumbent.OperationId);
            Add(command, "$conflictingOperation", conflictingOperation);
            Add(command, "$incumbentReplay", incumbent.ReplayToken);
            Add(command, "$conflictingReplay", conflictingReplay);
            Add(command, "$incumbentEnvelope", incumbent.EnvelopeHash);
            Add(command, "$conflictingEnvelope", conflictingEnvelope);
            command.ExecuteNonQuery();
        }
        using (var update = db.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE ratchet_state SET fork_latched=1 WHERE singleton=1 AND fork_latched=0;";
            if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Fork latch CAS failed.");
        }
        transaction.Commit();
        return new MessagingCryptoV1CommitResult(
            MessagingCryptoV1CommitDisposition.ForkLatched, current.Generation,
            current.StateCommitment.ToArray(), current.JournalGeneration,
            current.JournalHead.ToArray(), true, current.TerminallyLatched);
    }

    private static void InsertJournal(
        SqliteConnection db,
        SqliteTransaction transaction,
        ulong journalGeneration,
        byte[] nextJournalHead,
        MessagingCryptoV1PreparedTransition.TransitionPayload payload,
        MessagingCryptoV1Trs1Facts prior,
        MessagingCryptoV1Trs1Facts next,
        byte[] fingerprint)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO ratchet_journal VALUES($journal,$operation,$replay,$fingerprint,$direction,$priorGeneration,$priorCommitment,$priorHash,$nextGeneration,$nextCommitment,$nextHash,$envelope,$priorHead,$nextHead,$deletion,$messageDeletion,$replayEvidence,$pqFence,$terminal);";
        Add(command, "$journal", U64(journalGeneration)); Add(command, "$operation", payload.OperationId);
        Add(command, "$replay", payload.ReplayToken); Add(command, "$fingerprint", fingerprint);
        Add(command, "$direction", (int)payload.Direction); Add(command, "$priorGeneration", U64(prior.Generation));
        Add(command, "$priorCommitment", prior.StateCommitment); Add(command, "$priorHash", prior.ExactHash);
        Add(command, "$nextGeneration", U64(next.Generation)); Add(command, "$nextCommitment", next.StateCommitment);
        Add(command, "$nextHash", next.ExactHash); Add(command, "$envelope", payload.EnvelopeHash);
        Add(command, "$priorHead", payload.JournalPredecessor); Add(command, "$nextHead", nextJournalHead);
        Add(command, "$deletion", payload.DeletionManifestCommitment);
        Add(command, "$messageDeletion", payload.MessageKeyDeletionEvidence);
        Add(command, "$replayEvidence", payload.ReplayEvidenceCommitment);
        Add(command, "$pqFence", payload.PqFenceMutationCommitment.Length == 0 ? DBNull.Value : payload.PqFenceMutationCommitment);
        Add(command, "$terminal", payload.TerminalStateCommitment.Length == 0 ? DBNull.Value : payload.TerminalStateCommitment);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Ratchet journal insert failed.");
    }

    private static void InsertJournal(
        SqliteConnection db,
        SqliteTransaction transaction,
        ulong journalGeneration,
        byte[] nextJournalHead,
        ExactDpe2ProtocolPlanSnapshot plan,
        MessagingCryptoV1Trs1Facts prior,
        MessagingCryptoV1Trs1Facts next,
        byte[] fingerprint)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO ratchet_journal VALUES($journal,$operation,$replay,$fingerprint,$direction,$priorGeneration,$priorCommitment,$priorHash,$nextGeneration,$nextCommitment,$nextHash,$envelope,$priorHead,$nextHead,$deletion,$messageDeletion,$replayEvidence,$pqFence,$terminal);";
        Add(command, "$journal", U64(journalGeneration)); Add(command, "$operation", plan.OperationId);
        Add(command, "$replay", plan.ReplayToken); Add(command, "$fingerprint", fingerprint);
        Add(command, "$direction", (int)plan.Direction); Add(command, "$priorGeneration", U64(prior.Generation));
        Add(command, "$priorCommitment", prior.StateCommitment); Add(command, "$priorHash", prior.ExactHash);
        Add(command, "$nextGeneration", U64(next.Generation)); Add(command, "$nextCommitment", next.StateCommitment);
        Add(command, "$nextHash", next.ExactHash); Add(command, "$envelope", plan.ExactEnvelopeHash);
        Add(command, "$priorHead", plan.JournalPredecessor); Add(command, "$nextHead", nextJournalHead);
        Add(command, "$deletion", plan.DeletionManifestCommitment);
        Add(command, "$messageDeletion", plan.MessageKeyDeletionEvidence);
        Add(command, "$replayEvidence", plan.ReplayEvidenceCommitment);
        Add(command, "$pqFence", plan.PqFenceMutationCommitment.Length == 0 ? DBNull.Value : plan.PqFenceMutationCommitment);
        Add(command, "$terminal", plan.TerminalStateCommitment.Length == 0 ? DBNull.Value : plan.TerminalStateCommitment);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Ratchet journal insert failed.");
    }

    private static void InsertExactDpe2Journal(
        SqliteConnection db,
        SqliteTransaction transaction,
        ulong journalGeneration,
        ExactDpe2ProtocolPlanSnapshot plan,
        byte[] planFingerprint,
        byte[] envelopeDigest)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO exact_dpe2_plan_journal VALUES($journal,$fingerprint,$header,$envelope,$digest,$checkpointGeneration,$checkpointCommitment,$dedup,1);";
        Add(command, "$journal", U64(journalGeneration)); Add(command, "$fingerprint", planFingerprint);
        Add(command, "$header", plan.ExactHeaderHash); Add(command, "$envelope", plan.ExactEnvelopeHash);
        Add(command, "$digest", envelopeDigest); Add(command, "$checkpointGeneration", U64(plan.CheckpointPriorGeneration));
        Add(command, "$checkpointCommitment", plan.CheckpointPriorCommitment);
        Add(command, "$dedup", plan.DeduplicationMutationCommitment.Length == 0
            ? DBNull.Value : plan.DeduplicationMutationCommitment);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Exact DPE2 journal insert failed.");
    }

    private static void UpdateState(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        ulong journalGeneration,
        byte[] nextJournalHead,
        MessagingCryptoV1PreparedTransition.TransitionPayload payload,
        MessagingCryptoV1Trs1Facts next)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE ratchet_state SET state_generation=$nextGeneration,state_commitment=$nextCommitment,state_hash=$nextHash,exact_trs1=$nextTrs1,journal_generation=$journal,journal_head=$nextHead,terminal_latched=$terminal WHERE singleton=1 AND state_generation=$priorGeneration AND state_commitment=$priorCommitment AND state_hash=$priorHash AND journal_generation=$priorJournal AND journal_head=$priorHead AND fork_latched=0 AND terminal_latched=0;";
        Add(command, "$nextGeneration", U64(next.Generation)); Add(command, "$nextCommitment", next.StateCommitment);
        Add(command, "$nextHash", next.ExactHash); Add(command, "$nextTrs1", payload.NextTrs1);
        Add(command, "$journal", U64(journalGeneration)); Add(command, "$nextHead", nextJournalHead);
        Add(command, "$terminal", next.TerminallyLatched ? 1 : 0);
        Add(command, "$priorGeneration", U64(current.Generation)); Add(command, "$priorCommitment", current.StateCommitment);
        Add(command, "$priorHash", current.StateHash); Add(command, "$priorJournal", U64(current.JournalGeneration));
        Add(command, "$priorHead", current.JournalHead);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Exact TRS1 CAS update failed.");
    }

    private static void UpdateState(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        ulong journalGeneration,
        byte[] nextJournalHead,
        ExactDpe2ProtocolPlanSnapshot plan,
        MessagingCryptoV1Trs1Facts next)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE ratchet_state SET state_generation=$nextGeneration,state_commitment=$nextCommitment,state_hash=$nextHash,exact_trs1=$nextTrs1,journal_generation=$journal,journal_head=$nextHead,terminal_latched=$terminal WHERE singleton=1 AND state_generation=$priorGeneration AND state_commitment=$priorCommitment AND state_hash=$priorHash AND journal_generation=$priorJournal AND journal_head=$priorHead AND fork_latched=0 AND terminal_latched=0;";
        Add(command, "$nextGeneration", U64(next.Generation)); Add(command, "$nextCommitment", next.StateCommitment);
        Add(command, "$nextHash", next.ExactHash); Add(command, "$nextTrs1", plan.NextTrs1);
        Add(command, "$journal", U64(journalGeneration)); Add(command, "$nextHead", nextJournalHead);
        Add(command, "$terminal", next.TerminallyLatched ? 1 : 0);
        Add(command, "$priorGeneration", U64(current.Generation)); Add(command, "$priorCommitment", current.StateCommitment);
        Add(command, "$priorHash", current.StateHash); Add(command, "$priorJournal", U64(current.JournalGeneration));
        Add(command, "$priorHead", current.JournalHead);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Exact TRS1 CAS update failed.");
    }

    private static bool MatchesCurrent(
        CurrentRow current,
        MessagingCryptoV1PreparedTransition.TransitionPayload payload,
        MessagingCryptoV1Trs1Facts prior) =>
        current.Generation == prior.Generation &&
        MessagingCryptoV1Trs1.Fixed(current.StateCommitment, prior.StateCommitment) &&
        MessagingCryptoV1Trs1.Fixed(current.StateHash, prior.ExactHash) &&
        MessagingCryptoV1Trs1.Fixed(current.ExactTrs1, payload.PriorTrs1) &&
        MessagingCryptoV1Trs1.Fixed(current.JournalHead, payload.JournalPredecessor);

    private static bool MatchesCurrent(
        CurrentRow current,
        ExactDpe2ProtocolPlanSnapshot plan,
        MessagingCryptoV1Trs1Facts prior) =>
        current.Generation == plan.PriorStateGeneration &&
        current.Generation == plan.CheckpointPriorGeneration &&
        current.JournalGeneration == plan.ExpectedJournalGeneration &&
        MessagingCryptoV1Trs1.Fixed(current.StateCommitment, plan.PriorStateCommitment) &&
        MessagingCryptoV1Trs1.Fixed(current.StateCommitment, plan.CheckpointPriorCommitment) &&
        MessagingCryptoV1Trs1.Fixed(current.StateCommitment, prior.StateCommitment) &&
        MessagingCryptoV1Trs1.Fixed(current.StateHash, prior.ExactHash) &&
        MessagingCryptoV1Trs1.Fixed(current.ExactTrs1, plan.PriorTrs1) &&
        MessagingCryptoV1Trs1.Fixed(current.JournalHead, plan.JournalPredecessor);

    private static void ValidateTransition(
        MessagingCryptoV1PreparedTransition.TransitionPayload payload,
        MessagingCryptoV1Trs1Facts prior,
        MessagingCryptoV1Trs1Facts next)
    {
        if (prior.TerminallyLatched) throw new InvalidOperationException("A terminal TRS1 cannot advance.");
        if (next.Generation != checked(prior.Generation + 1))
            throw new InvalidOperationException("TRS1 transition must advance exactly one storage generation.");
        var terminalCommitmentPresent = payload.TerminalStateCommitment.Length != 0;
        if (next.TerminallyLatched != terminalCommitmentPresent ||
            terminalCommitmentPresent && !MessagingCryptoV1Trs1.Fixed(
                payload.TerminalStateCommitment, next.StateCommitment))
            throw new InvalidOperationException("Terminal TRS1 state is not bound to its terminal commitment.");
        if (payload.Direction == MessagingCryptoV1Direction.RollbackLatch != next.TerminallyLatched)
            throw new InvalidOperationException("Rollback-latch direction and TRS1 terminal state disagree.");
    }

    private static void ValidateExactDpe2Shape(ExactDpe2ProtocolPlanSnapshot plan)
    {
        static void Required32(byte[] value, string name) =>
            MessagingCryptoV1PreparedTransition.Validate32(value, name);
        static void Optional32(byte[] value, string name)
        {
            if (value.Length != 0) MessagingCryptoV1PreparedTransition.Validate32(value, name);
        }

        Required32(plan.OperationId, nameof(plan.OperationId));
        Required32(plan.ReplayToken, nameof(plan.ReplayToken));
        Required32(plan.ExactHeaderHash, nameof(plan.ExactHeaderHash));
        Required32(plan.ExactEnvelopeHash, nameof(plan.ExactEnvelopeHash));
        Required32(plan.JournalPredecessor, nameof(plan.JournalPredecessor));
        Required32(plan.PriorStateCommitment, nameof(plan.PriorStateCommitment));
        Required32(plan.CheckpointPriorCommitment, nameof(plan.CheckpointPriorCommitment));
        Required32(plan.DeletionManifestCommitment, nameof(plan.DeletionManifestCommitment));
        Required32(plan.ReplayEvidenceCommitment, nameof(plan.ReplayEvidenceCommitment));
        Optional32(plan.DeduplicationMutationCommitment, nameof(plan.DeduplicationMutationCommitment));
        Optional32(plan.PqFenceMutationCommitment, nameof(plan.PqFenceMutationCommitment));
        Optional32(plan.TerminalStateCommitment, nameof(plan.TerminalStateCommitment));
        MessagingCryptoV1PreparedTransition.ValidateTrs1(plan.PriorTrs1, nameof(plan.PriorTrs1));
        if (plan.ExactEnvelope.Length is < 4_513 or > 50_705)
            throw new CryptographicException("The exact DPE2 envelope is outside its closed bound.");
        if (!MessagingCryptoV1Trs1.Fixed(plan.ReplayToken, plan.ExactEnvelopeHash))
            throw new CryptographicException("The replay token must bind the exact DPE2 envelope hash.");
        if (plan.Direction == MessagingCryptoV1Direction.Send && !plan.HasStateMutation)
            throw new CryptographicException("A send cannot be committed as a non-mutating replay.");
        if (plan.HasStateMutation)
        {
            Required32(plan.NextStateCommitment, nameof(plan.NextStateCommitment));
            Required32(plan.MessageKeyDeletionEvidence, nameof(plan.MessageKeyDeletionEvidence));
            MessagingCryptoV1PreparedTransition.ValidateTrs1(plan.NextTrs1, nameof(plan.NextTrs1));
            if (!plan.MessageKeyDeleted)
                throw new CryptographicException("A fresh DPE2 transition lacks message-key deletion evidence.");
        }
        else if (plan.NextTrs1.Length != 0 || plan.NextStateCommitment.Length != 0 ||
                 plan.MessageKeyDeletionEvidence.Length != 0 || plan.MessageKeyDeleted)
        {
            throw new CryptographicException("An exact replay cannot carry a ratchet mutation.");
        }
    }

    private static void ValidateExactDpe2Prior(
        ExactDpe2ProtocolPlanSnapshot plan,
        MessagingCryptoV1Trs1Facts prior)
    {
        if (prior.Generation != plan.PriorStateGeneration ||
            !MessagingCryptoV1Trs1.Fixed(prior.StateCommitment, plan.PriorStateCommitment))
            throw new CryptographicException("The exact DPE2 plan does not bind its prior TRS1.");
        if (plan.CheckpointPriorGeneration < plan.PriorStateGeneration)
            throw new CryptographicException("The protected checkpoint precedes the plan state.");
    }

    private static void ValidateExactDpe2Next(
        ExactDpe2ProtocolPlanSnapshot plan,
        MessagingCryptoV1Trs1Facts prior,
        MessagingCryptoV1Trs1Facts next)
    {
        if (prior.TerminallyLatched || next.Generation != checked(prior.Generation + 1) ||
            next.Generation != plan.NextStateGeneration ||
            !MessagingCryptoV1Trs1.Fixed(next.StateCommitment, plan.NextStateCommitment))
            throw new CryptographicException("The exact DPE2 plan does not bind its next TRS1 transition.");
        var terminal = plan.TerminalStateCommitment.Length != 0;
        if (next.TerminallyLatched != terminal || terminal &&
            !MessagingCryptoV1Trs1.Fixed(next.StateCommitment, plan.TerminalStateCommitment))
            throw new CryptographicException("The exact DPE2 terminal commitment is inconsistent.");
    }

    private static byte[] ComputeExactDpe2PlanFingerprint(ExactDpe2ProtocolPlanSnapshot plan)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/exact-dpe2-plan"u8);
        Append(hash, [(byte)plan.Direction, plan.HasStateMutation ? (byte)1 : (byte)0,
            plan.MessageKeyDeleted ? (byte)1 : (byte)0]);
        Append(hash, U64(plan.PriorStateGeneration)); Append(hash, U64(plan.NextStateGeneration));
        Append(hash, U64(plan.CheckpointPriorGeneration)); Append(hash, U64(plan.ExpectedJournalGeneration));
        Append(hash, plan.OperationId); Append(hash, plan.ReplayToken); Append(hash, plan.ExactHeaderHash);
        Append(hash, plan.ExactEnvelopeHash); Append(hash, plan.ExactEnvelope);
        Append(hash, plan.JournalPredecessor); Append(hash, plan.PriorTrs1); Append(hash, plan.NextTrs1);
        Append(hash, plan.PriorStateCommitment); Append(hash, plan.NextStateCommitment);
        Append(hash, plan.CheckpointPriorCommitment); Append(hash, plan.DeletionManifestCommitment);
        Append(hash, plan.MessageKeyDeletionEvidence); Append(hash, plan.ReplayEvidenceCommitment);
        Append(hash, plan.DeduplicationMutationCommitment); Append(hash, plan.PqFenceMutationCommitment);
        Append(hash, plan.TerminalStateCommitment);
        return hash.GetHashAndReset();
    }

    private static bool IsExactDpe2Retry(
        SqliteConnection db,
        SqliteTransaction transaction,
        CollisionRow incumbent,
        byte[] planFingerprint,
        byte[] envelopeDigest)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT plan_fingerprint,exact_envelope_digest FROM exact_dpe2_plan_journal WHERE journal_generation=$journal;";
        Add(command, "$journal", U64(incumbent.JournalGeneration));
        using var reader = command.ExecuteReader();
        return reader.Read() &&
            FixedColumn(reader, 0, planFingerprint) &&
            FixedColumn(reader, 1, envelopeDigest) && !reader.Read();
    }

    private static bool IsAuthenticatedReceiveReplay(
        SqliteConnection db,
        SqliteTransaction transaction,
        CollisionRow incumbent,
        ExactDpe2ProtocolPlanSnapshot plan,
        CurrentRow current,
        MessagingCryptoV1Trs1Facts prior,
        byte[] envelopeDigest)
    {
        if (plan.Direction != MessagingCryptoV1Direction.Receive ||
            !MatchesCurrent(current, plan, prior) ||
            !MessagingCryptoV1Trs1.Fixed(incumbent.OperationId, plan.OperationId) ||
            !MessagingCryptoV1Trs1.Fixed(incumbent.ReplayToken, plan.ReplayToken) ||
            !MessagingCryptoV1Trs1.Fixed(incumbent.EnvelopeHash, plan.ExactEnvelopeHash))
            return false;
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT exact_header_hash,exact_envelope_hash,exact_envelope_digest FROM exact_dpe2_plan_journal WHERE journal_generation=$journal;";
        Add(command, "$journal", U64(incumbent.JournalGeneration));
        using var reader = command.ExecuteReader();
        return reader.Read() && FixedColumn(reader, 0, plan.ExactHeaderHash) &&
            FixedColumn(reader, 1, plan.ExactEnvelopeHash) &&
            FixedColumn(reader, 2, envelopeDigest) && !reader.Read();
    }

    private ExactDpe2ReceiveReplayDisposition DetermineReceiveReplayDisposition(
        SqliteConnection db,
        SqliteTransaction transaction,
        byte[] operationId,
        byte[] exactHeaderHash,
        byte[] exactEnvelopeHash,
        byte[] exactEnvelopeDigest)
    {
        using var operation = ReadCollision(db, transaction, "operation_id", operationId);
        using var replay = ReadCollision(db, transaction, "replay_token", exactEnvelopeHash);
        if (operation is null && replay is null)
            return ExactDpe2ReceiveReplayDisposition.Fresh;

        if (operation is null || replay is null ||
            operation.JournalGeneration != replay.JournalGeneration ||
            !MessagingCryptoV1Trs1.Fixed(operation.OperationId, operationId) ||
            !MessagingCryptoV1Trs1.Fixed(operation.ReplayToken, exactEnvelopeHash) ||
            !MessagingCryptoV1Trs1.Fixed(operation.EnvelopeHash, exactEnvelopeHash) ||
            !MessagingCryptoV1Trs1.Fixed(replay.OperationId, operationId) ||
            !MessagingCryptoV1Trs1.Fixed(replay.ReplayToken, exactEnvelopeHash) ||
            !MessagingCryptoV1Trs1.Fixed(replay.EnvelopeHash, exactEnvelopeHash))
            throw new CryptographicException(
                "The receive DPE2 collides with retained replay evidence.");

        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT exact_header_hash,exact_envelope_hash,exact_envelope_digest FROM exact_dpe2_plan_journal WHERE journal_generation=$journal;";
        Add(command, "$journal", U64(operation.JournalGeneration));
        using var reader = command.ExecuteReader();
        if (!reader.Read() ||
            !FixedColumn(reader, 0, exactHeaderHash) ||
            !FixedColumn(reader, 1, exactEnvelopeHash) ||
            !FixedColumn(reader, 2, exactEnvelopeDigest) ||
            reader.Read())
            throw new CryptographicException(
                "The receive DPE2 differs from its retained exact replay evidence.");
        return ExactDpe2ReceiveReplayDisposition.ExactReplay;
    }

    private byte[] ComputeReplayRetentionCommitment(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current)
    {
        using var count = db.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = "SELECT count(*) FROM exact_dpe2_plan_journal;";
        var exactDpe2Count = Convert.ToInt64(count.ExecuteScalar(), CultureInfo.InvariantCulture);
        if (exactDpe2Count < 0 || (ulong)exactDpe2Count > current.JournalGeneration)
            throw new FormatException("Exact DPE2 replay-retention cardinality is inconsistent.");

        // Policy generation 1 retains every exact DPE2 replay row for the whole
        // bounded generation-2 session journal. A future compaction/rollover is
        // a new policy generation, never an implicit reinterpretation here.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/replay-retention/v1"u8);
        Append(hash, U64(1));
        Append(hash, U64(SchemaGeneration));
        Append(hash, U64(MessagingCryptoV1Limits.MaximumJournalEntries));
        Append(hash, U64(current.JournalGeneration == 0 ? 0UL : 1UL));
        Append(hash, U64(current.JournalGeneration));
        Append(hash, U64(checked((ulong)exactDpe2Count)));
        Append(hash, scope.SessionId);
        Append(hash, U64(scope.DatabaseGeneration));
        Append(hash, current.JournalHead);
        var commitment = hash.GetHashAndReset();
        if (commitment.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(commitment);
            throw new CryptographicException("The replay-retention commitment is invalid.");
        }
        return commitment;
    }

    private static byte[] ComputeInitializationFingerprint(
        ReadOnlySpan<byte> operationId,
        MessagingCryptoV1Trs1Facts facts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/initialization"u8);
        Append(hash, operationId); Append(hash, U64(facts.Generation));
        Append(hash, facts.StateCommitment); Append(hash, facts.ExactHash);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeTransitionFingerprint(
        MessagingCryptoV1PreparedTransition.TransitionPayload payload,
        MessagingCryptoV1Trs1Facts prior,
        MessagingCryptoV1Trs1Facts next) => ComputeTransitionFingerprint(
            payload.Direction, payload.OperationId, payload.ReplayToken, payload.EnvelopeHash,
            prior.Generation, prior.StateCommitment, prior.ExactHash,
            next.Generation, next.StateCommitment, next.ExactHash,
            payload.JournalPredecessor, payload.DeletionManifestCommitment,
            payload.MessageKeyDeletionEvidence, payload.ReplayEvidenceCommitment,
            payload.PqFenceMutationCommitment, payload.TerminalStateCommitment);

    private static byte[] ComputeTransitionFingerprint(JournalRow row) => ComputeTransitionFingerprint(
        row.Direction, row.OperationId, row.ReplayToken, row.EnvelopeHash,
        row.PriorGeneration, row.PriorCommitment, row.PriorStateHash,
        row.NextGeneration, row.NextCommitment, row.NextStateHash,
        row.PriorJournalHead, row.DeletionManifestCommitment,
        row.MessageKeyDeletionEvidence, row.ReplayEvidenceCommitment,
        row.PqFenceMutationCommitment, row.TerminalStateCommitment);

    private static byte[] ComputeTransitionFingerprint(
        MessagingCryptoV1Direction direction,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> replayToken,
        ReadOnlySpan<byte> envelopeHash,
        ulong priorGeneration,
        ReadOnlySpan<byte> priorCommitment,
        ReadOnlySpan<byte> priorHash,
        ulong nextGeneration,
        ReadOnlySpan<byte> nextCommitment,
        ReadOnlySpan<byte> nextHash,
        ReadOnlySpan<byte> priorJournalHead,
        ReadOnlySpan<byte> deletionManifest,
        ReadOnlySpan<byte> messageKeyDeletion,
        ReadOnlySpan<byte> replayEvidence,
        ReadOnlySpan<byte> pqFence,
        ReadOnlySpan<byte> terminalCommitment)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/transition"u8);
        Append(hash, [(byte)direction]); Append(hash, operationId); Append(hash, replayToken);
        Append(hash, envelopeHash); Append(hash, U64(priorGeneration)); Append(hash, priorCommitment);
        Append(hash, priorHash); Append(hash, U64(nextGeneration)); Append(hash, nextCommitment);
        Append(hash, nextHash); Append(hash, priorJournalHead); Append(hash, deletionManifest);
        Append(hash, messageKeyDeletion); Append(hash, replayEvidence); Append(hash, pqFence);
        Append(hash, terminalCommitment);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeInitialJournalHead(MessagingCryptoV1StoreScope scope)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/journal-genesis"u8);
        Append(hash, scope.AccountId); Append(hash, U64(scope.AccountGeneration));
        Append(hash, scope.LocalDeviceId); Append(hash, U64(scope.DeviceGeneration));
        Append(hash, scope.ConversationId); Append(hash, scope.SessionId);
        Append(hash, U64(scope.DatabaseGeneration));
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeNextJournalHead(
        ReadOnlySpan<byte> priorHead,
        ulong generation,
        ReadOnlySpan<byte> fingerprint)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/journal-step"u8);
        Append(hash, priorHead); Append(hash, U64(generation)); Append(hash, fingerprint);
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length); hash.AppendData(value);
    }

    private CollisionRow? ReadCollision(
        SqliteConnection db,
        SqliteTransaction transaction,
        string column,
        byte[] value)
    {
        if (column is not ("operation_id" or "replay_token")) throw new ArgumentOutOfRangeException(nameof(column));
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"SELECT transition_fingerprint,operation_id,replay_token,envelope_hash,journal_generation,next_generation,next_commitment,next_journal_head,terminal_state_commitment FROM ratchet_journal WHERE {column}=$value;";
        Add(command, "$value", value); using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var result = new CollisionRow((byte[])reader[0], (byte[])reader[1], (byte[])reader[2], (byte[])reader[3],
            ReadU64((byte[])reader[4]), ReadU64((byte[])reader[5]), (byte[])reader[6], (byte[])reader[7],
            !reader.IsDBNull(8));
        if (reader.Read()) { result.Dispose(); throw new FormatException("Duplicate ratchet collision rows exist."); }
        return result;
    }

    private CurrentRow? ReadCurrent(SqliteConnection db, SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT state_generation,state_commitment,state_hash,exact_trs1,journal_generation,journal_head,fork_latched,terminal_latched,initialization_operation_id,initialization_fingerprint,initial_generation,initial_commitment,initial_state_hash FROM ratchet_state WHERE singleton=1;";
        using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        var result = new CurrentRow(ReadU64((byte[])reader[0]), (byte[])reader[1], (byte[])reader[2],
            (byte[])reader[3], ReadU64((byte[])reader[4]), (byte[])reader[5], reader.GetInt32(6) == 1,
            reader.GetInt32(7) == 1, (byte[])reader[8], (byte[])reader[9], ReadU64((byte[])reader[10]),
            (byte[])reader[11], (byte[])reader[12]);
        if (reader.Read()) { result.Dispose(); throw new FormatException("Duplicate current TRS1 rows exist."); }
        return result;
    }

    private static MessagingCryptoV1CommitResult Result(
        MessagingCryptoV1CommitDisposition disposition,
        CurrentRow current) => new(disposition, current.Generation, current.StateCommitment.ToArray(),
        current.JournalGeneration, current.JournalHead.ToArray(), current.ForkLatched,
        current.TerminallyLatched);

    private static MessagingCryptoV1CommitResult ExactReplayResult(CollisionRow row) => new(
        MessagingCryptoV1CommitDisposition.ExactReplay, row.NextGeneration,
        row.NextCommitment.ToArray(), row.JournalGeneration, row.NextJournalHead.ToArray(),
        false, row.TerminallyLatched);

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try
        {
            db.Open();
            var result = SQLitePCL.raw.sqlite3_key(db.Handle, key);
            if (result != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected the messaging-crypto key.", result);
            Execute(db, null, "PRAGMA cipher_memory_security=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;");
            return db;
        }
        catch { db.Dispose(); throw; }
    }

    private static void ValidateCipher(SqliteConnection db)
    {
        if (Scalar(db, "PRAGMA cipher_version;") is not string version ||
            !version.StartsWith("4.", StringComparison.Ordinal))
            throw new InvalidOperationException("SQLCipher v4 is unavailable.");
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA cipher_integrity_check;";
        using var reader = command.ExecuteReader();
        while (reader.Read())
            if (!string.Equals(reader.GetString(0), "ok", StringComparison.OrdinalIgnoreCase))
                throw new FormatException("SQLCipher integrity check failed.");
    }

    private void ValidateEncryptedHeader()
    {
        using var stream = new FileStream(statePath, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        Span<byte> header = stackalloc byte[16];
        if (stream.Read(header) != header.Length) throw new FormatException("Encrypted database header is truncated.");
        if (header.SequenceEqual("SQLite format 3\0"u8))
            throw new FormatException("Messaging-crypto database has a plaintext SQLite header.");
    }

    private SqliteConnection GetConnection() => connection ??
        throw new ObjectDisposedException(nameof(SqliteMessagingCryptoV1Store));
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static ulong ReadU64(ReadOnlySpan<byte> value) => value.Length == 8
        ? BinaryPrimitives.ReadUInt64BigEndian(value) : throw new FormatException("Expected canonical u64be.");
    private static void Add(SqliteCommand command, string name, object value) => command.Parameters.AddWithValue(name, value);
    private static object? Scalar(SqliteConnection db, string sql) { using var command = db.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar(); }
    private static long ScalarLong(SqliteConnection db, string sql) => Convert.ToInt64(Scalar(db, sql), CultureInfo.InvariantCulture);
    private static void Execute(SqliteConnection db, SqliteTransaction? transaction, string sql) { using var command = db.CreateCommand(); command.Transaction = transaction; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static bool FixedColumn(SqliteDataReader reader, int ordinal, ReadOnlySpan<byte> expected) =>
        reader[ordinal] is byte[] value && MessagingCryptoV1Trs1.Fixed(value, expected);

    private static string[] ExpectedSchemaObjects() => SchemaDdl
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(statement =>
        {
            var match = Regex.Match(statement, @"^CREATE\s+TABLE\s+([a-z0-9_]+)",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (!match.Success) throw new InvalidOperationException("Sealed messaging-crypto schema is malformed.");
            return $"table|{match.Groups[1].Value}|{match.Groups[1].Value}|{NormalizeSql(statement)}";
        }).OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    private static string[] ReadSchemaObjects(SqliteConnection db)
    {
        using var command = db.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name,tbl_name;";
        using var reader = command.ExecuteReader(); var rows = new List<string>();
        while (reader.Read()) rows.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{reader.GetString(2)}|{NormalizeSql(reader.GetString(3))}");
        return rows.ToArray();
    }
    private static string NormalizeSql(string sql) => Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");
    private static byte[] HashSchemaObjects(IEnumerable<string> rows) =>
        SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join('\n', rows)));
    private static void Replace(ref byte[] target, ReadOnlySpan<byte> replacement)
    {
        CryptographicOperations.ZeroMemory(target); target = replacement.ToArray();
    }
    private static MessagingCryptoV1StoreOpenException Failure(
        MessagingCryptoV1StoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);

    private sealed class CurrentRow(
        ulong generation, byte[] stateCommitment, byte[] stateHash, byte[] exactTrs1,
        ulong journalGeneration, byte[] journalHead, bool forkLatched, bool terminallyLatched,
        byte[] initializationOperationId, byte[] initializationFingerprint,
        ulong initialGeneration, byte[] initialCommitment, byte[] initialStateHash) : IDisposable
    {
        internal ulong Generation { get; } = generation;
        internal byte[] StateCommitment { get; } = stateCommitment;
        internal byte[] StateHash { get; } = stateHash;
        internal byte[] ExactTrs1 { get; } = exactTrs1;
        internal ulong JournalGeneration { get; } = journalGeneration;
        internal byte[] JournalHead { get; } = journalHead;
        internal bool ForkLatched { get; } = forkLatched;
        internal bool TerminallyLatched { get; } = terminallyLatched;
        internal byte[] InitializationOperationId { get; } = initializationOperationId;
        internal byte[] InitializationFingerprint { get; } = initializationFingerprint;
        internal ulong InitialGeneration { get; } = initialGeneration;
        internal byte[] InitialCommitment { get; } = initialCommitment;
        internal byte[] InitialStateHash { get; } = initialStateHash;
        public void Dispose() => Zero(StateCommitment, StateHash, ExactTrs1, JournalHead,
            InitializationOperationId, InitializationFingerprint, InitialCommitment, InitialStateHash);
    }

    private sealed class CollisionRow(
        byte[] fingerprint,
        byte[] operationId,
        byte[] replayToken,
        byte[] envelopeHash,
        ulong journalGeneration,
        ulong nextGeneration,
        byte[] nextCommitment,
        byte[] nextJournalHead,
        bool terminallyLatched) : IDisposable
    {
        internal byte[] Fingerprint { get; } = fingerprint;
        internal byte[] OperationId { get; } = operationId;
        internal byte[] ReplayToken { get; } = replayToken;
        internal byte[] EnvelopeHash { get; } = envelopeHash;
        internal ulong JournalGeneration { get; } = journalGeneration;
        internal ulong NextGeneration { get; } = nextGeneration;
        internal byte[] NextCommitment { get; } = nextCommitment;
        internal byte[] NextJournalHead { get; } = nextJournalHead;
        internal bool TerminallyLatched { get; } = terminallyLatched;
        public void Dispose() => Zero(Fingerprint, OperationId, ReplayToken, EnvelopeHash,
            NextCommitment, NextJournalHead);
    }

    private sealed class JournalRow : IDisposable
    {
        private JournalRow() { }
        internal ulong JournalGeneration { get; private init; }
        internal byte[] OperationId { get; private init; } = [];
        internal byte[] ReplayToken { get; private init; } = [];
        internal byte[] Fingerprint { get; private init; } = [];
        internal MessagingCryptoV1Direction Direction { get; private init; }
        internal ulong PriorGeneration { get; private init; }
        internal byte[] PriorCommitment { get; private init; } = [];
        internal byte[] PriorStateHash { get; private init; } = [];
        internal ulong NextGeneration { get; private init; }
        internal byte[] NextCommitment { get; private init; } = [];
        internal byte[] NextStateHash { get; private init; } = [];
        internal byte[] EnvelopeHash { get; private init; } = [];
        internal byte[] PriorJournalHead { get; private init; } = [];
        internal byte[] NextJournalHead { get; private init; } = [];
        internal byte[] DeletionManifestCommitment { get; private init; } = [];
        internal byte[] MessageKeyDeletionEvidence { get; private init; } = [];
        internal byte[] ReplayEvidenceCommitment { get; private init; } = [];
        internal byte[] PqFenceMutationCommitment { get; private init; } = [];
        internal byte[] TerminalStateCommitment { get; private init; } = [];

        internal static JournalRow Read(SqliteDataReader reader)
        {
            var direction = (MessagingCryptoV1Direction)reader.GetInt32(4);
            if (!Enum.IsDefined(direction)) throw new FormatException("Unknown ratchet journal direction.");
            return new JournalRow
            {
                JournalGeneration = ReadU64((byte[])reader[0]), OperationId = (byte[])reader[1],
                ReplayToken = (byte[])reader[2], Fingerprint = (byte[])reader[3], Direction = direction,
                PriorGeneration = ReadU64((byte[])reader[5]), PriorCommitment = (byte[])reader[6],
                PriorStateHash = (byte[])reader[7], NextGeneration = ReadU64((byte[])reader[8]),
                NextCommitment = (byte[])reader[9], NextStateHash = (byte[])reader[10],
                EnvelopeHash = (byte[])reader[11], PriorJournalHead = (byte[])reader[12],
                NextJournalHead = (byte[])reader[13], DeletionManifestCommitment = (byte[])reader[14],
                MessageKeyDeletionEvidence = (byte[])reader[15], ReplayEvidenceCommitment = (byte[])reader[16],
                PqFenceMutationCommitment = reader.IsDBNull(17) ? [] : (byte[])reader[17],
                TerminalStateCommitment = reader.IsDBNull(18) ? [] : (byte[])reader[18],
            };
        }

        public void Dispose() => Zero(OperationId, ReplayToken, Fingerprint, PriorCommitment,
            PriorStateHash, NextCommitment, NextStateHash, EnvelopeHash, PriorJournalHead,
            NextJournalHead, DeletionManifestCommitment, MessageKeyDeletionEvidence,
            ReplayEvidenceCommitment, PqFenceMutationCommitment, TerminalStateCommitment);
    }

    private static void Zero(params byte[][] values)
    {
        foreach (var value in values) CryptographicOperations.ZeroMemory(value);
    }
}
