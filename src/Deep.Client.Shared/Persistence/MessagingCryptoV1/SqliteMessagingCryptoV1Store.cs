using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.ContactV1;
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
    private const int SchemaGeneration = 5;
    // Replay-retention context generation is a cryptographic wire/domain value,
    // not the physical SQLite schema version. Generation 5 adds the initiator
    // DPH2 outbox and does not redefine the generation-3 replay set.
    private const int ReplayRetentionContextGeneration = 3;
    private const string SchemaDdl = """
        CREATE TABLE messaging_crypto_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),account_id BLOB NOT NULL CHECK(length(account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),local_device_id BLOB NOT NULL CHECK(length(local_device_id)=32),device_generation BLOB NOT NULL CHECK(length(device_generation)=8),conversation_id BLOB NOT NULL CHECK(length(conversation_id)=32),session_id BLOB NOT NULL CHECK(length(session_id)=32));
        CREATE TABLE ratchet_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),state_generation BLOB NOT NULL CHECK(length(state_generation)=8),state_commitment BLOB NOT NULL CHECK(length(state_commitment)=32),state_hash BLOB NOT NULL CHECK(length(state_hash)=32),exact_trs1 BLOB NOT NULL CHECK(length(exact_trs1) BETWEEN 600 AND 2097152),journal_generation BLOB NOT NULL CHECK(length(journal_generation)=8),journal_head BLOB NOT NULL CHECK(length(journal_head)=32),fork_latched INTEGER NOT NULL CHECK(fork_latched IN(0,1)),terminal_latched INTEGER NOT NULL CHECK(terminal_latched IN(0,1)),initialization_operation_id BLOB NOT NULL CHECK(length(initialization_operation_id)=32),initialization_fingerprint BLOB NOT NULL CHECK(length(initialization_fingerprint)=32),initial_generation BLOB NOT NULL CHECK(length(initial_generation)=8),initial_commitment BLOB NOT NULL CHECK(length(initial_commitment)=32),initial_state_hash BLOB NOT NULL CHECK(length(initial_state_hash)=32));
        CREATE TABLE ratchet_journal(journal_generation BLOB PRIMARY KEY CHECK(length(journal_generation)=8),operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=32),replay_token BLOB NOT NULL UNIQUE CHECK(length(replay_token)=32),transition_fingerprint BLOB NOT NULL CHECK(length(transition_fingerprint)=32),direction INTEGER NOT NULL CHECK(direction BETWEEN 1 AND 3),prior_generation BLOB NOT NULL CHECK(length(prior_generation)=8),prior_commitment BLOB NOT NULL CHECK(length(prior_commitment)=32),prior_state_hash BLOB NOT NULL CHECK(length(prior_state_hash)=32),next_generation BLOB NOT NULL CHECK(length(next_generation)=8),next_commitment BLOB NOT NULL CHECK(length(next_commitment)=32),next_state_hash BLOB NOT NULL CHECK(length(next_state_hash)=32),envelope_hash BLOB NOT NULL CHECK(length(envelope_hash)=32),prior_journal_head BLOB NOT NULL CHECK(length(prior_journal_head)=32),next_journal_head BLOB NOT NULL CHECK(length(next_journal_head)=32),deletion_manifest_commitment BLOB NOT NULL CHECK(length(deletion_manifest_commitment)=32),message_key_deletion_evidence BLOB NOT NULL CHECK(length(message_key_deletion_evidence)=32),replay_evidence_commitment BLOB NOT NULL CHECK(length(replay_evidence_commitment)=32),pq_fence_mutation_commitment BLOB NULL CHECK(pq_fence_mutation_commitment IS NULL OR length(pq_fence_mutation_commitment)=32),terminal_state_commitment BLOB NULL CHECK(terminal_state_commitment IS NULL OR length(terminal_state_commitment)=32));
        CREATE TABLE ratchet_fork_latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),collision_kind INTEGER NOT NULL CHECK(collision_kind IN(1,2)),incumbent_fingerprint BLOB NOT NULL CHECK(length(incumbent_fingerprint)=32),conflicting_fingerprint BLOB NOT NULL CHECK(length(conflicting_fingerprint)=32),incumbent_operation_id BLOB NOT NULL CHECK(length(incumbent_operation_id)=32),conflicting_operation_id BLOB NOT NULL CHECK(length(conflicting_operation_id)=32),incumbent_replay_token BLOB NOT NULL CHECK(length(incumbent_replay_token)=32),conflicting_replay_token BLOB NOT NULL CHECK(length(conflicting_replay_token)=32),incumbent_envelope_hash BLOB NOT NULL CHECK(length(incumbent_envelope_hash)=32),conflicting_envelope_hash BLOB NOT NULL CHECK(length(conflicting_envelope_hash)=32),CHECK(incumbent_fingerprint<>conflicting_fingerprint));
        CREATE TABLE initial_prekey_inventory(prekey_kind INTEGER NOT NULL CHECK(prekey_kind IN(1,2)),prekey_id BLOB NOT NULL CHECK(length(prekey_id)=32),opaque_sealed_record BLOB NOT NULL CHECK(length(opaque_sealed_record) BETWEEN 32 AND 2097152),PRIMARY KEY(prekey_kind,prekey_id));
        CREATE TABLE initial_session_journal(singleton INTEGER PRIMARY KEY CHECK(singleton=1),prekey_source INTEGER NOT NULL CHECK(prekey_source IN(1,2,3)),claim_operation_id BLOB NOT NULL UNIQUE CHECK(length(claim_operation_id)=32),initialization_fingerprint BLOB NOT NULL CHECK(length(initialization_fingerprint)=32),xpc1_full_replay_hash BLOB NOT NULL CHECK(length(xpc1_full_replay_hash)=32),dph2_full_replay_hash BLOB NOT NULL CHECK(length(dph2_full_replay_hash)=32),x25519_prekey_id BLOB NULL UNIQUE CHECK(x25519_prekey_id IS NULL OR length(x25519_prekey_id)=32),mlkem_prekey_id BLOB NOT NULL UNIQUE CHECK(length(mlkem_prekey_id)=32),initial_generation BLOB NOT NULL CHECK(length(initial_generation)=8),initial_commitment BLOB NOT NULL CHECK(length(initial_commitment)=32),initial_state_hash BLOB NOT NULL CHECK(length(initial_state_hash)=32),CHECK((prekey_source=3 AND x25519_prekey_id IS NULL) OR (prekey_source IN(1,2) AND x25519_prekey_id IS NOT NULL)));
        CREATE TABLE initial_session_fork_latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),collision_kind INTEGER NOT NULL CHECK(collision_kind IN(1,2,3)),incumbent_fingerprint BLOB NOT NULL CHECK(length(incumbent_fingerprint)=32),conflicting_fingerprint BLOB NOT NULL CHECK(length(conflicting_fingerprint)=32),incumbent_operation_id BLOB NOT NULL CHECK(length(incumbent_operation_id)=32),conflicting_operation_id BLOB NOT NULL CHECK(length(conflicting_operation_id)=32),incumbent_x25519_prekey_id BLOB NULL CHECK(incumbent_x25519_prekey_id IS NULL OR length(incumbent_x25519_prekey_id)=32),conflicting_x25519_prekey_id BLOB NULL CHECK(conflicting_x25519_prekey_id IS NULL OR length(conflicting_x25519_prekey_id)=32),incumbent_mlkem_prekey_id BLOB NOT NULL CHECK(length(incumbent_mlkem_prekey_id)=32),conflicting_mlkem_prekey_id BLOB NOT NULL CHECK(length(conflicting_mlkem_prekey_id)=32),CHECK(incumbent_fingerprint<>conflicting_fingerprint));
        CREATE TABLE initiator_initial_session_outbox(singleton INTEGER PRIMARY KEY CHECK(singleton=1),claim_operation_id BLOB NOT NULL UNIQUE CHECK(length(claim_operation_id)=32),initialization_fingerprint BLOB NOT NULL CHECK(length(initialization_fingerprint)=32),session_id BLOB NOT NULL UNIQUE CHECK(length(session_id)=32),full_dph2_replay_hash BLOB NOT NULL UNIQUE CHECK(length(full_dph2_replay_hash)=32),claim_binding BLOB NOT NULL UNIQUE CHECK(length(claim_binding)=32),exact_dph2 BLOB NOT NULL CHECK(length(exact_dph2) IN(5917,18205,34589)),network_id BLOB NOT NULL CHECK(length(network_id)=16),local_account_id BLOB NOT NULL CHECK(length(local_account_id)=32),local_account_generation BLOB NOT NULL CHECK(length(local_account_generation)=8),local_device_id BLOB NOT NULL CHECK(length(local_device_id)=32),local_device_generation BLOB NOT NULL CHECK(length(local_device_generation)=8),contact_store_generation INTEGER NOT NULL CHECK(contact_store_generation>0),contact_relationship_id BLOB NOT NULL CHECK(length(contact_relationship_id)=32),contact_conversation_id BLOB NOT NULL CHECK(length(contact_conversation_id)=32),contact_evidence_hash BLOB NOT NULL CHECK(length(contact_evidence_hash)=32),peer_package_hash BLOB NOT NULL CHECK(length(peer_package_hash)=32),remote_account_id BLOB NOT NULL CHECK(length(remote_account_id)=32),remote_account_generation BLOB NOT NULL CHECK(length(remote_account_generation)=8),remote_directory_generation BLOB NOT NULL CHECK(length(remote_directory_generation)=8),remote_device_id BLOB NOT NULL CHECK(length(remote_device_id)=32),remote_device_generation BLOB NOT NULL CHECK(length(remote_device_generation)=8),initial_generation BLOB NOT NULL CHECK(length(initial_generation)=8),initial_commitment BLOB NOT NULL CHECK(length(initial_commitment)=32),initial_state_hash BLOB NOT NULL CHECK(length(initial_state_hash)=32));
        CREATE TABLE initiator_initial_session_fork_latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),incumbent_fingerprint BLOB NOT NULL CHECK(length(incumbent_fingerprint)=32),conflicting_fingerprint BLOB NOT NULL CHECK(length(conflicting_fingerprint)=32),incumbent_operation_id BLOB NOT NULL CHECK(length(incumbent_operation_id)=32),conflicting_operation_id BLOB NOT NULL CHECK(length(conflicting_operation_id)=32),incumbent_session_id BLOB NOT NULL CHECK(length(incumbent_session_id)=32),conflicting_session_id BLOB NOT NULL CHECK(length(conflicting_session_id)=32),incumbent_dph2_hash BLOB NOT NULL CHECK(length(incumbent_dph2_hash)=32),conflicting_dph2_hash BLOB NOT NULL CHECK(length(conflicting_dph2_hash)=32),CHECK(incumbent_fingerprint<>conflicting_fingerprint));
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

    internal bool OwnsSession(ReadOnlySpan<byte> sessionId) =>
        MessagingCryptoV1Trs1.Fixed(scope.SessionId, sessionId);

    internal bool OwnsContactInitialSession(
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> sessionId) =>
        MessagingCryptoV1Trs1.Fixed(scope.AccountId, accountId) &&
        MessagingCryptoV1Trs1.Fixed(scope.LocalDeviceId, localDeviceId) &&
        scope.DeviceGeneration == localDeviceGeneration &&
        MessagingCryptoV1Trs1.Fixed(scope.ConversationId, conversationId) &&
        MessagingCryptoV1Trs1.Fixed(scope.SessionId, sessionId);

    internal void RequireInitiatorScope(InitiatorInitialSessionVerifiedScope verifiedScope)
    {
        ArgumentNullException.ThrowIfNull(verifiedScope);
        RequireInitiatorScopeValues(
            verifiedScope.LocalAccountId,
            verifiedScope.ConversationId,
            scope.SessionId);
    }

    internal void RequireInitiatorScopeValues(
        ReadOnlySpan<byte> localAccountId,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> sessionId)
    {
        if (!MessagingCryptoV1Trs1.Fixed(scope.AccountId, localAccountId) ||
            !MessagingCryptoV1Trs1.Fixed(scope.ConversationId, conversationId) ||
            !MessagingCryptoV1Trs1.Fixed(scope.SessionId, sessionId))
            throw new CryptographicException(
                "The initiator DPH2 capability is outside this account/contact/session store scope.");
    }

    internal void RequireInitiatorDph2Values(
        ReadOnlySpan<byte> localAccountId,
        ReadOnlySpan<byte> localDeviceId,
        ulong localDeviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> sessionId)
    {
        RequireInitiatorScopeValues(localAccountId, conversationId, sessionId);
        if (!MessagingCryptoV1Trs1.Fixed(scope.LocalDeviceId, localDeviceId) ||
            scope.DeviceGeneration != localDeviceGeneration)
            throw new CryptographicException(
                "The initiator DPH2 local-device generation is outside this store scope.");
    }

    internal async ValueTask<MessagingCryptoV1CommitResult> CommitInitiatorInitialSessionAsync(
        InitiatorInitialSessionProtocolSnapshot snapshot,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        RequireInitiatorScopeValues(
            snapshot.LocalAccountId, snapshot.ConversationId, snapshot.SessionId);
        var facts = MessagingCryptoV1Trs1.Validate(snapshot.ExactTrs1, scope);
        if (facts.TerminallyLatched)
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
            throw new CryptographicException("An initiator handshake cannot initialize a terminal TRS1 state.");
        }
        var fingerprint = ComputeInitiatorInitializationFingerprint(snapshot, facts);
        var initialHead = ComputeInitialJournalHead(scope);
        var gateHeld = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            ThrowIfDisposed();
            MessagingCryptoV1StoreTestHooks.Hit(
                MessagingCryptoV1StoreFailpoint.BeforeInitiatorInitialTransaction);
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            using var current = ReadCurrent(db, transaction);
            if (current is not null)
            {
                using var incumbent = ReadInitiatorInitialSession(db, transaction);
                if (current.ForkLatched)
                    return Result(MessagingCryptoV1CommitDisposition.AlreadyForkLatched, current);
                if (incumbent is null)
                    return Result(MessagingCryptoV1CommitDisposition.CasConflict, current);
                if (InitiatorInitialSessionMatches(incumbent, snapshot, fingerprint, facts))
                    return Result(MessagingCryptoV1CommitDisposition.ExactReplay, current);
                return LatchInitiatorInitialFork(
                    db, transaction, current, incumbent, snapshot, fingerprint);
            }

            using var responderInitial = ReadInitialSession(db, transaction);
            if (responderInitial is not null ||
                ScalarLong(db, "SELECT count(*) FROM initial_prekey_inventory;") != 0)
                throw new CryptographicException(
                    "Responder pre-key state cannot initialize an initiator session store.");

            using (var command = db.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "INSERT INTO ratchet_state VALUES(1,$generation,$commitment,$hash,$trs1,$journalGeneration,$journalHead,0,0,$operation,$fingerprint,$generation,$commitment,$hash);";
                Add(command, "$generation", U64(facts.Generation));
                Add(command, "$commitment", facts.StateCommitment);
                Add(command, "$hash", facts.ExactHash);
                Add(command, "$trs1", snapshot.ExactTrs1);
                Add(command, "$journalGeneration", U64(0));
                Add(command, "$journalHead", initialHead);
                Add(command, "$operation", snapshot.ClaimOperationId);
                Add(command, "$fingerprint", fingerprint);
                if (command.ExecuteNonQuery() != 1)
                    throw new InvalidOperationException("Initiator TRS1 initialization CAS failed.");
            }
            MessagingCryptoV1StoreTestHooks.Hit(
                MessagingCryptoV1StoreFailpoint.AfterInitiatorInitialStateInsert);
            InsertInitiatorInitialSession(db, transaction, snapshot, facts, fingerprint);
            MessagingCryptoV1StoreTestHooks.Hit(
                MessagingCryptoV1StoreFailpoint.AfterInitiatorInitialOutboxInsert);
            MessagingCryptoV1StoreTestHooks.Hit(
                MessagingCryptoV1StoreFailpoint.BeforeInitiatorInitialCommit);
            transaction.Commit();
            MessagingCryptoV1StoreTestHooks.Hit(
                MessagingCryptoV1StoreFailpoint.AfterInitiatorInitialCommit);
            return new MessagingCryptoV1CommitResult(
                MessagingCryptoV1CommitDisposition.Initialized,
                facts.Generation,
                facts.StateCommitment.ToArray(),
                0,
                initialHead.ToArray(),
                false,
                false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
            CryptographicOperations.ZeroMemory(fingerprint);
            CryptographicOperations.ZeroMemory(initialHead);
            if (gateHeld) gate.Release();
        }
    }

    internal async ValueTask<InitiatorInitialSessionDispatchEnvelope?>
        ReadInitiatorInitialSessionDispatchAsync(
            InitiatorInitialSessionVerifiedScope verifiedScope,
            CancellationToken cancellationToken = default)
    {
        RequireInitiatorScope(verifiedScope);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: true);
            using var current = ReadCurrent(db, transaction);
            using var row = ReadInitiatorInitialSession(db, transaction);
            if (current is null || row is null) return null;
            if (current.ForkLatched)
                throw new CryptographicException(
                    "The initiator session is fork-latched and cannot be dispatched.");
            if (!InitiatorScopeMatches(row, verifiedScope) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitializationFingerprint, row.Fingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitializationOperationId, row.ClaimOperationId))
                throw new CryptographicException(
                    "The durable initiator DPH2 belongs to another verified contact generation.");
            return new InitiatorInitialSessionDispatchEnvelope(
                row.ExactDph2, row.ClaimOperationId, row.SessionId, row.FullDph2ReplayHash);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<bool> HasExactDeviceWideInitialSessionAsync(
        Dpk2PrekeyKind kind,
        ReadOnlyMemory<byte> claimOperationId,
        ReadOnlyMemory<byte> xpc1FullReplayHash,
        ReadOnlyMemory<byte> dph2FullReplayHash,
        ReadOnlyMemory<byte> x25519PreKeyId,
        ReadOnlyMemory<byte> mlKemPreKeyId,
        ReadOnlyMemory<byte> initialStateHash,
        CancellationToken cancellationToken = default)
    {
        var source = kind switch
        {
            Dpk2PrekeyKind.OneTime => MessagingCryptoV1InitialPreKeySource.DeviceWideOneTimeReservation,
            Dpk2PrekeyKind.LastResort => MessagingCryptoV1InitialPreKeySource.DeviceWideLastResortReservation,
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: true);
            using var current = ReadCurrent(db, transaction);
            using var initial = ReadInitialSession(db, transaction);
            return current is not null && initial is not null && !current.ForkLatched &&
                initial.PreKeySource == source &&
                MessagingCryptoV1Trs1.Fixed(initial.ClaimOperationId, claimOperationId.Span) &&
                MessagingCryptoV1Trs1.Fixed(initial.Xpc1FullReplayHash, xpc1FullReplayHash.Span) &&
                MessagingCryptoV1Trs1.Fixed(initial.Dph2FullReplayHash, dph2FullReplayHash.Span) &&
                MessagingCryptoV1Trs1.Fixed(initial.X25519PreKeyId, x25519PreKeyId.Span) &&
                MessagingCryptoV1Trs1.Fixed(initial.MlKemPreKeyId, mlKemPreKeyId.Span) &&
                MessagingCryptoV1Trs1.Fixed(initial.InitialStateHash, initialStateHash.Span) &&
                MessagingCryptoV1Trs1.Fixed(current.InitializationOperationId, initial.ClaimOperationId) &&
                MessagingCryptoV1Trs1.Fixed(current.InitialStateHash, initial.InitialStateHash);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<MessagingCryptoV1CommitResult> CommitInitialSessionAsync(
        MessagingCryptoV1InitialSessionHandoff handoff,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        using var payload = handoff.Consume();
        var facts = MessagingCryptoV1Trs1.Validate(payload.ExactTrs1, scope);
        if (facts.TerminallyLatched)
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
            throw new InvalidOperationException("A verified handshake cannot initialize a terminal TRS1 state.");
        }
        var fingerprint = ComputeInitializationFingerprint(payload, facts);
        var initialHead = ComputeInitialJournalHead(scope);
        var gateHeld = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            ThrowIfDisposed();
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeInitialTransaction);
            var db = GetConnection();
            using var transaction = db.BeginTransaction(deferred: false);
            using var current = ReadCurrent(db, transaction);
            if (current is not null)
            {
                using var initial = ReadInitialSession(db, transaction) ??
                    throw new FormatException("Initial-session replay evidence is absent.");
                if (current.ForkLatched)
                    return Result(MessagingCryptoV1CommitDisposition.AlreadyForkLatched, current);
                if (InitialSessionMatches(initial, payload, fingerprint, facts))
                    return Result(MessagingCryptoV1CommitDisposition.ExactReplay, current);
                var collisionKind = InitialCollisionKind(initial, payload);
                if (collisionKind != 0)
                    return LatchInitialFork(db, transaction, current, initial, payload, fingerprint, collisionKind);
                return Result(MessagingCryptoV1CommitDisposition.CasConflict, current);
            }

            if (payload.PreKeySource == MessagingCryptoV1InitialPreKeySource.LocalAtomicInventory &&
                (!HasInitialPreKey(db, transaction, 1, payload.X25519PreKeyId) ||
                 !HasInitialPreKey(db, transaction, 2, payload.MlKemPreKeyId)))
                return new MessagingCryptoV1CommitResult(
                    MessagingCryptoV1CommitDisposition.PreKeyUnavailable, facts.Generation,
                    facts.StateCommitment.ToArray(), 0, initialHead.ToArray(), false, false);

            using var command = db.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ratchet_state VALUES(1,$generation,$commitment,$hash,$trs1,$journalGeneration,$journalHead,0,0,$operation,$fingerprint,$generation,$commitment,$hash);";
            Add(command, "$generation", U64(facts.Generation));
            Add(command, "$commitment", facts.StateCommitment);
            Add(command, "$hash", facts.ExactHash);
            Add(command, "$trs1", payload.ExactTrs1);
            Add(command, "$journalGeneration", U64(0));
            Add(command, "$journalHead", initialHead);
            Add(command, "$operation", payload.ClaimOperationId);
            Add(command, "$fingerprint", fingerprint);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("TRS1 initialization CAS failed.");
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterInitialStateInsert);
            InsertInitialSession(db, transaction, payload, facts, fingerprint);
            if (payload.PreKeySource == MessagingCryptoV1InitialPreKeySource.LocalAtomicInventory)
            {
                DeleteInitialPreKey(db, transaction, 1, payload.X25519PreKeyId);
                DeleteInitialPreKey(db, transaction, 2, payload.MlKemPreKeyId);
            }
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterInitialPreKeyConsumption);
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.BeforeInitialCommit);
            transaction.Commit();
            MessagingCryptoV1StoreTestHooks.Hit(MessagingCryptoV1StoreFailpoint.AfterInitialCommit);
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
            if (gateHeld) gate.Release();
        }
    }

#if DEEP_TEST_INTERNALS
    internal async ValueTask ProvisionOpaqueInitialPreKeysForTestsAsync(
        ReadOnlyMemory<byte> x25519PreKeyId,
        ReadOnlyMemory<byte> x25519OpaqueSealedRecord,
        ReadOnlyMemory<byte> mlKemPreKeyId,
        ReadOnlyMemory<byte> mlKemOpaqueSealedRecord,
        CancellationToken cancellationToken = default)
    {
        MessagingCryptoV1PreparedTransition.Validate32(x25519PreKeyId.Span, nameof(x25519PreKeyId));
        MessagingCryptoV1PreparedTransition.Validate32(mlKemPreKeyId.Span, nameof(mlKemPreKeyId));
        ValidateOpaqueSealedRecord(x25519OpaqueSealedRecord.Span, nameof(x25519OpaqueSealedRecord));
        ValidateOpaqueSealedRecord(mlKemOpaqueSealedRecord.Span, nameof(mlKemOpaqueSealedRecord));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            using var transaction = GetConnection().BeginTransaction(deferred: false);
            InsertInitialPreKey(GetConnection(), transaction, 1, x25519PreKeyId.Span, x25519OpaqueSealedRecord.Span);
            InsertInitialPreKey(GetConnection(), transaction, 2, mlKemPreKeyId.Span, mlKemOpaqueSealedRecord.Span);
            transaction.Commit();
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<int> ReadInitialPreKeyCountForTestsAsync(
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return checked((int)ScalarLong(GetConnection(), "SELECT count(*) FROM initial_prekey_inventory;"));
        }
        finally { gate.Release(); }
    }
#endif

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
                    "Messaging-crypto DDL differs from the sealed generation-5 schema.");
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
        var initialCount = ScalarLong(db, "SELECT count(*) FROM initial_session_journal;");
        var initialForkCount = ScalarLong(db, "SELECT count(*) FROM initial_session_fork_latch;");
        var initiatorCount = ScalarLong(db, "SELECT count(*) FROM initiator_initial_session_outbox;");
        var initiatorForkCount = ScalarLong(db, "SELECT count(*) FROM initiator_initial_session_fork_latch;");
        var preKeyCount = ScalarLong(db, "SELECT count(*) FROM initial_prekey_inventory;");
        var x25519PreKeyCount = ScalarLong(db, "SELECT count(*) FROM initial_prekey_inventory WHERE prekey_kind=1;");
        var mlKemPreKeyCount = ScalarLong(db, "SELECT count(*) FROM initial_prekey_inventory WHERE prekey_kind=2;");
        if (preKeyCount is not (0 or 2) ||
            preKeyCount == 2 && (x25519PreKeyCount != 1 || mlKemPreKeyCount != 1))
            throw new FormatException("Initial pre-key inventory cardinality is invalid.");
        if (current is null)
        {
            if (journalCount != 0 || exactDpe2Count != 0 || forkCount != 0 ||
                initialCount != 0 || initialForkCount != 0 || initiatorCount != 0 ||
                initiatorForkCount != 0)
                throw new FormatException("Orphan ratchet evidence exists.");
            return;
        }
        if (journalCount < 0 || journalCount > MessagingCryptoV1Limits.MaximumJournalEntries ||
            exactDpe2Count < 0 || exactDpe2Count > journalCount ||
            initialCount + initiatorCount != 1 || preKeyCount != 0 ||
            current.JournalGeneration != checked((ulong)journalCount) ||
            (current.ForkLatched
                ? forkCount + initialForkCount + initiatorForkCount != 1
                : forkCount + initialForkCount + initiatorForkCount != 0))
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

        using var initial = ReadInitialSession(db, null);
        using var initiator = ReadInitiatorInitialSession(db, null);
        if (initial is not null)
            ValidateResponderInitialization(current, initial);
        else if (initiator is not null)
            ValidateInitiatorInitialization(current, initiator);
        else
            throw new FormatException("Initial-session evidence is absent.");

        ValidateJournalChain(db, current);
        if (initialForkCount == 1)
            ValidateInitialForkLatch(db, current, initial ??
                throw new FormatException("Responder initial-session evidence is absent."));
        else if (initiatorForkCount == 1)
            ValidateInitiatorForkLatch(db, current, initiator ??
                throw new FormatException("Initiator initial-session evidence is absent."));
        else ValidateForkLatch(db, current);
    }

    private static void ValidateResponderInitialization(CurrentRow current, InitialSessionRow initial)
    {
        var facts = new MessagingCryptoV1Trs1Facts(current.InitialGeneration,
            current.InitialCommitment.ToArray(), current.InitialStateHash.ToArray(), false);
        var expected = ComputeInitializationFingerprint(
            initial.PreKeySource, initial.ClaimOperationId, initial.Xpc1FullReplayHash,
            initial.Dph2FullReplayHash, initial.X25519PreKeyId, initial.MlKemPreKeyId, facts);
        try
        {
            if (!MessagingCryptoV1Trs1.Fixed(expected, current.InitializationFingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(expected, initial.Fingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitializationOperationId, initial.ClaimOperationId) ||
                current.InitialGeneration != initial.InitialGeneration ||
                !MessagingCryptoV1Trs1.Fixed(current.InitialCommitment, initial.InitialCommitment) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitialStateHash, initial.InitialStateHash))
                throw new FormatException("TRS1 responder initialization evidence is corrupt.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
        }
    }

    private void ValidateInitiatorInitialization(
        CurrentRow current,
        InitiatorInitialSessionRow initiator)
    {
        var record = Dph2Codec.Decode(initiator.ExactDph2);
        var canonical = Dph2Codec.Encode(record);
        var replay = MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record);
        var claim = MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(record);
        var facts = new MessagingCryptoV1Trs1Facts(current.InitialGeneration,
            current.InitialCommitment.ToArray(), current.InitialStateHash.ToArray(), false);
        var expected = ComputeInitiatorInitializationFingerprint(initiator, facts);
        try
        {
            if (!MessagingCryptoV1Trs1.Fixed(canonical, initiator.ExactDph2) ||
                !MessagingCryptoV1Trs1.Fixed(initiator.LocalAccountId, scope.AccountId) ||
                initiator.LocalAccountGeneration != scope.AccountGeneration ||
                !MessagingCryptoV1Trs1.Fixed(initiator.LocalDeviceId, scope.LocalDeviceId) ||
                initiator.LocalDeviceGeneration != scope.DeviceGeneration ||
                !MessagingCryptoV1Trs1.Fixed(initiator.ConversationId, scope.ConversationId) ||
                !MessagingCryptoV1Trs1.Fixed(initiator.SessionId, scope.SessionId) ||
                !MessagingCryptoV1Trs1.Fixed(record.SessionId.Span, initiator.SessionId) ||
                !MessagingCryptoV1Trs1.Fixed(record.NetworkId.Span, initiator.NetworkId) ||
                !MessagingCryptoV1Trs1.Fixed(record.InitiatorAccountId.Span, initiator.LocalAccountId) ||
                !MessagingCryptoV1Trs1.Fixed(record.InitiatorDeviceId.Span, initiator.LocalDeviceId) ||
                record.InitiatorDeviceGeneration != initiator.LocalDeviceGeneration ||
                !MessagingCryptoV1Trs1.Fixed(record.ResponderAccountId.Span, initiator.RemoteAccountId) ||
                !MessagingCryptoV1Trs1.Fixed(record.ResponderDeviceId.Span, initiator.RemoteDeviceId) ||
                record.ResponderDeviceGeneration != initiator.RemoteDeviceGeneration ||
                !MessagingCryptoV1Trs1.Fixed(record.ClaimOperationId.Span, initiator.ClaimOperationId) ||
                !MessagingCryptoV1Trs1.Fixed(replay, initiator.FullDph2ReplayHash) ||
                !MessagingCryptoV1Trs1.Fixed(claim, initiator.ClaimBinding) ||
                !MessagingCryptoV1Trs1.Fixed(expected, current.InitializationFingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(expected, initiator.Fingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitializationOperationId, initiator.ClaimOperationId) ||
                current.InitialGeneration != initiator.InitialGeneration ||
                !MessagingCryptoV1Trs1.Fixed(current.InitialCommitment, initiator.InitialCommitment) ||
                !MessagingCryptoV1Trs1.Fixed(current.InitialStateHash, initiator.InitialStateHash))
                throw new FormatException("TRS1 initiator initialization evidence is corrupt.");
        }
        finally
        {
            Zero(canonical, replay, claim, expected, facts.StateCommitment, facts.ExactHash);
        }
    }

    private static void ValidateInitialForkLatch(
        SqliteConnection db,
        CurrentRow current,
        InitialSessionRow initial)
    {
        if (!current.ForkLatched) throw new FormatException("Orphan initial-session fork evidence exists.");
        using var command = db.CreateCommand();
        command.CommandText = "SELECT collision_kind,incumbent_fingerprint,conflicting_fingerprint,incumbent_operation_id,incumbent_x25519_prekey_id,incumbent_mlkem_prekey_id FROM initial_session_fork_latch WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new FormatException("Initial-session fork evidence is absent.");
        var kind = reader.GetInt32(0);
        var incumbentFingerprint = (byte[])reader[1];
        var conflictingFingerprint = (byte[])reader[2];
        var incumbentOperation = (byte[])reader[3];
        var incumbentX25519 = reader.IsDBNull(4) ? [] : (byte[])reader[4];
        var incumbentMlKem = (byte[])reader[5];
        try
        {
            if (reader.Read() || kind is < 1 or > 3 ||
                MessagingCryptoV1Trs1.Fixed(incumbentFingerprint, conflictingFingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentFingerprint, initial.Fingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentOperation, initial.ClaimOperationId) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentX25519, initial.X25519PreKeyId) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentMlKem, initial.MlKemPreKeyId))
                throw new FormatException("Initial-session fork evidence is invalid.");
        }
        finally { Zero(incumbentFingerprint, conflictingFingerprint, incumbentOperation, incumbentX25519, incumbentMlKem); }
    }

    private static void ValidateInitiatorForkLatch(
        SqliteConnection db,
        CurrentRow current,
        InitiatorInitialSessionRow initiator)
    {
        if (!current.ForkLatched)
            throw new FormatException("Orphan initiator initial-session fork evidence exists.");
        using var command = db.CreateCommand();
        command.CommandText = "SELECT incumbent_fingerprint,conflicting_fingerprint,incumbent_operation_id,incumbent_session_id,incumbent_dph2_hash FROM initiator_initial_session_fork_latch WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new FormatException("Initiator initial-session fork evidence is absent.");
        var incumbentFingerprint = (byte[])reader[0];
        var conflictingFingerprint = (byte[])reader[1];
        var incumbentOperation = (byte[])reader[2];
        var incumbentSession = (byte[])reader[3];
        var incumbentDph2Hash = (byte[])reader[4];
        try
        {
            if (reader.Read() ||
                MessagingCryptoV1Trs1.Fixed(incumbentFingerprint, conflictingFingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentFingerprint, initiator.Fingerprint) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentOperation, initiator.ClaimOperationId) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentSession, initiator.SessionId) ||
                !MessagingCryptoV1Trs1.Fixed(incumbentDph2Hash, initiator.FullDph2ReplayHash))
                throw new FormatException("Initiator initial-session fork evidence is invalid.");
        }
        finally
        {
            Zero(incumbentFingerprint, conflictingFingerprint, incumbentOperation,
                incumbentSession, incumbentDph2Hash);
        }
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
        // bounded generation-3 session journal. A future compaction/rollover is
        // a new policy generation, never an implicit reinterpretation here.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/replay-retention/v1"u8);
        Append(hash, U64(1));
        Append(hash, U64(ReplayRetentionContextGeneration));
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
        MessagingCryptoV1InitialSessionHandoff.InitializationPayload payload,
        MessagingCryptoV1Trs1Facts facts) => ComputeInitializationFingerprint(
            payload.PreKeySource, payload.ClaimOperationId, payload.Xpc1FullReplayHash, payload.Dph2FullReplayHash,
            payload.X25519PreKeyId, payload.MlKemPreKeyId, facts);

    private static byte[] ComputeInitializationFingerprint(
        MessagingCryptoV1InitialPreKeySource preKeySource,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        MessagingCryptoV1Trs1Facts facts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/initialization/v3"u8);
        Append(hash, [(byte)preKeySource]); Append(hash, claimOperationId); Append(hash, xpc1FullReplayHash);
        Append(hash, dph2FullReplayHash); Append(hash, x25519PreKeyId);
        Append(hash, mlKemPreKeyId); Append(hash, U64(facts.Generation));
        Append(hash, facts.StateCommitment); Append(hash, facts.ExactHash);
        return hash.GetHashAndReset();
    }

    private byte[] ComputeInitiatorInitializationFingerprint(
        InitiatorInitialSessionProtocolSnapshot snapshot,
        MessagingCryptoV1Trs1Facts facts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/initiator-initialization/v1"u8);
        Append(hash, snapshot.NetworkId);
        Append(hash, scope.AccountId);
        Append(hash, U64(scope.AccountGeneration));
        Append(hash, scope.LocalDeviceId);
        Append(hash, U64(scope.DeviceGeneration));
        Append(hash, U64(checked((ulong)snapshot.ContactStoreGeneration)));
        Append(hash, snapshot.RelationshipId);
        Append(hash, snapshot.ConversationId);
        Append(hash, snapshot.ContactEvidenceHash);
        Append(hash, snapshot.PeerPackageHash);
        Append(hash, snapshot.RemoteAccountId);
        Append(hash, U64(snapshot.RemoteAccountGeneration));
        Append(hash, U64(snapshot.RemoteDirectoryGeneration));
        Append(hash, snapshot.RemoteDeviceId);
        Append(hash, U64(snapshot.RemoteDeviceGeneration));
        Append(hash, snapshot.ClaimOperationId);
        Append(hash, snapshot.SessionId);
        Append(hash, snapshot.FullDph2ReplayHash);
        Append(hash, snapshot.ClaimBinding);
        Append(hash, snapshot.ExactDph2);
        Append(hash, U64(facts.Generation));
        Append(hash, facts.StateCommitment);
        Append(hash, facts.ExactHash);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeInitiatorInitializationFingerprint(
        InitiatorInitialSessionRow row,
        MessagingCryptoV1Trs1Facts facts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/initiator-initialization/v1"u8);
        Append(hash, row.NetworkId);
        Append(hash, row.LocalAccountId);
        Append(hash, U64(row.LocalAccountGeneration));
        Append(hash, row.LocalDeviceId);
        Append(hash, U64(row.LocalDeviceGeneration));
        Append(hash, U64(checked((ulong)row.ContactStoreGeneration)));
        Append(hash, row.RelationshipId);
        Append(hash, row.ConversationId);
        Append(hash, row.ContactEvidenceHash);
        Append(hash, row.PeerPackageHash);
        Append(hash, row.RemoteAccountId);
        Append(hash, U64(row.RemoteAccountGeneration));
        Append(hash, U64(row.RemoteDirectoryGeneration));
        Append(hash, row.RemoteDeviceId);
        Append(hash, U64(row.RemoteDeviceGeneration));
        Append(hash, row.ClaimOperationId);
        Append(hash, row.SessionId);
        Append(hash, row.FullDph2ReplayHash);
        Append(hash, row.ClaimBinding);
        Append(hash, row.ExactDph2);
        Append(hash, U64(facts.Generation));
        Append(hash, facts.StateCommitment);
        Append(hash, facts.ExactHash);
        return hash.GetHashAndReset();
    }

    private static bool InitiatorInitialSessionMatches(
        InitiatorInitialSessionRow incumbent,
        InitiatorInitialSessionProtocolSnapshot candidate,
        ReadOnlySpan<byte> fingerprint,
        MessagingCryptoV1Trs1Facts facts) =>
        MessagingCryptoV1Trs1.Fixed(incumbent.Fingerprint, fingerprint) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.ClaimOperationId, candidate.ClaimOperationId) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.SessionId, candidate.SessionId) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.FullDph2ReplayHash, candidate.FullDph2ReplayHash) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.ClaimBinding, candidate.ClaimBinding) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.ExactDph2, candidate.ExactDph2) &&
        incumbent.InitialGeneration == facts.Generation &&
        MessagingCryptoV1Trs1.Fixed(incumbent.InitialCommitment, facts.StateCommitment) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.InitialStateHash, facts.ExactHash);

    private static bool InitiatorScopeMatches(
        InitiatorInitialSessionRow row,
        InitiatorInitialSessionVerifiedScope scope) =>
        MessagingCryptoV1Trs1.Fixed(row.NetworkId, scope.NetworkId) &&
        MessagingCryptoV1Trs1.Fixed(row.LocalAccountId, scope.LocalAccountId) &&
        row.ContactStoreGeneration == scope.ContactStoreGeneration &&
        MessagingCryptoV1Trs1.Fixed(row.RelationshipId, scope.RelationshipId) &&
        MessagingCryptoV1Trs1.Fixed(row.ConversationId, scope.ConversationId) &&
        MessagingCryptoV1Trs1.Fixed(row.ContactEvidenceHash, scope.ContactEvidenceHash) &&
        MessagingCryptoV1Trs1.Fixed(row.PeerPackageHash, scope.PeerPackageHash) &&
        MessagingCryptoV1Trs1.Fixed(row.RemoteAccountId, scope.RemoteAccountId) &&
        row.RemoteAccountGeneration == scope.RemoteAccountGeneration &&
        row.RemoteDirectoryGeneration == scope.RemoteDirectoryGeneration &&
        MessagingCryptoV1Trs1.Fixed(row.RemoteDeviceId, scope.RemoteDeviceId) &&
        row.RemoteDeviceGeneration == scope.RemoteDeviceGeneration;

    private static bool InitialSessionMatches(
        InitialSessionRow incumbent,
        MessagingCryptoV1InitialSessionHandoff.InitializationPayload payload,
        ReadOnlySpan<byte> fingerprint,
        MessagingCryptoV1Trs1Facts facts) =>
        incumbent.PreKeySource == payload.PreKeySource &&
        MessagingCryptoV1Trs1.Fixed(incumbent.ClaimOperationId, payload.ClaimOperationId) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.Fingerprint, fingerprint) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.Xpc1FullReplayHash, payload.Xpc1FullReplayHash) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.Dph2FullReplayHash, payload.Dph2FullReplayHash) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.X25519PreKeyId, payload.X25519PreKeyId) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.MlKemPreKeyId, payload.MlKemPreKeyId) &&
        incumbent.InitialGeneration == facts.Generation &&
        MessagingCryptoV1Trs1.Fixed(incumbent.InitialCommitment, facts.StateCommitment) &&
        MessagingCryptoV1Trs1.Fixed(incumbent.InitialStateHash, facts.ExactHash);

    private static int InitialCollisionKind(
        InitialSessionRow incumbent,
        MessagingCryptoV1InitialSessionHandoff.InitializationPayload payload)
    {
        if (MessagingCryptoV1Trs1.Fixed(incumbent.ClaimOperationId, payload.ClaimOperationId)) return 1;
        if (incumbent.X25519PreKeyId.Length != 0 && payload.X25519PreKeyId.Length != 0 &&
            MessagingCryptoV1Trs1.Fixed(incumbent.X25519PreKeyId, payload.X25519PreKeyId)) return 2;
        if (MessagingCryptoV1Trs1.Fixed(incumbent.MlKemPreKeyId, payload.MlKemPreKeyId)) return 3;
        return 0;
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

    private static void ValidateOpaqueSealedRecord(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length is < 32 or > MessagingCryptoV1Limits.MaximumTrs1Bytes)
            throw new ArgumentOutOfRangeException(name, "An opaque sealed pre-key record must be within 32 bytes..2 MiB.");
    }

    private static void InsertInitialPreKey(
        SqliteConnection db,
        SqliteTransaction transaction,
        int kind,
        ReadOnlySpan<byte> preKeyId,
        ReadOnlySpan<byte> opaqueSealedRecord)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO initial_prekey_inventory VALUES($kind,$id,$record);";
        Add(command, "$kind", kind); Add(command, "$id", preKeyId.ToArray());
        Add(command, "$record", opaqueSealedRecord.ToArray());
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Initial pre-key provision failed.");
    }

    private static bool HasInitialPreKey(
        SqliteConnection db,
        SqliteTransaction transaction,
        int kind,
        ReadOnlySpan<byte> preKeyId)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT count(*) FROM initial_prekey_inventory WHERE prekey_kind=$kind AND prekey_id=$id;";
        Add(command, "$kind", kind); Add(command, "$id", preKeyId.ToArray());
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static void DeleteInitialPreKey(
        SqliteConnection db,
        SqliteTransaction transaction,
        int kind,
        ReadOnlySpan<byte> preKeyId)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM initial_prekey_inventory WHERE prekey_kind=$kind AND prekey_id=$id;";
        Add(command, "$kind", kind); Add(command, "$id", preKeyId.ToArray());
        if (command.ExecuteNonQuery() != 1)
            throw new CryptographicException("A mandatory one-time pre-key was not consumed exactly once.");
    }

    private void InsertInitiatorInitialSession(
        SqliteConnection db,
        SqliteTransaction transaction,
        InitiatorInitialSessionProtocolSnapshot snapshot,
        MessagingCryptoV1Trs1Facts facts,
        ReadOnlySpan<byte> fingerprint)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO initiator_initial_session_outbox VALUES(
                1,$operation,$fingerprint,$session,$replay,$claim,$dph2,$network,
                $localAccount,$localAccountGeneration,$localDevice,$localDeviceGeneration,
                $contactStoreGeneration,$relationship,$conversation,$contactEvidence,$peerPackage,
                $remoteAccount,$remoteAccountGeneration,$remoteDirectoryGeneration,
                $remoteDevice,$remoteDeviceGeneration,$initialGeneration,$initialCommitment,$initialHash);
            """;
        Add(command, "$operation", snapshot.ClaimOperationId);
        Add(command, "$fingerprint", fingerprint.ToArray());
        Add(command, "$session", snapshot.SessionId);
        Add(command, "$replay", snapshot.FullDph2ReplayHash);
        Add(command, "$claim", snapshot.ClaimBinding);
        Add(command, "$dph2", snapshot.ExactDph2);
        Add(command, "$network", snapshot.NetworkId);
        Add(command, "$localAccount", scope.AccountId.ToArray());
        Add(command, "$localAccountGeneration", U64(scope.AccountGeneration));
        Add(command, "$localDevice", scope.LocalDeviceId.ToArray());
        Add(command, "$localDeviceGeneration", U64(scope.DeviceGeneration));
        Add(command, "$contactStoreGeneration", snapshot.ContactStoreGeneration);
        Add(command, "$relationship", snapshot.RelationshipId);
        Add(command, "$conversation", snapshot.ConversationId);
        Add(command, "$contactEvidence", snapshot.ContactEvidenceHash);
        Add(command, "$peerPackage", snapshot.PeerPackageHash);
        Add(command, "$remoteAccount", snapshot.RemoteAccountId);
        Add(command, "$remoteAccountGeneration", U64(snapshot.RemoteAccountGeneration));
        Add(command, "$remoteDirectoryGeneration", U64(snapshot.RemoteDirectoryGeneration));
        Add(command, "$remoteDevice", snapshot.RemoteDeviceId);
        Add(command, "$remoteDeviceGeneration", U64(snapshot.RemoteDeviceGeneration));
        Add(command, "$initialGeneration", U64(facts.Generation));
        Add(command, "$initialCommitment", facts.StateCommitment);
        Add(command, "$initialHash", facts.ExactHash);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidOperationException("Initiator initial-session outbox insert failed.");
    }

    private static InitiatorInitialSessionRow? ReadInitiatorInitialSession(
        SqliteConnection db,
        SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT claim_operation_id,initialization_fingerprint,session_id,
                   full_dph2_replay_hash,claim_binding,exact_dph2,network_id,
                   local_account_id,local_account_generation,local_device_id,
                   local_device_generation,contact_store_generation,
                   contact_relationship_id,contact_conversation_id,contact_evidence_hash,
                   peer_package_hash,remote_account_id,remote_account_generation,
                   remote_directory_generation,remote_device_id,remote_device_generation,
                   initial_generation,initial_commitment,initial_state_hash
              FROM initiator_initial_session_outbox WHERE singleton=1;
            """;
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var result = new InitiatorInitialSessionRow(
            (byte[])reader[0], (byte[])reader[1], (byte[])reader[2], (byte[])reader[3],
            (byte[])reader[4], (byte[])reader[5], (byte[])reader[6], (byte[])reader[7],
            ReadU64((byte[])reader[8]), (byte[])reader[9], ReadU64((byte[])reader[10]),
            reader.GetInt32(11), (byte[])reader[12], (byte[])reader[13], (byte[])reader[14],
            (byte[])reader[15], (byte[])reader[16], ReadU64((byte[])reader[17]),
            ReadU64((byte[])reader[18]), (byte[])reader[19], ReadU64((byte[])reader[20]),
            ReadU64((byte[])reader[21]), (byte[])reader[22], (byte[])reader[23]);
        if (reader.Read())
        {
            result.Dispose();
            throw new FormatException("Duplicate initiator initial-session rows exist.");
        }
        return result;
    }

    private static MessagingCryptoV1CommitResult LatchInitiatorInitialFork(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        InitiatorInitialSessionRow incumbent,
        InitiatorInitialSessionProtocolSnapshot conflicting,
        ReadOnlySpan<byte> conflictingFingerprint)
    {
        using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO initiator_initial_session_fork_latch VALUES(1,$incumbentFingerprint,$conflictingFingerprint,$incumbentOperation,$conflictingOperation,$incumbentSession,$conflictingSession,$incumbentDph2,$conflictingDph2);";
            Add(command, "$incumbentFingerprint", incumbent.Fingerprint);
            Add(command, "$conflictingFingerprint", conflictingFingerprint.ToArray());
            Add(command, "$incumbentOperation", incumbent.ClaimOperationId);
            Add(command, "$conflictingOperation", conflicting.ClaimOperationId);
            Add(command, "$incumbentSession", incumbent.SessionId);
            Add(command, "$conflictingSession", conflicting.SessionId);
            Add(command, "$incumbentDph2", incumbent.FullDph2ReplayHash);
            Add(command, "$conflictingDph2", conflicting.FullDph2ReplayHash);
            if (command.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Initiator initial-session fork insert failed.");
        }
        using (var update = db.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE ratchet_state SET fork_latched=1 WHERE singleton=1 AND fork_latched=0;";
            if (update.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Initiator initial-session fork latch CAS failed.");
        }
        transaction.Commit();
        return new MessagingCryptoV1CommitResult(
            MessagingCryptoV1CommitDisposition.ForkLatched,
            current.Generation,
            current.StateCommitment.ToArray(),
            current.JournalGeneration,
            current.JournalHead.ToArray(),
            true,
            current.TerminallyLatched);
    }

    private static void InsertInitialSession(
        SqliteConnection db,
        SqliteTransaction transaction,
        MessagingCryptoV1InitialSessionHandoff.InitializationPayload payload,
        MessagingCryptoV1Trs1Facts facts,
        ReadOnlySpan<byte> fingerprint)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO initial_session_journal VALUES(1,$source,$operation,$fingerprint,$xpc1,$dph2,$x25519,$mlkem,$generation,$commitment,$hash);";
        Add(command, "$source", (int)payload.PreKeySource); Add(command, "$operation", payload.ClaimOperationId); Add(command, "$fingerprint", fingerprint.ToArray());
        Add(command, "$xpc1", payload.Xpc1FullReplayHash); Add(command, "$dph2", payload.Dph2FullReplayHash);
        Add(command, "$x25519", payload.X25519PreKeyId.Length == 0 ? DBNull.Value : payload.X25519PreKeyId); Add(command, "$mlkem", payload.MlKemPreKeyId);
        Add(command, "$generation", U64(facts.Generation)); Add(command, "$commitment", facts.StateCommitment);
        Add(command, "$hash", facts.ExactHash);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Initial-session journal insert failed.");
    }

    private static InitialSessionRow? ReadInitialSession(SqliteConnection db, SqliteTransaction? transaction)
    {
        using var command = db.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT prekey_source,claim_operation_id,initialization_fingerprint,xpc1_full_replay_hash,dph2_full_replay_hash,x25519_prekey_id,mlkem_prekey_id,initial_generation,initial_commitment,initial_state_hash FROM initial_session_journal WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var source = (MessagingCryptoV1InitialPreKeySource)reader.GetInt32(0);
        if (!Enum.IsDefined(source)) throw new FormatException("Unknown initial pre-key source.");
        var result = new InitialSessionRow(source, (byte[])reader[1], (byte[])reader[2], (byte[])reader[3],
            (byte[])reader[4], reader.IsDBNull(5) ? [] : (byte[])reader[5], (byte[])reader[6], ReadU64((byte[])reader[7]),
            (byte[])reader[8], (byte[])reader[9]);
        if (reader.Read()) { result.Dispose(); throw new FormatException("Duplicate initial-session rows exist."); }
        return result;
    }

    private static MessagingCryptoV1CommitResult LatchInitialFork(
        SqliteConnection db,
        SqliteTransaction transaction,
        CurrentRow current,
        InitialSessionRow incumbent,
        MessagingCryptoV1InitialSessionHandoff.InitializationPayload conflicting,
        ReadOnlySpan<byte> conflictingFingerprint,
        int kind)
    {
        using (var command = db.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO initial_session_fork_latch VALUES(1,$kind,$incumbentFingerprint,$conflictingFingerprint,$incumbentOperation,$conflictingOperation,$incumbentX25519,$conflictingX25519,$incumbentMlKem,$conflictingMlKem);";
            Add(command, "$kind", kind); Add(command, "$incumbentFingerprint", incumbent.Fingerprint);
            Add(command, "$conflictingFingerprint", conflictingFingerprint.ToArray());
            Add(command, "$incumbentOperation", incumbent.ClaimOperationId);
            Add(command, "$conflictingOperation", conflicting.ClaimOperationId);
            Add(command, "$incumbentX25519", incumbent.X25519PreKeyId.Length == 0 ? DBNull.Value : incumbent.X25519PreKeyId);
            Add(command, "$conflictingX25519", conflicting.X25519PreKeyId.Length == 0 ? DBNull.Value : conflicting.X25519PreKeyId);
            Add(command, "$incumbentMlKem", incumbent.MlKemPreKeyId);
            Add(command, "$conflictingMlKem", conflicting.MlKemPreKeyId);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Initial-session fork latch insert failed.");
        }
        using (var update = db.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE ratchet_state SET fork_latched=1 WHERE singleton=1 AND fork_latched=0;";
            if (update.ExecuteNonQuery() != 1) throw new InvalidOperationException("Initial-session fork latch CAS failed.");
        }
        transaction.Commit();
        return new MessagingCryptoV1CommitResult(MessagingCryptoV1CommitDisposition.ForkLatched,
            current.Generation, current.StateCommitment.ToArray(), current.JournalGeneration,
            current.JournalHead.ToArray(), true, current.TerminallyLatched);
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

    private sealed class InitialSessionRow(
        MessagingCryptoV1InitialPreKeySource preKeySource,
        byte[] claimOperationId,
        byte[] fingerprint,
        byte[] xpc1FullReplayHash,
        byte[] dph2FullReplayHash,
        byte[] x25519PreKeyId,
        byte[] mlKemPreKeyId,
        ulong initialGeneration,
        byte[] initialCommitment,
        byte[] initialStateHash) : IDisposable
    {
        internal MessagingCryptoV1InitialPreKeySource PreKeySource { get; } = preKeySource;
        internal byte[] ClaimOperationId { get; } = claimOperationId;
        internal byte[] Fingerprint { get; } = fingerprint;
        internal byte[] Xpc1FullReplayHash { get; } = xpc1FullReplayHash;
        internal byte[] Dph2FullReplayHash { get; } = dph2FullReplayHash;
        internal byte[] X25519PreKeyId { get; } = x25519PreKeyId;
        internal byte[] MlKemPreKeyId { get; } = mlKemPreKeyId;
        internal ulong InitialGeneration { get; } = initialGeneration;
        internal byte[] InitialCommitment { get; } = initialCommitment;
        internal byte[] InitialStateHash { get; } = initialStateHash;
        public void Dispose() => Zero(ClaimOperationId, Fingerprint, Xpc1FullReplayHash,
            Dph2FullReplayHash, X25519PreKeyId, MlKemPreKeyId, InitialCommitment, InitialStateHash);
    }

    private sealed class InitiatorInitialSessionRow(
        byte[] claimOperationId,
        byte[] fingerprint,
        byte[] sessionId,
        byte[] fullDph2ReplayHash,
        byte[] claimBinding,
        byte[] exactDph2,
        byte[] networkId,
        byte[] localAccountId,
        ulong localAccountGeneration,
        byte[] localDeviceId,
        ulong localDeviceGeneration,
        int contactStoreGeneration,
        byte[] relationshipId,
        byte[] conversationId,
        byte[] contactEvidenceHash,
        byte[] peerPackageHash,
        byte[] remoteAccountId,
        ulong remoteAccountGeneration,
        ulong remoteDirectoryGeneration,
        byte[] remoteDeviceId,
        ulong remoteDeviceGeneration,
        ulong initialGeneration,
        byte[] initialCommitment,
        byte[] initialStateHash) : IDisposable
    {
        internal byte[] ClaimOperationId { get; } = claimOperationId;
        internal byte[] Fingerprint { get; } = fingerprint;
        internal byte[] SessionId { get; } = sessionId;
        internal byte[] FullDph2ReplayHash { get; } = fullDph2ReplayHash;
        internal byte[] ClaimBinding { get; } = claimBinding;
        internal byte[] ExactDph2 { get; } = exactDph2;
        internal byte[] NetworkId { get; } = networkId;
        internal byte[] LocalAccountId { get; } = localAccountId;
        internal ulong LocalAccountGeneration { get; } = localAccountGeneration;
        internal byte[] LocalDeviceId { get; } = localDeviceId;
        internal ulong LocalDeviceGeneration { get; } = localDeviceGeneration;
        internal int ContactStoreGeneration { get; } = contactStoreGeneration;
        internal byte[] RelationshipId { get; } = relationshipId;
        internal byte[] ConversationId { get; } = conversationId;
        internal byte[] ContactEvidenceHash { get; } = contactEvidenceHash;
        internal byte[] PeerPackageHash { get; } = peerPackageHash;
        internal byte[] RemoteAccountId { get; } = remoteAccountId;
        internal ulong RemoteAccountGeneration { get; } = remoteAccountGeneration;
        internal ulong RemoteDirectoryGeneration { get; } = remoteDirectoryGeneration;
        internal byte[] RemoteDeviceId { get; } = remoteDeviceId;
        internal ulong RemoteDeviceGeneration { get; } = remoteDeviceGeneration;
        internal ulong InitialGeneration { get; } = initialGeneration;
        internal byte[] InitialCommitment { get; } = initialCommitment;
        internal byte[] InitialStateHash { get; } = initialStateHash;

        public void Dispose() => Zero(
            ClaimOperationId, Fingerprint, SessionId, FullDph2ReplayHash,
            ClaimBinding, ExactDph2, NetworkId, LocalAccountId, LocalDeviceId,
            RelationshipId, ConversationId, ContactEvidenceHash, PeerPackageHash,
            RemoteAccountId, RemoteDeviceId, InitialCommitment, InitialStateHash);
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
