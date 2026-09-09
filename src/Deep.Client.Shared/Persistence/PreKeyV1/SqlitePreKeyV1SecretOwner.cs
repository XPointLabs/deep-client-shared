using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.PreKeyV1;

internal enum PreKeyV1InitialSessionSagaDisposition
{
    Initialized = 1,
    ExactReplay = 2,
    PreKeyUnavailable = 3,
    ForkLatched = 4,
    SessionRejected = 5,
}

internal sealed record PreKeyV1InitialSessionSagaResult(
    PreKeyV1InitialSessionSagaDisposition Disposition,
    PreKeyV1ClaimDisposition PreKeyDisposition,
    MessagingCryptoV1CommitDisposition? SessionDisposition,
    bool ForkLatched);

/// <summary>
/// Account/device-wide SQLCipher authority for DPK2 private material. Session stores
/// receive no key bytes and cannot decide whether a pre-key is fresh.
/// </summary>
internal sealed partial class SqlitePreKeyV1SecretOwner : IAsyncDisposable
{
    private const int ApplicationId = 0x504B5631; // PKV1
    private const int SchemaGeneration = 4;
    private const string SchemaDdl = """
        CREATE TABLE prekey_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_generation BLOB NOT NULL CHECK(length(database_generation)=8),network_id BLOB NOT NULL CHECK(length(network_id)=16),account_id BLOB NOT NULL CHECK(length(account_id)=32),account_generation BLOB NOT NULL CHECK(length(account_generation)=8),device_id BLOB NOT NULL CHECK(length(device_id)=32),device_generation BLOB NOT NULL CHECK(length(device_generation)=8),dpd1_reference BLOB NOT NULL CHECK(length(dpd1_reference)=38),dpd1_hash BLOB NOT NULL CHECK(length(dpd1_hash)=32),fork_latched INTEGER NOT NULL CHECK(fork_latched IN(0,1)));
        CREATE TABLE one_time_prekeys(exact_dpk2_hash BLOB PRIMARY KEY CHECK(length(exact_dpk2_hash)=32),exact_dpk2 BLOB NOT NULL CHECK(length(exact_dpk2)=2037),inventory_epoch BLOB NOT NULL CHECK(length(inventory_epoch)=8),bundle_id BLOB NOT NULL UNIQUE CHECK(length(bundle_id)=32),x25519_prekey_id BLOB NOT NULL UNIQUE CHECK(length(x25519_prekey_id)=32),mlkem_prekey_id BLOB NOT NULL UNIQUE CHECK(length(mlkem_prekey_id)=32),sealed_secret BLOB NOT NULL CHECK(length(sealed_secret) BETWEEN 386 AND 4481),state INTEGER NOT NULL CHECK(state IN(1,2)));
        CREATE TABLE last_resort_prekeys(exact_dpk2_hash BLOB PRIMARY KEY CHECK(length(exact_dpk2_hash)=32),exact_dpk2 BLOB NOT NULL CHECK(length(exact_dpk2)=1973),inventory_epoch BLOB NOT NULL CHECK(length(inventory_epoch)=8),bundle_id BLOB NOT NULL UNIQUE CHECK(length(bundle_id)=32),mlkem_prekey_id BLOB NOT NULL UNIQUE CHECK(length(mlkem_prekey_id)=32),sealed_secret BLOB NULL CHECK(sealed_secret IS NULL OR length(sealed_secret) BETWEEN 386 AND 4481),reuse_limit INTEGER NOT NULL CHECK(reuse_limit BETWEEN 1 AND 64),next_counter INTEGER NOT NULL CHECK(next_counter BETWEEN 1 AND 65),CHECK((next_counter<=reuse_limit AND sealed_secret IS NOT NULL) OR (next_counter=reuse_limit+1 AND sealed_secret IS NULL)));
        CREATE TABLE prekey_publications(inventory_epoch BLOB PRIMARY KEY CHECK(length(inventory_epoch)=8),service_generation BLOB NOT NULL CHECK(length(service_generation)=8),operation_id BLOB NOT NULL UNIQUE CHECK(length(operation_id)=32),predecessor_xpi1_hash BLOB NOT NULL CHECK(length(predecessor_xpi1_hash)=32),current_dmd1_generation BLOB NOT NULL CHECK(length(current_dmd1_generation)=8),current_dmd1_hash BLOB NOT NULL CHECK(length(current_dmd1_hash)=32),xpi1_hash BLOB NOT NULL UNIQUE CHECK(length(xpi1_hash)=32),xpp1_hash BLOB NOT NULL UNIQUE CHECK(length(xpp1_hash)=32),exact_xpi1 BLOB NOT NULL CHECK(length(exact_xpi1)=560),exact_xpp1 BLOB NOT NULL CHECK(length(exact_xpp1) BETWEEN 67983 AND 8362607));
        CREATE TABLE prekey_claim_journal(operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),kind INTEGER NOT NULL CHECK(kind IN(1,2)),session_id BLOB NOT NULL CHECK(length(session_id)=32),exact_dpk2_hash BLOB NOT NULL CHECK(length(exact_dpk2_hash)=32),xpc1_full_replay_hash BLOB NOT NULL CHECK(length(xpc1_full_replay_hash)=32),dph2_full_replay_hash BLOB NOT NULL CHECK(length(dph2_full_replay_hash)=32),x25519_prekey_id BLOB NULL CHECK(x25519_prekey_id IS NULL OR length(x25519_prekey_id)=32),mlkem_prekey_id BLOB NOT NULL CHECK(length(mlkem_prekey_id)=32),last_resort_counter INTEGER NOT NULL CHECK(last_resort_counter BETWEEN 0 AND 64),initial_session_hash BLOB NULL CHECK(initial_session_hash IS NULL OR length(initial_session_hash)=32),state INTEGER NOT NULL CHECK(state IN(1,2,3)),CHECK((kind=1 AND x25519_prekey_id IS NOT NULL AND last_resort_counter=0) OR (kind=2 AND x25519_prekey_id IS NULL AND last_resort_counter BETWEEN 1 AND 64)));
        CREATE UNIQUE INDEX one_time_claim_x25519 ON prekey_claim_journal(x25519_prekey_id) WHERE kind=1;
        CREATE UNIQUE INDEX one_time_claim_mlkem ON prekey_claim_journal(mlkem_prekey_id) WHERE kind=1;
        CREATE UNIQUE INDEX last_resort_claim_counter ON prekey_claim_journal(exact_dpk2_hash,last_resort_counter) WHERE kind=2;
        CREATE TABLE prekey_fork_latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1),reason INTEGER NOT NULL CHECK(reason BETWEEN 1 AND 5),incumbent_fingerprint BLOB NOT NULL CHECK(length(incumbent_fingerprint)=32),conflicting_fingerprint BLOB NOT NULL CHECK(length(conflicting_fingerprint)=32),incumbent_operation_id BLOB NULL CHECK(incumbent_operation_id IS NULL OR length(incumbent_operation_id)=32),conflicting_operation_id BLOB NULL CHECK(conflicting_operation_id IS NULL OR length(conflicting_operation_id)=32),CHECK(incumbent_fingerprint<>conflicting_fingerprint));
        """;

    private static readonly byte[] ExpectedSchemaFingerprint = HashSchema(ReadSchemaStatements());
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly byte[] key;
    private readonly Dpk2PreKeyPersistenceProtector preKeyProtector;
    private readonly PreKeyV1StoreScope scope;
    private readonly string statePath;
    private readonly string connectionString;
    private SqliteConnection? connection;
    private int disposed;

    static SqlitePreKeyV1SecretOwner() => SQLitePCL.Batteries_V2.Init();

    internal SqlitePreKeyV1SecretOwner(PreKeyV1StoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options); key = options.CopyEncryptionKey(); scope = options.Scope;
        preKeyProtector = new Dpk2PreKeyPersistenceProtector(key);
        statePath = options.StatePath; var exists = File.Exists(statePath);
        if (!exists && !options.AllowCreate)
        {
            DisposeProtectorAndKey();
            throw Failure(PreKeyV1StoreOpenFailure.UnreadableOrWrongKey, "The protected pre-key store does not exist.");
        }
        if (exists && new FileInfo(statePath).Length == 0)
        {
            DisposeProtectorAndKey();
            throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "The protected pre-key store is empty.");
        }
        var parent = Path.GetDirectoryName(statePath); if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        connectionString = new SqliteConnectionStringBuilder { DataSource = statePath,
            Mode = options.AllowCreate ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite,
            Cache = SqliteCacheMode.Private, Pooling = false }.ToString();
        try
        {
            using var opened = Open(); if (exists) Validate(opened); else Create(opened);
            ValidateEncryptedHeader(); connection = Open();
        }
        catch (PreKeyV1StoreOpenException) { DisposeProtectorAndKey(); throw; }
        catch (SqliteException ex) { DisposeProtectorAndKey(); throw Failure(PreKeyV1StoreOpenFailure.UnreadableOrWrongKey, "The protected pre-key store cannot be opened with this key.", ex); }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or OverflowException)
        { DisposeProtectorAndKey(); throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "The protected pre-key store is corrupt.", ex); }
    }

    internal bool IsKeyZeroedForTesting => key.All(static value => value == 0);
    internal PreKeyV1StoreScope Scope => scope;

    internal PreKeyV1ProvisioningCapability SealAuthored(AuthoredDpk2Offering offering) =>
        PreKeyV1ProvisioningCapability.ConsumeAuthored(scope, offering, preKeyProtector);

    internal bool OwnsResponder(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration) =>
        Fixed(scope.NetworkId, networkId) &&
        Fixed(scope.AccountId, accountId) &&
        Fixed(scope.DeviceId, deviceId) &&
        scope.DeviceGeneration == deviceGeneration;

    /// <summary>
    /// Opaque, single-use bridge into the existing atomic initial-session store.
    /// Only this device-wide secret owner may mint the production permit; callers
    /// cannot construct one from raw replay hashes or caller-selected pre-key IDs.
    /// </summary>
    internal sealed class InitialSessionCommitPermit : IDisposable
    {
        private readonly Dpk2PrekeyKind kind;
        private byte[]? claimOperationId;
        private byte[]? xpc1FullReplayHash;
        private byte[]? dph2FullReplayHash;
        private byte[]? x25519PreKeyId;
        private byte[]? mlKemPreKeyId;
        private byte[]? exactTrs1;
        private int consumed;

        internal InitialSessionCommitPermit(
            Dpk2PrekeyKind kind,
            ReadOnlySpan<byte> claimOperationId,
            ReadOnlySpan<byte> xpc1FullReplayHash,
            ReadOnlySpan<byte> dph2FullReplayHash,
            ReadOnlySpan<byte> x25519PreKeyId,
            ReadOnlySpan<byte> mlKemPreKeyId,
            ReadOnlySpan<byte> exactTrs1)
        {
            PreKeyV1StoreScope.ValidateNonZero(claimOperationId, 32, nameof(claimOperationId));
            PreKeyV1StoreScope.ValidateNonZero(xpc1FullReplayHash, 32, nameof(xpc1FullReplayHash));
            PreKeyV1StoreScope.ValidateNonZero(dph2FullReplayHash, 32, nameof(dph2FullReplayHash));
            if (kind == Dpk2PrekeyKind.OneTime)
                PreKeyV1StoreScope.ValidateNonZero(x25519PreKeyId, 32, nameof(x25519PreKeyId));
            else if (kind == Dpk2PrekeyKind.LastResort)
            {
                if (!x25519PreKeyId.IsEmpty)
                    throw new ArgumentException("A last-resort reservation has no one-time X25519 pre-key ID.", nameof(x25519PreKeyId));
            }
            else throw new ArgumentOutOfRangeException(nameof(kind));
            PreKeyV1StoreScope.ValidateNonZero(mlKemPreKeyId, 32, nameof(mlKemPreKeyId));
            if (exactTrs1.Length is < 600 or > 2_097_152)
                throw new ArgumentOutOfRangeException(nameof(exactTrs1),
                    "The exact TRS1 must fit the sealed initial-session bounds.");
            this.kind = kind;
            this.claimOperationId = claimOperationId.ToArray();
            this.xpc1FullReplayHash = xpc1FullReplayHash.ToArray();
            this.dph2FullReplayHash = dph2FullReplayHash.ToArray();
            this.x25519PreKeyId = x25519PreKeyId.ToArray();
            this.mlKemPreKeyId = mlKemPreKeyId.ToArray();
            this.exactTrs1 = exactTrs1.ToArray();
        }

#if DEEP_TEST_INTERNALS
        internal static InitialSessionCommitPermit CreateForTests(
            Dpk2PrekeyKind kind,
            ReadOnlySpan<byte> claimOperationId,
            ReadOnlySpan<byte> xpc1FullReplayHash,
            ReadOnlySpan<byte> dph2FullReplayHash,
            ReadOnlySpan<byte> x25519PreKeyId,
            ReadOnlySpan<byte> mlKemPreKeyId,
            ReadOnlySpan<byte> exactTrs1) => new(
                kind, claimOperationId, xpc1FullReplayHash, dph2FullReplayHash,
                x25519PreKeyId, mlKemPreKeyId, exactTrs1);
#endif

        internal Payload Consume()
        {
            if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
                throw new InvalidOperationException("The PreKeyV1 initial-session permit is single-use.");
            return new Payload(
                kind == Dpk2PrekeyKind.OneTime
                    ? MessagingCryptoV1InitialPreKeySource.DeviceWideOneTimeReservation
                    : MessagingCryptoV1InitialPreKeySource.DeviceWideLastResortReservation,
                Take(ref claimOperationId),
                Take(ref xpc1FullReplayHash),
                Take(ref dph2FullReplayHash),
                Take(ref x25519PreKeyId),
                Take(ref mlKemPreKeyId),
                Take(ref exactTrs1));
        }

        public void Dispose()
        {
            Zero(ref claimOperationId);
            Zero(ref xpc1FullReplayHash);
            Zero(ref dph2FullReplayHash);
            Zero(ref x25519PreKeyId);
            Zero(ref mlKemPreKeyId);
            Zero(ref exactTrs1);
        }

        private static byte[] Take(ref byte[]? value) => Interlocked.Exchange(ref value, null) ??
            throw new InvalidOperationException("The PreKeyV1 initial-session permit lost ownership.");

        private static void Zero(ref byte[]? value)
        {
            var owned = Interlocked.Exchange(ref value, null);
            if (owned is not null) CryptographicOperations.ZeroMemory(owned);
        }

        internal sealed class Payload(
            MessagingCryptoV1InitialPreKeySource preKeySource,
            byte[] claimOperationId,
            byte[] xpc1FullReplayHash,
            byte[] dph2FullReplayHash,
            byte[] x25519PreKeyId,
            byte[] mlKemPreKeyId,
            byte[] exactTrs1) : IDisposable
        {
            internal MessagingCryptoV1InitialPreKeySource PreKeySource { get; } = preKeySource;
            internal byte[] ClaimOperationId { get; } = claimOperationId;
            internal byte[] Xpc1FullReplayHash { get; } = xpc1FullReplayHash;
            internal byte[] Dph2FullReplayHash { get; } = dph2FullReplayHash;
            internal byte[] X25519PreKeyId { get; } = x25519PreKeyId;
            internal byte[] MlKemPreKeyId { get; } = mlKemPreKeyId;
            internal byte[] ExactTrs1 { get; } = exactTrs1;

            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(ClaimOperationId);
                CryptographicOperations.ZeroMemory(Xpc1FullReplayHash);
                CryptographicOperations.ZeroMemory(Dph2FullReplayHash);
                CryptographicOperations.ZeroMemory(X25519PreKeyId);
                CryptographicOperations.ZeroMemory(MlKemPreKeyId);
                CryptographicOperations.ZeroMemory(ExactTrs1);
            }
        }
    }

    internal async ValueTask<PreKeyV1ProvisionDisposition> ProvisionAsync(
        PreKeyV1ProvisioningCapability capability, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(capability); using var payload = capability.Consume();
        var record = Dpk2Codec.Decode(payload.ExactDpk2);
        var exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
        var secretHash = SHA256.HashData(payload.SealedSecret);
        var fingerprint = FingerprintProvision(record, exactHash, secretHash);
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: false);
            if (IsForkLatched(db, transaction)) return PreKeyV1ProvisionDisposition.AlreadyForkLatched;
            if (HasHistoricalClaim(db, transaction, exactHash, record))
            {
                var incumbent = HistoricalFingerprint(db, transaction, exactHash, record);
                try { LatchFork(db, transaction, 4, incumbent, fingerprint, null, null); }
                finally { CryptographicOperations.ZeroMemory(incumbent); }
                return PreKeyV1ProvisionDisposition.ForkLatched;
            }
            var collision = ReadProvisionCollision(db, transaction, record);
            if (collision is not null)
            {
                using (collision)
                {
                    if (Fixed(collision.Fingerprint, fingerprint)) return PreKeyV1ProvisionDisposition.ExactReplay;
                    LatchFork(db, transaction, 4, collision.Fingerprint, fingerprint, null, null);
                    return PreKeyV1ProvisionDisposition.ForkLatched;
                }
            }
            InsertProvision(db, transaction, record, exactHash, payload);
            transaction.Commit(); return PreKeyV1ProvisionDisposition.Provisioned;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactHash); CryptographicOperations.ZeroMemory(secretHash);
            CryptographicOperations.ZeroMemory(fingerprint); if (entered) gate.Release();
        }
    }

    internal async ValueTask<PreKeyV1InitialSessionSagaResult> CommitInitialSessionSagaAsync(
        VerifiedDevicePreKeyClaimReservation verifiedReservation,
        VerifiedInitialSessionPreKeyClaim verifiedClaim,
        SqliteMessagingCryptoV1Store sessionStore,
        ManagedResponderInitialSessionFactory factory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim);
        ArgumentNullException.ThrowIfNull(factory);
        using var capability = PreKeyV1ClaimCapability.ConsumeVerified(verifiedReservation);
        using (factory)
        {
            return await CommitInitialSessionSagaCoreAsync(
                    capability,
                    sessionStore,
                    restored => factory.CreateExactTrs1(verifiedClaim, restored),
                    nameof(factory),
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

#if DEEP_TEST_INTERNALS
    internal ValueTask<PreKeyV1InitialSessionSagaResult> CommitInitialSessionSagaForTestsAsync(
        PreKeyV1ClaimCapability capability,
        SqliteMessagingCryptoV1Store sessionStore,
        ReadOnlyMemory<byte> exactTrs1,
        CancellationToken cancellationToken = default) =>
        CommitInitialSessionSagaCoreAsync(
            capability,
            sessionStore,
            _ => exactTrs1.ToArray(),
            nameof(exactTrs1),
            cancellationToken);
#endif

    private async ValueTask<PreKeyV1InitialSessionSagaResult> CommitInitialSessionSagaCoreAsync(
        PreKeyV1ClaimCapability capability,
        SqliteMessagingCryptoV1Store sessionStore,
        Func<RestoredDpk2PreKeySecretCapability, byte[]> createExactTrs1,
        string sourceName,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(sessionStore);
        ArgumentNullException.ThrowIfNull(createExactTrs1);
        using var claim = capability.Consume();
        if (!sessionStore.OwnsSession(claim.SessionId))
            throw new CryptographicException("The verified pre-key claim session does not match the messaging store scope.");

        byte[]? exactTrs1 = null;
        try
        {
            var reserve = await ReserveAndUseAsync(claim, restored =>
            {
                exactTrs1 = createExactTrs1(restored) ??
                    throw new InvalidOperationException("The initial-session factory returned no exact TRS1.");
                MessagingCryptoV1PreparedTransition.ValidateTrs1(exactTrs1, sourceName);
            }, cancellationToken).ConfigureAwait(false);

            if (reserve.Disposition == PreKeyV1ClaimDisposition.ExactFinalReplay)
            {
                var initialSessionHash = await ReadBoundInitialSessionHashAsync(claim, cancellationToken)
                    .ConfigureAwait(false);
                try
                {
                    var exact = initialSessionHash.Length == 32 &&
                        await sessionStore.HasExactDeviceWideInitialSessionAsync(
                            claim.Kind, claim.OperationId, claim.Xpc1FullReplayHash,
                            claim.Dph2FullReplayHash, claim.X25519PreKeyId,
                            claim.MlKemPreKeyId, initialSessionHash, cancellationToken)
                            .ConfigureAwait(false);
                    return new(exact
                            ? PreKeyV1InitialSessionSagaDisposition.ExactReplay
                            : PreKeyV1InitialSessionSagaDisposition.SessionRejected,
                        reserve.Disposition,
                        exact ? MessagingCryptoV1CommitDisposition.ExactReplay : null,
                        false);
                }
                finally { CryptographicOperations.ZeroMemory(initialSessionHash); }
            }
            if (reserve.ForkLatched)
                return new(PreKeyV1InitialSessionSagaDisposition.ForkLatched, reserve.Disposition, null, true);
            if (reserve.Disposition == PreKeyV1ClaimDisposition.Unavailable)
                return new(PreKeyV1InitialSessionSagaDisposition.PreKeyUnavailable, reserve.Disposition, null, false);
            if (reserve.Disposition is not (PreKeyV1ClaimDisposition.Reserved or PreKeyV1ClaimDisposition.ExactReservedReplay) || exactTrs1 is null)
                return new(PreKeyV1InitialSessionSagaDisposition.SessionRejected, reserve.Disposition, null, false);

            var binding = await BindInitialSessionAsync(claim, exactTrs1, cancellationToken).ConfigureAwait(false);
            if (binding is PreKeyV1ClaimDisposition.ForkLatched or PreKeyV1ClaimDisposition.AlreadyForkLatched)
                return new(PreKeyV1InitialSessionSagaDisposition.ForkLatched, binding, null, true);

            using var permit = new InitialSessionCommitPermit(
                claim.Kind, claim.OperationId, claim.Xpc1FullReplayHash, claim.Dph2FullReplayHash,
                claim.X25519PreKeyId, claim.MlKemPreKeyId, exactTrs1);
            using var handoff = MessagingCryptoV1InitialSessionHandoff.CreateFromDeviceWidePreKeyOwner(permit);
            var committed = await sessionStore.CommitInitialSessionAsync(handoff, cancellationToken).ConfigureAwait(false);
            if (committed.Disposition is not (MessagingCryptoV1CommitDisposition.Initialized or MessagingCryptoV1CommitDisposition.ExactReplay))
                return new(committed.ForkLatched
                        ? PreKeyV1InitialSessionSagaDisposition.ForkLatched
                        : PreKeyV1InitialSessionSagaDisposition.SessionRejected,
                    reserve.Disposition, committed.Disposition, committed.ForkLatched);

            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterSessionCommitBeforeFinalize);
            var finalized = await FinalizeAsync(claim, burn: false, requireInitialSessionBinding: true,
                cancellationToken).ConfigureAwait(false);
            if (finalized.ForkLatched)
                return new(PreKeyV1InitialSessionSagaDisposition.ForkLatched, finalized.Disposition,
                    committed.Disposition, true);
            if (finalized.Disposition is not (PreKeyV1ClaimDisposition.Consumed or PreKeyV1ClaimDisposition.ExactFinalReplay))
                return new(PreKeyV1InitialSessionSagaDisposition.SessionRejected, finalized.Disposition,
                    committed.Disposition, false);
            return new(committed.Disposition == MessagingCryptoV1CommitDisposition.Initialized
                    ? PreKeyV1InitialSessionSagaDisposition.Initialized
                    : PreKeyV1InitialSessionSagaDisposition.ExactReplay,
                finalized.Disposition, committed.Disposition, false);
        }
        finally
        {
            if (exactTrs1 is not null) CryptographicOperations.ZeroMemory(exactTrs1);
        }
    }

    private async ValueTask<PreKeyV1ClaimResult> ReserveAndUseAsync(
        PreKeyV1ClaimCapability.Payload claim,
        Action<RestoredDpk2PreKeySecretCapability> callback,
        CancellationToken cancellationToken)
    {
        var fingerprint = FingerprintClaim(claim);
        RestoredDpk2PreKeySecretCapability? restored = null; var entered = false;
        PreKeyV1ClaimResult result;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.BeforeReserveTransaction);
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: false);
            if (IsForkLatched(db, transaction))
                return new(PreKeyV1ClaimDisposition.AlreadyForkLatched, false, true, claim.LastResortCounter);
            using var prior = ReadClaim(db, transaction, claim.OperationId);
            if (prior is not null)
            {
                if (!Fixed(prior.Fingerprint, fingerprint))
                {
                    LatchFork(db, transaction, 1, prior.Fingerprint, fingerprint, prior.OperationId, claim.OperationId);
                    return new(PreKeyV1ClaimDisposition.ForkLatched, false, true, claim.LastResortCounter);
                }
                if (prior.State != 1)
                    return new(PreKeyV1ClaimDisposition.ExactFinalReplay, false, false, claim.LastResortCounter);
                restored = ReadRestoredCapability(db, transaction, claim);
                transaction.Commit();
                result = new(PreKeyV1ClaimDisposition.ExactReservedReplay, true, false, claim.LastResortCounter);
            }
            else
            {
                using var reused = ReadClaimCollision(db, transaction, claim);
                if (reused is not null)
                {
                    LatchFork(db, transaction, claim.Kind == Dpk2PrekeyKind.OneTime ? 2 : 3,
                        reused.Fingerprint, fingerprint, reused.OperationId, claim.OperationId);
                    return new(PreKeyV1ClaimDisposition.ForkLatched, false, true, claim.LastResortCounter);
                }
                if (!CanReserve(db, transaction, claim))
                    return new(PreKeyV1ClaimDisposition.Unavailable, false, false, claim.LastResortCounter);
                InsertClaim(db, transaction, claim, fingerprint);
                PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterClaimInsert);
                if (claim.Kind == Dpk2PrekeyKind.OneTime) MarkOneTimeReserved(db, transaction, claim.ExactDpk2Hash);
                PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterInventoryUpdate);
                restored = ReadRestoredCapability(db, transaction, claim);
                PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.BeforeReserveCommit);
                transaction.Commit();
                PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterReserveCommit);
                result = new(PreKeyV1ClaimDisposition.Reserved, true, false, claim.LastResortCounter);
            }
            callback(restored!); return result;
        }
        finally
        {
            restored?.Dispose();
            CryptographicOperations.ZeroMemory(fingerprint); if (entered) gate.Release();
        }
    }

#if DEEP_TEST_INTERNALS
    internal async ValueTask<PreKeyV1ClaimResult> ReserveAndRestoreForTestsAsync(
        PreKeyV1ClaimCapability capability,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(capability);
        using var claim = capability.Consume();
        return await ReserveAndUseAsync(claim, static _ => { }, cancellationToken)
            .ConfigureAwait(false);
    }

    internal ValueTask<PreKeyV1ClaimResult> ConsumeAsync(PreKeyV1ClaimCapability capability,
        CancellationToken cancellationToken = default) => FinalizeAsync(capability, burn: false, cancellationToken);
    internal ValueTask<PreKeyV1ClaimResult> BurnAsync(PreKeyV1ClaimCapability capability,
        CancellationToken cancellationToken = default) => FinalizeAsync(capability, burn: true, cancellationToken);

    internal async ValueTask<bool> AreLastResortSecretsClearedForTestsAsync(
        ReadOnlyMemory<byte> exactDpk2Hash,
        CancellationToken cancellationToken = default)
    {
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true;
            ThrowIfDisposed(); using var command = GetConnection().CreateCommand();
            command.CommandText = "SELECT sealed_secret IS NULL FROM last_resort_prekeys WHERE exact_dpk2_hash=$hash;";
            Add(command, "$hash", exactDpk2Hash.ToArray());
            return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
        }
        finally { if (entered) gate.Release(); }
    }

    private async ValueTask<PreKeyV1ClaimResult> FinalizeAsync(
        PreKeyV1ClaimCapability capability, bool burn, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability); using var claim = capability.Consume();
        return await FinalizeAsync(claim, burn, requireInitialSessionBinding: false, cancellationToken)
            .ConfigureAwait(false);
    }
#endif

    private async ValueTask<PreKeyV1ClaimResult> FinalizeAsync(
        PreKeyV1ClaimCapability.Payload claim,
        bool burn,
        bool requireInitialSessionBinding,
        CancellationToken cancellationToken)
    {
        var fingerprint = FingerprintClaim(claim); var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: false);
            if (IsForkLatched(db, transaction)) return new(PreKeyV1ClaimDisposition.AlreadyForkLatched, false, true, claim.LastResortCounter);
            using var prior = ReadClaim(db, transaction, claim.OperationId);
            if (prior is null || !Fixed(prior.Fingerprint, fingerprint))
            {
                if (prior is not null)
                {
                    LatchFork(db, transaction, 1, prior.Fingerprint, fingerprint, prior.OperationId, claim.OperationId);
                    return new(PreKeyV1ClaimDisposition.ForkLatched, false, true, claim.LastResortCounter);
                }
                return new(PreKeyV1ClaimDisposition.InvalidState, false, false, claim.LastResortCounter);
            }
            if (requireInitialSessionBinding && prior.InitialSessionHash.Length != 32)
                return new(PreKeyV1ClaimDisposition.InvalidState, false, false, claim.LastResortCounter);
            var target = burn ? 3 : 2;
            if (prior.State != 1)
                return new(prior.State == target ? PreKeyV1ClaimDisposition.ExactFinalReplay : PreKeyV1ClaimDisposition.InvalidState,
                    false, false, claim.LastResortCounter);
            UpdateClaimState(db, transaction, claim.OperationId, target);
            if (claim.Kind == Dpk2PrekeyKind.OneTime) DeleteOneTime(db, transaction, claim.ExactDpk2Hash);
            else AdvanceLastResort(db, transaction, claim.ExactDpk2Hash, claim.LastResortCounter);
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.BeforeFinalizeCommit);
            transaction.Commit(); PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterFinalizeCommit);
            return new(burn ? PreKeyV1ClaimDisposition.Burned : PreKeyV1ClaimDisposition.Consumed,
                false, false, claim.LastResortCounter);
        }
        finally { CryptographicOperations.ZeroMemory(fingerprint); if (entered) gate.Release(); }
    }

    private async ValueTask<PreKeyV1ClaimDisposition> BindInitialSessionAsync(
        PreKeyV1ClaimCapability.Payload claim,
        ReadOnlyMemory<byte> exactTrs1,
        CancellationToken cancellationToken)
    {
        var claimFingerprint = FingerprintClaim(claim);
        var sessionHash = SHA256.HashData(exactTrs1.Span);
        var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: false);
            if (IsForkLatched(db, transaction)) return PreKeyV1ClaimDisposition.AlreadyForkLatched;
            using var prior = ReadClaim(db, transaction, claim.OperationId);
            if (prior is null || !Fixed(prior.Fingerprint, claimFingerprint) || prior.State != 1)
                return PreKeyV1ClaimDisposition.InvalidState;
            if (prior.InitialSessionHash.Length == 32)
            {
                if (Fixed(prior.InitialSessionHash, sessionHash))
                    return PreKeyV1ClaimDisposition.ExactReservedReplay;
                LatchFork(db, transaction, 5, prior.InitialSessionHash, sessionHash,
                    prior.OperationId, claim.OperationId);
                return PreKeyV1ClaimDisposition.ForkLatched;
            }
            using var update = db.CreateCommand(); update.Transaction = transaction;
            update.CommandText = "UPDATE prekey_claim_journal SET initial_session_hash=$hash WHERE operation_id=$operation AND state=1 AND initial_session_hash IS NULL;";
            Add(update, "$hash", sessionHash); Add(update, "$operation", claim.OperationId);
            if (update.ExecuteNonQuery() != 1)
                throw new InvalidOperationException("Initial-session binding CAS failed.");
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterInitialSessionBindingBeforeCommit);
            transaction.Commit();
            PreKeyV1StoreTestHooks.Hit(PreKeyV1StoreFailpoint.AfterInitialSessionBindingCommit);
            return PreKeyV1ClaimDisposition.Reserved;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(claimFingerprint);
            CryptographicOperations.ZeroMemory(sessionHash);
            if (entered) gate.Release();
        }
    }

    private async ValueTask<byte[]> ReadBoundInitialSessionHashAsync(
        PreKeyV1ClaimCapability.Payload claim,
        CancellationToken cancellationToken)
    {
        var fingerprint = FingerprintClaim(claim); var entered = false;
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true; ThrowIfDisposed();
            var db = GetConnection(); using var transaction = db.BeginTransaction(deferred: true);
            if (IsForkLatched(db, transaction)) return [];
            using var prior = ReadClaim(db, transaction, claim.OperationId);
            return prior is not null && prior.State == 2 && Fixed(prior.Fingerprint, fingerprint)
                ? prior.InitialSessionHash.ToArray()
                : [];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fingerprint);
            if (entered) gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await gate.WaitAsync().ConfigureAwait(false);
        try { connection?.Dispose(); connection = null; preKeyProtector.Dispose(); CryptographicOperations.ZeroMemory(key); }
        finally { gate.Release(); }
    }

    private void Create(SqliteConnection db)
    {
        Execute(db, null, $"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaGeneration}; PRAGMA journal_mode=WAL;");
        Execute(db, null, SchemaDdl); using var command = db.CreateCommand();
        command.CommandText = "INSERT INTO prekey_meta VALUES(1,$database,$network,$account,$accountGeneration,$device,$deviceGeneration,$dpdRef,$dpdHash,0);";
        Add(command, "$database", U64(scope.DatabaseGeneration)); Add(command, "$network", scope.NetworkId.ToArray());
        Add(command, "$account", scope.AccountId.ToArray()); Add(command, "$accountGeneration", U64(scope.AccountGeneration));
        Add(command, "$device", scope.DeviceId.ToArray()); Add(command, "$deviceGeneration", U64(scope.DeviceGeneration));
        Add(command, "$dpdRef", scope.Dpd1Reference.ToArray()); Add(command, "$dpdHash", scope.Dpd1Hash.ToArray());
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Pre-key scope insert failed.");
        Execute(db, null, "PRAGMA wal_checkpoint(FULL);"); Validate(db);
    }

    private void Validate(SqliteConnection db)
    {
        if (ScalarLong(db, "PRAGMA application_id;") != ApplicationId) throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Unexpected pre-key application ID.");
        if (ScalarLong(db, "PRAGMA user_version;") != SchemaGeneration) throw Failure(PreKeyV1StoreOpenFailure.UnsupportedGeneration, "Unsupported pre-key schema generation.");
        ValidateCipher(db);
        if (!string.Equals(Convert.ToString(Scalar(db, "PRAGMA quick_check;"), CultureInfo.InvariantCulture), "ok", StringComparison.OrdinalIgnoreCase))
            throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Pre-key quick check failed.");
        var actual = HashSchema(ReadActualSchema(db));
        try { if (!Fixed(actual, ExpectedSchemaFingerprint)) throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Pre-key DDL differs from the sealed schema."); }
        finally { CryptographicOperations.ZeroMemory(actual); }
        using var command = db.CreateCommand();
        command.CommandText = "SELECT database_generation,network_id,account_id,account_generation,device_id,device_generation,dpd1_reference,dpd1_hash,fork_latched FROM prekey_meta WHERE singleton=1;";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Pre-key scope metadata is absent.");
        if (!FixedColumn(reader, 0, U64(scope.DatabaseGeneration)) || !FixedColumn(reader, 1, scope.NetworkId) ||
            !FixedColumn(reader, 2, scope.AccountId) || !FixedColumn(reader, 3, U64(scope.AccountGeneration)) ||
            !FixedColumn(reader, 4, scope.DeviceId) || !FixedColumn(reader, 5, U64(scope.DeviceGeneration)) ||
            !FixedColumn(reader, 6, scope.Dpd1Reference) || !FixedColumn(reader, 7, scope.Dpd1Hash))
            throw Failure(PreKeyV1StoreOpenFailure.ScopeMismatch, "Pre-key store scope differs from the requested device generation.");
        var latched = reader.GetInt32(8) == 1; if (reader.Read()) throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Duplicate pre-key scope rows exist.");
        reader.Close();
        var forkCount = ScalarLong(db, "SELECT count(*) FROM prekey_fork_latch;");
        if (latched ? forkCount != 1 : forkCount != 0) throw Failure(PreKeyV1StoreOpenFailure.Corrupt, "Pre-key fork evidence is inconsistent.");
        ValidateRows(db);
    }

    private void ValidateRows(SqliteConnection db)
    {
        using var oneTime = db.CreateCommand();
        oneTime.CommandText = "SELECT exact_dpk2_hash,exact_dpk2,sealed_secret FROM one_time_prekeys;";
        using var reader = oneTime.ExecuteReader();
        while (reader.Read())
        {
            var exact = (byte[])reader[1]; var sealedSecret = (byte[])reader[2]; var record = Dpk2Codec.Decode(exact);
            var hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
            try
            {
                if (record.MlKemKind != Dpk2PrekeyKind.OneTime || !Fixed(hash, (byte[])reader[0]) ||
                    !RecordMatchesStoreScope(record))
                    throw new FormatException("Persisted one-time DPK2 identity or secret is corrupt.");
                using var restored = preKeyProtector.Restore(
                    Dpk2PreKeyPersistenceBlob.Decode(sealedSecret), exact,
                    new Dpk2PreKeyPersistenceScope(scope.NetworkId, scope.AccountId,
                        scope.AccountGeneration, scope.DeviceId, scope.DeviceGeneration, scope.Dpd1Reference));
            }
            finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(sealedSecret); CryptographicOperations.ZeroMemory(hash); }
        }
        reader.Close();
        using var last = db.CreateCommand(); last.CommandText = "SELECT exact_dpk2_hash,exact_dpk2,sealed_secret,reuse_limit,next_counter FROM last_resort_prekeys;";
        using var lastReader = last.ExecuteReader();
        while (lastReader.Read())
        {
            var exact = (byte[])lastReader[1];
            var sealedSecret = lastReader.IsDBNull(2) ? [] : (byte[])lastReader[2];
            var record = Dpk2Codec.Decode(exact); var hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
            try
            {
                var exhausted = lastReader.GetInt32(4) == record.ReuseLimit + 1;
                if (record.MlKemKind != Dpk2PrekeyKind.LastResort || !Fixed(hash, (byte[])lastReader[0]) ||
                    !RecordMatchesStoreScope(record) || (!exhausted && sealedSecret.Length == 0) ||
                    (exhausted && sealedSecret.Length != 0) || record.ReuseLimit != lastReader.GetInt32(3) ||
                    lastReader.GetInt32(4) > record.ReuseLimit + 1)
                    throw new FormatException("Persisted last-resort DPK2 policy is corrupt.");
                if (!exhausted)
                    using (preKeyProtector.Restore(Dpk2PreKeyPersistenceBlob.Decode(sealedSecret), exact,
                        new Dpk2PreKeyPersistenceScope(scope.NetworkId, scope.AccountId,
                            scope.AccountGeneration, scope.DeviceId, scope.DeviceGeneration, scope.Dpd1Reference))) { }
            }
            finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(sealedSecret); CryptographicOperations.ZeroMemory(hash); }
        }
        lastReader.Close();
        ValidatePublicationRows(db);
    }

    private bool RecordMatchesStoreScope(Dpk2Record record) =>
        Fixed(record.NetworkId.Span, scope.NetworkId) &&
        Fixed(record.ResponderAccountId.Span, scope.AccountId) &&
        Fixed(record.ResponderDeviceId.Span, scope.DeviceId) &&
        record.ResponderDeviceGeneration == scope.DeviceGeneration &&
        Fixed(record.ResponderDpd1Ref.Span, scope.Dpd1Reference);

    private static void InsertProvision(SqliteConnection db, SqliteTransaction transaction, Dpk2Record record,
        byte[] hash, PreKeyV1ProvisioningCapability.Payload payload)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        if (record.MlKemKind == Dpk2PrekeyKind.OneTime)
        {
            command.CommandText = "INSERT INTO one_time_prekeys VALUES($hash,$exact,$epoch,$bundle,$xId,$mlId,$sealed,1);";
            Add(command, "$xId", record.OneTimeX25519PrekeyId.ToArray());
        }
        else
        {
            command.CommandText = "INSERT INTO last_resort_prekeys VALUES($hash,$exact,$epoch,$bundle,$mlId,$sealed,$limit,1);";
            Add(command, "$limit", (int)record.ReuseLimit);
        }
        Add(command, "$hash", hash); Add(command, "$exact", payload.ExactDpk2); Add(command, "$epoch", U64(record.InventoryEpoch));
        Add(command, "$bundle", record.BundleId.ToArray()); Add(command, "$mlId", record.MlKemPrekeyId.ToArray()); Add(command, "$sealed", payload.SealedSecret);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("DPK2 provisioning insert failed.");
    }

    private static ProvisionCollision? ReadProvisionCollision(SqliteConnection db, SqliteTransaction transaction, Dpk2Record record)
    {
        using var command = db.CreateCommand(); command.Transaction = transaction;
        command.CommandText = record.MlKemKind == Dpk2PrekeyKind.OneTime
            ? "SELECT exact_dpk2,sealed_secret FROM one_time_prekeys WHERE exact_dpk2_hash=$hash OR bundle_id=$bundle OR x25519_prekey_id=$x OR mlkem_prekey_id=$ml LIMIT 1;"
            : "SELECT exact_dpk2,sealed_secret FROM last_resort_prekeys WHERE exact_dpk2_hash=$hash OR bundle_id=$bundle OR mlkem_prekey_id=$ml LIMIT 1;";
        var hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(record);
        try
        {
            Add(command, "$hash", hash); Add(command, "$bundle", record.BundleId.ToArray()); Add(command, "$ml", record.MlKemPrekeyId.ToArray());
            if (record.MlKemKind == Dpk2PrekeyKind.OneTime) Add(command, "$x", record.OneTimeX25519PrekeyId.ToArray());
            using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
            var exact = (byte[])reader[0];
            var sealedSecret = reader.IsDBNull(1) ? [] : (byte[])reader[1];
            var persisted = Dpk2Codec.Decode(exact); var persistedHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(persisted);
            var blobHash = SHA256.HashData(sealedSecret);
            try { return new ProvisionCollision(FingerprintProvision(persisted, persistedHash, blobHash)); }
            finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(sealedSecret); CryptographicOperations.ZeroMemory(persistedHash); CryptographicOperations.ZeroMemory(blobHash); }
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    private static bool HasHistoricalClaim(SqliteConnection db, SqliteTransaction tx, byte[] hash, Dpk2Record record)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT count(*) FROM prekey_claim_journal WHERE exact_dpk2_hash=$hash OR mlkem_prekey_id=$ml OR (kind=1 AND x25519_prekey_id=$x);";
        Add(command, "$hash", hash); Add(command, "$ml", record.MlKemPrekeyId.ToArray());
        Add(command, "$x", record.MlKemKind == Dpk2PrekeyKind.OneTime ? record.OneTimeX25519PrekeyId.ToArray() : new byte[32]);
        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) != 0;
    }

    private static byte[] HistoricalFingerprint(SqliteConnection db, SqliteTransaction tx, byte[] hash, Dpk2Record record)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT fingerprint FROM prekey_claim_journal WHERE exact_dpk2_hash=$hash OR mlkem_prekey_id=$ml OR (kind=1 AND x25519_prekey_id=$x) LIMIT 1;";
        Add(command, "$hash", hash); Add(command, "$ml", record.MlKemPrekeyId.ToArray());
        Add(command, "$x", record.MlKemKind == Dpk2PrekeyKind.OneTime ? record.OneTimeX25519PrekeyId.ToArray() : new byte[32]);
        return (byte[]?)command.ExecuteScalar() ?? throw new FormatException("Historical pre-key evidence vanished.");
    }

    private static bool CanReserve(SqliteConnection db, SqliteTransaction tx, PreKeyV1ClaimCapability.Payload claim)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        if (claim.Kind == Dpk2PrekeyKind.OneTime)
            command.CommandText = "SELECT count(*) FROM one_time_prekeys WHERE exact_dpk2_hash=$hash AND x25519_prekey_id=$x AND mlkem_prekey_id=$ml AND state=1;";
        else
            command.CommandText = "SELECT count(*) FROM last_resort_prekeys WHERE exact_dpk2_hash=$hash AND mlkem_prekey_id=$ml AND next_counter=$counter AND next_counter<=reuse_limit AND NOT EXISTS(SELECT 1 FROM prekey_claim_journal WHERE exact_dpk2_hash=$hash AND kind=2 AND state=1);";
        AddClaim(command, claim); return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static void InsertClaim(SqliteConnection db, SqliteTransaction tx, PreKeyV1ClaimCapability.Payload claim, byte[] fingerprint)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "INSERT INTO prekey_claim_journal VALUES($operation,$fingerprint,$kind,$session,$hash,$xpc1,$dph2,$x,$ml,$counter,NULL,1);";
        Add(command, "$operation", claim.OperationId); Add(command, "$fingerprint", fingerprint); Add(command, "$kind", (int)claim.Kind);
        Add(command, "$session", claim.SessionId); Add(command, "$hash", claim.ExactDpk2Hash); Add(command, "$xpc1", claim.Xpc1FullReplayHash);
        Add(command, "$dph2", claim.Dph2FullReplayHash); Add(command, "$x", claim.X25519PreKeyId.Length == 0 ? DBNull.Value : claim.X25519PreKeyId);
        Add(command, "$ml", claim.MlKemPreKeyId); Add(command, "$counter", (int)claim.LastResortCounter);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Pre-key reservation journal insert failed.");
    }

    private static ClaimRow? ReadClaim(SqliteConnection db, SqliteTransaction tx, byte[] operation)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT operation_id,fingerprint,initial_session_hash,state FROM prekey_claim_journal WHERE operation_id=$operation;";
        Add(command, "$operation", operation); using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        return new((byte[])reader[0], (byte[])reader[1], reader.IsDBNull(2) ? [] : (byte[])reader[2], reader.GetInt32(3));
    }

    private static ClaimRow? ReadClaimCollision(SqliteConnection db, SqliteTransaction tx, PreKeyV1ClaimCapability.Payload claim)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = claim.Kind == Dpk2PrekeyKind.OneTime
            ? "SELECT operation_id,fingerprint,initial_session_hash,state FROM prekey_claim_journal WHERE kind=1 AND (x25519_prekey_id=$x OR mlkem_prekey_id=$ml) LIMIT 1;"
            : "SELECT operation_id,fingerprint,initial_session_hash,state FROM prekey_claim_journal WHERE kind=2 AND exact_dpk2_hash=$hash AND last_resort_counter=$counter LIMIT 1;";
        AddClaim(command, claim); using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        return new((byte[])reader[0], (byte[])reader[1], reader.IsDBNull(2) ? [] : (byte[])reader[2], reader.GetInt32(3));
    }

    private RestoredDpk2PreKeySecretCapability ReadRestoredCapability(SqliteConnection db, SqliteTransaction tx, PreKeyV1ClaimCapability.Payload claim)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = claim.Kind == Dpk2PrekeyKind.OneTime
            ? "SELECT exact_dpk2,sealed_secret FROM one_time_prekeys WHERE exact_dpk2_hash=$hash AND state=2;"
            : "SELECT exact_dpk2,sealed_secret FROM last_resort_prekeys WHERE exact_dpk2_hash=$hash;";
        Add(command, "$hash", claim.ExactDpk2Hash); using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new CryptographicException("Reserved pre-key secret material is unavailable.");
        var exact = (byte[])reader[0];
        if (reader.IsDBNull(1))
        {
            CryptographicOperations.ZeroMemory(exact);
            throw new CryptographicException("Reserved pre-key secret material is exhausted.");
        }
        var sealedSecret = (byte[])reader[1];
        if (reader.Read()) { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(sealedSecret); throw new FormatException("Duplicate pre-key secret rows exist."); }
        try
        {
            var blob = Dpk2PreKeyPersistenceBlob.Decode(sealedSecret);
            var persistenceScope = new Dpk2PreKeyPersistenceScope(
                scope.NetworkId, scope.AccountId, scope.AccountGeneration,
                scope.DeviceId, scope.DeviceGeneration, scope.Dpd1Reference);
            return preKeyProtector.Restore(blob, exact, persistenceScope);
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(sealedSecret); }
    }

    private static void MarkOneTimeReserved(SqliteConnection db, SqliteTransaction tx, byte[] hash)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "UPDATE one_time_prekeys SET state=2 WHERE exact_dpk2_hash=$hash AND state=1;";
        Add(command, "$hash", hash); if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("One-time pre-key reserve CAS failed.");
    }

    private static void UpdateClaimState(SqliteConnection db, SqliteTransaction tx, byte[] operation, int target)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "UPDATE prekey_claim_journal SET state=$target WHERE operation_id=$operation AND state=1;";
        Add(command, "$target", target); Add(command, "$operation", operation);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Pre-key finalization CAS failed.");
    }

    private static void DeleteOneTime(SqliteConnection db, SqliteTransaction tx, byte[] hash)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "DELETE FROM one_time_prekeys WHERE exact_dpk2_hash=$hash AND state=2;";
        Add(command, "$hash", hash); if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("One-time pre-key deletion failed.");
    }

    private static void AdvanceLastResort(SqliteConnection db, SqliteTransaction tx, byte[] hash, ushort counter)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "UPDATE last_resort_prekeys SET sealed_secret=CASE WHEN next_counter+1>reuse_limit THEN NULL ELSE sealed_secret END,next_counter=next_counter+1 WHERE exact_dpk2_hash=$hash AND next_counter=$counter;";
        Add(command, "$hash", hash); Add(command, "$counter", (int)counter);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Last-resort counter CAS failed.");
    }

    private static void AddClaim(SqliteCommand command, PreKeyV1ClaimCapability.Payload claim)
    {
        Add(command, "$hash", claim.ExactDpk2Hash); Add(command, "$x", claim.X25519PreKeyId.Length == 0 ? new byte[32] : claim.X25519PreKeyId);
        Add(command, "$ml", claim.MlKemPreKeyId); Add(command, "$counter", (int)claim.LastResortCounter);
    }

    private static void LatchFork(SqliteConnection db, SqliteTransaction tx, int reason, byte[] incumbent, byte[] conflicting, byte[]? incumbentOp, byte[]? conflictingOp)
    {
        using var command = db.CreateCommand(); command.Transaction = tx;
        command.CommandText = "INSERT INTO prekey_fork_latch VALUES(1,$reason,$incumbent,$conflicting,$incumbentOp,$conflictingOp);";
        Add(command, "$reason", reason); Add(command, "$incumbent", incumbent); Add(command, "$conflicting", conflicting);
        Add(command, "$incumbentOp", incumbentOp is null ? DBNull.Value : incumbentOp); Add(command, "$conflictingOp", conflictingOp is null ? DBNull.Value : conflictingOp);
        command.ExecuteNonQuery(); Execute(db, tx, "UPDATE prekey_meta SET fork_latched=1 WHERE singleton=1 AND fork_latched=0;"); tx.Commit();
    }

    private static bool IsForkLatched(SqliteConnection db, SqliteTransaction tx)
    {
        using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = "SELECT fork_latched FROM prekey_meta WHERE singleton=1;";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;
    }

    private static byte[] FingerprintProvision(Dpk2Record record, byte[] exactHash,
        ReadOnlySpan<byte> sealedSecretHash)
    {
        var bundleId = record.BundleId.ToArray();
        var x25519PreKeyId = record.OneTimeX25519PrekeyId.ToArray();
        var mlKemPreKeyId = record.MlKemPrekeyId.ToArray();
        var blobHash = sealedSecretHash.ToArray();
        try
        {
            return Hash("Deep/Client/PreKeyV1/provision/v3", exactHash, bundleId,
                x25519PreKeyId, mlKemPreKeyId, blobHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bundleId);
            CryptographicOperations.ZeroMemory(x25519PreKeyId);
            CryptographicOperations.ZeroMemory(mlKemPreKeyId);
            CryptographicOperations.ZeroMemory(blobHash);
        }
    }

    private static byte[] FingerprintClaim(PreKeyV1ClaimCapability.Payload claim) => Hash(
        "Deep/Client/PreKeyV1/claim/v1", new byte[] { (byte)claim.Kind }, U16(claim.LastResortCounter), claim.OperationId,
        claim.SessionId, claim.ExactDpk2Hash, claim.Xpc1FullReplayHash, claim.Dph2FullReplayHash,
        claim.X25519PreKeyId, claim.MlKemPreKeyId);

    private static byte[] Hash(string domain, params ReadOnlyMemory<byte>[] parts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256); Append(hash, Encoding.ASCII.GetBytes(domain));
        foreach (var part in parts) Append(hash, part.Span); return hash.GetHashAndReset();
    }
    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    { Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length)); hash.AppendData(length); hash.AppendData(value); }

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(connectionString);
        try { db.Open(); var rc = SQLitePCL.raw.sqlite3_key(db.Handle, key); if (rc != SQLitePCL.raw.SQLITE_OK) throw new SqliteException("SQLCipher rejected the pre-key key.", rc);
            Execute(db, null, "PRAGMA cipher_memory_security=ON; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;"); return db; }
        catch { db.Dispose(); throw; }
    }
    private static void ValidateCipher(SqliteConnection db)
    {
        if (Scalar(db, "PRAGMA cipher_version;") is not string version || !version.StartsWith("4.", StringComparison.Ordinal)) throw new InvalidOperationException("SQLCipher v4 is unavailable.");
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA cipher_integrity_check;"; using var reader = command.ExecuteReader();
        while (reader.Read()) if (!string.Equals(reader.GetString(0), "ok", StringComparison.OrdinalIgnoreCase)) throw new FormatException("SQLCipher integrity check failed.");
    }
    private void ValidateEncryptedHeader()
    { using var stream = new FileStream(statePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); Span<byte> header = stackalloc byte[16]; if (stream.Read(header) != 16 || header.SequenceEqual("SQLite format 3\0"u8)) throw new FormatException("Pre-key database header is not an encrypted SQLCipher header."); }
    private SqliteConnection GetConnection() => connection ?? throw new ObjectDisposedException(nameof(SqlitePreKeyV1SecretOwner));
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private void DisposeProtectorAndKey()
    {
        preKeyProtector.Dispose();
        CryptographicOperations.ZeroMemory(key);
    }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static void Add(SqliteCommand command, string name, object value) => command.Parameters.AddWithValue(name, value);
    private static void Execute(SqliteConnection db, SqliteTransaction? tx, string sql) { using var command = db.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); }
    private static object? Scalar(SqliteConnection db, string sql) { using var command = db.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar(); }
    private static long ScalarLong(SqliteConnection db, string sql) => Convert.ToInt64(Scalar(db, sql), CultureInfo.InvariantCulture);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool FixedColumn(SqliteDataReader reader, int ordinal, ReadOnlySpan<byte> expected) => reader[ordinal] is byte[] bytes && Fixed(bytes, expected);
    private static string[] ReadSchemaStatements() => SchemaDdl.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(statement =>
    { var match = Regex.Match(statement, @"^CREATE\s+(TABLE|UNIQUE\s+INDEX)\s+([a-z0-9_]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); if (!match.Success) throw new InvalidOperationException("Sealed pre-key schema is malformed.");
        var type = match.Groups[1].Value.StartsWith("TABLE", StringComparison.OrdinalIgnoreCase) ? "table" : "index"; var name = match.Groups[2].Value; return $"{type}|{name}|{Normalize(statement)}"; }).OrderBy(static value => value, StringComparer.Ordinal).ToArray();
    private static string[] ReadActualSchema(SqliteConnection db)
    { using var command = db.CreateCommand(); command.CommandText = "SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;"; using var reader = command.ExecuteReader(); var rows = new List<string>(); while (reader.Read()) rows.Add($"{reader.GetString(0)}|{reader.GetString(1)}|{Normalize(reader.GetString(2))}"); return rows.ToArray(); }
    private static string Normalize(string sql) => Regex.Replace(sql.Trim().TrimEnd(';'), @"\s+", " ");
    private static byte[] HashSchema(IEnumerable<string> rows) => SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', rows)));
    private static PreKeyV1StoreOpenException Failure(PreKeyV1StoreOpenFailure reason, string message, Exception? inner = null) => new(reason, message, inner);

    private sealed class ClaimRow(byte[] operationId, byte[] fingerprint, byte[] initialSessionHash, int state) : IDisposable
    { internal byte[] OperationId { get; } = operationId; internal byte[] Fingerprint { get; } = fingerprint;
        internal byte[] InitialSessionHash { get; } = initialSessionHash; internal int State { get; } = state;
        public void Dispose() { CryptographicOperations.ZeroMemory(OperationId); CryptographicOperations.ZeroMemory(Fingerprint); CryptographicOperations.ZeroMemory(InitialSessionHash); } }
    private sealed class ProvisionCollision(byte[] fingerprint) : IDisposable
    { internal byte[] Fingerprint { get; } = fingerprint; public void Dispose() => CryptographicOperations.ZeroMemory(Fingerprint); }
}
