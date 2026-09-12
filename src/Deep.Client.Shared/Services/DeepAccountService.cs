using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepAccountService
{
    internal const string PendingSecureStorageJournalSlot = DeepAccountStoreContract.PendingAccountSlot;
    private readonly IDeepAccountStore store;
    private readonly IDeepSecureStorage secureStorage;
    private readonly IClock clock;
    private readonly byte[] networkId;
    private readonly object preparedDraftOwner = new();
    private static readonly SemaphoreSlim ProcessMutationGate = new(1, 1);

    // Shared-owned compositions reuse the account's exact protected-store
    // authority without exporting it to application assemblies.
    internal IDeepSecureStorage SecureStorageForOwnedComposition => secureStorage;

    public DeepAccountService(
        IDeepAccountStore store,
        IDeepSecureStorage secureStorage,
        IClock clock,
        ReadOnlySpan<byte> networkId)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.secureStorage = secureStorage ?? throw new ArgumentNullException(nameof(secureStorage));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        if (networkId.Length != DeepAccountStoreContract.NetworkIdSize
            || networkId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                $"Network ID must contain exactly {DeepAccountStoreContract.NetworkIdSize} bytes and must not be all zero.",
                nameof(networkId));
        }

        this.networkId = networkId.ToArray();
    }

    public DeepPreparedAccountCreationDraft PrepareCreate(string displayName)
    {
        var normalizedName = NormalizeDisplayName(displayName);
        var phrase = DeepRecoveryV1.Generate();
        try
        {
            return new DeepPreparedAccountCreationDraft(
                preparedDraftOwner,
                normalizedName,
                phrase);
        }
        catch
        {
            phrase.Dispose();
            throw;
        }
    }

    public async Task<DeepAccountCreationResult> CreateAsync(
        string displayName,
        CancellationToken cancellationToken = default)
    {
        var normalizedName = NormalizeDisplayName(displayName);
        var phrase = DeepRecoveryV1.Generate();
        return await CommitNewIdentityAsync(
                phrase,
                normalizedName,
                DeepAccountActivationState.ActiveLocal,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<DeepAccountCreationResult> CommitPreparedAsync(
        DeepPreparedAccountCreationDraft draft,
        DeepOwnedRecoveryPhraseUtf8 userConfirmation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(draft);
        cancellationToken.ThrowIfCancellationRequested();
        var phrase = draft.BeginCommit(preparedDraftOwner, userConfirmation);
        try
        {
            return await CommitNewIdentityAsync(
                    phrase,
                    draft.DisplayName,
                    DeepAccountActivationState.ActiveLocal,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            draft.CompleteCommit();
        }
    }

    public async Task<DeepAccountCreationResult> RestoreAsNewDeviceAsync(
        DeepOwnedRecoveryPhraseUtf8 recoveryPhrase,
        string displayName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recoveryPhrase);
        var normalizedName = NormalizeDisplayName(displayName);
        using var phrase = recoveryPhrase.Use(VerifyRecoveryPhraseUtf8);
        return await CommitNewIdentityAsync(
            phrase,
            normalizedName,
            DeepAccountActivationState.RestorePendingActivation,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DeepLocalIdentitySnapshot?> GetLocalIdentityAsync(
        CancellationToken cancellationToken = default)
    {
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            return reconciled.Identity;
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task<bool> HasRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            if (reconciled.Identity is null)
            {
                return false;
            }

            using var retained = await secureStorage
                .ReadOwnedAsync(
                    DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retained is null)
            {
                return false;
            }
            ValidateRetainedRecoveryPhrase(retained);
            return true;
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task<bool> RevealRetainedRecoveryPhraseAsync(
        DeepRecoveryPhraseUtf8Consumer consumer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(consumer);
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            if (reconciled.Identity is null)
            {
                return false;
            }

            using var retained = await secureStorage
                .ReadOwnedAsync(
                    DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
                    cancellationToken)
                .ConfigureAwait(false);
            if (retained is null)
            {
                return false;
            }
            ValidateRetainedRecoveryPhrase(retained);
            retained.Use(bytes => consumer(bytes));
            return true;
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task DeleteRetainedRecoveryPhraseAsync(
        CancellationToken cancellationToken = default)
    {
        // Deleting recovery authority is irreversible. First prove that the
        // verifier-minted DPA1/DRS1/DPD1/DMD1 closure is durably restartable.
        _ = await EnsureGenesisDeviceActivatedAsync(cancellationToken)
            .ConfigureAwait(false);
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            if (reconciled.Identity is null)
            {
                throw new InvalidOperationException("No local Deep account exists.");
            }
            await secureStorage.DeleteBatchAsync(
                    [DeepAccountStoreContract.RetainedRecoveryPhraseSlot],
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task<DeepAccount> UpdateDisplayNameAsync(
        string displayName,
        CancellationToken cancellationToken = default)
    {
        var normalizedName = NormalizeDisplayName(displayName);
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = reconciled.Identity
                ?? throw new InvalidOperationException("No local Deep account exists.");
            var profile = new DeepLocalProfile(normalizedName, clock.UtcNow);
            await store.UpdateProfileAsync(
                    reconciled.MutationCapability,
                    current.Account.PermanentId,
                    profile,
                    cancellationToken)
                .ConfigureAwait(false);
            return current.Account with { DisplayName = normalizedName };
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task ResetLocalAccountAsync(CancellationToken cancellationToken = default)
    {
        await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var mutationLease = await store
                .AcquireMutationLeaseAsync(cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var reconciled = await RecoverPendingSecureStorageAsync(
                    mutationLease,
                    cancellationToken)
                .ConfigureAwait(false);
            var current = reconciled.Identity;
            var slotsToDelete = new HashSet<string>(StringComparer.Ordinal)
            {
                PendingSecureStorageJournalSlot,
                DeepAccountStoreContract.DatabaseAccountManifestSlot,
                DeepAccountStoreContract.RetainedRecoveryPhraseSlot
            };
            if (current is not null)
            {
                foreach (var slot in AccountSlots(current.SecureSlots))
                {
                    slotsToDelete.Add(slot);
                }
            }
            await store.ClearLocalAccountAsync(
                    reconciled.MutationCapability,
                    CancellationToken.None)
                .ConfigureAwait(false);
            await secureStorage.DeleteBatchAsync(slotsToDelete.ToArray(), CancellationToken.None)
                .ConfigureAwait(false);
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    private async Task<DeepAccountCreationResult> CommitNewIdentityAsync(
        VerifiedDeepRecoveryPhrase phrase,
        string displayName,
        DeepAccountActivationState activationState,
        CancellationToken cancellationToken)
    {
        using var retainedRecoveryPhrase = RetainedRecoveryPhraseBytes.CopyFrom(phrase);
        DeepRecoveryAccountCapabilities capabilities;
        try
        {
            capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
                phrase,
                networkId,
                DeepAccountStoreContract.CurrentAccountGeneration);
        }
        finally
        {
            // The 256-bit recovery entropy is no longer needed once the account
            // capabilities exist. Do not retain it across a store or SQLite await.
            phrase.Dispose();
        }

        using (capabilities)
        {
            await ProcessMutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using var mutationLease = await store
                    .AcquireMutationLeaseAsync(cancellationToken)
                    .ConfigureAwait(false);
                var reconciled = await RecoverPendingSecureStorageAsync(
                        mutationLease,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (reconciled.Identity is not null)
                {
                    throw new DeepAccountAlreadyExistsException();
                }

                var permanentId = DeepPermanentIdV1.FromCapabilities(capabilities);
                var accountIdentity = capabilities.AccountIdentity;

                using var deviceSecrets = new OwnedGenesisDeviceSecrets();
                using var persistedDeviceSecrets = deviceSecrets.ExportOwnedPersistenceCopy();
                var deviceSigningKey = new byte[DeepAccountStoreContract.KeyMaterialSize];
                var deviceAgreementKey = new byte[DeepAccountStoreContract.KeyMaterialSize];
                var deviceId = new byte[DeepAccountStoreContract.KeyMaterialSize];
                var deviceRevocationHandle = new byte[DeepAccountStoreContract.KeyMaterialSize];
                var devicePrekey = RandomNumberGenerator.GetBytes(DeepAccountStoreContract.KeyMaterialSize);
                var pushKey = RandomNumberGenerator.GetBytes(DeepAccountStoreContract.KeyMaterialSize);
                var messageStoreInstanceIdBytes = RandomNumberGenerator.GetBytes(
                    DeepAccountStoreContract.KeyMaterialSize);
                byte[]? pendingJournal = null;
                try
                {
                    persistedDeviceSecrets.CopyTo(
                        deviceSigningKey,
                        deviceAgreementKey,
                        deviceId,
                        deviceRevocationHandle);
                    var prekeyPublic = DeepIdentityCrypto.DeriveX25519PublicKey(devicePrekey);
                    try
                    {
                        var now = clock.UtcNow;
                        var deviceIdentity = deviceSecrets.CreateLocalIntent(accountIdentity);
                        var slots = store.GetGenerationSecureStorageSlots();
                        var device = new DeepDevice(
                            deviceIdentity,
                            prekeyPublic,
                            now);
                        var account = new DeepAccount(
                            permanentId,
                            accountIdentity,
                            displayName,
                            now,
                            activationState,
                            deviceIdentity.DeviceId);
                        var profile = new DeepLocalProfile(displayName, now);
                        var identity = new DeepLocalIdentitySnapshot(
                            DeepAccountStoreContract.CurrentStoreGeneration,
                            networkId.ToArray(),
                            account,
                            device,
                            profile,
                            slots);
                        var operation = DeepAccountCreationOperation.Create(identity);
                        var immutableIdentityCommitment = DeepAccountImmutableIdentityHash.Compute(identity);
                        var messageStoreInstanceId = MessageStoreInstanceId32.FromBytes(
                            messageStoreInstanceIdBytes);
                        try
                        {

                            pendingJournal = SqliteDeepAccountStoreBootstrap.EncodeAccountManifest(
                                operation,
                                immutableIdentityCommitment,
                                messageStoreInstanceId,
                                slots);

                            var writes = new[]
                            {
                        new DeepSecureStorageWrite(PendingSecureStorageJournalSlot, pendingJournal),
                        new DeepSecureStorageWrite(
                            DeepAccountStoreContract.DatabaseAccountManifestSlot,
                            pendingJournal),
                        new DeepSecureStorageWrite(slots.DeviceSigningKey, deviceSigningKey),
                        new DeepSecureStorageWrite(slots.DeviceAgreementKey, deviceAgreementKey),
                        new DeepSecureStorageWrite(slots.DeviceId, deviceId),
                        new DeepSecureStorageWrite(
                            slots.DeviceRevocationHandle,
                            deviceRevocationHandle),
                        new DeepSecureStorageWrite(slots.DevicePrekey, devicePrekey),
                        new DeepSecureStorageWrite(slots.PushKey, pushKey),
                        new DeepSecureStorageWrite(
                            slots.MessageStoreInstanceId,
                            messageStoreInstanceIdBytes),
                        new DeepSecureStorageWrite(
                            DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
                            retainedRecoveryPhrase.Value)
                    };
                            await secureStorage.WriteBatchAsync(writes, cancellationToken).ConfigureAwait(false);
                            try
                            {
                                await store.CreateAsync(
                                        reconciled.MutationCapability,
                                        identity,
                                        operation,
                                        immutableIdentityCommitment,
                                        cancellationToken)
                                    .ConfigureAwait(false);
                            }
                            catch (Exception creationFailure)
                            {
                                DeepAccountCreationOperation? committedOperation;
                                try
                                {
                                    committedOperation = await store
                                        .ReadCreationOperationAsync(CancellationToken.None)
                                        .ConfigureAwait(false);
                                }
                                catch (Exception reconciliationFailure)
                                {
                                    throw new DeepAccountCreationOutcomeUnknownException(
                                        creationFailure,
                                        reconciliationFailure);
                                }

                                if (committedOperation is null)
                                {
                                    await secureStorage.DeleteBatchAsync(
                                            AccountSlots(slots)
                                                .Append(PendingSecureStorageJournalSlot)
                                                .Append(DeepAccountStoreContract.DatabaseAccountManifestSlot)
                                                .Append(DeepAccountStoreContract.RetainedRecoveryPhraseSlot)
                                                .ToArray(),
                                            CancellationToken.None)
                                        .ConfigureAwait(false);
                                    throw;
                                }

                                if (!committedOperation.Matches(operation))
                                {
                                    throw ResetRequired("A different account creation operation committed while reconciliation was pending.");
                                }

                                identity = await store.ReadAsync(deviceIdentity, CancellationToken.None).ConfigureAwait(false)
                                    ?? throw ResetRequired("The committed account creation receipt has no identity row.");
                                if (!operation.MatchesIdentity(identity))
                                {
                                    throw ResetRequired("The committed account does not match its creation operation.");
                                }
                            }

                            await TryDeletePendingJournalAfterProvenCommitAsync().ConfigureAwait(false);

                            return new DeepAccountCreationResult(identity);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(prekeyPublic);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(deviceSigningKey);
                    CryptographicOperations.ZeroMemory(deviceAgreementKey);
                    CryptographicOperations.ZeroMemory(deviceId);
                    CryptographicOperations.ZeroMemory(deviceRevocationHandle);
                    CryptographicOperations.ZeroMemory(devicePrekey);
                    CryptographicOperations.ZeroMemory(pushKey);
                    CryptographicOperations.ZeroMemory(messageStoreInstanceIdBytes);
                    if (pendingJournal is not null)
                    {
                        CryptographicOperations.ZeroMemory(pendingJournal);
                    }
                }
            }
            finally
            {
                ProcessMutationGate.Release();
            }
        }
    }

    private async Task EnsureRequiredSecretsExistAsync(
        DeepLocalIdentitySnapshot identity,
        MessageStoreInstanceId32 expectedMessageStoreInstanceId,
        CancellationToken cancellationToken)
    {
        var slots = identity.SecureSlots;
        await ValidateKeyPairAsync(
                slots.DevicePrekey,
                identity.Device.PrekeyPublicKey,
                static (seed, expected) =>
                    DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(seed, expected.Span),
                cancellationToken)
            .ConfigureAwait(false);

        using var push = await secureStorage.ReadOwnedAsync(slots.PushKey, cancellationToken)
            .ConfigureAwait(false)
            ?? throw ResetRequired("The push-key secure-storage slot is missing.");
        if (push.Length != DeepAccountStoreContract.KeyMaterialSize
            || !push.Use(static value => value.IndexOfAnyExcept((byte)0) >= 0))
        {
            throw ResetRequired("The push-key secure-storage slot is invalid.");
        }

        using var instanceId = await secureStorage
            .ReadOwnedAsync(slots.MessageStoreInstanceId, cancellationToken)
            .ConfigureAwait(false)
            ?? throw ResetRequired("The message-store instance secure-storage slot is missing.");
        if (instanceId.Length != DeepAccountStoreContract.KeyMaterialSize
            || !instanceId.Use(value => CryptographicOperations.FixedTimeEquals(
                value,
                expectedMessageStoreInstanceId.Span)))
        {
            throw ResetRequired("The message-store instance secure-storage slot is invalid.");
        }
    }

    private async Task<LocalDeviceIdentityIntent> RestoreLocalDeviceIntentAsync(
        DeepAccountIdentityCapability accountIdentity,
        DeepSecureStorageSlots slots,
        CancellationToken cancellationToken)
    {
        byte[]? signingSeed = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? agreementPrivateScalar = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? deviceId = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? revocationHandle = new byte[DeepAccountStoreContract.KeyMaterialSize];
        try
        {
            await CopyExactSecureValueAsync(
                    slots.DeviceSigningKey,
                    signingSeed,
                    cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(
                    slots.DeviceAgreementKey,
                    agreementPrivateScalar,
                    cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(slots.DeviceId, deviceId, cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(
                    slots.DeviceRevocationHandle,
                    revocationHandle,
                    cancellationToken)
                .ConfigureAwait(false);

            using var persisted = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                signingSeed,
                agreementPrivateScalar,
                deviceId,
                revocationHandle);
            signingSeed = agreementPrivateScalar = deviceId = revocationHandle = null;
            using var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
            return restored.CreateLocalIntent(accountIdentity);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw ResetRequired(
                "Protected local-device identity material is invalid.",
                exception);
        }
        finally
        {
            Zero(signingSeed);
            Zero(agreementPrivateScalar);
            Zero(deviceId);
            Zero(revocationHandle);
        }
    }

    private async Task CopyExactSecureValueAsync(
        string slot,
        byte[] destination,
        CancellationToken cancellationToken)
    {
        using var value = await secureStorage.ReadOwnedAsync(slot, cancellationToken)
            .ConfigureAwait(false)
            ?? throw ResetRequired("A local-device identity secure-storage slot is missing.");
        if (value.Length != DeepAccountStoreContract.KeyMaterialSize)
        {
            throw ResetRequired(
                "A local-device identity secure-storage slot has an invalid length.");
        }
        value.CopyTo(destination);
    }

    private async Task ValidateKeyPairAsync(
        string slot,
        ReadOnlyMemory<byte> expectedPublicKey,
        PublicKeyMatcher publicKeyMatches,
        CancellationToken cancellationToken)
    {
        using var seed = await secureStorage.ReadOwnedAsync(slot, cancellationToken).ConfigureAwait(false)
            ?? throw ResetRequired("A device-key secure-storage slot is missing.");
        try
        {
            if (seed.Length != DeepAccountStoreContract.KeyMaterialSize)
            {
                throw ResetRequired("A device-key secure-storage slot has an invalid length.");
            }

            if (!seed.Use(value => publicKeyMatches(value, expectedPublicKey)))
            {
                throw ResetRequired("A device private key does not match its stored public key.");
            }
        }
        catch (ArgumentException exception)
        {
            throw ResetRequired("A device private key contains an invalid value.", exception);
        }
    }

    private async Task<ReconciledAccountState> RecoverPendingSecureStorageAsync(
        DeepAccountMutationLease mutationLease,
        CancellationToken cancellationToken)
    {
        using var manifestValue = await secureStorage
            .ReadOwnedAsync(DeepAccountStoreContract.DatabaseAccountManifestSlot, cancellationToken)
            .ConfigureAwait(false);
        using var pendingValue = await secureStorage
            .ReadOwnedAsync(PendingSecureStorageJournalSlot, cancellationToken)
            .ConfigureAwait(false);
        var manifest = manifestValue is null
            ? null
            : manifestValue.Use(SqliteDeepAccountStoreBootstrap.DecodeAccountManifest);
        var pending = pendingValue is null
            ? null
            : pendingValue.Use(SqliteDeepAccountStoreBootstrap.DecodeAccountManifest);

        var committedOperation = await store.ReadCreationOperationAsync(cancellationToken)
            .ConfigureAwait(false);
        var accountIdentity = await store.ReadAccountIdentityAsync(cancellationToken)
            .ConfigureAwait(false);
        if (manifest is null)
        {
            if (pending is not null || committedOperation is not null || accountIdentity is not null)
            {
                throw ResetRequired("Local account state is missing its fixed generation manifest.");
            }
            _ = await store.ReadAsync(null, cancellationToken).ConfigureAwait(false);
            return new ReconciledAccountState(
                null,
                null,
                new DeepAccountReconciledMutationCapability(mutationLease, null, default));
        }

        if (pending is not null && !manifest.Matches(pending))
        {
            throw ResetRequired("Pending journal and fixed generation manifest disagree.");
        }
        if (committedOperation is null)
        {
            if (accountIdentity is not null)
            {
                throw ResetRequired("A local account exists without its creation receipt.");
            }
            _ = await store.ReadAsync(null, cancellationToken).ConfigureAwait(false);
            await secureStorage.DeleteBatchAsync(
                    manifest.Slots
                        .Append(PendingSecureStorageJournalSlot)
                        .Append(DeepAccountStoreContract.DatabaseAccountManifestSlot)
                        .Append(DeepAccountStoreContract.RetainedRecoveryPhraseSlot)
                        .ToArray(),
                    CancellationToken.None)
                .ConfigureAwait(false);
            return new ReconciledAccountState(
                null,
                null,
                new DeepAccountReconciledMutationCapability(mutationLease, null, default));
        }

        if (accountIdentity is null)
        {
            throw ResetRequired("A committed account creation receipt has no identity row.");
        }
        if (!accountIdentity.NetworkId.Matches(networkId))
        {
            throw ResetRequired("The local Deep account belongs to another network.");
        }
        var generationSlots = store.GetGenerationSecureStorageSlots();
        if (!committedOperation.Matches(manifest.Operation)
            || !manifest.Slots.SequenceEqual(AccountSlots(generationSlots), StringComparer.Ordinal))
        {
            throw ResetRequired("The fixed generation manifest does not match the committed account receipt.");
        }
        var localDeviceIdentity = await RestoreLocalDeviceIntentAsync(
                accountIdentity,
                generationSlots,
                cancellationToken)
            .ConfigureAwait(false);
        var current = await store.ReadAsync(localDeviceIdentity, cancellationToken)
            .ConfigureAwait(false)
            ?? throw ResetRequired("A committed account creation receipt has no identity row.");
        EnsureNetwork(current);
        if (!current.SecureSlots.Equals(generationSlots))
        {
            throw ResetRequired("Persisted secure slots do not match the database generation.");
        }
        var immutableIdentityCommitment = DeepAccountImmutableIdentityHash.Compute(current);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    immutableIdentityCommitment,
                    manifest.ImmutableIdentityCommitment.Span))
            {
                throw ResetRequired(
                    "The fixed generation manifest does not match the immutable local identity.");
            }

            // Exact initial-snapshot rehash is required only while a pending journal
            // proves that creation reconciliation has not finished. Routine mutable state
            // may diverge from the immutable initial receipt after this journal is removed.
            await EnsureRequiredSecretsExistAsync(
                    current,
                    manifest.MessageStoreInstanceId,
                    cancellationToken)
                .ConfigureAwait(false);
            if (pending is not null)
            {
                if (!pending.Operation.MatchesIdentity(current))
                {
                    throw ResetRequired("Pending creation journal does not match the exact initial snapshot.");
                }
                await secureStorage.DeleteBatchAsync([PendingSecureStorageJournalSlot], CancellationToken.None)
                    .ConfigureAwait(false);
            }
            return new ReconciledAccountState(
                current,
                manifest.MessageStoreInstanceId,
                new DeepAccountReconciledMutationCapability(
                    mutationLease,
                    committedOperation,
                    immutableIdentityCommitment));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(immutableIdentityCommitment);
        }
    }

    private async Task TryDeletePendingJournalAfterProvenCommitAsync()
    {
        try
        {
            await secureStorage.DeleteBatchAsync(
                    [PendingSecureStorageJournalSlot],
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch
        {
            // The pending journal itself is the durable retry record. The exact
            // database receipt and immutable manifest were already proven, so a
            // cleanup failure must not turn a confirmed account into phrase loss.
        }
    }

    private void EnsureNetwork(DeepLocalIdentitySnapshot identity)
    {
        if (!CryptographicOperations.FixedTimeEquals(identity.NetworkId.Span, networkId))
        {
            throw ResetRequired("The local Deep account belongs to another network.");
        }
    }

    private static string NormalizeDisplayName(string displayName)
        => DeepDisplayName.Normalize(displayName, nameof(displayName));

    private static VerifiedDeepRecoveryPhrase VerifyRecoveryPhraseUtf8(ReadOnlySpan<byte> encoded)
        => DeepRecoveryV1.VerifyCanonicalUtf8(encoded);

    private static void ValidateRetainedRecoveryPhrase(OwnedDeepSecret retained)
    {
        try
        {
            using var verified = retained.Use(VerifyRecoveryPhraseUtf8);
        }
        catch (ArgumentException exception)
        {
            throw ResetRequired("The retained recovery phrase is invalid.", exception);
        }
    }

    private static string[] AccountSlots(DeepSecureStorageSlots slots) =>
    [
        slots.DeviceSigningKey,
        slots.DeviceAgreementKey,
        slots.DeviceId,
        slots.DeviceRevocationHandle,
        slots.DevicePrekey,
        slots.PushKey,
        slots.MessageStoreInstanceId
    ];

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static LocalStateResetRequiredException ResetRequired(string message, Exception? inner = null) =>
        new(LocalStateResetRequiredReason.InvalidCurrentSchema, message, inner);

    private delegate bool PublicKeyMatcher(
        ReadOnlySpan<byte> secret,
        ReadOnlyMemory<byte> expectedPublicKey);

    private sealed class RetainedRecoveryPhraseBytes : IDisposable
    {
        private byte[]? value;

        private RetainedRecoveryPhraseBytes(byte[] value) => this.value = value;

        internal ReadOnlyMemory<byte> Value => value
            ?? throw new ObjectDisposedException(nameof(RetainedRecoveryPhraseBytes));

        internal static RetainedRecoveryPhraseBytes CopyFrom(VerifiedDeepRecoveryPhrase phrase)
        {
            byte[]? copy = null;
            phrase.UseCanonicalUtf8(bytes => copy = bytes.ToArray());
            return new RetainedRecoveryPhraseBytes(copy!);
        }

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref value, null);
            if (current is not null)
            {
                CryptographicOperations.ZeroMemory(current);
            }
        }
    }

    private sealed record ReconciledAccountState(
        DeepLocalIdentitySnapshot? Identity,
        MessageStoreInstanceId32? MessageStoreInstanceId,
        DeepAccountReconciledMutationCapability MutationCapability);
}
