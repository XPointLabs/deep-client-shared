using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Verified, public-only result of activating the local generation-one device.
/// Secret signing and agreement authority remains owned by the account service.
/// </summary>
public sealed class DeepGenesisDeviceActivation
{
    internal DeepGenesisDeviceActivation(
        VerifiedDeviceRelative verifiedDevice,
        Dmd1LineageState currentDirectory)
    {
        VerifiedDevice = verifiedDevice ?? throw new ArgumentNullException(nameof(verifiedDevice));
        CurrentDirectory = currentDirectory ?? throw new ArgumentNullException(nameof(currentDirectory));
    }

    public VerifiedDeviceRelative VerifiedDevice { get; }
    public Dmd1LineageState CurrentDirectory { get; }
}

public sealed partial class DeepAccountService
{
    private const ulong GenesisDeviceLifetimeSeconds = 366UL * 24 * 60 * 60;
    private const ulong GenesisDeviceRetentionSeconds = 2UL * 366 * 24 * 60 * 60;

    public async Task<DeepGenesisDeviceActivation> EnsureGenesisDeviceActivatedAsync(
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
            var identity = reconciled.Identity ??
                throw new InvalidOperationException("No local Deep account exists.");
            if (identity.Account.ActivationState != DeepAccountActivationState.ActiveLocal)
                throw new InvalidOperationException(
                    "A restored account requires network device enrollment before local activation.");

            var evidenceStore = new ProtectedGenesisIdentityStateStore(
                secureStorage,
                identity.NetworkId.Span,
                identity.Account.AccountIdentity.AccountId.Bytes.Span);
            using var deviceSecrets = await RestoreCurrentGenesisDeviceSecretsAsync(
                    identity,
                    cancellationToken)
                .ConfigureAwait(false);
            DeepRecoveryAccountCapabilities? recovery = null;
            try
            {
                recovery = await TryOpenRetainedRecoveryAuthorityAsync(
                        identity,
                        cancellationToken)
                    .ConfigureAwait(false);
                var now = RequireUnixSeconds(clock.UtcNow);
                var accountEvidence = await evidenceStore.ReadAccountAsync(cancellationToken)
                    .ConfigureAwait(false);
                GenesisAccountAuthoringResult account;
                if (accountEvidence is null)
                {
                    if (recovery is null)
                        throw ResetRequired(
                            "Genesis account evidence is missing after recovery authority was deleted.");
                    account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(recovery, now, 1);
                    EnsureAccountMatches(identity, account.AccountIdentity);
                    await evidenceStore.WriteAccountAsync(
                            account.CanonicalDpa1,
                            account.CanonicalDrs1,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    account = Dnp1IdentityAuthoringV1.RestoreGenesisAccount(
                        accountEvidence.CanonicalDpa1,
                        accountEvidence.CanonicalDrs1,
                        now);
                    EnsureAccountMatches(identity, account.AccountIdentity);
                }

                GenesisDeviceIssuanceResult issued;
                var issuancePersistence = new ProtectedGenesisDeviceIssuancePersistence(
                    secureStorage,
                    identity.NetworkId.Span,
                    identity.Account.AccountIdentity.AccountId.Bytes.Span);
                if (recovery is not null)
                {
                    issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
                            recovery,
                            account,
                            deviceSecrets,
                            issuancePersistence,
                            now,
                            checked(now + GenesisDeviceLifetimeSeconds),
                            checked(now + GenesisDeviceRetentionSeconds),
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    issued = await Dnp1IdentityAuthoringV1.RestoreGenesisDeviceAsync(
                            account.CanonicalDpa1,
                            account.CanonicalDrs1,
                            deviceSecrets,
                            issuancePersistence,
                            now,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                var verifiedDevice = issued.IssuedDevice?.Verified ??
                    throw ResetRequired("Genesis device issuance did not reach a durable verified result.");
                EnsureDeviceMatches(identity, verifiedDevice);
                var closure = ApplicationCoreVerifier.CreateIdentityClosure(
                    verifiedDevice.Identity,
                    [verifiedDevice]);
                var canonicalDmd1 = await evidenceStore.ReadDirectoryAsync(cancellationToken)
                    .ConfigureAwait(false);
                Dmd1LineageState directory;
                if (canonicalDmd1 is null)
                {
                    if (recovery is null)
                        throw ResetRequired(
                            "Genesis DMD1 is missing after recovery authority was deleted.");
                    directory = recovery.AuthorGenesisDmd1(closure, now);
                    await evidenceStore.WriteDirectoryAsync(
                            directory.Head.Record.CanonicalBytes,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    try
                    {
                        var parsed = ApplicationCoreCodec.DecodeDmd1(canonicalDmd1);
                        var verified = ApplicationCoreVerifier.VerifyDmd1(parsed, closure);
                        directory = ApplicationCoreVerifier.StartDmd1Lineage(verified).Next;
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(canonicalDmd1);
                    }
                }
                return new DeepGenesisDeviceActivation(verifiedDevice, directory);
            }
            catch (Exception exception) when (
                exception is ArgumentException or CryptographicException or RecordException or InvalidDataException)
            {
                throw ResetRequired(
                    "The protected genesis identity closure is invalid or cross-sourced.",
                    exception);
            }
            finally
            {
                recovery?.Dispose();
            }
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    public async Task<LocalDeviceX25519AgreementAuthority>
        OpenCurrentDeviceAgreementAuthorityAsync(
            DeepLocalIdentitySnapshot expectedIdentity,
            VerifiedDeviceRelative verifiedDevice,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        ArgumentNullException.ThrowIfNull(verifiedDevice);
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
            var current = reconciled.Identity ??
                throw new InvalidOperationException("No local Deep account exists.");
            EnsureExpectedDeviceSnapshot(current, expectedIdentity);
            EnsureDeviceMatches(current, verifiedDevice);
            using var secrets = await RestoreCurrentGenesisDeviceSecretsAsync(
                    current,
                    cancellationToken)
                .ConfigureAwait(false);
            return secrets.CreateAgreementAuthority(verifiedDevice);
        }
        catch (Exception exception) when (
            exception is ArgumentException or CryptographicException or RecordException)
        {
            throw ResetRequired(
                "The current verified device cannot open agreement authority.",
                exception);
        }
        finally
        {
            ProcessMutationGate.Release();
        }
    }

    private async Task<DeepRecoveryAccountCapabilities?> TryOpenRetainedRecoveryAuthorityAsync(
        DeepLocalIdentitySnapshot identity,
        CancellationToken cancellationToken)
    {
        using var retained = await secureStorage.ReadOwnedAsync(
                DeepAccountStoreContract.RetainedRecoveryPhraseSlot,
                cancellationToken)
            .ConfigureAwait(false);
        if (retained is null) return null;
        byte[]? encoded = null;
        try
        {
            retained.Use(value => encoded = value.ToArray());
            using var phrase = DeepRecoveryV1.VerifyCanonicalUtf8(encoded!);
            var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
                phrase,
                identity.NetworkId.Span,
                identity.Account.AccountIdentity.AccountGeneration);
            if (!recovery.AccountIdentity.Equals(identity.Account.AccountIdentity))
            {
                recovery.Dispose();
                throw new CryptographicException(
                    "The retained recovery authority belongs to another account.");
            }
            return recovery;
        }
        finally
        {
            if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private async Task<OwnedGenesisDeviceSecrets> RestoreCurrentGenesisDeviceSecretsAsync(
        DeepLocalIdentitySnapshot identity,
        CancellationToken cancellationToken)
    {
        byte[]? signing = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? agreement = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? deviceId = new byte[DeepAccountStoreContract.KeyMaterialSize];
        byte[]? revocation = new byte[DeepAccountStoreContract.KeyMaterialSize];
        try
        {
            await CopyExactSecureValueAsync(
                    identity.SecureSlots.DeviceSigningKey, signing, cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(
                    identity.SecureSlots.DeviceAgreementKey, agreement, cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(
                    identity.SecureSlots.DeviceId, deviceId, cancellationToken)
                .ConfigureAwait(false);
            await CopyExactSecureValueAsync(
                    identity.SecureSlots.DeviceRevocationHandle, revocation, cancellationToken)
                .ConfigureAwait(false);
            using var persisted = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
                signing, agreement, deviceId, revocation);
            signing = agreement = deviceId = revocation = null;
            return OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
        }
        finally
        {
            Zero(signing); Zero(agreement); Zero(deviceId); Zero(revocation);
        }
    }

    private static void EnsureAccountMatches(
        DeepLocalIdentitySnapshot identity,
        DeepAccountIdentityCapability account)
    {
        if (!account.Equals(identity.Account.AccountIdentity))
            throw new CryptographicException(
                "The signed genesis account does not match the local account snapshot.");
    }

    private static void EnsureDeviceMatches(
        DeepLocalIdentitySnapshot identity,
        VerifiedDeviceRelative device)
    {
        if (!device.Certificate.DeviceId.Span.SequenceEqual(identity.Device.DeviceId.Bytes.Span) ||
            device.Certificate.DeviceGeneration != identity.Device.DeviceGeneration ||
            !device.Certificate.DeviceEd25519PublicKey.Span.SequenceEqual(
                identity.Device.SigningPublicKey.Span) ||
            !device.Certificate.DeviceX25519PublicKey.Span.SequenceEqual(
                identity.Device.AgreementPublicKey.Span))
            throw new CryptographicException(
                "The verified genesis device does not match the protected local device.");
    }

    private static ulong RequireUnixSeconds(DateTimeOffset value)
    {
        var seconds = value.ToUnixTimeSeconds();
        return seconds > 0
            ? checked((ulong)seconds)
            : throw new ArgumentOutOfRangeException(nameof(value));
    }
}
