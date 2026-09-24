using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Isolated offline DID2 genesis authoring. It does not select a current
/// account, write the account SQL schema or compose MAUI. No V1 storage slot
/// is read or written by this issuer.
/// </summary>
internal sealed class DeepIdV2OfflineGenesisIssuer
{
    private const ulong DeviceLifetimeSeconds = 366UL * 24 * 60 * 60;
    private const ulong DeviceRetentionSeconds = 2UL * DeviceLifetimeSeconds;
    private readonly IDeepSecureStorage storage;
    private readonly byte[] networkId;
    private readonly ushort deploymentProfileId;

    internal DeepIdV2OfflineGenesisIssuer(IDeepSecureStorage storage,
        ReadOnlySpan<byte> networkId, ushort deploymentProfileId)
    {
        this.storage = storage ?? throw new ArgumentNullException(nameof(storage));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0)
            throw new ArgumentException("A nonzero DID2 network/profile is required.");
        this.networkId = networkId.ToArray();
        this.deploymentProfileId = deploymentProfileId;
    }

    internal async ValueTask<CreatedDeepIdV2OfflineGenesis> CreateAsync(
        VerifiedDeepRecoveryPhrase phrase, ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        ArgumentNullException.ThrowIfNull(mlDsa65);
        if (trustedUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(trustedUnixSeconds));
        cancellationToken.ThrowIfCancellationRequested();
        using var recovery = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase, networkId, 1);
        using var deviceSecrets = new OwnedGenesisDeviceSecrets();
        var account = Dnp1IdentityAuthoringV1.AuthorGenesisAccount(
            recovery, trustedUnixSeconds, 1);
        var accountId = account.AccountIdentity.AccountId.Bytes.ToArray();
        var issuance = new ProtectedGenesisDeviceIssuancePersistence(
            storage, networkId, accountId,
            GenesisIssuanceStoreNamespace.StoreV2);
        var issued = await Dnp1IdentityAuthoringV1.IssueGenesisDeviceAsync(
            recovery, account, deviceSecrets, issuance,
            trustedUnixSeconds,
            checked(trustedUnixSeconds + DeviceLifetimeSeconds),
            checked(trustedUnixSeconds + DeviceRetentionSeconds),
            cancellationToken).ConfigureAwait(false);
        var verifiedDevice = issued.IssuedDevice?.Verified ??
            throw new InvalidOperationException(
                "DID2 genesis device issuance did not complete.");
        var closure = ApplicationCoreVerifier.CreateIdentityClosure(
            verifiedDevice.Identity, [verifiedDevice]);
        var binding = recovery.AuthorGenesisDab2(
            phrase, closure, deploymentProfileId);
        var directory = recovery.AuthorGenesisDmd1(closure,
            trustedUnixSeconds);
        var authorization = recovery.AuthorGenesisDca1V2(binding, directory,
            verifiedDevice, trustedUnixSeconds);
        var checkpoint = recovery.AuthorGenesisAdc1V2(binding, directory,
            trustedUnixSeconds);
        await new ProtectedDeepIdV2RecoveryPhraseStore(storage,
            networkId, accountId).WriteVerifiedAsync(phrase, cancellationToken)
            .ConfigureAwait(false);
        var verified = await new ProtectedDeepIdV2GenesisBootstrap(storage,
            networkId, accountId).CommitAsync(deviceSecrets, binding.Head,
            authorization, checkpoint, trustedUnixSeconds,
            deploymentProfileId, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
        return new(accountId, verified);
    }
}

internal sealed class CreatedDeepIdV2OfflineGenesis(
    ReadOnlySpan<byte> accountId,
    VerifiedDeepIdV2LocalGenesis verified) : IDisposable
{
    private readonly byte[] accountId = accountId.ToArray();
    internal ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    internal VerifiedDeepIdV2LocalGenesis Verified { get; } = verified;

    public void Dispose() => Verified.Dispose();
}
