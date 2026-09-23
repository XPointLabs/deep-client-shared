using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Two-slot, add-only V2 genesis commit. A partial commit never grants local
/// authority. Retain the recovery phrase until CommitAsync returns after its
/// verified read-back; a retry with the same exact artifacts is idempotent.
/// </summary>
internal sealed class ProtectedDeepIdV2GenesisBootstrap
{
    private readonly ProtectedDeepIdV2GenesisDeviceSecretsStore secretsStore;
    private readonly ProtectedDeepIdV2GenesisContactStore publicStore;

    internal ProtectedDeepIdV2GenesisBootstrap(IDeepSecureStorage storage,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> accountId)
    {
        secretsStore = new(storage, networkId, accountId);
        publicStore = new(storage, networkId, accountId);
    }

    internal async ValueTask<VerifiedDeepIdV2LocalGenesis> CommitAsync(
        OwnedGenesisDeviceSecrets secrets, VerifiedDab2 binding,
        VerifiedDca1V2 authorization, VerifiedAdc1V2 checkpoint,
        ulong trustedUnixSeconds, ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.Identity.ActiveDevices.Count != 1)
            throw new CryptographicException(
                "A V2 genesis bootstrap requires exactly one verified device.");
        await secretsStore.WriteVerifiedAsync(secrets,
            binding.Identity.ActiveDevices.Single(), cancellationToken)
            .ConfigureAwait(false);
        await publicStore.WriteVerifiedAsync(binding, authorization,
            checkpoint, cancellationToken).ConfigureAwait(false);
        return await ReadVerifiedAsync(trustedUnixSeconds,
            deploymentProfileId, mlDsa65, cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "The V2 genesis bootstrap did not reach a complete durable state.");
    }

    internal async ValueTask<VerifiedDeepIdV2LocalGenesis?> ReadVerifiedAsync(
        ulong trustedUnixSeconds, ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65, CancellationToken cancellationToken)
    {
        var publicEvidence = await publicStore.ReadVerifiedAsync(
            trustedUnixSeconds, deploymentProfileId, mlDsa65,
            cancellationToken).ConfigureAwait(false);
        if (publicEvidence is null)
        {
            if (await secretsStore.HasRecordAsync(cancellationToken)
                    .ConfigureAwait(false))
                throw new CryptographicException(
                    "The V2 genesis bootstrap has device secrets but no public closure.");
            return null;
        }
        if (publicEvidence.Binding.Identity.ActiveDevices.Count != 1)
            throw new CryptographicException(
                "The restored V2 genesis has an unexpected device count.");
        var secrets = await secretsStore.ReadVerifiedAsync(
            publicEvidence.Binding.Identity.ActiveDevices.Single(),
            cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "The V2 genesis bootstrap has public closure but no device secrets.");
        return new(publicEvidence, secrets);
    }
}

internal sealed class VerifiedDeepIdV2LocalGenesis(
    VerifiedDeepIdV2GenesisContactEvidence publicEvidence,
    OwnedGenesisDeviceSecrets deviceSecrets) : IDisposable
{
    internal VerifiedDeepIdV2GenesisContactEvidence PublicEvidence { get; } =
        publicEvidence;
    internal OwnedGenesisDeviceSecrets DeviceSecrets { get; } = deviceSecrets;

    public void Dispose() => DeviceSecrets.Dispose();
}
