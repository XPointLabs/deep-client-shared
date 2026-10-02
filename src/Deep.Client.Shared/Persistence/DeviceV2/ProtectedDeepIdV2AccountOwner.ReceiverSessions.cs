using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async ValueTask<DeepIdV2InitialContactSessionCommit?> FindReceiverSessionAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Dph2Record incoming, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var certificate = current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate;
        if (!DeepIdV2InitialContactSessionCommit.Fixed(incoming.NetworkId.Span, networkId) ||
            !DeepIdV2InitialContactSessionCommit.Fixed(incoming.ResponderAccountId.Span, current.AccountId.Span) ||
            !DeepIdV2InitialContactSessionCommit.Fixed(incoming.ResponderDeviceId.Span, certificate.DeviceId.Span) ||
            incoming.ResponderDeviceGeneration != certificate.DeviceGeneration)
            throw new System.Security.Cryptography.CryptographicException("Receiver replay is outside the current local account/device.");
        return await SqliteDeepIdV2AccountGeneration.FindReceiverUnderLeaseAsync(storage, sqlStatePath, current, incoming, ct).ConfigureAwait(false);
    }

    internal async ValueTask<DeepIdV2InitialContactSessionCommit> CommitReceiverSessionAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, VerifiedDph2InitialClaim claim, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2DirectoryFreshness initiator, OnionMonotonicReading reading, OnionTrustedTimeAuthority time,
        int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, fresh.Proof, reading.BootId.Span, reading.SampleSeconds);
        return await SqliteDeepIdV2AccountGeneration.CommitReceiverUnderLeaseAsync(storage, sqlStatePath, current,
            claim, fresh, initiator, reading, time, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
    }
}
