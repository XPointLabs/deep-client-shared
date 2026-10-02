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
    internal async ValueTask<Dph2InitialClaimPreview> PreviewInitialClaimAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Dph2Record dph2, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2DirectoryFreshness initiator, OnionMonotonicReading reading,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, fresh.Proof, reading.BootId.Span, reading.SampleSeconds);
        return await SqliteDeepIdV2AccountGeneration.PreviewInitialClaimUnderLeaseAsync(storage, sqlStatePath,
            current, dph2, fresh, initiator, reading, trustedTime, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
    }
}
