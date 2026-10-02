using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> EnsureContactRendezvousAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier mlDsa65, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        OnionMonotonicReading reading, OnionTrustedTimeAuthority trustedTime, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, mlDsa65, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, fresh.Proof,
            reading.BootId.Span, reading.SampleSeconds);
        return await SqliteDeepIdV2AccountGeneration.EnsureContactRendezvousUnderLeaseAsync(
            storage, current, intent, fresh, reading, trustedTime, ct).ConfigureAwait(false);
    }
}
