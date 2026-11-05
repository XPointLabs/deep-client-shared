using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task RequireCurrentContactRouteAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var route = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        await RecheckPeerMailboxRouteUnderLeaseAsync(current, opened, route, own, peer, source, held, ct).ConfigureAwait(false);
        var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(final.Exact.Span, route.NativeFloor.Span))
            throw new CryptographicException("Current contact route changed its actual native custody.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    // Denial-only diagnostics from actual authenticated native history. Neither
    // these interval predicates nor parsed XUR metadata grants any operation.
    internal async Task<DeepIdV2ContactRouteHealth> ReadContactRouteHealthAsync(ulong seconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var history = await ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
            peer, own, source, held, ct).ConfigureAwait(false);
        var xur = ContactCodec.Decode("XUR1", history.InboundXur1.Span);
        var final = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        var lower = checked(peer.TrustedLowerUnixSeconds + final.SampleSeconds - peer.MonotonicSample);
        var upper = checked(peer.TrustedUpperUnixSeconds + final.SampleSeconds - peer.MonotonicSample);
        bool Covers(ContactRecord record, ushort start, ushort expiry) => lower <= upper &&
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(start).Span) <= lower &&
            upper < BinaryPrimitives.ReadUInt64BigEndian(record.Field(expiry).Span);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        return new(Covers(history.Head.Authorization, 12, 13), Covers(xur, 11, 12), history.Faulted);
    }
}
