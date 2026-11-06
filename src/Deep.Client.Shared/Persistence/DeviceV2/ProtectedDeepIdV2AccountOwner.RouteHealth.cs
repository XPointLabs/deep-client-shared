using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<bool> ReadExpiredPeerAnnouncementForMaintenanceAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var history = await ReadPagedLiveRouteHistoryUnderLeaseAsync(opened, 2, own, peer, source, held, ct).ConfigureAwait(false);
        if (history is null)
        {
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            await RequireNoRetainedPeerRouteFaultUnderLeaseAsync(opened, held, ct).ConfigureAwait(false);
            return false; // Unsupported initial/retained legacy L selects no alternate permission.
        }
        var consent = history.PeerConsent ?? throw new CryptographicException("Maintenance lost actual native peer consent.");
        var expired = await Deep.Protocol.ContactV2.DeepIdV2ContactRouteUpdateVerifier.IsVerifiedHistoryAnnouncementExpiredForMaintenanceAsync(
            history.Facts, history.Announcement, peer, own.Network, own.Authority,
            source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2, Did2RouteHistorySelection.Current(), held, ct).ConfigureAwait(false);
        consent.RequireSame(read);
        if (!read.Snapshot.FirstFault.IsAbsent || read.Snapshot.L.IsAbsent ||
            !FixedRoute(SHA256.HashData(read.Original(read.Snapshot.L).Span), history.EventHash.Span))
            throw new CryptographicException("Maintenance classification changed its actual native peer route.");
        var final = await source.RecheckEndpointPairUnderLeaseAsync(own, peer, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, final);
        await opened.WithPairedSqlAsync(PagedPeerConsentPairedRead(read, consent),
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return expired;
    }

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
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct,
        bool includeOwnDiagnostics = false)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var history = await ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
            peer, own, source, held, ct).ConfigureAwait(false);
        var rendezvous = await ReadPeerRendezvousTipUnderLeaseAsync(opened, history.InboundXur1,
            own, peer, source, held, ct).ConfigureAwait(false);
        var xur = ContactCodec.Decode("XUR1", rendezvous.Tip.Span);
        (ulong Generation, ulong Carried, bool Pending)? ownUpdate = null;
        if (includeOwnDiagnostics)
            ownUpdate = await ReadOwnRendezvousDiagnosticsUnderLeaseAsync(opened, own, source, held, ct).ConfigureAwait(false);
        var final = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        var lower = checked(peer.TrustedLowerUnixSeconds + final.SampleSeconds - peer.MonotonicSample);
        var upper = checked(peer.TrustedUpperUnixSeconds + final.SampleSeconds - peer.MonotonicSample);
        bool Covers(ContactRecord record, ushort start, ushort expiry) => lower <= upper &&
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(start).Span) <= lower &&
            upper < BinaryPrimitives.ReadUInt64BigEndian(record.Field(expiry).Span);
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var updateIssued = BinaryPrimitives.ReadUInt64BigEndian(xur.Field(11).Span);
        var updateExpiry = BinaryPrimitives.ReadUInt64BigEndian(xur.Field(12).Span);
        return new(Covers(history.Head.Authorization, 12, 13), Covers(xur, 11, 12), history.Faulted || rendezvous.Faulted,
            BinaryPrimitives.ReadUInt64BigEndian(xur.Field(4).Span), updateIssued, updateExpiry,
            updateExpiry > upper ? updateExpiry - upper : 0, ownUpdate?.Generation, ownUpdate?.Carried, ownUpdate?.Pending);
    }

    private async Task<(ulong Generation, ulong Carried, bool Pending)> ReadOwnRendezvousDiagnosticsUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
            Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false);
        RequireRouteHistoryConsent(read); var original = RendezvousAnchor(read);
        var (state, exact) = await ReadRendezvousContinuationUnderLeaseAsync(opened, 1, original, held, ct).ConfigureAwait(false);
        try
        {
            await RequireOwnRecordedRendezvousChainAsync(original, state.Successors, own, source, ct).ConfigureAwait(false);
            var latest = await ReadLatestNativeRendezvousUnderLeaseAsync(opened, 1, held, ct).ConfigureAwait(false);
            var page = latest is null ? null : (ContactRouteHistoryDmc2Payload)latest.Value.Message.ParsedPayload;
            if (page is not null && (state.Successors.Count < page.RendezvousSuccessors.Count ||
                !RendezvousPrefixesAgree(state.Successors, page.RendezvousSuccessors)))
                throw new CryptographicException("Owned rendezvous diagnostic lost its actual native signed floor.");
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Owned rendezvous diagnostic lost mandatory authored custody.");
            var authored = raw.Use(bytes => bytes.ToArray());
            try
            {
                using var journal = ProtectedDid2DirectTextJournal.Decode(authored, opened.Scope.Network,
                    opened.Scope.LocalAccount, opened.Scope.Instance);
                var pending = journal.Entries.Values.Any(entry => entry.Kind == Dmc2ContentKind.ContactRouteUpdate &&
                    FixedRoute(entry.Scope.Exact, opened.Scope.Exact) && !entry.Stored && !entry.WorkStopped);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, authored, ct).ConfigureAwait(false);
                await RejoinOwnedHistoryReadAsync(opened, read, ct).ConfigureAwait(false);
                held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
                return ((ulong)state.Successors.Count, (ulong)(page?.RendezvousSuccessors.Count ?? 0), pending);
            }
            finally { CryptographicOperations.ZeroMemory(authored); }
        }
        finally { if (exact is not null) CryptographicOperations.ZeroMemory(exact); }
    }
}
