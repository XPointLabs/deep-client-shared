using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Fence BEFORE new authored/counter/ratchet work, not merely at ingress.
    // Read only actual authenticated native history under the account lease.
    // This does not require a current delivery route (offline authoring and
    // pre-acceptance work retain their separate rules), and does not block
    // exact committed replay, history, reads or independently qualified ACK.
    private async Task RequireNoRetainedPeerRouteFaultUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        foreach (var received in opened.Sql.ReadVerifiedIncomingRouteControls(floor, ct))
        {
            using var native = received;
            using var plain = native.OwnAuthenticatedDmc2();
            var message = plain.Use(static bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
            try
            {
                if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate) continue;
                Did2RouteProcessingMetadata.RequireReceivedEvent(native.RouteProcessing, message);
                if (native.RouteProcessing[0] == 2)
                    throw new CryptographicException("Retained authenticated route fault fences this peer's new sends.");
            }
            finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        }
        var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(floor.Exact.Span, final.Exact.Span))
            throw new CryptographicException("Native route-fault custody changed before new work.");
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
    }

    // Constructed only from native SQL/floor read-back and independent Protocol
    // verification. Original invitation framing stays immutable and is never
    // substituted with an invented successor XIR.
    private sealed record OwnedPeerMailboxRoute(ParsedDeepIdV2ContactMailboxRoute Package,
        VerifiedDeepIdV2MailboxRouteClosure Route, ReadOnlyMemory<byte> LocatorHash,
        ReadOnlyMemory<byte> HeadEventHash, ReadOnlyMemory<byte> NativeFloor, PeerRouteInputFence? Inputs);

    private sealed record OwnedPeerRouteHistory(ParsedDeepIdV2ContactMailboxRoute Original,
        ParsedContactRouteClosure Head, ReadOnlyMemory<byte> HeadEventHash, ReadOnlyMemory<byte> NativeFloor,
        ReadOnlyMemory<byte> PreviousRoute, ReadOnlyMemory<byte> PreviousEventHash, ReadOnlyMemory<byte> LastUpdate,
        bool Faulted, Func<ulong, CancellationToken, Task<bool>> HasConsent, ReadOnlyMemory<byte> InboundXur1);

    private async Task<OwnedPeerRouteHistory> ReadNativePeerRouteHistoryUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, ParsedDeepIdV2ContactMailboxRoute original,
        ReadOnlyMemory<byte> originalEvent, ReadOnlyMemory<byte> inboundXur1,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, Func<ulong, CancellationToken, Task<bool>> hasConsent, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var scope = opened.Scope;
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var head = original.Route;
        byte[] headHash = SHA256.HashData(originalEvent.Span), previousHash = [], previousRoute = [], updateBytes = [];
        var faulted = false;
        try
        {
            // No highest-generation selection, cache lookup or second journal.
            // A malformed authenticated event remains in native custody and
            // causes the same refusal again after restart.
            foreach (var received in opened.Sql.ReadVerifiedIncomingRouteControls(floor, ct))
            {
                held.RequireOwner(lease);
                using var plain = received.OwnAuthenticatedDmc2();
                var message = plain.Use(static bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
                if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate)
                {
                    if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
                    continue;
                }
                if (message.ParsedPayload is not ContactRouteUpdateDmc2Payload update)
                    throw new CryptographicException("Native private route update has no canonical payload.");
                // The first outcome is authenticated by the same native header,
                // including protected compacted history, not an application row.
                Did2RouteProcessingMetadata.RequireReceivedEvent(received.RouteProcessing, message);
                if (received.RouteProcessing[0] == 2) { faulted = true; continue; }
                if (!await hasConsent(received.Ordinal, ct).ConfigureAwait(false))
                    throw new CryptographicException("Accepted native route control contradicts actual consent.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (FixedRoute(received.EventHash, headHash)) continue; // Exact current-head duplicate.
                var generation = BinaryPrimitives.ReadUInt64BigEndian(head.Reachability.Field(3).Span);
                if (update.RouteGeneration <= generation)
                {
                    // An earlier exact event can arrive in another authenticated
                    // envelope. Its first actual receive must precede this row;
                    // changed bytes at the same generation do not qualify.
                    using var first = opened.Sql.ReadVerifiedReceiveForEvent(floor, received.EventHash) ??
                        throw new CryptographicException("Private route duplicate lost its native original.");
                    if (first.Ordinal < received.Ordinal) continue;
                    throw new CryptographicException("Authenticated private route history has a generation fork.");
                }
                if (faulted)
                    throw new CryptographicException("Native route history promotes control after a retained route fault.");
                if (generation == ulong.MaxValue || update.RouteGeneration != generation + 1 ||
                    !FixedRoute(update.PredecessorRouteUpdateHash.Span, headHash))
                    throw new CryptographicException("Authenticated private route history has a gap or changed predecessor.");
                var next = await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(original,
                    peer, own.Network, own.Authority, source.RendezvousTrustedTime,
                    head.ExactBytes, headHash, scope.Relationship.ToArray(), scope.Conversation.ToArray(),
                    message.CanonicalBytes, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(previousHash); CryptographicOperations.ZeroMemory(previousRoute);
                CryptographicOperations.ZeroMemory(updateBytes);
                previousHash = headHash; previousRoute = head.ExactBytes.ToArray();
                updateBytes = message.CanonicalBytes.ToArray(); headHash = received.EventHash.ToArray(); head = next;
            }

            var finalFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, finalFloor.Exact.Span))
                throw new CryptographicException("Native route history changed during private route verification.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(original, head, headHash.ToArray(), floor.Exact.ToArray(), previousRoute.ToArray(),
                previousHash.ToArray(), updateBytes.ToArray(), faulted, hasConsent, inboundXur1.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(headHash); CryptographicOperations.ZeroMemory(previousHash);
            CryptographicOperations.ZeroMemory(previousRoute); CryptographicOperations.ZeroMemory(updateBytes);
        }
    }

    private async Task<OwnedPeerMailboxRoute> RequireCurrentPeerRouteUnderLeaseAsync(
        OwnedDid2MessagingStorage opened, OwnedPeerRouteHistory history, PeerRouteInputFence? inputs,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        if (history.Faulted)
            throw new CryptographicException("Retained authenticated route fault fences this peer's new sends.");
        VerifiedDeepIdV2MailboxRouteClosure route;
        if (history.LastUpdate.IsEmpty)
        {
            var initial = await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(history.Original, peer, own.Network,
                own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            route = initial.Route;
        }
        else
            route = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(history.Original, peer,
                own.Network, own.Authority, source.RendezvousTrustedTime, history.PreviousRoute, history.PreviousEventHash,
                opened.Scope.Relationship.ToArray(), opened.Scope.Conversation.ToArray(), history.LastUpdate, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(floor.Exact.Span, history.NativeFloor.Span))
            throw new CryptographicException("Native route predecessor changed during current delivery verification.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return new(history.Original, route, route.LocatorHash.ToArray(), history.HeadEventHash, history.NativeFloor, inputs);
    }
}
