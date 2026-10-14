using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Historical comparison metadata, not current route/admission/deletion
    // authority. The caller's exact route is never accepted on its own: only
    // native Hello/Accept or a qualified original receive can supply it.
    private async Task<ParsedContactRouteClosure> ReadOriginalPeerStoreRouteAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        SqliteDeepMailboxStore application, ReadOnlyMemory<byte> exactOriginalRoute, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var expected = ContactRouteClosureCodec.Decode(exactOriginalRoute.Span); // Bounded immutable copy before awaits.
        var scope = opened.Scope;
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var head = await ReadInitialPeerStoreRouteAsync(current, held, opened, application, ct).ConfigureAwait(false);
        var initial = opened.Sql.ReadVerifiedActiveInitialEvents(floor);
        byte[] headHash = [], accepted = [];
        try
        {
            var hello = ApplicationCoreCodec.DecodeDmc2(initial.Hello);
            var policy = ((ContactHelloDmc2Payload)hello.ParsedPayload).Policy;
            ulong consentOrdinal = 0, headSequence = hello.SenderClientSequence;
            headHash = SHA256.HashData(initial.Hello);
            if (scope.IsInitiator)
            {
                accepted = await application.ReadContactAcceptAsync(current.AccountId,
                    BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
                    scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), ct).ConfigureAwait(false) ??
                    throw new CryptographicException("Historical peer route lost actual acceptance custody.");
                using var native = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)) ??
                    throw new CryptographicException("Historical peer route has no native acceptance.");
                var message = ApplicationCoreCodec.DecodeDmc2(accepted);
                policy &= ((ContactAcceptDmc2Payload)message.ParsedPayload).Policy;
                consentOrdinal = native.Ordinal; headSequence = message.SenderClientSequence;
                CryptographicOperations.ZeroMemory(headHash); headHash = native.EventHash.ToArray();
            }
            else
            {
                using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Historical route lost mandatory local consent custody.");
                using var commands = root.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                var winner = commands.FindScope(scope);
                if (winner is not null)
                {
                    using var native = opened.Sql.ReadVerifiedOperation(floor, winner.Operation);
                    if (native is not null)
                    {
                        policy &= await RequireRetainedContactAcceptEventUnderLeaseAsync(held, opened, application,
                            winner, winner.Operation.ToArray(), ct).ConfigureAwait(false);
                        consentOrdinal = native.Ordinal;
                    }
                }
            }

            ParsedContactRouteClosure? selected = FixedRoute(head.ExactBytes.Span, expected.ExactBytes.Span) ? head : null;
            var faulted = false;
            foreach (var native in opened.Sql.ReadVerifiedIncomingRouteControls(floor, ct))
            {
                held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
                using var plain = native.OwnAuthenticatedDmc2();
                var message = plain.Use(static bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
                if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate)
                {
                    if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
                    continue;
                }
                Did2RouteProcessingMetadata.RequireReceivedEvent(native.RouteProcessing, message);
                if (native.RouteProcessing[0] == 2) { faulted = true; continue; }
                if (consentOrdinal == 0 || native.Ordinal <= consentOrdinal || (policy & ContactPolicy.AllowRouteUpdates) == 0)
                    throw new CryptographicException("Historical accepted route contradicts native consent.");
                var update = (ContactRouteUpdateDmc2Payload)message.ParsedPayload;
                if (message.Flags != Dmc2Flags.None || message.ReplyToLogicalMessageId.Length != 0 ||
                    message.SenderClientSequence < (scope.IsInitiator ? 4UL : 3UL) ||
                    !FixedRoute(message.NetworkId.Span, scope.Network) || !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
                    !FixedRoute(message.SenderAccountId.Span, scope.RemoteAccount) || !FixedRoute(message.SenderDeviceId.Span, scope.RemoteDevice) ||
                    !FixedRoute(update.RelationshipId.Span, scope.Relationship))
                    throw new CryptographicException("Historical accepted route has a different native endpoint or authored position.");
                if (FixedRoute(native.EventHash, headHash)) continue;
                var generation = BinaryPrimitives.ReadUInt64BigEndian(head.Reachability.Field(3).Span);
                if (update.RouteGeneration <= generation)
                {
                    using var first = opened.Sql.ReadVerifiedReceiveForEvent(floor, native.EventHash) ??
                        throw new CryptographicException("Historical duplicate lost its original native processing.");
                    if (first.Ordinal >= native.Ordinal || first.RouteProcessing[0] != 1)
                        throw new CryptographicException("Historical native route has a changed-generation fork.");
                    using var original = first.OwnAuthenticatedDmc2();
                    if (!original.Use(bytes => FixedRoute(bytes, message.CanonicalBytes.Span)))
                        throw new CryptographicException("Historical duplicate changed its original authenticated bytes.");
                    continue;
                }
                if (faulted || generation == ulong.MaxValue || update.RouteGeneration != generation + 1 ||
                    message.SenderClientSequence <= headSequence || !FixedRoute(update.PredecessorRouteUpdateHash.Span, headHash))
                    throw new CryptographicException("Historical native route has a gap, fork or post-fault promotion.");
                // The decoded canonical control already contains the exact
                // six-record closure after relationship32/generation8/hash32.
                // Parse those original bytes; do not re-author/reframe a route.
                var next = ContactRouteClosureCodec.Decode(update.CanonicalBytes.Span[72..]);
                if (!FixedRoute(head.Reachability.CoreHash.Span, next.Reachability.Field(4).Span))
                    throw new CryptographicException("Historical native route changed its exact reachability predecessor.");
                foreach (var tag in new[] { 1, 2, 10, 12, 13, 14, 18 })
                    if (!FixedRoute(head.Reachability.Field(tag).Span, next.Reachability.Field(tag).Span))
                        throw new CryptographicException("Historical native route changed retained recipient scope.");
                // Inner signature/lineage verification is bound by the original
                // independently qualified native processing, not an SQL flag.
                // Every Store caller additionally verifies its signed original
                // projection, replica evidence, holder request and quorum.
                head = next; headSequence = message.SenderClientSequence;
                CryptographicOperations.ZeroMemory(headHash); headHash = native.EventHash.ToArray();
                if (FixedRoute(next.ExactBytes.Span, expected.ExactBytes.Span)) selected = next;
            }
            if (!FixedRoute((await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false)).Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Historical native route changed under the owned read lease.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return selected ?? throw new CryptographicException("Original Store route is absent from qualified native peer history.");
        }
        finally
        {
            foreach (var bytes in new[] { initial.SessionInit, initial.Hello, headHash, accepted }) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
