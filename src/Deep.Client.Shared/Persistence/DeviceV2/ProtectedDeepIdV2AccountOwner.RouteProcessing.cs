using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // No raw/classification/time constructor or test minting path. This result
    // can only bind the actual independently verified owner/lease/native floor
    // to a fresh Protocol-sealed receive. It is not semantic or ACK authority.
    internal sealed class OwnedPeerRouteProcessingOutcome
    {
        private readonly byte[] scopeHash, predecessor, operation, eventHash, exact;
        private OwnedPeerRouteProcessingOutcome(Did2MessagingSessionScope scope, Did2MessagingFloor floor,
            ExactDpe2ProtocolPlanSnapshot snapshot, ReadOnlySpan<byte> exact)
        {
            Did2RouteProcessingMetadata.RequireShape(exact);
            if (exact[0] == 0) throw new InvalidDataException("A route receive requires its actual processing outcome.");
            scopeHash = scope.Hash.ToArray(); predecessor = floor.Exact.ToArray();
            operation = snapshot.OperationId.ToArray(); eventHash = SHA256.HashData(snapshot.AuthenticatedDmc2);
            this.exact = exact.ToArray();
        }

        internal void CopyForSealedTransition(Did2MessagingSessionScope scope, Did2MessagingFloor floor,
            ExactDpe2ProtocolPlanSnapshot snapshot, Span<byte> destination)
        {
            if (destination.Length != Did2RouteProcessingMetadata.Bytes ||
                snapshot.Direction != MessagingCryptoV1Direction.Receive || !snapshot.HasStateMutation ||
                !FixedRoute(scope.Hash, scopeHash) || !FixedRoute(floor.Exact.Span, predecessor) ||
                !FixedRoute(snapshot.OperationId, operation) ||
                !FixedRoute(SHA256.HashData(snapshot.AuthenticatedDmc2), eventHash))
                throw new CryptographicException("Route processing belongs to a different sealed native receive.");
            exact.CopyTo(destination);
        }

        internal static async Task<OwnedPeerRouteProcessingOutcome> CaptureUnderLeaseAsync(
            ProtectedDeepIdV2AccountOwner owner, VerifiedDeepIdV2CurrentAccount current,
            OwnedDid2MessagingStorage opened, HeldDeepIdV2AccountLease held, Did2MessagingFloor floor,
            ExactDpe2ProtocolPlanSnapshot snapshot,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
            VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
        {
            held.RequireOwner(owner.lease); ct.ThrowIfCancellationRequested();
            var scope = opened.Scope;
            if (snapshot.Direction != MessagingCryptoV1Direction.Receive || !snapshot.HasStateMutation ||
                snapshot.AuthenticatedDmc2.Length is < 4497 or > 23649 ||
                snapshot.PriorStateGeneration != floor.RatchetGeneration ||
                snapshot.ExpectedJournalGeneration != floor.Ordinal ||
                !FixedRoute(snapshot.JournalPredecessor, floor.Head) ||
                !FixedRoute(snapshot.PriorStateCommitment, floor.RatchetCommitment))
                throw new CryptographicException("Route processing lacks its actual fresh native predecessor.");
            var message = ApplicationCoreCodec.DecodeDmc2(snapshot.AuthenticatedDmc2);
            if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate)
            {
                if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose();
                throw new CryptographicException("Route processing requires the canonical authenticated control.");
            }
            var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            var actual = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(actual.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Route processing predecessor changed under the actual account lease.");

            // An independently authenticated duplicate keeps its original first
            // result, even after event expiry. Exact envelope replay bypasses
            // capture altogether and uses the existing native row.
            var eventHash = SHA256.HashData(snapshot.AuthenticatedDmc2);
            using var original = opened.Sql.ReadVerifiedReceiveForEvent(floor, eventHash);
            byte[] exact;
            if (original is not null)
            {
                using var plain = original.OwnAuthenticatedDmc2();
                if (!plain.Use(bytes => FixedRoute(bytes, snapshot.AuthenticatedDmc2)))
                    throw new CryptographicException("Route duplicate differs from its original authenticated event.");
                Did2RouteProcessingMetadata.RequireReceivedEvent(original.RouteProcessing, message);
                exact = original.RouteProcessing.ToArray();
            }
            else
            {
                var history = await owner.ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(current, opened,
                    own, peer, source, held, ct).ConfigureAwait(false);
                // These are local/base authority prerequisites, outside remote
                // rejection classification. Lost custody/time/DCA never mints
                // an irreversible peer fault.
                await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
                    peer, own, source, held, ct).ConfigureAwait(false);
                var accepted = !history.Faulted && HasAvailableNativePeerControlPosition(opened, floor, message, ct) &&
                    await history.HasConsent(checked(floor.Ordinal + 1), ct).ConfigureAwait(false);
                VerifiedDeepIdV2UpdatedMailboxRoute? verified = null;
                if (accepted)
                {
                    try
                    {
                        verified = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(history.Original,
                            peer, own.Network, own.Authority, source.RendezvousTrustedTime, history.Head.ExactBytes,
                            history.HeadEventHash, scope.Relationship.ToArray(), scope.Conversation.ToArray(),
                            message.CanonicalBytes, ct).ConfigureAwait(false);
                    }
                    catch (CryptographicException) { accepted = false; }
                    catch (InvalidDataException) { accepted = false; }
                }
                await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
                    peer, own, source, held, ct).ConfigureAwait(false);
                await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
                var reading = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
                if (reading.SampleSeconds < first.SampleSeconds || !FixedRoute(reading.BootId.Span, first.BootId.Span))
                    throw new CryptographicException("Route processing crossed protected clock continuity.");
                var lower = Math.Min(checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
                    checked(peer.TrustedLowerUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
                var upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
                    checked(peer.TrustedUpperUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
                var sample = reading.SampleSeconds; var boot = reading.BootId;
                if (accepted)
                {
                    DeepIdV2ContactRouteTimeWindow? window = null;
                    try
                    {
                        window = await verified!.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                    }
                    catch (CryptographicException)
                    {
                        // Expiring remote route can be rejected only if all
                        // independent base authorities still remain current.
                        accepted = false;
                        await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
                            peer, own, source, held, ct).ConfigureAwait(false);
                        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
                        reading = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
                        if (reading.SampleSeconds < sample || !FixedRoute(reading.BootId.Span, boot.Span))
                            throw new CryptographicException("Route rejection crossed its final protected clock.");
                        lower = Math.Min(checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
                            checked(peer.TrustedLowerUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
                        upper = Math.Max(checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample),
                            checked(peer.TrustedUpperUnixSeconds + reading.SampleSeconds - peer.MonotonicSample));
                        sample = reading.SampleSeconds; boot = reading.BootId;
                    }
                    if (window is not null)
                    {
                        // Our continuity failure is local, not a remotely
                        // rejected event; never catch and persist it as a fault.
                        if (window.MonotonicSample < sample || !FixedRoute(window.BootId.Span, boot.Span))
                            throw new CryptographicException("Route admission crossed its final protected clock.");
                        lower = window.LowerUnixSeconds; upper = window.UpperUnixSeconds;
                        sample = window.MonotonicSample; boot = window.BootId;
                    }
                }
                exact = new byte[Did2RouteProcessingMetadata.Bytes]; exact[0] = accepted ? (byte)1 : (byte)2;
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(8), checked(lower * 1000));
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(16), checked(upper * 1000));
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(24), sample);
                SHA256.HashData(boot.Span, exact.AsSpan(32));
            }
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(final.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Route processing lost its actual native predecessor before capture.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(owner.lease);
            return new(scope, floor, snapshot, exact);
        }
    }

    private static bool HasAvailableNativePeerControlPosition(OwnedDid2MessagingStorage opened,
        Did2MessagingFloor floor, ParsedDmc2 message, CancellationToken ct)
    {
        var scope = opened.Scope;
        if (message.ParsedPayload is not ContactRouteUpdateDmc2Payload update ||
            message.SenderClientSequence < (scope.IsInitiator ? 4UL : 3UL) ||
            !FixedRoute(message.ConversationId.Span, scope.Conversation) ||
            !FixedRoute(update.RelationshipId.Span, scope.Relationship)) return false;
        // The first classification joins actual authenticated positions,
        // including unmaterialized and compacted native events, not SQL inbox
        // counters. A different event at the same authored position is a fault.
        foreach (var native in opened.Sql.ReadVerifiedIncomingEvents(floor, ct))
        {
            using var plain = native.OwnAuthenticatedDmc2();
            var prior = plain.Use(static bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
            try
            {
                if (prior.SenderClientSequence == message.SenderClientSequence &&
                    FixedRoute(prior.ConversationId.Span, message.ConversationId.Span) &&
                    !FixedRoute(prior.CanonicalBytes.Span, message.CanonicalBytes.Span)) return false;
            }
            finally { if (prior.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        return true;
    }
}
