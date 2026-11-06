using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingArchiveSemanticReplay
{
    // Selected bootstrap reads replay old private-control state, while each
    // retained kind6 body/before chain is separately authenticated by SQL.
    // Only its already adopted sticky peer-fault reference affects that old
    // state; this does not derive C/P or qualify another public artifact.
    internal void RetainPeerFaultReference(Did2MessagingArchiveReference reference)
    {
        if (reference.IsAbsent || reference.Kind is not (2 or 3)) throw Bad();
        var current = Get(Did2MessagingArchiveReducer.ReferenceKind.FirstFault);
        if (current.IsAbsent) Set(Did2MessagingArchiveReducer.ReferenceKind.FirstFault, reference);
        else if (!Fixed(current.Exact.Span, reference.Exact.Span)) throw Bad();
    }
    private void ObservePage(Did2MessagingArchiveOriginal native, ParsedDmc2 message, ContactRouteHistoryDmc2Payload page)
        => ObservePageFacts(scope, native, message, page, Get(Did2MessagingArchiveReducer.ReferenceKind.Consent), initialHello, observe, read, Source);

    internal static void ObservePageFacts(Did2MessagingSessionScope scope, Did2MessagingArchiveOriginal native,
        ParsedDmc2 message, ContactRouteHistoryDmc2Payload page, Did2MessagingArchiveReference consent,
        ReadOnlyMemory<byte> initialHello, ObserveFact observe, ReadFact read,
        Func<Did2MessagingArchiveReference, ReadOnlyMemory<byte>> source)
    {
        var reference = native.Reference;
        if (reference.Direction == 2) Did2RouteProcessingMetadata.RequireReceivedEvent(native.Metadata.AsSpan(608, 64), message);
        if (!Fixed(page.RelationshipId.Span, scope.Relationship) || consent.IsAbsent)
        { if (reference.Direction == 2) return; throw Bad(); }
        var acceptance = source(consent); var accepted = ApplicationCoreCodec.DecodeDmc2(acceptance.Span);
        var hello = ApplicationCoreCodec.DecodeDmc2(initialHello.Span);
        bool bound;
        try
        {
            bound = hello.ParsedPayload is ContactHelloDmc2Payload greeting && accepted.ParsedPayload is ContactAcceptDmc2Payload accept &&
                Fixed(greeting.RelationshipId.Span, scope.Relationship) && Fixed(accept.RelationshipId.Span, scope.Relationship) &&
                Fixed(accept.ContactHelloHash.Span, SHA256.HashData(initialHello.Span)) &&
                (greeting.Policy & accept.Policy & ContactPolicy.AllowRouteUpdates) != 0;
        }
        finally { if (accepted.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        var historyDirection = page.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest ? (byte)(3 - reference.Direction) : reference.Direction;
        var anchor = (historyDirection == 1) == scope.IsInitiator ? initialHello : acceptance;
        if (!bound || !Fixed(page.OriginalAnchorHash.Span, SHA256.HashData(anchor.Span)))
        { if (reference.Direction == 2) return; throw Bad(); }
        if (reference.Direction == 2)
        {
            Did2RouteProcessingMetadata.RequireReceivedEvent(native.Metadata.AsSpan(608, 64), message);
            for (var index = 0; index < page.Atoms.Count; index++)
            {
                var atomSource = Did2RouteHistorySource.From(reference, checked((byte)(index + 1)));
                var xra = ContactCodec.Decode("XRA1", page.Atoms[index].ExactXra1.Span);
                observe(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(2, 2, Did2MessagingArchiveRouteSource.Generation(xra)),
                    Did2MessagingArchiveRouteFacts.Candidate(atomSource, message.SenderClientSequence));
                if (page.Atoms[index].IsCompleted)
                {
                    var route = ContactRouteClosureCodec.Decode(page.Atoms[index].ExactCompletedRoute.Span);
                    observe(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(2, 1, Did2MessagingArchiveRouteSource.Generation(route.Reachability)),
                        Did2MessagingArchiveRouteFacts.Candidate(atomSource, message.SenderClientSequence));
                }
            }
        }
        if (page.Mode is DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement)
        {
            var value = new byte[96]; reference.Exact.Span.CopyTo(value);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(88), message.SenderClientSequence);
            observe(Did2MessagingArchiveFamily.RouteControl,
                Did2MessagingArchiveRouteFacts.EndpointSelector(reference.Direction, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span), page.RightCursor.Span.Slice(8, 32)), value);
        }
        if (page.RendezvousSuccessors.Count > 0)
        {
            var value = new byte[104]; reference.Exact.Span.CopyTo(value);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(88), message.SenderClientSequence);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(96), (ulong)page.RendezvousSuccessors.Count);
            observe(Did2MessagingArchiveFamily.RouteControl,
                Did2MessagingArchiveRouteFacts.LatestRendezvousSelector(reference.Direction), value);
            for (var i = 0; i < page.RendezvousSuccessors.Count; i++)
            {
                var generation = new byte[240]; reference.Exact.Span.CopyTo(generation);
                SHA256.HashData(page.RendezvousSuccessors[i].Span, generation.AsSpan(88, 32));
                observe(Did2MessagingArchiveFamily.RouteControl,
                    Did2MessagingArchiveRouteFacts.RendezvousGenerationSelector(reference.Direction, (ulong)i + 1), generation);
            }
        }
        if (reference.Direction == 1 && page.Mode == DeepIdV2ContactRouteHistoryMode.HistoryRequest)
        {
            observe(Did2MessagingArchiveFamily.RouteControl, Did2MessagingArchiveRouteFacts.CorrelationSelector(2, native.Metadata.AsSpan(300, 32)), reference.Exact.Span);
            var value = new byte[96]; reference.Exact.Span.CopyTo(value);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(88), message.SenderClientSequence);
            observe(Did2MessagingArchiveFamily.RouteControl, Did2MessagingArchiveRouteFacts.LatestRequestSelector(), value);
        }
        else if (reference.Direction == 1 && page.RequestEventHash.Span.IndexOfAnyExcept((byte)0) >= 0)
        {
            var request = read(Did2MessagingArchiveFamily.FirstIncomingEvent, page.RequestEventHash.Span) ?? throw Bad();
            var requestRef = Did2MessagingArchiveReference.Decode(request, false);
            var requestMessage = ApplicationCoreCodec.DecodeDmc2(source(requestRef).Span);
            if (requestMessage.ParsedPayload is not ContactRouteHistoryDmc2Payload requestPage || requestPage.Mode != DeepIdV2ContactRouteHistoryMode.HistoryRequest ||
                !Fixed(SHA256.HashData(requestMessage.CanonicalBytes.Span), page.RequestEventHash.Span)) throw Bad();
            observe(Did2MessagingArchiveFamily.RouteControl, Did2MessagingArchiveRouteFacts.CorrelationSelector(3, page.RequestEventHash.Span), reference.Exact.Span);
        }
    }

    private void ObserveDecision(Did2MessagingArchiveOriginal native)
    {
        var reference = native.Reference;
        if (native.Metadata[5] != 6 || native.Metadata[6] != 0 || reference.Direction != 0) throw Bad();
        var body = Did2RouteHistoryDecision.Decode(native.Plaintext, scope);
        var before = Did2MessagingFloor.Decode(native.Metadata.AsSpan(8, Did2MessagingFloor.Bytes), scope);
        body.RequireBefore(before);
        if (!Fixed(SHA256.HashData(native.Plaintext), native.Metadata.AsSpan(300, 32)) || !Fixed(body.Operation(scope, before), reference.Operation)) throw Bad();
        var decisionKind = body.Subject == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnDecision : Did2MessagingArchiveReducer.ReferenceKind.PeerDecision;
        var headKind = body.Subject == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead;
        var previous = Get(decisionKind);
        if (!Fixed(previous.Exact.Span, body.PreviousDecision.Exact.Span) || !Fixed(body.Consent.Exact.Span, Get(Did2MessagingArchiveReducer.ReferenceKind.Consent).Exact.Span)) throw Bad();
        Did2RouteHistoryDecision? prior = previous.IsAbsent ? null : Did2RouteHistoryDecision.Decode(original(previous).Span, scope);
        if (prior is null)
        {
            var anchor = (body.Subject == 1) == scope.IsInitiator ? Did2MessagingArchiveReference.Initial(reducer.AsSpan(224, 32)) : body.Consent;
            if (body.Action != Did2RouteHistoryDecision.ActionKind.Bootstrap || body.C.AtomIndex != 0 || body.P.AtomIndex != 0 ||
                !Fixed(body.C.Reference.Exact.Span, anchor.Exact.Span) || !Fixed(body.P.Reference.Exact.Span, anchor.Exact.Span) ||
                !Fixed(body.L.Exact.Span, Get(headKind).Exact.Span) ||
                !Fixed(body.FirstFault.Exact.Span, Get(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).Exact.Span)) throw Bad();
        }
        else
        {
            if (body.Action == Did2RouteHistoryDecision.ActionKind.Bootstrap || prior.Subject != body.Subject) throw Bad();
            var fault = prior.FirstFault;
            if (fault.IsAbsent && prior.Action == Did2RouteHistoryDecision.ActionKind.Conflict) fault = previous;
            if (!Fixed(body.FirstFault.Exact.Span, fault.Exact.Span)) throw Bad();
            var cSame = Fixed(body.C.Exact.Span, prior.C.Exact.Span); var pSame = Fixed(body.P.Exact.Span, prior.P.Exact.Span);
            if (body.Action == Did2RouteHistoryDecision.ActionKind.Evidence)
            {
                if (!Fixed(body.L.Exact.Span, prior.L.Exact.Span) || body.SelectedAtomIndex == 0 || cSame && pSame ||
                    !cSame && (!Fixed(body.C.Reference.Exact.Span, body.Selected.Exact.Span) || body.C.AtomIndex != body.SelectedAtomIndex) ||
                    !pSame && (!Fixed(body.P.Reference.Exact.Span, body.Selected.Exact.Span) || body.P.AtomIndex != body.SelectedAtomIndex)) throw Bad();
            }
            else if (!cSame || !pSame || body.Action == Did2RouteHistoryDecision.ActionKind.Conflict && !Fixed(body.L.Exact.Span, prior.L.Exact.Span)) throw Bad();
            if (body.Action == Did2RouteHistoryDecision.ActionKind.Promotion && !fault.IsAbsent) throw Bad();
        }
        if (body.Action is Did2RouteHistoryDecision.ActionKind.Bootstrap or Did2RouteHistoryDecision.ActionKind.Evidence)
        {
            if (prior is null || !Fixed(prior.C.Exact.Span, body.C.Exact.Span)) VerifiedHistory(1, body.C);
            if (prior is null || !Fixed(prior.P.Exact.Span, body.P.Exact.Span)) VerifiedHistory(2, body.P);
        }
        if (body.Action == Did2RouteHistoryDecision.ActionKind.Promotion)
        {
            if (!Fixed(body.Selected.Exact.Span, body.L.Exact.Span)) throw Bad();
            var message = ApplicationCoreCodec.DecodeDmc2(Source(body.L).Span);
            if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload page || page.Mode is not (DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement) ||
                body.L.Direction != body.Subject || !Fixed(page.RelationshipId.Span, scope.Relationship)) throw Bad();
            var selector = Did2MessagingArchiveRouteFacts.HistorySelector(body.Subject, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span));
            var fact = read(Did2MessagingArchiveFamily.RouteHistory, selector) ?? throw Bad();
            var verified = Did2MessagingArchiveReference.Decode(fact.AsSpan(0, 88), false);
            var verifiedBody = Did2RouteHistoryDecision.Decode(original(verified).Span, scope);
            var closure = Did2MessagingArchiveRouteSource.Completed(verifiedBody.C, Source);
            if (!Fixed(closure.Route.Reachability.CoreHash.Span, page.RightCursor.Span.Slice(8, 32)) ||
                !Fixed(SHA256.HashData(closure.Route.ExactBytes.Span), body.EndpointHash)) throw Bad();
            // Legacy head/Previous retains its original private-event ordering.
            // A later-qualified public endpoint can have arrived earlier; its
            // independent L source lives in this decision and the new reducer ref.
            var oldLive = prior?.L ?? Get(headKind);
            if (body.Subject == 2) QualifiedPeer(reference, closure.Route.ExactBytes.Span, body.Consent.Ordinal,
                oldLive.IsAbsent ? new byte[32] : SHA256.HashData(Source(oldLive).Span), message.SenderClientSequence);
        }
        if (body.Action == Did2RouteHistoryDecision.ActionKind.Conflict) RequireProvenConflict(body);
        if (body.Action != Did2RouteHistoryDecision.ActionKind.Promotion)
        {
            var completed = Did2MessagingArchiveRouteSource.Completed(body.C, Source);
            if (!Fixed(SHA256.HashData(completed.Route.ExactBytes.Span), body.EndpointHash)) throw Bad();
        }
        if (body.Subject == 2 && body.Action == Did2RouteHistoryDecision.ActionKind.Conflict && Get(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).IsAbsent)
            Set(Did2MessagingArchiveReducer.ReferenceKind.FirstFault, reference);
        Set(decisionKind, reference);

        void VerifiedHistory(byte kind, Did2RouteHistorySource source)
        {
            byte[] identity; ulong generation;
            if (kind == 1)
            {
                var completed = Did2MessagingArchiveRouteSource.Completed(source, Source);
                generation = Did2MessagingArchiveRouteSource.Generation(completed.Route.Reachability);
                identity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, true, completed.Invite.ObjectHash.Span, completed.Route.Reachability.CoreHash.Span);
            }
            else
            {
                var proposal = Did2MessagingArchiveRouteSource.Proposal(source, Source);
                generation = Did2MessagingArchiveRouteSource.Generation(proposal.Xra);
                identity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, false, proposal.Xra.CoreHash.Span, proposal.Xrc.CoreHash.Span, proposal.Xss.CoreHash.Span);
            }
            observe(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(body.Subject, kind, generation),
                Did2MessagingArchiveRouteFacts.Verified(reference, identity));
        }
    }

    private void RequireProvenConflict(Did2RouteHistoryDecision body)
    {
        var selected = Did2RouteHistorySource.From(body.Selected, body.SelectedAtomIndex);
        var related = body.Conflicting;
        if (Fixed(selected.Exact.Span, related.Exact.Span)) throw Bad();
        var left = ApplicationCoreCodec.DecodeDmc2(Source(selected.Reference).Span);
        var right = ApplicationCoreCodec.DecodeDmc2(Source(related.Reference).Span);
        foreach (var message in new[] { left, right })
            if (!Fixed(message.NetworkId.Span, scope.Network) || !Fixed(message.ConversationId.Span, scope.Conversation) ||
                !Fixed(message.SenderAccountId.Span, body.Subject == 1 ? scope.LocalAccount : scope.RemoteAccount) ||
                !Fixed(message.SenderDeviceId.Span, body.Subject == 1 ? scope.LocalDevice : scope.RemoteDevice)) throw Bad();
        if (selected.AtomIndex == 0 && related.AtomIndex == 0)
        {
            if (body.Subject != 2 || selected.Reference.Kind != 2 || related.Reference.Kind != 2 ||
                left.SenderClientSequence != right.SenderClientSequence || Fixed(SHA256.HashData(left.CanonicalBytes.Span), SHA256.HashData(right.CanonicalBytes.Span))) throw Bad();
            var position = new byte[40]; scope.Conversation.CopyTo(position);
            BinaryPrimitives.WriteUInt64BigEndian(position.AsSpan(32), left.SenderClientSequence);
            var fact = read(Did2MessagingArchiveFamily.PeerAuthoredPosition, position) ?? throw Bad();
            var first = Did2MessagingArchiveReference.Decode(fact.AsSpan(0, 88), false);
            var second = Did2MessagingArchiveReference.Decode(fact.AsSpan(120, 88), false);
            var selectedHash = SHA256.HashData(left.CanonicalBytes.Span); var relatedHash = SHA256.HashData(right.CanonicalBytes.Span);
            if (Fixed(first.Exact.Span, related.Reference.Exact.Span))
            { if (!Fixed(fact.AsSpan(88, 32), relatedHash) || Fixed(fact.AsSpan(88, 32), selectedHash)) throw Bad(); }
            else if (Fixed(second.Exact.Span, related.Reference.Exact.Span))
            { if (!Fixed(fact.AsSpan(208, 32), relatedHash) || !Fixed(fact.AsSpan(88, 32), selectedHash)) throw Bad(); }
            else throw Bad();
            return;
        }
        if (selected.AtomIndex == 0) throw Bad();
        if (TryConflict(2)) return;
        if (Did2MessagingArchiveRouteSource.Atom(selected, left).IsCompleted &&
            (related.AtomIndex == 0 || Did2MessagingArchiveRouteSource.Atom(related, right).IsCompleted) && TryConflict(1)) return;
        throw Bad();

        bool TryConflict(byte kind)
        {
            ulong generation, otherGeneration; byte[] identity, otherIdentity;
            if (kind == 1)
            {
                var one = Did2MessagingArchiveRouteSource.Completed(selected, Source); var two = Did2MessagingArchiveRouteSource.Completed(related, Source);
                generation = Did2MessagingArchiveRouteSource.Generation(one.Route.Reachability); otherGeneration = Did2MessagingArchiveRouteSource.Generation(two.Route.Reachability);
                identity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, true, one.Invite.ObjectHash.Span, one.Route.Reachability.CoreHash.Span);
                otherIdentity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, true, two.Invite.ObjectHash.Span, two.Route.Reachability.CoreHash.Span);
            }
            else
            {
                var one = Did2MessagingArchiveRouteSource.Proposal(selected, Source); var two = Did2MessagingArchiveRouteSource.Proposal(related, Source);
                generation = Did2MessagingArchiveRouteSource.Generation(one.Xra); otherGeneration = Did2MessagingArchiveRouteSource.Generation(two.Xra);
                identity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, false, one.Xra.CoreHash.Span, one.Xrc.CoreHash.Span, one.Xss.CoreHash.Span);
                otherIdentity = Did2MessagingArchiveRouteFacts.Identity(scope, body.Subject, false, two.Xra.CoreHash.Span, two.Xrc.CoreHash.Span, two.Xss.CoreHash.Span);
            }
            if (generation != otherGeneration || Fixed(identity, otherIdentity)) return false;
            var fact = read(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(body.Subject, kind, generation));
            if (fact is null) return false;
            var verified = Did2MessagingArchiveReference.Decode(fact.AsSpan(0, 88));
            if (verified.IsAbsent || !Fixed(fact.AsSpan(88, 32), otherIdentity)) return false;
            var prior = Did2RouteHistoryDecision.Decode(original(verified).Span, scope);
            return Fixed((kind == 1 ? prior.C : prior.P).Exact.Span, related.Exact.Span);
        }
    }
}
