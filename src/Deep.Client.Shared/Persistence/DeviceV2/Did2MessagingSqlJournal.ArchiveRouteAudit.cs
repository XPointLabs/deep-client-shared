using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private void AddArchiveAuthoredReference(Dictionary<ulong, Did2MessagingArchiveOriginal> result,
        Did2MessagingArchiveReference reference, SqliteTransaction tx)
    {
        if (reference.Kind == 3)
        {
            using var decision = ReadRouteHistoryDecision(reference, tx);
            foreach (var source in new[] { decision.Body.Selected, decision.Body.C.Reference, decision.Body.P.Reference, decision.Body.L,
                decision.Body.Consent, decision.Body.Conflicting.Reference }) AddArchiveAuthoredReference(result, source, tx);
            if (decision.Body.FirstFault.Kind == 2) AddArchiveAuthoredReference(result, decision.Body.FirstFault, tx);
            return;
        }
        if (reference.Kind == 2 && reference.Direction == 1 && !result.ContainsKey(reference.Ordinal))
            result.Add(reference.Ordinal, ReadArchiveOriginal(reference, tx));
    }

    private static bool VerifyArchiveRouteObservation(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector,
        ReadOnlySpan<byte> actual, ReadOnlySpan<byte> observation)
    {
        if (family == Did2MessagingArchiveFamily.RouteControl)
        {
            if (selector[0] == 6)
            {
                var firstSource = Did2MessagingArchiveReference.Decode(actual[..88], false);
                var observedSource = Did2MessagingArchiveReference.Decode(observation[..88], false);
                if (firstSource.Ordinal > observedSource.Ordinal) throw new CryptographicException("Rendezvous replay omitted its first native source.");
                if (Fixed(actual.Slice(88, 32), observation.Slice(88, 32)))
                {
                    if (firstSource.Ordinal == observedSource.Ordinal && !Fixed(actual[..120], observation[..120]))
                        throw new CryptographicException("Rendezvous replay changed its exact first source.");
                    return firstSource.Ordinal == observedSource.Ordinal;
                }
                var conflictingSource = Did2MessagingArchiveReference.Decode(actual.Slice(120, 88));
                if (conflictingSource.IsAbsent || conflictingSource.Ordinal > observedSource.Ordinal)
                    throw new CryptographicException("Rendezvous replay omitted its first divergent native source.");
                if (conflictingSource.Ordinal == observedSource.Ordinal && !Fixed(actual.Slice(120, 120), observation[..120]))
                    throw new CryptographicException("Rendezvous replay changed its exact divergent source.");
                return false; // One fact is counted once, at its first source.
            }
            if (selector[0] is not (1 or 4 or 5))
            {
                if (!Fixed(actual, observation)) throw new CryptographicException("Full route correlation replay changes its unique original.");
                return true;
            }
            var selected = Did2MessagingArchiveReference.Decode(actual[..88], false); var source = Did2MessagingArchiveReference.Decode(observation[..88], false);
            var actualSequence = Did2MessagingArchiveEncoding.U64(actual, 88); var observedSequence = Did2MessagingArchiveEncoding.U64(observation, 88);
            if (selector[0] == 5)
            {
                var actualGeneration = Did2MessagingArchiveEncoding.U64(actual, 96);
                var observedGeneration = Did2MessagingArchiveEncoding.U64(observation, 96);
                if (actualGeneration < observedGeneration) throw new CryptographicException("Rendezvous replay omitted its greatest generation.");
                if (actualGeneration > observedGeneration) return false;
            }
            if (actualSequence < observedSequence || actualSequence == observedSequence && selected.Ordinal > source.Ordinal ||
                selected.Ordinal == source.Ordinal && !Fixed(actual, observation)) throw new CryptographicException("Full endpoint/request replay did not retain its greatest authenticated sequence.");
            return selected.Ordinal == source.Ordinal;
        }
        var first = Did2MessagingArchiveReference.Decode(actual[..88]); var incoming = Did2MessagingArchiveReference.Decode(observation[..88]);
        if (!incoming.IsAbsent)
        {
            if (first.IsAbsent || first.Ordinal > incoming.Ordinal || !Fixed(actual.Slice(88, 32), observation.Slice(88, 32)) ||
                first.Ordinal == incoming.Ordinal && !Fixed(first.Exact.Span, incoming.Exact.Span))
                throw new CryptographicException("Full historical identity replay changes its first independently verified decision.");
        }
        var candidate = Did2RouteHistorySource.Decode(actual.Slice(120, 96)); var next = Did2RouteHistorySource.Decode(observation.Slice(120, 96));
        if (!next.IsAbsent)
        {
            var sequence = Did2MessagingArchiveEncoding.U64(actual, 216); var nextSequence = Did2MessagingArchiveEncoding.U64(observation, 216);
            if (candidate.IsAbsent || sequence < nextSequence || sequence == nextSequence &&
                (candidate.Reference.Ordinal > next.Reference.Ordinal || candidate.Reference.Ordinal == next.Reference.Ordinal && candidate.AtomIndex > next.AtomIndex))
                throw new CryptographicException("Full historical candidate replay did not retain its greatest usable source position.");
            if (candidate.Reference.Ordinal == next.Reference.Ordinal && candidate.AtomIndex == next.AtomIndex && !Fixed(actual[120..], observation[120..]))
                throw new CryptographicException("Full historical candidate replay changed an exact original atom.");
        }
        return !first.IsAbsent ? !incoming.IsAbsent && Fixed(first.Exact.Span, incoming.Exact.Span) :
            !next.IsAbsent && Fixed(candidate.Exact.Span, next.Exact.Span);
    }

    private void VerifyArchiveRouteWitness(Did2MessagingArchiveReference reference, Did2MessagingArchiveOriginal original,
        Did2MessagingArchivePatricia.Node leaf, bool candidate, SqliteTransaction tx)
    {
        if (leaf.Family == Did2MessagingArchiveFamily.RouteHistory)
        {
            if (!candidate)
            {
                if (reference.Kind != 3) throw new CryptographicException("A verified historical fact lost its native decision source.");
                var decision = Did2RouteHistoryDecision.Decode(original.Plaintext, scope);
                if (decision.Subject != leaf.Selector[0] || decision.Action is not (Did2RouteHistoryDecision.ActionKind.Bootstrap or Did2RouteHistoryDecision.ActionKind.Evidence))
                    throw new CryptographicException("A verified historical fact has an ineligible decision subject/action.");
                var source = leaf.Selector[1] == 1 ? decision.C : decision.P;
                RequireNativeReference(source.Reference, tx); using var actual = ReadArchiveOriginal(source.Reference, tx);
                return; // Full semantic replay independently checks artifact identity and generation with authored custody.
            }
            var selected = Did2RouteHistorySource.Decode(leaf.Value.Slice(120, 96), false);
            var message = ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            Did2RouteProcessingMetadata.RequireReceivedEvent(original.Metadata.AsSpan(608, 64), message);
            var atom = Did2MessagingArchiveRouteSource.Atom(selected, message);
            var generation = leaf.Selector[1] == 1 ? atom.IsCompleted ? Did2MessagingArchiveRouteSource.Generation(ContactRouteClosureCodec.Decode(atom.ExactCompletedRoute.Span).Reachability) :
                throw new CryptographicException("A candidate C fact names a proposal-only atom.") :
                Did2MessagingArchiveRouteSource.Generation(ContactCodec.Decode("XRA1", atom.ExactXra1.Span));
            if (leaf.Selector[0] != 2 || generation != BinaryPrimitives.ReadUInt64BigEndian(leaf.Selector[2..]) ||
                message.SenderClientSequence != Did2MessagingArchiveEncoding.U64(leaf.Value, 216))
                throw new CryptographicException("A historical candidate changes its actual native generation or sender position.");
            return;
        }
        if (reference.Kind != 2 || reference.Direction != 1 && leaf.Selector[0] is not (1 or 5 or 6))
            throw new CryptographicException("Route correlation has another native source direction.");
        if (leaf.Selector[0] == 5)
        {
            var message = ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload { RendezvousSuccessors.Count: > 0 } page ||
                reference.Direction != leaf.Selector[1] || message.SenderClientSequence != Did2MessagingArchiveEncoding.U64(leaf.Value, 88) ||
                (ulong)page.RendezvousSuccessors.Count != Did2MessagingArchiveEncoding.U64(leaf.Value, 96))
                throw new CryptographicException("Rendezvous observation lost its actual native announcement.");
            if (reference.Direction == 2) Did2RouteProcessingMetadata.RequireReceivedEvent(original.Metadata.AsSpan(608, 64), message);
            return;
        }
        if (leaf.Selector[0] == 6)
        {
            var message = ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            var generation = BinaryPrimitives.ReadUInt64BigEndian(leaf.Selector[2..]);
            if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload page ||
                page.RendezvousSuccessors.Count < (int)generation || reference.Direction != leaf.Selector[1] ||
                !Fixed(SHA256.HashData(page.RendezvousSuccessors[(int)generation - 1].Span), leaf.Value.Slice(candidate ? 208 : 88, 32)))
                throw new CryptographicException("Rendezvous generation witness changed its native signed source.");
            if (reference.Direction == 2) Did2RouteProcessingMetadata.RequireReceivedEvent(original.Metadata.AsSpan(608, 64), message);
            return;
        }
        if (leaf.Selector[0] == 2 && !Fixed(leaf.Selector[1..], original.Metadata.AsSpan(300, 32)))
            throw new CryptographicException("Outgoing request correlation changes its actual native event hash.");
        if (reference.Direction == 2)
        {
            var message = ApplicationCoreCodec.DecodeDmc2(original.Plaintext);
            if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload page || page.Mode is not (DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement) ||
                message.SenderClientSequence != Did2MessagingArchiveEncoding.U64(leaf.Value, 88) ||
                !Fixed(leaf.Selector[2..10], page.RightCursor.Span[..8]) || !Fixed(leaf.Selector[10..], page.RightCursor.Span.Slice(8, 32)))
                throw new CryptographicException("Endpoint candidate changes its actual incoming announcement.");
        }
        // Outgoing mode/scope/counter and tag3/tag4 selector bindings are
        // independently derived from permanent authored originals in full replay.
    }
}
