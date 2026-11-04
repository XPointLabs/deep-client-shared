using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private Did2MessagingArchiveReducer ReplayRouteWorkingReducer(Did2MessagingFloor stable, Did2MessagingArchiveReducer before,
        IReadOnlyList<byte[]> headers, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored,
        (byte[] Metadata, byte[] Hello) initial, SqliteTransaction tx,
        Action<Did2MessagingArchiveFamily, byte[], byte[]>? selectedObservation = null)
    {
        var originals = new List<Did2MessagingArchiveOriginal>();
        var observations = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            var replay = new Did2MessagingArchiveSemanticReplay(scope, stable, before, Observe, Read,
                initial.Metadata, initial.Hello, Resolve);
            for (var index = 0; index < headers.Count; index++)
            {
                var header = headers[index]; if (header[5] is not (2 or 5 or 6)) continue;
                var native = ReadArchiveOriginal(CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx), tx); originals.Add(native);
                if (native.Reference.Kind == 3)
                {
                    var decision = Did2RouteHistoryDecision.Decode(native.Plaintext, scope);
                    if (decision.Subject == 2 && decision.Action == Did2RouteHistoryDecision.ActionKind.Conflict)
                        replay.RetainPeerFaultReference(decision.FirstFault.IsAbsent ? native.Reference : decision.FirstFault);
                    continue;
                }
                replay.Observe(native, native.Reference.Direction == 1 ? QualifiedRouteOriginal(native, authored) : default);
            }
            return replay.Complete();

            void Observe(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector, ReadOnlySpan<byte> incoming)
            {
                var key = ((byte)family).ToString() + Convert.ToHexString(selector);
                var previous = Read(family, selector);
                var next = previous is null ? incoming.ToArray() : MergeRouteReplayFact(family, selector, previous, incoming);
                _ = Did2MessagingArchivePatricia.Leaf(scope, family, selector, next);
                observations[key] = next; selectedObservation?.Invoke(family, selector.ToArray(), next);
            }
            byte[]? Read(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
            {
                var key = ((byte)family).ToString() + Convert.ToHexString(selector);
                return observations.TryGetValue(key, out var exact) ? exact : ReadArchiveFact(family, selector, tx);
            }
            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 1) return initial.Hello;
                RequireNativeReference(reference, tx); var native = ReadArchiveOriginal(reference, tx); originals.Add(native);
                return reference.Kind == 3 || reference.Direction == 2 ? native.Plaintext : QualifiedRouteOriginal(native, authored);
            }
        }
        finally { foreach (var original in originals) original.Dispose(); }
    }

    private byte[]? ReadRouteFactAtStable(Did2RouteHistoryFactSelector selector, Did2MessagingFloor stable,
        Did2MessagingArchiveReducer reducer, IReadOnlyList<byte[]> headers, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>? authored,
        (byte[] Metadata, byte[] Hello) initial, SqliteTransaction tx, bool sourcesOnly, bool current, int maximumAuthoredOriginals,
        Dictionary<string, Did2MessagingArchiveOriginal> originals, bool conflict = false,
        Did2MessagingArchiveReference? actualConsent = null)
    {
        var value = ReadArchiveFact(selector.Family, selector.Selector.Span, tx);
        foreach (var (header, index) in headers.Select((header, index) => (header, index)))
        {
            if (header[5] == 6)
            {
                using var decision = ReadRouteHistoryDecision(CaptureDecisionReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx), tx);
                if (selector.Family == Did2MessagingArchiveFamily.RouteHistory && selector.Selector.Span[0] == decision.Body.Subject &&
                    decision.Body.Action is Did2RouteHistoryDecision.ActionKind.Bootstrap or Did2RouteHistoryDecision.ActionKind.Evidence)
                {
                    var source = selector.Selector.Span[1] == 1 ? decision.Body.C : decision.Body.P;
                    AddSource(source.Reference);
                    if ((conflict || selector.Selector.Span[1] == 2) && !decision.Body.PreviousDecision.IsAbsent)
                    {
                        using var prior = ReadRouteHistoryDecision(decision.Body.PreviousDecision, tx);
                        AddSource(prior.Body.C.Reference);
                        if (conflict) AddSource(prior.Body.P.Reference);
                    }
                }
            }
            else if (header[5] == 2 && header[6] == 1 && !current && !sourcesOnly && authored is null)
                throw new CryptographicException("Working route facts require the actual paired authored source inventory.");
            else if (header[5] == 2 && header[6] == 1 && !current && sourcesOnly)
                AddSource(CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx));
        }
        if (sourcesOnly) return value;
        if (!current)
        {
            var incoming = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (var (header, index) in headers.Select((header, index) => (header, index)))
            {
                if (header[5] != 2) continue;
                var reference = CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx);
                var id = Id(reference);
                if (!originals.TryGetValue(id, out var native)) { native = ReadArchiveOriginal(reference, tx); originals.Add(id, native); }
                var message = ApplicationCoreCodec.DecodeDmc2(QualifiedRouteOriginal(native, authored).Span);
                try
                {
                    if (reference.Direction == 2)
                    {
                        var key = Convert.ToHexString(header.AsSpan(300, 32));
                        var before = Read(Did2MessagingArchiveFamily.FirstIncomingEvent, header.AsSpan(300, 32));
                        if (before is null || Did2MessagingArchiveReference.Decode(before, false).Ordinal > reference.Ordinal)
                            incoming[key] = reference.Exact.ToArray();
                    }
                    if (message.ParsedPayload is ContactRouteHistoryDmc2Payload page)
                        Did2MessagingArchiveSemanticReplay.ObservePageFacts(scope, native, message, page,
                            actualConsent ?? reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.Consent), initial.Hello, Observe, Read, Resolve);
                }
                finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            }
            void Observe(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> key, ReadOnlySpan<byte> exact)
            {
                if (family != selector.Family || !Fixed(key, selector.Selector.Span)) return;
                value = value is null ? exact.ToArray() : MergeRouteReplayFact(family, key, value, exact);
            }
            byte[]? Read(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> key)
            {
                if (family == Did2MessagingArchiveFamily.FirstIncomingEvent && incoming.TryGetValue(Convert.ToHexString(key), out var found)) return found;
                return ReadArchiveFact(family, key, tx);
            }
        }
        {
            foreach (var (header, index) in headers.Select((header, index) => (header, index)))
            {
                if (header[5] != 6 || selector.Family != Did2MessagingArchiveFamily.RouteHistory) continue;
                using var decision = ReadRouteHistoryDecision(CaptureDecisionReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx), tx);
                if (decision.Body.Subject != selector.Selector.Span[0] || decision.Body.Action is not (Did2RouteHistoryDecision.ActionKind.Bootstrap or Did2RouteHistoryDecision.ActionKind.Evidence)) continue;
                var kind = selector.Selector.Span[1]; var source = kind == 1 ? decision.Body.C : decision.Body.P;
                byte[] identity; ulong generation;
                if (kind == 1)
                {
                    var c = Did2MessagingArchiveRouteSource.Completed(source, Resolve);
                    generation = Did2MessagingArchiveRouteSource.Generation(c.Route.Reachability);
                    identity = Did2MessagingArchiveRouteFacts.Identity(scope, decision.Body.Subject, true, c.Invite.ObjectHash.Span, c.Route.Reachability.CoreHash.Span);
                }
                else
                {
                    var p = Did2MessagingArchiveRouteSource.Proposal(source, Resolve);
                    generation = Did2MessagingArchiveRouteSource.Generation(p.Xra);
                    identity = Did2MessagingArchiveRouteFacts.Identity(scope, decision.Body.Subject, false, p.Xra.CoreHash.Span, p.Xrc.CoreHash.Span, p.Xss.CoreHash.Span);
                }
                if (generation != Did2MessagingArchiveEncoding.U64(selector.Selector.Span, 2)) continue;
                var incoming = Did2MessagingArchiveRouteFacts.Verified(decision.Reference, identity);
                value = value is null ? incoming : Did2MessagingArchiveRouteFacts.MergeHistory(value, incoming);
            }
        }
        return value;

        void AddSource(Did2MessagingArchiveReference reference)
        {
            if (reference.IsAbsent || reference.Kind != 2 || reference.Direction != 1) return;
            var id = Id(reference); if (originals.ContainsKey(id)) return;
            RequireNativeReference(reference, tx); originals.Add(id, ReadArchiveOriginal(reference, tx));
            if (originals.Values.Count(row => row.Reference.Kind == 2 && row.Reference.Direction == 1) > maximumAuthoredOriginals)
                throw new InvalidDataException("Selected route-history authored facts exceed the existing bounded inventory.");
        }
        ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
        {
            if (reference.Kind == 1) return initial.Hello;
            var id = Id(reference);
            if (!originals.TryGetValue(id, out var native))
            {
                RequireNativeReference(reference, tx); native = ReadArchiveOriginal(reference, tx); originals.Add(id, native);
                if (originals.Values.Count(row => row.Reference.Kind == 2 && row.Reference.Direction == 1) > maximumAuthoredOriginals)
                    throw new InvalidDataException("Selected route-history source closure exceeds its declared purpose bound.");
            }
            return QualifiedRouteOriginal(native, authored);
        }
    }

    private static byte[] MergeRouteReplayFact(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector,
        ReadOnlySpan<byte> previous, ReadOnlySpan<byte> incoming)
    {
        if (family == Did2MessagingArchiveFamily.RouteHistory) return Did2MessagingArchiveRouteFacts.MergeHistory(previous, incoming);
        if (family == Did2MessagingArchiveFamily.RouteControl) return Did2MessagingArchiveRouteFacts.MergeControl(selector, previous, incoming);
        if (family is Did2MessagingArchiveFamily.Operation or Did2MessagingArchiveFamily.Ordinal)
        {
            if (!Fixed(previous, incoming)) throw new CryptographicException("Working route replay substituted an immutable native fact.");
            return previous.ToArray();
        }
        if (family is Did2MessagingArchiveFamily.FirstIncomingEvent or Did2MessagingArchiveFamily.QualifiedPeerRoute)
            return (Did2MessagingArchiveEncoding.U64(incoming, 8) < Did2MessagingArchiveEncoding.U64(previous, 8) ? incoming : previous).ToArray();
        return Did2MessagingArchiveBuilder.Merge(family, selector, previous, incoming);
    }
}
