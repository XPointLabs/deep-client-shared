using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private Did2MessagingArchiveReference CaptureNativeReference(ulong ordinal, ReadOnlySpan<byte> metadata, SqliteTransaction tx)
    {
        if (metadata[5] == 6) return CaptureDecisionReference(ordinal, metadata, tx);
        using var tuple = new SelectedTuple(ordinal, metadata[6], metadata.Slice(268, 32).ToArray(), metadata.ToArray());
        return CaptureTupleReference(tuple, tx);
    }

    private Did2MessagingArchiveReference FindNativeOperation(ReadOnlySpan<byte> operation, IReadOnlyList<byte[]> headers, SqliteTransaction tx)
    {
        var archived = ReadArchiveFact(Did2MessagingArchiveFamily.Operation, operation, tx);
        Did2MessagingArchiveReference? result = archived is null ? null : Did2MessagingArchiveReference.Decode(archived, false);
        for (var index = 0; index < headers.Count; index++)
        {
            var header = headers[index];
            if (header[5] is not (2 or 5 or 6) || !Fixed(header.AsSpan(268, 32), operation)) continue;
            if (result is not null) throw new CryptographicException("Selected operation repeats across archive and working custody.");
            result = CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), header, tx);
        }
        if (result is null || result.Kind != 2) throw new CryptographicException("Selected route control is absent or is not an original native event.");
        RequireNativeReference(result, tx); return result;
    }

    private Did2RouteHistoryStoredDecision? ReadSubjectDecision(byte subject, Did2MessagingArchiveReducer reducer,
        IReadOnlyList<byte[]> headers, SqliteTransaction tx)
    {
        if (subject is < 1 or > 2) throw new ArgumentOutOfRangeException(nameof(subject));
        var reference = reducer.Reference(subject == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnDecision : Did2MessagingArchiveReducer.ReferenceKind.PeerDecision);
        if (!reference.IsAbsent) RequireNativeReference(reference, tx);
        Did2RouteHistoryStoredDecision? previous = reference.IsAbsent ? null : ReadRouteHistoryDecision(reference, tx);
        try
        {
            if (previous is not null && previous.Body.Subject != subject) throw new CryptographicException("Archive subject decision has another direction.");
            for (var index = 0; index < headers.Count; index++)
            {
                var metadata = headers[index]; if (metadata[5] != 6) continue;
                var nextRef = CaptureDecisionReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), metadata, tx);
                var next = ReadRouteHistoryDecision(nextRef, tx);
                if (next.Body.Subject != subject) { next.Dispose(); continue; }
                try
                {
                    RequireDecisionTransition(previous, next.Body);
                    previous?.Dispose(); previous = next; next = null!;
                }
                finally { next?.Dispose(); }
            }
            var result = previous; previous = null; return result;
        }
        finally { previous?.Dispose(); }
    }

    private void RequireDecisionTransition(Did2RouteHistoryStoredDecision? previous, Did2RouteHistoryDecision next)
    {
        if (previous is null)
        {
            if (next.Action != Did2RouteHistoryDecision.ActionKind.Bootstrap || !next.PreviousDecision.IsAbsent)
                throw new CryptographicException("Missing adopted route progress does not permit reseeding.");
            return;
        }
        if (next.Action == Did2RouteHistoryDecision.ActionKind.Bootstrap || previous.Body.Subject != next.Subject ||
            !Fixed(previous.Reference.Exact.Span, next.PreviousDecision.Exact.Span) ||
            !Fixed(previous.Body.Consent.Exact.Span, next.Consent.Exact.Span))
            throw new CryptographicException("Route decision changes its exact adopted predecessor or consent.");
        var fault = previous.Body.FirstFault;
        if (fault.IsAbsent && previous.Body.Action == Did2RouteHistoryDecision.ActionKind.Conflict) fault = previous.Reference;
        if (!Fixed(fault.Exact.Span, next.FirstFault.Exact.Span)) throw new CryptographicException("Route decision changed its first sticky fault.");
        var cSame = Fixed(previous.Body.C.Exact.Span, next.C.Exact.Span); var pSame = Fixed(previous.Body.P.Exact.Span, next.P.Exact.Span);
        var lSame = Fixed(previous.Body.L.Exact.Span, next.L.Exact.Span);
        switch (next.Action)
        {
            case Did2RouteHistoryDecision.ActionKind.Evidence:
                if (!lSame || cSame && pSame || next.SelectedAtomIndex == 0 ||
                    !cSame && (!Fixed(next.C.Reference.Exact.Span, next.Selected.Exact.Span) || next.C.AtomIndex != next.SelectedAtomIndex) ||
                    !pSame && (!Fixed(next.P.Reference.Exact.Span, next.Selected.Exact.Span) || next.P.AtomIndex != next.SelectedAtomIndex))
                    throw new CryptographicException("Evidence decision is not one selected adjacent atom.");
                break;
            case Did2RouteHistoryDecision.ActionKind.Promotion:
                if (!cSame || !pSame || !fault.IsAbsent || !Fixed(next.L.Exact.Span, next.Selected.Exact.Span))
                    throw new CryptographicException("Current promotion changed history or bypassed a sticky fault.");
                break;
            case Did2RouteHistoryDecision.ActionKind.Conflict:
                if (!cSame || !pSame || !lSame) throw new CryptographicException("Conflict decision changed retained progress/current route.");
                break;
            default: throw new InvalidDataException("Route decision has another transition action.");
        }
    }

    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadRouteHistoryAuthoredSources(Did2MessagingFloor stable,
        byte subject, Did2RouteHistorySelection selection)
    {
        using var snapshot = CaptureRouteHistorySnapshotCore(stable, subject, selection, null, sourcesOnly: true);
        return CopyOutgoingSources(snapshot.Originals);
    }

    internal Did2RouteHistorySnapshot CaptureRouteHistorySnapshot(Did2MessagingFloor stable, byte subject,
        Did2RouteHistorySelection selection, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>? authored = null) =>
        CaptureRouteHistorySnapshotCore(stable, subject, selection, authored, sourcesOnly: false);

    internal Did2RouteHistorySnapshot CaptureRouteHistorySourceSnapshot(Did2MessagingFloor stable, byte subject,
        Did2RouteHistorySelection selection) => CaptureRouteHistorySnapshotCore(stable, subject, selection, null, sourcesOnly: true);

    internal void RequireRouteHistorySnapshot(Did2RouteHistorySnapshot expected,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>? authored = null)
    {
        RequireScope(expected.Scope);
        using var actual = CaptureRouteHistorySnapshot(expected.Before, expected.Subject, expected.Selection, authored);
        if (!Fixed(expected.Transcript, actual.Transcript) ||
            !Fixed(expected.InitialSessionInit.Span, actual.InitialSessionInit.Span) ||
            !Fixed(expected.InitialHello.Span, actual.InitialHello.Span))
            throw new CryptographicException("Selected route-history native source snapshot changed after qualification.");
    }

    private Did2RouteHistorySnapshot CaptureRouteHistorySnapshotCore(Did2MessagingFloor stable, byte subject,
        Did2RouteHistorySelection selection, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>? authored, bool sourcesOnly)
    {
        ArgumentNullException.ThrowIfNull(selection);
        if (subject is < 1 or > 2 || stable.Phase != 1 || stable.Status != 1) throw new InvalidDataException("Route history requires an active stable subject.");
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        var reducer = ReadArchiveReducer(tx); var root = archiveRoot ?? throw new InvalidDataException("Route history lost its independent archive root.");
        var originals = new Dictionary<string, Did2MessagingArchiveOriginal>(StringComparer.Ordinal);
        var decisions = new Dictionary<string, Did2RouteHistoryStoredDecision>(StringComparer.Ordinal);
        var facts = new List<Did2RouteHistoryFact>(); var initial = ReadArchiveInitialSource(tx); byte[] init = [];
        try
        {
            using (var query = Command("SELECT session_init,typeof(session_init),length(session_init) FROM initial_events WHERE singleton=1;", tx))
            using (var row = query.ExecuteReader())
            {
                if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) is < 1 or > 32768) throw new CryptographicException("Actual relationship initiation is absent.");
                init = row.GetFieldValue<byte[]>(0); if (row.Read()) throw new CryptographicException("Actual relationship initiation is duplicated.");
            }
            var helloRef = Did2MessagingArchiveReference.Initial(SHA256.HashData(initial.Metadata));
            var head = ReadSubjectDecision(subject, reducer, headers, tx);
            using var otherHead = ReadSubjectDecision(subject == 1 ? (byte)2 : (byte)1, reducer, headers, tx);
            if (head is not null) decisions.Add(Id(head.Reference), head);
            var consent = head?.Body.Consent ?? reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.Consent);
            var l = head?.Body.L ?? reducer.Reference(subject == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead);
            var fault = head?.Body.FirstFault ?? reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.FirstFault);
            if (head?.Body.Action == Did2RouteHistoryDecision.ActionKind.Conflict && fault.IsAbsent) fault = head.Reference;

            // Bootstrap alone needs the old outgoing control suffix to derive
            // original L/consent. Adopted kind6 state does not walk those pages.
            if (head is null)
            {
                foreach (var kind in new[] { Did2MessagingArchiveReducer.ReferenceKind.OwnHead, Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious, Did2MessagingArchiveReducer.ReferenceKind.Consent })
                    AddOriginal(reducer.Reference(kind));
                foreach (var (metadata, index) in headers.Select((value, index) => (value, index)))
                {
                    if (metadata[5] is 2 or 5) AddOriginal(CaptureNativeReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), metadata, tx));
                    else if (metadata[5] == 6)
                    {
                        _ = AddDecision(CaptureDecisionReference(checked(WorkingBasis.Ordinal + (ulong)index + 1), metadata, tx));
                    }
                }
                if (!sourcesOnly)
                {
                    var before = ReplayRouteWorkingReducer(stable, reducer, headers, authored ?? new Dictionary<ulong, ReadOnlyMemory<byte>>(), initial, tx);
                    consent = before.Reference(Did2MessagingArchiveReducer.ReferenceKind.Consent);
                    l = before.Reference(subject == 1 ? Did2MessagingArchiveReducer.ReferenceKind.OwnHead : Did2MessagingArchiveReducer.ReferenceKind.PeerHead);
                    fault = before.Reference(Did2MessagingArchiveReducer.ReferenceKind.FirstFault);
                }
            }
            AddOriginal(consent); AddOriginal(l); AddFault(fault);
            var anchor = (subject == 1) == scope.IsInitiator ? helloRef : consent;
            if (anchor.IsAbsent && sourcesOnly) anchor = helloRef; // Source preselection is not adopted-state authority.
            if (anchor.IsAbsent || consent.IsAbsent && !sourcesOnly) throw new CryptographicException("Route history lacks its actual original relationship consent.");
            var anchorRow = AddOriginal(anchor)!;
            var selectedRef = selection.IsInitial ? anchor : selection.IsCurrent ? (l.IsAbsent ? anchor : l) : FindNativeOperation(selection.Operation.Span, headers, tx);
            var selected = AddOriginal(selectedRef)!;
            if (!selection.IsCurrent && !selection.IsCustody && head is not null)
            {
                AddOriginal(head.Body.C.Reference); AddOriginal(head.Body.P.Reference);
            }
            var selectors = selection.Facts;
            if (selection.IsCurrentPeerEndpoint && subject == 2 && head is not null && l.Kind == 2 && l.Direction == 2)
            {
                // L remains the latest decision's independently adopted head,
                // even when newer evidence has advanced C/P beyond that head.
                var native = AddOriginal(l)!;
                var message = ApplicationCoreCodec.DecodeDmc2(native.Plaintext);
                Did2RouteProcessingMetadata.RequireReceivedEvent(native.Metadata.AsSpan(608, 64), message);
                if (message.ParsedPayload is ContactRouteHistoryDmc2Payload page)
                {
                    if (page.Mode is not (DeepIdV2ContactRouteHistoryMode.Announcement or DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement))
                        throw new CryptographicException("Adopted current peer route lost its original announcement.");
                    selectors = [
                        new(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(subject, 1, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span))),
                        new(Did2MessagingArchiveFamily.RouteHistory, Did2MessagingArchiveRouteFacts.HistorySelector(subject, 2, BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span[40..])))];
                }
            }
            foreach (var selector in selectors)
            {
                if ((selection.IsCurrent || selection.IsPositionConflict) && (selector.Family != Did2MessagingArchiveFamily.RouteHistory || selector.Selector.Span[0] != subject))
                    throw new InvalidDataException("Current route read has a foreign completed-history purpose.");
                if (selection.IsCurrent && !fault.IsAbsent && selectors.Count != 0)
                    throw new CryptographicException("A sticky-faulted current route cannot request historical qualification.");
                var value = ReadRouteFactAtStable(selector, stable, reducer, headers, authored, initial, tx, sourcesOnly, selection.IsCurrent || selection.IsPositionConflict, selection.MaximumAuthoredOriginals, originals, selection.IsConflict, consent);
                facts.Add(Did2RouteHistoryFact.Capture(selector, value));
                if (value is null) continue;
                if (selector.Family == Did2MessagingArchiveFamily.RouteHistory)
                {
                    var verified = Did2MessagingArchiveReference.Decode(value.AsSpan(0, 88));
                    if (!verified.IsAbsent)
                    {
                        var decision = AddDecision(verified); var source = selector.Selector.Span[1] == 1 ? decision.Body.C : decision.Body.P;
                        AddOriginal(source.Reference);
                        if ((selection.IsConflict || selector.Selector.Span[1] == 2) && !decision.Body.PreviousDecision.IsAbsent)
                        {
                            var prior = AddDecision(decision.Body.PreviousDecision); AddOriginal(prior.Body.C.Reference);
                            if (selection.IsConflict) AddOriginal(prior.Body.P.Reference);
                        }
                    }
                    if (!selection.IsCurrent && !selection.IsPositionConflict) AddOriginal(Did2RouteHistorySource.Decode(value.AsSpan(120, 96)).Reference);
                }
                else
                {
                    AddOriginal(Did2MessagingArchiveReference.Decode(value.AsSpan(0, 88), false));
                    if (selector.Selector.Span[0] == 6) AddOriginal(Did2MessagingArchiveReference.Decode(value.AsSpan(120, 88)));
                }
            }
            Did2MessagingArchiveReference? positionConflict = null; byte[]? positionFact = null;
            if (selection.IsPositionConflict)
            {
                if (subject != 2) throw new InvalidDataException("Native authored-position conflict requires an incoming subject.");
                (positionConflict, positionFact) = ReadRoutePositionConflict(selected, headers, tx);
                if (positionConflict is not null) AddOriginal(positionConflict);
            }
            if (!sourcesOnly)
                foreach (var original in originals.Values)
                    if (original.Reference.Kind == 2 && original.Reference.Direction == 1) _ = QualifiedRouteOriginal(original, authored);
            using var transcript = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            transcript.AppendData("Deep/STORE-V2/route-history-source"u8); transcript.AppendData([0, subject]);
            transcript.AppendData(stable.Exact.Span); transcript.AppendData(root.Exact.Span); transcript.AppendData(reducer.Exact.Span);
            foreach (var original in originals.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value))
            { transcript.AppendData(original.Reference.Exact.Span); transcript.AppendData(SHA256.HashData(original.Metadata)); transcript.AppendData(SHA256.HashData(original.Envelope)); transcript.AppendData(SHA256.HashData(original.Plaintext)); }
            foreach (var decision in decisions.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value))
            { transcript.AppendData(decision.Reference.Exact.Span); transcript.AppendData(decision.Metadata.Span); transcript.AppendData(decision.Body.Exact.Span); }
            foreach (var fact in facts)
            { transcript.AppendData([(byte)fact.Selector.Family]); transcript.AppendData(fact.Selector.Selector.Span); transcript.AppendData([fact.Value is null ? (byte)0 : (byte)1]); if (fact.Value is { } exact) transcript.AppendData(exact.Span); }
            transcript.AppendData([positionConflict is null ? (byte)0 : (byte)1]);
            if (positionConflict is not null) transcript.AppendData(positionConflict.Exact.Span);
            if (positionFact is not null) transcript.AppendData(positionFact);
            var result = new Did2RouteHistorySnapshot(scope, stable, subject, root, reducer, selection, head, selected, anchorRow,
                originals.Values.ToArray(), decisions.Values.ToArray(), facts, l, consent, fault, init, initial.Hello, transcript.GetHashAndReset(), positionConflict, positionFact);
            init = []; initial.Hello = []; originals.Clear(); decisions.Clear(); return result;

            Did2MessagingArchiveOriginal? AddOriginal(Did2MessagingArchiveReference reference)
            {
                if (reference.IsAbsent) return null;
                if (reference.Kind == 3) { _ = AddDecision(reference); return null; }
                var id = Id(reference); if (originals.TryGetValue(id, out var found)) return found;
                RequireNativeReference(reference, tx); var row = ReadArchiveOriginal(reference, tx); originals.Add(id, row);
                if (originals.Values.Count(value => value.Reference.Kind == 2 && value.Reference.Direction == 1) > selection.MaximumAuthoredOriginals)
                    throw new InvalidDataException("Selected route-history authored closure exceeds the existing bounded inventory.");
                return row;
            }
            Did2RouteHistoryStoredDecision AddDecision(Did2MessagingArchiveReference reference)
            {
                var id = Id(reference); if (decisions.TryGetValue(id, out var found)) return found;
                RequireNativeReference(reference, tx); var row = ReadRouteHistoryDecision(reference, tx); decisions.Add(id, row); return row;
            }
            void AddFault(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 3)
                { var first = AddDecision(reference); AddOriginal(first.Body.Selected); AddOriginal(first.Body.Conflicting.Reference); }
                else AddOriginal(reference);
            }
        }
        catch { foreach (var row in originals.Values) row.Dispose(); foreach (var row in decisions.Values) row.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello); CryptographicOperations.ZeroMemory(init); }
    }

    private static string Id(Did2MessagingArchiveReference reference) => Convert.ToHexString(reference.Exact.Span);
    private static ReadOnlyMemory<byte> QualifiedRouteOriginal(Did2MessagingArchiveOriginal native,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>? authored)
    {
        if (native.Reference.Kind == 1 || native.Reference.Direction == 2) return native.Plaintext;
        if (native.Reference.Kind != 2 || native.Reference.Direction != 1 || authored is null || !authored.TryGetValue(native.Reference.Ordinal, out var exact) ||
            !Fixed(SHA256.HashData(exact.Span), native.Metadata.AsSpan(300, 32))) throw new CryptographicException("Selected route source lacks its independent authored original.");
        return exact;
    }
    private static IReadOnlyList<Did2MessagingArchiveOriginal> CopyOutgoingSources(IEnumerable<Did2MessagingArchiveOriginal> originals) =>
        originals.Where(row => row.Reference.Kind == 2 && row.Reference.Direction == 1)
            .Select(row => new Did2MessagingArchiveOriginal(row.Reference, row.Metadata.ToArray(), row.Envelope.ToArray(), row.Plaintext.ToArray())).ToArray();
}
