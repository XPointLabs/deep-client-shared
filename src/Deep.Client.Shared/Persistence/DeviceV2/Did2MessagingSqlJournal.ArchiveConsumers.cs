using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class Did2MessagingOwnedEventBatch(IReadOnlyList<OwnedDid2MessagingPersistedEvent> rows) : IReadOnlyList<OwnedDid2MessagingPersistedEvent>, IDisposable
{
    public int Count => rows.Count;
    public OwnedDid2MessagingPersistedEvent this[int index] => rows[index];
    public IEnumerator<OwnedDid2MessagingPersistedEvent> GetEnumerator() => rows.GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    public void Dispose() { foreach (var row in rows) row.Dispose(); }
}

internal sealed partial class Did2MessagingSqlJournal
{
    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadRouteAuthoredSources(Did2MessagingFloor stable, bool own)
    {
        using var tx = connection.BeginTransaction(deferred: true); RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        var rows = new Dictionary<ulong, Did2MessagingArchiveOriginal>();
        try
        {
            var reducer = ReadArchiveReducer(tx);
            foreach (var kind in own ? new[] { Did2MessagingArchiveReducer.ReferenceKind.OwnHead, Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious, Did2MessagingArchiveReducer.ReferenceKind.Consent } :
                new[] { Did2MessagingArchiveReducer.ReferenceKind.Consent }) Add(reducer.Reference(kind));
            if (own)
                for (var i = 0; i < headers.Count; i++)
                {
                    var metadata = headers[i]; if (metadata[5] != 2 || metadata[6] != 1) continue;
                    using var tuple = new SelectedTuple(checked(WorkingBasis.Ordinal + (ulong)i + 1), 1, metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                    Add(CaptureTupleReference(tuple, tx));
                }
            return rows.Values.ToArray();
        }
        catch { foreach (var row in rows.Values) row.Dispose(); throw; }
        void Add(Did2MessagingArchiveReference reference)
        { if (reference.Kind == 2 && reference.Direction == 1 && !rows.ContainsKey(reference.Ordinal)) rows.Add(reference.Ordinal, ReadArchiveOriginal(reference, tx)); }
    }
    internal sealed record OutgoingOperationBatch(ulong Through, bool Complete, IReadOnlyList<byte[]> Operations);
    internal OutgoingOperationBatch ReadVerifiedOutgoingOperationBatch(Did2MessagingFloor stable, ulong cursor)
    {
        using var tx = connection.BeginTransaction(deferred: true); RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        if (cursor > stable.Ordinal) throw new InvalidDataException("Outgoing coverage cursor exceeds its actual floor.");
        var through = Math.Min(stable.Ordinal, checked(cursor + Math.Min(32UL, ulong.MaxValue - cursor)));
        var result = new List<byte[]>(); var number = new byte[8];
        try
        {
            for (var ordinal = Math.Max(3UL, cursor + 1); ordinal <= through; ordinal++)
            {
                Did2MessagingArchiveReference reference;
                if (ordinal <= WorkingBasis.Ordinal)
                {
                    BinaryPrimitives.WriteUInt64BigEndian(number, ordinal);
                    reference = Did2MessagingArchiveReference.Decode(ReadArchiveFact(Did2MessagingArchiveFamily.Ordinal, number, tx) ??
                        throw new CryptographicException("Outgoing native coverage omitted an archived ordinal."), false);
                    reference.RequireAtBasis(WorkingBasis.Ordinal);
                }
                else
                {
                    var metadata = headers[checked((int)(ordinal - WorkingBasis.Ordinal - 1))];
                    if (metadata[5] is not (2 or 5)) continue;
                    using var tuple = new SelectedTuple(ordinal, metadata[6], metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                    reference = CaptureTupleReference(tuple, tx);
                }
                if (reference.Kind == 3) { using var decision = ReadRouteHistoryDecision(reference, tx); continue; }
                using var native = ReadArchiveOriginal(reference, tx);
                if (reference.Direction == 1) result.Add(reference.Operation.ToArray());
            }
            return new(through, through == stable.Ordinal, result);
        }
        catch { foreach (var operation in result) CryptographicOperations.ZeroMemory(operation); throw; }
    }
    internal sealed class ArchiveRouteSources(Did2MessagingArchiveReducer reducer,
        IReadOnlyList<Did2MessagingArchiveOriginal> originals) : IDisposable
    {
        internal Did2MessagingArchiveReducer Reducer { get; } = reducer;
        internal IReadOnlyList<Did2MessagingArchiveOriginal> Originals { get; } = originals;
        public void Dispose() { foreach (var row in Originals) row.Dispose(); }
    }

    internal ArchiveRouteSources ReadArchiveRouteSources(Did2MessagingFloor stable, bool own)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out _));
        var reducer = ReadArchiveReducer(tx); var rows = new List<Did2MessagingArchiveOriginal>();
        try
        {
            foreach (var kind in own ? new[] { Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious, Did2MessagingArchiveReducer.ReferenceKind.OwnHead } :
                new[] { Did2MessagingArchiveReducer.ReferenceKind.PeerPrevious, Did2MessagingArchiveReducer.ReferenceKind.PeerHead, Did2MessagingArchiveReducer.ReferenceKind.FirstFault })
            {
                var reference = reducer.Reference(kind);
                if (reference.Kind == 2 && !rows.Any(row => row.Reference.Ordinal == reference.Ordinal)) rows.Add(ReadArchiveOriginal(reference, tx));
                else if (reference.Kind == 1)
                {
                    var initial = ReadArchiveInitialSource(tx);
                    try { if (!Fixed(SHA256.HashData(initial.Metadata), reference.MetadataHash)) throw new CryptographicException("Archive route head changes the initial singleton."); }
                    finally { CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello); }
                }
            }
            return new(reducer, rows);
        }
        catch { foreach (var row in rows) row.Dispose(); throw; }
    }

    internal bool ReadVerifiedPeerRouteFault(Did2MessagingFloor stable)
    {
        using (var tx = connection.BeginTransaction(deferred: true))
        {
            RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
            using var head = ReadSubjectDecision(2, ReadArchiveReducer(tx), headers, tx);
            if (head is not null)
            {
                var fault = head.Body.FirstFault;
                if (fault.IsAbsent && head.Body.Action == Did2RouteHistoryDecision.ActionKind.Conflict) fault = head.Reference;
                if (!fault.IsAbsent)
                {
                    RequireNativeReference(fault, tx); using var actual = ReadArchiveOriginal(fault, tx);
                    if (fault.Kind == 3 && Did2RouteHistoryDecision.Decode(actual.Plaintext, scope).Action != Did2RouteHistoryDecision.ActionKind.Conflict)
                        throw new CryptographicException("Sticky route-history fault lost its actual conflict decision.");
                    return true;
                }
            }
        }
        using var sources = ReadArchiveRouteSources(stable, own: false);
        if (!sources.Reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).IsAbsent)
        {
            var fault = sources.Originals.Single(row => row.Reference.Ordinal == sources.Reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.FirstFault).Ordinal);
            var message = ApplicationCoreCodec.DecodeDmc2(fault.Plaintext);
            Did2RouteProcessingMetadata.RequireReceivedEvent(fault.Metadata.AsSpan(608, 64), message);
            if (fault.Metadata[608] != 2) throw new CryptographicException("Archive sticky route fault changes its actual original outcome.");
            return true;
        }
        var suffix = ReadVerifiedWorkingEvents(stable, 2, routeOnly: true);
        try { return suffix.Any(row => row.RouteProcessing[0] == 2); }
        finally { foreach (var row in suffix) row.Dispose(); }
    }

    internal ulong ReadVerifiedMaximumPeerEpoch(Did2MessagingFloor stable)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        var reducer = ReadArchiveReducer(tx); var epoch = reducer.MaximumPeerEpoch;
        var reference = reducer.Reference(Did2MessagingArchiveReducer.ReferenceKind.MaximumPeerEpoch);
        if (!reference.IsAbsent)
        {
            reference.RequireAtBasis(WorkingBasis.Ordinal);
            using var native = ReadArchiveOriginal(reference, tx);
            if (Dpe2Codec.Decode(native.Envelope).RatchetHeader.SckaSendingEpoch != epoch)
                throw new CryptographicException("Archive peer epoch changes its selected authenticated source.");
        }
        for (var index = 0; index < headers.Count; index++)
        {
            var metadata = headers[index]; if (metadata[5] != 2 || metadata[6] != 2) continue;
            using var tuple = new SelectedTuple(checked(WorkingBasis.Ordinal + (ulong)index + 1), 2, metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
            using var native = ReadCapturedOrdinaryEvent(tuple, tx) ?? throw new CryptographicException("Working peer epoch source is absent.");
            epoch = Math.Max(epoch, Dpe2Codec.Decode(native.ExactEnvelope).RatchetHeader.SckaSendingEpoch);
        }
        return epoch;
    }

    internal Did2MessagingOwnedEventBatch ReadVerifiedWorkingEvents(Did2MessagingFloor stable,
        int direction, bool routeOnly = false)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        var rows = new List<OwnedDid2MessagingPersistedEvent>();
        try
        {
            for (var index = 0; index < headers.Count; index++)
            {
                var metadata = headers[index];
                if (metadata[5] != 2 || metadata[6] != direction || routeOnly && metadata[608] is not (1 or 2 or 3)) continue;
                using var tuple = new SelectedTuple(checked(WorkingBasis.Ordinal + (ulong)index + 1), direction,
                    metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                rows.Add(ReadCapturedOrdinaryEvent(tuple, tx) ?? throw new CryptographicException("Working suffix selected event is absent."));
            }
            return new(rows);
        }
        catch { foreach (var row in rows) row.Dispose(); throw; }
    }

    internal bool HasVerifiedAvailablePeerPosition(Did2MessagingFloor stable, ParsedDmc2 message)
    {
        var selector = new byte[40]; message.ConversationId.Span.CopyTo(selector);
        BinaryPrimitives.WriteUInt64BigEndian(selector.AsSpan(32), message.SenderClientSequence);
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        var selected = ReadArchiveFact(Did2MessagingArchiveFamily.PeerAuthoredPosition, selector, tx);
        if (selected is not null)
        {
            for (var index = 0; index < 2; index++)
            {
                var reference = Did2MessagingArchiveReference.Decode(selected.AsSpan(index == 0 ? 0 : 120, 88));
                if (reference.IsAbsent) continue;
                using var native = ReadArchiveOriginal(reference, tx);
                var parsed = ApplicationCoreCodec.DecodeDmc2(native.Plaintext);
                try
                {
                    if (parsed.SenderClientSequence != message.SenderClientSequence || !Fixed(parsed.ConversationId.Span, message.ConversationId.Span) ||
                        !Fixed(SHA256.HashData(native.Plaintext), selected.AsSpan(index == 0 ? 88 : 208, 32)))
                        throw new CryptographicException("Selected authored-position witness changes its actual original.");
                    if (!Fixed(native.Plaintext, message.CanonicalBytes.Span)) return false;
                }
                finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            }
        }
        for (var index = 0; index < headers.Count; index++)
        {
            var metadata = headers[index]; if (metadata[5] != 2 || metadata[6] != 2) continue;
            using var tuple = new SelectedTuple(checked(WorkingBasis.Ordinal + (ulong)index + 1), 2, metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
            using var native = ReadCapturedOrdinaryEvent(tuple, tx) ?? throw new CryptographicException("Working authored position lost its source.");
            using var exact = native.OwnAuthenticatedDmc2(); var prior = exact.Use(ApplicationCoreCodec.DecodeDmc2);
            try { if (prior.SenderClientSequence == message.SenderClientSequence && Fixed(prior.ConversationId.Span, message.ConversationId.Span) && !Fixed(prior.CanonicalBytes.Span, message.CanonicalBytes.Span)) return false; }
            finally { if (prior.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        return true;
    }

    internal OwnedDeepSecret ReadVerifiedAttachmentManifest(Did2MessagingFloor stable, ReadOnlySpan<byte> logical, ReadOnlySpan<byte> authorDevice)
    {
        if (logical.Length != 32 || authorDevice.Length != 32) throw new ArgumentException("Exact attachment selector required.");
        var selector = new byte[64]; logical.CopyTo(selector); authorDevice.CopyTo(selector.AsSpan(32));
        using var tx = connection.BeginTransaction(deferred: true);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        byte[]? manifest = null; var matches = 0;
        try
        {
            var archived = ReadArchiveFact(Did2MessagingArchiveFamily.IncomingAttachment, selector, tx);
            if (archived is not null)
                for (var index = 0; index < 2; index++)
                {
                    var reference = Did2MessagingArchiveReference.Decode(archived.AsSpan(index * 88, 88));
                    if (reference.IsAbsent) continue;
                    using var native = ReadArchiveOriginal(reference, tx); Observe(native.Plaintext);
                }
            for (var index = 0; index < headers.Count; index++)
            {
                var metadata = headers[index]; if (metadata[5] != 2 || metadata[6] != 2) continue;
                using var tuple = new SelectedTuple(checked(WorkingBasis.Ordinal + (ulong)index + 1), 2, metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                using var native = ReadCapturedOrdinaryEvent(tuple, tx) ?? throw new CryptographicException("Working attachment source is absent.");
                using var exact = native.OwnAuthenticatedDmc2(); exact.Use(Observe);
            }
            if (matches != 1 || manifest is null) throw new InvalidOperationException("Received attachment is absent from authenticated native history.");
            return new(manifest);
        }
        finally { if (manifest is not null) CryptographicOperations.ZeroMemory(manifest); }
        void Observe(ReadOnlySpan<byte> exact)
        {
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            try
            {
                if (!Fixed(parsed.LogicalMessageId.Span, selector.AsSpan(0, 32)) || !Fixed(parsed.SenderDeviceId.Span, selector.AsSpan(32))) return;
                matches++;
                if (matches != 1 || parsed.ParsedPayload is not AttachmentOfferDmc2Payload offer || !Fixed(parsed.SenderAccountId.Span, scope.RemoteAccount) || !Fixed(parsed.ConversationId.Span, scope.Conversation))
                    throw new CryptographicException("Received attachment selector has no unique authenticated peer offer.");
                manifest = offer.Manifest.CanonicalBytes.ToArray();
            }
            finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
    }
}
