using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal sealed record ArchiveAuditStep(Did2MessagingArchiveReducer Reducer, ulong Cursor, ulong Count,
        ulong[] Families, bool Complete);

    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadArchiveReplayAuthoredSources(Did2MessagingArchiveRoot root,
        Did2MessagingArchiveReducer before, ulong cursor)
    {
        RequireActualArchiveAuditRoot(root);
        return ReadArchiveReplayAuthoredSources(root.Basis.Ordinal, before, cursor);
    }

    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadEnrollmentSourceAuthoredSources(Did2MessagingArchiveReducer before, ulong cursor)
    {
        if (!archiveEnrollment) throw new InvalidOperationException("Only explicit enrollment audits unindexed authored sources.");
        return ReadArchiveReplayAuthoredSources(historyRoot.Basis.Ordinal, before, cursor);
    }

    private IReadOnlyList<Did2MessagingArchiveOriginal> ReadArchiveReplayAuthoredSources(ulong through, Did2MessagingArchiveReducer before, ulong cursor)
    {
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction(deferred: true);
        var rows = ReadArchiveOriginalBatch(cursor, through, tx);
        var result = new Dictionary<ulong, Did2MessagingArchiveOriginal>();
        try
        {
            foreach (var row in rows) if (row.Reference.Direction == 1) result.Add(row.Reference.Ordinal,
                new(row.Reference, row.Metadata.ToArray(), row.Envelope.ToArray(), row.Plaintext.ToArray()));
            foreach (var kind in new[] { Did2MessagingArchiveReducer.ReferenceKind.Consent,
                Did2MessagingArchiveReducer.ReferenceKind.OwnHead, Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious })
            {
                var reference = before.Reference(kind);
                if (reference.Kind == 2 && reference.Direction == 1 && !result.ContainsKey(reference.Ordinal))
                    result.Add(reference.Ordinal, ReadArchiveOriginal(reference, tx));
            }
            return result.Values.ToArray();
        }
        catch { foreach (var row in result.Values) row.Dispose(); throw; }
        finally { foreach (var row in rows) row.Dispose(); }
    }

    internal ArchiveAuditStep VerifyEnrollmentSourceReplayBatch(Did2MessagingArchiveReducer before, ulong cursor, ulong count,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored)
    {
        if (!archiveEnrollment) throw new InvalidOperationException("Only explicit enrollment audits the unindexed original source.");
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction(deferred: true);
        RequireAllCipherPages(tx); VerifyHistoryPrefix(tx); var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx);
        var rows = ReadArchiveOriginalBatch(cursor, historyRoot.Basis.Ordinal, tx); var borrowed = new List<Did2MessagingArchiveOriginal>();
        var initial = historyRoot.Basis.Ordinal == 0 ? (Metadata: Array.Empty<byte>(), Hello: Array.Empty<byte>()) : ReadArchiveInitialSource(tx);
        try
        {
            var replay = new Did2MessagingArchiveSemanticReplay(scope, historyRoot.Basis, before, static (_, _, _) => { }, ReadFirst,
                initial.Metadata, initial.Hello, Resolve);
            foreach (var row in rows)
            {
                var own = row.Reference.Direction == 1 && authored.TryGetValue(row.Reference.Ordinal, out var exact) ? exact : ReadOnlyMemory<byte>.Empty;
                replay.Observe(row, own); cursor = row.Reference.Ordinal; count = checked(count + 1);
            }
            if (count > historyRoot.HistoryCount || rows.Count < 32 && count != historyRoot.HistoryCount)
                throw new CryptographicException("Full unindexed semantic source audit changes its authenticated event count.");
            return new(replay.Complete(), cursor, count, new ulong[6], rows.Count < 32);

            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 1) return initial.Hello;
                var row = ReadArchiveOriginal(reference, tx); borrowed.Add(row);
                if (reference.Direction == 2) return row.Plaintext;
                if (reference.Direction != 1 || !authored.TryGetValue(reference.Ordinal, out var own) || !Fixed(SHA256.HashData(own.Span), row.Metadata.AsSpan(300, 32)))
                    throw new CryptographicException("Unindexed semantic source audit lost its independent authored original.");
                return own;
            }
            byte[]? ReadFirst(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
            {
                if (family != Did2MessagingArchiveFamily.FirstIncomingEvent) throw new InvalidDataException("Unindexed source replay requested another fact purpose.");
                using var query = Command("SELECT rowid,ordinal,operation,metadata FROM events NOT INDEXED WHERE direction=2 AND ordinal<=$basis AND substr(metadata,301,32)=$hash ORDER BY ordinal LIMIT 1;", tx);
                query.Parameters.AddWithValue("$basis", checked((long)historyRoot.Basis.Ordinal)); query.Parameters.AddWithValue("$hash", selector.ToArray());
                using var row = query.ExecuteReader();
                if (!row.Read()) return null;
                return Did2MessagingArchiveReference.Event(2, checked((ulong)row.GetInt64(1)), checked((ulong)row.GetInt64(0)), row.GetFieldValue<byte[]>(2), SHA256.HashData(row.GetFieldValue<byte[]>(3))).Exact.ToArray();
            }
        }
        finally
        {
            foreach (var row in rows) row.Dispose(); foreach (var row in borrowed) row.Dispose();
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
        }
    }

    private void RequireActualArchiveAuditRoot(Did2MessagingArchiveRoot root)
    {
        root.RequireSource(historyRoot);
        if (!archiveEnrollment && (archiveRoot is null || !Fixed(archiveRoot.Exact.Span, root.Exact.Span)))
            throw new CryptographicException("Full archive audit lost its actual independent root.");
    }

    // Independent constant-memory source replay. The immutable tree is used
    // only as a membership proof target, never as the semantic replay input.
    internal ArchiveAuditStep VerifyArchiveReplayBatch(Did2MessagingArchiveRoot root,
        Did2MessagingArchiveReducer before, ulong cursor, ulong count,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored)
    {
        RequireActualArchiveAuditRoot(root); RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction(deferred: true);
        var previousRoot = archiveRoot; archiveRoot = root;
        var rows = ReadArchiveOriginalBatch(cursor, root.Basis.Ordinal, tx);
        var borrowed = new List<Did2MessagingArchiveOriginal>();
        var initial = root.Basis.Ordinal == 0 ? (Metadata: Array.Empty<byte>(), Hello: Array.Empty<byte>()) : ReadArchiveInitialSource(tx);
        var families = new ulong[6];
        try
        {
            var replay = new Did2MessagingArchiveSemanticReplay(scope, root.Basis, before, Observe,
                (family, selector) => ReadArchiveFact(family, selector, tx), initial.Metadata, initial.Hello, Resolve);
            foreach (var row in rows)
            {
                ReadOnlyMemory<byte> own = default;
                if (row.Reference.Direction == 1 && (!authored.TryGetValue(row.Reference.Ordinal, out own) ||
                    !Fixed(SHA256.HashData(own.Span), row.Metadata.AsSpan(300, 32)))) throw new CryptographicException("Full archive replay lost its independent authored original.");
                replay.Observe(row, own); cursor = row.Reference.Ordinal; count = checked(count + 1);
            }
            if (count > root.ArchiveCount) throw new CryptographicException("Full archive source has extra original events.");
            return new(replay.Complete(), cursor, count, families, rows.Count < 32);

            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 1) return initial.Hello;
                var row = ReadArchiveOriginal(reference, tx); borrowed.Add(row);
                if (reference.Direction == 2) return row.Plaintext;
                if (reference.Direction != 1 || !authored.TryGetValue(reference.Ordinal, out var own) ||
                    !Fixed(SHA256.HashData(own.Span), row.Metadata.AsSpan(300, 32))) throw new CryptographicException("Full archive reducer lost its selected authored source.");
                return own;
            }
            void Observe(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector, ReadOnlySpan<byte> observation)
            {
                var exact = ReadArchiveFact(family, selector, tx) ?? throw new CryptographicException("Full archive omitted a qualified source fact.");
                var first = Did2MessagingArchiveReference.Decode(exact.AsSpan(0, 88), false);
                var source = Did2MessagingArchiveReference.Decode(observation[..88], false);
                if (first.Ordinal > source.Ordinal) throw new CryptographicException("Full archive did not select the earliest qualified source.");
                if (family is Did2MessagingArchiveFamily.Operation or Did2MessagingArchiveFamily.Ordinal)
                { if (!Fixed(exact, observation)) throw new CryptographicException("Full archive source membership differs."); }
                else if (first.Ordinal == source.Ordinal)
                {
                    var width = family switch { Did2MessagingArchiveFamily.PeerAuthoredPosition => 120, Did2MessagingArchiveFamily.IncomingAttachment => 88, _ => exact.Length };
                    if (!Fixed(exact.AsSpan(0, width), observation[..width])) throw new CryptographicException("Full archive first witness differs from the actual source.");
                }
                if (family is Did2MessagingArchiveFamily.PeerAuthoredPosition or Did2MessagingArchiveFamily.IncomingAttachment)
                {
                    var offset = family == Did2MessagingArchiveFamily.PeerAuthoredPosition ? 120 : 88;
                    var second = Did2MessagingArchiveReference.Decode(exact.AsSpan(offset, 88));
                    var differs = family == Did2MessagingArchiveFamily.IncomingAttachment ? source.Ordinal != first.Ordinal : !Fixed(exact.AsSpan(88, 32), observation.Slice(88, 32));
                    if (differs && (second.IsAbsent || second.Ordinal > source.Ordinal)) throw new CryptographicException("Full archive omitted its earliest sticky second witness.");
                }
                if (first.Ordinal == source.Ordinal) families[(int)family - 1] = checked(families[(int)family - 1] + 1);
            }
        }
        finally
        {
            archiveRoot = previousRoot;
            foreach (var row in rows) row.Dispose(); foreach (var row in borrowed) row.Dispose();
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
        }
    }

    internal ulong[] VerifyCompleteArchiveTree(Did2MessagingArchiveRoot root)
    {
        RequireActualArchiveAuditRoot(root);
        return VerifyArchiveTree(root.PatriciaHash, root.Basis.Ordinal, root.Basis.Ordinal);
    }

    internal void RequireStagedArchiveProgress(ProtectedDid2MessagingArchiveEnrollment progress)
    {
        if (!archiveEnrollment || !Fixed(progress.SourceHistory.Exact.Span, historyRoot.Exact.Span))
            throw new InvalidOperationException("Staging readback requires exact actual enrollment history.");
        var reducer = ReadEnrollmentReducer(progress);
        foreach (var kind in Enum.GetValues<Did2MessagingArchiveReducer.ReferenceKind>())
        {
            var reference = reducer.Reference(kind);
            if (reference.Kind == 2 && reference.Ordinal > progress.Cursor)
                throw new CryptographicException("A staging reducer names an event beyond protected progress.");
        }
        var counts = VerifyArchiveTree(progress.PatriciaHash, progress.TargetBasis.Ordinal, progress.Cursor);
        if (counts[0] != progress.Count || counts[2] != progress.Count)
            throw new CryptographicException("Staging tree membership differs from protected event progress.");
        using var query = Command("SELECT singleton,exact,typeof(exact),length(exact) FROM archive_state;");
        using var row = query.ExecuteReader();
        if (!row.Read())
        {
            if (progress.Phase == ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady) throw new CryptographicException("FinalReady archive mirror is absent.");
            return;
        }
        if (progress.Count != progress.SourceHistory.HistoryCount || row.GetInt64(0) != 1 || row.GetString(2) != "blob" || row.GetInt64(3) != 608)
            throw new CryptographicException("Incomplete staging has an unexpected archive mirror.");
        var candidate = Did2MessagingArchiveRoot.Create(scope, 1, progress.SourceHistory, progress.TargetBasis,
            progress.Count, progress.PatriciaHash, progress.ReducerHash);
        if (!Fixed(row.GetFieldValue<byte[]>(1), candidate.Exact.Span) || row.Read()) throw new CryptographicException("Staging mirror differs from its exact phase-owned candidate.");
    }

    internal void RequireCandidateArchiveMirror(Did2MessagingArchiveRoot root)
    {
        var before = archiveRoot; archiveRoot = root;
        try { RequireArchiveMirror(); }
        finally { archiveRoot = before; }
    }

    private ulong[] VerifyArchiveTree(ReadOnlySpan<byte> rootHash, ulong basisOrdinal, ulong lastEventOrdinal)
    {
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction(deferred: true); RequireAllCipherPages(tx);
        var counts = new ulong[6];
        var stack = new Stack<(byte[] Hash, byte[] Prefix, int Bits)>();
        if (!Fixed(rootHash, Did2MessagingArchiveEncoding.EmptyHash(scope))) stack.Push((rootHash.ToArray(), new byte[32], 0));
        while (stack.TryPop(out var frame))
        {
            if (stack.Count > 256) throw new CryptographicException("Archive canonical traversal exceeds its depth bound.");
            var raw = ReadArchiveNode(frame.Hash, tx) ?? throw new CryptographicException("Archive canonical tree lost a named child.");
            var node = Did2MessagingArchivePatricia.Decode(scope, raw.Span);
            if (!ArchivePrefixMatches(node.KeyOrPrefix, frame.Prefix, frame.Bits) || !node.IsLeaf && node.Bit < frame.Bits)
                throw new CryptographicException("Archive child changes its canonical prefix or split ordering.");
            if (!node.IsLeaf)
            {
                var left = node.KeyOrPrefix.ToArray(); var right = left.ToArray(); right[node.Bit / 8] |= (byte)(1 << (7 - node.Bit % 8));
                stack.Push((node.RightHash.ToArray(), right, node.Bit + 1)); stack.Push((node.LeftHash.ToArray(), left, node.Bit + 1));
                continue;
            }
            counts[(int)node.Family - 1] = checked(counts[(int)node.Family - 1] + 1);
            var first = Did2MessagingArchiveReference.Decode(node.Value[..88], false); first.RequireAtBasis(basisOrdinal);
            VerifyWitness(first, node, false);
            var offset = node.Family switch { Did2MessagingArchiveFamily.PeerAuthoredPosition => 120, Did2MessagingArchiveFamily.IncomingAttachment => 88, _ => 0 };
            if (offset != 0)
            {
                var second = Did2MessagingArchiveReference.Decode(node.Value.Slice(offset, 88));
                if (!second.IsAbsent) { second.RequireAtBasis(basisOrdinal); VerifyWitness(second, node, true); }
            }
        }
        return counts;

        void VerifyWitness(Did2MessagingArchiveReference reference, Did2MessagingArchivePatricia.Node leaf, bool second)
        {
            if (reference.Kind == 2 && reference.Ordinal > lastEventOrdinal)
                throw new CryptographicException("Archive staging leaf names an event beyond protected progress.");
            if (reference.Kind == 1)
            {
                var initial = ReadArchiveInitialSource(tx);
                try
                {
                    var hello = ApplicationCoreCodec.DecodeDmc2(initial.Hello);
                    if (scope.IsInitiator || leaf.Family != Did2MessagingArchiveFamily.QualifiedPeerRoute ||
                        !Fixed(reference.MetadataHash, SHA256.HashData(initial.Metadata)) || hello.ParsedPayload is not ContactHelloDmc2Payload greeting ||
                        !Fixed(leaf.Selector, SHA256.HashData(greeting.MailboxRoute.Route.ExactBytes.Span))) throw new CryptographicException("Archive initial qualified route has another actual source.");
                }
                finally { CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello); }
                return;
            }
            using var row = ReadArchiveOriginal(reference, tx);
            if (leaf.Family == Did2MessagingArchiveFamily.Operation && !Fixed(leaf.Selector, reference.Operation) ||
                leaf.Family == Did2MessagingArchiveFamily.Ordinal && BinaryPrimitives.ReadUInt64BigEndian(leaf.Selector) != reference.Ordinal ||
                leaf.Family == Did2MessagingArchiveFamily.FirstIncomingEvent && (reference.Direction != 2 || !Fixed(leaf.Selector, row.Metadata.AsSpan(300, 32))))
                throw new CryptographicException("Archive leaf differs from its actual typed source selector.");
            if (leaf.Family is Did2MessagingArchiveFamily.PeerAuthoredPosition or Did2MessagingArchiveFamily.IncomingAttachment or Did2MessagingArchiveFamily.QualifiedPeerRoute)
            {
                if (reference.Direction != 2) throw new CryptographicException("Archive peer witness has an outgoing source.");
                var message = ApplicationCoreCodec.DecodeDmc2(row.Plaintext);
                try
                {
                    if (leaf.Family == Did2MessagingArchiveFamily.PeerAuthoredPosition &&
                        (!Fixed(leaf.Selector[..32], message.ConversationId.Span) || BinaryPrimitives.ReadUInt64BigEndian(leaf.Selector[32..]) != message.SenderClientSequence ||
                        !Fixed(leaf.Value.Slice(second ? 208 : 88, 32), row.Metadata.AsSpan(300, 32))) ||
                        leaf.Family == Did2MessagingArchiveFamily.IncomingAttachment && (!Fixed(leaf.Selector[..32], message.LogicalMessageId.Span) || !Fixed(leaf.Selector[32..], message.SenderDeviceId.Span)))
                        throw new CryptographicException("Archive peer witness changes its selected exact original.");
                    if (leaf.Family == Did2MessagingArchiveFamily.QualifiedPeerRoute)
                    {
                        var closure = message.ParsedPayload switch { ContactAcceptDmc2Payload accepted => accepted.MailboxRoute.Route.ExactBytes,
                            ContactRouteUpdateDmc2Payload update => update.ExactRouteClosure, _ => throw new CryptographicException("Archive qualified route has an ineligible source kind.") };
                        if (!Fixed(leaf.Selector, SHA256.HashData(closure.Span))) throw new CryptographicException("Archive qualified route changes its exact closure.");
                    }
                }
                finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
            }
        }
    }

    internal void RequireFinalArchiveAudit(Did2MessagingArchiveRoot root, Did2MessagingArchiveReducer reducer,
        ulong count, IReadOnlyList<ulong> sourceFamilies, IReadOnlyList<ulong> treeFamilies)
    {
        RequireActualArchiveAuditRoot(root);
        if (count != root.ArchiveCount || sourceFamilies.Count != 6 || treeFamilies.Count != 6 ||
            sourceFamilies.Where((value, index) => value != treeFamilies[index]).Any() ||
            sourceFamilies[0] != count || sourceFamilies[2] != count || !Fixed(root.SummaryHash, reducer.Digest.Span))
            throw new CryptographicException("Archive source/tree/reducer coverage differs after independent full replay.");
        var previous = archiveRoot; archiveRoot = root;
        try
        {
            using var tx = connection.BeginTransaction(deferred: true);
            if (!Fixed(ReadArchiveReducer(tx).Exact.Span, reducer.Exact.Span)) throw new CryptographicException("Actual archive reducer differs from its full replay.");
            if (!archiveEnrollment) RequireArchiveMirror(tx);
            var headers = ReadJournal(out var tip, tx);
            if (headers.Count > 64) throw new CryptographicException("Final archive audit exceeds its complete bounded working suffix.");
            VerifyRows(headers, tip, tx);
            RequireSame(openedFloor ?? throw new InvalidOperationException("Final archive audit has no actual opened floor."), tip);
        }
        finally { archiveRoot = previous; }
    }

    internal void WriteEnrollmentArchiveMirror(Did2MessagingArchiveRoot root, Did2MessagingArchiveReducer reducer)
    {
        if (!archiveEnrollment || enrollmentProgress is null || enrollmentProgress.Phase is not (ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged or ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building or ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady))
            throw new InvalidOperationException("Only actual stored enrollment may write its final archive mirror.");
        if (enrollmentProgress.Count != enrollmentProgress.SourceHistory.HistoryCount || root.Revision != 1 ||
            root.ArchiveCount != enrollmentProgress.Count || !Fixed(root.Basis.Exact.Span, enrollmentProgress.TargetBasis.Exact.Span) ||
            !Fixed(root.PatriciaHash, enrollmentProgress.PatriciaHash) || !Fixed(root.SummaryHash, enrollmentProgress.ReducerHash))
            throw new CryptographicException("Enrollment mirror candidate differs from actual opened completed progress.");
        root.RequireSource(historyRoot); reducer.RequireRoot(root);
        using var tx = connection.BeginTransaction(); InsertArchiveReducer(reducer, tx); ReplaceArchiveMirror(root, tx, null); tx.Commit();
    }
}
