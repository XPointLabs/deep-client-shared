using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal sealed record ArchivePrefixEffects(Did2MessagingArchiveRoot Successor,
        ReadOnlyMemory<byte> Before, ReadOnlyMemory<byte> After, IReadOnlyList<Did2CompactionPlan.Row> Rows,
        IReadOnlyList<Did2MessagingArchivePatricia.Node> TreeNodes, Did2MessagingArchiveReducer Reducer,
        IReadOnlyList<Did2MessagingArchivePatricia.Node> ProofNodes);

    // Detached, verified originals for the independent authored application join.
    // Own reducer references are bounded metadata, never a lifetime source scan.
    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadArchivePrefixAuthoredSources(
        Did2MessagingFloor stable, int prefixRows, Did2MessagingArchiveRoot? successor = null)
    {
        if (archiveEnrollment || archiveRoot is null || prefixRows is < 1 or > 32)
            throw new InvalidDataException("Archive prefix source selection requires its indexed bounded profile.");
        RequireCipherPolicy(); ValidateSchema(); using var tx = connection.BeginTransaction(deferred: true);
        var mirror = ReadDeltaMirror(tx);
        if (!Fixed(mirror.Exact.Span, archiveRoot.Exact.Span) &&
            (successor is null || !Fixed(mirror.Exact.Span, successor.Exact.Span)))
            throw new CryptographicException("Archive prefix source selection has another SQL mirror.");
        var source = ForOrdinaryRuntime(connection, scope, historyRoot, mirror);
        source.RequireSame(stable, source.VerifyActiveTip(tx, null, out var headers));
        var selected = new Dictionary<ulong, Did2MessagingArchiveOriginal>();
        try
        {
            if (successor is not null && Fixed(mirror.Exact.Span, successor.Exact.Span))
            {
                if (successor.Basis.Ordinal < (ulong)prefixRows) throw new InvalidDataException("Archive prefix selected ordinal range underflows.");
                var number = new byte[8];
                for (var ordinal = successor.Basis.Ordinal - (ulong)prefixRows + 1; ordinal <= successor.Basis.Ordinal; ordinal++)
                {
                    if (ordinal <= 2) continue;
                    BinaryPrimitives.WriteUInt64BigEndian(number, ordinal);
                    var fact = source.ReadArchiveFact(Did2MessagingArchiveFamily.Ordinal, number, tx) ??
                        throw new CryptographicException("Archive prefix source selection omitted an original.");
                    Add(Did2MessagingArchiveReference.Decode(fact, false));
                }
            }
            else
            {
                if (prefixRows > headers.Count) throw new InvalidDataException("Archive prefix exceeds its source suffix.");
                for (var index = 0; index < prefixRows; index++)
                {
                    var metadata = headers[index]; if (metadata[5] is not (2 or 5)) continue;
                    using var tuple = new SelectedTuple(checked(mirror.Basis.Ordinal + (ulong)index + 1), metadata[6], metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                    Add(source.CaptureTupleReference(tuple, tx));
                }
            }
            var reducer = source.ReadArchiveReducer(tx);
            foreach (var kind in new[] { Did2MessagingArchiveReducer.ReferenceKind.OwnHead,
                Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious, Did2MessagingArchiveReducer.ReferenceKind.Consent })
                Add(reducer.Reference(kind));
            return selected.OrderBy(pair => pair.Key).Select(pair => pair.Value).ToArray();
        }
        catch { foreach (var original in selected.Values) original.Dispose(); throw; }
        void Add(Did2MessagingArchiveReference reference)
        {
            if (reference.Kind != 2 || reference.Direction != 1 || selected.ContainsKey(reference.Ordinal)) return;
            selected.Add(reference.Ordinal, source.ReadArchiveOriginal(reference, tx));
        }
    }

    internal ArchivePrefixEffects CaptureArchivePrefixEffects(Did2MessagingFloor stable, int prefixRows,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> qualifiedAuthored)
    {
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        return CaptureArchivePrefixEffects(stable, prefixRows, qualifiedAuthored, tx);
    }

    private ArchivePrefixEffects CaptureArchivePrefixEffects(Did2MessagingFloor stable, int prefixRows,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored, SqliteTransaction tx)
    {
        ArgumentNullException.ThrowIfNull(authored);
        if (archiveEnrollment || archiveRoot is null || stable.Phase != 1 || stable.Status != 1 ||
            prefixRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new InvalidDataException("Archive prefix needs an indexed stable bounded selection.");
        var beforeRoot = archiveRoot; beforeRoot.RequireSource(historyRoot);
        RequireSame(stable, VerifyActiveTip(tx, null, out var headers));
        if (prefixRows > headers.Count) throw new InvalidDataException("Archive prefix exceeds its exact working suffix.");
        var target = beforeRoot.Basis;
        var rows = new List<Did2CompactionPlan.Row>(prefixRows);
        for (var index = 0; index < prefixRows; index++)
        {
            target = Did2MessagingFloor.FromJournalMetadata(scope, target, headers[index]);
            rows.Add(new(Did2CompactionPlan.Disposition.JournalPrefix, PrefixRowSelector(scope, target.Ordinal), SHA256.HashData(headers[index])));
        }
        if (target.Status != 1 || target.Ordinal < 2) throw new InvalidDataException("Only an active stable prefix can advance the archive basis.");
        var initial = ReadDeltaInitial(tx); var selected = new List<Did2MessagingArchiveOriginal>();
        var borrowed = new List<Did2MessagingArchiveOriginal>();
        try
        {
            var builder = new Did2MessagingArchiveBuilder(scope, beforeRoot.PatriciaHash, digest => ReadArchiveNode(digest, tx));
            var replay = new Did2MessagingArchiveSemanticReplay(scope, target, ReadArchiveReducer(tx), builder,
                initial.Metadata, initial.Hello, Resolve);
            for (var index = 0; index < prefixRows; index++)
            {
                var metadata = headers[index]; if (metadata[5] is not (2 or 5)) continue;
                var ordinal = checked(beforeRoot.Basis.Ordinal + (ulong)index + 1);
                using var tuple = new SelectedTuple(ordinal, metadata[6], metadata.AsSpan(268, 32).ToArray(), metadata.ToArray());
                var native = ReadArchiveOriginal(CaptureTupleReference(tuple, tx), tx); selected.Add(native);
                replay.Observe(native, QualifiedDeltaAuthored(native, authored));
            }
            var tree = builder.Complete(); var reducer = replay.Complete();
            var successor = Did2MessagingArchiveRoot.Create(scope, checked(beforeRoot.Revision + 1), historyRoot, target,
                checked(beforeRoot.ArchiveCount + (ulong)selected.Count), tree.PatriciaHash.Span, reducer.Digest.Span);
            reducer.RequireRoot(successor);
            var selectors = DeltaSelectors(selected, authored, beforeRoot.Basis.Ordinal == 0, initial.Hello);
            var beforeProof = DeltaProofNodes(beforeRoot, selectors, tx);
            var overlay = tree.Nodes.ToDictionary(node => Convert.ToHexString(node.Digest.Span), node => node.Exact, StringComparer.Ordinal);
            var afterProof = DeltaProofNodes(successor, selectors, tx, overlay);
            foreach (var node in tree.Nodes)
                if (!afterProof.TryGetValue(Convert.ToHexString(node.Digest.Span), out var covered) || !Fixed(covered.Exact.Span, node.Exact.Span))
                    throw new CryptographicException("Archive insertion is not covered by a final selected proof path.");
            var beforeHash = SHA256.HashData(beforeRoot.Exact.Span);
            var before = ArchiveDeltaReceipt(1, beforeHash, successor, headers.Count, 0, selected, beforeProof, reducer, beforeRoot, tx);
            var after = ArchiveDeltaReceipt(2, beforeHash, successor, headers.Count - prefixRows, target.Ordinal, selected, afterProof, reducer, successor, tx);
            rows.Sort((left, right) => left.Selector.Span.SequenceCompareTo(right.Selector.Span));
            foreach (var pair in afterProof)
            {
                if (beforeProof.TryGetValue(pair.Key, out var prior) && !Fixed(prior.Exact.Span, pair.Value.Exact.Span))
                    throw new CryptographicException("Archive proof union has an immutable hash collision.");
                beforeProof[pair.Key] = pair.Value;
            }
            return new(successor, before, after, rows.AsReadOnly(), tree.Nodes, reducer,
                beforeProof.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value).ToArray());

            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 1) return initial.Hello;
                var native = ReadArchiveOriginal(reference, tx); borrowed.Add(native);
                return reference.Direction == 2 ? native.Plaintext : QualifiedDeltaAuthored(native, authored);
            }
        }
        finally
        {
            foreach (var native in selected) native.Dispose(); foreach (var native in borrowed) native.Dispose();
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
        }
    }

    // Only the exact stored-plan opener selects this function. The SQL mirror
    // may be the before root or the staged successor while protected adoption
    // lags; no generic ordinary mirror failure enters this recovery path.
    internal byte[] ReadArchivePrefixProjection(Did2MessagingFloor stable, Did2CompactionPlan plan,
        Did2MessagingArchiveRoot successor, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> qualifiedAuthored)
    {
        RequireCipherPolicy(); ValidateSchema(); using var tx = connection.BeginTransaction(deferred: true);
        return ReadArchivePrefixProjection(stable, plan, successor, qualifiedAuthored, tx);
    }

    private byte[] ReadArchivePrefixProjection(Did2MessagingFloor stable, Did2CompactionPlan plan,
        Did2MessagingArchiveRoot successor, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored, SqliteTransaction tx)
    {
        var changed = RequireArchivePrefixPlan(plan, successor);
        var mirror = ReadDeltaMirror(tx); var mirrorHash = SHA256.HashData(mirror.Exact.Span);
        if (Fixed(mirrorHash, changed.Before.Span))
        {
            if (archiveRoot is null || !Fixed(archiveRoot.Exact.Span, mirror.Exact.Span))
                throw new CryptographicException("Stored prefix before mirror lost its actual protected predecessor.");
            var effects = CaptureArchivePrefixEffects(stable, plan.RowCount, authored, tx);
            RequireDeltaEffects(plan, successor, effects); return effects.Before.ToArray();
        }
        if (!Fixed(mirror.Exact.Span, successor.Exact.Span)) throw new CryptographicException("Stored prefix has a mixed or foreign SQL mirror.");
        var after = ForOrdinaryRuntime(connection, scope, historyRoot, successor);
        after.RequireSame(stable, after.VerifyActiveTip(tx, null, out var headers));
        if (successor.Basis.Ordinal < (ulong)plan.RowCount) throw new InvalidDataException("Stored prefix underflows its selected ordinal range.");
        var oldBasis = successor.Basis.Ordinal - (ulong)plan.RowCount;
        var selected = new List<Did2MessagingArchiveOriginal>(); var initial = after.ReadDeltaInitial(tx);
        try
        {
            var expectedRows = Enumerable.Range(0, plan.RowCount).Select(plan.ReadRow).ToDictionary(row => Convert.ToHexString(row.Selector.Span), StringComparer.Ordinal);
            var ordinalSelector = new byte[8];
            for (var ordinal = checked(oldBasis + 1); ordinal <= successor.Basis.Ordinal; ordinal++)
            {
                var rowSelector = PrefixRowSelector(scope, ordinal);
                if (!expectedRows.Remove(Convert.ToHexString(rowSelector), out var row) || row.Action != Did2CompactionPlan.Disposition.JournalPrefix)
                    throw new CryptographicException("Stored prefix rows do not match the exact selected ordinal range.");
                if (ordinal == 1)
                {
                    if (!Fixed(row.Commitment.Span, SHA256.HashData(initial.Metadata))) throw new CryptographicException("Stored prefix changed its initial import.");
                    continue;
                }
                if (ordinal == 2) continue; // Activation has no events row; its exact captured commitment remains in the protected plan.
                BinaryPrimitives.WriteUInt64BigEndian(ordinalSelector, ordinal);
                var fact = after.ReadArchiveFact(Did2MessagingArchiveFamily.Ordinal, ordinalSelector, tx) ??
                    throw new CryptographicException("Stored prefix successor omitted a selected ordinal.");
                var reference = Did2MessagingArchiveReference.Decode(fact, false); reference.RequireAtBasis(successor.Basis.Ordinal);
                var native = after.ReadArchiveOriginal(reference, tx); selected.Add(native);
                if (!Fixed(row.Commitment.Span, SHA256.HashData(native.Metadata))) throw new CryptographicException("Stored prefix changed a selected original.");
                _ = QualifiedDeltaAuthored(native, authored);
            }
            if (expectedRows.Count != 0) throw new CryptographicException("Stored prefix contains extra selected row selectors.");
            var selectors = after.DeltaSelectors(selected, authored, oldBasis == 0, initial.Hello);
            var proof = after.DeltaProofNodes(successor, selectors, tx);
            var reducer = after.ReadArchiveReducer(tx);
            var digest = after.ArchiveDeltaReceipt(2, changed.Before.Span, successor, headers.Count, 0, selected, proof, reducer, mirror, tx);
            if (!Fixed(digest, plan.SqlAfter)) throw new CryptographicException("Stored prefix is not its exact bounded SQL successor.");
            return digest;
        }
        finally
        {
            foreach (var native in selected) native.Dispose();
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
        }
    }

    internal void ApplyArchivePrefix(Did2CompactionPlan plan, Did2MessagingFloor stable,
        Did2MessagingArchiveRoot successor, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> qualifiedAuthored)
    {
        if (plan.Phase != 1) throw new InvalidDataException("Only a prepared stored archive prefix can enter SQL.");
        _ = RequireArchivePrefixPlan(plan, successor); RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        var effects = CaptureArchivePrefixEffects(stable, plan.RowCount, qualifiedAuthored, tx);
        RequireDeltaEffects(plan, successor, effects);
        InsertArchiveNodes(effects.TreeNodes, tx); InsertArchiveReducer(effects.Reducer, tx);
        ReplaceArchiveMirror(successor, tx, archiveRoot);
        using (var delete = Command("DELETE FROM journal WHERE ordinal<=$through;", tx))
        {
            delete.Parameters.AddWithValue("$through", checked((long)successor.Basis.Ordinal));
            if (delete.ExecuteNonQuery() != plan.RowCount) throw new CryptographicException("Archive prefix removed another journal row set.");
        }
        if (!Fixed(ReadArchivePrefixProjection(stable, plan, successor, qualifiedAuthored, tx), plan.SqlAfter))
            throw new CryptographicException("Archive prefix successor differs before commit.");
        tx.Commit();
    }

    private Did2CompactionPlan.Root RequireArchivePrefixPlan(Did2CompactionPlan plan, Did2MessagingArchiveRoot successor)
    {
        successor.RequireSource(historyRoot);
        if (archiveEnrollment || plan.Phase is < 1 or > 3 || plan.Target != Did2CompactionPlan.SqlTarget.Messaging ||
            plan.RootCount != 6 || plan.SuccessorBytes != 608 || plan.PartCount != 1 || !Fixed(plan.SqlSelector, scope.Hash))
            throw new InvalidDataException("Archive delta requires its exact closed stored prefix profile.");
        var root = Enumerable.Range(0, plan.RootCount).Select(plan.ReadRoot).Single(root => root.Kind == Did2CompactionPlan.RootKind.MessagingArchive);
        if (root.Guard || !Fixed(root.After.Span, SHA256.HashData(successor.Exact.Span))) throw new CryptographicException("Stored archive successor binding differs.");
        return root;
    }

    private static void RequireDeltaEffects(Did2CompactionPlan plan, Did2MessagingArchiveRoot successor, ArchivePrefixEffects effects)
    {
        if (!Fixed(effects.Before.Span, plan.SqlBefore) || !Fixed(effects.After.Span, plan.SqlAfter) ||
            !Fixed(effects.Successor.Exact.Span, successor.Exact.Span) || effects.Rows.Count != plan.RowCount)
            throw new CryptographicException("Stored archive prefix differs from freshly derived exact effects.");
        for (var index = 0; index < effects.Rows.Count; index++)
        {
            var expected = plan.ReadRow(index); var actual = effects.Rows[index];
            if (expected.Action != actual.Action || !Fixed(expected.Selector.Span, actual.Selector.Span) || !Fixed(expected.Commitment.Span, actual.Commitment.Span))
                throw new CryptographicException("Stored archive prefix changed its selected row commitments.");
        }
    }

    private Did2MessagingArchiveRoot ReadDeltaMirror(SqliteTransaction tx)
    {
        using var query = Command("SELECT singleton,exact,typeof(singleton),typeof(exact),length(exact) FROM archive_state;", tx);
        using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(2) != "integer" || row.GetInt64(0) != 1 || row.GetString(3) != "blob" || row.GetInt64(4) != 608)
            throw new CryptographicException("Stored archive prefix lost its exact singleton mirror.");
        var mirror = Did2MessagingArchiveRoot.Decode(row.GetFieldValue<byte[]>(1), scope); mirror.RequireSource(historyRoot);
        if (row.Read()) throw new CryptographicException("Archive prefix mirror is not singular."); return mirror;
    }

    private (byte[] Metadata, byte[] Hello) ReadDeltaInitial(SqliteTransaction tx)
    {
        var metadata = ReadInitialMetadata(tx);
        using var query = Command("SELECT hello,typeof(hello),length(hello),metadata,typeof(metadata),length(metadata) FROM initial_events WHERE singleton=1;", tx);
        using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) is < 1 or > 32768 || row.GetString(4) != "blob" || row.GetInt64(5) != 672 ||
            !Fixed(row.GetFieldValue<byte[]>(3), metadata)) throw new CryptographicException("Archive prefix lost its authenticated initial singleton.");
        var hello = row.GetFieldValue<byte[]>(0);
        if (row.Read()) { CryptographicOperations.ZeroMemory(hello); throw new CryptographicException("Archive prefix initial singleton is not unique."); }
        return (metadata, hello);
    }

    private static ReadOnlyMemory<byte> QualifiedDeltaAuthored(Did2MessagingArchiveOriginal native,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored)
    {
        if (native.Reference.Direction != 1) return default;
        if (!authored.TryGetValue(native.Reference.Ordinal, out var exact) || exact.IsEmpty ||
            !Fixed(SHA256.HashData(exact.Span), native.Metadata.AsSpan(300, 32)))
            throw new CryptographicException("Archive prefix lacks the independently qualified authored original.");
        return exact;
    }

    private List<(Did2MessagingArchiveFamily Family, byte[] Selector)> DeltaSelectors(
        IReadOnlyList<Did2MessagingArchiveOriginal> selected, IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored,
        bool bootstrap, ReadOnlyMemory<byte> initialHello)
    {
        var result = new List<(Did2MessagingArchiveFamily, byte[])>();
        if (bootstrap && !scope.IsInitiator)
        {
            var hello = ApplicationCoreCodec.DecodeDmc2(initialHello.Span);
            if (hello.ParsedPayload is not ContactHelloDmc2Payload greeting) throw new CryptographicException("Archive prefix bootstrap is not an actual Hello.");
            Add(Did2MessagingArchiveFamily.QualifiedPeerRoute, SHA256.HashData(greeting.MailboxRoute.Route.ExactBytes.Span));
        }
        foreach (var native in selected)
        {
            var reference = native.Reference;
            Add(Did2MessagingArchiveFamily.Operation, reference.Operation.ToArray());
            var ordinal = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(ordinal, reference.Ordinal); Add(Did2MessagingArchiveFamily.Ordinal, ordinal);
            if (reference.Direction != 2) { _ = QualifiedDeltaAuthored(native, authored); continue; }
            var message = ApplicationCoreCodec.DecodeDmc2(native.Plaintext);
            try
            {
                if (!Fixed(message.NetworkId.Span, scope.Network) || !Fixed(message.ConversationId.Span, scope.Conversation) ||
                    !Fixed(message.SenderAccountId.Span, scope.RemoteAccount) || !Fixed(message.SenderDeviceId.Span, scope.RemoteDevice))
                    throw new CryptographicException("Archive prefix incoming selector has another semantic scope.");
                Add(Did2MessagingArchiveFamily.FirstIncomingEvent, native.Metadata.AsSpan(300, 32).ToArray());
                var position = new byte[40]; scope.Conversation.CopyTo(position); BinaryPrimitives.WriteUInt64BigEndian(position.AsSpan(32), message.SenderClientSequence);
                Add(Did2MessagingArchiveFamily.PeerAuthoredPosition, position);
                var attachment = new byte[64]; message.LogicalMessageId.Span.CopyTo(attachment); message.SenderDeviceId.Span.CopyTo(attachment.AsSpan(32));
                Add(Did2MessagingArchiveFamily.IncomingAttachment, attachment);
                var closure = message.ParsedPayload switch
                {
                    ContactHelloDmc2Payload hello => hello.MailboxRoute.Route.ExactBytes,
                    ContactAcceptDmc2Payload accept => accept.MailboxRoute.Route.ExactBytes,
                    ContactRouteUpdateDmc2Payload update => update.ExactRouteClosure,
                    _ => ReadOnlyMemory<byte>.Empty
                };
                if (!closure.IsEmpty) Add(Did2MessagingArchiveFamily.QualifiedPeerRoute, SHA256.HashData(closure.Span));
            }
            finally { if (message.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        if (result.Count > 6 * Did2CompactionPlan.MaximumRows) throw new InvalidDataException("Archive prefix exceeds its bounded typed selector set.");
        return result;
        void Add(Did2MessagingArchiveFamily family, byte[] selector)
        {
            if (!result.Any(item => item.Item1 == family && Fixed(item.Item2, selector))) result.Add((family, selector));
        }
    }

    private Dictionary<string, Did2MessagingArchivePatricia.Node> DeltaProofNodes(Did2MessagingArchiveRoot root,
        IReadOnlyList<(Did2MessagingArchiveFamily Family, byte[] Selector)> selectors, SqliteTransaction tx,
        IReadOnlyDictionary<string, ReadOnlyMemory<byte>>? overlay = null)
    {
        var result = new Dictionary<string, Did2MessagingArchivePatricia.Node>(StringComparer.Ordinal);
        foreach (var (family, selector) in selectors)
        {
            var key = Did2MessagingArchivePatricia.Key(scope, family, selector); var expected = root.PatriciaHash.ToArray();
            var path = new List<ReadOnlyMemory<byte>>();
            while (!Fixed(expected, Did2MessagingArchiveEncoding.EmptyHash(scope)))
            {
                if (path.Count >= 257) throw new CryptographicException("Archive delta proof exceeds its closed depth.");
                var id = Convert.ToHexString(expected);
                var exact = overlay is not null && overlay.TryGetValue(id, out var staged) ? staged :
                    ReadArchiveNode(expected, tx) ?? throw new CryptographicException("Archive delta proof is missing a named immutable node.");
                var node = Did2MessagingArchivePatricia.Decode(scope, exact.Span);
                if (!Fixed(node.Digest.Span, expected)) throw new CryptographicException("Archive delta proof node hash differs.");
                if (result.TryGetValue(id, out var prior) && !Fixed(prior.Exact.Span, exact.Span)) throw new CryptographicException("Archive delta proof has an immutable collision.");
                result[id] = node; path.Add(exact);
                if (node.IsLeaf || !ArchivePrefixMatches(key, node.KeyOrPrefix, node.Bit)) break;
                expected = ((key[node.Bit / 8] & (0x80 >> (node.Bit % 8))) != 0 ? node.RightHash : node.LeftHash).ToArray();
            }
            _ = Did2MessagingArchivePatricia.VerifyProof(scope, root, family, selector, path);
        }
        return result;
    }

    private byte[] ArchiveDeltaReceipt(byte side, ReadOnlySpan<byte> beforeRootHash, Did2MessagingArchiveRoot successor,
        int journalCount, ulong skipThrough, IReadOnlyList<Did2MessagingArchiveOriginal> selected,
        IReadOnlyDictionary<string, Did2MessagingArchivePatricia.Node> proofs, Did2MessagingArchiveReducer reducer,
        Did2MessagingArchiveRoot mirror, SqliteTransaction tx)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-delta"u8); hash.AppendData([0, side]); hash.AppendData(scope.Hash);
        hash.AppendData(ArchiveSchemaHash(6)); hash.AppendData(beforeRootHash); hash.AppendData(successor.Exact.Span);
        foreach (var name in new[] { "initial_events", "ratchet", "scope" }) AppendOriginalTable(hash, name, tx);
        if (journalCount is < 0 or > 64 || selected.Count > 32) throw new InvalidDataException("Archive delta SQL transcript exceeds its bounds.");
        hash.AppendData([checked((byte)journalCount)]);
        if (AppendOriginalTable(hash, "journal", tx, skipJournalThrough: skipThrough) != (ulong)journalCount)
            throw new CryptographicException("Archive delta journal count changed within its source snapshot.");
        hash.AppendData([checked((byte)selected.Count)]);
        foreach (var native in selected)
        {
            hash.AppendData(native.Reference.Exact.Span); AppendDeltaSelectedRow(hash, native, tx);
            AppendDeltaPayload(hash, native.Envelope, false);
            AppendDeltaPayload(hash, native.Plaintext, native.Reference.Direction != 2);
        }
        using var nodes = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        nodes.AppendData("Deep/STORE-V2/archive-delta-nodes"u8); nodes.AppendData([0]); nodes.AppendData(scope.Hash);
        Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number, checked((uint)proofs.Count)); nodes.AppendData(number);
        foreach (var node in proofs.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value))
        {
            nodes.AppendData(node.Digest.Span); BinaryPrimitives.WriteUInt16BigEndian(number, checked((ushort)node.Exact.Length));
            nodes.AppendData(number[..2]); nodes.AppendData(node.Exact.Span);
        }
        hash.AppendData(nodes.GetHashAndReset()); hash.AppendData(reducer.Digest.Span); hash.AppendData(mirror.Exact.Span);
        return hash.GetHashAndReset();
    }

    private void AppendDeltaSelectedRow(IncrementalHash hash, Did2MessagingArchiveOriginal native, SqliteTransaction tx)
    {
        (string Name, int Minimum, int Maximum)[] cells = [("rowid", 0, 0), .. OriginalCells("events")];
        using var query = Command("SELECT rowid,operation,ordinal,direction,envelope,plaintext,metadata," +
            string.Join(',', cells.Select(cell => $"typeof({cell.Name}),length({cell.Name})")) + " FROM events NOT INDEXED WHERE rowid=$rowid;", tx);
        query.Parameters.AddWithValue("$rowid", checked((long)native.Reference.RowId)); using var row = query.ExecuteReader();
        if (!row.Read()) throw new CryptographicException("Archive delta selected row is missing.");
        Span<byte> number = stackalloc byte[8]; hash.AppendData([1]); BinaryPrimitives.WriteUInt64BigEndian(number, (ulong)cells.Length); hash.AppendData(number);
        for (var index = 0; index < cells.Length; index++)
        {
            var type = row.GetString(cells.Length + index * 2);
            if (type == "null")
            {
                if (cells[index].Name != "plaintext" || native.Reference.Direction == 2) throw new InvalidDataException("Archive delta has a noncanonical selected NULL.");
                hash.AppendData([0]); continue;
            }
            if (cells[index].Minimum == 0)
            {
                if (type != "integer") throw new InvalidDataException("Archive delta integer has another SQL type.");
                hash.AppendData([1]); BinaryPrimitives.WriteInt64BigEndian(number, row.GetInt64(index)); hash.AppendData(number);
            }
            else
            {
                if (type != "blob" || row.GetInt64(cells.Length + index * 2 + 1) < cells[index].Minimum ||
                    row.GetInt64(cells.Length + index * 2 + 1) > cells[index].Maximum) throw new InvalidDataException("Archive delta blob has another SQL type/length.");
                var bytes = row.GetFieldValue<byte[]>(index);
                try { hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length)); hash.AppendData(number); hash.AppendData(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        if (row.Read()) throw new CryptographicException("Archive delta selected rowid is not unique.");
    }

    private static void AppendDeltaPayload(IncrementalHash hash, ReadOnlySpan<byte> bytes, bool absent)
    {
        if (absent) { if (!bytes.IsEmpty) throw new InvalidDataException("Archive delta NULL payload carries bytes."); hash.AppendData([0]); return; }
        hash.AppendData([2]); Span<byte> number = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length));
        hash.AppendData(number); hash.AppendData(SHA256.HashData(bytes));
    }
}
