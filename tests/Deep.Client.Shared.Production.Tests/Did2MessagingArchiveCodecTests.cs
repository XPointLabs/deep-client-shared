using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Independent sorted-tree construction below uses no production key/node
// encoders. Structural fixtures do not mint native, route or retirement facts.
public sealed class Did2MessagingArchiveCodecTests
{
    [Fact]
    public void IndependentSortedTreeProvesEveryFamilyMembershipAndAuthenticatedAbsence()
    {
        var scope = Scope(); var entries = Entries(scope); var tree = Tree(scope, entries);
        foreach (var entry in entries)
        {
            var proof = Proof(tree, entry.Key);
            Assert.Equal(entry.Value, Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, proof));
            var encoded = Did2MessagingArchivePatricia.Leaf(scope, entry.Family, entry.Selector, entry.Value);
            Assert.Equal(entry.Exact, encoded.Exact.ToArray()); Assert.Equal(entry.Hash, encoded.Digest.ToArray());
        }
        for (var index = 50; index < 70; index++)
        {
            var selector = Hash(index); var key = Key(scope, Did2MessagingArchiveFamily.Operation, selector);
            Assert.Null(Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, Did2MessagingArchiveFamily.Operation, selector, Proof(tree, key)));
        }
        Assert.Null(Did2MessagingArchivePatricia.VerifyProof(scope, Digest("archive-empty", scope, []),
            Did2MessagingArchiveFamily.Operation, Hash(90), []));
    }

    [Fact]
    public void OmittedChangedForeignAndExtraProofNodesCannotBecomeAbsence()
    {
        var scope = Scope(); var entries = Entries(scope); var tree = Tree(scope, entries); var entry = entries[0];
        var proof = Proof(tree, entry.Key);
        Assert.True(proof.Count > 1);
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, proof.Skip(1).ToArray()));
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, proof.Take(proof.Count - 1).ToArray()));
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, [..proof, proof[^1]]));
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(Scope(2), tree.Hash, entry.Family, entry.Selector, proof));
        var changedSibling = proof[0].ToArray(); changedSibling[40] ^= 1;
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, [changedSibling, ..proof.Skip(1)]));
        var changedLeaf = proof[^1].ToArray(); changedLeaf[4] ^= 1;
        Reject(() => Did2MessagingArchivePatricia.Decode(scope, changedLeaf));
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, tree.Hash, entry.Family, entry.Selector, []));
    }

    [Fact]
    public void AuthenticatedChildAtWrongEdgeOrPrefixRejectsEvenWhenAllHashesMatch()
    {
        var scope = Scope(); var entries = Entries(scope); var target = entries[0];
        var bit = 0; var other = entries.First(entry => Bit(entry.Key, bit) != Bit(target.Key, bit));
        // Deliberately place the chosen query leaf under the wrong authenticated
        // branch edge, then authenticate that malformed parent as expected root.
        var wrong = Branch(scope, bit, new byte[32], Bit(target.Key, bit) ? target : other,
            Bit(target.Key, bit) ? other : target);
        var chosen = other;
        Reject(() => Did2MessagingArchivePatricia.VerifyProof(scope, wrong.Hash, target.Family, target.Selector,
            [wrong.Exact, chosen.Exact]));
        // A branch prefix can be individually canonical but incompatible with
        // its authenticated parent. RequireChild checks its hash AND placement.
        var descendant = Branch(scope, 1, new byte[32], target, other);
        var parent = Branch(scope, 0, new byte[32], entries[2], descendant);
        var decodedParent = Did2MessagingArchivePatricia.Decode(scope, parent.Exact);
        var decodedChild = Did2MessagingArchivePatricia.Decode(scope, descendant.Exact);
        Reject(() => Did2MessagingArchivePatricia.RequireChild(decodedParent, true, decodedChild));
        var noncanonical = descendant.Exact.ToArray(); noncanonical[39] = 1;
        Reject(() => Did2MessagingArchivePatricia.Decode(scope, noncanonical));
        var unknownBit = descendant.Exact.ToArray(); Put16(unknownBit, 4, 256);
        Reject(() => Did2MessagingArchivePatricia.Decode(scope, unknownBit));
    }

    [Fact]
    public void DistinctPeerWitnessAndDuplicateAttachmentRowSurviveExactFraming()
    {
        var scope = Scope(); var authored = Entries(scope).Single(entry => entry.Family == Did2MessagingArchiveFamily.PeerAuthoredPosition);
        var decoded = Did2MessagingArchivePatricia.Decode(scope, authored.Exact);
        Assert.Equal(authored.Value, decoded.Value.ToArray());
        Assert.NotEqual(authored.Value.AsSpan(88, 32).ToArray(), authored.Value.AsSpan(208, 32).ToArray());
        var sameHash = authored.Value.ToArray(); sameHash.AsSpan(88, 32).CopyTo(sameHash.AsSpan(208));
        Reject(() => Did2MessagingArchivePatricia.Leaf(scope, authored.Family, authored.Selector, sameHash));
        var hiddenRef = authored.Value.ToArray(); hiddenRef.AsSpan(120, 88).Clear();
        Reject(() => Did2MessagingArchivePatricia.Leaf(scope, authored.Family, authored.Selector, hiddenRef));
        var attachment = Entries(scope).Single(entry => entry.Family == Did2MessagingArchiveFamily.IncomingAttachment);
        var second = Did2MessagingArchivePatricia.Decode(scope, attachment.Exact).Value.Slice(88, 88).ToArray();
        Assert.Equal(2, second[1]); Assert.Equal(4UL, BinaryPrimitives.ReadUInt64BigEndian(second.AsSpan(8)));
        // There is intentionally no event-hash inequality requirement for F6:
        // two matching rows are a collision even for identical DMC bytes.
        var sameRow = attachment.Value.ToArray(); sameRow.AsSpan(0, 88).CopyTo(sameRow.AsSpan(88));
        Reject(() => Did2MessagingArchivePatricia.Leaf(scope, attachment.Family, attachment.Selector, sameRow));
    }

    [Theory]
    [InlineData("absent-nonzero")]
    [InlineData("rowid-zero")]
    [InlineData("rowid-overflow")]
    [InlineData("ordinal-overflow")]
    [InlineData("unknown-kind")]
    [InlineData("reserved")]
    [InlineData("zero-operation")]
    [InlineData("initial-operation")]
    public void ReferenceGrammarRejectsUnboundOrNoncanonicalLocators(string defect)
    {
        var raw = Reference(2, 3, 11, 1);
        switch (defect)
        {
            case "absent-nonzero": raw[0] = 0; break;
            case "rowid-zero": Put64(raw, 16, 0); break;
            case "rowid-overflow": Put64(raw, 16, (ulong)long.MaxValue + 1); break;
            case "ordinal-overflow": Put64(raw, 8, (ulong)long.MaxValue + 1); break;
            case "unknown-kind": raw[0] = 3; break;
            case "reserved": raw[7] = 1; break;
            case "zero-operation": raw.AsSpan(24, 32).Clear(); break;
            case "initial-operation": raw[0] = 1; raw[1] = 0; Put64(raw, 8, 1); Put64(raw, 16, 1); break;
        }
        Reject(() => Did2MessagingArchiveReference.Decode(raw));
        Assert.True(Did2MessagingArchiveReference.Decode(new byte[88]).IsAbsent);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(4)] [InlineData(12)] [InlineData(44)]
    [InlineData(348)] [InlineData(536)] [InlineData(544)] [InlineData(576)]
    public void EmptyRootRejectsChangedGenerationScopeSourceBasisCountAndCommitments(int offset)
    {
        var scope = Scope(); var root = Did2MessagingArchiveRoot.Empty(scope);
        var raw = root.Exact.ToArray();
        if (offset == 4) raw.AsSpan(4, 8).Clear();
        else raw[offset] ^= 1;
        Reject(() => Did2MessagingArchiveRoot.Decode(raw, scope));
        Assert.Equal(608, root.Exact.Length);
        var reducer = Did2MessagingArchiveReducer.Empty(scope); reducer.RequireRoot(root);
        Assert.Equal(Digest("archive-reducer", scope, reducer.Exact.ToArray()), reducer.Digest.ToArray());
        var forged = reducer.Exact.ToArray(); forged[904] = 1;
        Reject(() => Did2MessagingArchiveReducer.Decode(forged, scope));
        var foreign = Did2MessagingArchiveReducer.Empty(Scope(2));
        Reject(() => foreign.RequireRoot(root));
    }

    private sealed record Entry(Did2MessagingArchiveFamily Family, byte[] Selector, byte[] Value, byte[] Key, byte[] Exact, byte[] Hash);
    private sealed record RefNode(byte[] Key, byte[] Exact, byte[] Hash, int Split = -1, RefNode? Left = null, RefNode? Right = null);

    private static List<Entry> Entries(Did2MessagingSessionScope scope)
    {
        var entries = new List<Entry>();
        for (byte direction = 1; direction <= 4; direction++) Add(Did2MessagingArchiveFamily.Operation, Hash(direction), Reference(direction, (ulong)direction + 2, (ulong)direction + 9, direction));
        Add(Did2MessagingArchiveFamily.FirstIncomingEvent, Hash(20), Reference(2, 3, 11, 1));
        var ordinal = new byte[8]; Put64(ordinal, 0, 3); Add(Did2MessagingArchiveFamily.Ordinal, ordinal, Reference(2, 3, 11, 1));
        var position = new byte[40]; scope.Conversation.CopyTo(position); Put64(position, 32, 8);
        Add(Did2MessagingArchiveFamily.PeerAuthoredPosition, position, [..Reference(2, 3, 11, 1), ..Hash(21), ..Reference(2, 4, 12, 2), ..Hash(22)]);
        var route = new byte[136]; Reference(2, 4, 12, 2).CopyTo(route, 0); Put64(route, 88, 3); Hash(23).CopyTo(route, 96); Put64(route, 128, 8);
        Add(Did2MessagingArchiveFamily.QualifiedPeerRoute, Hash(24), route);
        Add(Did2MessagingArchiveFamily.IncomingAttachment, [..Hash(25), ..scope.RemoteDevice], [..Reference(2, 3, 11, 1), ..Reference(2, 4, 12, 2)]);
        return entries;
        void Add(Did2MessagingArchiveFamily family, byte[] selector, byte[] value)
        {
            var key = Key(scope, family, selector); var raw = new byte[40 + selector.Length + value.Length];
            raw[0] = 1; raw[1] = 1; raw[2] = (byte)family; key.CopyTo(raw, 4);
            Put16(raw, 36, selector.Length); Put16(raw, 38, value.Length); selector.CopyTo(raw, 40); value.CopyTo(raw, 40 + selector.Length);
            entries.Add(new(family, selector, value, key, raw, Digest("archive-node", scope, raw)));
        }
    }

    private static RefNode Tree(Did2MessagingSessionScope scope, List<Entry> entries)
    {
        var sorted = entries.OrderBy(entry => Convert.ToHexString(entry.Key), StringComparer.Ordinal).ToArray();
        return Build(sorted);
        RefNode Build(Entry[] slice)
        {
            if (slice.Length == 1) return new(slice[0].Key, slice[0].Exact, slice[0].Hash);
            var split = Enumerable.Range(0, 256).First(bit => Bit(slice[0].Key, bit) != Bit(slice[^1].Key, bit));
            var prefix = slice[0].Key.ToArray(); for (var bit = split; bit < 256; bit++) prefix[bit / 8] &= (byte)~(0x80 >> (bit % 8));
            var left = Build(slice.Where(entry => !Bit(entry.Key, split)).ToArray());
            var right = Build(slice.Where(entry => Bit(entry.Key, split)).ToArray());
            return Branch(scope, split, prefix, left, right);
        }
    }
    private static RefNode Branch(Did2MessagingSessionScope scope, int bit, byte[] prefix, Entry left, Entry right) =>
        Branch(scope, bit, prefix, new RefNode(left.Key, left.Exact, left.Hash), new RefNode(right.Key, right.Exact, right.Hash));
    private static RefNode Branch(Did2MessagingSessionScope scope, int bit, byte[] prefix, Entry left, RefNode right) =>
        Branch(scope, bit, prefix, new RefNode(left.Key, left.Exact, left.Hash), right);
    private static RefNode Branch(Did2MessagingSessionScope scope, int bit, byte[] prefix, RefNode left, RefNode right)
    {
        var raw = new byte[104]; raw[0] = 1; raw[1] = 2; Put16(raw, 4, bit); prefix.CopyTo(raw, 8); left.Hash.CopyTo(raw, 40); right.Hash.CopyTo(raw, 72);
        return new(prefix, raw, Digest("archive-node", scope, raw), bit, left, right);
    }
    private static IReadOnlyList<ReadOnlyMemory<byte>> Proof(RefNode node, byte[] key)
    {
        var result = new List<ReadOnlyMemory<byte>>();
        while (true)
        {
            result.Add(node.Exact); if (node.Split < 0) return result;
            if (Enumerable.Range(0, node.Split).Any(bit => Bit(key, bit) != Bit(node.Key, bit))) return result;
            node = (Bit(key, node.Split) ? node.Right : node.Left)!;
        }
    }
    private static byte[] Key(Did2MessagingSessionScope scope, Did2MessagingArchiveFamily family, byte[] selector)
    { var raw = new byte[3 + selector.Length]; raw[0] = (byte)family; Put16(raw, 1, selector.Length); selector.CopyTo(raw, 3); return Digest("archive-key", scope, raw); }
    private static byte[] Digest(string domain, Did2MessagingSessionScope scope, byte[] bytes) =>
        SHA256.HashData([..Encoding.UTF8.GetBytes("Deep/STORE-V2/" + domain), 0, ..scope.Hash, ..bytes]);
    private static byte[] Reference(byte direction, ulong ordinal, ulong rowId, int operation)
    { var raw = new byte[88]; raw[0] = 2; raw[1] = direction; Put64(raw, 8, ordinal); Put64(raw, 16, rowId); Hash(operation).CopyTo(raw, 24); Hash(operation + 100).CopyTo(raw, 56); return raw; }
    private static byte[] Hash(int value) => SHA256.HashData(Encoding.UTF8.GetBytes("archive codec fixture " + value));
    private static bool Bit(byte[] value, int bit) => (value[bit / 8] & (0x80 >> (bit % 8))) != 0;
    private static void Put16(byte[] raw, int offset, int value) => BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(offset), checked((ushort)value));
    private static void Put64(byte[] raw, int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), value);
    private static void Reject(Action action)
    { var error = Record.Exception(action); Assert.True(error is InvalidDataException or CryptographicException, error?.ToString() ?? "Accepted hostile archive input"); }
    private static Did2MessagingSessionScope Scope(byte variant = 1)
    {
        var raw = new byte[404]; raw[0] = 1; raw[1] = 1; raw.AsSpan(4, 16).Fill(variant);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) Hash(offset + variant).CopyTo(raw, offset);
        foreach (var offset in new[] { 84, 124, 164, 204 }) Put64(raw, offset, 1);
        return Did2MessagingSessionScope.RestoreMetadata(raw);
    }
}
