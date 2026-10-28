using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingArchiveBuilderTests
{
    [Fact]
    public void EveryFamilyIncrementalAndReorderedConstructionEqualIndependentFullReplay()
    {
        var scope = Scope(); var observations = Observations(scope); var reference = FullReference(scope, observations);
        for (var seed = 0; seed < 6; seed++)
        {
            var random = new Random(seed); var shuffled = observations.OrderBy(_ => random.Next()).ToArray();
            var source = new Dictionary<string, byte[]>(StringComparer.Ordinal); var root = Empty(scope);
            foreach (var chunk in shuffled.Chunk(11))
            {
                var builder = Builder(scope, root, source);
                foreach (var observation in chunk) builder.Add(observation.Family, observation.Selector, observation.Value);
                var result = builder.Complete();
                foreach (var node in result.Nodes) source[Id(node.Digest.Span)] = node.Exact.ToArray();
                root = result.PatriciaHash.ToArray();
            }
            Assert.Equal(reference.Root, root);
            foreach (var entry in reference.Entries)
                Assert.Equal(entry.Value, Did2MessagingArchivePatricia.VerifyProof(scope, root, entry.Family,
                    entry.Selector, Proof(source, root, entry.Key)));
        }
    }

    [Fact]
    public void BatchOutputContainsOnlySortedUniqueFinalReachableNodesAndReplayIsIdempotent()
    {
        var scope = Scope(); var observations = Observations(scope); var reference = FullReference(scope, observations);
        var builder = Builder(scope, Empty(scope), []);
        foreach (var observation in observations) builder.Add(observation.Family, observation.Selector, observation.Value);
        var result = builder.Complete(); Assert.Equal(reference.Root, result.PatriciaHash.ToArray());
        var actual = result.Nodes.Select(node => Id(node.Digest.Span)).ToArray();
        Assert.Equal(actual.Order(StringComparer.Ordinal), actual); Assert.Equal(actual.Distinct().Count(), actual.Length);
        Assert.Equal(reference.Nodes.Count, result.Nodes.Count);
        foreach (var node in result.Nodes) Assert.Equal(reference.Nodes[Id(node.Digest.Span)], node.Exact.ToArray());
        var replay = Builder(scope, reference.Root, reference.Nodes);
        foreach (var observation in observations) replay.Add(observation.Family, observation.Selector, observation.Value);
        Assert.Empty(replay.Complete().Nodes); Assert.Equal(reference.Root, replay.Complete().PatriciaHash.ToArray());
    }

    [Fact]
    public void DistinctEventWitnessAndSecondRowWitnessRetainDifferentStickyFacts()
    {
        var scope = Scope(); var a = Ref(2, 3, 11); var duplicate = Ref(2, 4, 12); var b = Ref(2, 5, 13); var later = Ref(2, 6, 14);
        var position = Position(scope, 9); var attachment = Concat(Hash(44), scope.RemoteDevice.ToArray());
        var builder = Builder(scope, Empty(scope), []);
        foreach (var (reference, eventHash) in new[] { (later, Hash(102)), (duplicate, Hash(100)), (b, Hash(101)), (a, Hash(100)) })
        {
            builder.Add(Did2MessagingArchiveFamily.PeerAuthoredPosition, position, Concat(reference, eventHash, new byte[120]));
            builder.Add(Did2MessagingArchiveFamily.IncomingAttachment, attachment, Concat(reference, new byte[88]));
        }
        var result = builder.Complete(); var nodes = result.Nodes.ToDictionary(node => Id(node.Digest.Span), node => node.Exact.ToArray());
        var peer = Read(Did2MessagingArchiveFamily.PeerAuthoredPosition, position);
        Assert.Equal(a, peer[..88]); Assert.Equal(b, peer[120..208]);
        var attached = Read(Did2MessagingArchiveFamily.IncomingAttachment, attachment);
        Assert.Equal(a, attached[..88]); Assert.Equal(duplicate, attached[88..]);
        // Later facts cannot erase the first observed collision/fork witness.
        builder.Add(Did2MessagingArchiveFamily.PeerAuthoredPosition, position, Concat(Ref(2, 8, 18), Hash(103), new byte[120]));
        builder.Add(Did2MessagingArchiveFamily.IncomingAttachment, attachment, Concat(Ref(2, 8, 18), new byte[88]));
        Assert.Equal(result.PatriciaHash.ToArray(), builder.Complete().PatriciaHash.ToArray());
        byte[] Read(Did2MessagingArchiveFamily family, byte[] selector) => Did2MessagingArchivePatricia.VerifyProof(scope,
            result.PatriciaHash.Span, family, selector, Proof(nodes, result.PatriciaHash.ToArray(), Key(scope, family, selector)))!;
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(5)]
    public void UniqueAndMinimumFamiliesRejectConflictingSameOrdinalWithoutChangingBuilder(byte familyByte)
    {
        var scope = Scope(); var family = (Did2MessagingArchiveFamily)familyByte; var first = Ref(2, 3, 11);
        var second = Ref(2, 3, 12); var selector = family switch
        {
            Did2MessagingArchiveFamily.Operation => first[24..56],
            Did2MessagingArchiveFamily.Ordinal => Number(3),
            _ => Hash(61)
        };
        if (family == Did2MessagingArchiveFamily.Operation) first.AsSpan(24, 32).CopyTo(second.AsSpan(24));
        byte[] Value(byte[] reference) => family == Did2MessagingArchiveFamily.QualifiedPeerRoute ? Route(reference, 2) : reference;
        var builder = Builder(scope, Empty(scope), []); builder.Add(family, selector, Value(first));
        var before = builder.Complete(); Reject(() => builder.Add(family, selector, Value(second)));
        Assert.Equal(before.PatriciaHash.ToArray(), builder.Complete().PatriciaHash.ToArray());
    }

    [Theory]
    [InlineData("missing-root")] [InlineData("missing-child")] [InlineData("changed-node")]
    [InlineData("wrong-scope")] [InlineData("wrong-edge")] [InlineData("wrong-selector")]
    public void UnauthenticatedOrMalformedNamedPathCannotBeTreatedAsAbsence(string defect)
    {
        var scope = Scope(); var facts = Observations(scope); var reference = FullReference(scope, facts);
        var source = reference.Nodes.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray()); var root = reference.Root.ToArray();
        var chosen = reference.Entries.First(entry => entry.Family == Did2MessagingArchiveFamily.Operation);
        var proof = Proof(source, root, chosen.Key);
        switch (defect)
        {
            case "missing-root": source.Remove(Id(root)); break;
            case "missing-child": source.Remove(Id(Digest("archive-node", scope, proof[1].ToArray()))); break;
            case "changed-node": source[Id(root)][40] ^= 1; break;
            case "wrong-scope": scope = Scope(2); break;
            case "wrong-edge":
                var branch = source[Id(root)].ToArray(); var left = branch[40..72]; branch.AsSpan(72, 32).CopyTo(branch.AsSpan(40));
                left.CopyTo(branch, 72); root = Digest("archive-node", scope, branch); source[Id(root)] = branch; break;
            case "wrong-selector":
                var leaf = proof[^1].ToArray(); leaf[40] ^= 1;
                root = Digest("archive-node", scope, leaf); source[Id(root)] = leaf; break;
        }
        var builder = Builder(scope, root, source);
        Reject(() => builder.Add(chosen.Family, chosen.Selector, chosen.Value));
        Assert.Equal(root, builder.Complete().PatriciaHash.ToArray()); Assert.Empty(builder.Complete().Nodes);
    }

    [Fact]
    public void GeneratedKeysDoNotProbeUnselectedStorageAndLeaveCollisionReadbackToInsertionOwner()
    {
        var scope = Scope(); var fact = Observations(scope)[0]; var reference = FullReference(scope, [fact]);
        var corrupt = reference.Nodes[Id(reference.Root)].ToArray(); corrupt[^1] ^= 1;
        var reads = 0;
        var builder = new Did2MessagingArchiveBuilder(scope, Empty(scope), _ => { reads++; return corrupt; });
        builder.Add(fact.Family, fact.Selector, fact.Value);
        Assert.Equal(0, reads); Assert.Equal(reference.Root, builder.Complete().PatriciaHash.ToArray());
        var output = Assert.Single(builder.Complete().Nodes);
        Assert.Equal(reference.Nodes[Id(reference.Root)], output.Exact.ToArray());
        Assert.NotEqual(corrupt, output.Exact.ToArray());
    }

    [Theory]
    [InlineData(4, "prebuilt-witness")] [InlineData(6, "prebuilt-witness")]
    [InlineData(4, "ordinal")] [InlineData(6, "ordinal")]
    [InlineData(4, "row")] [InlineData(6, "row")]
    [InlineData(4, "operation")] [InlineData(6, "operation")]
    [InlineData(4, "event-hash")]
    public void WitnessOwnerRejectsCallerWitnessAndConflictingSourceReference(byte familyByte, string defect)
    {
        var scope = Scope(); var family = (Did2MessagingArchiveFamily)familyByte; var first = Ref(2, 3, 11); var next = Ref(2, 4, 12);
        var selector = familyByte == 4 ? Position(scope, 7) : Concat(Hash(71), scope.RemoteDevice.ToArray());
        byte[] Value(byte[] reference, int eventHash = 10) => familyByte == 4 ? Concat(reference, Hash(eventHash), new byte[120]) : Concat(reference, new byte[88]);
        var builder = Builder(scope, Empty(scope), []); builder.Add(family, selector, Value(first)); var before = builder.Complete();
        switch (defect)
        {
            case "ordinal": Put64(next, 8, 3); break;
            case "row": Put64(next, 16, 11); break;
            case "operation": first.AsSpan(24, 32).CopyTo(next.AsSpan(24)); break;
            case "event-hash": next = first; break;
        }
        var incoming = Value(next, defect == "event-hash" ? 11 : 10);
        if (defect == "prebuilt-witness") next.CopyTo(incoming, familyByte == 4 ? 120 : 88);
        if (defect == "prebuilt-witness" && familyByte == 4) Hash(11).CopyTo(incoming, 208);
        Reject(() => builder.Add(family, selector, incoming));
        Assert.Equal(before.PatriciaHash.ToArray(), builder.Complete().PatriciaHash.ToArray());
    }

    [Fact]
    public void InitialQualifiedRouteAndEmptyTreeStaySeparateFromEventCountOrAuthority()
    {
        var scope = Scope(); var builder = Builder(scope, Empty(scope), []);
        Assert.Empty(builder.Complete().Nodes); Assert.Equal(Empty(scope), builder.Complete().PatriciaHash.ToArray());
        var initial = new byte[88]; initial[0] = 1; Put64(initial, 8, 1); Put64(initial, 16, 1); Hash(72).CopyTo(initial, 56);
        var selector = Hash(73); var value = Route(initial, 2, 0);
        builder.Add(Did2MessagingArchiveFamily.QualifiedPeerRoute, selector, value);
        var expected = FullReference(scope, [new(Did2MessagingArchiveFamily.QualifiedPeerRoute, selector, value)]);
        Assert.Equal(expected.Root, builder.Complete().PatriciaHash.ToArray());
    }

    private sealed record Observation(Did2MessagingArchiveFamily Family, byte[] Selector, byte[] Value);
    private sealed record Entry(Did2MessagingArchiveFamily Family, byte[] Selector, byte[] Value, byte[] Key, byte[] Exact, byte[] Hash);
    private sealed record ReferenceTree(byte[] Root, Dictionary<string, byte[]> Nodes, Entry[] Entries);
    private static ReferenceTree FullReference(Did2MessagingSessionScope scope, IReadOnlyList<Observation> observations)
    {
        var entries = observations.GroupBy(fact => ((byte)fact.Family, Id(fact.Selector))).Select(group =>
        {
            var ordered = group.OrderBy(fact => Read64(fact.Value, 8)).ToArray(); var first = ordered[0]; var value = first.Value.ToArray();
            if (first.Family is Did2MessagingArchiveFamily.Operation or Did2MessagingArchiveFamily.Ordinal)
                Assert.All(ordered, fact => Assert.Equal(value, fact.Value));
            if (first.Family == Did2MessagingArchiveFamily.PeerAuthoredPosition)
            {
                var second = ordered.FirstOrDefault(fact => !fact.Value.AsSpan(88, 32).SequenceEqual(value.AsSpan(88, 32)));
                if (second is not null) { second.Value.AsSpan(0, 88).CopyTo(value.AsSpan(120)); second.Value.AsSpan(88, 32).CopyTo(value.AsSpan(208)); }
            }
            if (first.Family == Did2MessagingArchiveFamily.IncomingAttachment)
            {
                var second = ordered.FirstOrDefault(fact => !fact.Value.AsSpan(0, 88).SequenceEqual(value.AsSpan(0, 88)));
                if (second is not null) second.Value.AsSpan(0, 88).CopyTo(value.AsSpan(88));
            }
            var key = Key(scope, first.Family, first.Selector); var exact = new byte[40 + first.Selector.Length + value.Length];
            exact[0] = 1; exact[1] = 1; exact[2] = (byte)first.Family; key.CopyTo(exact, 4);
            Put16(exact, 36, first.Selector.Length); Put16(exact, 38, value.Length); first.Selector.CopyTo(exact, 40); value.CopyTo(exact, 40 + first.Selector.Length);
            return new Entry(first.Family, first.Selector, value, key, exact, Digest("archive-node", scope, exact));
        }).OrderBy(entry => Id(entry.Key), StringComparer.Ordinal).ToArray();
        var nodes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        return new(entries.Length == 0 ? Empty(scope) : Build(entries), nodes, entries);
        byte[] Build(Entry[] slice)
        {
            if (slice.Length == 1) { nodes[Id(slice[0].Hash)] = slice[0].Exact; return slice[0].Hash; }
            var split = Enumerable.Range(0, 256).First(bit => Bit(slice[0].Key, bit) != Bit(slice[^1].Key, bit));
            var prefix = slice[0].Key.ToArray(); for (var bit = split; bit < 256; bit++) prefix[bit / 8] &= (byte)~(0x80 >> (bit % 8));
            var left = Build(slice.Where(entry => !Bit(entry.Key, split)).ToArray()); var right = Build(slice.Where(entry => Bit(entry.Key, split)).ToArray());
            var raw = new byte[104]; raw[0] = 1; raw[1] = 2; Put16(raw, 4, split); prefix.CopyTo(raw, 8); left.CopyTo(raw, 40); right.CopyTo(raw, 72);
            var digest = Digest("archive-node", scope, raw); nodes[Id(digest)] = raw; return digest;
        }
    }

    private static List<Observation> Observations(Did2MessagingSessionScope scope)
    {
        var facts = new List<Observation>();
        for (var index = 3; index < 43; index++)
        {
            var direction = (byte)(index % 4 + 1); var reference = Ref(direction, (ulong)index, (ulong)index + 100);
            facts.Add(new(Did2MessagingArchiveFamily.Operation, reference[24..56], reference));
            facts.Add(new(Did2MessagingArchiveFamily.Ordinal, Number((ulong)index), reference));
            if (direction != 2) continue;
            var eventHash = Hash(index % 3 + 1000);
            facts.Add(new(Did2MessagingArchiveFamily.FirstIncomingEvent, eventHash, reference));
            facts.Add(new(Did2MessagingArchiveFamily.PeerAuthoredPosition, Position(scope, (ulong)(index % 2 + 1)), Concat(reference, eventHash, new byte[120])));
            facts.Add(new(Did2MessagingArchiveFamily.QualifiedPeerRoute, Hash(index % 2 + 2000), Route(reference, (ulong)index)));
            facts.Add(new(Did2MessagingArchiveFamily.IncomingAttachment, Concat(Hash(index % 2 + 3000), scope.RemoteDevice.ToArray()), Concat(reference, new byte[88])));
        }
        return facts;
    }
    private static Did2MessagingArchiveBuilder Builder(Did2MessagingSessionScope scope, byte[] root, Dictionary<string, byte[]> source) =>
        new(scope, root, hash => source.TryGetValue(Id(hash.Span), out var exact) ? exact : null);
    private static IReadOnlyList<ReadOnlyMemory<byte>> Proof(Dictionary<string, byte[]> nodes, byte[] root, byte[] key)
    {
        var path = new List<ReadOnlyMemory<byte>>(); var hash = root;
        while (true)
        {
            var raw = nodes[Id(hash)]; path.Add(raw); if (raw[1] == 1) return path;
            var bit = BinaryPrimitives.ReadUInt16BigEndian(raw.AsSpan(4));
            if (Enumerable.Range(0, bit).Any(index => Bit(key, index) != Bit(raw[8..40], index))) return path;
            hash = Bit(key, bit) ? raw[72..104] : raw[40..72];
        }
    }
    private static byte[] Key(Did2MessagingSessionScope scope, Did2MessagingArchiveFamily family, byte[] selector)
    { var raw = new byte[3 + selector.Length]; raw[0] = (byte)family; Put16(raw, 1, selector.Length); selector.CopyTo(raw, 3); return Digest("archive-key", scope, raw); }
    private static byte[] Empty(Did2MessagingSessionScope scope) => Digest("archive-empty", scope, []);
    private static byte[] Digest(string domain, Did2MessagingSessionScope scope, byte[] exact) =>
        SHA256.HashData(Concat(Encoding.UTF8.GetBytes("Deep/STORE-V2/" + domain), [0], scope.Hash.ToArray(), exact));
    private static byte[] Ref(byte direction, ulong ordinal, ulong row)
    { var raw = new byte[88]; raw[0] = 2; raw[1] = direction; Put64(raw, 8, ordinal); Put64(raw, 16, row); Hash((int)row).CopyTo(raw, 24); Hash((int)row + 4000).CopyTo(raw, 56); return raw; }
    private static byte[] Route(byte[] reference, ulong sequence, ulong consent = 2)
    { var raw = new byte[136]; reference.CopyTo(raw, 0); Put64(raw, 88, consent); Put64(raw, 128, sequence); return raw; }
    private static byte[] Position(Did2MessagingSessionScope scope, ulong sequence) => Concat(scope.Conversation.ToArray(), Number(sequence));
    private static byte[] Number(ulong value) { var raw = new byte[8]; Put64(raw, 0, value); return raw; }
    private static byte[] Concat(params byte[][] arrays) => arrays.SelectMany(array => array).ToArray();
    private static byte[] Hash(int value) => SHA256.HashData(Encoding.UTF8.GetBytes("archive builder structural fixture " + value));
    private static string Id(ReadOnlySpan<byte> value) => Convert.ToHexString(value);
    private static ulong Read64(byte[] raw, int offset) => BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(offset));
    private static bool Bit(byte[] key, int bit) => (key[bit / 8] & (0x80 >> (bit % 8))) != 0;
    private static void Put16(byte[] raw, int offset, int value) => BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(offset), checked((ushort)value));
    private static void Put64(byte[] raw, int offset, ulong value) => BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(offset), value);
    private static void Reject(Action action)
    { var error = Record.Exception(action); Assert.True(error is InvalidDataException or CryptographicException, error?.ToString() ?? "Accepted hostile archive insertion"); }
    private static Did2MessagingSessionScope Scope(byte variant = 1)
    {
        var raw = new byte[404]; raw[0] = 1; raw[1] = 1; raw.AsSpan(4, 16).Fill(variant);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) Hash(offset + variant).CopyTo(raw, offset);
        foreach (var offset in new[] { 84, 124, 164, 204 }) Put64(raw, offset, 1);
        return Did2MessagingSessionScope.RestoreMetadata(raw);
    }
}
