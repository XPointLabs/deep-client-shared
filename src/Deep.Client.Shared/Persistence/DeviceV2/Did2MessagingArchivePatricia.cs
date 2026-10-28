using System.Buffers.Binary;
using System.Security.Cryptography;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2MessagingArchiveFamily : byte
{
    Operation = 1, FirstIncomingEvent = 2, Ordinal = 3,
    PeerAuthoredPosition = 4, QualifiedPeerRoute = 5, IncomingAttachment = 6
}

/// <summary>Pure immutable-node codec and bounded path verifier; no SQL or runtime adoption.</summary>
internal static class Did2MessagingArchivePatricia
{
    internal const int BranchBytes = 104, LeafHeaderBytes = 40, MaximumNodeBytes = 320, MaximumProofNodes = 257;

    internal sealed class Node
    {
        private readonly byte[] exact, digest;
        internal Node(byte[] exact, byte[] digest) { this.exact = exact; this.digest = digest; }
        internal ReadOnlyMemory<byte> Exact => exact;
        internal ReadOnlyMemory<byte> Digest => digest;
        internal bool IsLeaf => exact[1] == 1;
        internal Did2MessagingArchiveFamily Family => IsLeaf ? (Did2MessagingArchiveFamily)exact[2] : throw Bad();
        internal int Bit => !IsLeaf ? BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(4)) : throw Bad();
        internal ReadOnlySpan<byte> KeyOrPrefix => exact.AsSpan(IsLeaf ? 4 : 8, 32);
        internal ReadOnlySpan<byte> LeftHash => !IsLeaf ? exact.AsSpan(40, 32) : throw Bad();
        internal ReadOnlySpan<byte> RightHash => !IsLeaf ? exact.AsSpan(72, 32) : throw Bad();
        internal ReadOnlySpan<byte> Selector => IsLeaf ? exact.AsSpan(LeafHeaderBytes,
            BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(36))) : throw Bad();
        internal ReadOnlySpan<byte> Value => IsLeaf ? exact.AsSpan(LeafHeaderBytes +
            BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(36))) : throw Bad();
    }

    internal static byte[] Key(Did2MessagingSessionScope scope, Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
    {
        ArgumentNullException.ThrowIfNull(scope); RequireSelector(family, selector);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-key"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        Span<byte> header = stackalloc byte[3]; header[0] = (byte)family;
        BinaryPrimitives.WriteUInt16BigEndian(header[1..], checked((ushort)selector.Length));
        hash.AppendData(header); hash.AppendData(selector); return hash.GetHashAndReset();
    }

    internal static Node Decode(Did2MessagingSessionScope scope, ReadOnlySpan<byte> raw)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (raw.Length is < BranchBytes or > MaximumNodeBytes || raw[0] != 1) throw Bad();
        if (raw[1] == 1)
        {
            if (raw[3] != 0) throw Bad();
            var family = (Did2MessagingArchiveFamily)raw[2];
            var selectorLength = BinaryPrimitives.ReadUInt16BigEndian(raw[36..]);
            var valueLength = BinaryPrimitives.ReadUInt16BigEndian(raw[38..]);
            if (raw.Length != LeafHeaderBytes + selectorLength + valueLength) throw Bad();
            var selector = raw.Slice(LeafHeaderBytes, selectorLength);
            RequireSelector(family, selector); RequireValue(family, selector, raw[(LeafHeaderBytes + selectorLength)..]);
            if (!Fixed(raw.Slice(4, 32), Key(scope, family, selector))) throw Bad();
        }
        else if (raw[1] == 2)
        {
            if (raw.Length != BranchBytes || !Zero(raw.Slice(2, 2)) || !Zero(raw.Slice(6, 2))) throw Bad();
            var bit = BinaryPrimitives.ReadUInt16BigEndian(raw[4..]);
            if (bit > 255 || !HasCanonicalPrefix(raw.Slice(8, 32), bit)) throw Bad();
            var left = raw.Slice(40, 32); var right = raw.Slice(72, 32); var empty = EmptyHash(scope);
            RequireHash(left); RequireHash(right);
            if (Fixed(left, right) || Fixed(left, empty) || Fixed(right, empty)) throw Bad();
        }
        else throw Bad();
        return new(raw.ToArray(), NodeHash(scope, raw));
    }

    internal static Node Leaf(Did2MessagingSessionScope scope, Did2MessagingArchiveFamily family,
        ReadOnlySpan<byte> selector, ReadOnlySpan<byte> value)
    {
        RequireSelector(family, selector); RequireValue(family, selector, value);
        var length = checked(LeafHeaderBytes + selector.Length + value.Length);
        if (length > MaximumNodeBytes) throw Bad();
        var raw = new byte[length]; raw[0] = 1; raw[1] = 1; raw[2] = (byte)family;
        Key(scope, family, selector).CopyTo(raw.AsSpan(4));
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(36), checked((ushort)selector.Length));
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(38), checked((ushort)value.Length));
        selector.CopyTo(raw.AsSpan(LeafHeaderBytes)); value.CopyTo(raw.AsSpan(LeafHeaderBytes + selector.Length));
        return Decode(scope, raw);
    }

    internal static Node Branch(Did2MessagingSessionScope scope, int bit, ReadOnlySpan<byte> prefix,
        ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (bit is < 0 or > 255 || prefix.Length != 32) throw Bad();
        RequireHash(left); RequireHash(right);
        var raw = new byte[BranchBytes]; raw[0] = 1; raw[1] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(4), checked((ushort)bit));
        prefix.CopyTo(raw.AsSpan(8)); left.CopyTo(raw.AsSpan(40)); right.CopyTo(raw.AsSpan(72));
        return Decode(scope, raw);
    }

    /// <summary>Null means authenticated divergence, never an absent supplied node.</summary>
    internal static byte[]? VerifyProof(Did2MessagingSessionScope scope, Did2MessagingArchiveRoot root,
        Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector,
        IReadOnlyList<ReadOnlyMemory<byte>> exactNodes)
    {
        ArgumentNullException.ThrowIfNull(root);
        // Decode joins the supplied scope even if this root object was restored
        // by another owner. No successful proof substitutes for actual storage.
        _ = Did2MessagingArchiveRoot.Decode(root.Exact.Span, scope);
        var value = VerifyProof(scope, root.PatriciaHash, family, selector, exactNodes);
        if (value is not null) RequireValueAtBasis(Decode(scope, exactNodes[^1].Span), root.Basis.Ordinal);
        return value;
    }

    /// <summary>Raw-hash variant for full audit/staging; the caller owns the independently expected hash.</summary>
    internal static byte[]? VerifyProof(Did2MessagingSessionScope scope, ReadOnlySpan<byte> expectedRoot,
        Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector,
        IReadOnlyList<ReadOnlyMemory<byte>> exactNodes)
    {
        ArgumentNullException.ThrowIfNull(exactNodes); RequireHash(expectedRoot);
        var key = Key(scope, family, selector);
        if (Fixed(expectedRoot, EmptyHash(scope)))
        { if (exactNodes.Count != 0) throw Bad(); return null; }
        if (exactNodes.Count is < 1 or > MaximumProofNodes) throw Bad();
        var expected = expectedRoot.ToArray(); Node? parent = null; var edge = false;
        for (var index = 0; index < exactNodes.Count; index++)
        {
            var node = Decode(scope, exactNodes[index].Span);
            if (!Fixed(expected, node.Digest.Span)) throw new CryptographicException("Messaging archive proof lost a named immutable node.");
            if (parent is not null) RequireChild(parent, edge, node);
            if (node.IsLeaf)
            {
                RequireTerminal(index, exactNodes.Count);
                if (!Fixed(node.KeyOrPrefix, key)) return null;
                if (node.Family != family || !Fixed(node.Selector, selector))
                    throw new CryptographicException("Messaging archive typed selector has a hash collision.");
                return node.Value.ToArray();
            }
            if (!PrefixMatches(key, node.KeyOrPrefix, node.Bit))
            { RequireTerminal(index, exactNodes.Count); return null; }
            edge = BitAt(key, node.Bit); expected = (edge ? node.RightHash : node.LeftHash).ToArray(); parent = node;
        }
        throw new CryptographicException("Messaging archive proof is missing its selected node.");
    }

    // Also used by a full tree audit: both children must be decoded/authenticated
    // independently before this structural relation proves their placement.
    internal static void RequireChild(Node parent, bool right, Node child)
    {
        ArgumentNullException.ThrowIfNull(parent); ArgumentNullException.ThrowIfNull(child);
        if (parent.IsLeaf || (!child.IsLeaf && child.Bit <= parent.Bit) ||
            !PrefixMatches(child.KeyOrPrefix, parent.KeyOrPrefix, parent.Bit) || BitAt(child.KeyOrPrefix, parent.Bit) != right ||
            !Fixed(right ? parent.RightHash : parent.LeftHash, child.Digest.Span)) throw Bad();
    }

    internal static void RequireValueAtBasis(Node leaf, ulong basisOrdinal)
    {
        ArgumentNullException.ThrowIfNull(leaf);
        if (!leaf.IsLeaf || basisOrdinal > long.MaxValue) throw Bad();
        Did2MessagingArchiveReference.Decode(leaf.Value[..Did2MessagingArchiveReference.Bytes], false).RequireAtBasis(basisOrdinal);
        if (leaf.Family == Did2MessagingArchiveFamily.PeerAuthoredPosition)
            Did2MessagingArchiveReference.Decode(leaf.Value.Slice(120, Did2MessagingArchiveReference.Bytes)).RequireAtBasis(basisOrdinal);
        if (leaf.Family == Did2MessagingArchiveFamily.IncomingAttachment)
            Did2MessagingArchiveReference.Decode(leaf.Value.Slice(88, Did2MessagingArchiveReference.Bytes)).RequireAtBasis(basisOrdinal);
        if (leaf.Family == Did2MessagingArchiveFamily.QualifiedPeerRoute && U64(leaf.Value, 88) > basisOrdinal) throw Bad();
    }

    private static void RequireSelector(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
    {
        switch (family)
        {
            case Did2MessagingArchiveFamily.Operation:
            case Did2MessagingArchiveFamily.FirstIncomingEvent:
            case Did2MessagingArchiveFamily.QualifiedPeerRoute:
                RequireHash(selector); return;
            case Did2MessagingArchiveFamily.Ordinal:
                if (selector.Length != 8 || U64(selector, 0) is 0 or > long.MaxValue) throw Bad();
                return;
            case Did2MessagingArchiveFamily.PeerAuthoredPosition:
                if (selector.Length != 40 || Zero(selector[..32]) || U64(selector, 32) == 0) throw Bad();
                return;
            case Did2MessagingArchiveFamily.IncomingAttachment:
                if (selector.Length != 64 || Zero(selector[..32]) || Zero(selector[32..])) throw Bad();
                return;
            default: throw Bad();
        }
    }

    private static void RequireValue(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector, ReadOnlySpan<byte> value)
    {
        var expectedBytes = family switch
        {
            Did2MessagingArchiveFamily.Operation or Did2MessagingArchiveFamily.FirstIncomingEvent or Did2MessagingArchiveFamily.Ordinal => 88,
            Did2MessagingArchiveFamily.PeerAuthoredPosition => 240,
            Did2MessagingArchiveFamily.QualifiedPeerRoute => 136,
            Did2MessagingArchiveFamily.IncomingAttachment => 176,
            _ => throw Bad()
        };
        if (value.Length != expectedBytes) throw Bad();
        var first = Did2MessagingArchiveReference.Decode(value[..88], false);
        if (family == Did2MessagingArchiveFamily.QualifiedPeerRoute)
        {
            if (first.Kind != 1 && (first.Kind != 2 || first.Direction != 2) || U64(value, 88) > long.MaxValue || U64(value, 128) == 0) throw Bad();
            return;
        }
        if (first.Kind != 2) throw Bad();
        switch (family)
        {
            case Did2MessagingArchiveFamily.Operation:
                if (!Fixed(selector, first.Operation)) throw Bad();
                break;
            case Did2MessagingArchiveFamily.Ordinal:
                if (U64(selector, 0) != first.Ordinal) throw Bad();
                break;
            case Did2MessagingArchiveFamily.FirstIncomingEvent:
                if (first.Direction != 2) throw Bad();
                break;
            case Did2MessagingArchiveFamily.PeerAuthoredPosition:
                if (first.Direction != 2) throw Bad();
                RequireHash(value.Slice(88, 32));
                var distinct = Did2MessagingArchiveReference.Decode(value.Slice(120, 88));
                if (distinct.IsAbsent)
                { if (!Zero(value.Slice(208, 32))) throw Bad(); }
                else
                {
                    RequireSecond(first, distinct); RequireHash(value.Slice(208, 32));
                    if (Fixed(value.Slice(88, 32), value.Slice(208, 32))) throw Bad();
                }
                break;
            case Did2MessagingArchiveFamily.IncomingAttachment:
                if (first.Direction != 2) throw Bad();
                var second = Did2MessagingArchiveReference.Decode(value.Slice(88, 88));
                if (!second.IsAbsent) RequireSecond(first, second);
                break;
        }
    }

    private static void RequireSecond(Did2MessagingArchiveReference first, Did2MessagingArchiveReference second)
    {
        if (second.Kind != 2 || second.Direction != 2 || second.Ordinal <= first.Ordinal || second.RowId == first.RowId ||
            Fixed(first.Operation, second.Operation)) throw Bad();
    }
    private static void RequireTerminal(int index, int count) { if (index != count - 1) throw Bad(); }
    private static bool BitAt(ReadOnlySpan<byte> value, int bit) => (value[bit / 8] & (0x80 >> (bit % 8))) != 0;
    private static bool PrefixMatches(ReadOnlySpan<byte> value, ReadOnlySpan<byte> prefix, int bits)
    {
        var bytes = bits / 8; var remainder = bits % 8;
        return value[..bytes].SequenceEqual(prefix[..bytes]) &&
            (remainder == 0 || ((value[bytes] ^ prefix[bytes]) & (0xff << (8 - remainder))) == 0);
    }
    private static bool HasCanonicalPrefix(ReadOnlySpan<byte> prefix, int bits)
    {
        var bytes = bits / 8; var remainder = bits % 8;
        return remainder == 0 ? Zero(prefix[bytes..]) :
            (prefix[bytes] & (0xff >> remainder)) == 0 && Zero(prefix[(bytes + 1)..]);
    }
}
