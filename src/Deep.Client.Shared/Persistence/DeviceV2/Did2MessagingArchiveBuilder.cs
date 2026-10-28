using System.Security.Cryptography;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>
/// Pure scoped Patricia path copying over already qualified source observations.
/// Neither input nor output conveys root custody, source qualification or admission.
/// The resolver must expose immutable bytes in one synchronous closed segment;
/// discard the builder before any external callback or source change.
/// </summary>
internal sealed class Did2MessagingArchiveBuilder
{
    private readonly Did2MessagingSessionScope scope;
    private readonly Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>?> resolve;
    private readonly Dictionary<string, Did2MessagingArchivePatricia.Node> added = new(StringComparer.Ordinal);
    private byte[] root;

    internal Did2MessagingArchiveBuilder(Did2MessagingSessionScope scope, ReadOnlySpan<byte> expectedRoot,
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>?> resolve)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(resolve);
        RequireHash(expectedRoot); this.scope = scope; this.resolve = resolve; root = expectedRoot.ToArray();
    }

    /// <summary>
    /// Adds one canonical observation. F4/F6 must contain only their first ref,
    /// with absent second witness; this owner derives both retained witnesses.
    /// F5 eligibility/consent/closure and every event hash/ref must already have
    /// been established by the existing full source verifier, including authored
    /// application custody for outgoing events. No native classification occurs here.
    /// The owner must add F1 and F3 for every archived event, then all eligible
    /// additional families; this builder cannot establish projection completeness.
    /// F1 and F3 are unique, F2/F5 retain the earliest ordinal, F4 retains the
    /// earliest distinct event, and F6 the earliest second row, even for a replay.
    /// A replay in any order produces the same ordinal-canonical result.
    /// </summary>
    internal void Add(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector, ReadOnlySpan<byte> singleValue)
    {
        var observation = Did2MessagingArchivePatricia.Leaf(scope, family, selector, singleValue);
        if (family == Did2MessagingArchiveFamily.PeerAuthoredPosition && !Zero(singleValue[120..]) ||
            family == Did2MessagingArchiveFamily.IncomingAttachment && !Zero(singleValue[88..])) throw Bad();
        var key = observation.KeyOrPrefix.ToArray();
        var path = ReadPath(family, selector, key, out var previous);
        var replacement = previous is null ? observation : Did2MessagingArchivePatricia.Leaf(scope, family, selector,
            Merge(family, previous, singleValue));
        if (previous is not null && Fixed(previous, replacement.Value)) return;

        var pending = new List<Did2MessagingArchivePatricia.Node> { replacement };
        if (path.Count != 0 && previous is null)
        {
            var terminal = path[^1];
            var split = FirstDifferentBit(key, terminal.KeyOrPrefix);
            replacement = Join(split, Prefix(key, split), Bit(key, split) ? terminal.Digest.Span : replacement.Digest.Span,
                Bit(key, split) ? replacement.Digest.Span : terminal.Digest.Span);
            pending.Add(replacement);
        }
        for (var index = path.Count - 2; index >= 0; index--)
        {
            var parent = path[index]; var right = Bit(key, parent.Bit);
            replacement = Join(parent.Bit, parent.KeyOrPrefix,
                right ? parent.LeftHash : replacement.Digest.Span,
                right ? replacement.Digest.Span : parent.RightHash);
            pending.Add(replacement);
        }

        // Validate in-memory immutable collisions before publishing any state.
        // Existing storage keys are checked by the actual insertion/readback
        // owner, without doubling the selected source-path lookup bound here.
        var unique = new Dictionary<string, Did2MessagingArchivePatricia.Node>(StringComparer.Ordinal);
        foreach (var node in pending)
        {
            var id = Id(node.Digest.Span);
            if (unique.TryGetValue(id, out var duplicate)) RequireExact(duplicate.Exact.Span, node.Exact.Span);
            else unique.Add(id, node);
            if (added.TryGetValue(id, out var existing)) RequireExact(existing.Exact.Span, node.Exact.Span);
        }
        foreach (var pair in unique) added.TryAdd(pair.Key, pair.Value);
        root = replacement.Digest.ToArray();
    }

    /// <summary>
    /// Raw byte commitments only. Returns sorted unique final reachable nodes;
    /// transient path versions are excluded. Existing exact nodes may be returned
    /// for idempotent insertion. The storage insertion/readback owner MUST reject
    /// every pre-existing same-hash/different-byte cell and read back all exact
    /// writes before protected CAS. Unselected storage keys are not probed here.
    /// </summary>
    internal Result Complete()
    {
        var reachable = new Dictionary<string, Did2MessagingArchivePatricia.Node>(StringComparer.Ordinal);
        Visit(root);
        return new(root.ToArray(), reachable.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value).ToArray());
        void Visit(ReadOnlySpan<byte> digest)
        {
            var id = Id(digest);
            if (!added.TryGetValue(id, out var node) || !reachable.TryAdd(id, node)) return;
            if (!node.IsLeaf) { Visit(node.LeftHash); Visit(node.RightHash); }
        }
    }

    internal sealed record Result(ReadOnlyMemory<byte> PatriciaHash, IReadOnlyList<Did2MessagingArchivePatricia.Node> Nodes);

    // Data from this segment's already authenticated paths, never permission.
    internal byte[]? Read(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector)
    {
        _ = ReadPath(family, selector, Did2MessagingArchivePatricia.Key(scope, family, selector), out var value);
        return value;
    }

    private List<Did2MessagingArchivePatricia.Node> ReadPath(Did2MessagingArchiveFamily family,
        ReadOnlySpan<byte> selector, byte[] key, out byte[]? value)
    {
        var path = new List<Did2MessagingArchivePatricia.Node>();
        var expected = root;
        if (!Fixed(expected, EmptyHash(scope)))
        {
            while (true)
            {
                if (path.Count >= Did2MessagingArchivePatricia.MaximumProofNodes) throw Bad();
                ReadOnlyMemory<byte>? raw = added.TryGetValue(Id(expected), out var local) ? local.Exact : resolve(expected);
                if (raw is null) throw new CryptographicException("Messaging archive insertion is missing a named immutable node.");
                var node = Did2MessagingArchivePatricia.Decode(scope, raw.Value.Span);
                if (!Fixed(expected, node.Digest.Span)) throw new CryptographicException("Messaging archive insertion node hash differs.");
                path.Add(node);
                if (node.IsLeaf || !Matches(key, node.KeyOrPrefix, node.Bit)) break;
                expected = (Bit(key, node.Bit) ? node.RightHash : node.LeftHash).ToArray();
            }
        }
        // Reuse the codec's full typed-selector, parent-prefix, edge and depth
        // validation. Divergence is absence only after this exact proof succeeds.
        value = Did2MessagingArchivePatricia.VerifyProof(scope, root, family, selector,
            path.Select(node => node.Exact).ToArray());
        return path;
    }

    private static byte[] Merge(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> prior, ReadOnlySpan<byte> incoming)
    {
        if (family is Did2MessagingArchiveFamily.Operation or Did2MessagingArchiveFamily.Ordinal)
        { RequireExact(prior, incoming); return prior.ToArray(); }
        if (family is Did2MessagingArchiveFamily.FirstIncomingEvent or Did2MessagingArchiveFamily.QualifiedPeerRoute)
        {
            var oldOrdinal = U64(prior, 8); var newOrdinal = U64(incoming, 8);
            if (oldOrdinal == newOrdinal) RequireExact(prior, incoming);
            return (newOrdinal < oldOrdinal ? incoming : prior).ToArray();
        }
        var candidates = new List<(Did2MessagingArchiveReference Ref, byte[] Hash)>();
        Include(prior[..88], family == Did2MessagingArchiveFamily.PeerAuthoredPosition ? prior.Slice(88, 32) : []);
        var secondOffset = family == Did2MessagingArchiveFamily.PeerAuthoredPosition ? 120 : 88;
        if (!Zero(prior.Slice(secondOffset, 88)))
            Include(prior.Slice(secondOffset, 88), family == Did2MessagingArchiveFamily.PeerAuthoredPosition ? prior.Slice(208, 32) : []);
        Include(incoming[..88], family == Did2MessagingArchiveFamily.PeerAuthoredPosition ? incoming.Slice(88, 32) : []);
        candidates.Sort((left, right) => left.Ref.Ordinal.CompareTo(right.Ref.Ordinal));
        var first = candidates[0];
        var second = candidates.Skip(1).FirstOrDefault(candidate =>
            family == Did2MessagingArchiveFamily.IncomingAttachment || !Fixed(first.Hash, candidate.Hash));
        var result = new byte[prior.Length]; first.Ref.Exact.Span.CopyTo(result);
        if (family == Did2MessagingArchiveFamily.PeerAuthoredPosition) first.Hash.CopyTo(result, 88);
        if (second.Ref is not null)
        {
            second.Ref.Exact.Span.CopyTo(result.AsSpan(secondOffset));
            if (family == Did2MessagingArchiveFamily.PeerAuthoredPosition) second.Hash.CopyTo(result, 208);
        }
        return result;

        void Include(ReadOnlySpan<byte> raw, ReadOnlySpan<byte> eventHash)
        {
            var reference = Did2MessagingArchiveReference.Decode(raw, false);
            foreach (var existing in candidates)
            {
                if (Fixed(existing.Ref.Exact.Span, raw)) { RequireExact(existing.Hash, eventHash); return; }
                if (existing.Ref.Ordinal == reference.Ordinal || existing.Ref.RowId == reference.RowId ||
                    Fixed(existing.Ref.Operation, reference.Operation))
                    throw new CryptographicException("Messaging archive observation conflicts with an existing source reference.");
            }
            candidates.Add((reference, eventHash.ToArray()));
        }
    }

    private Did2MessagingArchivePatricia.Node Join(int bit, ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        Did2MessagingArchivePatricia.Branch(scope, bit, prefix, left, right);
    private static void RequireExact(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    { if (!Fixed(expected, actual)) throw new CryptographicException("Messaging archive immutable fact or node conflicts."); }
    private static string Id(ReadOnlySpan<byte> digest) => Convert.ToHexString(digest);
    private static bool Bit(ReadOnlySpan<byte> key, int bit) => (key[bit / 8] & (0x80 >> (bit % 8))) != 0;
    private static bool Matches(ReadOnlySpan<byte> key, ReadOnlySpan<byte> prefix, int count)
    { for (var bit = 0; bit < count; bit++) if (Bit(key, bit) != Bit(prefix, bit)) return false; return true; }
    private static int FirstDifferentBit(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    { for (var bit = 0; bit < 256; bit++) if (Bit(left, bit) != Bit(right, bit)) return bit; throw Bad(); }
    private static byte[] Prefix(ReadOnlySpan<byte> key, int count)
    {
        var prefix = key.ToArray();
        for (var bit = count; bit < 256; bit++) prefix[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        return prefix;
    }
}
