using System.Buffers.Binary;
using System.Security.Cryptography;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Pure closed F7/F8 construction and deterministic merging. A typed fact never
// substitutes for resolving and independently qualifying its actual sources.
internal static class Did2MessagingArchiveRouteFacts
{
    internal static byte[] HistorySelector(byte direction, byte kind, ulong generation)
    {
        var raw = new byte[10]; raw[0] = direction; raw[1] = kind;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(2), generation);
        Did2MessagingArchivePatricia.RequireSelector(Did2MessagingArchiveFamily.RouteHistory, raw); return raw;
    }
    internal static byte[] EndpointSelector(byte direction, ulong generation, ReadOnlySpan<byte> core)
    {
        RequireHash(core); var raw = new byte[42]; raw[0] = 1; raw[1] = direction;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(2), generation); core.CopyTo(raw.AsSpan(10)); return raw;
    }
    internal static byte[] CorrelationSelector(byte tag, ReadOnlySpan<byte> hash)
    {
        RequireHash(hash); var raw = new byte[33]; raw[0] = tag; hash.CopyTo(raw.AsSpan(1));
        Did2MessagingArchivePatricia.RequireSelector(Did2MessagingArchiveFamily.RouteControl, raw); return raw;
    }
    internal static byte[] LatestRequestSelector() => [4, 1];
    internal static byte[] Candidate(Did2RouteHistorySource source, ulong sequence)
    {
        var raw = new byte[224]; source.Exact.Span.CopyTo(raw.AsSpan(120));
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(216), sequence); return raw;
    }
    internal static byte[] Verified(Did2MessagingArchiveReference decision, ReadOnlySpan<byte> identity)
    {
        RequireHash(identity); var raw = new byte[224]; decision.Exact.Span.CopyTo(raw); identity.CopyTo(raw.AsSpan(88)); return raw;
    }
    internal static byte[] Identity(Did2MessagingSessionScope scope, byte direction, bool completed,
        ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third = default)
    {
        if (direction is < 1 or > 2 || (completed ? !third.IsEmpty : third.Length != 32)) throw Bad();
        RequireHash(first); RequireHash(second); if (!completed) RequireHash(third);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(completed ? "Deep/STORE-V2/route-history-C"u8 : "Deep/STORE-V2/route-history-P"u8);
        hash.AppendData([0]); hash.AppendData(scope.Hash); hash.AppendData([direction]);
        hash.AppendData(first); hash.AppendData(second); if (!completed) hash.AppendData(third); return hash.GetHashAndReset();
    }
    internal static byte[] MergeHistory(ReadOnlySpan<byte> previous, ReadOnlySpan<byte> incoming)
    {
        var result = previous.ToArray();
        var oldVerified = Did2MessagingArchiveReference.Decode(previous[..88]);
        var nextVerified = Did2MessagingArchiveReference.Decode(incoming[..88]);
        if (!nextVerified.IsAbsent)
        {
            if (!oldVerified.IsAbsent && !Fixed(previous.Slice(88, 32), incoming.Slice(88, 32)))
                throw new CryptographicException("A distinct verified route identity requires an explicit conflict decision.");
            if (oldVerified.IsAbsent || nextVerified.Ordinal < oldVerified.Ordinal) incoming[..120].CopyTo(result);
            else if (nextVerified.Ordinal == oldVerified.Ordinal && !Fixed(previous[..120], incoming[..120])) throw Bad();
        }
        var oldCandidate = Did2RouteHistorySource.Decode(previous.Slice(120, 96));
        var nextCandidate = Did2RouteHistorySource.Decode(incoming.Slice(120, 96));
        if (!nextCandidate.IsAbsent)
        {
            var oldSequence = U64(previous, 216); var nextSequence = U64(incoming, 216);
            if (oldCandidate.IsAbsent || nextSequence > oldSequence || nextSequence == oldSequence && Earlier(nextCandidate, oldCandidate))
                incoming[120..].CopyTo(result.AsSpan(120));
            else if (nextSequence == oldSequence && nextCandidate.Reference.Ordinal == oldCandidate.Reference.Ordinal &&
                nextCandidate.AtomIndex == oldCandidate.AtomIndex && !Fixed(previous[120..], incoming[120..])) throw Bad();
        }
        return result;
    }
    internal static byte[] MergeControl(ReadOnlySpan<byte> selector, ReadOnlySpan<byte> previous, ReadOnlySpan<byte> incoming)
    {
        if (selector[0] is not (1 or 4))
        {
            if (!Fixed(previous, incoming)) throw new CryptographicException("Route request/response custody has a different immutable original.");
            return previous.ToArray();
        }
        var old = Did2MessagingArchiveReference.Decode(previous[..88], false);
        var next = Did2MessagingArchiveReference.Decode(incoming[..88], false);
        var oldSequence = U64(previous, 88); var nextSequence = U64(incoming, 88);
        if (nextSequence == oldSequence && next.Ordinal == old.Ordinal && !Fixed(previous, incoming)) throw Bad();
        return (nextSequence > oldSequence || nextSequence == oldSequence && next.Ordinal < old.Ordinal ? incoming : previous).ToArray();
    }
    private static bool Earlier(Did2RouteHistorySource left, Did2RouteHistorySource right) =>
        left.Reference.Ordinal < right.Reference.Ordinal || left.Reference.Ordinal == right.Reference.Ordinal && left.AtomIndex < right.AtomIndex;
}
