using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0027 clean-break snapshot. A retired intent remains permanently reserved.
// Decoding grants neither native preparation nor source-deletion authority.
internal static class ProtectedDph2PreClaimJournal
{
    internal const string Slot = "deep.store.v2.dph2-preclaim-journal";
    internal const int HeaderBytes = 92, EntryHeaderBytes = 136, MaximumIntents = 128;
    internal const int MaximumBytes = HeaderBytes + MaximumIntents *
        (EntryHeaderBytes + InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount);
    internal sealed record Tombstone(byte[] BlobHash, byte[] SourceBasis, byte[] MutableScope);
    internal sealed record State(ulong Revision, SortedDictionary<string, InitiatorDph2PreKeyClaimPersistenceBlob> Claims)
    {
        internal SortedDictionary<string, Tombstone> Retired { get; init; } = new(StringComparer.Ordinal);
        internal int Count => Claims.Count + Retired.Count;
    }
    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance) =>
        Encode(new(1, new(StringComparer.Ordinal)), network, account, instance);
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes || exact[0] != 2 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new CryptographicException("The protected preclaim journal has a different closed generation/scope.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2, 2));
        if (count > MaximumIntents) throw new InvalidDataException("Protected preclaim count exceeds its bound.");
        var state = new State(BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8)), new(StringComparer.Ordinal));
        var offset = HeaderBytes; string? previous = null;
        for (var index = 0; index < count; index++)
        {
            if (exact.Length - offset < EntryHeaderBytes) throw new InvalidDataException("Protected preclaim entry is truncated.");
            var header = exact.Slice(offset, EntryHeaderBytes); RequireIntent(header[..32]);
            var name = Convert.ToHexString(header[..32]);
            if (previous is not null && string.CompareOrdinal(previous, name) >= 0 || header[32] is not (1 or 2) ||
                header.Slice(33, 3).IndexOfAnyExcept((byte)0) >= 0 || Zero(header.Slice(36, 32)))
                throw new InvalidDataException("Protected preclaim intent/order/status is invalid.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(header[132..]); offset += EntryHeaderBytes;
            if (header[32] == 1)
            {
                if (length != InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount || exact.Length - offset < length ||
                    !Zero(header.Slice(68, 64))) throw new InvalidDataException("Live preclaim entry has a different shape.");
                var body = exact.Slice(offset, checked((int)length));
                if (!Fixed(SHA256.HashData(body), header.Slice(36, 32)))
                    throw new CryptographicException("Protected preclaim blob digest differs.");
                state.Claims.Add(name, InitiatorDph2PreKeyClaimPersistenceBlob.Decode(body.ToArray()));
                offset += checked((int)length);
            }
            else
            {
                if (length != 0 || Zero(header.Slice(68, 32)) || Zero(header.Slice(100, 32)))
                    throw new InvalidDataException("Retired preclaim entry contains keys or no transfer binding.");
                state.Retired.Add(name, new(header.Slice(36, 32).ToArray(), header.Slice(68, 32).ToArray(), header.Slice(100, 32).ToArray()));
            }
            previous = name;
        }
        if (offset != exact.Length) throw new InvalidDataException("Protected preclaim snapshot has trailing bytes.");
        Validate(state); return state;
    }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance); Validate(state);
        var exact = new byte[HeaderBytes + state.Count * EntryHeaderBytes +
            state.Claims.Count * InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount]; exact[0] = 2;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), checked((ushort)state.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        var offset = HeaderBytes;
        foreach (var name in state.Claims.Keys.Concat(state.Retired.Keys).Order(StringComparer.Ordinal))
        {
            var intent = Convert.FromHexString(name); RequireIntent(intent);
            if (Convert.ToHexString(intent) != name) throw new InvalidDataException("Protected preclaim intent name is noncanonical.");
            var header = exact.AsSpan(offset, EntryHeaderBytes); intent.CopyTo(header); offset += EntryHeaderBytes;
            if (state.Claims.TryGetValue(name, out var blob))
            {
                header[32] = 1; SHA256.HashData(blob.CanonicalBytes.Span).CopyTo(header[36..]);
                BinaryPrimitives.WriteUInt32BigEndian(header[132..], checked((uint)blob.CanonicalBytes.Length));
                blob.CanonicalBytes.Span.CopyTo(exact.AsSpan(offset)); offset += blob.CanonicalBytes.Length;
            }
            else
            {
                var retired = state.Retired[name]; header[32] = 2;
                retired.BlobHash.CopyTo(header[36..]); retired.SourceBasis.CopyTo(header[68..]); retired.MutableScope.CopyTo(header[100..]);
            }
        }
        return exact;
    }
    private static void Validate(State state)
    {
        if (state.Count > MaximumIntents || state.Revision != 1UL + (ulong)state.Count + (ulong)state.Retired.Count ||
            state.Claims.Keys.Intersect(state.Retired.Keys, StringComparer.Ordinal).Any())
            throw new InvalidDataException("Protected preclaim count/revision or intent reservation differs.");
        foreach (var value in state.Retired.Values)
        { RequireIntent(value.BlobHash); RequireIntent(value.SourceBasis); RequireIntent(value.MutableScope); }
    }
    internal static void RequireIntent(ReadOnlySpan<byte> intent)
    {
        if (intent.Length != 32 || Zero(intent)) throw new ArgumentException("An exact nonzero logical intent is required.", nameof(intent));
    }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || Zero(network)) throw new ArgumentException("An exact nonzero network is required.");
        RequireIntent(account); RequireIntent(instance);
    }
    private static bool Zero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
