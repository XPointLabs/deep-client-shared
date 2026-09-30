using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Sole authoritative protected snapshot, not a SQL hash floor: there is no
// floor-before-SQL gap for pre-XPK1 secrets. Caller holds the account lease.
// Structural decoding grants no authority; Protocol must restore current.
internal static class ProtectedDph2PreClaimJournal
{
    internal const string Slot = "deep.store.v2.dph2-preclaim-journal";
    internal const int HeaderBytes = 92, MaximumIntents = 128;
    private const int EntryBytes = 32 + InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount;
    internal const int MaximumBytes = HeaderBytes + MaximumIntents * EntryBytes;

    internal sealed record State(ulong Revision,
        SortedDictionary<string, InitiatorDph2PreKeyClaimPersistenceBlob> Claims);

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance) => Encode(new(1, new(StringComparer.Ordinal)), network, account, instance);

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes || exact[0] != 1 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) ||
            !Fixed(exact.Slice(60, 32), instance))
            throw new CryptographicException("The protected preclaim journal is incompatible or has a different scope.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2, 2));
        var revision = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        if (count > MaximumIntents || exact.Length != HeaderBytes + count * EntryBytes || revision != (ulong)count + 1)
            throw new InvalidDataException("The protected preclaim journal has no canonical count/revision.");
        var claims = new SortedDictionary<string, InitiatorDph2PreKeyClaimPersistenceBlob>(StringComparer.Ordinal);
        string? previous = null;
        for (var index = 0; index < count; index++)
        {
            var offset = HeaderBytes + index * EntryBytes;
            var id = exact.Slice(offset, 32);
            RequireIntent(id);
            var name = Convert.ToHexString(id);
            if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                throw new InvalidDataException("The protected preclaim intents are duplicate or unsorted.");
            var blob = InitiatorDph2PreKeyClaimPersistenceBlob.Decode(
                exact.Slice(offset + 32, InitiatorDph2PreKeyClaimPersistenceBlob.CanonicalByteCount).ToArray());
            claims.Add(name, blob);
            previous = name;
        }
        return new(revision, claims);
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Claims.Count > MaximumIntents || state.Revision != (ulong)state.Claims.Count + 1)
            throw new InvalidDataException("The protected preclaim count/revision is invalid.");
        var exact = new byte[HeaderBytes + state.Claims.Count * EntryBytes];
        exact[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2, 2), checked((ushort)state.Claims.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4, 8), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        var index = 0;
        foreach (var claim in state.Claims)
        {
            var intent = Convert.FromHexString(claim.Key);
            RequireIntent(intent);
            if (Convert.ToHexString(intent) != claim.Key)
                throw new InvalidDataException("The protected preclaim intent name is noncanonical.");
            var offset = HeaderBytes + index++ * EntryBytes;
            intent.CopyTo(exact, offset);
            claim.Value.CanonicalBytes.Span.CopyTo(exact.AsSpan(offset + 32));
        }
        return exact;
    }

    internal static void RequireIntent(ReadOnlySpan<byte> intent)
    {
        if (intent.Length != 32 || intent.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact nonzero logical intent is required.", nameof(intent));
    }

    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact nonzero network is required.", nameof(network));
        RequireIntent(account); RequireIntent(instance);
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
