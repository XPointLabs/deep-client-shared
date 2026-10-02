using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Identity;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Local protected custody only. The account lease is held by the caller;
// parsing cannot mint current issuer/time, placement or contact authority.
internal static class ProtectedContactRendezvousJournal
{
    internal const string Slot = "deep.store.v2.contact-rendezvous-journal";
    internal const int HeaderBytes = 92, EntryBytes = 602, MaximumIntents = 128;
    internal const int MaximumBytes = HeaderBytes + MaximumIntents * EntryBytes;

    internal sealed class State : IDisposable
    {
        internal SortedDictionary<string, byte[]> Entries { get; } = new(StringComparer.Ordinal);
        public void Dispose()
        {
            foreach (var entry in Entries.Values) CryptographicOperations.ZeroMemory(entry);
            Entries.Clear();
        }
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance)
    {
        using var state = new State();
        return Encode(state, network, account, instance);
    }

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes || exact[0] != 1 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) ||
            !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("The protected rendezvous snapshot is incompatible or has another scope.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2, 2));
        if (count > MaximumIntents || exact.Length != HeaderBytes + count * EntryBytes ||
            BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8)) != (ulong)count + 1)
            throw new InvalidDataException("The protected rendezvous count/revision is noncanonical.");
        var state = new State();
        try
        {
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                var entry = exact.Slice(HeaderBytes + index * EntryBytes, EntryBytes);
                var name = Convert.ToHexString(entry[..32]);
                RequireEntry(entry, network);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Protected rendezvous intents are duplicate or unsorted.");
                state.Entries.Add(name, entry.ToArray());
                previous = name;
            }
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumIntents) throw new IOException("The protected rendezvous journal is full.");
        // Validate everything before allocating a secret-bearing output.
        foreach (var pair in state.Entries)
        {
            RequireEntry(pair.Value, network);
            if (Convert.ToHexString(pair.Value.AsSpan(0, 32)) != pair.Key)
                throw new InvalidDataException("The protected rendezvous intent name differs from its bytes.");
        }
        var exact = new byte[HeaderBytes + state.Entries.Count * EntryBytes];
        exact[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2, 2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4, 8), (ulong)state.Entries.Count + 1);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.Values) { entry.CopyTo(exact, offset); offset += EntryBytes; }
        return exact;
    }

    private static void RequireEntry(ReadOnlySpan<byte> entry, ReadOnlySpan<byte> network)
    {
        if (entry.Length != EntryBytes) throw new InvalidDataException("A protected rendezvous entry has an invalid size.");
        ProtectedDph2PreClaimJournal.RequireIntent(entry[..32]);
        ProtectedDph2PreClaimJournal.RequireIntent(entry.Slice(32, 32));
        var record = ContactCodec.Decode("XUR1", entry[64..]);
        if (!Fixed(record.Field(1).Span, network) ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(4).Span) != 0 ||
            record.Field(5).Span.IndexOfAnyExcept((byte)0) >= 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(record.Field(10).Span) != 7 ||
            !DeepIdentityCrypto.X25519PublicKeyMatchesPrivateScalar(entry.Slice(32, 32), record.Field(9).Span))
            throw new CryptographicException("Protected rendezvous metadata custody differs from its exact record.");
    }

    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact network scope is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
