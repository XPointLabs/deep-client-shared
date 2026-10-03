using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Protected local custody only. The actual account owner holds the lease.
// Decoding never establishes current route/issuer or transport authority.
internal static class ProtectedDid2MailboxGrantJournal
{
    internal const string Slot = "deep.store.v2.mailbox-grant-journal";
    // Version 2 admits only selector-bound XMC2/MCG3 custody, including empty state.
    private const byte Version = 2;
    internal const int HeaderBytes = 92, EntryBytes = 1045, MaximumEntries = 128;
    internal const int MaximumBytes = HeaderBytes + MaximumEntries * EntryBytes;
    private const int RequestOffset = 100, ResponseOffset = RequestOffset + 435;

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        internal SortedDictionary<string, byte[]> Entries { get; } = new(StringComparer.Ordinal);
        public void Dispose()
        {
            foreach (var entry in Entries.Values) CryptographicOperations.ZeroMemory(entry);
            Entries.Clear();
        }
    }

    internal static byte[] Scope(ReadOnlySpan<byte> routeHash, ReadOnlySpan<byte> locator, byte domain)
    {
        Required32(routeHash); Required32(locator);
        if (domain is not (1 or 2)) throw new InvalidDataException("Unknown mailbox holder role.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Local/DID2/MailboxHolder/1"u8);
        hash.AppendData(routeHash); hash.AppendData(locator); hash.AppendData(new[] { domain });
        return hash.GetHashAndReset();
    }

    internal static byte[] Pending(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> routeHash,
        AuthoredMailboxGrantRequest request, ReadOnlySpan<byte> network)
    {
        Required32(seed); Required32(routeHash);
        var entry = new byte[EntryBytes];
        try
        {
            Scope(routeHash, request.LocatorHash.Span, (byte)request.Domain).CopyTo(entry, 0);
            seed.CopyTo(entry.AsSpan(32)); routeHash.CopyTo(entry.AsSpan(64)); entry[96] = 1;
            request.ExactXmg1.Span.CopyTo(entry.AsSpan(RequestOffset, 435));
            RequireEntry(entry, network); return entry;
        }
        catch { CryptographicOperations.ZeroMemory(entry); throw; }
    }

    internal static byte[] WithWinner(ReadOnlySpan<byte> pending, ReadOnlySpan<byte> exactXmc2,
        ReadOnlySpan<byte> network)
    {
        RequireEntry(pending, network);
        if (pending[96] != 1 || exactXmc2.Length != 510)
            throw new InvalidDataException("Only a pending grant may adopt one exact success.");
        var entry = pending.ToArray();
        try
        {
            entry[96] = 2; exactXmc2.CopyTo(entry.AsSpan(ResponseOffset));
            RequireEntry(entry, network); return entry;
        }
        catch { CryptographicOperations.ZeroMemory(entry); throw; }
    }

    internal static ReadOnlyMemory<byte> Request(byte[] entry) => entry.AsMemory(RequestOffset, 435);
    internal static ReadOnlyMemory<byte> Response(byte[] entry) => entry.AsMemory(ResponseOffset, 510);
    internal static ReadOnlySpan<byte> Seed(byte[] entry) => entry.AsSpan(32, 32);
    internal static bool HasWinner(byte[] entry) => entry[96] == 2;

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes || exact[0] != Version || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("Mailbox holder custody is incompatible or has a foreign account instance.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2, 2));
        var revision = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        if (count > MaximumEntries || exact.Length != HeaderBytes + count * EntryBytes || revision < (ulong)count + 1)
            throw new InvalidDataException("Mailbox holder custody count/revision is noncanonical.");
        var state = new State { Revision = revision };
        try
        {
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                var entry = exact.Slice(HeaderBytes + index * EntryBytes, EntryBytes);
                RequireEntry(entry, network); var name = Convert.ToHexString(entry[..32]);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Mailbox holder scopes are duplicate or unsorted.");
                state.Entries.Add(name, entry.ToArray()); previous = name;
            }
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries) throw new IOException("Protected mailbox holder custody is full.");
        if (state.Revision < (ulong)state.Entries.Count + 1) throw new InvalidDataException("Mailbox custody revision reversed.");
        foreach (var pair in state.Entries)
        {
            RequireEntry(pair.Value, network);
            if (Convert.ToHexString(pair.Value.AsSpan(0, 32)) != pair.Key)
                throw new InvalidDataException("Mailbox holder scope name differs from its exact entry.");
        }
        var exact = new byte[HeaderBytes + state.Entries.Count * EntryBytes]; exact[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2, 2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4, 8), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.Values) { entry.CopyTo(exact, offset); offset += EntryBytes; }
        return exact;
    }

    private static void RequireEntry(ReadOnlySpan<byte> entry, ReadOnlySpan<byte> network)
    {
        if (entry.Length != EntryBytes || entry[96] is not (1 or 2) || entry.Slice(97, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Mailbox holder custody phase/size is noncanonical.");
        Required32(entry.Slice(32, 32)); Required32(entry.Slice(64, 32));
        var request = ContactCodec.Decode("XMG1", entry.Slice(RequestOffset, 435));
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        if (!Fixed(request.Field(1).Span, network) ||
            !Fixed(entry[..32], Scope(entry.Slice(64, 32), request.Field(3).Span, request.Field(6).Span[0])))
            throw new CryptographicException("Mailbox holder custody differs from its scope.");
        var seed = entry.Slice(32, 32).ToArray();
        try
        {
            var pair = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                if (!Fixed(pair.PublicKey, request.Field(5).Span))
                    throw new CryptographicException("Mailbox holder seed differs from its signed request.");
            }
            finally { CryptographicOperations.ZeroMemory(pair.PrivateKey); }
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
        var response = entry.Slice(ResponseOffset, 510);
        if (entry[96] == 1)
        {
            if (response.IndexOfAnyExcept((byte)0) >= 0) throw new InvalidDataException("Pending mailbox custody contains a winner.");
        }
        else
        {
            var result = ContactCodec.Decode("XMC2", response);
            ContactCodec.ValidateMailboxGrantResultBinding(request, result);
            if (BinaryPrimitives.ReadUInt16BigEndian(result.Field(3).Span) != 1 || !Fixed(result.Field(7).Span, entry.Slice(64, 32)))
                throw new CryptographicException("Mailbox custody winner differs from its exact route.");
        }
    }

    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact network scope is required.");
        Required32(account); Required32(instance);
    }
    private static void Required32(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("An exact nonzero mailbox custody field is required."); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
