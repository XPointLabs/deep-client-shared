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
    // One current local reader; generation 2 scope-overwrite custody is retired.
    private const byte Version = 3;
    internal const int HeaderBytes = 96, EntryBytes = 1077, MaximumEntries = 128;
    private const int SelectionBytes = 96, PredecessorOffset = 1045;
    internal const int MaximumBytes = HeaderBytes + MaximumEntries * (EntryBytes + SelectionBytes);
    private const int RequestOffset = 100, ResponseOffset = RequestOffset + 435;

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        // Keys are SHA256(exact XMG1), the existing XMC2 request binding.
        internal SortedDictionary<string, byte[]> Entries { get; } = new(StringComparer.Ordinal);
        internal SortedDictionary<string, Selection> Selections { get; } = new(StringComparer.Ordinal);
        public void Dispose()
        {
            foreach (var entry in Entries.Values) CryptographicOperations.ZeroMemory(entry);
            Entries.Clear();
            Selections.Clear();
        }
    }

    internal sealed record Selection(string? Current, string? Pending);
    internal static string Acquisition(byte[] entry) => Convert.ToHexString(SHA256.HashData(Request(entry).Span));
    private static string EntryScope(byte[] entry) => Convert.ToHexString(entry.AsSpan(0, 32));
    private static string? Predecessor(byte[] entry) => NameOrNull(entry.AsSpan(PredecessorOffset, 32));
    private static string? NameOrNull(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0 ? null : Convert.ToHexString(value);

    // Incomplete successors cannot replace current. Only the initial candidate
    // is resumed by ordinary acquisition; renewal adoption has its own owner lane.
    internal static byte[]? AcquisitionForNewWork(State state, string scope) =>
        state.Selections.TryGetValue(scope, out var selection)
            ? state.Entries[selection.Current ?? selection.Pending!]
            : null;

    internal static byte[]? CurrentWinner(State state, string scope) =>
        state.Selections.TryGetValue(scope, out var selection) && selection.Current is { } name
            ? state.Entries[name] : null;

    // Only the held owner calls these transitions. They do not establish issuer authority.
    internal static void AddPending(State state, byte[] entry)
    {
        if (state.Entries.Count >= MaximumEntries) throw new IOException("Protected mailbox holder custody is full.");
        if (entry.Length != EntryBytes || entry[96] != 1)
            throw new InvalidDataException("Only an exact pending acquisition can be enrolled.");
        var scope = EntryScope(entry); state.Selections.TryGetValue(scope, out var previous);
        if (HasWinner(entry) || Predecessor(entry) is not null || previous?.Pending is not null)
            throw new InvalidDataException("A scope may have only one exact pending acquisition.");
        var name = Acquisition(entry);
        if (state.Entries.ContainsKey(name)) throw new InvalidDataException("Mailbox acquisition already exists.");
        if (previous?.Current is { } predecessor)
            Convert.FromHexString(predecessor).CopyTo(entry, PredecessorOffset);
        state.Entries.Add(name, entry);
        state.Selections[scope] = new(previous?.Current, name);
    }

    internal static void PromoteWinner(State state, string scope)
    {
        if (!state.Selections.TryGetValue(scope, out var selection) || selection.Pending is not { } pending ||
            !HasWinner(state.Entries[pending]) || Predecessor(state.Entries[pending]) != selection.Current)
            throw new InvalidDataException("Only an exact pending winner can replace its protected predecessor.");
        state.Selections[scope] = new(pending, null);
    }

    internal static byte[] RequireRetainedWinner(State state, string scope, ReadOnlySpan<byte> grantHash)
    {
        Required32(grantHash);
        if (state.Selections.TryGetValue(scope, out var selection))
            for (var name = selection.Current; name is not null; name = Predecessor(state.Entries[name]))
            {
                var entry = state.Entries[name];
                var response = ContactCodec.Decode("XMC2", Response(entry).Span);
                if (Fixed(SHA256.HashData(response.Field(8).Span), grantHash)) return entry;
            }
        throw new CryptographicException("Exact original protected mailbox grant is absent; substitution is forbidden.");
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
        var selectionCount = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(92, 2));
        var revision = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        if (count > MaximumEntries || selectionCount > count || exact.Slice(94, 2).IndexOfAnyExcept((byte)0) >= 0 ||
            exact.Length != HeaderBytes + count * EntryBytes + selectionCount * SelectionBytes || revision < (ulong)count + 1)
            throw new InvalidDataException("Mailbox holder custody count/revision is noncanonical.");
        var state = new State { Revision = revision };
        try
        {
            string? previous = null;
            for (var index = 0; index < count; index++)
            {
                var entry = exact.Slice(HeaderBytes + index * EntryBytes, EntryBytes);
                RequireEntry(entry, network); var name = Convert.ToHexString(SHA256.HashData(entry.Slice(RequestOffset, 435)));
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Mailbox acquisitions are duplicate or unsorted.");
                state.Entries.Add(name, entry.ToArray()); previous = name;
            }
            previous = null;
            for (var index = 0; index < selectionCount; index++)
            {
                var selected = exact.Slice(HeaderBytes + count * EntryBytes + index * SelectionBytes, SelectionBytes);
                var name = Convert.ToHexString(selected[..32]);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Mailbox selections are duplicate or unsorted.");
                state.Selections.Add(name, new(NameOrNull(selected.Slice(32, 32)), NameOrNull(selected.Slice(64, 32))));
                previous = name;
            }
            RequireSelections(state);
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
            if (Acquisition(pair.Value) != pair.Key)
                throw new InvalidDataException("Mailbox acquisition name differs from its exact request.");
        }
        RequireSelections(state);
        var exact = new byte[HeaderBytes + state.Entries.Count * EntryBytes + state.Selections.Count * SelectionBytes]; exact[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2, 2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4, 8), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92, 2), checked((ushort)state.Selections.Count));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.Values) { entry.CopyTo(exact, offset); offset += EntryBytes; }
        foreach (var pair in state.Selections)
        {
            Convert.FromHexString(pair.Key).CopyTo(exact, offset);
            if (pair.Value.Current is { } current) Convert.FromHexString(current).CopyTo(exact, offset + 32);
            if (pair.Value.Pending is { } pending) Convert.FromHexString(pending).CopyTo(exact, offset + 64);
            offset += SelectionBytes;
        }
        return exact;
    }

    private static void RequireSelections(State state)
    {
        var reached = new HashSet<string>(StringComparer.Ordinal);
        var grants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in state.Selections)
        {
            if (pair.Key.Length != 64 || pair.Key.Any(value => value is not (>= '0' and <= '9') and not (>= 'A' and <= 'F')) ||
                pair.Value is not { } selected || selected.Current is null && selected.Pending is null)
                throw new InvalidDataException("Mailbox selection is noncanonical.");
            if (selected.Pending is { } pending)
            {
                Visit(pending, pair.Key, requireWinner: false);
                if (Predecessor(state.Entries[pending]) != selected.Current)
                    throw new InvalidDataException("Pending mailbox successor differs from its selected predecessor.");
            }
            for (var name = selected.Current; name is not null; name = Predecessor(state.Entries[name]))
                Visit(name, pair.Key, requireWinner: true);
        }
        if (reached.Count != state.Entries.Count) throw new InvalidDataException("Mailbox custody contains unreferenced acquisitions.");

        void Visit(string name, string scope, bool requireWinner)
        {
            if (!state.Entries.TryGetValue(name, out var entry) || EntryScope(entry) != scope || !reached.Add(name) ||
                requireWinner && !HasWinner(entry))
                throw new InvalidDataException("Mailbox selection is dangling, cross-scope, cyclic or not a winner.");
            if (HasWinner(entry) && !grants.Add(Convert.ToHexString(SHA256.HashData(
                    ContactCodec.Decode("XMC2", Response(entry).Span).Field(8).Span))))
                throw new InvalidDataException("Mailbox acquisitions contain duplicate grants.");
        }
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
