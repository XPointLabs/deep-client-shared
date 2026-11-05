using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class ProtectedDid2ContactRouteJournal
{
    internal const int MaximumArchivedBytes = 4 * 1024 * 1024;
    internal const int ArchiveReferenceBytes = 104;
    internal sealed class ArchiveReference(byte[] hash, byte[] route, int length, bool retiring = false) : IDisposable
    {
        internal byte[] Hash { get; } = hash;
        internal byte[] Route { get; } = route;
        internal int Length { get; } = length;
        internal bool Retiring { get; set; } = retiring;
        internal byte[]? ReadScope { get; set; }
        public void Dispose() { CryptographicOperations.ZeroMemory(Hash); CryptographicOperations.ZeroMemory(Route); if (ReadScope is not null) CryptographicOperations.ZeroMemory(ReadScope); }
    }

    internal static int WorkingCount(State state) => state.Entries.Keys.Count(name => !state.Archived.ContainsKey(name));
    internal static int ArchivedBytes(State state) => state.Archived.Values.Sum(reference => reference.Length);
    internal static int ErasureScopeBytes(State state) => checked(state.Archived.Values.Count(reference => reference.Retiring) * 32);
    internal static int ReservedBytes(State state) => checked(HeaderBytes + state.Archived.Count * ArchiveReferenceBytes + ErasureScopeBytes(state) +
        state.Entries.Where(pair => !state.Archived.ContainsKey(pair.Key)).Sum(pair => 4 + pair.Value.ReservedBytes));
    internal static string ArchiveSlot(ReadOnlySpan<byte> instance, string name) =>
        "deep.store.v2.contact-route-archive." + Convert.ToHexString(instance) + "." + name;

    // Called only after exact bytes and scope passed AccountRegistrationGrammar.
    // This avoids decoding every working entry again on a tombstone-free reopen.
    internal static bool HasErasureAfterGrammarValidation(ReadOnlySpan<byte> bytes)
    {
        var offset = HeaderBytes;
        for (var index = 0; index < BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]); index++)
            offset = checked(offset + 4 + (int)BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]));
        for (var index = 0; index < bytes[1]; index++, offset += ArchiveReferenceBytes)
            if (bytes[offset + 100] == 3) return true;
        return false;
    }

    private static void ValidateArchive(State state)
    {
        if (state.Archived.Count > MaximumIntents || ArchivedBytes(state) > MaximumArchivedBytes)
            throw new IOException("Protected publication archive capacity is exhausted.");
        if (state.PinnedIntent.Length != 32) throw new InvalidDataException("Publication working owner is malformed.");
        var pinned = Convert.ToHexString(state.PinnedIntent);
        if (state.Archived.Count != 0 && (state.PinnedIntent.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            !state.Entries.TryGetValue(pinned, out var current) || current.Kind != 1))
            throw new InvalidDataException("Publication archive lost its current working owner.");
        foreach (var pair in state.Archived)
        {
            Required32(Convert.FromHexString(pair.Key)); Required32(pair.Value.Hash); Required32(pair.Value.Route);
            if (pair.Value.Retiring != (pair.Value.ReadScope is not null)) throw new InvalidDataException("Publication erasure scope is absent or unexpected.");
            if (pair.Value.ReadScope is { } readScope) Required32(readScope);
            if (pair.Key == pinned || pair.Value.Length is < PrefixBytes or > MaximumEntryBytes)
                throw new InvalidDataException("Publication archive cannot replace current working custody.");
            if (state.Entries.TryGetValue(pair.Key, out var loaded)) RequireArchiveEntry(pair.Key, pair.Value, loaded);
        }
    }

    internal static void RequireArchiveEntry(string name, ArchiveReference reference, Entry entry)
    {
        if (entry.Phase != 7 || entry.Kind != 1 || entry.Exact.Length != reference.Length ||
            name != Convert.ToHexString(entry.Exact[..32]) || !Fixed(SHA256.HashData(entry.Exact), reference.Hash) ||
            !Fixed(ContactRouteClosureCodec.Decode(entry.Record(6).Span).ExactHash.Span, reference.Route))
            throw new CryptographicException("Publication archive differs from its exact protected original.");
    }

    private static void WriteArchiveReferences(State state, Span<byte> bytes)
    {
        var scopes = bytes[(state.Archived.Count * ArchiveReferenceBytes)..];
        foreach (var pair in state.Archived)
        {
            Convert.FromHexString(pair.Key).CopyTo(bytes); pair.Value.Hash.CopyTo(bytes[32..]);
            pair.Value.Route.CopyTo(bytes[64..]); BinaryPrimitives.WriteUInt32BigEndian(bytes[96..], checked((uint)pair.Value.Length));
            bytes[100] = pair.Value.Retiring ? (byte)3 : (byte)0;
            if (pair.Value.Retiring) { pair.Value.ReadScope!.CopyTo(scopes); scopes = scopes[32..]; }
            bytes = bytes[ArchiveReferenceBytes..];
        }
    }

    private static void ReadArchiveReferences(State state, ReadOnlySpan<byte> bytes, int count)
    {
        if (bytes.Length < checked(count * ArchiveReferenceBytes)) throw new InvalidDataException("Publication archive reference framing differs.");
        string? previous = null;
        for (var index = 0; index < count; index++, bytes = bytes[ArchiveReferenceBytes..])
        {
            var name = Convert.ToHexString(bytes[..32]);
            if (previous is not null && string.CompareOrdinal(previous, name) >= 0 || state.Entries.ContainsKey(name) ||
                bytes[100] is not (0 or 3) || bytes.Slice(101, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Publication archive references overlap or are noncanonical.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[96..]);
            if (length is < PrefixBytes or > MaximumEntryBytes) throw new InvalidDataException("Publication archive length is hostile.");
            state.Archived.Add(name, new(bytes.Slice(32, 32).ToArray(), bytes.Slice(64, 32).ToArray(), checked((int)length), bytes[100] == 3)); previous = name;
        }
        if (bytes.Length != ErasureScopeBytes(state)) throw new InvalidDataException("Publication erasure scope framing differs.");
        foreach (var reference in state.Archived.Values.Where(reference => reference.Retiring))
        { reference.ReadScope = bytes[..32].ToArray(); bytes = bytes[32..]; }
        try { ValidateArchive(state); }
        catch (IOException error) { throw new InvalidDataException("Publication archive exceeds its declared quota.", error); }
    }

    // This parser is reachable only through explicit authenticated enrollment.
    // Ordinary admission accepts V11 exclusively, including an empty journal.
    internal static State DecodeForEnrollment(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (bytes.Length > 0 && bytes[0] == Version) return Decode(bytes, network, account, instance);
        Scope(network, account, instance);
        const int oldHeader = 92;
        if (bytes.Length is < oldHeader or > MaximumBytes || bytes[0] != 10 || bytes[1] != 0 ||
            !Fixed(bytes.Slice(12, 16), network) || !Fixed(bytes.Slice(28, 32), account) || !Fixed(bytes.Slice(60, 32), instance))
            throw new InvalidDataException("Publication enrollment requires its exact current owned source.");
        var state = new State(); var offset = oldHeader; var reserved = oldHeader; ulong revision = 1; string? previous = null;
        try
        {
            var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
            if (count > MaximumIntents) throw new InvalidDataException("Publication enrollment count is hostile.");
            for (var index = 0; index < count; index++)
            {
                if (bytes.Length - offset < 4) throw new InvalidDataException("Publication enrollment is truncated.");
                var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
                if (length > MaximumEntryBytes || length > bytes.Length - offset) throw new InvalidDataException("Publication enrollment entry is hostile.");
                var entry = Entry.Decode(bytes.Slice(offset, checked((int)length)), network, account); offset += checked((int)length);
                var name = Convert.ToHexString(entry.Exact[..32]);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                { entry.Dispose(); throw new InvalidDataException("Publication enrollment intents are duplicate or unsorted."); }
                state.Entries.Add(name, entry); previous = name; revision += entry.Phase;
                reserved = checked(reserved + 4 + entry.ReservedBytes);
            }
            if (offset != bytes.Length || reserved > MaximumBytes || BinaryPrimitives.ReadUInt64BigEndian(bytes[4..]) != revision)
                throw new InvalidDataException("Publication enrollment revision or reservation differs.");
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static async Task HydrateAsync(IDeepSecureStorage storage, State state, ReadOnlyMemory<byte> root,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct,
        string? selectedIntent = null, ReadOnlyMemory<byte> selectedRoute = default)
    {
        var references = state.Archived.Where(pair => !pair.Value.Retiring && !state.Entries.ContainsKey(pair.Key) &&
            (selectedIntent is null || pair.Key == selectedIntent) &&
            (selectedRoute.IsEmpty || Fixed(pair.Value.Route, selectedRoute.Span))).ToArray();
        for (var offset = 0; offset < references.Length; offset += 16)
        {
            var group = references.Skip(offset).Take(16).ToArray();
            var slots = group.Select(pair => ArchiveSlot(instance.Span, pair.Key)).ToArray();
            var guards = new Dictionary<string, byte[]?> { [Slot] = SHA256.HashData(root.Span) };
            for (var index = 0; index < group.Length; index++) guards.Add(slots[index], group[index].Value.Hash);
            using var originals = await storage.ReadOwnedGuardedBatchAsync(slots, guards, ct).ConfigureAwait(false);
            for (var index = 0; index < group.Length; index++)
            {
                using var original = originals[index] ?? throw new InvalidDataException("Exact publication archive is absent.");
                var entry = original.Use(bytes => Entry.Decode(bytes, network.Span, account.Span));
                try { RequireArchiveEntry(group[index].Key, group[index].Value, entry); state.Entries.Add(group[index].Key, entry); }
                catch { entry.Dispose(); throw; }
            }
        }
    }

    internal static async Task RequireArchiveCustodyAsync(IDeepSecureStorage storage, OwnedDeepSecret root,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        using var state = root.Use(bytes => Decode(bytes, network.Span, account.Span, instance.Span));
        if (state.Archived.Count == 0) return;
        var guards = new Dictionary<string, byte[]?> { [Slot] = root.Use(bytes => SHA256.HashData(bytes)) };
        foreach (var pair in state.Archived)
        {
            var slot = ArchiveSlot(instance.Span, pair.Key);
            if (!pair.Value.Retiring) { guards.Add(slot, pair.Value.Hash); continue; }
            using var original = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false);
            if (original is not null && !original.Use(bytes => Fixed(SHA256.HashData(bytes), pair.Value.Hash)))
                throw new CryptographicException("Retiring publication original differs from its protected tombstone.");
            guards.Add(slot, original is null ? null : pair.Value.Hash);
        }
        using var checkedCustody = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false);
    }

    internal static IReadOnlyList<DeepSecureStorageWrite> StageArchive(State state, ReadOnlySpan<byte> instance, bool all)
    {
        var copies = new List<DeepSecureStorageWrite>();
        try
        {
            foreach (var pair in state.Entries.ToArray())
            {
                if (!all && ReservedBytes(state) <= MaximumBytes) break;
                if (pair.Value.Phase != 7 || pair.Value.Kind != 1 || state.Archived.ContainsKey(pair.Key) ||
                    pair.Key == Convert.ToHexString(state.PinnedIntent)) continue;
                var nextBytes = checked(ArchivedBytes(state) + pair.Value.Exact.Length);
                if (nextBytes > MaximumArchivedBytes) throw new IOException("Protected publication archive byte capacity is exhausted.");
                var reference = new ArchiveReference(SHA256.HashData(pair.Value.Exact),
                    ContactRouteClosureCodec.Decode(pair.Value.Record(6).Span).ExactHash.ToArray(), pair.Value.Exact.Length);
                state.Archived.Add(pair.Key, reference);
                copies.Add(new(ArchiveSlot(instance, pair.Key), pair.Value.Exact.ToArray()));
            }
            ValidateArchive(state);
            if (ReservedBytes(state) > MaximumBytes) throw new IOException("Protected publication working reservation is exhausted.");
            return copies;
        }
        catch
        {
            foreach (var copy in copies) CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsMemory(copy.Value).Span);
            throw;
        }
    }

    internal static void RequireArchiveSuccessor(State before, State after)
    {
        foreach (var pair in before.Archived)
            if (!after.Archived.TryGetValue(pair.Key, out var reference) || reference.Length != pair.Value.Length || reference.Retiring != pair.Value.Retiring ||
                !Fixed(reference.Hash, pair.Value.Hash) || !Fixed(reference.Route, pair.Value.Route) ||
                (reference.ReadScope is null) != (pair.Value.ReadScope is null) ||
                reference.ReadScope is not null && !Fixed(reference.ReadScope, pair.Value.ReadScope!))
                throw new CryptographicException("Ordinary publication adoption cannot replace immutable archive custody.");
        if (before.PinnedIntent.AsSpan().IndexOfAnyExcept((byte)0) >= 0 && !Fixed(before.PinnedIntent, after.PinnedIntent))
            throw new CryptographicException("Publication working owner cannot change during adoption.");
    }
}
