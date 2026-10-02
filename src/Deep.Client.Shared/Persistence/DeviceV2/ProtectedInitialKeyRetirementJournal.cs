using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0027's key-free deletion manifest. Parsing is not transfer authority.
// Every caller holds the process-independent account lease.
internal static class ProtectedInitialKeyRetirementJournal
{
    internal const string Slot = "deep.store.v2.initial-key-retirements";
    internal const int HeaderBytes = 92, EntryBytes = 236, MaximumEntries = 256;
    internal sealed class Entry
    {
        private readonly byte[] bytes;
        internal Entry(ReadOnlySpan<byte> exact)
        {
            if (exact.Length != EntryBytes || exact[0] is not (1 or 2) || exact[1] is not (1 or 2) ||
                exact[2] != 0 || exact[3] != 0 || BinaryPrimitives.ReadUInt64BigEndian(exact[36..]) is 0 or > 128)
                throw new InvalidDataException("Initial-key retirement has an invalid closed entry.");
            foreach (var offset in new[] { 4, 44, 76, 108, 140, 172 })
                if (exact.Slice(offset, 32).IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("Initial-key retirement has an empty commitment.");
            if ((exact[0] == 2) != (exact.Slice(204, 32).IndexOfAnyExcept((byte)0) < 0))
                throw new InvalidDataException("Initial-key retirement has a different preclaim role.");
            bytes = exact.ToArray();
        }
        internal ReadOnlySpan<byte> Exact => bytes;
        internal byte Role => bytes[0];
        internal byte Phase => bytes[1];
        internal ulong Ordinal => BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(36));
        internal ReadOnlySpan<byte> SourceInstance => bytes.AsSpan(4, 32);
        internal ReadOnlySpan<byte> RecordHash => bytes.AsSpan(44, 32);
        internal ReadOnlySpan<byte> ScopeHash => bytes.AsSpan(76, 32);
        internal ReadOnlySpan<byte> Basis => bytes.AsSpan(108, 32);
        internal ReadOnlySpan<byte> TrsHash => bytes.AsSpan(140, 32);
        internal ReadOnlySpan<byte> Intent => bytes.AsSpan(172, 32);
        internal ReadOnlySpan<byte> PreclaimHash => bytes.AsSpan(204, 32);
        internal string Coordinate => $"{Role:X2}{Convert.ToHexString(SourceInstance)}{Ordinal:X16}";
        internal Entry Stable() { var result = bytes.ToArray(); result[1] = 2; return new(result); }
    }
    internal sealed record State(ulong Revision, SortedDictionary<string, Entry> Entries)
    {
        internal Entry? Find(byte role, ReadOnlySpan<byte> instance, ulong ordinal)
        {
            var key = $"{role:X2}{Convert.ToHexString(instance)}{ordinal:X16}";
            return Entries.GetValueOrDefault(key);
        }
        internal void RequireSourceTip(byte role, ReadOnlySpan<byte> instance, ulong maximumOrdinal)
        {
            foreach (var entry in Entries.Values)
                if (entry.Role == role && Fixed(entry.SourceInstance, instance) && entry.Ordinal > maximumOrdinal)
                    throw new CryptographicException("Protected retirement refers to missing source history.");
        }
        internal void RequirePreclaimState(ProtectedDph2PreClaimJournal.State preclaims)
        {
            foreach (var entry in Entries.Values.Where(value => value.Role == 1))
            {
                var name = Convert.ToHexString(entry.Intent);
                if (preclaims.Retired.TryGetValue(name, out var retired))
                {
                    if (!Fixed(retired.BlobHash, entry.PreclaimHash) || !Fixed(retired.SourceBasis, entry.Basis) || !Fixed(retired.MutableScope, entry.ScopeHash))
                        throw new CryptographicException("Protected preclaim tombstone differs from its retirement.");
                }
                else if (entry.Phase == 2 || !preclaims.Claims.TryGetValue(name, out var live) ||
                    !Fixed(SHA256.HashData(live.CanonicalBytes.Span), entry.PreclaimHash))
                    throw new CryptographicException("Protected preclaim was lost or resurrected after retirement.");
            }
            foreach (var pair in preclaims.Retired)
                if (!Entries.Values.Any(entry => entry.Role == 1 && Convert.ToHexString(entry.Intent) == pair.Key))
                    throw new CryptographicException("Preclaim tombstone has no protected retirement history.");
        }
        internal void RequireSource(byte role, ReadOnlySpan<byte> instance, ulong ordinal,
            ReadOnlySpan<byte> recordHash, ReadOnlySpan<byte> metadata, ReadOnlySpan<byte> trsHash,
            ReadOnlySpan<byte> intent, bool live)
        {
            var entry = Find(role, instance, ordinal);
            if (entry is null)
            {
                if (!live) throw new CryptographicException("Initial state disappeared without protected retirement.");
                return;
            }
            if (!Fixed(entry.RecordHash, recordHash) || !Fixed(entry.Basis, SHA256.HashData(metadata)) ||
                !Fixed(entry.TrsHash, trsHash) || !Fixed(entry.Intent, intent) || entry.Phase == 2 && live)
                throw new CryptographicException("Initial-state retirement differs or erased state was resurrected.");
        }
    }
    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance) =>
        Encode(new(1, new(StringComparer.Ordinal)), network, account, instance);
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > HeaderBytes + MaximumEntries * EntryBytes ||
            exact[0] != 1 || exact[1] != 0 || !Fixed(exact.Slice(12, 16), network) ||
            !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new CryptographicException("Initial-key retirement journal has a different scope/generation.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2, 2));
        if (count > MaximumEntries || exact.Length != HeaderBytes + count * EntryBytes)
            throw new InvalidDataException("Initial-key retirement journal is not bounded/canonical.");
        var entries = new SortedDictionary<string, Entry>(StringComparer.Ordinal);
        string? previous = null;
        for (var index = 0; index < count; index++)
        {
            var entry = new Entry(exact.Slice(HeaderBytes + index * EntryBytes, EntryBytes));
            if (previous is not null && string.CompareOrdinal(previous, entry.Coordinate) >= 0)
                throw new InvalidDataException("Initial-key retirement coordinates are duplicate or unsorted.");
            entries.Add(entry.Coordinate, entry); previous = entry.Coordinate;
        }
        var result = new State(BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8)), entries);
        Validate(result); return result;
    }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance); Validate(state);
        var result = new byte[HeaderBytes + state.Entries.Count * EntryBytes]; result[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(4), state.Revision);
        network.CopyTo(result.AsSpan(12)); account.CopyTo(result.AsSpan(28)); instance.CopyTo(result.AsSpan(60));
        var index = 0; foreach (var entry in state.Entries.Values) entry.Exact.CopyTo(result.AsSpan(HeaderBytes + index++ * EntryBytes));
        return result;
    }
    private static void Validate(State state)
    {
        if (state.Entries.Count > MaximumEntries || state.Revision != 1UL + (ulong)state.Entries.Count +
            (ulong)state.Entries.Values.Count(entry => entry.Phase == 2))
            throw new InvalidDataException("Initial-key retirement revision/cardinality differs.");
        var scopes = new HashSet<string>(StringComparer.Ordinal); var bases = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in state.Entries)
            if (pair.Key != pair.Value.Coordinate || !scopes.Add(Convert.ToHexString(pair.Value.ScopeHash)) ||
                !bases.Add(Convert.ToHexString(pair.Value.Basis)))
                throw new InvalidDataException("Initial-key retirement binding is nonunique.");
    }
    internal static async Task<Entry> StageUnderLeaseAsync(IDeepSecureStorage storage, Did2InitialStateTransfer transfer,
        ReadOnlyMemory<byte> sourceInstance, ulong ordinal, ReadOnlyMemory<byte> recordHash,
        ReadOnlyMemory<byte> intent, ReadOnlyMemory<byte> preclaimHash, CancellationToken ct)
    {
        var scope = transfer.Scope;
        if (sourceInstance.Length != 32 || recordHash.Length != 32 || intent.Length != 32 || preclaimHash.Length != 32)
            throw new ArgumentException("Retirement source fields have different exact widths.");
        var accountInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct).ConfigureAwait(false);
        if (!Fixed(accountInstance, scope.Instance)) throw new CryptographicException("Mutable import has a different account instance.");
        var raw = new byte[EntryBytes]; raw[0] = scope.IsInitiator ? (byte)1 : (byte)2; raw[1] = 1;
        sourceInstance.Span.CopyTo(raw.AsSpan(4, 32)); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(36), ordinal);
        recordHash.Span.CopyTo(raw.AsSpan(44, 32)); scope.Hash.CopyTo(raw.AsSpan(76)); scope.InitialBasis.CopyTo(raw.AsSpan(108));
        transfer.ImportedFloor.RatchetHash.CopyTo(raw.AsSpan(140)); intent.Span.CopyTo(raw.AsSpan(172, 32));
        preclaimHash.Span.CopyTo(raw.AsSpan(204, 32)); var entry = new Entry(raw);
        using var owner = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Retirement root disappeared.");
        var previous = owner.Use(static value => value.ToArray());
        var state = Decode(previous, scope.Network, scope.LocalAccount, scope.Instance);
        var existing = state.Find(entry.Role, entry.SourceInstance, entry.Ordinal);
        if (existing is not null)
        {
            if (!Fixed(existing.Stable().Exact, entry.Stable().Exact)) throw new CryptographicException("Retirement source transfer was substituted.");
            return existing;
        }
        state.Entries.Add(entry.Coordinate, entry);
        var next = Encode(state with { Revision = checked(state.Revision + 1) }, scope.Network, scope.LocalAccount, scope.Instance);
        if (!await storage.CompareExchangeAsync(Slot, previous, next, ct).ConfigureAwait(false))
            throw new CryptographicException("Retirement pending lost its exact protected predecessor.");
        return entry;
    }
    internal static async Task CompleteUnderLeaseAsync(IDeepSecureStorage storage, Did2InitialStateTransfer transfer,
        Entry expected, CancellationToken ct)
    {
        var scope = transfer.Scope;
        using var owner = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Retirement root disappeared.");
        var previous = owner.Use(static value => value.ToArray());
        var state = Decode(previous, scope.Network, scope.LocalAccount, scope.Instance);
        var retained = state.Find(expected.Role, expected.SourceInstance, expected.Ordinal);
        if (retained is null || !Fixed(retained.Stable().Exact, expected.Stable().Exact))
            throw new CryptographicException("Retirement completion differs from its protected source transfer.");
        if (retained.Phase == 2) return;
        state.Entries[retained.Coordinate] = retained.Stable();
        var next = Encode(state with { Revision = checked(state.Revision + 1) }, scope.Network, scope.LocalAccount, scope.Instance);
        if (!await storage.CompareExchangeAsync(Slot, previous, next, ct).ConfigureAwait(false))
            throw new CryptographicException("Retirement stable lost its exact protected pending predecessor.");
    }

    internal static async Task<State> ReadAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, CancellationToken ct)
    {
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, network, account, ct).ConfigureAwait(false);
        using var owned = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected initial-key retirement journal is missing; explicit reset is required.");
        return owned.Use(value => Decode(value, network.Span, account.Span, instance));
    }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact nonzero retirement network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
