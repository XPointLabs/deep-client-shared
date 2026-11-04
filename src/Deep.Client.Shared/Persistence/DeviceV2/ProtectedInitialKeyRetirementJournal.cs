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
            if (exact.Length != EntryBytes || exact[0] is not (1 or 2 or 3) || exact[1] is not (1 or 2) ||
                exact[2] != 0 || exact[3] != 0 || BinaryPrimitives.ReadUInt64BigEndian(exact[36..]) > 128 ||
                exact[0] != 3 && BinaryPrimitives.ReadUInt64BigEndian(exact[36..]) == 0)
                throw new InvalidDataException("Initial-key retirement has an invalid closed entry.");
            foreach (var offset in exact[0] == 3 ? new[] { 4, 76, 172 } : new[] { 4, 44, 76, 108, 140, 172 })
                if (exact.Slice(offset, 32).IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("Initial-key retirement has an empty commitment.");
            if (exact[0] != 3 && (exact[0] == 2) != Zero(exact.Slice(204, 32)))
                throw new InvalidDataException("Initial-key retirement has a different preclaim role.");
            if (exact[0] == 3)
            {
                var absent = BinaryPrimitives.ReadUInt64BigEndian(exact[36..]) == 0;
                foreach (var offset in new[] { 44, 108, 140 })
                    if (Zero(exact.Slice(offset, 32)) != absent)
                        throw new InvalidDataException("Cancelled source has mixed absence commitments.");
                if (!absent && Zero(exact.Slice(204, 32)))
                    throw new InvalidDataException("Cancelled source has mixed absence or lost original preclaim commitments.");
            }
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
        internal string Coordinate => Role == 3 ? $"{Role:X2}{Convert.ToHexString(SourceInstance)}{Convert.ToHexString(Intent)}" :
            $"{Role:X2}{Convert.ToHexString(SourceInstance)}{Ordinal:X16}";
        internal Entry Stable() { var result = bytes.ToArray(); result[1] = 2; return new(result); }
    }
    internal sealed record State(ulong Revision, SortedDictionary<string, Entry> Entries)
    {
        internal Entry? Find(byte role, ReadOnlySpan<byte> instance, ulong ordinal)
        {
            var key = $"{role:X2}{Convert.ToHexString(instance)}{ordinal:X16}";
            return Entries.GetValueOrDefault(key);
        }
        internal Entry? FindCancellation(ReadOnlySpan<byte> intent)
        {
            Entry? found = null;
            foreach (var entry in Entries.Values)
                if (entry.Role == 3 && Fixed(entry.Intent, intent))
                {
                    if (found is not null) throw new CryptographicException("Cancelled intent has duplicate source owners.");
                    found = entry;
                }
            return found;
        }
        internal void RequireSourceTip(byte role, ReadOnlySpan<byte> instance, ulong maximumOrdinal)
        {
            foreach (var entry in Entries.Values)
                if ((entry.Role == role || role == 1 && entry.Role == 3) && Fixed(entry.SourceInstance, instance) && entry.Ordinal > maximumOrdinal)
                    throw new CryptographicException("Protected retirement refers to missing source history.");
        }
        internal void RequirePreclaimState(ProtectedDph2PreClaimJournal.State preclaims)
        {
            foreach (var entry in Entries.Values.Where(value => value.Role is 1 or 3))
            {
                var name = Convert.ToHexString(entry.Intent);
                if (entry.Role == 3)
                {
                    if (preclaims.Retired.ContainsKey(name)) throw new CryptographicException("Cancellation cannot borrow transferred preclaim custody.");
                    if (preclaims.Cancelled.TryGetValue(name, out var cancelled))
                    {
                        if (!Fixed(cancelled.BlobHash, entry.PreclaimHash) || !Fixed(cancelled.DraftBinding, entry.ScopeHash))
                            throw new CryptographicException("Cancelled preclaim differs from its independent deletion owner.");
                    }
                    else if (entry.Phase == 2 || (preclaims.Claims.TryGetValue(name, out var pending)
                        ? !Fixed(SHA256.HashData(pending.CanonicalBytes.Span), entry.PreclaimHash) : !Zero(entry.PreclaimHash)))
                        throw new CryptographicException("Cancelled preclaim was lost or resurrected.");
                    continue;
                }
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
            foreach (var pair in preclaims.Cancelled)
                if (!Entries.Values.Any(entry => entry.Role == 3 && Convert.ToHexString(entry.Intent) == pair.Key))
                    throw new CryptographicException("Cancelled preclaim has no independent deletion owner.");
        }
        internal void RequireSource(byte role, ReadOnlySpan<byte> instance, ulong ordinal,
            ReadOnlySpan<byte> recordHash, ReadOnlySpan<byte> metadata, ReadOnlySpan<byte> trsHash,
            ReadOnlySpan<byte> intent, bool live)
        {
            var entry = Find(role, instance, ordinal);
            if (entry is null && role == 1)
            {
                var cancelled = FindCancellation(intent);
                if (cancelled is not null)
                {
                    if (cancelled.Ordinal != ordinal || !Fixed(cancelled.SourceInstance, instance) ||
                        !Fixed(cancelled.RecordHash, recordHash) || !Fixed(cancelled.Basis, SHA256.HashData(metadata)) ||
                        !Fixed(cancelled.TrsHash, trsHash) || cancelled.Phase == 2 && live)
                        throw new CryptographicException("Cancelled initial source was substituted or its keys resurrected.");
                    return;
                }
            }
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
            exact[0] != 2 || exact[1] != 0 || !Fixed(exact.Slice(12, 16), network) ||
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
        var result = new byte[HeaderBytes + state.Entries.Count * EntryBytes]; result[0] = 2;
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
        var sourceCoordinates = new HashSet<string>(StringComparer.Ordinal); var intents = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in state.Entries)
        {
            var entry = pair.Value;
            if (pair.Key != entry.Coordinate || !scopes.Add(Convert.ToHexString(entry.ScopeHash)) ||
                !Zero(entry.Basis) && !bases.Add(Convert.ToHexString(entry.Basis)) ||
                entry.Role is 1 or 3 && !intents.Add(Convert.ToHexString(entry.Intent)) ||
                entry.Ordinal != 0 && !sourceCoordinates.Add($"{(entry.Role == 3 ? 1 : entry.Role):X2}{Convert.ToHexString(entry.SourceInstance)}{entry.Ordinal:X16}"))
                throw new InvalidDataException("Initial-key retirement binding is nonunique.");
        }
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

    internal sealed record SourceSnapshot(State State, IReadOnlyDictionary<string, byte[]?> OwnerHashes);

    // Established ratchets use the durable transfer receipt, not the original
    // source database. This pure selection is consumed only with a fresh
    // native import/ancestry check in the same physical SQL segment.
    internal static Entry CaptureEstablishedProof(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        var state = Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        var role = scope.IsInitiator ? (byte)1 : (byte)2;
        Entry? selected = null;
        foreach (var entry in state.Entries.Values)
        {
            if (entry.Role != role || !Fixed(entry.ScopeHash, scope.Hash)) continue;
            if (selected is not null) throw new CryptographicException("Established native scope has duplicate source retirement proofs.");
            selected = entry;
        }
        if (selected is null || selected.Phase != 2 || !Fixed(selected.Basis, scope.InitialBasis))
            throw new CryptographicException("Established native scope lacks its exact stable source retirement proof.");
        byte[] expectedInstance;
        if (scope.IsInitiator)
        {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            digest.AppendData("Deep/STORE-V2/device-state-key"u8);
            digest.AppendData(scope.Network); digest.AppendData(scope.LocalAccount); digest.AppendData(scope.Instance);
            expectedInstance = digest.GetHashAndReset();
        }
        else expectedInstance = scope.Instance.ToArray();
        if (!Fixed(selected.SourceInstance, expectedInstance))
            throw new CryptographicException("Established native retirement has another original source instance.");
        return new(selected.Exact);
    }

    internal static async Task<State> ReadAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, CancellationToken ct)
        => (await ReadSourceSnapshotCoreAsync(storage, network, account, false, ct).ConfigureAwait(false)).State;

    internal static Task<SourceSnapshot> ReadSourceSnapshotAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, CancellationToken ct)
        => ReadSourceSnapshotCoreAsync(storage, network, account, false, ct);

    internal static Task<SourceSnapshot> ReadArchiveEnrollmentSourceSnapshotAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, CancellationToken ct)
        => ReadSourceSnapshotCoreAsync(storage, network, account, true, ct);

    private static async Task<SourceSnapshot> ReadSourceSnapshotCoreAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, bool archiveEnrollment,
        CancellationToken ct)
    {
        // One independent actual inventory per invocation. The optional stop
        // owners are required/decoded only when this journal contains role3;
        // every matching native floor/history is still read by its real owner.
        string[] slots = [SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
            Slot, ProtectedDid2ContactStartJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot];
        using var custody = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (custody.Count != 4) throw new InvalidDataException("Initial retirement read group has another shape.");
        var registration = custody[0] ?? throw new InvalidDataException("The DID2 SQL key record is absent.");
        var instance = registration.Use(bytes => SqliteDeepIdV2AccountGeneration.ReadAccountInstanceFromRegistration(bytes, network.Span, account.Span));
        try
        {
            var owned = custody[1] ?? throw new InvalidDataException("Protected initial-key retirement journal is missing; explicit reset is required.");
            var result = owned.Use(value => Decode(value, network.Span, account.Span, instance));
            var hashes = Enumerable.Range(0, slots.Length).Select(index => custody[index]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
            var ownerHashes = Enumerable.Range(0, slots.Length).ToDictionary(index => slots[index], index => hashes[index], StringComparer.Ordinal);
            if (result.Entries.Values.Any(entry => entry.Role == 3))
            {
                var scopes = CaptureCancellationOwnerScopes(result, custody[2], custody[3], network, account, instance, archiveEnrollment);
                custody.Dispose();
                var nativeHashes = await RequireCancelledNativeScopesAsync(storage, scopes, ct).ConfigureAwait(false);
                foreach (var pair in nativeHashes) ownerHashes.Add(pair.Key, pair.Value);
                var finalSlots = ownerHashes.Keys.Order(StringComparer.Ordinal).ToArray();
                await RequireExactOwnerHashesAsync(storage, finalSlots, finalSlots.Select(slot => ownerHashes[slot]).ToArray(), ct).ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
            return new(result, ownerHashes);
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }
    internal static async Task<Entry> StageCancellationUnderLeaseAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, Entry candidate, CancellationToken ct)
    {
        if (candidate.Role != 3 || candidate.Phase != 1) throw new InvalidDataException("Only exact pending Initial cancellation may stage.");
        using var raw = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            var state = Decode(before, network.Span, account.Span, instance.Span);
            var prior = state.FindCancellation(candidate.Intent);
            if (prior is not null)
            {
                if (!Fixed(prior.Stable().Exact, candidate.Stable().Exact)) throw new CryptographicException("Cancelled source selection changed.");
                await RequireCancellationOwnersAsync(storage, state, network, account, instance, ct).ConfigureAwait(false);
                return prior;
            }
            state.Entries.Add(candidate.Coordinate, candidate);
            after = Encode(state with { Revision = checked(state.Revision + 1) }, network.Span, account.Span, instance.Span);
            await RequireCancellationOwnersAsync(storage, state, network, account, instance, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            if (!await storage.CompareExchangeAsync(Slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Cancelled source pending conflicted.");
            return candidate;
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }
    internal static async Task CompleteCancellationUnderLeaseAsync(IDeepSecureStorage storage,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, Entry expected, CancellationToken ct)
    {
        using var raw = await storage.ReadOwnedAsync(Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            var state = Decode(before, network.Span, account.Span, instance.Span);
            var pending = state.FindCancellation(expected.Intent);
            if (pending is null || !Fixed(pending.Stable().Exact, expected.Stable().Exact)) throw new CryptographicException("Cancelled source completion changed its pending owner.");
            await RequireCancellationOwnersAsync(storage, state, network, account, instance, ct).ConfigureAwait(false);
            if (pending.Phase == 2) return;
            state.Entries[pending.Coordinate] = pending.Stable();
            after = Encode(state with { Revision = checked(state.Revision + 1) }, network.Span, account.Span, instance.Span);
            ct.ThrowIfCancellationRequested();
            if (!await storage.CompareExchangeAsync(Slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Cancelled source completion conflicted.");
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }
    private static async Task RequireCancellationOwnersAsync(IDeepSecureStorage storage, State state,
        ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        if (!state.Entries.Values.Any(entry => entry.Role == 3)) return;
        string[] slots = [ProtectedDid2ContactStartJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot];
        using var roots = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (roots.Count != 2) throw new InvalidDataException("Initial cancellation owner read group has another shape.");
        var hashes = Enumerable.Range(0, slots.Length).Select(index => roots[index]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
        var scopes = CaptureCancellationOwnerScopes(state, roots[0], roots[1], network, account, instance);
        roots.Dispose();
        await RequireCancelledNativeScopesAsync(storage, scopes, ct).ConfigureAwait(false);
        await RequireExactOwnerHashesAsync(storage, slots, hashes, ct).ConfigureAwait(false);
    }

    private static Did2MessagingSessionScope[] CaptureCancellationOwnerScopes(State state,
        OwnedDeepSecret? draftRoot, OwnedDeepSecret? catalogRoot, ReadOnlyMemory<byte> network,
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, bool archiveEnrollment = false)
    {
        var raw = draftRoot ?? throw new InvalidDataException("Initial cancellation lost its protected draft owner.");
        using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network.Span, account.Span, instance.Span));
        var catalogRaw = catalogRoot ?? throw new InvalidDataException("Initial cancellation lost its protected catalog owner.");
        using var catalog = catalogRaw.Use(bytes => archiveEnrollment ?
            ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, network.Span, account.Span, instance.Span) :
            ProtectedDid2MessagingSessionCatalog.Decode(bytes, network.Span, account.Span, instance.Span));
        return CaptureCancelledNativeScopes(state, drafts, catalog);
    }

    private static async Task RequireExactOwnerHashesAsync(IDeepSecureStorage storage, string[] slots,
        byte[]?[] hashes, CancellationToken ct)
    {
        using var actual = await storage.ReadOwnedBatchAsync(slots, ct).ConfigureAwait(false);
        if (actual.Count != slots.Length) throw new InvalidDataException("Initial retirement owner readback has another shape.");
        for (var index = 0; index < slots.Length; index++)
            if (hashes[index] is { } expected ? actual[index]?.Use(bytes => Fixed(SHA256.HashData(bytes), expected)) != true : actual[index] is not null)
                throw new CryptographicException("Initial retirement owners changed across cancellation source callbacks.");
    }

    // The account opener already decoded these owners and the SQL instance from
    // one authenticated registration group while holding the actual account
    // lease. Reuse only that call-local data, not a cached verification result.
    // Native floor/history reads and every cancellation binding remain mandatory.
    internal static async Task RequireCancellationOwnersUnderLeaseAsync(IDeepSecureStorage storage, State state,
        ProtectedDid2ContactStartJournal.State drafts, ProtectedDid2MessagingSessionCatalog.Snapshot catalog, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var scopes = CaptureCancelledNativeScopes(state, drafts, catalog);
        await RequireCancelledNativeScopesAsync(storage, scopes, ct).ConfigureAwait(false);
    }

    private static Did2MessagingSessionScope[] CaptureCancelledNativeScopes(State state,
        ProtectedDid2ContactStartJournal.State drafts, ProtectedDid2MessagingSessionCatalog.Snapshot catalog)
    {
        var scopes = new List<Did2MessagingSessionScope>();
        foreach (var entry in state.Entries.Values.Where(entry => entry.Role == 3))
        {
            if (!drafts.Entries.TryGetValue(Convert.ToHexString(entry.Intent), out var draft) || !draft.WorkStopped || draft.NativeStopMode != 2 ||
                !Fixed(draft.CancellationBinding, entry.ScopeHash)) throw new CryptographicException("Initial cancellation lost its exact protected stop owner.");
            for (var index = 0; index < catalog.Count; index++)
            {
                var scope = catalog.Scope(index);
                if (!scope.IsInitiator || !Fixed(scope.Conversation, draft.Conversation) || !Fixed(scope.LocalDevice, draft.LocalDevice) ||
                    !Fixed(scope.RemoteAccount, draft.Exact.Slice(64, 32))) continue;
                if (entry.Ordinal == 0 || !Fixed(scope.InitialBasis, entry.Basis) || catalog.Phase(index) != 2)
                    throw new CryptographicException("Cancelled Initial has foreign or unresolved import custody.");
                scopes.Add(Did2MessagingSessionScope.RestoreMetadata(scope.Exact));
            }
        }
        return scopes.ToArray();
    }

    private static async Task<Dictionary<string, byte[]>> RequireCancelledNativeScopesAsync(IDeepSecureStorage storage,
        IReadOnlyList<Did2MessagingSessionScope> scopes, CancellationToken ct)
    {
        var hashes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var scope in scopes)
        {
                var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
                var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
                if (!Fixed(floor.Exact.Span, Did2MessagingFloor.Empty(scope).Exact.Span) ||
                    !Fixed(history.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span))
                    throw new CryptographicException("Pre-session cancellation cannot own a committed native import.");
                hashes[scope.FloorSlot] = SHA256.HashData(floor.Exact.Span);
                hashes[Did2MessagingHistoryCheckpoint.Slot(scope)] = SHA256.HashData(history.Exact.Span);
        }
        return hashes;
    }
    private static bool Zero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact nonzero retirement network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
