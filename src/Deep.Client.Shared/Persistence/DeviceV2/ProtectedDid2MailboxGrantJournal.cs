using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Protected local custody only. The actual account owner holds the lease.
// Decoding never establishes current route/issuer or transport authority.
internal static class ProtectedDid2MailboxGrantJournal
{
    internal const string Slot = "deep.store.v2.mailbox-grant-journal";
    // One current local reader. Prior custody cannot express two-phase late adoption.
    private const byte Version = 5;
    internal const int HeaderBytes = 96, MaximumEntries = 128;
    private const int SelectionBytes = 128, PredecessorOffset = 1045;
    private const int CeilingOffset = 1077, ClosedLowerOffset = 1085, EvidenceOffset = 1097;
    private const int MinimumPolicyBytes = 497, MaximumPolicyBytes = 1169;
    private const int MinimumEntryBytes = EvidenceOffset + MinimumPolicyBytes + ContactRouteClosureCodec.MinimumEncodedBytes;
    private const int MaximumEntryBytes = EvidenceOffset + MaximumPolicyBytes + ContactRouteClosureCodec.MaximumEncodedBytes;
    internal const int MaximumBytes = HeaderBytes + MaximumEntries * (4 + MaximumEntryBytes + SelectionBytes);
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

    internal sealed record Selection(string? Current, string? Pending, string? RetainedTail);
    internal static string Acquisition(byte[] entry) => Convert.ToHexString(SHA256.HashData(Request(entry).Span));
    private static string EntryScope(byte[] entry) => Convert.ToHexString(entry.AsSpan(0, 32));
    private static string? Predecessor(byte[] entry) => NameOrNull(entry.AsSpan(PredecessorOffset, 32));
    private static string? NameOrNull(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0 ? null : Convert.ToHexString(value);

    // Incomplete successors cannot replace current. Only the initial candidate
    // is resumed by ordinary acquisition; renewal adoption has its own owner lane.
    internal static byte[]? AcquisitionForNewWork(State state, string scope)
    {
        if (!state.Selections.TryGetValue(scope, out var selection)) return null;
        if ((selection.Current ?? selection.Pending) is { } name) return state.Entries[name];
        throw new IOException("Closed unresolved mailbox acquisition requires owned settlement; automatic reissuance is forbidden.");
    }

    internal static byte[]? CurrentWinner(State state, string scope) =>
        state.Selections.TryGetValue(scope, out var selection) && selection.Current is { } name
            ? state.Entries[name] : null;

    // Only the held owner calls these transitions. They do not establish issuer authority.
    internal static void AddPending(State state, byte[] entry)
    {
        if (state.Entries.Count >= MaximumEntries) throw new IOException("Protected mailbox holder custody is full.");
        if (entry.Length is < MinimumEntryBytes or > MaximumEntryBytes || entry[96] != 1)
            throw new InvalidDataException("Only an exact pending acquisition can be enrolled.");
        var scope = EntryScope(entry); state.Selections.TryGetValue(scope, out var previous);
        if (HasWinner(entry) || Predecessor(entry) is not null || previous?.Pending is not null)
            throw new InvalidDataException("A scope may have only one exact pending acquisition.");
        var name = Acquisition(entry);
        if (state.Entries.ContainsKey(name)) throw new InvalidDataException("Mailbox acquisition already exists.");
        if (previous?.RetainedTail is { } predecessor)
            Convert.FromHexString(predecessor).CopyTo(entry, PredecessorOffset);
        state.Entries.Add(name, entry);
        state.Selections[scope] = new(previous?.Current, name, previous?.RetainedTail);
    }

    internal static void PromoteWinner(State state, string scope)
    {
        if (!state.Selections.TryGetValue(scope, out var selection) || selection.Pending is not { } pending ||
            !HasWinner(state.Entries[pending]) || Predecessor(state.Entries[pending]) != selection.RetainedTail)
            throw new InvalidDataException("Only an exact pending winner can replace its protected predecessor.");
        state.Selections[scope] = new(pending, null, pending);
    }

    // The codec checks shape only; the held owner independently authenticates
    // lower time before this transition and before protected CAS/read-back.
    internal static byte[] WithClosedUnresolved(ReadOnlySpan<byte> pending, ulong authenticatedLower,
        ReadOnlySpan<byte> network)
    {
        RequireEntry(pending, network);
        if (pending[96] != 1 || authenticatedLower < RequestExpiry(pending))
            throw new InvalidDataException("Only an independently expired pending acquisition may close unresolved.");
        var entry = pending.ToArray(); entry[96] = 3;
        BinaryPrimitives.WriteUInt64BigEndian(entry.AsSpan(ClosedLowerOffset, 8), authenticatedLower);
        return entry;
    }

    internal static void ClosePending(State state, string scope)
    {
        if (!state.Selections.TryGetValue(scope, out var selected) || selected.Pending is not { } name ||
            !IsClosedUnresolved(state.Entries[name]) || Predecessor(state.Entries[name]) != selected.RetainedTail)
            throw new InvalidDataException("Only the exact pending acquisition can close unresolved.");
        state.Selections[scope] = new(selected.Current, null, name);
    }

    internal static byte[] RequireRetainedWinner(State state, string scope, ReadOnlySpan<byte> grantHash)
    {
        Required32(grantHash);
        if (state.Selections.TryGetValue(scope, out var selection))
            for (var name = selection.RetainedTail; name is not null; name = Predecessor(state.Entries[name]))
            {
                var entry = state.Entries[name];
                if (!IsAdoptedWinner(entry)) continue;
                var response = ContactCodec.Decode("XMC2", Response(entry).Span);
                if (Fixed(SHA256.HashData(response.Field(8).Span), grantHash)) return entry;
            }
        throw new CryptographicException("Exact original protected mailbox grant is absent; substitution is forbidden.");
    }

    internal static byte[] RequireLateResultForResume(State state, string scope)
    {
        byte[]? adopted = null;
        if (state.Selections.TryGetValue(scope, out var selection))
            for (var name = selection.RetainedTail; name is not null; name = Predecessor(state.Entries[name]))
            {
                var entry = state.Entries[name];
                if (IsLateCandidate(entry)) return entry;
                if (adopted is null && IsLateAdopted(entry)) adopted = entry;
            }
        return adopted ?? throw new InvalidDataException("No protected late-result continuation exists.");
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

    internal static byte[] Pending(ReadOnlySpan<byte> seed, VerifiedDeepIdV2ContactRouteClosure route,
        AuthoredMailboxGrantRequest request, VerifiedMailboxAuthorityV2 policy, ReadOnlySpan<byte> network)
    {
        Required32(seed); route.Network.EnsureCurrent();
        var exactRoute = route.ExactRouteClosure; var exactPolicy = policy.ExactPma2;
        var routeHash = SHA256.HashData(exactRoute.Span);
        if (!policy.BindsProjection(route.Route.Projection.CanonicalBytes.Span))
            throw new CryptographicException("Original grant policy does not bind the acquisition projection.");
        var entry = new byte[checked(EvidenceOffset + exactPolicy.Length + exactRoute.Length)];
        try
        {
            Scope(routeHash, request.LocatorHash.Span, (byte)request.Domain).CopyTo(entry, 0);
            seed.CopyTo(entry.AsSpan(32)); routeHash.CopyTo(entry.AsSpan(64)); entry[96] = 1;
            request.ExactXmg1.Span.CopyTo(entry.AsSpan(RequestOffset, 435));
            BinaryPrimitives.WriteUInt16BigEndian(entry.AsSpan(1093, 2), checked((ushort)exactPolicy.Length));
            BinaryPrimitives.WriteUInt16BigEndian(entry.AsSpan(1095, 2), checked((ushort)exactRoute.Length));
            exactPolicy.Span.CopyTo(entry.AsSpan(EvidenceOffset));
            exactRoute.Span.CopyTo(entry.AsSpan(EvidenceOffset + exactPolicy.Length));
            BinaryPrimitives.WriteUInt64BigEndian(entry.AsSpan(CeilingOffset, 8), OriginalCeiling(entry));
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

    // Shape only: current issuer/route/time verification belongs to the held
    // account owner. Preserve the closure proof and exact predecessor chain.
    internal static byte[] WithLateWinner(ReadOnlySpan<byte> closed, ReadOnlySpan<byte> exactXmc2,
        ReadOnlySpan<byte> network)
    {
        RequireEntry(closed, network);
        if (closed[96] != 3 || exactXmc2.Length != 510)
            throw new InvalidDataException("Only a closed unresolved acquisition may retain one late success.");
        var entry = closed.ToArray();
        try
        {
            entry[96] = 4; exactXmc2.CopyTo(entry.AsSpan(ResponseOffset));
            RequireEntry(entry, network); return entry;
        }
        catch { CryptographicOperations.ZeroMemory(entry); throw; }
    }

    internal static void AdoptLateWinner(State state, string acquisition)
    {
        if (!state.Entries.TryGetValue(acquisition, out var entry) || entry[96] != 4 ||
            !state.Selections.TryGetValue(EntryScope(entry), out var selected))
            throw new InvalidDataException("Only an exact retained late candidate may be adopted.");
        // The candidate is already retained, never re-enrolled as a fresh
        // request. A newer selected winner/pending candidate is not overwritten.
        RequireSelections(state);
        entry[96] = 5;
        var scope = EntryScope(entry);
        string? latest = null;
        for (var name = selected.RetainedTail; name is not null; name = Predecessor(state.Entries[name]))
            if (IsAdoptedWinner(state.Entries[name])) { latest = name; break; }
        state.Selections[scope] = selected with { Current = latest };
    }

    internal static ReadOnlyMemory<byte> Request(byte[] entry) => entry.AsMemory(RequestOffset, 435);
    internal static ReadOnlyMemory<byte> Response(byte[] entry) => entry.AsMemory(ResponseOffset, 510);
    internal static ReadOnlySpan<byte> Seed(byte[] entry) => entry.AsSpan(32, 32);
    internal static bool HasWinner(byte[] entry) => entry[96] is 2 or 4 or 5;
    internal static bool IsAdoptedWinner(byte[] entry) => entry[96] is 2 or 5;
    internal static bool IsLateCandidate(byte[] entry) => entry[96] == 4;
    internal static bool IsLateAdopted(byte[] entry) => entry[96] == 5;
    internal static bool IsClosedUnresolved(byte[] entry) => entry[96] == 3;
    internal static ulong PossibleGrantExpiry(byte[] entry) => BinaryPrimitives.ReadUInt64BigEndian(entry.AsSpan(CeilingOffset, 8));
    internal static ulong ClosedLower(byte[] entry) => BinaryPrimitives.ReadUInt64BigEndian(entry.AsSpan(ClosedLowerOffset, 8));
    internal static ulong RequestExpiry(ReadOnlySpan<byte> entry) =>
        BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XMG1", entry.Slice(RequestOffset, 435)).Field(10).Span);
    internal static ReadOnlyMemory<byte> OriginalPolicy(byte[] entry) =>
        entry.AsMemory(EvidenceOffset, BinaryPrimitives.ReadUInt16BigEndian(entry.AsSpan(1093, 2)));
    internal static ReadOnlyMemory<byte> OriginalRoute(byte[] entry) =>
        entry.AsMemory(EvidenceOffset + OriginalPolicy(entry).Length, BinaryPrimitives.ReadUInt16BigEndian(entry.AsSpan(1095, 2)));

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
            revision < (ulong)count + 1)
            throw new InvalidDataException("Mailbox holder custody count/revision is noncanonical.");
        var state = new State { Revision = revision };
        try
        {
            string? previous = null; var offset = HeaderBytes;
            for (var index = 0; index < count; index++)
            {
                if (exact.Length - offset < 4) throw new InvalidDataException("Mailbox acquisition framing is truncated.");
                var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset, 4)); offset += 4;
                if (length is < MinimumEntryBytes or > MaximumEntryBytes || length > exact.Length - offset)
                    throw new InvalidDataException("Mailbox acquisition exceeds its original evidence bounds.");
                var entry = exact.Slice(offset, checked((int)length)); offset += checked((int)length);
                RequireEntry(entry, network); var name = Convert.ToHexString(SHA256.HashData(entry.Slice(RequestOffset, 435)));
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Mailbox acquisitions are duplicate or unsorted.");
                state.Entries.Add(name, entry.ToArray()); previous = name;
            }
            if (exact.Length - offset != selectionCount * SelectionBytes)
                throw new InvalidDataException("Mailbox selection framing is noncanonical.");
            previous = null;
            for (var index = 0; index < selectionCount; index++)
            {
                var selected = exact.Slice(offset + index * SelectionBytes, SelectionBytes);
                var name = Convert.ToHexString(selected[..32]);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                    throw new InvalidDataException("Mailbox selections are duplicate or unsorted.");
                state.Selections.Add(name, new(NameOrNull(selected.Slice(32, 32)), NameOrNull(selected.Slice(64, 32)),
                    NameOrNull(selected.Slice(96, 32))));
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
        var exact = new byte[checked(HeaderBytes + state.Entries.Values.Sum(entry => 4 + entry.Length) + state.Selections.Count * SelectionBytes)]; exact[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2, 2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4, 8), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92, 2), checked((ushort)state.Selections.Count));
        var offset = HeaderBytes;
        foreach (var entry in state.Entries.Values)
        {
            BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(offset, 4), checked((uint)entry.Length)); offset += 4;
            entry.CopyTo(exact, offset); offset += entry.Length;
        }
        foreach (var pair in state.Selections)
        {
            Convert.FromHexString(pair.Key).CopyTo(exact, offset);
            if (pair.Value.Current is { } current) Convert.FromHexString(current).CopyTo(exact, offset + 32);
            if (pair.Value.Pending is { } pending) Convert.FromHexString(pending).CopyTo(exact, offset + 64);
            if (pair.Value.RetainedTail is { } tail) Convert.FromHexString(tail).CopyTo(exact, offset + 96);
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
                pair.Value is not { } selected || selected.RetainedTail is null && selected.Pending is null)
                throw new InvalidDataException("Mailbox selection is noncanonical.");
            if (selected.Pending is { } pending)
            {
                Visit(pending, pair.Key);
                if (state.Entries[pending][96] is not (1 or 2) || Predecessor(state.Entries[pending]) != selected.RetainedTail)
                    throw new InvalidDataException("Pending mailbox successor differs from its selected predecessor.");
            }
            string? newestWinner = null;
            for (var name = selected.RetainedTail; name is not null; name = Predecessor(state.Entries[name]))
            {
                Visit(name, pair.Key);
                if (!HasWinner(state.Entries[name]) && !IsClosedUnresolved(state.Entries[name]))
                    throw new InvalidDataException("Retained mailbox history contains an open candidate.");
                if (newestWinner is null && IsAdoptedWinner(state.Entries[name])) newestWinner = name;
            }
            if (selected.Current != newestWinner)
                throw new InvalidDataException("Mailbox current selection differs from its latest retained winner.");
        }
        if (reached.Count != state.Entries.Count) throw new InvalidDataException("Mailbox custody contains unreferenced acquisitions.");

        void Visit(string name, string scope)
        {
            if (!state.Entries.TryGetValue(name, out var entry) || EntryScope(entry) != scope || !reached.Add(name))
                throw new InvalidDataException("Mailbox selection is dangling, cross-scope, cyclic or not a winner.");
            if (HasWinner(entry) && !grants.Add(Convert.ToHexString(SHA256.HashData(
                    ContactCodec.Decode("XMC2", Response(entry).Span).Field(8).Span))))
                throw new InvalidDataException("Mailbox acquisitions contain duplicate grants.");
        }
    }

    private static void RequireEntry(ReadOnlySpan<byte> entry, ReadOnlySpan<byte> network)
    {
        if (entry.Length is < MinimumEntryBytes or > MaximumEntryBytes || entry[96] is not (1 or 2 or 3 or 4 or 5) || entry.Slice(97, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Mailbox holder custody phase/size is noncanonical.");
        Required32(entry.Slice(32, 32)); Required32(entry.Slice(64, 32));
        var ceiling = BinaryPrimitives.ReadUInt64BigEndian(entry.Slice(CeilingOffset, 8));
        var closedLower = BinaryPrimitives.ReadUInt64BigEndian(entry.Slice(ClosedLowerOffset, 8));
        if (ceiling == 0 || ceiling != OriginalCeiling(entry) ||
            (entry[96] is 3 or 4 or 5 ? closedLower < RequestExpiry(entry) : closedLower != 0))
            throw new InvalidDataException("Original issuance ceiling or closed acquisition outcome differs.");
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
        if (entry[96] is 1 or 3)
        {
            if (response.IndexOfAnyExcept((byte)0) >= 0) throw new InvalidDataException("Pending mailbox custody contains a winner.");
        }
        else
        {
            var result = ContactCodec.Decode("XMC2", response);
            ContactCodec.ValidateMailboxGrantResultBinding(request, result);
            if (BinaryPrimitives.ReadUInt16BigEndian(result.Field(3).Span) != 1 || !Fixed(result.Field(7).Span, entry.Slice(64, 32)))
                throw new CryptographicException("Mailbox custody winner differs from its exact route.");
            if (MailboxAuthenticatedCapabilityCodec.DecodeGrant(result.Field(8).Span).ExpiresAtUnixSeconds > ceiling)
                throw new CryptographicException("Mailbox winner exceeds its protected original issuance ceiling.");
        }
    }

    private static ulong OriginalCeiling(ReadOnlySpan<byte> entry)
    {
        var policyLength = BinaryPrimitives.ReadUInt16BigEndian(entry.Slice(1093, 2));
        var routeLength = BinaryPrimitives.ReadUInt16BigEndian(entry.Slice(1095, 2));
        if (policyLength is < MinimumPolicyBytes or > MaximumPolicyBytes ||
            routeLength is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            entry.Length != EvidenceOffset + policyLength + routeLength)
            throw new InvalidDataException("Original grant policy/route evidence framing differs.");
        var policy = ContactCodec.Decode("PMA2", entry.Slice(EvidenceOffset, policyLength));
        var route = ContactRouteClosureCodec.Decode(entry.Slice(EvidenceOffset + policyLength, routeLength));
        var request = ContactCodec.Decode("XMG1", entry.Slice(RequestOffset, 435));
        if (!Fixed(route.ExactHash.Span, entry.Slice(64, 32)) ||
            !Fixed(policy.Field(1).Span, request.Field(1).Span) ||
            !Fixed(route.Reachability.Field(1).Span, request.Field(1).Span) ||
            // Canonical PMT2 decoding verifies the exact PMA2 CoreRef header.
            !Fixed(route.Projection.Field(4).Span[6..], policy.CoreHash.Span) ||
            !Fixed(request.Field(7).Span, ContactCodec.ArtifactReference("PMT2", route.Projection).CanonicalBytes.Span) ||
            !Fixed(request.Field(8).Span, route.Selection.ArtifactHash.Span))
            throw new CryptographicException("Original issuance evidence differs from the exact signed request.");
        static ulong Expiry(ContactRecord record, int tag) => BinaryPrimitives.ReadUInt64BigEndian(record.Field(tag).Span);
        var ceiling = new[] { Expiry(policy, 12), Expiry(route.Reachability, 17), Expiry(route.Authorization, 13),
            Expiry(route.Route, 18), Expiry(route.Successor, 11), Expiry(route.Projection, 12), Expiry(route.Selection, 9) }.Min();
        if (ceiling <= Expiry(request, 9)) throw new InvalidDataException("Original issuance evidence has no possible grant interval.");
        return ceiling;
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
