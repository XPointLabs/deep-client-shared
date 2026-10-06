using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR30/46 common owned MessageCreate/AttachmentOffer command namespace.
// The storage identifier is not a second counter or a legacy wire reader.
internal static class ProtectedDid2DirectTextJournal
{
    internal const string Slot = "deep.store.v2.direct-text-journal";
    internal const int HeaderBytes = 96, PrefixBytes = 524, MaximumEntries = 512, MaximumEventBytes = 16668;
    internal const int FloorBytes = Did2MessagingSessionScope.Bytes + 8, MaximumFloors = MaximumEntries;
    internal const int MaximumBytes = HeaderBytes + (PrefixBytes + FloorBytes) * MaximumEntries + MaximumEventBytes;

    internal sealed class Entry : IDisposable
    {
        private byte[]? bytes;
        private Entry(byte[] bytes) => this.bytes = bytes;
        internal ReadOnlySpan<byte> Exact => bytes ?? throw new ObjectDisposedException(nameof(Entry));
        internal ReadOnlySpan<byte> Operation => Exact[..32];
        internal Did2MessagingSessionScope Scope => Did2MessagingSessionScope.RestoreMetadata(Exact.Slice(32, 404));
        internal ReadOnlySpan<byte> Logical => Exact.Slice(436, 32);
        internal ulong Sequence => BinaryPrimitives.ReadUInt64BigEndian(Exact[468..]);
        internal ulong Created => BinaryPrimitives.ReadUInt64BigEndian(Exact[476..]);
        internal ReadOnlySpan<byte> EventHash => Exact.Slice(484, 32);
        internal bool Pending => Exact[516] == 1;
        internal bool Stored => Exact[516] == 3;
        internal ReadOnlySpan<byte> PendingDmc2 => Exact[PrefixBytes..];
        internal string Position => Convert.ToHexString(Scope.Conversation) + Convert.ToHexString(Scope.LocalDevice);

        internal static Entry Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
        {
            if (exact.Length < PrefixBytes || exact.Length > PrefixBytes + MaximumEventBytes ||
                exact[516] is not (1 or 2 or 3) || exact.Slice(517, 3).IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Protected direct text has an unknown shape.");
            var size = BinaryPrimitives.ReadUInt32BigEndian(exact[520..]);
            if (size != exact.Length - PrefixBytes || (exact[516] != 1 ? size != 0 : size is < 285 or > MaximumEventBytes))
                throw new InvalidDataException("Protected direct text has a noncanonical phase/length.");
            ProtectedDph2PreClaimJournal.RequireIntent(exact[..32]);
            ProtectedDph2PreClaimJournal.RequireIntent(exact.Slice(436, 32));
            ProtectedDph2PreClaimJournal.RequireIntent(exact.Slice(484, 32));
            var scope = Did2MessagingSessionScope.RestoreMetadata(exact.Slice(32, 404));
            var sequence = BinaryPrimitives.ReadUInt64BigEndian(exact[468..]);
            var created = BinaryPrimitives.ReadUInt64BigEndian(exact[476..]);
            if (!Fixed(scope.Network, network) || !Fixed(scope.LocalAccount, account) || !Fixed(scope.Instance, instance) ||
                sequence < (scope.IsInitiator ? 3UL : 4UL) || sequence >= long.MaxValue || created is 0 or > long.MaxValue)
                throw new CryptographicException("Protected direct text differs from its local scope.");
            var result = new Entry(exact.ToArray());
            try { if (result.Pending) result.RequireEvent(result.PendingDmc2); return result; }
            catch { result.Dispose(); throw; }
        }

        internal static Entry Prepare(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation, ParsedDmc2 message)
        {
            ProtectedDph2PreClaimJournal.RequireIntent(operation);
            var exact = message.CanonicalBytes.ToArray();
            var frame = new byte[PrefixBytes + exact.Length];
            try
            {
                operation.CopyTo(frame); scope.Exact.CopyTo(frame.AsSpan(32)); message.LogicalMessageId.Span.CopyTo(frame.AsSpan(436));
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(468), message.SenderClientSequence);
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(476), message.CreatedAtUnixMilliseconds);
                SHA256.HashData(exact, frame.AsSpan(484, 32)); frame[516] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(520), checked((uint)exact.Length)); exact.CopyTo(frame, PrefixBytes);
                return Decode(frame, scope.Network, scope.LocalAccount, scope.Instance);
            }
            finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(frame); }
        }

        internal Entry Stabilize()
        {
            if (!Pending) throw new InvalidOperationException("Only a pending direct command can stabilize.");
            var frame = Exact[..PrefixBytes].ToArray(); frame[516] = 2; frame.AsSpan(520, 4).Clear();
            try { var scope = Scope; return Decode(frame, scope.Network, scope.LocalAccount, scope.Instance); }
            finally { CryptographicOperations.ZeroMemory(frame); }
        }

        internal Entry WithVerifiedStore()
        {
            if (Pending || Stored) throw new InvalidOperationException("Only an authored command can retain Store completion.");
            var frame = Exact.ToArray(); frame[516] = 3;
            try { var scope = Scope; return Decode(frame, scope.Network, scope.LocalAccount, scope.Instance); }
            finally { CryptographicOperations.ZeroMemory(frame); }
        }

        internal void RequireEvent(ReadOnlySpan<byte> exact)
        {
            if (exact.Length is < 285 or > MaximumEventBytes || !Fixed(SHA256.HashData(exact), EventHash) ||
                Pending && !Fixed(exact, PendingDmc2))
                throw new CryptographicException("Direct text differs from its protected command hash.");
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact); var scope = Scope;
            try
            {
                if (parsed.ContentKind is not (Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer) || parsed.Flags != Dmc2Flags.None ||
                    parsed.ExpiresAtUnixMilliseconds != 0 || parsed.ReplyToLogicalMessageId.Length != 0 ||
                    !Fixed(parsed.NetworkId.Span, scope.Network) || !Fixed(parsed.SenderAccountId.Span, scope.LocalAccount) ||
                    !Fixed(parsed.SenderDeviceId.Span, scope.LocalDevice) || !Fixed(parsed.ConversationId.Span, scope.Conversation) ||
                    !Fixed(parsed.LogicalMessageId.Span, Logical) || parsed.SenderClientSequence != Sequence ||
                    parsed.CreatedAtUnixMilliseconds != Created || !Fixed(parsed.CanonicalBytes.Span, exact))
                    throw new CryptographicException("Direct text differs from its protected command scope.");
            }
            finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload offer) offer.Manifest.Dispose(); }
        }
        public void Dispose()
        { var owned = Interlocked.Exchange(ref bytes, null); if (owned is not null) CryptographicOperations.ZeroMemory(owned); }
    }

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        internal SortedDictionary<string, AuthoredFloor> Floors { get; } = new(StringComparer.Ordinal);
        internal Entry? Pending => Entries.Values.SingleOrDefault(entry => entry.Pending);
        internal ulong NextSequence(Did2MessagingSessionScope scope)
        {
            if (!Floors.TryGetValue(Position(scope), out var floor))
                return Baseline(scope);
            if (!Fixed(floor.Scope.Exact, scope.Exact))
                throw new CryptographicException("An authored counter cannot move to another session scope.");
            return floor.NextSequence;
        }
        internal void RequireCapacity(Did2MessagingSessionScope scope)
        {
            if (Entries.Count >= MaximumEntries || !Floors.ContainsKey(Position(scope)) && Floors.Count >= MaximumFloors)
                throw new InvalidOperationException("Protected ordinary custody requires verified compaction; floors cannot be evicted.");
            if (NextSequence(scope) >= long.MaxValue || Revision == ulong.MaxValue)
                throw new InvalidOperationException("The protected authored counter or revision is exhausted.");
        }
        internal void AddPending(Entry entry)
        {
            var scope = entry.Scope; RequireCapacity(scope);
            if (!entry.Pending || Pending is not null || entry.Sequence != NextSequence(scope) ||
                Entries.ContainsKey(Convert.ToHexString(entry.Operation)))
                throw new InvalidDataException("New ordinary work must reserve exactly the protected next sequence.");
            Entries.Add(Convert.ToHexString(entry.Operation), entry);
            Floors[Position(scope)] = new(scope, checked(entry.Sequence + 1));
            Revision = checked(Revision + 1);
        }
        internal void Stabilize(string name)
        {
            var entry = Entries[name];
            var next = entry.Stabilize();
            try { Revision = checked(Revision + 1); Entries[name] = next; entry.Dispose(); }
            catch { next.Dispose(); throw; }
        }
        internal void RetainStore(string name)
        {
            var entry = Entries[name];
            var next = entry.WithVerifiedStore();
            try { Revision = checked(Revision + 1); Entries[name] = next; entry.Dispose(); }
            catch { next.Dispose(); throw; }
        }
        public void Dispose()
        { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); Floors.Clear(); }
    }

    // Scope metadata supplies the actual SQL counter selector after the last
    // working row disappears. It is not session/endpoint or deletion authority.
    internal sealed record AuthoredFloor(Did2MessagingSessionScope Scope, ulong NextSequence);
    internal static string Position(Did2MessagingSessionScope scope) =>
        Convert.ToHexString(scope.Conversation) + Convert.ToHexString(scope.LocalDevice);
    internal static ulong Baseline(Did2MessagingSessionScope scope) => scope.IsInitiator ? 3UL : 4UL;

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes || exact[0] != 3 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance) ||
            exact.Slice(94, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Protected direct text journal has an unknown or foreign header.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        var floorCount = BinaryPrimitives.ReadUInt16BigEndian(exact[92..]);
        if (count > MaximumEntries || floorCount > MaximumFloors || exact.Length < HeaderBytes + floorCount * FloorBytes)
            throw new InvalidDataException("Protected direct text journal exceeds capacity.");
        var state = new State { Revision = BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) };
        try
        {
            var offset = HeaderBytes; string? prior = null;
            for (var i = 0; i < floorCount; i++)
            {
                var scope = Did2MessagingSessionScope.RestoreMetadata(exact.Slice(offset, Did2MessagingSessionScope.Bytes));
                var next = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(offset + Did2MessagingSessionScope.Bytes, 8));
                var position = Position(scope);
                if (!Fixed(scope.Network, network) || !Fixed(scope.LocalAccount, account) || !Fixed(scope.Instance, instance) ||
                    next <= Baseline(scope) || next > long.MaxValue ||
                    prior is not null && string.CompareOrdinal(prior, position) >= 0)
                    throw new InvalidDataException("Protected authored floor is absent, foreign or noncanonical.");
                state.Floors.Add(position, new(scope, next)); prior = position; offset += FloorBytes;
            }
            prior = null;
            var logicals = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < count; i++)
            {
                if (exact.Length - offset < PrefixBytes) throw new InvalidDataException("Protected direct text entry is truncated.");
                var size = BinaryPrimitives.ReadUInt32BigEndian(exact[(offset + 520)..]);
                if (size > MaximumEventBytes || size > exact.Length - offset - PrefixBytes)
                    throw new InvalidDataException("Protected direct text entry exceeds its bound.");
                var entry = Entry.Decode(exact.Slice(offset, PrefixBytes + checked((int)size)), network, account, instance);
                var name = Convert.ToHexString(entry.Operation);
                if (prior is not null && string.CompareOrdinal(prior, name) >= 0 ||
                    !logicals.Add(entry.Position + Convert.ToHexString(entry.Logical)))
                { entry.Dispose(); throw new InvalidDataException("Protected direct text repeats an operation or logical position."); }
                state.Entries.Add(name, entry); prior = name; offset += entry.Exact.Length;
            }
            var pending = state.Entries.Values.Count(e => e.Pending);
            // Revision and counters survive compaction. The current row count
            // cannot reconstruct either lifetime value or authorize a reset.
            var reserved = state.Floors.Values.Aggregate(0UL, (total, floor) =>
                checked(total + floor.NextSequence - Baseline(floor.Scope)));
            var minimumRevision = checked(1UL + checked(2UL * reserved) - checked((ulong)pending) +
                checked((ulong)state.Entries.Values.Count(e => e.Stored)));
            if (offset != exact.Length || pending > 1 || state.Revision < minimumRevision ||
                floorCount == 0 && state.Revision != 1)
                throw new InvalidDataException("Protected direct text journal has a noncanonical revision/pending state.");
            foreach (var group in state.Entries.Values.GroupBy(e => e.Position))
            {
                var ordered = group.OrderBy(e => e.Sequence).ToArray();
                if (!state.Floors.TryGetValue(group.Key, out var floor) ||
                    floor.NextSequence != checked(ordered[^1].Sequence + 1))
                    throw new InvalidDataException("Ordinary working rows lost their independent authored floor.");
                var next = ordered[0].Sequence;
                foreach (var entry in ordered)
                {
                    if (entry.Sequence != next++ || !Fixed(entry.Scope.Exact, floor.Scope.Exact) ||
                        entry.Pending && !ReferenceEquals(entry, ordered[^1]))
                        throw new InvalidDataException("Protected direct text authored positions are not contiguous.");
                }
            }
            return state;
        }
        catch { state.Dispose(); throw; }
    }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries || state.Floors.Count > MaximumFloors)
            throw new InvalidOperationException("Protected direct text requires owned rollover.");
        var exact = new byte[HeaderBytes + state.Floors.Count * FloorBytes + state.Entries.Values.Sum(e => e.Exact.Length)];
        try
        {
            exact[0] = 3; BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), checked((ushort)state.Entries.Count));
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), state.Revision);
            BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), checked((ushort)state.Floors.Count));
            network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
            var offset = HeaderBytes;
            foreach (var pair in state.Floors)
            {
                if (pair.Key != Position(pair.Value.Scope)) throw new InvalidDataException("Authored floor selector changed.");
                pair.Value.Scope.Exact.CopyTo(exact.AsSpan(offset));
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(offset + Did2MessagingSessionScope.Bytes), pair.Value.NextSequence);
                offset += FloorBytes;
            }
            foreach (var pair in state.Entries)
            {
                if (pair.Key != Convert.ToHexString(pair.Value.Operation)) throw new InvalidDataException("Direct text journal key differs from its command.");
                pair.Value.Exact.CopyTo(exact.AsSpan(offset)); offset += pair.Value.Exact.Length;
            }
            using var validated = Decode(exact, network, account, instance); return exact;
        }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || Did2MessagingSessionScope.Zero(network)) throw new ArgumentException("An exact network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
}
