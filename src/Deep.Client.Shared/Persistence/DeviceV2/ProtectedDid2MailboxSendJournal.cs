using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Local protected commitment only; never a route, signer or receipt authority.
internal static class ProtectedDid2MailboxSendJournal
{
    internal const string Slot = "deep.store.v2.mailbox-send-journal";
    private const byte Version = 4;
    internal const int HeaderBytes = 96, EntryBytes = 432, MaximumEntries = 512;
    internal const int FloorBytes = 72, MaximumFloors = MaximumEntries;
    internal const int MaximumBytes = HeaderBytes + EntryBytes * MaximumEntries + FloorBytes * MaximumFloors;

    // The grant digest prevents changed claims reusing an enrolled issuer/serial
    // namespace. Neither these local commitments nor a zero counter is authority.
    internal sealed record Floor(byte[] GrantHash, ulong HighestCounter);

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        internal SortedDictionary<string, Floor> Floors { get; } = new(StringComparer.Ordinal);
        internal Entry? Current(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> operation)
        {
            if (!Entries.TryGetValue(Convert.ToHexString(Key(scopeHash, operation)), out var entry)) return null;
            for (var count = 0; count < MaximumEntries; count++)
            {
                if (!entry.HasSuccessor) return entry;
                if (!Entries.TryGetValue(Convert.ToHexString(Key(scopeHash, entry.Successor)), out entry))
                    throw new InvalidDataException("A protected send successor is missing.");
            }
            throw new InvalidDataException("A protected send chain exceeds its fixed bound.");
        }

        // Structural selection only, never outcome or retirement authority.
        // A caller must verify every actual request/Store before removing a chain.
        internal IReadOnlyList<Entry> Chain(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> operation)
        {
            Require32(scopeHash); Require32(operation);
            if (!Entries.TryGetValue(Convert.ToHexString(Key(scopeHash, operation)), out var entry))
                throw new InvalidDataException("The original protected send chain is absent.");
            if (entry.HasPredecessor || !Fixed(entry.Attempt, operation))
                throw new InvalidDataException("A send chain must begin at its original native operation.");
            var result = new List<Entry>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (true)
            {
                if (result.Count >= MaximumEntries || !seen.Add(entry.Name) ||
                    !Fixed(entry.ScopeHash, scopeHash) || !Fixed(entry.Operation, operation))
                    throw new InvalidDataException("A protected send chain is cyclic, foreign or oversized.");
                result.Add(entry);
                if (!entry.HasSuccessor) break;
                if (!Entries.TryGetValue(Convert.ToHexString(Key(scopeHash, entry.Successor)), out var next))
                    throw new InvalidDataException("A protected send successor is missing.");
                RequireLink(entry, next); entry = next;
            }
            var owned = 0;
            foreach (var candidate in Entries.Values)
                if (Fixed(candidate.ScopeHash, scopeHash) && Fixed(candidate.Operation, operation)) owned++;
            if (owned != result.Count) throw new InvalidDataException("Unlinked attempts cannot disappear with a selected send chain.");
            return result;
        }

        internal IReadOnlyList<Entry> RequirePreparedChain(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> operation)
        {
            var chain = Chain(scopeHash, operation);
            foreach (var entry in chain)
            {
                if (!entry.Prepared) throw new IOException("Pending work pins the complete protected send chain.");
                if (MinimumCounter(entry.GrantHash) <= entry.Counter)
                    throw new CryptographicException("Every removed attempt requires its exact prepared request and independent counter floor.");
            }
            return chain;
        }

        internal byte[] ChainCommitment(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> operation)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            // Fixed-width records in authenticated reciprocal order: one bounded
            // plan row commits the complete chain, not merely its root or tail.
            foreach (var entry in Chain(scopeHash, operation)) hash.AppendData(entry.Exact);
            return hash.GetHashAndReset();
        }

        // Structural mutation only. The held owner independently verifies time,
        // original SQL/native custody and a current replacement before encoding.
        internal void LinkSuccessor(Entry predecessor, Entry successor)
        {
            if (Entries.Count >= MaximumEntries) throw new IOException("Protected send attempts are full.");
            if (!Entries.TryGetValue(predecessor.Name, out var actual) ||
                !Fixed(actual.Exact, predecessor.Exact) || actual.HasSuccessor || !actual.Closed ||
                Entries.ContainsKey(successor.Name))
                throw new InvalidDataException("The original closed send cannot acquire this successor.");
            RequireLink(actual, successor);
            var revision = checked(Revision + 1);
            var linked = actual.WithSuccessor(successor.Attempt);
            var adopted = Entry.Decode(successor.Exact);
            Entries[actual.Name] = linked; actual.Dispose(); Entries.Add(adopted.Name, adopted);
            Revision = revision;
        }
        internal void EnrollGrant(MailboxAuthenticatedGrant grant)
        {
            var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
            try { EnrollScope(SHA256.HashData(exact), MailboxCapabilityReplayStateMachine.ComputeScopeKey(
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(exact), MailboxAuthenticatedOperation.Store)); }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        internal void RequireGrant(MailboxAuthenticatedGrant grant)
        {
            var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
            try
            {
                var scope = Convert.ToHexString(MailboxCapabilityReplayStateMachine.ComputeScopeKey(
                    MailboxAuthenticatedCapabilityCodec.DecodeGrant(exact), MailboxAuthenticatedOperation.Store));
                if (!Floors.TryGetValue(scope, out var floor) || !Fixed(floor.GrantHash, SHA256.HashData(exact)))
                    throw new CryptographicException("Mailbox replay namespace has no exact enrolled grant floor.");
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        internal void EnrollScope(ReadOnlySpan<byte> grantHash, ReadOnlySpan<byte> scopeHash)
        {
            Require32(grantHash); Require32(scopeHash);
            var name = Convert.ToHexString(scopeHash);
            if (Floors.TryGetValue(name, out var existing))
            {
                if (!Fixed(existing.GrantHash, grantHash)) throw new CryptographicException("Mailbox replay namespace changed its exact grant.");
                return;
            }
            if (Floors.Count >= MaximumFloors) throw new IOException("Protected mailbox replay floors are full.");
            if (FindFloor(grantHash, required: false) is not null)
                throw new CryptographicException("A mailbox grant cannot enroll another replay namespace.");
            Floors.Add(name, new(grantHash.ToArray(), 0));
        }
        internal ulong MinimumCounter(ReadOnlySpan<byte> grantHash)
        {
            return checked(FindFloor(grantHash)!.Value.Value.HighestCounter + 1);
        }
        internal void AdvanceCounter(ReadOnlySpan<byte> grantHash, ulong counter)
        {
            var pair = FindFloor(grantHash)!.Value;
            if (counter == 0 || counter == ulong.MaxValue || counter <= pair.Value.HighestCounter)
                throw new CryptographicException("Mailbox counter cannot move behind its protected replay floor.");
            Floors[pair.Key] = pair.Value with { HighestCounter = counter };
        }
        private KeyValuePair<string, Floor>? FindFloor(ReadOnlySpan<byte> grantHash, bool required = true)
        {
            Require32(grantHash);
            KeyValuePair<string, Floor>? found = null;
            foreach (var pair in Floors)
                if (Fixed(pair.Value.GrantHash, grantHash))
                {
                    if (found is not null) throw new InvalidDataException("Duplicate protected grant floor.");
                    found = pair;
                }
            if (found is null && required) throw new InvalidDataException("Protected mailbox replay floor is absent; no repair is permitted.");
            return found;
        }
        public void Dispose()
        {
            foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear();
            foreach (var floor in Floors.Values) CryptographicOperations.ZeroMemory(floor.GrantHash); Floors.Clear();
        }
    }

    internal sealed class Entry : IDisposable
    {
        private byte[]? bytes;
        private Entry(byte[] bytes) { this.bytes = bytes; }
        internal ReadOnlySpan<byte> Exact => bytes ?? throw new ObjectDisposedException(nameof(Entry));
        internal string Name => Convert.ToHexString(Exact[..32]);
        internal ReadOnlySpan<byte> ScopeHash => Exact.Slice(32, 32);
        internal ReadOnlySpan<byte> Operation => Exact.Slice(64, 32);
        internal ReadOnlySpan<byte> GrantHash => Exact.Slice(96, 32);
        internal ReadOnlySpan<byte> RouteHash => Exact.Slice(128, 32);
        internal ReadOnlySpan<byte> EnvelopeHash => Exact.Slice(160, 32);
        internal ReadOnlySpan<byte> MailboxOperation => Exact.Slice(192, 16);
        internal ulong Created => U64(Exact.Slice(208));
        internal ulong Expires => U64(Exact.Slice(216));
        internal ReadOnlySpan<byte> BodyHash => Exact.Slice(224, 32);
        internal ulong Counter => U64(Exact.Slice(256));
        internal ReadOnlySpan<byte> MauHash => Exact.Slice(264, 32);
        internal bool Prepared => Exact[296] is 2 or 4;
        internal bool Closed => Exact[296] is 3 or 4;
        internal ReadOnlySpan<byte> Attempt => Exact.Slice(304, 32);
        internal ReadOnlySpan<byte> Predecessor => Exact.Slice(336, 32);
        internal ReadOnlySpan<byte> Successor => Exact.Slice(368, 32);
        internal bool HasPredecessor => !Zero(Predecessor);
        internal bool HasSuccessor => !Zero(Successor);
        internal ulong RetryUntil => U64(Exact.Slice(400));
        internal ulong ClosedAtLower => U64(Exact.Slice(408));
        internal ulong Ordinal => U64(Exact.Slice(416));
        internal ulong AdmissionUntil => U64(Exact.Slice(424));

        internal static Entry Pending(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation,
            ReadOnlySpan<byte> grantHash, ReadOnlySpan<byte> routeHash, MailboxEncryptedEnvelope envelope, ulong? retryUntil = null)
        {
            Require32(operation); Require32(grantHash); Require32(routeHash);
            var retry = retryUntil ?? envelope.ExpiresAtUnixSeconds;
            if (retry <= envelope.CreatedAtUnixSeconds || retry > envelope.ExpiresAtUnixSeconds)
                throw new InvalidDataException("Original application retry deadline is outside its object horizon.");
            var body = MailboxAuthenticatedRequestTranscript.ForStore(envelope).CanonicalRequest.ToArray();
            var record = new byte[EntryBytes];
            Key(scope.Hash, operation).CopyTo(record, 0); scope.Hash.CopyTo(record.AsSpan(32));
            operation.CopyTo(record.AsSpan(64)); grantHash.CopyTo(record.AsSpan(96)); routeHash.CopyTo(record.AsSpan(128));
            SHA256.HashData(envelope.Ciphertext.Span, record.AsSpan(160, 32));
            envelope.OperationId.Span.CopyTo(record.AsSpan(192, 16));
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(208), envelope.CreatedAtUnixSeconds);
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(216), envelope.ExpiresAtUnixSeconds);
            operation.CopyTo(record.AsSpan(304, 32));
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(400), retry);
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(416), 1);
            // Conservative structural ceiling, not authenticated grant authority.
            // The actual owner constrains and independently verifies it.
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(424), retry);
            try { SHA256.HashData(body, record.AsSpan(224, 32)); record[296] = 1; return Decode(record); }
            finally { CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(record); }
        }

        internal Entry WithPrepared(ReadOnlySpan<byte> exactMau, ulong counter)
        {
            if (Prepared || Closed || counter == 0 || exactMau.IsEmpty || exactMau.Length > 70_000)
                throw new InvalidDataException("Only one bounded pending request can adopt a prepared MAU3.");
            var next = Exact.ToArray();
            try
            {
                BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(256), counter);
                SHA256.HashData(exactMau, next.AsSpan(264, 32)); next[296] = 2; return Decode(next);
            }
            finally { CryptographicOperations.ZeroMemory(next); }
        }

        internal Entry WithAdmissionCeiling(ulong admissionUntil)
        {
            if (Prepared || Closed || HasSuccessor || admissionUntil <= Created || admissionUntil > AdmissionUntil)
                throw new InvalidDataException("Original admission cannot be extended or replaced.");
            var next = Exact.ToArray();
            try { BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(424), admissionUntil); return Decode(next); }
            finally { CryptographicOperations.ZeroMemory(next); }
        }

        internal Entry CloseUnknown(ulong authenticatedLower)
        {
            if (Closed || HasSuccessor || authenticatedLower < AdmissionUntil)
                throw new InvalidDataException("Original send admission has not ended or is already closed.");
            var next = Exact.ToArray();
            try
            {
                next[296] = Prepared ? (byte)4 : (byte)3;
                BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(408), authenticatedLower);
                return Decode(next);
            }
            finally { CryptographicOperations.ZeroMemory(next); }
        }

        internal Entry WithSuccessor(ReadOnlySpan<byte> attempt)
        {
            Require32(attempt);
            if (!Closed || HasSuccessor || Fixed(attempt, Attempt))
                throw new InvalidDataException("Only an unlinked closed attempt can retain a successor.");
            var next = Exact.ToArray();
            try { attempt.CopyTo(next.AsSpan(368, 32)); return Decode(next); }
            finally { CryptographicOperations.ZeroMemory(next); }
        }

        internal static Entry SuccessorOf(Entry predecessor, ReadOnlySpan<byte> attempt,
            ReadOnlySpan<byte> grantHash, ReadOnlySpan<byte> routeHash, MailboxEncryptedEnvelope envelope,
            ulong admissionUntil)
        {
            Require32(attempt); Require32(grantHash); Require32(routeHash);
            if (!predecessor.Closed || predecessor.HasSuccessor || Fixed(attempt, predecessor.Operation) ||
                Fixed(attempt, predecessor.Attempt) || Fixed(grantHash, predecessor.GrantHash))
                throw new InvalidDataException("A successor requires a distinct attempt and grant after closure.");
            // Check immutable local transition limits before encoding the wire
            // request. Closure never grants a new object/retry lifetime, even
            // when the proposed envelope would also fail the wire TTL grammar.
            if (envelope.ExpiresAtUnixSeconds != predecessor.Expires ||
                envelope.CreatedAtUnixSeconds < predecessor.ClosedAtLower ||
                envelope.CreatedAtUnixSeconds >= predecessor.RetryUntil ||
                admissionUntil <= envelope.CreatedAtUnixSeconds || admissionUntil > predecessor.RetryUntil ||
                predecessor.Ordinal >= MaximumEntries)
                throw new InvalidDataException("A successor exceeds its original deadline or closure bounds.");
            var body = MailboxAuthenticatedRequestTranscript.ForStore(envelope).CanonicalRequest.ToArray();
            var record = new byte[EntryBytes];
            try
            {
                Key(predecessor.ScopeHash, attempt).CopyTo(record, 0);
                predecessor.ScopeHash.CopyTo(record.AsSpan(32)); predecessor.Operation.CopyTo(record.AsSpan(64));
                grantHash.CopyTo(record.AsSpan(96)); routeHash.CopyTo(record.AsSpan(128));
                SHA256.HashData(envelope.Ciphertext.Span, record.AsSpan(160, 32));
                envelope.OperationId.Span.CopyTo(record.AsSpan(192, 16));
                BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(208), envelope.CreatedAtUnixSeconds);
                BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(216), envelope.ExpiresAtUnixSeconds);
                SHA256.HashData(body, record.AsSpan(224, 32)); record[296] = 1;
                attempt.CopyTo(record.AsSpan(304)); predecessor.Attempt.CopyTo(record.AsSpan(336));
                BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(400), predecessor.RetryUntil);
                BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(416), checked(predecessor.Ordinal + 1));
                BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(424), admissionUntil);
                var successor = Decode(record);
                try { RequireLink(predecessor, successor); return successor; }
                catch { successor.Dispose(); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(record); }
        }

        internal static Entry Decode(ReadOnlySpan<byte> record)
        {
            if (record.Length != EntryBytes || record[296] is not (1 or 2 or 3 or 4) || record.Slice(297, 7).IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Unknown protected mailbox send shape.");
            foreach (var offset in new[] { 0, 32, 64, 96, 128, 160, 224 }) Require32(record.Slice(offset, 32));
            Require32(record.Slice(304, 32));
            var closed = record[296] is 3 or 4; var prepared = record[296] is 2 or 4;
            if (!Fixed(Key(record.Slice(32, 32), record.Slice(304, 32)), record[..32]) ||
                Zero(record.Slice(192, 16)) || U64(record.Slice(208)) == 0 ||
                U64(record.Slice(216)) <= U64(record.Slice(208)) ||
                U64(record.Slice(216)) - U64(record.Slice(208)) is < MailboxClientLimits.MinimumTtlSeconds or > MailboxClientLimits.MaximumTtlSeconds ||
                U64(record.Slice(400)) <= U64(record.Slice(208)) || U64(record.Slice(400)) > U64(record.Slice(216)) ||
                U64(record.Slice(424)) <= U64(record.Slice(208)) || U64(record.Slice(424)) > U64(record.Slice(400)) ||
                U64(record.Slice(416)) is 0 or > MaximumEntries ||
                (closed ? U64(record.Slice(408)) < U64(record.Slice(424)) : U64(record.Slice(408)) != 0 || !Zero(record.Slice(368, 32))) ||
                (Zero(record.Slice(336, 32)) ? U64(record.Slice(416)) != 1 || !Fixed(record.Slice(304, 32), record.Slice(64, 32)) :
                    U64(record.Slice(416)) <= 1 || Fixed(record.Slice(304, 32), record.Slice(64, 32))) ||
                Fixed(record.Slice(304, 32), record.Slice(336, 32)) || Fixed(record.Slice(304, 32), record.Slice(368, 32)) ||
                (prepared ? U64(record.Slice(256)) == 0 || Zero(record.Slice(264, 32)) :
                    U64(record.Slice(256)) != 0 || !Zero(record.Slice(264, 32))))
                throw new InvalidDataException("Protected mailbox send bindings or phase are inconsistent.");
            return new(record.ToArray());
        }
        public void Dispose() { var value = Interlocked.Exchange(ref bytes, null); if (value is not null) CryptographicOperations.ZeroMemory(value); }
    }

    internal static byte[] Key(ReadOnlySpan<byte> scopeHash, ReadOnlySpan<byte> operation)
    {
        Require32(scopeHash); Require32(operation);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Local/DID2/MailboxSend/1"u8); hash.AppendData([0]);
        hash.AppendData(scopeHash); hash.AppendData(operation); return hash.GetHashAndReset();
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length is < HeaderBytes or > MaximumBytes || exact[0] != Version || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance) ||
            exact.Slice(94, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Protected mailbox send custody is absent, foreign or unsupported.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2)); var revision = U64(exact.Slice(4));
        var floors = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(92));
        if (count > MaximumEntries || floors > MaximumFloors ||
            exact.Length != HeaderBytes + floors * FloorBytes + count * EntryBytes || revision < (ulong)Math.Max(count, floors) + 1)
            throw new InvalidDataException("Protected mailbox send count/revision is inconsistent.");
        var state = new State { Revision = revision };
        try
        {
            string? previous = null;
            var grants = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < floors; i++)
            {
                var record = exact.Slice(HeaderBytes + i * FloorBytes, FloorBytes);
                Require32(record[..32]); Require32(record.Slice(32, 32));
                var name = Convert.ToHexString(record[..32]); var high = U64(record.Slice(64));
                if (high == ulong.MaxValue || previous is not null && string.CompareOrdinal(previous, name) >= 0 ||
                    !grants.Add(Convert.ToHexString(record.Slice(32, 32))))
                    throw new InvalidDataException("Protected mailbox replay floor is noncanonical.");
                state.Floors.Add(name, new(record.Slice(32, 32).ToArray(), high)); previous = name;
            }
            previous = null;
            var pending = new HashSet<string>(StringComparer.Ordinal); var counters = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < count; i++)
            {
                var entry = Entry.Decode(exact.Slice(HeaderBytes + floors * FloorBytes + i * EntryBytes, EntryBytes));
                try
                {
                    var name = entry.Name; var grant = Convert.ToHexString(entry.GrantHash);
                    if (state.MinimumCounter(entry.GrantHash) <= entry.Counter)
                        throw new InvalidDataException("Prepared mailbox request exceeds its protected replay floor.");
                    if (previous is not null && string.CompareOrdinal(previous, name) >= 0 ||
                        (entry.Prepared ? !counters.Add(grant + ":" + entry.Counter) : !entry.Closed && !pending.Add(grant)))
                        throw new InvalidDataException("Duplicate protected mailbox key, pending operation or counter.");
                    state.Entries.Add(name, entry); previous = name; entry = null!;
                }
                finally { entry?.Dispose(); }
            }
            foreach (var entry in state.Entries.Values)
            {
                if (entry.HasPredecessor)
                {
                    if (!state.Entries.TryGetValue(Convert.ToHexString(Key(entry.ScopeHash, entry.Predecessor)), out var predecessor) ||
                        !Fixed(predecessor.Successor, entry.Attempt))
                        throw new InvalidDataException("Protected send predecessor/link is missing.");
                    RequireLink(predecessor, entry);
                }
                if (entry.HasSuccessor &&
                    (!state.Entries.TryGetValue(Convert.ToHexString(Key(entry.ScopeHash, entry.Successor)), out var successor) ||
                     !Fixed(successor.Predecessor, entry.Attempt)))
                    throw new InvalidDataException("Protected send successor/link is missing.");
            }
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries || state.Floors.Count > MaximumFloors ||
            state.Revision < (ulong)Math.Max(state.Entries.Count, state.Floors.Count) + 1)
            throw new InvalidDataException("Protected mailbox send capacity/revision is inconsistent.");
        var exact = new byte[HeaderBytes + state.Floors.Count * FloorBytes + state.Entries.Count * EntryBytes]; exact[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), state.Revision);
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), checked((ushort)state.Floors.Count));
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        try
        {
            var offset = HeaderBytes;
            foreach (var pair in state.Floors)
            {
                var scopeHash = Convert.FromHexString(pair.Key); Require32(scopeHash); Require32(pair.Value.GrantHash);
                scopeHash.CopyTo(exact, offset); pair.Value.GrantHash.CopyTo(exact, offset + 32);
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(offset + 64), pair.Value.HighestCounter); offset += FloorBytes;
            }
            foreach (var pair in state.Entries)
            {
                if (pair.Key != pair.Value.Name) throw new InvalidDataException("Protected mailbox send dictionary key changed.");
                pair.Value.Exact.CopyTo(exact.AsSpan(offset)); offset += EntryBytes;
            }
            using var validated = Decode(exact, network, account, instance); return exact;
        }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }

    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { if (network.Length != 16 || Zero(network)) throw new InvalidDataException("Invalid mailbox send network."); Require32(account); Require32(instance); }
    private static void Require32(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || Zero(value)) throw new InvalidDataException("Absent protected mailbox send binding."); }
    private static bool Zero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);

    private static void RequireLink(Entry predecessor, Entry successor)
    {
        if (!predecessor.Closed || !Fixed(successor.Predecessor, predecessor.Attempt) ||
            !Fixed(predecessor.ScopeHash, successor.ScopeHash) || !Fixed(predecessor.Operation, successor.Operation) ||
            !Fixed(predecessor.EnvelopeHash, successor.EnvelopeHash) || Fixed(predecessor.GrantHash, successor.GrantHash) ||
            Fixed(predecessor.MailboxOperation, successor.MailboxOperation) || predecessor.Expires != successor.Expires ||
            predecessor.RetryUntil != successor.RetryUntil || successor.Ordinal != predecessor.Ordinal + 1 ||
            successor.Created < predecessor.ClosedAtLower)
            throw new InvalidDataException("A protected send successor changed its original message or closure.");
    }
}
