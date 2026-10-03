using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Local protected commitment only; never a route, signer or receipt authority.
internal static class ProtectedDid2MailboxSendJournal
{
    internal const string Slot = "deep.store.v2.mailbox-send-journal";
    private const byte Version = 2;
    internal const int HeaderBytes = 92, EntryBytes = 304, MaximumEntries = 512;
    internal const int MaximumBytes = HeaderBytes + EntryBytes * MaximumEntries;

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        internal ulong MinimumCounter(ReadOnlySpan<byte> grantHash)
        {
            ulong maximum = 0;
            foreach (var entry in Entries.Values)
                if (entry.Prepared && Fixed(entry.GrantHash, grantHash)) maximum = Math.Max(maximum, entry.Counter);
            return checked(maximum + 1);
        }
        public void Dispose() { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); }
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
        internal bool Prepared => Exact[296] == 2;

        internal static Entry Pending(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation,
            ReadOnlySpan<byte> grantHash, ReadOnlySpan<byte> routeHash, MailboxEncryptedEnvelope envelope)
        {
            Require32(operation); Require32(grantHash); Require32(routeHash);
            var body = MailboxAuthenticatedRequestTranscript.ForStore(envelope).CanonicalRequest.ToArray();
            var record = new byte[EntryBytes];
            Key(scope.Hash, operation).CopyTo(record, 0); scope.Hash.CopyTo(record.AsSpan(32));
            operation.CopyTo(record.AsSpan(64)); grantHash.CopyTo(record.AsSpan(96)); routeHash.CopyTo(record.AsSpan(128));
            SHA256.HashData(envelope.Ciphertext.Span, record.AsSpan(160, 32));
            envelope.OperationId.Span.CopyTo(record.AsSpan(192, 16));
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(208), envelope.CreatedAtUnixSeconds);
            BinaryPrimitives.WriteUInt64BigEndian(record.AsSpan(216), envelope.ExpiresAtUnixSeconds);
            try { SHA256.HashData(body, record.AsSpan(224, 32)); record[296] = 1; return Decode(record); }
            finally { CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(record); }
        }

        internal Entry WithPrepared(ReadOnlySpan<byte> exactMau, ulong counter)
        {
            if (Prepared || counter == 0 || exactMau.IsEmpty || exactMau.Length > 70_000)
                throw new InvalidDataException("Only one bounded pending request can adopt a prepared MAU3.");
            var next = Exact.ToArray();
            try
            {
                BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(256), counter);
                SHA256.HashData(exactMau, next.AsSpan(264, 32)); next[296] = 2; return Decode(next);
            }
            finally { CryptographicOperations.ZeroMemory(next); }
        }

        internal static Entry Decode(ReadOnlySpan<byte> record)
        {
            if (record.Length != EntryBytes || record[296] is not (1 or 2) || record[297..].IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Unknown protected mailbox send shape.");
            foreach (var offset in new[] { 0, 32, 64, 96, 128, 160, 224 }) Require32(record.Slice(offset, 32));
            if (!Fixed(Key(record.Slice(32, 32), record.Slice(64, 32)), record[..32]) ||
                Zero(record.Slice(192, 16)) || U64(record.Slice(208)) == 0 ||
                U64(record.Slice(216)) <= U64(record.Slice(208)) ||
                U64(record.Slice(216)) - U64(record.Slice(208)) is < MailboxClientLimits.MinimumTtlSeconds or > MailboxClientLimits.MaximumTtlSeconds ||
                (record[296] == 1 ? U64(record.Slice(256)) != 0 || !Zero(record.Slice(264, 32)) :
                    U64(record.Slice(256)) == 0 || Zero(record.Slice(264, 32))))
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
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("Protected mailbox send custody is absent, foreign or unsupported.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(2)); var revision = U64(exact.Slice(4));
        if (count > MaximumEntries || exact.Length != HeaderBytes + count * EntryBytes || revision < (ulong)count + 1)
            throw new InvalidDataException("Protected mailbox send count/revision is inconsistent.");
        var state = new State { Revision = revision };
        try
        {
            string? previous = null;
            var pending = new HashSet<string>(StringComparer.Ordinal); var counters = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < count; i++)
            {
                var entry = Entry.Decode(exact.Slice(HeaderBytes + i * EntryBytes, EntryBytes));
                try
                {
                    var name = entry.Name; var grant = Convert.ToHexString(entry.GrantHash);
                    if (previous is not null && string.CompareOrdinal(previous, name) >= 0 ||
                        (entry.Prepared ? !counters.Add(grant + ":" + entry.Counter) : !pending.Add(grant)))
                        throw new InvalidDataException("Duplicate protected mailbox key, pending operation or counter.");
                    state.Entries.Add(name, entry); previous = name; entry = null!;
                }
                finally { entry?.Dispose(); }
            }
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries || state.Revision < (ulong)state.Entries.Count + 1)
            throw new InvalidDataException("Protected mailbox send capacity/revision is inconsistent.");
        var exact = new byte[HeaderBytes + state.Entries.Count * EntryBytes]; exact[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), checked((ushort)state.Entries.Count));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), state.Revision);
        network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
        try
        {
            var offset = HeaderBytes;
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
}
