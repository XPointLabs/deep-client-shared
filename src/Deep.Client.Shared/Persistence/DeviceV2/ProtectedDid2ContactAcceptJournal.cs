using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0029 protected local authoring custody. Decoding grants no freshness,
// accepted-contact, ratchet, transport or ACK authority.
internal static class ProtectedDid2ContactAcceptJournal
{
    internal const string Slot = "deep.store.v2.contact-accept-journal";
    internal const int HeaderBytes = 92, PrefixBytes = 468, MaximumEntries = 128;
    internal const int MinimumEntryBytes = PrefixBytes + ApplicationCoreCodec.MinimumContactControlRecordBytes;
    internal const int MaximumEntryBytes = PrefixBytes + ApplicationCoreCodec.MaximumContactControlRecordBytes;
    internal const int MaximumBytes = DeepSecureStorageRegistration.MaximumValueBytes;

    internal sealed class Entry : IDisposable
    {
        private byte[]? exact;
        private Entry(byte[] exact) => this.exact = exact;
        internal ReadOnlySpan<byte> Exact => exact ?? throw new ObjectDisposedException(nameof(Entry));
        internal ReadOnlySpan<byte> Operation => Exact[..32];
        internal Did2MessagingSessionScope Scope => Did2MessagingSessionScope.RestoreMetadata(Exact.Slice(32, 404));
        internal ReadOnlySpan<byte> HelloHash => Exact.Slice(436, 32);
        internal ReadOnlySpan<byte> Accept => Exact[PrefixBytes..];
        internal static Entry Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
        {
            if (bytes.Length is < MinimumEntryBytes or > MaximumEntryBytes) throw new InvalidDataException("Contact acceptance entry has an unknown size.");
            ProtectedDph2PreClaimJournal.RequireIntent(bytes[..32]);
            var scope = Did2MessagingSessionScope.RestoreMetadata(bytes.Slice(32, 404));
            var accepted = ApplicationCoreCodec.DecodeDmc2(bytes[468..]);
            var logical = LogicalId(scope, bytes[..32]);
            try
            {
                if (scope.IsInitiator || !Fixed(scope.Network, network) || !Fixed(scope.LocalAccount, account) ||
                    !Fixed(scope.Instance, instance) || !Fixed(accepted.CanonicalBytes.Span, bytes[468..]) ||
                    !Fixed(accepted.NetworkId.Span, network) || !Fixed(accepted.ConversationId.Span, scope.Conversation) ||
                    !Fixed(accepted.SenderAccountId.Span, account) || !Fixed(accepted.SenderDeviceId.Span, scope.LocalDevice) ||
                    !Fixed(accepted.LogicalMessageId.Span, logical) || accepted.SenderClientSequence != 3 ||
                    accepted.ParsedPayload is not ContactAcceptDmc2Payload response ||
                    !Fixed(response.RelationshipId.Span, scope.Relationship) || !Fixed(response.ContactHelloHash.Span, bytes.Slice(436, 32)) ||
                    !Fixed(response.ResponderDmd1Hash.Span, scope.LocalDirectory) ||
                    Did2MessagingSessionScope.Zero(bytes.Slice(436, 32)))
                    throw new CryptographicException("Protected ContactAccept differs from its responder pending scope.");
                return new(bytes.ToArray());
            }
            finally { CryptographicOperations.ZeroMemory(logical); }
        }
        internal static Entry FromAuthor(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation,
            ReadOnlySpan<byte> hello, AuthoredVerifiedContactAccept authored)
        {
            if (authored.Record.CanonicalBytes.Length is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes)
                throw new InvalidDataException("ContactAccept has an invalid canonical current bound.");
            var bytes = new byte[checked(PrefixBytes + authored.Record.CanonicalBytes.Length)];
            try
            {
                operation.CopyTo(bytes); scope.Exact.CopyTo(bytes.AsSpan(32));
                SHA256.HashData(hello, bytes.AsSpan(436, 32));
                authored.Record.CanonicalBytes.Span.CopyTo(bytes.AsSpan(468));
                return Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        public void Dispose()
        {
            var bytes = Interlocked.Exchange(ref exact, null);
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal sealed class State : IDisposable
    {
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        internal Entry? FindScope(Did2MessagingSessionScope scope) =>
            Entries.Values.SingleOrDefault(entry => Fixed(entry.Scope.Exact, scope.Exact));
        public void Dispose() { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); }
    }

    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }

    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > MaximumBytes ||
            exact[0] != 2 || exact[1] != 0 || !Fixed(exact.Slice(12, 16), network) ||
            !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("Protected contact acceptance has an unknown or foreign header.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        if (count > MaximumEntries || exact.Length < HeaderBytes + count * (4 + MinimumEntryBytes) ||
            BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) != (ulong)count + 1)
            throw new InvalidDataException("Protected contact acceptance has a noncanonical count/revision.");
        var state = new State();
        try
        {
            string? previous = null;
            var scopes = new HashSet<string>(StringComparer.Ordinal);
            var positions = new HashSet<string>(StringComparer.Ordinal);
            var offset = HeaderBytes;
            for (var i = 0; i < count; i++)
            {
                if (exact.Length - offset < 4) throw new InvalidDataException("Protected acceptance entry framing is truncated.");
                var size = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset, 4)); offset += 4;
                if (size is < MinimumEntryBytes or > MaximumEntryBytes || size > exact.Length - offset)
                    throw new InvalidDataException("Protected acceptance entry size is hostile.");
                var entry = Entry.Decode(exact.Slice(offset, checked((int)size)), network, account, instance);
                offset += checked((int)size);
                var name = Convert.ToHexString(entry.Operation); var scope = entry.Scope;
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0 ||
                    !scopes.Add(Convert.ToHexString(scope.Hash)) ||
                    !positions.Add(Convert.ToHexString(scope.Conversation) + Convert.ToHexString(scope.LocalDevice)))
                { entry.Dispose(); throw new InvalidDataException("Protected contact acceptance repeats an operation or authored position."); }
                state.Entries.Add(name, entry); previous = name;
            }
            if (offset != exact.Length) throw new InvalidDataException("Protected acceptance has trailing bytes.");
            return state;
        }
        catch { state.Dispose(); throw; }
    }

    internal static byte[] Encode(State state, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries) throw new IOException("Protected contact acceptance is at capacity.");
        var size = checked(HeaderBytes + state.Entries.Values.Sum(entry => 4 + entry.Exact.Length));
        if (size > MaximumBytes) throw new IOException("Protected contact acceptance byte capacity is exhausted.");
        var exact = new byte[size];
        try
        {
            exact[0] = 2; BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), checked((ushort)state.Entries.Count));
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), (ulong)state.Entries.Count + 1);
            network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
            var offset = HeaderBytes;
            foreach (var pair in state.Entries)
            {
                if (pair.Key != Convert.ToHexString(pair.Value.Operation))
                    throw new InvalidDataException("Protected acceptance key differs from its operation.");
                BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(offset, 4), checked((uint)pair.Value.Exact.Length)); offset += 4;
                pair.Value.Exact.CopyTo(exact.AsSpan(offset)); offset += pair.Value.Exact.Length;
            }
            using var validated = Decode(exact, network, account, instance);
            return exact;
        }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }

    internal static byte[] LogicalId(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/contact-accept-logical"u8); digest.AppendData([0]);
        digest.AppendData(scope.Hash); digest.AppendData(operation); return digest.GetHashAndReset();
    }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || Did2MessagingSessionScope.Zero(network)) throw new ArgumentException("An exact network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
}
