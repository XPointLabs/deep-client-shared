using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0064: exact local draft custody, never claim/route/dispatch authority.
internal static class ProtectedDid2ContactStartJournal
{
    internal const string Slot = "deep.store.v2.contact-start-journal";
    internal const int HeaderBytes = 92, PrefixBytes = 464, MaximumEntries = 128;
    internal const int MinimumEntryBytes = PrefixBytes, MaximumEntryBytes = 16389;
    internal const int MaximumBytes = DeepSecureStorageRegistration.MaximumValueBytes;

    internal static void RequireInitialBucket(int initBytes, int helloBytes)
    {
        if (initBytes is < 780 or > 1830 || helloBytes is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes ||
            16839L + initBytes + helloBytes > 32764)
            throw new InvalidDataException("The exact contact events cannot fit the current bounded initial transcript.");
    }

    internal sealed class Entry : IDisposable
    {
        private byte[]? exact;
        private Entry(byte[] exact) => this.exact = exact;
        internal ReadOnlySpan<byte> Exact => exact ?? throw new ObjectDisposedException(nameof(Entry));
        internal ReadOnlySpan<byte> Intent => Exact[..32];
        internal bool PayloadRetired => Exact[432] == 2;
        internal ProtectedDid2DirectTextJournal.WorkStopReason StopReason => (ProtectedDid2DirectTextJournal.WorkStopReason)Exact[433];
        internal bool WorkStopped => StopReason != ProtectedDid2DirectTextJournal.WorkStopReason.Active;
        internal byte AuditDisposition => Exact[434];
        internal byte NativeStopMode => Exact[435];
        internal byte[] CancellationBinding => SHA256.HashData(Exact[..432]);
        internal ulong StoppedAtUpper => BinaryPrimitives.ReadUInt64BigEndian(Exact[448..]);
        internal ulong FirstSuccessfulStoreUpper => BinaryPrimitives.ReadUInt64BigEndian(Exact[456..]);
        internal bool SuccessfullyStored => !WorkStopped && (FirstSuccessfulStoreUpper != 0 || PayloadRetired);
        internal ulong TerminalAtUpper => WorkStopped ? StoppedAtUpper : FirstSuccessfulStoreUpper;
        internal ReadOnlySpan<byte> InitHash => Exact.Slice(288, 32);
        internal ReadOnlySpan<byte> HelloHash => Exact.Slice(320, 32);
        internal ReadOnlySpan<byte> Conversation => Exact.Slice(352, 32);
        internal ReadOnlySpan<byte> LocalDevice => Exact.Slice(384, 32);
        internal ulong HelloCreatedAtUnixMilliseconds => BinaryPrimitives.ReadUInt64BigEndian(Exact[416..]);
        internal ulong ExpiresAtUnixMilliseconds => BinaryPrimitives.ReadUInt64BigEndian(Exact[424..]);
        internal ReadOnlySpan<byte> Init => !PayloadRetired ? Exact.Slice(PrefixBytes, checked((int)BinaryPrimitives.ReadUInt32BigEndian(Exact[440..]))) :
            throw new InvalidOperationException("Retired Initial custody has no working event payload.");
        internal ReadOnlySpan<byte> Hello => Exact[(PrefixBytes + Init.Length)..];
        internal void RequireExactEvents(ReadOnlySpan<byte> init, ReadOnlySpan<byte> hello, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (!Fixed(InitHash, SHA256.HashData(init)) || !Fixed(HelloHash, SHA256.HashData(hello)) ||
                !PayloadRetired && (!Fixed(Init, init) || !Fixed(Hello, hello)))
                throw new CryptographicException("Initial events differ from their protected explicit draft commitment.");
            RequireCanonicalEvents(Exact, init, hello, network, account);
        }
        internal static Entry Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (bytes.Length is < MinimumEntryBytes or > MaximumEntryBytes)
                throw new InvalidDataException("Initial contact draft has an invalid bounded size.");
            for (var offset = 0; offset < 416; offset += 32) ProtectedDph2PreClaimJournal.RequireIntent(bytes.Slice(offset, 32));
            var created = BinaryPrimitives.ReadUInt64BigEndian(bytes[416..]);
            var expiry = BinaryPrimitives.ReadUInt64BigEndian(bytes[424..]);
            if (bytes[432] is not (1 or 2) || (bytes[433] == 0 ? bytes[435] != 0 : bytes[435] is not (1 or 2)) ||
                bytes.Slice(436, 4).IndexOfAnyExcept((byte)0) >= 0 ||
                created == 0 || expiry <= created || expiry - created >= 3_600_000)
                throw new InvalidDataException("Initial draft phase, retained interval or reserved bytes are invalid.");
            Did2ControlWorkStop.RequireCanonical(bytes[433], bytes[434], BinaryPrimitives.ReadUInt64BigEndian(bytes[448..]), bytes[432] == 2,
                BinaryPrimitives.ReadUInt64BigEndian(bytes[456..]));
            var initialLength = BinaryPrimitives.ReadUInt32BigEndian(bytes[440..]);
            var helloLength = BinaryPrimitives.ReadUInt32BigEndian(bytes[444..]);
            if (bytes[432] == 2)
            {
                if (bytes.Length != PrefixBytes || initialLength != 0 || helloLength != 0)
                    throw new InvalidDataException("Retired Initial custody contains working payload bytes.");
                return new(bytes.ToArray());
            }
            if (initialLength is < 780 or > 1830 || helloLength is < ApplicationCoreCodec.MinimumContactControlRecordBytes or > ApplicationCoreCodec.MaximumContactControlRecordBytes ||
                PrefixBytes + (long)initialLength + helloLength != bytes.Length)
                throw new InvalidDataException("Initial draft declared lengths are hostile.");
            RequireInitialBucket((int)initialLength, (int)helloLength);
            var initBytes = bytes.Slice(PrefixBytes, (int)initialLength);
            var helloBytes = bytes[(PrefixBytes + (int)initialLength)..];
            if (!Fixed(bytes.Slice(288, 32), SHA256.HashData(initBytes)) || !Fixed(bytes.Slice(320, 32), SHA256.HashData(helloBytes)))
                throw new CryptographicException("Initial payload differs from its exact draft commitments.");
            RequireCanonicalEvents(bytes, initBytes, helloBytes, network, account);
            return new(bytes.ToArray());
        }
        private static void RequireCanonicalEvents(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> initBytes, ReadOnlySpan<byte> helloBytes,
            ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            RequireInitialBucket(initBytes.Length, helloBytes.Length);
            var init = ApplicationCoreCodec.DecodeDmc2(initBytes);
            var hello = ApplicationCoreCodec.DecodeDmc2(helloBytes);
            if (init.ParsedPayload is not SessionInitDmc2Payload initial || hello.ParsedPayload is not ContactHelloDmc2Payload contact ||
                init.SenderClientSequence != 1 || hello.SenderClientSequence != 2 ||
                !Fixed(init.NetworkId.Span, network) || !Fixed(hello.NetworkId.Span, network) ||
                !Fixed(init.SenderAccountId.Span, account) || !Fixed(hello.SenderAccountId.Span, account) ||
                !Fixed(init.SenderDeviceId.Span, hello.SenderDeviceId.Span) ||
                !Fixed(init.SenderDeviceId.Span, bytes.Slice(384, 32)) ||
                !Fixed(init.ConversationId.Span, hello.ConversationId.Span) ||
                !Fixed(init.ConversationId.Span, bytes.Slice(352, 32)) ||
                !Fixed(hello.ConversationId.Span, ApplicationCoreVerifier.ComputeContactConversationId(network, contact.RelationshipId.Span, account, bytes.Slice(64, 32))) ||
                Fixed(init.LogicalMessageId.Span, hello.LogicalMessageId.Span) ||
                init.CreatedAtUnixMilliseconds == ulong.MaxValue || hello.CreatedAtUnixMilliseconds != init.CreatedAtUnixMilliseconds + 1 ||
                init.ExpiresAtUnixMilliseconds != hello.ExpiresAtUnixMilliseconds ||
                hello.CreatedAtUnixMilliseconds != BinaryPrimitives.ReadUInt64BigEndian(bytes[416..]) ||
                hello.ExpiresAtUnixMilliseconds != BinaryPrimitives.ReadUInt64BigEndian(bytes[424..]) ||
                init.ExpiresAtUnixMilliseconds - init.CreatedAtUnixMilliseconds > 3_600_000 ||
                initial.Capabilities != (SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl) ||
                !Fixed(initial.SenderDirectory.RecordHash.Span, bytes.Slice(256, 32)) ||
                !Fixed(contact.InitiatorDmd1Hash.Span, bytes.Slice(256, 32)) ||
                !Fixed(contact.InitiatorDab2Reference.Span[6..], bytes.Slice(224, 32)) ||
                !Fixed(contact.MailboxRoute.Authorization.DeepAccountId.Span, account) ||
                !Fixed(contact.MailboxRoute.Authorization.PublisherDeviceId.Span, hello.SenderDeviceId.Span) ||
                !Fixed(contact.MailboxRoute.Authorization.Dab2Reference.CanonicalHash.Span, bytes.Slice(224, 32)) ||
                !Fixed(contact.MailboxRoute.Authorization.AuthorizedDmd1Hash.Span, bytes.Slice(256, 32)))
                throw new CryptographicException("Initial draft differs from its retained local/peer metadata.");
        }
        internal static Entry Create(ReadOnlySpan<byte> metadata288, ParsedDmc2 init, ParsedDmc2 hello,
            ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (metadata288.Length != 288) throw new ArgumentException("Exact draft metadata is required.");
            RequireInitialBucket(init.CanonicalBytes.Length, hello.CanonicalBytes.Length);
            var exact = new byte[PrefixBytes + init.CanonicalBytes.Length + hello.CanonicalBytes.Length];
            try
            {
                metadata288.CopyTo(exact);
                SHA256.HashData(init.CanonicalBytes.Span, exact.AsSpan(288, 32));
                SHA256.HashData(hello.CanonicalBytes.Span, exact.AsSpan(320, 32));
                init.ConversationId.Span.CopyTo(exact.AsSpan(352)); init.SenderDeviceId.Span.CopyTo(exact.AsSpan(384));
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(416), hello.CreatedAtUnixMilliseconds);
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(424), hello.ExpiresAtUnixMilliseconds);
                exact[432] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(440), (uint)init.CanonicalBytes.Length);
                BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(444), (uint)hello.CanonicalBytes.Length);
                init.CanonicalBytes.Span.CopyTo(exact.AsSpan(PrefixBytes));
                hello.CanonicalBytes.Span.CopyTo(exact.AsSpan(PrefixBytes + init.CanonicalBytes.Length));
                return Decode(exact, network, account);
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        internal Entry WithoutWorkingPayload(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            var marker = Exact[..PrefixBytes].ToArray(); marker[432] = 2; marker.AsSpan(440, 8).Clear();
            if (WorkStopped || SuccessfullyStored) marker[434] = 1;
            try { return Decode(marker, network, account); }
            finally { CryptographicOperations.ZeroMemory(marker); }
        }
        internal Entry WithStoppedWork(ProtectedDid2DirectTextJournal.WorkStopReason reason, ulong stoppedAtUpper,
            ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, bool nativeCommitted)
        {
            if (WorkStopped || SuccessfullyStored || PayloadRetired || reason is not (ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled or ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired))
                throw new InvalidOperationException("Only active working Initial may acquire a stop fence.");
            var next = Exact.ToArray(); next[433] = (byte)reason; next[435] = nativeCommitted ? (byte)1 : (byte)2;
            BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(448), stoppedAtUpper);
            try { return Decode(next, network, account); }
            finally { CryptographicOperations.ZeroMemory(next); }
        }
        internal Entry WithoutStoppedAudit(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if ((!WorkStopped && !SuccessfullyStored) || !PayloadRetired || AuditDisposition != 1) throw new InvalidOperationException("Only retained Initial audit may expire.");
            var next = Exact.ToArray(); next[434] = 2; next.AsSpan(448, 16).Clear();
            try { return Decode(next, network, account); }
            finally { CryptographicOperations.ZeroMemory(next); }
        }
        internal Entry WithVerifiedStore(ulong upper, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        {
            if (upper is 0 or > long.MaxValue - 2_592_000) throw new InvalidDataException("Successful Initial time is invalid.");
            var next = Exact.ToArray();
            if (!WorkStopped && !SuccessfullyStored) BinaryPrimitives.WriteUInt64BigEndian(next.AsSpan(456), upper);
            try { return Decode(next, network, account); }
            finally { CryptographicOperations.ZeroMemory(next); }
        }
        public void Dispose() { var bytes = Interlocked.Exchange(ref exact, null); if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    internal sealed class State : IDisposable
    {
        internal ulong Revision { get; set; } = 1;
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        public void Dispose() { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); }
    }
    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length is < HeaderBytes or > MaximumBytes || exact[0] != 5 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("Contact draft journal is absent, foreign or incompatible.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        if (count > MaximumEntries || exact.Length < HeaderBytes + count * (4 + MinimumEntryBytes) ||
            BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) < (ulong)count + 1 ||
            count == 0 && BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) != 1)
            throw new InvalidDataException("Draft journal has a hostile count/revision.");
        var state = new State { Revision = BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) };
        try
        {
            var offset = HeaderBytes; string? previous = null;
            for (var i = 0; i < count; i++)
            {
                if (exact.Length - offset < 4) throw new InvalidDataException("Draft journal framing is truncated.");
                var length = BinaryPrimitives.ReadUInt32BigEndian(exact[offset..]); offset += 4;
                if (length is < MinimumEntryBytes or > MaximumEntryBytes || length > exact.Length - offset)
                    throw new InvalidDataException("Draft entry length exceeds its closed bound.");
                var entry = Entry.Decode(exact.Slice(offset, (int)length), network, account); offset += (int)length;
                var name = Convert.ToHexString(entry.Intent);
                if (previous is not null && string.CompareOrdinal(previous, name) >= 0)
                { entry.Dispose(); throw new InvalidDataException("Draft intents are repeated or unordered."); }
                state.Entries.Add(name, entry); previous = name;
            }
            if (offset != exact.Length) throw new InvalidDataException("Draft journal has trailing bytes.");
            return state;
        }
        catch { state.Dispose(); throw; }
    }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries) throw new IOException("Contact draft cardinality is exhausted.");
        var size = checked(HeaderBytes + state.Entries.Values.Sum(entry => 4 + entry.Exact.Length));
        if (size > MaximumBytes) throw new IOException("Contact draft byte capacity is exhausted.");
        var exact = new byte[size];
        try
        {
            exact[0] = 5; BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), (ushort)state.Entries.Count);
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(4), Math.Max(state.Revision, (ulong)state.Entries.Count + 1));
            network.CopyTo(exact.AsSpan(12)); account.CopyTo(exact.AsSpan(28)); instance.CopyTo(exact.AsSpan(60));
            var offset = HeaderBytes;
            foreach (var pair in state.Entries)
            {
                if (pair.Key != Convert.ToHexString(pair.Value.Intent)) throw new InvalidDataException("Draft intent key differs.");
                BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(offset), (uint)pair.Value.Exact.Length); offset += 4;
                pair.Value.Exact.CopyTo(exact.AsSpan(offset)); offset += pair.Value.Exact.Length;
            }
            using var validated = Decode(exact, network, account, instance); return exact;
        }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
}

internal sealed class OwnedDid2InitialContactDraft : IDisposable
{
    private readonly ProtectedDid2ContactStartJournal.Entry entry;
    internal OwnedDid2InitialContactDraft(ProtectedDid2ContactStartJournal.Entry winner, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
        => entry = ProtectedDid2ContactStartJournal.Entry.Decode(winner.Exact, network, account);
    internal OwnedDid2InitialContactDraft(ProtectedDid2ContactStartJournal.Entry winner, ReadOnlySpan<byte> init, ReadOnlySpan<byte> hello,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account)
    {
        winner.RequireExactEvents(init, hello, network, account);
        entry = ProtectedDid2ContactStartJournal.Entry.Create(winner.Exact[..288], ApplicationCoreCodec.DecodeDmc2(init),
            ApplicationCoreCodec.DecodeDmc2(hello), network, account);
    }
    internal ReadOnlySpan<byte> ExactInit => entry.Init;
    internal ReadOnlySpan<byte> ExactHello => entry.Hello;
    public void Dispose() { entry.Dispose(); GC.SuppressFinalize(this); }
    ~OwnedDid2InitialContactDraft() => entry.Dispose();
}
