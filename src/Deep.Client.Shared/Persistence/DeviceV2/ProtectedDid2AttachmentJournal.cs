using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// DR-0031 local asset custody. This never authorizes a blob request or event.
internal static class ProtectedDid2AttachmentJournal
{
    internal const string Slot = "deep.store.v2.attachment-journal";
    internal const int HeaderBytes = 92, EntryBytes = 144, MaximumEntries = 128;
    internal const long MaximumCiphertextBytes = 512L * 1024 * 1024;
    internal sealed class Entry : IDisposable
    {
        private byte[]? bytes;
        internal Entry(ReadOnlySpan<byte> exact)
        {
            if (exact.Length != EntryBytes || exact[128] is not (1 or 2) || exact.Slice(129, 3).IndexOfAnyExcept((byte)0) >= 0 ||
                BinaryPrimitives.ReadUInt32BigEndian(exact[132..]) is < 310 or > 4653 ||
                BinaryPrimitives.ReadUInt64BigEndian(exact[136..]) is < 1 or > 26214400)
                throw new InvalidDataException("Attachment custody has an unknown closed shape.");
            foreach (var offset in new[] { 0, 32, 64, 96 }) ProtectedDph2PreClaimJournal.RequireIntent(exact.Slice(offset, 32));
            bytes = exact.ToArray();
        }
        internal ReadOnlySpan<byte> Exact => bytes ?? throw new ObjectDisposedException(nameof(Entry));
        internal ReadOnlySpan<byte> Operation => Exact[..32];
        internal ReadOnlySpan<byte> Object => Exact.Slice(32, 32);
        internal ReadOnlySpan<byte> ManifestHash => Exact.Slice(64, 32);
        internal ReadOnlySpan<byte> PlaintextHash => Exact.Slice(96, 32);
        internal bool Pending => Exact[128] == 1;
        internal int ManifestLength => checked((int)BinaryPrimitives.ReadUInt32BigEndian(Exact[132..]));
        internal ulong PlaintextLength => BinaryPrimitives.ReadUInt64BigEndian(Exact[136..]);
        internal static Entry Prepare(ReadOnlySpan<byte> op, ReadOnlySpan<byte> manifest, ReadOnlySpan<byte> plainHash)
        {
            ProtectedDph2PreClaimJournal.RequireIntent(op); ProtectedDph2PreClaimJournal.RequireIntent(plainHash);
            using var parsed = ApplicationCoreCodec.DecodeDam1(manifest);
            var frame = new byte[EntryBytes];
            try
            {
                op.CopyTo(frame); parsed.ObjectId.Span.CopyTo(frame.AsSpan(32)); SHA256.HashData(manifest, frame.AsSpan(64, 32));
                plainHash.CopyTo(frame.AsSpan(96)); frame[128] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(132), checked((uint)manifest.Length));
                BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(136), parsed.TotalPlaintextBytes); return new(frame);
            }
            finally { CryptographicOperations.ZeroMemory(frame); }
        }
        internal Entry Stabilize()
        {
            if (!Pending) throw new InvalidOperationException("Only a pending asset can stabilize.");
            var frame = Exact.ToArray(); frame[128] = 2;
            try { return new(frame); } finally { CryptographicOperations.ZeroMemory(frame); }
        }
        internal ParsedDam1 RequireManifest(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network)
        {
            if (exact.Length != ManifestLength || !Fixed(SHA256.HashData(exact), ManifestHash))
                throw new CryptographicException("Attachment manifest differs from protected custody.");
            var parsed = ApplicationCoreCodec.DecodeDam1(exact);
            try
            {
                if (!Fixed(parsed.NetworkId.Span, network) || !Fixed(parsed.ObjectId.Span, Object) || parsed.TotalPlaintextBytes != PlaintextLength)
                    throw new CryptographicException("Attachment scope differs from protected custody.");
                return parsed;
            }
            catch { parsed.Dispose(); throw; }
        }
        public void Dispose() { var owned = Interlocked.Exchange(ref bytes, null); if (owned is not null) CryptographicOperations.ZeroMemory(owned); }
    }
    internal sealed class State : IDisposable
    {
        internal SortedDictionary<string, Entry> Entries { get; } = new(StringComparer.Ordinal);
        internal Entry? Pending => Entries.Values.SingleOrDefault(entry => entry.Pending);
        public void Dispose() { foreach (var entry in Entries.Values) entry.Dispose(); Entries.Clear(); }
    }
    internal static byte[] Empty(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    { using var state = new State(); return Encode(state, network, account, instance); }
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (exact.Length < HeaderBytes || exact.Length > HeaderBytes + EntryBytes * MaximumEntries || exact[0] != 1 || exact[1] != 0 ||
            !Fixed(exact.Slice(12, 16), network) || !Fixed(exact.Slice(28, 32), account) || !Fixed(exact.Slice(60, 32), instance))
            throw new InvalidDataException("Attachment journal is absent, foreign or unsupported.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        if (count > MaximumEntries || exact.Length != HeaderBytes + EntryBytes * count)
            throw new InvalidDataException("Attachment journal exceeds its closed count/size.");
        var state = new State(); var objects = new HashSet<string>(StringComparer.Ordinal); string? prior = null;
        try
        {
            for (var i = 0; i < count; i++)
            {
                var entry = new Entry(exact.Slice(HeaderBytes + i * EntryBytes, EntryBytes));
                var name = Convert.ToHexString(entry.Operation);
                if (prior is not null && string.CompareOrdinal(prior, name) >= 0 || !objects.Add(Convert.ToHexString(entry.Object)))
                { entry.Dispose(); throw new InvalidDataException("Attachment journal repeats an operation or object."); }
                state.Entries.Add(name, entry); prior = name;
            }
            var pending = state.Entries.Values.Count(entry => entry.Pending);
            if (pending > 1 || BinaryPrimitives.ReadUInt64BigEndian(exact[4..]) != 1UL + 2UL * (ulong)(count - pending) + (ulong)pending)
                throw new InvalidDataException("Attachment journal has a noncanonical revision/pending state.");
            return state;
        }
        catch { state.Dispose(); throw; }
    }
    internal static byte[] Encode(State state, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        RequireScope(network, account, instance);
        if (state.Entries.Count > MaximumEntries) throw new InvalidOperationException("Attachment custody requires verified lifecycle rollover.");
        var frame = new byte[HeaderBytes + state.Entries.Count * EntryBytes];
        try
        {
            var pending = state.Entries.Values.Count(entry => entry.Pending);
            frame[0] = 1; BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), checked((ushort)state.Entries.Count));
            BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(4), 1UL + 2UL * (ulong)(state.Entries.Count - pending) + (ulong)pending);
            network.CopyTo(frame.AsSpan(12)); account.CopyTo(frame.AsSpan(28)); instance.CopyTo(frame.AsSpan(60));
            var offset = HeaderBytes;
            foreach (var pair in state.Entries)
            {
                if (pair.Key != Convert.ToHexString(pair.Value.Operation)) throw new InvalidDataException("Attachment journal key differs.");
                pair.Value.Exact.CopyTo(frame.AsSpan(offset)); offset += EntryBytes;
            }
            using var verified = Decode(frame, network, account, instance); return frame;
        }
        catch { CryptographicOperations.ZeroMemory(frame); throw; }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static void RequireScope(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (network.Length != 16 || Did2MessagingSessionScope.Zero(network)) throw new ArgumentException("An exact network is required.");
        ProtectedDph2PreClaimJournal.RequireIntent(account); ProtectedDph2PreClaimJournal.RequireIntent(instance);
    }
}
