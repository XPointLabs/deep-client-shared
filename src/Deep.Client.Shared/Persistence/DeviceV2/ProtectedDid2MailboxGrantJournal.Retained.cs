using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static partial class ProtectedDid2MailboxGrantJournal
{
    // Working acquisitions are bounded separately from exact sealed custody.
    // These references never replace replay floors or grant effect authority.
    internal const int MaximumRetained = ProtectedDid2MailboxSendJournal.MaximumFloors + ProtectedDid2MailboxReadJournal.MaximumFloors;
    private const int RetainedReferenceBytes = 104;
    internal sealed class RetainedReference(byte[] grantHash, byte[] entryHash, byte phase) : IDisposable
    {
        internal readonly byte[] GrantHash = grantHash, EntryHash = entryHash;
        // 1: sealed, 2: restored for epoch exclusion, 3: authorized slot deletion.
        internal byte Phase = phase;
        public void Dispose() { CryptographicOperations.ZeroMemory(GrantHash); CryptographicOperations.ZeroMemory(EntryHash); }
    }

    internal static string RetainedSlot(ReadOnlySpan<byte> acquisition)
    { Required32(acquisition); return "deep.store.v2.mailbox-grant-retained." + Convert.ToHexStringLower(acquisition); }

    private static void RequireRetainedReferences(State state)
    {
        if (state.Retained.Count > MaximumRetained) throw new IOException("Retained grant custody is full.");
        var grants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in state.Retained)
        {
            var name = Convert.FromHexString(pair.Key); Required32(name);
            if (Convert.ToHexString(name) != pair.Key || pair.Value.Phase is < 1 or > 3 ||
                pair.Value.Phase != 2 && state.Entries.ContainsKey(pair.Key))
                throw new InvalidDataException("Retained acquisition reference is noncanonical.");
            Required32(pair.Value.GrantHash); Required32(pair.Value.EntryHash);
            if (!grants.Add(Convert.ToHexString(pair.Value.GrantHash))) throw new InvalidDataException("Retained grants are duplicate.");
            if (state.Entries.TryGetValue(pair.Key, out var restored) &&
                (!Fixed(SHA256.HashData(restored), pair.Value.EntryHash) ||
                 !Fixed(SHA256.HashData(ContactCodec.Decode("XMC2", Response(restored).Span).Field(8).Span), pair.Value.GrantHash)))
                throw new CryptographicException("Restored acquisition differs from its retained exact original.");
        }
    }

    private static void ReadRetainedReferences(State state, ReadOnlySpan<byte> bytes, int count)
    {
        string? prior = null;
        for (var i = 0; i < count; i++)
        {
            var row = bytes.Slice(i * RetainedReferenceBytes, RetainedReferenceBytes);
            var name = Convert.ToHexString(row[..32]);
            if (prior is not null && string.CompareOrdinal(prior, name) >= 0 || row[97..].IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Retained acquisition references are unsorted or noncanonical.");
            state.Retained.Add(name, new(row.Slice(32, 32).ToArray(), row.Slice(64, 32).ToArray(), row[96])); prior = name;
        }
        RequireRetainedReferences(state);
    }

    private static void WriteRetainedReferences(State state, Span<byte> bytes)
    {
        foreach (var pair in state.Retained)
        {
            Convert.FromHexString(pair.Key).CopyTo(bytes); pair.Value.GrantHash.CopyTo(bytes[32..]);
            pair.Value.EntryHash.CopyTo(bytes[64..]); bytes[96] = pair.Value.Phase; bytes = bytes[RetainedReferenceBytes..];
        }
    }

    // Pure structural selection. The owner independently pins actual read/send
    // dependencies and copies the complete original into atomic protected custody.
    internal static byte[] RequireSealableOldest(State state, ReadOnlySpan<byte> acquisition)
    {
        var name = Convert.ToHexString(acquisition);
        if (state.Retained.ContainsKey(name) || state.Retained.Count >= MaximumRetained)
            throw new IOException("Acquisition already owns retained custody or retention is full.");
        if (!state.Entries.TryGetValue(name, out var candidate) || !IsAdoptedWinner(candidate))
            throw new IOException("Only an exact adopted acquisition can be sealed.");
        var domain = (MailboxCapabilityDomain)ContactCodec.Decode("XMG2", Request(candidate).Span).Field(6).Span[0];
        var entry = RequireOldestAdopted(state, acquisition, domain);
        if (state.Selections[EntryScope(entry)].Current == name)
            throw new IOException("The selected current holder must remain in the working set.");
        return entry;
    }

    internal static (byte[] Working, byte[] Retained) SealOldest(State state, ReadOnlySpan<byte> acquisition,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var retained = StageSealedOldest(state, acquisition, network, account, instance);
        try { return (Encode(state, network, account, instance), retained); }
        catch { CryptographicOperations.ZeroMemory(retained); throw; }
    }

    // In-memory staging only. The held owner encodes the complete successor
    // once and atomically inserts ALL sealed copies with that exact root.
    internal static byte[] StageSealedOldest(State state, ReadOnlySpan<byte> acquisition,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var entry = RequireSealableOldest(state, acquisition);
        using var single = new State { Revision = 2 };
        var name = Convert.ToHexString(acquisition); var scope = EntryScope(entry);
        single.Entries.Add(name, entry.ToArray()); single.Selections.Add(scope, new(name, null, name));
        var retained = Encode(single, network, account, instance);
        try
        {
            state.Retained.Add(name, new(SHA256.HashData(ContactCodec.Decode("XMC2", Response(entry).Span).Field(8).Span), SHA256.HashData(entry), 1));
            StageOldestAdoptedRemoval(state, acquisition, entry);
            return retained;
        }
        catch { CryptographicOperations.ZeroMemory(retained); throw; }
    }

    internal static State DecodeRetained(State working, string name, ReadOnlySpan<byte> raw,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var reference = working.Retained[name];
        var retained = Decode(raw, network, account, instance);
        try
        {
            if (retained.Entries.Count != 1 || retained.Retained.Count != 0 || !retained.Entries.TryGetValue(name, out var entry) ||
                !IsAdoptedWinner(entry) || !Fixed(SHA256.HashData(entry), reference.EntryHash) ||
                !Fixed(SHA256.HashData(ContactCodec.Decode("XMC2", Response(entry).Span).Field(8).Span), reference.GrantHash))
                throw new CryptographicException("Retained acquisition differs from its protected exact reference.");
            return retained;
        }
        catch { retained.Dispose(); throw; }
    }

    internal static byte[] RestoreRetainedOldest(State working, string name, byte[] original,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (working.Retained[name].Phase != 1 || working.Entries.Count >= MaximumEntries || working.Entries.ContainsKey(name))
            throw new IOException("Retained acquisition cannot enter working epoch exclusion.");
        var scope = EntryScope(original);
        if (working.Selections.TryGetValue(scope, out var selected))
        {
            if (selected.Pending is not null || selected.Current is null) throw new IOException("Unresolved selection pins restoration.");
            var cursor = selected.RetainedTail!;
            for (var remaining = MaximumEntries; ; remaining--)
            {
                if (remaining == 0 || !IsAdoptedWinner(working.Entries[cursor])) throw new IOException("Unresolved chain pins restoration.");
                var next = Predecessor(working.Entries[cursor]);
                if (next is null) break; cursor = next;
            }
            var oldStart = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XMG2", Request(original).Span).Field(9).Span);
            var nextStart = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XMG2", Request(working.Entries[cursor]).Span).Field(9).Span);
            if (oldStart > nextStart) throw new IOException("An older retained predecessor must retire first.");
            Convert.FromHexString(name).CopyTo(working.Entries[cursor].AsSpan(PredecessorOffset, 32));
        }
        else working.Selections.Add(scope, new(name, null, name));
        working.Entries.Add(name, original.ToArray()); working.Retained[name].Phase = 2;
        working.Revision = checked(working.Revision + 1);
        return Encode(working, network, account, instance);
    }
}
