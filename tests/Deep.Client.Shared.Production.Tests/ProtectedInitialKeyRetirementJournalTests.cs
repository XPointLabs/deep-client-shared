using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Metadata/anti-rollback checks only. These bytes do not mint transfer/receipt.
public sealed class ProtectedInitialKeyRetirementJournalTests
{
    private static readonly byte[] Network = Bytes(16, 1), Account = Bytes(32, 2), Instance = Bytes(32, 3);
    [Fact]
    public void PendingDeletionAllowsExactMissingStateStableRejectsResurrection()
    {
        var metadata = new byte[] { 1, 2, 3 }; var rowHash = Bytes(32, 5); var trsHash = Bytes(32, 6); var intent = Bytes(32, 7);
        var raw = Entry(2, 1, 1); rowHash.CopyTo(raw, 44); SHA256.HashData(metadata).CopyTo(raw, 108);
        trsHash.CopyTo(raw, 140); intent.CopyTo(raw, 172);
        var entry = new ProtectedInitialKeyRetirementJournal.Entry(raw);
        var state = new ProtectedInitialKeyRetirementJournal.State(2, new(StringComparer.Ordinal) { [entry.Coordinate] = entry });
        var exact = ProtectedInitialKeyRetirementJournal.Encode(state, Network, Account, Instance);
        var pending = ProtectedInitialKeyRetirementJournal.Decode(exact, Network, Account, Instance);
        Assert.Equal(92 + 236, exact.Length);
        foreach (var live in new[] { true, false }) pending.RequireSource(2, Instance, 1, rowHash, metadata, trsHash, intent, live);
        pending.RequireSourceTip(2, Instance, 1);
        Assert.Throws<CryptographicException>(() => pending.RequireSourceTip(2, Instance, 0));
        var altered = metadata.ToArray(); altered[0] ^= 1;
        Assert.Throws<CryptographicException>(() => pending.RequireSource(2, Instance, 1, rowHash, altered, trsHash, intent, false));
        state.Entries[entry.Coordinate] = entry.Stable();
        var stable = ProtectedInitialKeyRetirementJournal.Decode(ProtectedInitialKeyRetirementJournal.Encode(state with { Revision = 3 },
            Network, Account, Instance), Network, Account, Instance);
        stable.RequireSource(2, Instance, 1, rowHash, metadata, trsHash, intent, false);
        Assert.Throws<CryptographicException>(() => stable.RequireSource(2, Instance, 1, rowHash, metadata, trsHash, intent, true));
        var empty = ProtectedInitialKeyRetirementJournal.Decode(ProtectedInitialKeyRetirementJournal.Empty(Network, Account, Instance), Network, Account, Instance);
        Assert.Throws<CryptographicException>(() => empty.RequireSource(2, Instance, 1, rowHash, metadata, trsHash, intent, false));
        Assert.Empty(typeof(Did2InitialStateTransfer).GetConstructors());
        Assert.Empty(typeof(Did2InitialKeyRetirementReceipt).GetConstructors());
    }
    [Fact]
    public void RoleRevisionOrderDuplicateBindingAndHostileScopeReject()
    {
        var entry = new ProtectedInitialKeyRetirementJournal.Entry(Entry(1, 1, 1));
        var state = new ProtectedInitialKeyRetirementJournal.State(2, new(StringComparer.Ordinal) { [entry.Coordinate] = entry });
        var exact = ProtectedInitialKeyRetirementJournal.Encode(state, Network, Account, Instance);
        foreach (var offset in new[] { 0, 1, 12, 28, 60 })
        {
            var changed = exact.ToArray(); changed[offset] ^= 1;
            Assert.Throws<CryptographicException>(() => ProtectedInitialKeyRetirementJournal.Decode(changed, Network, Account, Instance));
        }
        var wrongRole = entry.Exact.ToArray(); wrongRole[0] = 2;
        Assert.Throws<InvalidDataException>(() => new ProtectedInitialKeyRetirementJournal.Entry(wrongRole));
        Assert.Throws<InvalidDataException>(() => ProtectedInitialKeyRetirementJournal.Encode(state with { Revision = 3 }, Network, Account, Instance));
        var secondRaw = Entry(1, 1, 2); var second = new ProtectedInitialKeyRetirementJournal.Entry(secondRaw);
        state.Entries.Add(second.Coordinate, second);
        Assert.Throws<InvalidDataException>(() => ProtectedInitialKeyRetirementJournal.Encode(state with { Revision = 3 }, Network, Account, Instance));
        secondRaw[76] ^= 1; secondRaw[108] ^= 1; second = new(secondRaw); state.Entries[second.Coordinate] = second;
        var pair = ProtectedInitialKeyRetirementJournal.Encode(state with { Revision = 3 }, Network, Account, Instance);
        var swapped = pair.ToArray(); pair.AsSpan(92, 236).CopyTo(swapped.AsSpan(92 + 236)); pair.AsSpan(92 + 236, 236).CopyTo(swapped.AsSpan(92));
        Assert.Throws<InvalidDataException>(() => ProtectedInitialKeyRetirementJournal.Decode(swapped, Network, Account, Instance));
        Assert.Throws<CryptographicException>(() => ProtectedInitialKeyRetirementJournal.Decode(new byte[92 + 257 * 236], Network, Account, Instance));
    }
    private static byte[] Entry(byte role, byte phase, ulong ordinal)
    {
        var raw = new byte[236]; raw[0] = role; raw[1] = phase; Instance.CopyTo(raw, 4);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(36), ordinal);
        foreach (var offset in new[] { 44, 76, 108, 140, 172 }) raw.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        if (role == 1) raw.AsSpan(204, 32).Fill(9); return raw;
    }
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
