using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDid2MailboxSendJournalTests
{
    private static readonly byte[] Network = Bytes(16, 0x11), Account = Bytes(32, 0x12), Instance = Bytes(32, 0x13);
    [Fact]
    public void InitialStoreOperationHasItsClosedDomainAndRequiresActualIntentShape()
    {
        var intent = Bytes(32, 0x41);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Local/DID2/InitialMailboxIntent/1"u8); hash.AppendData([0]); hash.AppendData(intent);
        Assert.Equal(hash.GetHashAndReset(), ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent));
        Assert.NotEqual(intent, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent));
        Assert.Throws<ArgumentException>(() => ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(new byte[31]));
        Assert.Throws<ArgumentException>(() => ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(new byte[32]));
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    [InlineData(7)] [InlineData(8)] [InlineData(9)]
    public void HeaderRejectsUnknownForeignOversizedOrNoncanonicalCustody(int fault)
    {
        var exact = ProtectedDid2MailboxSendJournal.Empty(Network, Account, Instance);
        switch (fault)
        {
            case 0: exact[0] = 1; break; // Retired MAU2 custody, even if empty.
            case 1: exact[1] = 1; break;
            case 2: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), 513); break;
            case 3: exact[11] = 0; break;
            case 4: exact[12] ^= 1; break;
            case 5: exact[60] ^= 1; break;
            case 6: exact = [.. exact, 0]; break;
            case 7: exact[0] = 2; break; // Previous commitment has no independent replay floors.
            case 8: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), 513); break;
            case 9: exact[94] = 1; break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)]
    public void EntryRejectsChangedKeyUnknownPhaseReservedMissingCounterOrInvalidLifetime(int fault)
    {
        using var pending = Pending(0x14);
        var exact = pending.Exact.ToArray();
        switch (fault)
        {
            case 0: exact[0] ^= 1; break;
            case 1: exact[296] = 3; break;
            case 2: exact[297] = 1; break;
            case 3: exact[296] = 2; break;
            case 4: exact[263] = 1; break;
            case 5: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(216), 1059); break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Entry.Decode(exact));
    }

    [Fact]
    public void ExactRoundtripPreparedCounterFloorAndDuplicatePendingOrCounterRejection()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        state.EnrollScope(Bytes(32, 0x18), Bytes(32, 0x45));
        using var pending = Pending(0x14);
        var entry = ProtectedDid2MailboxSendJournal.Entry.Decode(pending.Exact);
        state.Entries.Add(entry.Name, entry);
        var bytes = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using (var read = ProtectedDid2MailboxSendJournal.Decode(bytes, Network, Account, Instance))
        { Assert.False(Assert.Single(read.Entries).Value.Prepared); Assert.Equal(1UL, read.MinimumCounter(Bytes(32, 0x18))); }
        using var other = Pending(0x15);
        state.Revision++;
        state.Entries.Add(other.Name, ProtectedDid2MailboxSendJournal.Entry.Decode(other.Exact));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance));
        state.Entries[other.Name].Dispose(); state.Entries.Remove(other.Name);
        var prepared = entry.WithPrepared(Bytes(64, 0x20), 7);
        state.AdvanceCounter(entry.GrantHash, 7);
        state.Entries[entry.Name] = prepared; entry.Dispose();
        bytes = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using (var read = ProtectedDid2MailboxSendJournal.Decode(bytes, Network, Account, Instance))
        { Assert.True(Assert.Single(read.Entries).Value.Prepared); Assert.Equal(8UL, read.MinimumCounter(Bytes(32, 0x18))); }
        var sameCounter = other.WithPrepared(Bytes(64, 0x21), 7);
        state.Entries.Add(sameCounter.Name, sameCounter);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance));
    }

    [Fact]
    public void WorkingEntryRemovalAndReopenCannotLowerIndependentFloor()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        state.EnrollScope(pending.GrantHash, Bytes(32, 0x45));
        var prepared = pending.WithPrepared(Bytes(64, 0x20), 7);
        state.AdvanceCounter(pending.GrantHash, 7); state.Entries.Add(prepared.Name, prepared);
        prepared.Dispose(); state.Entries.Clear(); state.Revision++;
        // Structural cleanup fixture only: no public retirement permission or
        // compaction consumer is established by deleting this commitment.
        var exact = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        using var reopened = ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance);
        Assert.Empty(reopened.Entries); Assert.Single(reopened.Floors);
        Assert.Equal(8UL, reopened.MinimumCounter(pending.GrantHash));
        Assert.Throws<CryptographicException>(() => reopened.AdvanceCounter(Bytes(32, 0x18), 7));
        Assert.Throws<InvalidDataException>(() => reopened.MinimumCounter(Bytes(32, 0x19)));
        reopened.AdvanceCounter(Bytes(32, 0x18), 8); reopened.Revision++;
        using var again = ProtectedDid2MailboxSendJournal.Decode(
            ProtectedDid2MailboxSendJournal.Encode(reopened, Network, Account, Instance), Network, Account, Instance);
        Assert.Equal(9UL, again.MinimumCounter(pending.GrantHash));
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void FloorsRejectMissingChangedUnderReservedOrExhaustedCustody(int fault)
    {
        using var state = new ProtectedDid2MailboxSendJournal.State { Revision = 2 };
        using var pending = Pending(0x14);
        state.EnrollScope(pending.GrantHash, Bytes(32, 0x45)); state.AdvanceCounter(pending.GrantHash, 7);
        var entry = pending.WithPrepared(Bytes(64, 0x20), 7); state.Entries.Add(entry.Name, entry);
        var exact = ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance);
        switch (fault)
        {
            case 0: BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(92), 0); break;
            case 1: exact[ProtectedDid2MailboxSendJournal.HeaderBytes + 32] ^= 1; break;
            case 2: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes + 64), 6); break;
            case 3: BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes + 64), ulong.MaxValue); break;
            case 4: exact.AsSpan(ProtectedDid2MailboxSendJournal.HeaderBytes, 32).Clear(); break;
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxSendJournal.Decode(exact, Network, Account, Instance));
    }

    [Fact]
    public void NamespaceCannotRebindGrantAndFloorCapacityCannotEvictEarlierCounter()
    {
        using var state = new ProtectedDid2MailboxSendJournal.State();
        for (var index = 0; index < ProtectedDid2MailboxSendJournal.MaximumFloors; index++)
        {
            var identity = SHA256.HashData(BitConverter.GetBytes(index));
            state.EnrollScope(identity, identity); state.Revision++;
        }
        var first = SHA256.HashData(BitConverter.GetBytes(0)); state.AdvanceCounter(first, 7); state.Revision++;
        Assert.Throws<IOException>(() => state.EnrollScope(Bytes(32, 0x17), Bytes(32, 0x19)));
        Assert.Throws<CryptographicException>(() => state.EnrollScope(Bytes(32, 0x18), first));
        Assert.Throws<IOException>(() => state.EnrollScope(first, Bytes(32, 0x19)));
        Assert.Equal(8UL, state.MinimumCounter(first)); Assert.Empty(state.Entries);
        using var reopened = ProtectedDid2MailboxSendJournal.Decode(
            ProtectedDid2MailboxSendJournal.Encode(state, Network, Account, Instance), Network, Account, Instance);
        Assert.Equal(8UL, reopened.MinimumCounter(first)); Assert.Equal(ProtectedDid2MailboxSendJournal.MaximumFloors, reopened.Floors.Count);
    }

    private static ProtectedDid2MailboxSendJournal.Entry Pending(byte operation)
    {
        var exact = Bytes(Did2MessagingSessionScope.Bytes, 0x30); exact[0] = 1; exact[1] = 1; exact[2] = 0; exact[3] = 0;
        exact[132] = 0x31; exact[172] = 0x32;
        var scope = Did2MessagingSessionScope.RestoreMetadata(exact);
        return ProtectedDid2MailboxSendJournal.Entry.Pending(scope, Bytes(32, operation), Bytes(32, 0x18), Bytes(32, 0x19), new()
        {
            Epoch = 1, MailboxId = new(Bytes(32, 0x16)), PlacementId = new(Bytes(32, 0x17)),
            OperationId = Bytes(16, operation), DeduplicationDigest = System.Security.Cryptography.SHA256.HashData(Bytes(64, 0x22)),
            CreatedAtUnixSeconds = 1000, ExpiresAtUnixSeconds = 1200, Ciphertext = Bytes(64, 0x22)
        });
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
