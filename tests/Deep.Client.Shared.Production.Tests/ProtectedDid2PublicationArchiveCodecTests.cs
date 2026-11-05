using System.Buffers.Binary;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDid2PublicationArchiveCodecTests
{
    private static readonly byte[] Network = Enumerable.Repeat((byte)1, 16).ToArray();
    private static readonly byte[] Account = Enumerable.Repeat((byte)2, 32).ToArray();
    private static readonly byte[] Instance = Enumerable.Repeat((byte)3, 32).ToArray();

    [Fact]
    public void ExplicitEnrollmentIsTheOnlyReaderOfAnExactV10Source()
    {
        var current = ProtectedDid2ContactRouteJournal.Empty(Network, Account, Instance);
        var old = current.AsSpan(0, 92).ToArray(); old[0] = 10;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactRouteJournal.Decode(old, Network, Account, Instance));
        using var source = ProtectedDid2ContactRouteJournal.DecodeForEnrollment(old, Network, Account, Instance);
        Assert.Empty(source.Entries); Assert.Empty(source.Archived);
        var enrolled = ProtectedDid2ContactRouteJournal.Encode(source, Network, Account, Instance);
        Assert.Equal(current, enrolled);
        using var reopened = ProtectedDid2ContactRouteJournal.Decode(enrolled, Network, Account, Instance);
        Assert.Empty(reopened.Entries); Assert.Empty(reopened.Archived);
    }

    [Theory]
    [InlineData(9)]
    [InlineData(12)]
    public void ExplicitEnrollmentNeverImportsAnotherGeneration(byte version)
    {
        var bytes = ProtectedDid2ContactRouteJournal.Empty(Network, Account, Instance); bytes[0] = version;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactRouteJournal.DecodeForEnrollment(bytes, Network, Account, Instance));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void HostileArchiveReferenceFailsBeforeAnyArchiveRead(int mode)
    {
        var bytes = new byte[ProtectedDid2ContactRouteJournal.HeaderBytes + ProtectedDid2ContactRouteJournal.ArchiveReferenceBytes];
        ProtectedDid2ContactRouteJournal.Empty(Network, Account, Instance).CopyTo(bytes, 0); bytes[1] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(4), 8);
        var row = bytes.AsSpan(ProtectedDid2ContactRouteJournal.HeaderBytes);
        row[..96].Fill(4); BinaryPrimitives.WriteUInt32BigEndian(row[96..], 1000);
        if (mode == 0) BinaryPrimitives.WriteUInt32BigEndian(row[96..], uint.MaxValue);
        if (mode == 1) row[100] = 1;
        if (mode == 2) row.Slice(32, 32).Clear();
        // Mode3 is otherwise framed but cannot archive without a current working owner.
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactRouteJournal.Decode(bytes, Network, Account, Instance));
    }

    [Fact]
    public void ArchiveQuotaAndCombinedIntentQuotaDoNotIncreaseProtectedInventoryLimits()
    {
        Assert.Equal(1024, DeepSecureStorageRegistration.MaximumEntries);
        Assert.Equal(8 * 1024 * 1024, DeepSecureStorageRegistration.MaximumPlaintextBytes);
        Assert.Equal(1024 * 1024, ProtectedDid2ContactRouteJournal.MaximumBytes);
        Assert.Equal(4 * 1024 * 1024, ProtectedDid2ContactRouteJournal.MaximumArchivedBytes);
        Assert.Equal(128, ProtectedDid2ContactRouteJournal.MaximumIntents);
        using var state = new ProtectedDid2ContactRouteJournal.State();
        for (var index = 1; index <= 9; index++)
        {
            var name = new byte[32]; BinaryPrimitives.WriteUInt32BigEndian(name, (uint)index);
            state.Archived.Add(Convert.ToHexString(name), new(new byte[32], new byte[32], ProtectedDid2ContactRouteJournal.MaximumEntryBytes));
        }
        Assert.Throws<IOException>(() => ProtectedDid2ContactRouteJournal.Encode(state, Network, Account, Instance));
        for (var index = 10; index <= 129; index++)
        {
            var name = new byte[32]; BinaryPrimitives.WriteUInt32BigEndian(name, (uint)index);
            state.Archived.Add(Convert.ToHexString(name), new(new byte[32], new byte[32], 1));
        }
        Assert.Throws<IOException>(() => ProtectedDid2ContactRouteJournal.Encode(state, Network, Account, Instance));
    }
}
