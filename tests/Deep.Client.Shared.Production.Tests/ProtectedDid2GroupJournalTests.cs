using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ProtectedDid2GroupJournalTests
{
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();

    [Fact]
    public void MandatoryRegistrationBindsAccountInstanceAndRejectsUnknownGenerations()
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        var exact = ProtectedDid2GroupJournal.Empty(network, account, instance);
        Assert.Equal(102, exact.Length);
        Assert.Equal((byte)3, exact[0]);
        var retired = exact.ToArray(); retired[0] = 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(retired, network, account, instance));
        retired[0] = 2;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(retired, network, account, instance));
        using var reopened = ProtectedDid2GroupJournal.Decode(exact, network, account, instance);
        Assert.Empty(reopened.Groups); Assert.Empty(reopened.Outbox); Assert.Empty(reopened.Messages); Assert.Empty(reopened.Receives); Assert.Empty(reopened.Chunks);
        Assert.Equal(1UL, reopened.Revision);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode([], network, account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(exact, B(16, 4), account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(exact, network, B(32, 4), instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(exact, network, account, B(32, 4)));
        foreach (var offset in new[] { 0, 1, 2, 3 })
        { var changed = exact.ToArray(); changed[offset] ^= 0x80; Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(changed, network, account, instance)); }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(exact[..^1], network, account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode([.. exact, 0], network, account, instance));
        var zeroRevision = exact.ToArray(); zeroRevision.AsSpan(84, 8).Clear();
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(zeroRevision, network, account, instance));
    }

    [Fact]
    public void HostileCountsRejectBeforeReadingOrAllocatingEntries()
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        var exact = ProtectedDid2GroupJournal.Empty(network, account, instance);
        foreach (var offset in new[] { 92, 94, 96, 98, 100 })
        {
            var changed = exact.ToArray(); BinaryPrimitives.WriteUInt16LittleEndian(changed.AsSpan(offset), ushort.MaxValue);
            Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Decode(changed, network, account, instance));
        }
        using var state = new ProtectedDid2GroupJournal.State();
        for (var i = 0; i < 513; i++) state.Outbox.Add(new());
        Assert.Throws<IOException>(() => ProtectedDid2GroupJournal.Encode(state, network, account, instance));
    }

    [Fact]
    public void NativeSelectorsAreExactUniqueAndZeroizedOnDisposal()
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        using var state = new ProtectedDid2GroupJournal.State();
        state.Receives.Add(new() { ScopeHash = B(32, 4), Operation = B(32, 5), Hash = B(32, 6) });
        var exact = ProtectedDid2GroupJournal.Encode(state, network, account, instance);
        using var reopened = ProtectedDid2GroupJournal.Decode(exact, network, account, instance);
        var selected = Assert.Single(reopened.Receives); Assert.Equal(B(32, 6), selected.Hash);
        state.Receives.Add(new() { ScopeHash = B(32, 4), Operation = B(32, 5), Hash = B(32, 7) });
        Assert.Throws<InvalidDataException>(() => ProtectedDid2GroupJournal.Encode(state, network, account, instance));
        reopened.Dispose(); Assert.All(selected.Hash, value => Assert.Equal((byte)0, value));
    }
}
