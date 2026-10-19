using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GroupAggregateCanCrossOrdinarySlotBoundWithoutChangingFormatOrOtherSlots(bool journaled)
    {
        using var f = new Fixture(journaled);
        var group = new byte[1024 * 1024 + 1]; group[^1] = 7;
        var next = group.ToArray(); next[^1] = 8;
        await f.Store.WriteBatchAsync([new(ProtectedDid2GroupJournal.Slot, group), new("foreign", new byte[] { 9 })]);
        Assert.True(await f.Store.CompareExchangeAsync(ProtectedDid2GroupJournal.Slot, group, next));
        Assert.False(await f.Store.CompareExchangeAsync(ProtectedDid2GroupJournal.Slot, group, next));
        Assert.True(await f.Store.CompareExchangeAndInsertAsync(ProtectedDid2GroupJournal.Slot, next, group,
            [new("part", new byte[] { 1 })]));
        Assert.True(await f.Store.CompareAndDeleteAsync(ProtectedDid2GroupJournal.Slot, group, ["part"]));
        using var current = await f.Store.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot);
        Assert.True(current!.Use(value => value.SequenceEqual(group)));
        using var foreign = await f.Store.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(value => value[0]));
        if (journaled)
        {
            using var reopened = f.OpenJournaled();
            using var retained = await reopened.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot);
            Assert.True(retained!.Use(value => value.SequenceEqual(group)));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GroupExceptionKeepsOrdinaryAndWholeInventoryBoundsAndRejectsAtomically(bool journaled)
    {
        using var f = new Fixture(journaled);
        var group = new byte[ProtectedDid2GroupJournal.MaximumBytes]; group[^1] = 7;
        var ordinary = new byte[1024 * 1024];
        await f.Store.WriteBatchAsync([new(ProtectedDid2GroupJournal.Slot, group),
            new("a", ordinary), new("b", ordinary), new("c", ordinary)]);
        await Assert.ThrowsAsync<ArgumentException>(() => f.Store.WriteBatchAsync([new("oversized", new byte[ordinary.Length + 1])]));
        await Assert.ThrowsAsync<ArgumentException>(() => f.Store.CompareExchangeAsync(ProtectedDid2GroupJournal.Slot,
            group, new byte[group.Length + 1]));
        // Four MiB for groups + four ordinary MiB + framing still exceeds the
        // unchanged eight MiB aggregate bound. No partially inserted slot.
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Store.WriteBatchAsync([new("overflow", ordinary)]));
        using var missing = await f.Store.ReadOwnedAsync("overflow"); Assert.Null(missing);
        using var current = await f.Store.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot);
        Assert.True(current!.Use(value => value.SequenceEqual(group)));
        if (journaled)
        {
            using var reopened = f.OpenJournaled();
            using var retained = await reopened.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot);
            Assert.True(retained!.Use(value => value.SequenceEqual(group)));
        }
    }
}
