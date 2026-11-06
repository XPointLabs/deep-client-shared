using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AtomicQueueBatch_RejectsAnyChangedRootWithoutPartialMutation(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("command", new byte[] { 1 }), new("session-a", new byte[] { 2 }), new("session-b", new byte[] { 3 })]);
        var guards = new Dictionary<string, byte[]> { ["command"] = [1], ["session-a"] = [2], ["session-b"] = [9] };
        DeepSecureStorageWrite[] writes = [new("command", new byte[] { 4 }), new("session-a", new byte[] { 5 }), new("session-b", new byte[] { 6 }), new("pending", new byte[] { 7 })];
        Assert.False(await fixture.Store.CompareExchangeBatchAsync(guards, writes, default));
        using var unchanged = await fixture.Store.ReadOwnedBatchAsync(["command", "session-a", "session-b", "pending"]);
        Assert.Equal(1, unchanged[0]!.Use(bytes => bytes[0])); Assert.Equal(2, unchanged[1]!.Use(bytes => bytes[0]));
        Assert.Equal(3, unchanged[2]!.Use(bytes => bytes[0])); Assert.Null(unchanged[3]);
        guards["session-b"] = [3];
        Assert.True(await fixture.Store.CompareExchangeBatchAsync(guards, writes, default));
        Assert.False(await fixture.Store.CompareExchangeBatchAsync(guards, writes, default));
        using var committed = await fixture.Store.ReadOwnedBatchAsync(["command", "session-a", "session-b", "pending"]);
        Assert.Equal(4, committed[0]!.Use(bytes => bytes[0])); Assert.Equal(5, committed[1]!.Use(bytes => bytes[0]));
        Assert.Equal(6, committed[2]!.Use(bytes => bytes[0])); Assert.Equal(7, committed[3]!.Use(bytes => bytes[0]));
    }

    [Theory]
    [InlineData("AfterPendingManifest", false)]
    [InlineData("AfterObjectStaged", false)]
    [InlineData("BeforeManifestReplace", false)]
    [InlineData("AfterManifestReplace", true)]
    [InlineData("AfterRetirementUnlink", true)]
    [InlineData("AfterCleanupManifest", true)]
    public async Task AtomicQueueBatch_ActualJournalCrashColdRecoversAllOrNoTargets(string point, bool committed)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("command", new byte[] { 1 }), new("session-a", new byte[] { 2 }), new("session-b", new byte[] { 3 })]);
        var guards = new Dictionary<string, byte[]> { ["command"] = [1], ["session-a"] = [2], ["session-b"] = [3] };
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(Enum.Parse<JournaledDeepSecureStorageFailpoint>(point)))
        {
            await Assert.ThrowsAsync<IOException>(() => fixture.Store.CompareExchangeBatchAsync(guards,
                [new("command", new byte[] { 4 }), new("session-a", new byte[] { 5 }), new("session-b", new byte[] { 6 }), new("pending", new byte[] { 7 })], default));
            Assert.True(crash.Reached);
        }
        using var reopened = fixture.OpenJournaled();
        using var inventory = await reopened.ReadOwnedBatchAsync(["command", "session-a", "session-b", "pending"]);
        Assert.Equal(committed ? 4 : 1, inventory[0]!.Use(bytes => bytes[0]));
        Assert.Equal(committed ? 5 : 2, inventory[1]!.Use(bytes => bytes[0]));
        Assert.Equal(committed ? 6 : 3, inventory[2]!.Use(bytes => bytes[0]));
        if (committed) Assert.Equal(7, inventory[3]!.Use(bytes => bytes[0])); else Assert.Null(inventory[3]);
        await reopened.AuditAsync();
    }
}
