using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")] [InlineData("first")] [InlineData("last")] [InlineData("cancelled")]
    public async Task Did2CompactionPartReadBatch_IdleReopenKeepsEveryOrphanAndCancellationGuard(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckIdleCompactionPartReadBatch(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckIdleCompactionPartReadBatch(string fault)
        {
            using (var baseline = await ReadSenderCompactionCurrent()) Assert.NotNull(baseline);
            var slots = Enumerable.Range(0, 16).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray();
            if (fault is "first" or "last")
                await storage.WriteBatchAsync([new(slots[fault == "first" ? 0 : 15], new byte[] { 1 })]);
            using var before = await innerStorage.ReadOwnedBatchAsync(slots);
            var hashes = Enumerable.Range(0, 16).Select(i => before[i]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
            storage.TrackApplicationReads = true; storage.ApplicationReadGroups.Clear(); storage.CompactionPartSingleReads = 0;
            using var cancelled = new CancellationTokenSource();
            if (fault == "cancelled") storage.AfterCompactionPartReadGroup = cancelled.Cancel;
            if (fault == "none")
            {
                using (var first = await ReadSenderCompactionCurrent()) Assert.NotNull(first);
                using (var second = await ReadSenderCompactionCurrent()) Assert.NotNull(second);
            }
            else
            {
                var error = await Record.ExceptionAsync(async () =>
                {
                    using var current = await SenderCompactionOwner().ReadCurrentAsync(1_000, pq, cancelled.Token);
                });
                if (fault == "cancelled") Assert.IsAssignableFrom<OperationCanceledException>(error);
                else Assert.IsType<InvalidDataException>(error);
            }
            Assert.Equal(fault == "none" ? 2 : 1,
                storage.ApplicationReadGroups.Count(group => group.SequenceEqual(slots)));
            Assert.Equal(0, storage.CompactionPartSingleReads);
            Assert.Null(storage.AfterCompactionPartReadGroup);
            storage.TrackApplicationReads = false;
            using var after = await innerStorage.ReadOwnedBatchAsync(slots);
            for (var i = 0; i < slots.Length; i++)
                Assert.Equal(hashes[i], after[i]?.Use(bytes => SHA256.HashData(bytes)));
        }
    }
}
