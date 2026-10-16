using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(-1)] // Independent unchanged snapshots, no plaintext cache.
    [InlineData(0)] // Lost current projection marker.
    [InlineData(1)] // Lost exact-history anchor.
    [InlineData(2)] // SQL rollback behind a future projection marker.
    [InlineData(3)] // SQL rollback behind a future history anchor.
    [InlineData(4)] // Cancellation after the actual batch callback.
    public async Task Did2NetworkMarkerBatch_OneAtomicReadKeepsAllFloorAndCancellationChecks(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.Source().VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        await fixture.CheckNetworkMarkerBatchAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckNetworkMarkerBatchAsync(int fault)
        {
            storage.TrackNetworkMarkerReads = true;
            storage.NetworkMarkerSingleReads = 0;
            storage.NetworkMarkerReadGroups.Clear();
            var history = (IDeepIdV2NetworkHistoryStore)NetworkStore;
            var first = await history.ReadHistoryAsync(default);
            Assert.NotNull(first);
            Assert.Equal(0, storage.NetworkMarkerSingleReads);
            var slots = Assert.Single(storage.NetworkMarkerReadGroups);
            Assert.Equal(4, slots.Length);
            Assert.Equal(4, slots.Distinct(StringComparer.Ordinal).Count());
            var second = await history.ReadHistoryAsync(default);
            Assert.NotNull(second);
            Assert.Equal(first.ExactHistory.ToArray(), second.ExactHistory.ToArray());
            Assert.Equal(2, storage.NetworkMarkerReadGroups.Count);
            Assert.Equal(0, storage.NetworkMarkerSingleReads);
            if (fault == -1) return;

            if (fault is 0 or 1) await storage.DeleteBatchAsync([slots[fault]]);
            else if (fault is 2 or 3)
            {
                using var original = await storage.ReadOwnedAsync(slots[fault - 2]);
                Assert.NotNull(original);
                var bytes = original.Use(value => value.ToArray());
                try { await storage.WriteBatchAsync([new(slots[fault], bytes)]); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            using var before = await storage.ReadOwnedBatchAsync(slots);
            var commitments = Enumerable.Range(0, slots.Length)
                .Select(index => before[index]?.Use(value => SHA256.HashData(value))).ToArray();
            if (fault == 4)
            {
                using var cancelled = new CancellationTokenSource();
                storage.AfterNetworkMarkerReadGroup = cancelled.Cancel;
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await history.ReadHistoryAsync(cancelled.Token));
                Assert.Null(storage.AfterNetworkMarkerReadGroup);
            }
            else await Assert.ThrowsAsync<CryptographicException>(async () => await history.ReadHistoryAsync(default));
            using var after = await storage.ReadOwnedBatchAsync(slots);
            for (var index = 0; index < slots.Length; index++)
                Assert.Equal(commitments[index], after[index]?.Use(value => SHA256.HashData(value)));
        }
    }
}
