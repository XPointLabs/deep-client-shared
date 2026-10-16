using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public async Task Did2AuthorityFloorBatch_ActualPairedRecheckKeepsIndependentReadsAndRejectsFloorDamage(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckAuthorityFloorBatchAsync(fault);
    }

    [Fact]
    public async Task Did2AuthorityFloorBatch_AnotherActualAccountBackendCannotSupplyTheNetworkFloor()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await using var foreign = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckForeignAuthorityFloorAsync(foreign);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckForeignAuthorityFloorAsync(Fixture foreign)
        {
            var source = Source();
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            NetworkStore = foreign.NetworkStore;
            var mixed = Source();
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await mixed.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, held, default));
        }

        internal async Task CheckAuthorityFloorBatchAsync(int fault)
        {
            var source = Source();
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            storage.TrackApplicationReads = true;
            await source.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, held, default);
            Assert.Equal(1, storage.ApplicationSingleReads); // Actual SQL key; no cached connection/key.
            var slots = Assert.Single(storage.ApplicationReadGroups);
            Assert.InRange(slots.Length, 6, 8);
            Assert.Equal(slots.Length, slots.Distinct(StringComparer.Ordinal).Count());
            await source.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, held, default);
            Assert.Equal(2, storage.ApplicationSingleReads);
            Assert.Equal(2, storage.ApplicationReadGroups.Count);
            storage.TrackApplicationReads = false;
            if (fault == -1) return;

            var directorySlots = slots.Where(slot => slot.Contains(".directory-lkg-floor.", StringComparison.Ordinal))
                .OrderBy(slot => long.Parse(slot[(slot.LastIndexOf('.') + 1)..], System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            var networkSlots = slots.Where(slot => slot.Contains(".network-lkg-floor.", StringComparison.Ordinal)).ToArray();
            Assert.Equal(4, networkSlots.Length);
            var currentDirectory = directorySlots[^2]; var futureDirectory = directorySlots[^1];
            if (fault is 0 or 2 or 3 or 9)
                await storage.DeleteBatchAsync([fault switch { 0 => currentDirectory, 2 => networkSlots[0], 3 => networkSlots[1], _ => directorySlots[0] }]);
            if (fault is 1 or 4 or 5 or 6)
            {
                var originalSlot = fault is 1 or 6 ? currentDirectory : networkSlots[fault - 4];
                var changedSlot = fault == 1 ? futureDirectory : fault == 6 ? currentDirectory : networkSlots[fault - 2];
                using var original = await storage.ReadOwnedAsync(originalSlot) ?? throw new InvalidDataException();
                var expected = original.Use(bytes => bytes.ToArray()); var changed = expected.ToArray();
                try
                {
                    if (fault == 6) { changed[^1] ^= 1; Assert.True(await storage.CompareExchangeAsync(changedSlot, expected, changed)); }
                    else await storage.WriteBatchAsync([new(changedSlot, changed)]);
                }
                finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(changed); }
            }
            using var before = await storage.ReadOwnedBatchAsync(slots);
            var commitments = Enumerable.Range(0, slots.Length).Select(i => before[i]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
            var sqlPath = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var sqlBefore = SHA256.HashData(await File.ReadAllBytesAsync(sqlPath));
            if (fault == 7)
            {
                using var cancelled = new CancellationTokenSource();
                storage.AfterNetworkMarkerReadGroup = cancelled.Cancel;
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await source.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, held, cancelled.Token));
                Assert.Null(storage.AfterNetworkMarkerReadGroup);
            }
            else if (fault == 8)
            {
                var foreignLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "foreign.lock"));
                using var foreignHeld = await foreignLease.AcquireAsync(default);
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                    await source.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, foreignHeld, default));
            }
            else await Assert.ThrowsAsync<CryptographicException>(async () =>
                await source.RecheckEndpointPairUnderLeaseAsync(own, own.Proof, held, default));
            using var after = await storage.ReadOwnedBatchAsync(slots);
            for (var i = 0; i < slots.Length; i++) Assert.Equal(commitments[i], after[i]?.Use(bytes => SHA256.HashData(bytes)));
            Assert.Equal(sqlBefore, SHA256.HashData(await File.ReadAllBytesAsync(sqlPath)));
        }
    }
}
