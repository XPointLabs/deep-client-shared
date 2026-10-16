using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, -1)]
    [InlineData(true, -1)]
    [InlineData(false, 0)]
    [InlineData(true, 0)]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 2)]
    [InlineData(true, 2)]
    [InlineData(false, 3)]
    [InlineData(true, 3)]
    [InlineData(false, 4)]
    [InlineData(true, 4)]
    [InlineData(false, 5)]
    [InlineData(true, 5)]
    [InlineData(false, 6)]
    [InlineData(true, 6)]
    [InlineData(false, 7)]
    [InlineData(true, 7)]
    public async Task Did2ApplicationReadBatch_IndependentOwnedSnapshotPreservesMissingScopeAndCancellationChecks(bool recovery, int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckApplicationReadBatchAsync(recovery, fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckApplicationReadBatchAsync(bool recovery, int fault)
        {
            using var current = await ReadSenderCompactionCurrent() ?? throw new InvalidDataException();
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using (await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, path, current, held, default)) { }
            using var key = await storage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var instance = key.Use(bytes => bytes.Slice(56, 32).ToArray());
            try
            {
                Task<SqliteDeepMailboxStore> Open(CancellationToken ct) => recovery
                    ? SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage, path,
                        Network, current.AccountId, instance, held, lease, ct)
                    : SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, path, current, held, ct);
                storage.TrackApplicationReads = true;
                using (await Open(default)) { }
                Assert.Equal(0, storage.ApplicationSingleReads);
                var slots = Assert.Single(storage.ApplicationReadGroups);
                Assert.Equal(6, slots.Length);
                Assert.Equal(6, slots.Distinct(StringComparer.Ordinal).Count());
                using (await Open(default)) { }
                Assert.Equal(2, storage.ApplicationReadGroups.Count);
                Assert.Equal(0, storage.ApplicationSingleReads);
                storage.TrackApplicationReads = false;
                if (fault == -1) return;
                if (fault < 6) await storage.DeleteBatchAsync([slots[fault]]);
                if (fault == 7)
                {
                    using var original = await storage.ReadOwnedAsync(slots[1]) ?? throw new InvalidDataException();
                    var expected = original.Use(bytes => bytes.ToArray());
                    var changed = expected.ToArray();
                    try
                    {
                        changed[52] ^= 1;
                        Assert.True(await storage.CompareExchangeAsync(slots[1], expected, changed));
                    }
                    finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(changed); }
                }
                using var before = await storage.ReadOwnedBatchAsync(slots);
                var commitments = Enumerable.Range(0, slots.Length).Select(i => before[i]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
                var sqlBefore = SHA256.HashData(await File.ReadAllBytesAsync(path + ".application.dmb1"));
                if (fault == 6)
                {
                    using var cancelled = new CancellationTokenSource();
                    storage.AfterApplicationReadGroup = cancelled.Cancel;
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { using var refused = await Open(cancelled.Token); });
                    Assert.Null(storage.AfterApplicationReadGroup);
                }
                else await Assert.ThrowsAsync<InvalidDataException>(async () => { using var refused = await Open(default); });
                using var after = await storage.ReadOwnedBatchAsync(slots);
                for (var i = 0; i < slots.Length; i++) Assert.Equal(commitments[i], after[i]?.Use(bytes => SHA256.HashData(bytes)));
                Assert.Equal(sqlBefore, SHA256.HashData(await File.ReadAllBytesAsync(path + ".application.dmb1")));
            }
            finally { CryptographicOperations.ZeroMemory(instance); }
        }
    }
}
