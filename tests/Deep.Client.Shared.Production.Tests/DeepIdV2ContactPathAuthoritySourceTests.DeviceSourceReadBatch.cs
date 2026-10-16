using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, -1)] [InlineData(true, -1)]
    [InlineData(false, 0)] [InlineData(true, 0)]
    [InlineData(false, 1)] [InlineData(true, 1)]
    [InlineData(false, 2)] [InlineData(true, 2)]
    [InlineData(false, 3)] [InlineData(true, 3)]
    public async Task Did2DeviceSourceReadBatch_FreshGroupsKeepMissingForeignAndCancellationChecks(bool retirementOnly, int fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckDeviceSourceReadBatch(retirementOnly, fault);
    }

    [Fact]
    public async Task Did2DeviceSourceReadBatch_EmptyRetirementDoesNotInventCancellationOwnerRequirements()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckEmptyRetirementOptionalOwners();
    }

    [Theory]
    [InlineData("none")] [InlineData("draft")] [InlineData("catalog")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2DeviceSourceReadBatch_ActualCancelledOwnerIsStillRequiredAfterColdReopen(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xb7);
        _ = await fixture.PrepareNativeHelloCompletion(intent, preSessionCut: "unknown-claim");
        await fixture.CancelPreSessionInitial(intent);
        fixture.ColdReopenCompactionStorage();
        await fixture.AssertPreSessionCancelled(intent);
        await fixture.CheckCancelledRetirementBatch(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckDeviceSourceReadBatch(bool retirementOnly, int fault)
        {
            using var current = await ReadSenderCompactionCurrent() ?? throw new InvalidDataException();
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            async Task Open(CancellationToken ct)
            {
                if (retirementOnly)
                    _ = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, current.AccountId, ct);
                else
                    using (await SqliteDeepIdV2AccountGeneration.OpenCurrentDeviceStateStoreAsync(storage, path, current, ct)) { }
            }
            await Open(default); // Establish the real device registration before fault injection.
            storage.TrackApplicationReads = true;
            storage.ApplicationReadGroups.Clear(); storage.ApplicationSingleReads = 0;
            await Open(default); await Open(default);
            Assert.Equal(retirementOnly ? 2 : 4, storage.ApplicationReadGroups.Count);
            Assert.Equal(retirementOnly ? 0 : 2, storage.ApplicationSingleReads); // Checkpoint remains a fresh read.
            var groups = storage.ApplicationReadGroups.ToArray();
            var selected = groups.First(group => group.Length == (retirementOnly ? 4 : 2));
            Assert.Equal(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, selected[0]);
            Assert.Equal(retirementOnly ? ProtectedInitialKeyRetirementJournal.Slot : SqliteDeepIdV2AccountGeneration.DeviceStateMarkerSlot, selected[1]);
            Assert.All(groups, group => Assert.Equal(group.Length, group.Distinct(StringComparer.Ordinal).Count()));
            storage.TrackApplicationReads = false;
            if (fault == -1) return;
            if (fault is 0 or 1) await storage.DeleteBatchAsync([selected[fault]]);
            if (fault == 2)
            {
                using var original = await storage.ReadOwnedAsync(selected[1]) ?? throw new InvalidDataException();
                var before = original.Use(bytes => bytes.ToArray()); var changed = before.ToArray();
                try
                {
                    // Exact marker scope or retirement network binding, not a parse shortcut.
                    changed[retirementOnly ? 12 : 0] ^= 1;
                    Assert.True(await storage.CompareExchangeAsync(selected[1], before, changed));
                }
                finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(changed); }
            }
            using var snapshot = await storage.ReadOwnedBatchAsync(selected);
            var commitments = Enumerable.Range(0, selected.Length).Select(i => snapshot[i]?.Use(bytes => SHA256.HashData(bytes))).ToArray();
            var devicePath = SqliteDeepIdV2AccountGeneration.DeviceStatePath(path);
            var sqlBefore = File.Exists(devicePath) ? SHA256.HashData(await File.ReadAllBytesAsync(devicePath)) : null;
            if (fault == 3)
            {
                using var cancel = new CancellationTokenSource();
                if (retirementOnly) storage.AfterRetirementReadGroup = cancel.Cancel;
                else storage.AfterDeviceRegistrationReadGroup = cancel.Cancel;
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Open(cancel.Token));
                Assert.Null(storage.AfterDeviceRegistrationReadGroup); Assert.Null(storage.AfterRetirementReadGroup);
            }
            else
            {
                var error = await Record.ExceptionAsync(() => Open(default));
                Assert.True(error is InvalidDataException or CryptographicException);
            }
            using var after = await storage.ReadOwnedBatchAsync(selected);
            for (var i = 0; i < selected.Length; i++) Assert.Equal(commitments[i], after[i]?.Use(bytes => SHA256.HashData(bytes)));
            Assert.Equal(sqlBefore, File.Exists(devicePath) ? SHA256.HashData(await File.ReadAllBytesAsync(devicePath)) : null);
        }

        internal async Task CheckEmptyRetirementOptionalOwners()
        {
            using var current = await ReadSenderCompactionCurrent() ?? throw new InvalidDataException();
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            await storage.DeleteBatchAsync([ProtectedDid2ContactStartJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot]);
            var state = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, current.AccountId, default);
            Assert.Empty(state.Entries); // No cancellation exists; no absent owner is inferred for live work.
        }

        internal async Task CheckCancelledRetirementBatch(string fault)
        {
            using var current = await ReadSenderCompactionCurrent() ?? throw new InvalidDataException();
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            if (fault != "none")
                await storage.DeleteBatchAsync([fault == "draft" ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2MessagingSessionCatalog.Slot]);
            storage.TrackApplicationReads = true;
            storage.ApplicationReadGroups.Clear(); storage.ApplicationSingleReads = 0;
            if (fault == "none")
            {
                var state = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, current.AccountId, default);
                Assert.Equal(3, Assert.Single(state.Entries).Value.Role);
            }
            else await Assert.ThrowsAsync<InvalidDataException>(() => ProtectedInitialKeyRetirementJournal.ReadAsync(storage, Network, current.AccountId, default));
            Assert.Equal(4, Assert.Single(storage.ApplicationReadGroups).Length);
            Assert.Equal(0, storage.ApplicationSingleReads);
            storage.TrackApplicationReads = false;
        }
    }
}
