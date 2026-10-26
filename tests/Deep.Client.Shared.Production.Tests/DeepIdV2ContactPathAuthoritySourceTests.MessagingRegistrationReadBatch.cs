using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task MessagingRegistrationReadBatch_ActualEncryptedReopenKeepsEveryRootAndCancellationGuard()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        await fixture.CheckMessagingRegistrationReadBatch(sender);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckMessagingRegistrationReadBatch(Did2MessagingSessionScope scope)
        {
            var accountPath = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var sqlPath = Path.Combine(accountPath + ".messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await ownerLease.AcquireAsync(default);
            var slots = new[] { SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
                ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope) };
            async Task Open(CancellationToken ct = default)
            {
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenRegisteredMessagingUnderLeaseAsync(
                    storage, accountPath, scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope, ct);
                held.RequireOwner(ownerLease);
            }

            storage.TrackApplicationReads = true;
            storage.ApplicationReadGroups.Clear(); storage.ApplicationSingleReads = 0;
            await Open(); await Open();
            Assert.Equal(6, storage.ApplicationReadGroups.Count);
            var roots = new[] { scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope) };
            Assert.Equal(new[] { slots, roots, roots, slots, roots, roots }, storage.ApplicationReadGroups.ToArray());
            // Reconciliation now joins the mandatory ACTUAL history with the
            // floor before SQL and after orphan-cleanup callbacks (DR-0175).
            Assert.Equal(0, storage.ApplicationSingleReads);
            storage.TrackApplicationReads = false;
            ColdReopenCompactionStorage();
            await Open();

            using var original = await storage.ReadOwnedBatchAsync(slots);
            var sqlBefore = SHA256.HashData(await File.ReadAllBytesAsync(sqlPath));
            for (var index = 0; index < slots.Length; index++)
            {
                var slot = slots[index];
                var exact = original[index]!.Use(bytes => bytes.ToArray());
                var changed = exact.ToArray();
                try
                {
                    await storage.DeleteBatchAsync([slot]);
                    await Assert.ThrowsAsync<InvalidDataException>(() => Open());
                    Assert.Equal(sqlBefore, SHA256.HashData(await File.ReadAllBytesAsync(sqlPath)));
                    await storage.WriteBatchAsync([new(slot, exact)]);
                    // Same-length, well-protected replacement: each selected
                    // registration still enforces its exact owner/scope grammar.
                    changed[index switch { 0 => 8, 1 => 12, _ => 12 }] ^= 1;
                    Assert.True(await storage.CompareExchangeAsync(slot, exact, changed));
                    var error = await Record.ExceptionAsync(() => Open());
                    Assert.True(error is InvalidDataException or CryptographicException);
                    Assert.Equal(sqlBefore, SHA256.HashData(await File.ReadAllBytesAsync(sqlPath)));
                    Assert.True(await storage.CompareExchangeAsync(slot, changed, exact));
                }
                finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(changed); }
            }
            using var cancelled = new CancellationTokenSource();
            storage.AfterMessagingRegistrationReadGroup = cancelled.Cancel;
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Open(cancelled.Token));
            Assert.Null(storage.AfterMessagingRegistrationReadGroup);
            Assert.Equal(sqlBefore, SHA256.HashData(await File.ReadAllBytesAsync(sqlPath)));
            using var after = await storage.ReadOwnedBatchAsync(slots);
            for (var index = 0; index < slots.Length; index++)
                Assert.Equal(original[index]!.Use(bytes => SHA256.HashData(bytes)), after[index]!.Use(bytes => SHA256.HashData(bytes)));
            await Open();
        }
    }
}
