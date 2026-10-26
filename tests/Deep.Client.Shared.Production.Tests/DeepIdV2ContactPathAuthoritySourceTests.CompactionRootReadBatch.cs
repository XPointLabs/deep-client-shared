using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task CompactionRootReadBatch_ActualPreparedPrefixHasOneFreshInventoryAndKeepsMissingCancellationAndColdRecovery()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var rows = checked((int)(await fixture.ReadMessagingFloor(sender)).Ordinal);
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Prepared prefix interruption."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CompactSenderPrefix(sender, rows, default));
        await fixture.CheckPrefixRootReadBatch(sender);
        fixture.ColdReopenCompactionStorage();
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertSenderCompactionIdle(sender);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPrefixRootReadBatch(Did2MessagingSessionScope scope)
        {
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await ownerLease.AcquireAsync(default);
            using var plan = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage,
                scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope.Instance.ToArray(), default);
            var slots = new[] { ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, Did2MessagingHistoryCheckpoint.Slot(scope),
                ProtectedDid2MessagingPeerBootstrap.Slot(scope), Did2CompactionPlan.Slot };
            Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> Read(CancellationToken ct = default) =>
                ProtectedDeepIdV2AccountOwner.ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, ownerLease, ct);
            storage.TrackApplicationReads = true;
            storage.ApplicationReadGroups.Clear(); storage.ApplicationSingleReads = 0;
            var before = await Read(); var again = await Read();
            Assert.Equal(2, storage.ApplicationReadGroups.Count);
            Assert.All(storage.ApplicationReadGroups, group => Assert.Equal(slots, group));
            Assert.Equal(0, storage.ApplicationSingleReads);
            Assert.Equal(before.Select(root => Convert.ToHexString(root.Digest.Span)), again.Select(root => Convert.ToHexString(root.Digest.Span)));
            storage.TrackApplicationReads = false;
            using var original = await storage.ReadOwnedBatchAsync(slots);
            for (var index = 0; index < slots.Length; index++)
            {
                var exact = original[index]!.Use(bytes => bytes.ToArray());
                try
                {
                    await storage.DeleteBatchAsync([slots[index]]);
                    await Assert.ThrowsAsync<InvalidDataException>(() => Read());
                    await storage.WriteBatchAsync([new(slots[index], exact)]);
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            using var cancellation = new CancellationTokenSource();
            storage.AfterCompactionRootsReadGroup = cancellation.Cancel;
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Read(cancellation.Token));
            Assert.Null(storage.AfterCompactionRootsReadGroup);
            var after = await Read();
            Assert.Equal(before.Select(root => Convert.ToHexString(root.Digest.Span)), after.Select(root => Convert.ToHexString(root.Digest.Span)));
            using var actual = await storage.ReadOwnedBatchAsync(slots);
            for (var index = 0; index < slots.Length; index++)
                Assert.Equal(original[index]!.Use(bytes => SHA256.HashData(bytes)), actual[index]!.Use(bytes => SHA256.HashData(bytes)));
        }
    }
}
