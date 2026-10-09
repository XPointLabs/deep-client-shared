using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Did2ClosedDepositRetirement_ActualHeldPlanFreshOwnerResumePreservesOtherRoots(int handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckClosedDepositRetirementAsync(handover, abandon: false);
    }

    [Fact]
    public async Task Did2ClosedDepositRetirement_OnlyUncommittedExactPredecessorCanAbandon()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckClosedDepositRetirementAsync(0, abandon: true);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task Did2ClosedDepositRetirement_ChangedBindingGuardFloorOrMissingPartFailsClosed(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckClosedDepositRetirementAsync(0, abandon: false, fault: fault);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Did2ClosedDepositRetirement_CancellationPreservesPlanAtBothCommitBoundaries(int handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckClosedDepositRetirementAsync(handover, abandon: handover == 0, cancel: true);
    }

    private sealed partial class Fixture
    {
        private ProtectedDeepIdV2AccountOwner PeerRetirementOwner() => new(peerStorage,
            new DeepIdV2AccountFileLease(Path.Combine(directory, "peer", "deep-store-v2-account.lock")),
            Path.Combine(directory, "peer", "deep-store-v2-account.dsv2"), Network, 1);

        internal async Task CheckClosedDepositRetirementAsync(int handover, bool abandon, int fault = -1, bool cancel = false)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this) { ShorterSignedExpiry = 1_200 };
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, new OwnedPublicationSource(this, route), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var reader = ReopenGrantReader(); var source = GrantReaderSource(reader);
            var resolved = await reader.ResolvePermanentContactAsync(address, source, new SyntheticPermanentRead(this, source, replicas.ExactPublication));
            var transport = new OwnedGrantTransport(this) { LoseResponse = true };
            await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(resolved, source, transport));
            byte[] acquisition; ulong ceiling;
            using (var pending = await ReadPeerGrantsAsync())
            {
                var entry = Assert.Single(pending.Entries).Value;
                acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry);
            }
            await AdvanceNetworkAsync(); AuthorSignedEpochAdvance();
            var nextTime = checked(ceiling + 5); Sample = checked(Sample + nextTime - ProofTime); ProofTime = nextTime;
            reader = ReopenGrantReader(); source = GrantReaderSource(reader);
            Assert.Equal(1, await reader.CloseExpiredMailboxAcquisitionsAsync(source));
            var slots = new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot };
            var hashes = new List<byte[]>();
            foreach (var slot in slots)
            { using var raw = await peerStorage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            using var cancellation = new CancellationTokenSource();
            using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(acquisition, source))
            {
                var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                Assert.Equal(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.None, dependencies.Dependencies);
                using (Did2CompactionTestHooks.Push(point =>
                {
                    if (point != points[handover]) return;
                    if (cancel) cancellation.Cancel();
                    else throw new IOException("Injected protected retirement handover.");
                }))
                {
                    if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RetireUnusedClosedDepositAcquisitionAsync(cancellation.Token));
                    else await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedDepositAcquisitionAsync());
                }
            }
            Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();
            var owner = PeerRetirementOwner();
            // Fresh owner/SQL connection and reopened encrypted journal, using
            // the fixture protector rather than Windows/Android platform custody.
            if (fault >= 0)
            {
                await CheckRejectedRetirementRecoveryAsync(owner, fault);
                Assert.Equal(1, transport.Calls);
                CryptographicOperations.ZeroMemory(acquisition);
                return;
            }
            if (abandon) await owner.AbandonUncommittedMailboxRetirementAsync(default);
            else
            {
                if (handover > 0)
                    await Assert.ThrowsAsync<InvalidOperationException>(() => owner.AbandonUncommittedMailboxRetirementAsync(default));
                await owner.ResumeOwnedLocalCompactionAsync(default);
            }
            using (var after = await ReadPeerGrantsAsync())
            {
                Assert.Equal(abandon ? 1 : 0, after.Entries.Count);
                Assert.Equal(abandon ? 1 : 0, after.Selections.Count);
                if (abandon) Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(Assert.Single(after.Entries).Value));
            }
            using var key = await peerStorage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot) ?? throw new InvalidDataException();
            var ownerScope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            try
            {
                using var idle = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(peerStorage, Network, ownerScope.AsMemory(0, 32), ownerScope.AsMemory(32, 32), default);
                Assert.Equal(0, idle.Phase);
            }
            finally { CryptographicOperations.ZeroMemory(ownerScope); }
            for (var index = 0; index < slots.Length; index++)
            { using var raw = await peerStorage.ReadOwnedAsync(slots[index]) ?? throw new InvalidDataException(); Assert.Equal(hashes[index], raw.Use(bytes => SHA256.HashData(bytes))); }
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
                Assert.Null(await peerStorage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)));
            Assert.Equal(1, transport.Calls); // No issuer/signing/transport callback during recovery.
            Assert.NotNull(await ReopenGrantReader().GetCurrentAsync());
            CryptographicOperations.ZeroMemory(acquisition);
        }

        private async Task<SqliteConnection> OpenPeerRetirementSqlAsync()
        {
            using var record = await peerStorage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot) ?? throw new InvalidDataException();
            var key = record.Use(bytes => bytes.Slice(88, 32).ToArray());
            try { return SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(Path.Combine(directory, "peer", "deep-store-v2-account.dsv2"), key, create: false); }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        private async Task<string[]> RetirementProtectedSnapshotAsync()
        {
            var result = new List<string>();
            foreach (var slot in new[] { Did2CompactionPlan.Slot, ProtectedDid2MailboxGrantJournal.Slot,
                ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2DirectTextJournal.Slot,
                ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot }.Concat(
                    Enumerable.Range(0, Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes).Select(ProtectedDid2CompactionPlan.PartSlot)))
            {
                using var raw = await peerStorage.ReadOwnedAsync(slot);
                result.Add(raw is null ? "absent" : raw.Use(bytes => Convert.ToHexString(SHA256.HashData(bytes))));
            }
            return result.ToArray();
        }

        private async Task<string> RetirementSqlProjectionAsync()
        {
            await using var sql = await OpenPeerRetirementSqlAsync(); using var read = sql.CreateCommand();
            read.CommandText = """
                SELECT hex(CAST(p.display_name AS BLOB))||':'||hex(d.dpd1_hash)||':'||
                  coalesce((SELECT hex(payload)||':'||typeof(revision)||':'||revision FROM protected_lkg_root WHERE root_kind=3),'absent')
                FROM local_profile p,local_device d WHERE p.singleton=1 AND d.singleton=1;
                """;
            return Assert.IsType<string>(read.ExecuteScalar());
        }

        private async Task CheckRejectedRetirementRecoveryAsync(ProtectedDeepIdV2AccountOwner owner, int fault)
        {
            if (fault <= 2)
            {
                await using var sql = await OpenPeerRetirementSqlAsync(); using var change = sql.CreateCommand();
                change.CommandText = fault switch
                {
                    0 => "UPDATE local_profile SET display_name='Other valid name' WHERE singleton=1;",
                    1 => "UPDATE local_device SET dpd1_hash=randomblob(32) WHERE singleton=1;",
                    _ => "DELETE FROM protected_lkg_root WHERE root_kind=3;"
                };
                Assert.Equal(1, change.ExecuteNonQuery());
            }
            else if (fault == 3) await peerStorage.DeleteBatchAsync([ProtectedDid2MailboxSendJournal.Slot]);
            else if (fault == 4)
            {
                using var raw = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                var before = raw.Use(bytes => bytes.ToArray());
                using var key = await peerStorage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot) ?? throw new InvalidDataException();
                var binding = key.Use(bytes => bytes.Slice(24, 64).ToArray());
                using var state = ProtectedDid2MailboxSendJournal.Decode(before, Network, binding.AsSpan(0, 32), binding.AsSpan(32, 32));
                state.Revision++;
                var after = ProtectedDid2MailboxSendJournal.Encode(state, Network, binding.AsSpan(0, 32), binding.AsSpan(32, 32));
                try { Assert.True(await peerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, before, after)); }
                finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); CryptographicOperations.ZeroMemory(binding); }
            }
            else await peerStorage.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)]);
            Assert.IsType<CompactionDiskFixtureStorage>(peerStorage).Reopen();
            var protectedBefore = await RetirementProtectedSnapshotAsync(); var sqlBefore = await RetirementSqlProjectionAsync();
            // Exact-state disagreement is rejected by the existing plan's
            // ObserveReadback contract as InvalidDataException, not crypto verification.
            await Assert.ThrowsAsync<InvalidDataException>(() => owner.ResumeOwnedLocalCompactionAsync(default));
            Assert.Equal(protectedBefore, await RetirementProtectedSnapshotAsync());
            Assert.Equal(sqlBefore, await RetirementSqlProjectionAsync());
            using var afterGrants = await ReadPeerGrantsAsync();
            Assert.True(ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(Assert.Single(afterGrants.Entries).Value));
        }
    }
}
