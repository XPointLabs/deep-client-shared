using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2SupersededRetrieveRetirement_ActualReadsKeepOriginalPathAndRecoverEveryHandover(bool nonempty)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        if (nonempty) await fixture.CheckCompletedAckFloorRetirementAsync(retireSupersededHolder: true);
        else await fixture.CheckEmptySupersededRetrieveRetirementAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckEmptySupersededRetrieveRetirementAsync()
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            TrackMailboxDispatchClock();
            var transport = new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(transport, terminal)).ProcessedEnvelopes);
            byte[] acquisition;
            using (var grants = await ReadPeerGrantsAsync(own: true))
                acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(Assert.Single(grants.Entries).Value));
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            var reader = ReopenAccount();
            using (var exclusion = await reader.OpenMailboxEpochExclusionAsync(acquisition, Source(reader)))
            {
                await exclusion.RetireIdleMailboxCounterFloorAsync();
                await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync());
            }
            await CheckSupersededRetrieveRetirementAsync(transport, own: true, acquisition);
            CryptographicOperations.ZeroMemory(acquisition);
        }

        internal async Task CheckSupersededRetrieveRetirementAsync(OwnedGrantTransport oldTransport, bool own, byte[] acquisition)
        {
            var secure = own ? (IDeepSecureStorage)storage : peerStorage;
            DeepIdV2AccountService Account() => own ? ReopenAccount() : ReopenGrantReader();
            Task Retire()
            {
                var account = Account();
                return account.RetireSupersededRetrieveAcquisitionAsync(acquisition, own ? Source(account) : GrantReaderSource(account));
            }
            // Namespace exclusion/floor removal alone cannot delete the last holder.
            await Assert.ThrowsAsync<IOException>(Retire);
            await StageVerifiedGrantSuccessorAsync(oldTransport, own, currentRetainedAuthority: true);
            var installedAccount = Account();
            _ = await installedAccount.AcquireOwnPermanentContactRetrieveGrantAsync(
                own ? Source(installedAccount) : GrantReaderSource(installedAccount), oldTransport);
            Assert.Equal(1, oldTransport.Calls); // Controlled selection is not an automatic issuer renewal.
            // A replacement installed in SQL without an actual completed read
            // is not enough to declare the retained path available.
            await Assert.ThrowsAsync<IOException>(Retire);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: own) { ReturnEmptyPage = true };
            Task<DeepIdV2MailboxSynchronizationResult> Poll() => own ? SynchronizeNativeSender(oldTransport, terminal) :
                SynchronizeNativeReceiver(oldTransport, terminal);
            using (ClientMailboxRetrieveTestHooks.Push(point =>
                { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Injected replacement read handover."); }))
                await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(Poll);
            using (var active = await ReadPeerMailboxReads(own)) { Assert.Equal(3, active.Phase); Assert.NotNull(active.Active); }
            await Assert.ThrowsAsync<IOException>(Retire);
            Assert.Equal(0, (await Poll()).ProcessedEnvelopes); Assert.Equal(1, terminal.RetrieveCalls);

            using var generation = await secure.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            var accountId = generation.Use(bytes => bytes.Slice(24, 32).ToArray());
            byte[] application = [];
            async Task<byte[]> SqlState()
            {
                byte[] state = [];
                await WithOwnedApplicationConnectionAsync(own, Network, accountId, sql =>
                    state = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, SHA256.HashData(acquisition), default));
                return state;
            }
            application = await SqlState();
            var roots = new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ProtectedDid2ContactRouteJournal.Slot };
            var hashes = new List<byte[]>();
            foreach (var slot in roots)
            { using var raw = await secure.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            using var before = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var original = before.Use(bytes => bytes.ToArray());
            byte[] originalRoute;
            using (var grants = await ReadPeerGrantsAsync(own))
                originalRoute = ProtectedDid2MailboxGrantJournal.OriginalRoute(grants.Entries[Convert.ToHexString(acquisition)]).ToArray();
            var native = await Account().ReadOwnMailboxReplayFenceAsync();
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            for (var index = 0; index < points.Length; index++)
            {
                if (index != 0)
                {
                    using var retired = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(await secure.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, retired.Use(bytes => bytes.ToArray()), original));
                }
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == points[index]) throw new IOException("Injected superseded Retrieve handover."); }))
                    await Assert.ThrowsAsync<IOException>(Retire);
                if (own) ColdReopenCompactionStorage(); else ColdReopenReceiverStoreStorage();
                var recovery = own ? SenderCompactionOwner() : PeerRetirementOwner();
                if (index == 0)
                {
                    using var publication = await secure.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot) ?? throw new InvalidDataException();
                    var exactPublication = publication.Use(bytes => bytes.ToArray());
                    var corrupt = exactPublication.Append((byte)0).ToArray();
                    try
                    {
                        Assert.True(await secure.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, exactPublication, corrupt));
                        using var stagedPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        await Assert.ThrowsAsync<InvalidDataException>(() => recovery.ResumeOwnedLocalCompactionAsync(default));
                        using var unchanged = await secure.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                        using var unchangedPlan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        Assert.Equal(original, unchanged.Use(bytes => bytes.ToArray()));
                        Assert.Equal(stagedPlan.Use(bytes => bytes.ToArray()), unchangedPlan.Use(bytes => bytes.ToArray()));
                    }
                    finally
                    {
                        Assert.True(await secure.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, corrupt, exactPublication));
                        CryptographicOperations.ZeroMemory(corrupt); CryptographicOperations.ZeroMemory(exactPublication);
                    }
                }
                await recovery.ResumeOwnedLocalCompactionAsync(default);
                using (var grants = await ReadPeerGrantsAsync(own))
                {
                    var current = Assert.Single(grants.Entries).Value;
                    Assert.NotEqual(Convert.ToHexString(acquisition), ProtectedDid2MailboxGrantJournal.Acquisition(current));
                    Assert.Single(grants.Selections);
                    Assert.Equal(originalRoute, ProtectedDid2MailboxGrantJournal.OriginalRoute(current).ToArray());
                }
                Assert.Equal(application, await SqlState());
                var afterFence = await Account().ReadOwnMailboxReplayFenceAsync();
                Assert.Equal(native.Digest.ToArray(), afterFence.Digest.ToArray());
                for (var rootIndex = 0; rootIndex < roots.Length; rootIndex++)
                { using var actual = await secure.ReadOwnedAsync(roots[rootIndex]) ?? throw new InvalidDataException(); Assert.Equal(hashes[rootIndex], actual.Use(bytes => SHA256.HashData(bytes))); }
                using var plan = await secure.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                Assert.Equal(0, plan.Use(bytes => bytes[1]));
            }
            // Last/current holder still cannot retire; the same installed read
            // path continues with its original traversal after cold recovery.
            byte[] currentAcquisition;
            using (var grants = await ReadPeerGrantsAsync(own))
                currentAcquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(Assert.Single(grants.Entries).Value));
            var remainingAccount = Account();
            var failure = await Record.ExceptionAsync(() => remainingAccount.RetireSupersededRetrieveAcquisitionAsync(currentAcquisition,
                own ? Source(remainingAccount) : GrantReaderSource(remainingAccount)));
            Assert.True(failure is CryptographicException or IOException, failure?.GetType().Name ?? "Last holder unexpectedly retired");
            Assert.Equal(0, (await Poll()).ProcessedEnvelopes); Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(1, oldTransport.Calls);
            foreach (var bytes in new[] { original, originalRoute, accountId, application, currentAcquisition }) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
