using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2ClosedRetrieveRetirement_UnknownIssuerReplyEveryHandoverAndOriginalPathRead()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckUnusedRetrieveRetirementAsync(abandon: false);
    }

    [Fact]
    public async Task Did2ClosedRetrieveRetirement_CancellationAllowsOnlyUncommittedAbandon()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckUnusedRetrieveRetirementAsync(abandon: true);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckUnusedRetrieveRetirementAsync(bool abandon)
        {
            var originalRoute = await PrepareRetainedPublicationAsync(elapsed: false);
            var lostIssuer = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), lostIssuer));
            byte[] acquisition;
            using (var pending = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(pending.Entries).Value;
                acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(2_000UL, ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry));
            }
            // Neither pending custody nor expiry without independent epoch
            // exclusion can become a retirement selection.
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.OpenMailboxEpochExclusionAsync(acquisition, Source()));
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            var currentAccount = ReopenAccount();
            Assert.Equal(1, await currentAccount.CloseExpiredMailboxAcquisitionsAsync(Source(currentAccount)));
            using var originalOwner = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var originalGrantRoot = originalOwner.Use(bytes => bytes.ToArray());
            // Publication and a lost issuer response do not initialize application
            // SQL. Retirement must not repair it or treat its absence as empty.
            using (var exclusion = await currentAccount.OpenMailboxEpochExclusionAsync(acquisition, Source(currentAccount)))
                await Assert.ThrowsAsync<CryptographicException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync());
            using (var unchanged = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException())
                Assert.Equal(originalGrantRoot, unchanged.Use(bytes => bytes.ToArray()));
            using (var untouched = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException())
                Assert.Equal(0, untouched.Use(bytes => bytes[1]));
            // The ordinary public client projection performs the authorized first
            // open. No test-created database substitutes for registered custody.
            Assert.Empty(await ListNativePendingText());
            var roots = new[] { ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot,
                ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
                SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ProtectedDid2ContactRouteJournal.Slot };
            var hashes = new List<byte[]>();
            foreach (var slot in roots)
            { using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var accountId = (await accounts.GetCurrentAsync())!.AccountId.ToArray();
            async Task<byte[]> SqlState()
            {
                byte[] value = [];
                await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                    value = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, SHA256.HashData(acquisition), default));
                return value;
            }
            var application = await SqlState();
            var fence = await currentAccount.ReadOwnMailboxReplayFenceAsync();
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            for (var index = 0; index < (abandon ? 2 : points.Length); index++)
            {
                if (index != 0)
                {
                    using var now = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot,
                        now.Use(bytes => bytes.ToArray()), originalGrantRoot)); // Disposable fixture predecessor only.
                }
                var account = ReopenAccount();
                using var cancellation = new CancellationTokenSource();
                using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
                {
                    Assert.True(exclusion.IsUnresolvedAcquisition);
                    var dependencies = await exclusion.CaptureRetirementDependenciesAsync();
                    Assert.Equal(ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath,
                        dependencies.Dependencies);
                    using (Did2CompactionTestHooks.Push(point =>
                        {
                            if (point != points[index]) return;
                            if (abandon) cancellation.Cancel(); else throw new IOException("Injected closed Retrieve handover.");
                        }))
                    {
                        if (abandon) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync(cancellation.Token));
                        else await Assert.ThrowsAsync<IOException>(() => exclusion.RetireUnusedClosedRetrieveAcquisitionAsync());
                    }
                }
                ColdReopenCompactionStorage();
                var recovery = SenderCompactionOwner();
                if (index == 0 && !abandon)
                {
                    using var publication = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot) ?? throw new InvalidDataException();
                    var good = publication.Use(bytes => bytes.ToArray()); var bad = good.Append((byte)0).ToArray();
                    try
                    {
                        Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, bad));
                        using var staged = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        await Assert.ThrowsAsync<InvalidDataException>(() => recovery.ResumeOwnedLocalCompactionAsync(default));
                        using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                        using var afterPlan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                        Assert.Equal(originalGrantRoot, after.Use(bytes => bytes.ToArray()));
                        Assert.Equal(staged.Use(bytes => bytes.ToArray()), afterPlan.Use(bytes => bytes.ToArray()));
                    }
                    finally
                    {
                        Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, bad, good));
                        CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(bad);
                    }
                }
                if (abandon && index == 0) await recovery.AbandonUncommittedMailboxRetirementAsync(default);
                else
                {
                    if (index > 0) await Assert.ThrowsAsync<InvalidOperationException>(() => recovery.AbandonUncommittedMailboxRetirementAsync(default));
                    await recovery.ResumeOwnedLocalCompactionAsync(default);
                }
                using (var grants = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(abandon && index == 0 ? 1 : 0, grants.Entries.Count);
                    Assert.Equal(grants.Entries.Count, grants.Selections.Count);
                }
                using var idle = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                Assert.Equal(0, idle.Use(bytes => bytes[1]));
                Assert.Equal(application, await SqlState());
                Assert.Equal(fence.Digest.ToArray(), (await ReopenAccount().ReadOwnMailboxReplayFenceAsync()).Digest.ToArray());
                for (var slot = 0; slot < roots.Length; slot++)
                { using var raw = await storage.ReadOwnedAsync(roots[slot]) ?? throw new InvalidDataException(); Assert.Equal(hashes[slot], raw.Use(bytes => SHA256.HashData(bytes))); }
                Assert.Equal(1, lostIssuer.Calls);
            }
            // The excluded unknown holder has retired, not the original path.
            // Use a new independently current issuer result for actual owned
            // Retrieve, not the lost expired response or a synthetic success flag.
            TrackMailboxDispatchClock();
            var freshIssuer = new OwnedGrantTransport(this, selfRetrieve: true);
            freshIssuer.BeforeReturn = async () =>
            {
                var dispatch = freshIssuer.Dispatch ?? throw new InvalidDataException();
                var canonical = ContactResolveCanonicalPathRequest.Decode(freshIssuer.OriginalRequest.Span);
                Assert.False(dispatch.Network.BindsProjection(canonical.ProjectionReference));
                Assert.NotNull(dispatch.RetainedReadRequest);
                var paths = new ContactResolvePrivacyPathProvider(Source(dispatch.Custody.Owner), dispatch.Custody.Guards);
                var authority = new ContactResolvePathAuthority(dispatch.Network,
                    ContactServicePlacementFactory.Create(dispatch.Network, canonical.RequestKind, canonical.ShardKey));
                var missing = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
                    await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, canonical, ReadOnlyMemory<byte>.Empty, authority, default));
                Assert.Equal("placement-request-mismatch", missing.Code);
                var changed = ContactResolveCanonicalPathRequest.Decode(lostIssuer.OriginalRequest.Span);
                var crossFeed = await Assert.ThrowsAsync<ContactResolvePathException>(async () =>
                    await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve, changed, ReadOnlyMemory<byte>.Empty,
                        authority, default, dispatch.RetainedReadRequest));
                Assert.Equal("retained-request-mismatch", crossFeed.Code);
            };
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(freshIssuer, terminal)).ProcessedEnvelopes);
            Assert.Equal(1, freshIssuer.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
            Assert.True(freshIssuer.BuiltHeldFrame);
            using (var grants = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(grants.Entries).Value;
                Assert.NotEqual(Convert.ToHexString(acquisition), ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                Assert.Equal(originalRoute.Route.ExactBytes.ToArray(), ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).ToArray());
            }
            Assert.Equal(plan.Intent.ToArray(), (await accounts.ReadOwnPermanentContactPlanAsync()).Intent.ToArray());
            foreach (var value in new[] { acquisition, originalGrantRoot, application, accountId }) CryptographicOperations.ZeroMemory(value);
        }
    }
}
