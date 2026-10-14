using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("reply")]
    [InlineData("selection")]
    [InlineData("after-sql")]
    [InlineData("expired")]
    [InlineData("floors")]
    [InlineData("traversals")]
    [InlineData("traversals-reuse")]
    public async Task Did2AutomaticGrantRenewal_NewReadPreservesActiveOriginalAndColdResumesSuccessor(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckAutomaticRetrieveRenewalAsync(fault);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("reply")]
    [InlineData("selection")]
    [InlineData("after-sql")]
    public async Task Did2AutomaticGrantRenewal_DepositRetainsOriginalAndColdResumesExactSuccessor(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckAutomaticDepositRenewalAsync(fault);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckAutomaticDepositRenewalAsync(string fault)
        {
            var source = Source(); var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(source, threshold, new OwnedPublicationSource(this, route), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var firstIssuer = new OwnedGrantTransport(this);
            var first = await Acquire(firstIssuer);
            byte[] original;
            using (var state = await ReadPeerGrantsAsync()) original = Assert.Single(state.Entries).Value.ToArray();
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(first.ExactGrant.Span);
            var refreshAt = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            try
            {
                AdvanceTo(checked(refreshAt - 6));
                var restoredIssuer = new OwnedGrantTransport(this);
                Assert.Equal(first.ExactXmc2.ToArray(), (await Acquire(restoredIssuer)).ExactXmc2.ToArray());
                Assert.Equal(0, restoredIssuer.Calls);
                AdvanceTo(checked(refreshAt - 5));
                Assert.True(checked(CurrentProofTime + 5) < grant.ExpiresAtUnixSeconds);
                var successorIssuer = new OwnedGrantTransport(this) { LoseResponse = fault == "reply" };
                var point = fault switch
                {
                    "selection" => (Did2MailboxInstallationFailpoint?)Did2MailboxInstallationFailpoint.BeforeSelection,
                    "after-sql" => Did2MailboxInstallationFailpoint.AfterSql,
                    _ => null
                };
                using (Did2MailboxInstallationTestHooks.Push(actual =>
                    { if (actual == point) throw new IOException("Interrupted Deposit grant successor handover."); }))
                {
                    if (fault == "none") _ = await Acquire(successorIssuer);
                    else await Assert.ThrowsAsync<IOException>(async () => _ = await Acquire(successorIssuer));
                }
                Assert.Equal(1, successorIssuer.Calls);
                using (var state = await ReadPeerGrantsAsync())
                {
                    Assert.Equal(2, state.Entries.Count);
                    Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                }
                successorIssuer.LoseResponse = false;
                var renewed = await Acquire(successorIssuer);
                Assert.NotEqual(first.ExactGrant.ToArray(), renewed.ExactGrant.ToArray());
                Assert.Equal(successorIssuer.OriginalRequest.ToArray(), renewed.ExactXmg2.ToArray());
                Assert.True(successorIssuer.ExactRetry);
                Assert.Equal(fault == "reply" ? 2 : 1, successorIssuer.Calls);
                using (var state = await ReadPeerGrantsAsync())
                {
                    var selection = Assert.Single(state.Selections).Value;
                    Assert.Null(selection.Pending);
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(renewed.ExactXmg2.Span)), selection.Current);
                    Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                }
                var finalIssuer = new OwnedGrantTransport(this);
                Assert.Equal(renewed.ExactXmc2.ToArray(), (await Acquire(finalIssuer)).ExactXmc2.ToArray());
                Assert.Equal(0, finalIssuer.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(original); }

            async Task<VerifiedDeepIdV2MailboxGrant> Acquire(OwnedGrantTransport issuer)
            {
                var reopened = ReopenGrantReader();
                var freshSource = GrantReaderSource(reopened);
                // XIQ read envelopes are short-lived independently of the grant.
                // Re-fetch the genuine signed read instead of stretching the
                // earlier candidate when advancing this fixture's signed clock.
                var resolved = await reopened.ResolvePermanentContactAsync(address, freshSource,
                    new SyntheticPermanentRead(this, freshSource, replicas.ExactPublication));
                return await reopened.AcquirePermanentContactDepositGrantAsync(resolved, freshSource, issuer);
            }
            void AdvanceTo(ulong center)
            {
                Assert.True(center > CurrentProofTime);
                var delta = center - CurrentProofTime;
                ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            }
        }

        private async Task CheckAutomaticRetrieveCapacityAsync(OwnedReadTerminal terminal, string fault)
        {
            using var key = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidDataException();
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
            var scope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            var original = root.Use(bytes => bytes.ToArray());
            byte[] staged = [];
            try
            {
                using var state = ProtectedDid2MailboxReadJournal.Decode(original, Network, scope.AsSpan(0, 32), scope.AsSpan(32));
                Assert.Null(state.Active); Assert.Equal(0, state.Phase);
                // Disposable protected metadata fixture, not evidence of 128
                // real deliveries and not a runtime eviction/repair operation.
                var counters = fault == "floors";
                if (fault == "traversals") state.Traversals.Clear();
                for (var ordinal = 1; (counters ? state.Counters.Count : state.Traversals.Count) < ProtectedDid2MailboxReadJournal.MaximumFloors; ordinal++)
                {
                    var distinct = new byte[32]; distinct[0] = 0x7f;
                    BinaryPrimitives.WriteInt32BigEndian(distinct.AsSpan(28), ordinal);
                    var name = Convert.ToHexString(distinct);
                    if (counters) Assert.True(state.Counters.TryAdd(name, 1UL));
                    else Assert.True(state.Traversals.TryAdd(name, new ClientMailboxTraversal(0, ReadOnlySpan<byte>.Empty, 0)));
                }
                state.Revision = Math.Max(state.Revision, checked((ulong)(state.Counters.Count + state.Traversals.Count) + 1));
                staged = ProtectedDid2MailboxReadJournal.Encode(state, Network, scope.AsSpan(0, 32), scope.AsSpan(32));
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxReadJournal.Slot, original, staged));
                if (fault == "traversals-reuse") return; // Full is not a ban on an existing exact scope.
                using var grantRoot = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                var grantHash = grantRoot.Use(bytes => SHA256.HashData(bytes));
                var calls = terminal.RetrieveCalls;
                for (var reopen = 0; reopen < 2; reopen++)
                {
                    var unusedIssuer = new OwnedGrantTransport(this, selfRetrieve: true);
                    await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(unusedIssuer, terminal));
                    Assert.Equal(0, unusedIssuer.Calls); Assert.Equal(calls, terminal.RetrieveCalls);
                    using var readAfter = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidDataException();
                    using var grantAfter = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.True(readAfter.Use(bytes => CryptographicOperations.FixedTimeEquals(bytes, staged)));
                    Assert.Equal(grantHash, grantAfter.Use(bytes => SHA256.HashData(bytes)));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scope); CryptographicOperations.ZeroMemory(original);
                CryptographicOperations.ZeroMemory(staged);
            }
        }

        internal async Task CheckAutomaticRetrieveRenewalAsync(string fault)
        {
            _ = await PrepareRetainedPublicationAsync(elapsed: false);
            var firstIssuer = new OwnedGrantTransport(this, selfRetrieve: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            Assert.Equal(0, (await SynchronizeNativeSender(firstIssuer, terminal)).ProcessedEnvelopes);
            Assert.Equal(1, firstIssuer.Calls);
            byte[] original;
            MailboxAuthenticatedGrant grant;
            using (var state = await ReadPeerGrantsAsync(own: true))
            {
                original = Assert.Single(state.Entries).Value.ToArray();
                grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                    ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(original).Span).Field(8).Span);
            }
            var originalGrantHash = SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant));
            var refreshAt = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            // Real signed current network/epoch successor, retaining the original
            // private publication/selection. No grant lifetime is lengthened.
            await AdvanceOriginalStoreEpochForTestAsync(checked(refreshAt - 6));
            var noIssue = new OwnedGrantTransport(this, selfRetrieve: true);
            try
            {
                Assert.Equal(0, (await SynchronizeNativeSender(noIssue, terminal)).ProcessedEnvelopes);
                Assert.Equal(0, noIssue.Calls);
                // Reserve the old read just before the margin, then cross the
                // deadline with that actual protected page still interrupted.
                using (ClientMailboxRetrieveTestHooks.Push(point =>
                    { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Interrupted original read at renewal margin."); }))
                    await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(noIssue, terminal));
                AdvanceTo(checked(refreshAt - 5));
                Assert.True(checked(CurrentProofTime + 5) < grant.ExpiresAtUnixSeconds);
                using (var active = await ReadPeerMailboxReads(own: true))
                {
                    Assert.Equal(3, active.Phase);
                    Assert.Equal(originalGrantHash, active.Active!.Grant);
                }
                var readsBeforeResume = terminal.RetrieveCalls;
                Assert.Equal(0, (await SynchronizeNativeSender(noIssue, terminal)).ProcessedEnvelopes);
                Assert.Equal(readsBeforeResume, terminal.RetrieveCalls); Assert.Equal(0, noIssue.Calls);
                ulong retainedCounter;
                using (var read = await ReadPeerMailboxReads(own: true))
                    retainedCounter = read.Counters[Convert.ToHexString(originalGrantHash)];
                using (var state = await ReadPeerGrantsAsync(own: true)) Assert.Equal(original, Assert.Single(state.Entries).Value);

                if (fault is "floors" or "traversals" or "traversals-reuse")
                {
                    await CheckAutomaticRetrieveCapacityAsync(terminal, fault);
                    if (fault != "traversals-reuse") return;
                }

                var successorIssuer = new OwnedGrantTransport(this, selfRetrieve: true) { LoseResponse = fault is "reply" or "expired" };
                var failpoint = fault switch
                {
                    "selection" => (Did2MailboxInstallationFailpoint?)Did2MailboxInstallationFailpoint.BeforeSelection,
                    "after-sql" => Did2MailboxInstallationFailpoint.AfterSql,
                    _ => null
                };
                using (Did2MailboxInstallationTestHooks.Push(point =>
                    { if (point == failpoint) throw new IOException("Interrupted automatic grant successor handover."); }))
                {
                    if (fault is "none" or "traversals-reuse") Assert.Equal(0, (await SynchronizeNativeSender(successorIssuer, terminal)).ProcessedEnvelopes);
                    else await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(successorIssuer, terminal));
                }
                Assert.Equal(1, successorIssuer.Calls);
                using (var state = await ReadPeerGrantsAsync(own: true))
                {
                    Assert.Equal(2, state.Entries.Count);
                    Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                }
                if (fault == "expired")
                {
                    var request = ContactCodec.Decode("XMG2", successorIssuer.OriginalRequest.Span);
                    AdvanceTo(checked(BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span) + 31));
                    var closing = ReopenAccount();
                    Assert.Equal(1, await closing.CloseExpiredMailboxAcquisitionsAsync(Source(closing)));
                    using var before = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    var unusedIssuer = new OwnedGrantTransport(this, selfRetrieve: true);
                    await Assert.ThrowsAsync<IOException>(() => SynchronizeNativeSender(unusedIssuer, terminal));
                    Assert.Equal(0, unusedIssuer.Calls);
                    using var after = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                    Assert.Equal(before.Use(bytes => bytes.ToArray()), after.Use(bytes => bytes.ToArray()));
                    using var closed = await ReadPeerGrantsAsync(own: true);
                    Assert.Null(Assert.Single(closed.Selections).Value.Pending);
                    Assert.Equal(ProtectedDid2MailboxGrantJournal.Acquisition(original), Assert.Single(closed.Selections).Value.Current);
                    Assert.Contains(closed.Entries.Values, ProtectedDid2MailboxGrantJournal.IsClosedUnresolved);
                    return; // Unknown issuance is not reminted or claimed settled.
                }
                successorIssuer.LoseResponse = false;
                Assert.Equal(0, (await SynchronizeNativeSender(successorIssuer, terminal)).ProcessedEnvelopes);
                Assert.Equal(fault == "reply" ? 2 : 1, successorIssuer.Calls);
                Assert.True(successorIssuer.ExactRetry);
                using (var state = await ReadPeerGrantsAsync(own: true))
                {
                    var selection = Assert.Single(state.Selections).Value;
                    Assert.Null(selection.Pending);
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(successorIssuer.OriginalRequest.Span)), selection.Current);
                    Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                    Assert.NotEqual(originalGrantHash, SHA256.HashData(
                        ContactCodec.Decode("XMC2", successorIssuer.OriginalResponse.Span).Field(8).Span));
                }
                using (var read = await ReadPeerMailboxReads(own: true))
                {
                    Assert.Equal(0, read.Phase); Assert.Null(read.Active);
                    Assert.Equal(retainedCounter, read.Counters[Convert.ToHexString(originalGrantHash)]);
                    Assert.Equal(2, read.Counters.Count);
                    if (fault == "traversals-reuse") Assert.Equal(ProtectedDid2MailboxReadJournal.MaximumFloors, read.Traversals.Count);
                }
                var restored = new OwnedGrantTransport(this, selfRetrieve: true);
                Assert.Equal(0, (await SynchronizeNativeSender(restored, terminal)).ProcessedEnvelopes);
                Assert.Equal(0, restored.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(originalGrantHash); }

            void AdvanceTo(ulong center)
            {
                Assert.True(center > CurrentProofTime);
                var delta = center - CurrentProofTime;
                ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            }
        }
    }
}
