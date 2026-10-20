using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2LogicalAssignment_ExpiredSnapshotCarriesLiveRouteButRejectsChangedEpoch(bool changedEpoch)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, expiringHistory: true, encryptedStorage: true);
        await fixture.CheckLogicalAssignmentAsync(changedEpoch);
    }

    [Fact]
    public async Task Did2LogicalAssignment_OwnedColdReopenKeepsCommittedJournalWithoutViewRepublish()
    {
        await using var fixture = await Fixture.CreateAsync(expiringHistory: true, encryptedStorage: true);
        await fixture.CheckOwnedLogicalAssignmentAsync();
    }

    [Fact]
    public async Task Did2LogicalAssignment_RouteControlIgnoresExpiredSnapshotButNotSignedRouteExpiry()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, expiringHistory: true, encryptedStorage: true);
        await fixture.CheckLogicalAssignmentAsync(false, routeControlOnly: true);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckOwnedLogicalAssignmentAsync()
        {
            var backend = new RenewalBackend(this);
            var committed = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), backend, backend, backend);
            var calls = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
            var before = await RouteSnapshot();
            try
            {
                await AdvanceNetworkAsync();
                ProofTime = 1_100; Sample = 200;
                var reopened = ReopenAccount();
                NetworkStore = await ReopenNetworkStoreAsync();
                var restored = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
                Assert.Equal(committed.ExactXpo1.ToArray(), restored.ExactXpo1.ToArray());
                Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                var after = await RouteSnapshot();
                try { Assert.Equal(before, after); }
                finally { CryptographicOperations.ZeroMemory(after); }
                using var state = await RouteState();
                Assert.Equal((byte)7, Assert.Single(state.Entries).Value.Phase);
            }
            finally { CryptographicOperations.ZeroMemory(before); }
        }

        internal async Task CheckLogicalAssignmentAsync(bool changedEpoch, bool routeControlOnly = false)
        {
            var identity = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            var inventory = await accounts.EnsureOwnPreKeyInventoryAsync(Source());
            var first = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var delegation = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(inventory.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(first.Proof, delegation, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var time = new OnionTrustedTimeAuthority(this);
            var advertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, first.Network,
                first.Authority, secrets!, 100, Bytes(32, 0xd1), Bytes(32, 0xd2), ScalarMult.Base(Bytes(32, 0xd3)),
                first.Proof.TrustedLowerUnixSeconds, 1_130, time);
            var threshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(recipient, first.Network,
                first.Authority, advertisement.CanonicalBytes, CreateRouteWitnesses(),
                first.Proof.TrustedLowerUnixSeconds, 1_130, time);
            var original = await DeepIdV2ContactRouteAuthor.CompleteGenesisAsync(recipient, first.Network,
                first.Authority, secrets!, advertisement.CanonicalBytes, threshold, 2, time);
            var exactInvite = original.ExactXir1V2.ToArray();
            var exactClosure = original.ExactRouteClosure.ToArray();
            Assert.Equal(1_090UL, BinaryPrimitives.ReadUInt64BigEndian(original.Route.Projection.Field(12).Span));
            Assert.True(BinaryPrimitives.ReadUInt64BigEndian(original.Route.Route.Field(18).Span) > 1_090UL);
            var readCapability = (await accounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            var contact = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(original, secrets!,
                [DeepIdV2PreKeyServiceCodec.Decode(inventory.ExactXps1.Span)], "Logical assignment QA", readCapability);
            var publication = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(original, contact, secrets!,
                Bytes(32, 0xc1), Bytes(32, 0xc2), Bytes(32, 0xc3));
            var authorization = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(original,
                publication.WireRequest, PublicationWitnesses());
            var receipt = PublicationResult(original, authorization.ExactXpu1);
            var committed = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(original, contact,
                publication.WireRequest, authorization.ExactXpu1, receipt);

            await AdvanceNetworkAsync(); // Genuine new view plus TLS/onion-key successors, same node identities.
            if (changedEpoch) AuthorSignedEpochAdvance();
            ProofTime = 1_100; Sample = 200;
            var reopened = ReopenAccount();
            NetworkStore = await ReopenNetworkStoreAsync();
            var next = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
            var currentRecipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(next.Proof, delegation, Boot, Sample);
            Assert.NotEqual(first.Network.ProtectedLkg!.ViewGeneration, next.Network.ProtectedLkg!.ViewGeneration);
            Assert.Equal(identity, (await reopened.GetCurrentAsync())!.PermanentId.CanonicalText);

            if (changedEpoch)
            {
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                    currentRecipient, next.Network, next.Authority, exactInvite, exactClosure, time));
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(
                    currentRecipient, next.Network, next.Authority, exactInvite, exactClosure, time));
                CryptographicOperations.ZeroMemory(readCapability);
                return;
            }

            var carried = await DeepIdV2ContactRouteVerifier.VerifyAsync(currentRecipient, next.Network,
                next.Authority, exactInvite, exactClosure, time);
            await carried.EnsureCurrentAsync();
            Assert.Equal(exactInvite, carried.ExactXir1V2.ToArray());
            Assert.Equal(exactClosure, carried.ExactRouteClosure.ToArray());
            Assert.Equal(0UL, BinaryPrimitives.ReadUInt64BigEndian(carried.Route.Route.Field(3).Span));
            Assert.Equal(original.Route.Selection.CanonicalBytes.ToArray(), carried.Route.Selection.CanonicalBytes.ToArray());
            if (routeControlOnly)
            {
                var controlPredecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(currentRecipient,
                    next.Network, next.Authority, carried.ExactXir1V2, carried.ExactRouteClosure, time);
                var controlXra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(currentRecipient,
                    next.Network, next.Authority, secrets!, carried.Route.Authorization.CanonicalBytes,
                    Bytes(32, 0xb1), Bytes(32, 0xb2), ScalarMult.Base(Bytes(32, 0xb3)), 1_150, time);
                var controlThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(currentRecipient,
                    next.Network, next.Authority, controlPredecessor, controlXra.CanonicalBytes, CreateRouteWitnesses(), 1_150, time);
                var controlRoute = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(currentRecipient,
                    next.Network, next.Authority, secrets!, controlPredecessor, controlXra.CanonicalBytes, controlThreshold, 2, time);
                var package = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteCodec.Encode(original));
                var eventHash = Bytes(32, 0xb4); var relationship = Bytes(32, 0xb5); var conversation = Bytes(32, 0xb6);
                var control = await ApplicationCoreCodec.AuthorVerifiedContactRouteUpdateAsync(controlRoute, package,
                    original.ExactRouteClosure, eventHash, relationship, conversation, Bytes(32, 0xb7), 3, time);
                Assert.True(control.Record.CreatedAtUnixMilliseconds > 1_090_000UL);
                Assert.Equal(1_150_000UL, control.Record.ExpiresAtUnixMilliseconds);
                var verified = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(package,
                    next.Proof, next.Network, next.Authority, time, original.ExactRouteClosure, eventHash,
                    relationship, conversation, control.CanonicalBytes);
                await verified.EnsureCurrentAsync();
                ProofTime = 1_150; Sample = 250;
                var now = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(
                    package, now.Proof, now.Network, now.Authority, time, original.ExactRouteClosure, eventHash,
                    relationship, conversation, control.CanonicalBytes));
                var facts = await DeepIdV2ContactRouteUpdateVerifier.RequireRetainedSuccessorFactsAsync(package, now.Proof,
                    now.Network, now.Authority, time, original.ExactRouteClosure, eventHash, relationship, conversation, control.CanonicalBytes);
                Assert.Equal(controlRoute.ExactRouteClosure.ToArray(), facts.ExactBytes.ToArray());
                CryptographicOperations.ZeroMemory(readCapability);
                return;
            }
            try
            {
                var restoredObject = await DeepIdV2ContactObjectAuthor.RestoreAsync(carried, contact.Closure.CanonicalBytes,
                    contact.ProtectedDcr1, readCapability);
                var restoredCommit = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(carried, restoredObject,
                    publication.WireRequest, authorization.ExactXpu1, receipt);
                Assert.Equal(committed.ExactXpo1.ToArray(), restoredCommit.ExactXpo1.ToArray());
                // Read-only commit restoration never makes the old XPU dispatchable.
                await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(
                    carried, publication.WireRequest, authorization.ExactXpu1));
            }
            finally { CryptographicOperations.ZeroMemory(readCapability); }
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(next.Network, next.Authority,
                successor!.ExactPma2, time);
            var storeEvidence = await MailboxStoreReplicaEvidenceVerifier.CaptureAsync(carried);
            var originalStoreKeys = MailboxStoreReplicaEvidenceVerifier.Verify(next.Network, next.Authority,
                carried.Route, storeEvidence);
            Assert.Equal(successor.ExactXnv1.ToArray(), storeEvidence.ExactXnv1.ToArray());
            Assert.True(originalStoreKeys.OriginalViewExpiresAt > 1_090UL);
            Assert.NotEqual(carried.Route.Projection.ArtifactHash.ToArray(), host.MembershipCommitment.ToArray());
            var issuedGrants = new List<byte[]>();
            foreach (var retrieve in new[] { false, true })
            {
                var seed = Bytes(32, retrieve ? (byte)0xf3 : (byte)0xf4);
                var locator = Bytes(32, 0xf1);
                var capability = retrieve ? Bytes(32, 0xf2) : carried.Route.Reachability.Field(10).ToArray();
                using var holder = ReachabilityMailboxHolderAuthority.OpenRetained(carried, locator, capability,
                    retrieve ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit, seed);
                var request = retrieve
                    ? await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(carried, locator, capability, holder)
                    : await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(carried, locator, holder);
                var grantTime = await carried.ReadCurrentTimeAsync();
                var policy = MailboxAuthorityV2Verifier.Verify(next.Authority, successor.ExactPma2.Span,
                    grantTime.LowerUnixSeconds, grantTime.UpperUnixSeconds);
                var pending = ProtectedDid2MailboxGrantJournal.Pending(seed, carried, request, policy,
                    ContactCodec.Decode("PMT2", successor.ExactPmt2.Span), Network);
                Assert.Throws<CryptographicException>(() => ProtectedDid2MailboxGrantJournal.Pending(seed, carried,
                    request, policy, carried.Route.Projection, Network));
                using var custody = new ProtectedDid2MailboxGrantJournal.State { Revision = 2 };
                ProtectedDid2MailboxGrantJournal.AddPending(custody, pending);
                var custodyAccount = currentRecipient.Authorization.Binding.Record.DeepAccountId.ToArray();
                var instance = Bytes(32, 0xf5);
                var exactPending = ProtectedDid2MailboxGrantJournal.Encode(custody, Network, custodyAccount, instance);
                using (var cold = ProtectedDid2MailboxGrantJournal.Decode(exactPending, Network, custodyAccount, instance))
                {
                    Assert.Equal(pending, Assert.Single(cold.Entries).Value);
                    Assert.Equal(exactClosure, ProtectedDid2MailboxGrantJournal.OriginalRoute(pending).ToArray());
                    var logicalEnd = new[] { 17, 13, 18, 11, 9 }.Zip(new[] {
                        carried.Route.Reachability, carried.Route.Authorization, carried.Route.Route,
                        carried.Route.Successor, carried.Route.Selection },
                        (tag, record) => BinaryPrimitives.ReadUInt64BigEndian(record.Field(tag).Span)).Min();
                    Assert.Equal(Math.Min(policy.ExpiresAtUnixSeconds, logicalEnd + (retrieve ? 2_592_000UL : 0UL)),
                        ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(pending));
                }
                var truncatedCeiling = exactPending.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(truncatedCeiling.AsSpan(96 + 4 + 1077), 1_090);
                Assert.Throws<InvalidDataException>(() => ProtectedDid2MailboxGrantJournal.Decode(
                    truncatedCeiling, Network, custodyAccount, instance));
                var response = await IssueOwnedGrantAsync(request, carried, retrieve, default);
                var evidence = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(carried, request,
                    response, successor.ExactPma2);
                await evidence.EnsureCurrentAsync();
                await host.EnsureGrantCurrentAsync(evidence.ExactGrant);
                var winner = ProtectedDid2MailboxGrantJournal.WithWinner(pending, evidence.ExactXmc2.Span, Network);
                custody.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(pending)] = winner;
                custody.Revision++;
                var exactWinner = ProtectedDid2MailboxGrantJournal.Encode(custody, Network, custodyAccount, instance);
                using (var cold = ProtectedDid2MailboxGrantJournal.Decode(exactWinner, Network, custodyAccount, instance))
                    Assert.Equal(response, ProtectedDid2MailboxGrantJournal.Response(Assert.Single(cold.Entries).Value).ToArray());
                var selected = await host.ResolveGrantReplicasAsync(evidence.ExactGrant);
                Assert.Equal(2, selected.Count);
                for (var index = 0; index < selected.Count; index++)
                    Assert.Equal(carried.Route.Selection.Field(6).Span.Slice(index * 32, 32).ToArray(), selected[index].NodeId.ToArray());
                issuedGrants.Add(evidence.ExactGrant.ToArray());
                foreach (var bytes in new[] { seed, capability, pending, exactPending, exactWinner })
                    CryptographicOperations.ZeroMemory(bytes);
            }

            // The actual account-owned Deposit command must persist its
            // original before the issuer callback across this expired snapshot,
            // then cold-retry a lost reply without replacing holder/request.
            var address = (await reopened.GetCurrentAsync())!.PermanentId;
            var reader = ReopenGrantReader();
            var readerSource = GrantReaderSource(reader);
            var resolvedContact = await reader.ResolvePermanentContactAsync(address, readerSource,
                new SyntheticPermanentRead(this, readerSource, authorization.ExactXpu1));
            var depositTransport = new OwnedGrantTransport(this) { LoseResponse = true };
            await Assert.ThrowsAsync<IOException>(() => reader.AcquirePermanentContactDepositGrantAsync(
                resolvedContact, readerSource, depositTransport));
            byte[] retainedRequest;
            using (var cold = await ReadPeerGrantsAsync())
            {
                var entry = Assert.Single(cold.Entries).Value;
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(entry));
                Assert.Equal(exactClosure, ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).ToArray());
                retainedRequest = ProtectedDid2MailboxGrantJournal.Request(entry).ToArray();
            }
            reader = ReopenGrantReader(); readerSource = GrantReaderSource(reader);
            resolvedContact = await reader.ResolvePermanentContactAsync(address, readerSource,
                new SyntheticPermanentRead(this, readerSource, authorization.ExactXpu1));
            depositTransport.LoseResponse = false;
            var installed = await reader.AcquirePermanentContactDepositGrantAsync(resolvedContact, readerSource, depositTransport);
            Assert.Equal(retainedRequest, installed.ExactXmg2.ToArray());
            Assert.Equal(2, depositTransport.Calls); Assert.True(depositTransport.ExactRetry);
            await AssertInstalledGrantSqlAsync(installed.ExactGrant, own: false);
            var cappedGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(installed.ExactGrant.Span);
            Assert.Equal(1_130UL, cappedGrant.ExpiresAtUnixSeconds);
            Assert.True(ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(
                cappedGrant.NotBeforeUnixSeconds, cappedGrant.ExpiresAtUnixSeconds, cappedGrant.Domain, ProofTime));
            // The generic retry-window margin is reached, but the same signed
            // route cannot yield a longer grant. Keep the actual live winner;
            // the independent expiry checks below remain mandatory.
            reader = ReopenGrantReader(); readerSource = GrantReaderSource(reader);
            var retained = await reader.AcquirePermanentContactDepositGrantAsync(resolvedContact, readerSource, depositTransport);
            Assert.Equal(installed.ExactXmc2.ToArray(), retained.ExactXmc2.ToArray());
            Assert.Equal(2, depositTransport.Calls);
            CryptographicOperations.ZeroMemory(retainedRequest);

            // The original route's OWN expiry remains binding despite a newer live network.
            ProofTime = 1_150; Sample = 250;
            var refreshed = await Source(reopened).VerifyForOwnPreKeyAuthoringAsync(reopened, default);
            currentRecipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(refreshed.Proof, delegation, Boot, Sample);
            var freshHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(refreshed.Network, refreshed.Authority,
                successor.ExactPma2, time);
            foreach (var grant in issuedGrants)
                await Assert.ThrowsAsync<CryptographicException>(async () => await freshHost.EnsureGrantCurrentAsync(grant));
            await Assert.ThrowsAsync<CryptographicException>(async () => await DeepIdV2ContactRouteVerifier.VerifyAsync(
                currentRecipient, refreshed.Network, refreshed.Authority, exactInvite, exactClosure, time));
            var predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(currentRecipient, refreshed.Network,
                refreshed.Authority, exactInvite, exactClosure, time);
            var successorAdvertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(currentRecipient,
                refreshed.Network, refreshed.Authority, secrets!, advertisement.CanonicalBytes,
                Bytes(32, 0xe1), Bytes(32, 0xe2), ScalarMult.Base(Bytes(32, 0xe3)), 1_250, time);
            var successorThreshold = await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(currentRecipient,
                refreshed.Network, refreshed.Authority, predecessor, successorAdvertisement.CanonicalBytes,
                CreateRouteWitnesses(), 1_250, time);
            var renewed = await DeepIdV2ContactRouteAuthor.CompleteSuccessorAsync(currentRecipient, refreshed.Network,
                refreshed.Authority, secrets!, predecessor, successorAdvertisement.CanonicalBytes, successorThreshold, 2, time);
            await renewed.EnsureCurrentAsync();
            Assert.Equal(original.Route.Projection.CanonicalBytes.ToArray(), renewed.Route.Projection.CanonicalBytes.ToArray());
            foreach (var tag in Enumerable.Range(1, 7))
                Assert.Equal(original.Route.Selection.Field(tag).ToArray(), renewed.Route.Selection.Field(tag).ToArray());
            Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(renewed.Route.Route.Field(3).Span));
            Assert.NotEqual(original.Route.Route.Field(8).ToArray(), renewed.Route.Route.Field(8).ToArray());
            Assert.Equal(original.Route.Route.Field(15).ToArray(), renewed.Route.Route.Field(15).ToArray());
            var renewalCapability = (await reopened.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            try
            {
                var priorObject = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(currentRecipient,
                    refreshed.Network, refreshed.Authority, predecessor, contact.Closure.CanonicalBytes,
                    contact.ProtectedDcr1, renewalCapability, time);
                var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(currentRecipient,
                    refreshed.Network, refreshed.Authority, priorObject, publication.WireRequest,
                    authorization.ExactXpu1, receipt, time);
                var routeRequest = new ContactRouteAuthorityWireRequest(Network, Bytes(32, 0xb1),
                    refreshed.Proof.QueriedDirectoryLeafKey.Span, refreshed.Proof.NextProtectedLkg.LogGeneration,
                    refreshed.Proof.NextProtectedLkg.CoreHash.Span, inventory.ExactDca1.Span,
                    successorAdvertisement.CanonicalBytes.Span, predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);
                var issuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(currentRecipient,
                    refreshed.Network, refreshed.Authority, routeRequest, successorThreshold, refreshed.Proof.ExactAdh1, time);
                var nextObject = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(renewed, issuance,
                    priorObject, secrets!, [DeepIdV2PreKeyServiceCodec.Decode(inventory.ExactXps1.Span)],
                    "Logical assignment QA", renewalCapability);
                var nextPublication = await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(renewed,
                    nextObject, secrets!, priorPublication, Bytes(32, 0xb2), Bytes(32, 0xb3));
                var nextAuthorization = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdSuccessorAsync(renewed,
                    nextPublication.WireRequest, priorPublication, PublicationWitnesses());
                var opaqueRequest = Xpu1Codec.Decode(nextAuthorization.ExactXpu1.Span);
                var placement = ContactServicePlacementFactory.Create(refreshed.Network,
                    ContactServiceRequestKind.PublishInvite, opaqueRequest.LocatorHash);
                var opaque = await Xpa1PublicationAuthorizationVerifier.VerifyAsync(opaqueRequest,
                    refreshed.Authority, refreshed.Proof, placement, time, default);
                Assert.Equal(1UL, opaque.Generation);
                await opaque.EnsureCurrentAsync();
            }
            finally { CryptographicOperations.ZeroMemory(renewalCapability); }
        }
    }
}
