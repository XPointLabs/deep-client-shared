using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2OwnedRenewal_ExpiredCommittedAccountResumesEveryPhaseAndAtomicallyPromotes()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOwnedRenewalAsync();
    }

    [Fact]
    public async Task Did2OwnedRenewal_PromotionPreservesInterruptedOriginalRetrieveAndRejectsMissingCustody()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckOwnedRenewalAsync(interruptedRetrieve: true);
    }

    [Fact]
    public async Task Did2OwnedRenewal_ExpiredIncompleteProposalIsNotSilentlyAbandoned()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SeedShortPermanentProposalAsync();
        var before = await fixture.RouteSnapshot();
        fixture.ProofTime += 60; fixture.Sample += 60;
        try
        {
            var backend = new RenewalBackend(fixture);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await fixture.Accounts.EnsureOwnPermanentContactPublishedAsync(
                fixture.Source(), backend, backend, backend));
            Assert.Equal(0, backend.RouteCalls); Assert.Equal(0, backend.PublicationCalls); Assert.Equal(0, backend.ReplicaCalls);
            var after = await fixture.RouteSnapshot();
            try { Assert.Equal(before, after); }
            finally { CryptographicOperations.ZeroMemory(after); }
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    private sealed partial class Fixture
    {
        // A genuinely signed short proposal stored through the canonical
        // protected codec. No runtime lifetime/test-currentness flag is added.
        internal async Task SeedShortPermanentProposalAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); var source = Source();
            var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, Boot, Sample);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            var scalar = Bytes(32, 0xb1); var keyId = Bytes(32, 0xb2); var nonce = Bytes(32, 0xb3);
            var configuration = Did2OwnedPermanentContactPlan.Configuration();
            var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(authorization, fresh.Network, fresh.Authority,
                device!, configuration.Quota, configuration.AntiSpamHash, keyId, DeepIdentityCrypto.DeriveX25519PublicKey(scalar),
                authorization.TrustedLowerUnixSeconds, authorization.TrustedUpperUnixSeconds + 20, source.RendezvousTrustedTime);
            var before = await RouteSnapshot();
            using var state = await RouteState();
            using var generation = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
            byte[]? after = null;
            try
            {
                Assert.Empty(state.Entries);
                state.Entries.Add(Convert.ToHexString(plan.Intent.Span), ProtectedDid2ContactRouteJournal.Entry.Proposal(plan.Intent.Span,
                    configuration, scalar, keyId, nonce, staged.ExactDca1, xra, new ContactRouteAuthorityWireRequest(Network, nonce,
                        fresh.Proof.QueriedDirectoryLeafKey.Span, fresh.Proof.NextProtectedLkg.LogGeneration, fresh.Proof.NextProtectedLkg.CoreHash.Span,
                        staged.ExactDca1.Span, xra.CanonicalBytes.Span), Network, checkpoint.Directory.Record.DeepAccountId.Span));
                after = ProtectedDid2ContactRouteJournal.Encode(state, Network, checkpoint.Directory.Record.DeepAccountId.Span, instance);
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, before, after));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(scalar);
                if (after is not null) CryptographicOperations.ZeroMemory(after);
            }
        }

        internal async Task CheckOwnedRenewalAsync(bool interruptedRetrieve = false)
        {
            await SeedShortPermanentProposalAsync();
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); var name = Convert.ToHexString(plan.Intent.Span);
            var backend = new RenewalBackend(this);
            var genesisCommit = await EnsureAsync();
            Assert.Equal(0UL, genesisCommit.Generation);
            var grants = new OwnedGrantTransport(this, selfRetrieve: true);
            var terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            byte[]? readRoot = null, grantRoot = null;
            if (interruptedRetrieve)
            {
                using (ClientMailboxRetrieveTestHooks.Push(point =>
                    { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) throw new IOException("Interrupted original-route read before promotion."); }))
                    await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => SynchronizeNativeSender(grants, terminal));
                using var reads = await ReadPeerMailboxReads(own: true);
                Assert.Equal(3, reads.Phase); Assert.NotNull(reads.Active);
                readRoot = await RootCopy(ProtectedDid2MailboxReadJournal.Slot);
                grantRoot = await RootCopy(ProtectedDid2MailboxGrantJournal.Slot);
                Assert.Equal(1, grants.Calls); Assert.Equal(1, terminal.RetrieveCalls);
            }
            byte[] priorBytes, priorLocator;
            using (var state = await RouteState())
            {
                var prior = state.Entries[name]; priorBytes = prior.Exact.ToArray();
                var priorRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(prior.Record(9).Span);
                priorLocator = Xpu1Codec.Decode(ContactPublicationAuthorityWireCodec.DecodeResponse(priorRequest,
                    prior.Record(10).Span).ExactXpu1.Span).LocatorHash.ToArray();
            }
            ProofTime += 60; Sample += 60;
            try
            {
                foreach (var (point, phase) in new[] { (Did2ContactRouteFailpoint.AfterProposal, 1),
                    (Did2ContactRouteFailpoint.AfterThreshold, 2), (Did2ContactRouteFailpoint.AfterComplete, 3),
                    (Did2ContactRouteFailpoint.AfterContactObject, 4), (Did2ContactRouteFailpoint.AfterRenewalRequest, 5),
                    (Did2ContactRouteFailpoint.AfterRenewalResponse, 6) })
                {
                    if (phase == 2)
                    {
                        backend.LoseRouteResponse = true;
                        await Assert.ThrowsAsync<IOException>(EnsureAsync);
                        await AssertCurrentPreservedAsync(1);
                    }
                    if (phase == 6)
                    {
                        backend.LosePublicationResponse = true;
                        await Assert.ThrowsAsync<IOException>(EnsureAsync);
                        await AssertCurrentPreservedAsync(5);
                    }
                    var hit = false;
                    using (Did2ContactRouteTestHooks.Push(actual =>
                        { if (actual == point) { hit = true; throw new IOException("Stop after durable successor adoption."); } }))
                        await Assert.ThrowsAsync<IOException>(EnsureAsync);
                    Assert.True(hit); await AssertCurrentPreservedAsync(phase);
                    if (phase == 1)
                    {
                        await CheckPendingPredecessorTamperingAsync();
                        var savedSample = Sample;
                        backend.AfterRouteReply = () => Sample = backend.CurrentDeadline;
                        try
                        {
                            await RequireRouteRejectionAsync(async () => await EnsureAsync());
                            await AssertCurrentPreservedAsync(1);
                        }
                        finally { backend.AfterRouteReply = null; Sample = savedSample; } // Fixture clock fault cleanup only.
                    }
                }
                Assert.Equal(2, backend.RouteSignings); Assert.Equal(2, backend.PublicationSignings); // Genesis + one successor only.
                backend.CorruptReceipt = true;
                await Assert.ThrowsAsync<CryptographicException>(EnsureAsync);
                await AssertCurrentPreservedAsync(6);
                backend.CorruptReceipt = false; backend.LoseReplicaResponse = true;
                await Assert.ThrowsAsync<IOException>(EnsureAsync);
                await AssertCurrentPreservedAsync(6);
                using (Did2ContactRouteTestHooks.Push(point =>
                    { if (point == Did2ContactRouteFailpoint.AfterRenewalPromotion) throw new IOException("Lost reply after atomic promotion."); }))
                    await Assert.ThrowsAsync<IOException>(EnsureAsync);
                byte[] exactCommit;
                using (var state = await RouteState())
                {
                    Assert.Equal(2, state.Entries.Count);
                    var entry = state.Entries[name];
                    Assert.Equal((byte)7, entry.Phase);
                    Assert.Equal(1UL, ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span).Generation);
                    var retained = Assert.Single(state.Entries, pair => pair.Key != name).Value;
                    Assert.Equal((byte)7, retained.Phase);
                    // Only the local intent prefix moves. Private capability,
                    // route keys and every exact signed record stay unchanged.
                    Assert.Equal(priorBytes.AsSpan(32).ToArray(), retained.Exact[32..].ToArray());
                    Assert.NotEqual(ContactRouteClosureCodec.Decode(retained.Record(6).Span).ExactHash.ToArray(),
                        ContactRouteClosureCodec.Decode(entry.Record(6).Span).ExactHash.ToArray());
                    exactCommit = entry.Record(11).ToArray();
                    Assert.Equal(priorLocator, Xpu1Codec.Decode(
                        ContactPublicationAuthorityWireCodec.DecodeResponse(ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span),
                            entry.Record(10).Span).ExactXpu1.Span).LocatorHash.ToArray());
                }
                var callbacks = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
                var currentCommit = await EnsureAsync();
                Assert.Equal(1UL, currentCommit.Generation); Assert.Equal(exactCommit, currentCommit.ExactXpo1.ToArray());
                Assert.Equal(callbacks, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                Assert.Equal(address.CanonicalText, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);
                Assert.True(plan.Matches(await accounts.ReadOwnPermanentContactPlanAsync()));
                if (interruptedRetrieve)
                {
                    Assert.Equal(readRoot, await RootCopy(ProtectedDid2MailboxReadJournal.Slot));
                    Assert.Equal(grantRoot, await RootCopy(ProtectedDid2MailboxGrantJournal.Slot));
                    await RejectMissingOriginalPublication();
                    Assert.Equal(0, (await SynchronizeNativeSender(grants, terminal)).ProcessedEnvelopes);
                    Assert.Equal(1, grants.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
                    Assert.Equal(grantRoot, await RootCopy(ProtectedDid2MailboxGrantJournal.Slot));
                    using var reads = await ReadPeerMailboxReads(own: true);
                    Assert.Equal(0, reads.Phase); Assert.Null(reads.Active);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(priorBytes);
                if (readRoot is not null) CryptographicOperations.ZeroMemory(readRoot);
                if (grantRoot is not null) CryptographicOperations.ZeroMemory(grantRoot);
            }

            async Task<byte[]> RootCopy(string slot)
            {
                using var root = await innerStorage.ReadOwnedAsync(slot) ?? throw new InvalidOperationException();
                return root.Use(bytes => bytes.ToArray());
            }
            async Task RejectMissingOriginalPublication()
            {
                var good = await RouteSnapshot(); byte[]? damaged = null;
                using var state = await RouteState();
                var archived = Assert.Single(state.Entries, pair => pair.Key != name);
                state.Entries.Remove(archived.Key); archived.Value.Dispose();
                using var generation = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
                var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
                try
                {
                    damaged = ProtectedDid2ContactRouteJournal.Encode(state, Network, checkpoint.Directory.Record.DeepAccountId.Span, instance);
                    Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, damaged));
                    await Assert.ThrowsAsync<CryptographicException>(() => SynchronizeNativeSender(grants, terminal));
                    Assert.Equal(damaged, await RouteSnapshot());
                    Assert.Equal(readRoot, await RootCopy(ProtectedDid2MailboxReadJournal.Slot));
                    Assert.Equal(grantRoot, await RootCopy(ProtectedDid2MailboxGrantJournal.Slot));
                    Assert.Equal(1, grants.Calls); Assert.Equal(1, terminal.RetrieveCalls);
                }
                finally
                {
                    // Disposable test fault only; production cannot reconstruct
                    // absent original private publication custody.
                    if (damaged is not null)
                    {
                        Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, good));
                        CryptographicOperations.ZeroMemory(damaged);
                    }
                    CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(instance);
                }
            }

            Task<VerifiedDeepIdV2PublicationCommit> EnsureAsync()
            {
                var account = ReopenAccount();
                return account.EnsureOwnPermanentContactPublishedAsync(Source(account), backend, backend, backend);
            }
            async Task AssertCurrentPreservedAsync(int phase)
            {
                using var state = await RouteState(); Assert.Equal(2, state.Entries.Count);
                Assert.Equal(priorBytes, state.Entries[name].Exact.ToArray());
                var pending = Assert.Single(state.Entries, pair => pair.Key != name).Value;
                Assert.Equal((byte)phase, pending.Phase);
                var request = ContactRouteAuthorityWireCodec.DecodeRequest(pending.Record(12).Span);
                Assert.Equal(state.Entries[name].Record(5).ToArray(), request.ExactPredecessorXir1V2.ToArray());
                Assert.Equal(state.Entries[name].Record(6).ToArray(), request.ExactPredecessorRouteClosure.ToArray());
                await Assert.ThrowsAsync<InvalidOperationException>(() => Task.FromResult(pending.RebindCommittedIntent(plan.Intent.Span,
                    Network, checkpoint.Directory.Record.DeepAccountId.Span)));
            }
            async Task CheckPendingPredecessorTamperingAsync()
            {
                var good = await RouteSnapshot(); byte[]? damaged = null;
                using var state = await RouteState();
                var pending = Assert.Single(state.Entries, pair => pair.Key != name);
                var entry = pending.Value.Exact.ToArray();
                using var generation = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
                var instance = generation!.Use(bytes => bytes.Slice(56, 32).ToArray());
                try
                {
                    var offset = ProtectedDid2ContactRouteJournal.PrefixBytes;
                    for (var index = 0; index < 12; index++) offset += 4 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(entry.AsSpan(offset)));
                    offset += 4; // Entire canonical route request slot12.
                    entry[offset + ContactRouteAuthorityWireCodec.RequestPrefixBytes + 4 + 610] ^= 1;
                    var hostile = ProtectedDid2ContactRouteJournal.Entry.Decode(entry, Network, checkpoint.Directory.Record.DeepAccountId.Span);
                    state.Entries[pending.Key] = hostile; pending.Value.Dispose();
                    damaged = ProtectedDid2ContactRouteJournal.Encode(state, Network, checkpoint.Directory.Record.DeepAccountId.Span, instance);
                    Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, damaged));
                    var calls = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
                    await Assert.ThrowsAsync<CryptographicException>(EnsureAsync);
                    Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                    var actual = await RouteSnapshot();
                    try { Assert.Equal(damaged, actual); }
                    finally { CryptographicOperations.ZeroMemory(actual); }
                }
                finally
                {
                    // Restore only our intentionally corrupted fixture snapshot;
                    // the runtime never repairs/replaces an unknown predecessor.
                    if (damaged is not null)
                    {
                        Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, good));
                        CryptographicOperations.ZeroMemory(damaged);
                    }
                    CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(entry); CryptographicOperations.ZeroMemory(instance);
                }
            }
        }
    }

    // Real PQ/device/witness/node crypto and protected SQL; in-process durable
    // winners and synthetic signed replica results, NOT live Registry/device evidence.
    private sealed class RenewalBackend(Fixture fixture)
        : IDid2ContactRouteThresholdSource, IDid2ContactPublicationSource, IDid2ContactReplicaPublicationTransport
    {
        internal int RouteCalls, PublicationCalls, ReplicaCalls, RouteSignings, PublicationSignings;
        internal bool LoseRouteResponse, LosePublicationResponse, LoseReplicaResponse, CorruptReceipt;
        internal Action? AfterRouteReply;
        internal ulong CurrentDeadline => authorization.Freshness.FreshnessDeadlineMonotonicSeconds;
        private DeepIdV2CurrentContactAuthorization authorization = null!;
        private VerifiedOnionNetworkContext network = null!;
        private VerifiedXPointNetworkAuthority authority = null!;
        private OnionTrustedTimeAuthority time = null!;
        private VerifiedDeepIdV2ContactRouteClosure route = null!;
        private readonly Dictionary<ulong, byte[]> routeRequests = [], publicationRequests = [], publicationWinners = [];
        private readonly Dictionary<ulong, ContactRouteAuthorityWireResponse> routeWinners = [];

        public async ValueTask<ContactRouteAuthorityWireResponse> FetchAsync(ContactRouteAuthorityWireRequest request,
            DeepIdV2CurrentContactAuthorization current, VerifiedOnionNetworkContext currentNetwork,
            VerifiedXPointNetworkAuthority currentAuthority, OnionTrustedTimeAuthority clock,
            Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            operation.RequireActive(); RouteCalls++; authorization = current; network = currentNetwork; authority = currentAuthority; time = clock;
            var xra = ContactCodec.Decode("XRA1", request.ExactXra1.Span);
            var generation = BinaryPrimitives.ReadUInt64BigEndian(xra.Field(3).Span);
            RequireExact(routeRequests, generation, ContactRouteAuthorityWireCodec.EncodeRequest(request));
            if (!routeWinners.TryGetValue(generation, out var winner))
            {
                var expiry = BinaryPrimitives.ReadUInt64BigEndian(xra.Field(13).Span);
                var threshold = request.HasPredecessor ? await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(current, network, authority,
                    await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(current, network, authority, request.ExactPredecessorXir1V2,
                        request.ExactPredecessorRouteClosure, time, ct), request.ExactXra1, fixture.CreateRouteWitnesses(), expiry, time, ct) :
                    await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(current, network, authority, request.ExactXra1,
                        fixture.CreateRouteWitnesses(), current.TrustedLowerUnixSeconds, expiry, time, ct);
                routeWinners.Add(generation, winner = new(request.NetworkId.Span, request.RequestNonce.Span,
                    threshold.Selection.CanonicalBytes.Span, threshold.LiveRoute.CanonicalBytes.Span,
                    threshold.Successor.CanonicalBytes.Span, current.Freshness.ExactAdh1.Span)); RouteSignings++;
            }
            if (LoseRouteResponse) { LoseRouteResponse = false; throw new IOException("Lost retained route winner."); }
            AfterRouteReply?.Invoke();
            return winner;
        }

        public async ValueTask<ReadOnlyMemory<byte>> FetchAsync(ContactPublicationAuthorityWireRequest request,
            Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            operation.RequireActive(); PublicationCalls++;
            RequireExact(publicationRequests, request.Generation, ContactPublicationAuthorityWireCodec.EncodeRequest(request));
            route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, network, authority,
                DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span).Bundle.Field(14)[40..], request.ExactRouteClosure, time, ct);
            if (!publicationWinners.TryGetValue(request.Generation, out var winner))
            {
                VerifiedDeepIdV2PublicationAuthorization authorized;
                if (request.Generation == 0) authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(route, request, fixture.PublicationWitnesses(), ct);
                else
                {
                    using var state = await fixture.RouteState(); var prior = Assert.Single(state.Entries.Values, entry => entry.Phase == 7);
                    var priorRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(prior.Record(9).Span);
                    var priorResponse = ContactPublicationAuthorityWireCodec.DecodeResponse(priorRequest, prior.Record(10).Span);
                    var predecessor = await DeepIdV2PublicationCommitVerifier.VerifyIssuerPredecessorAsync(authorization, network, authority,
                        priorRequest, priorResponse.ExactXpu1, request.ExactPriorXpo1, time, ct);
                    authorized = await DeepIdV2PublicationAuthorityAuthor.AuthorIssuerThresholdSuccessorAsync(route, request, predecessor, fixture.PublicationWitnesses(), ct);
                }
                publicationWinners.Add(request.Generation, winner = ContactPublicationAuthorityWireCodec.EncodeResponse(request,
                    new(request.NetworkId.Span, request.RequestNonce.Span, authorized.ExactXpu1.Span))); PublicationSignings++;
            }
            if (LosePublicationResponse) { LosePublicationResponse = false; throw new IOException("Lost retained publication winner."); }
            return winner.ToArray();
        }

        public Task<ReadOnlyMemory<byte>> PublishAsync(ReadOnlyMemory<byte> exactXpu1, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); operation.RequireActive(); ReplicaCalls++;
            if (LoseReplicaResponse) { LoseReplicaResponse = false; throw new IOException("Lost replica reply."); }
            return Task.FromResult<ReadOnlyMemory<byte>>(fixture.PublicationResult(route, exactXpu1, CorruptReceipt));
        }
        private static void RequireExact(Dictionary<ulong, byte[]> requests, ulong generation, byte[] exact)
        {
            if (requests.TryGetValue(generation, out var prior)) Assert.Equal(prior, exact);
            else requests.Add(generation, exact);
        }
    }
}
