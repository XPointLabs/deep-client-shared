using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Did2RetainedRead_ActualOwnerPersistsRequestAndColdReopensWinnerAfterRouteExpiry(bool elapsedRoute, bool loseReply)
    {
        // Real PQ account, protected publication and SQLCipher account/holder
        // custody. The signed issuer/receipt courier is in process: not device,
        // native-server custody or private Registry HTTPS/SQL acceptance.
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var original = await fixture.PrepareRetainedPublicationAsync(elapsedRoute);
        var courier = new RetainedReadCourier(fixture, original) { LoseReply = loseReply };
        if (loseReply)
        {
            await Assert.ThrowsAsync<IOException>(() => fixture.Accounts.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(), courier));
            using var pending = await fixture.ReadPeerGrantsAsync(own: true);
            Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            Assert.Null(Assert.Single(pending.Selections).Value.Current);
            courier.LoseReply = false;
        }
        var reopened = fixture.ReopenAccount();
        var result = await reopened.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(reopened), courier);
        Assert.Equal(MailboxCapabilityDomain.Retrieve, result.Domain);
        Assert.Equal(1, courier.Issuer.Calls);
        Assert.Equal(loseReply ? 2 : 1, courier.Calls);
        Assert.Equal(courier.Request.ToArray(), result.ExactXmg2.ToArray());
        var cold = fixture.ReopenAccount();
        Assert.Equal(result.ExactXmc2.ToArray(), (await cold.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(cold), courier)).ExactXmc2.ToArray());
        Assert.Equal(loseReply ? 2 : 1, courier.Calls);
        using var selected = await fixture.ReadPeerGrantsAsync(own: true);
        var winner = Assert.Single(selected.Entries).Value;
        Assert.True(ProtectedDid2MailboxGrantJournal.HasWinner(winner));
        Assert.Equal(ProtectedDid2MailboxGrantJournal.Acquisition(winner), Assert.Single(selected.Selections).Value.Current);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(result.ExactGrant.Span);
        Assert.Equal(original.Route.Projection.ArtifactHash.ToArray(), grant.MembershipCommitment.ToArray());
        Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(original.Route.Selection.Field(4).Span), grant.Epoch);
        await fixture.AssertInstalledGrantSqlAsync(result.ExactGrant, own: true);
        if (elapsedRoute)
        {
            Assert.True(fixture.ProofTime >= OriginalAdmissionEnd(original.Route));
            Assert.True(grant.NotBeforeUnixSeconds >= OriginalAdmissionEnd(original.Route));
            await Assert.ThrowsAsync<CryptographicException>(() => cold.ReadOwnPrivateContactMailboxRouteAsync(fixture.Source(cold)));
        }
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("publication")]
    [InlineData("time")]
    [InlineData("cancel")]
    public async Task Did2RetainedRead_RejectsResultOrCustodyLossWithoutAdoptingWinner(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var original = await fixture.PrepareRetainedPublicationAsync(elapsed: true);
        var before = await fixture.Source().VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        var proofDeadline = before.Proof.FreshnessDeadlineMonotonicSeconds;
        using var cancellation = new CancellationTokenSource();
        var courier = new RetainedReadCourier(fixture, original) { CorruptSignature = fault == "signature" };
        courier.BeforeReturn = async () =>
        {
            if (fault == "publication") await fixture.DamageRetainedPublicationAsync();
            if (fault == "time")
            {
                var elapsed = checked(proofDeadline - fixture.Sample);
                fixture.Sample = proofDeadline; fixture.ProofTime += elapsed;
            }
            if (fault == "cancel") cancellation.Cancel();
        };
        if (fault == "cancel")
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Accounts.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(), courier, cancellation.Token));
        else
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.Accounts.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(), courier));
        using (var pending = await fixture.ReadPeerGrantsAsync(own: true))
        {
            Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(pending.Entries).Value));
            Assert.Null(Assert.Single(pending.Selections).Value.Current);
        }
        if (fault is "publication" or "time") return; // No repair, expired-request retry or rewindowing.
        courier.BeforeReturn = null; courier.CorruptSignature = false;
        var reopened = fixture.ReopenAccount();
        var recovered = await reopened.AcquireOwnPermanentContactRetrieveGrantAsync(fixture.Source(reopened), courier);
        Assert.Equal(courier.Request.ToArray(), recovered.ExactXmg2.ToArray());
        Assert.Equal(1, courier.Issuer.Calls);
    }

    [Fact]
    public async Task Did2RetainedRead_UnpublishedOwnRouteCannotEnterCourier()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckUnpublishedRetainedReadAsync();
    }

    private static ulong OriginalAdmissionEnd(ParsedContactRouteClosure route) => new[] {
        BinaryPrimitives.ReadUInt64BigEndian(route.Reachability.Field(17).Span),
        BinaryPrimitives.ReadUInt64BigEndian(route.Authorization.Field(13).Span),
        BinaryPrimitives.ReadUInt64BigEndian(route.Route.Field(18).Span),
        BinaryPrimitives.ReadUInt64BigEndian(route.Successor.Field(11).Span),
        BinaryPrimitives.ReadUInt64BigEndian(route.Projection.Field(12).Span),
        BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(9).Span) }.Min();

    private sealed partial class Fixture
    {
        internal ValueTask<VerifiedMailboxHostAuthorityV2> RetainedReadHostAsync(Did2OwnedContactTransportContext dispatch,
            CancellationToken ct) => MailboxHostAuthorityV2Verifier.VerifyAsync(dispatch.Network, ProofAuthority,
                objectHorizonClosure?.ExactOrderedPma2Chain[^1] ?? rotatedIssuerPma ?? successor?.ExactPma2 ?? operational.ExactPma2,
                Source(dispatch.Custody.Owner).RendezvousTrustedTime, ct);

        internal async Task<ParsedDeepIdV2ContactMailboxRoute> PrepareRetainedPublicationAsync(bool elapsed, ulong signedExpiry = 1_200)
        {
            var source = Source(); var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this) { ShorterSignedExpiry = signedExpiry };
            var route = await accounts.EnsureOwnContactRouteAsync(plan.Intent, source, Did2OwnedPermanentContactPlan.Configuration(), threshold);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(source, threshold,
                new OwnedPublicationSource(this, route), new OwnedPublicationReplica(this, route));
            var facts = await accounts.ReadOwnPrivateContactMailboxRouteAsync(source);
            if (elapsed)
            {
                // The nominal center alone is not a trusted lower bound. Move
                // beyond the signed uncertainty, then assert the actual grant's
                // authenticated NotBefore is after original admission expiry.
                var next = OriginalAdmissionEnd(facts.Route) + 31;
                Sample += next - ProofTime; ProofTime = next;
            }
            return facts;
        }

        internal async Task DamageRetainedPublicationAsync()
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot) ?? throw new InvalidOperationException();
            var original = root.Use(bytes => bytes.ToArray()); var corrupt = original.Append((byte)0).ToArray();
            try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, original, corrupt)); }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(corrupt); }
        }

        internal async Task CheckUnpublishedRetainedReadAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync(); using var threshold = new OwnedRouteThreshold(this);
            var route = await accounts.EnsureOwnContactRouteAsync(plan.Intent, Source(), Did2OwnedPermanentContactPlan.Configuration(), threshold);
            var original = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteCodec.Encode(route));
            var courier = new RetainedReadCourier(this, original);
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.AcquireOwnPermanentContactRetrieveGrantAsync(Source(), courier));
            Assert.Equal(0, courier.Calls); Assert.Equal(0, courier.Issuer.Calls);
            using var custody = await ReadPeerGrantsAsync(own: true); Assert.Empty(custody.Entries);
        }
    }

    private sealed class RetainedReadCourier(Fixture fixture, ParsedDeepIdV2ContactMailboxRoute original)
        : IDid2RetainedMailboxReadGrantTransport
    {
        internal FixtureMailboxIssuer Issuer { get; } = new(0x32);
        internal int Calls { get; private set; }
        internal bool LoseReply { get; set; }
        internal bool CorruptSignature { get; set; }
        internal Func<Task>? BeforeReturn { get; set; }
        private byte[]? request, response;
        internal ReadOnlyMemory<byte> Request => request ?? throw new InvalidOperationException();
        public async ValueTask<ReadOnlyMemory<byte>> AcquireRetainedReadAsync(AuthoredMailboxGrantRequest exact,
            Did2OwnedContactTransportContext dispatch, CancellationToken ct)
        {
            dispatch.RequireActive(); ct.ThrowIfCancellationRequested(); Calls++;
            using (var custody = await fixture.ReadPeerGrantsAsync(own: true))
            {
                var pending = Assert.Single(custody.Entries).Value;
                Assert.Equal(exact.ExactXmg2.ToArray(), ProtectedDid2MailboxGrantJournal.Request(pending).ToArray());
                Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(pending));
            }
            if (request is null) request = exact.ExactXmg2.ToArray();
            else Assert.Equal(request, exact.ExactXmg2.ToArray());
            if (response is null)
            {
                var host = await fixture.RetainedReadHostAsync(dispatch, ct);
                var parsed = ContactCodec.Decode("XMG2", request);
                var horizon = checked(OriginalAdmissionEnd(original.Route) + 2_592_000UL);
                var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(request), parsed.Field(3).Span,
                    MailboxGrantCapabilityDigest.Compute(parsed.Field(4).Span, MailboxCapabilityDomain.Retrieve), original.Route.ExactHash.Span, horizon);
                var placement = ContactServicePlacementFactory.Create(dispatch.Network, ContactServiceRequestKind.AcquireMailboxGrant, parsed.Field(3));
                var evidence = placement.RankedReplicaNodeIds.Select(id => new DeepIdV2MailboxGrantReplicaEvidence(id.ToArray(),
                    fixture.PublicationReceipt(id, MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple)))).ToArray();
                var candidate = await host.VerifyRetainedReadIssuanceAsync(request, original.Route.ExactBytes, horizon, evidence, ct);
                response = (await candidate.AuthorSuccessAsync(Issuer, ct)).ToArray();
            }
            if (LoseReply) throw new IOException("Injected retained-read issuer reply loss.");
            var returned = response.ToArray(); if (CorruptSignature) returned[^1] ^= 1;
            if (BeforeReturn is not null) await BeforeReturn();
            return returned;
        }
    }
}
