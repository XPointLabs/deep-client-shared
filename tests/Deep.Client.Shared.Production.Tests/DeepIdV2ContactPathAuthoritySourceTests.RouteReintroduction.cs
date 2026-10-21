using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_NativeControlStoreAndColdOrdinaryReplayKeepOriginalCiphertext()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray(); byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext);
        _ = await fixture.DeliverReintroducedRoute(sender, operation, new OwnedGrantTransport(fixture, ownerOnPrimary: true), terminal);
        Assert.Equal(1, terminal.Calls);
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using (var received = await fixture.ReceiveOwnedMessage(receiver, ciphertext)) Assert.Equal(1, received.RouteProcessing[0]);
        fixture.ColdReopenCompactionStorage();
        // Ordinary historical replay must understand publication provenance;
        // no special route override or second Store can survive this call.
        var replay = new OwnedStoreFixture(fixture, sender, operation, ciphertext);
        _ = await fixture.DeliverNativeMessage(sender, operation, new OwnedGrantTransport(fixture, ownerOnPrimary: true), replay);
        Assert.Equal(0, replay.Calls);
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_OrdinaryOrMissingNativeOperationRefusesBeforeGrantAndStore(bool missing)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var command = await fixture.CreateOwnedText(sender, "ordinary text cannot use recovery carriage");
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedMessage(sender, command.OperationId,
            ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span))) ciphertext = sent.ExactEnvelope.ToArray();
        var operation = missing ? Bytes(32, 0xdc) : command.OperationId.ToArray();
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, ciphertext);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverReintroducedRoute(sender, operation, grants, terminal));
        Assert.Equal(0, terminal.Calls); Assert.Equal(0, grants.Calls);
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    private sealed partial class Fixture
    {
        internal async Task<Deep.Client.Shared.Services.ClientMailboxStoreResult> DeliverReintroducedRoute(
            Did2MessagingSessionScope scope, byte[] operation, IDid2MailboxGrantTransport grants,
            IDid2OwnedMailboxTransportFactory transport)
        {
            var source = Source();
            var fresh = await accounts.ResolvePermanentContactAsync(nativeMessagingContact!.Candidate.Address, source,
                new SyntheticPermanentRead(this, source, nativeMessagingPublication));
            var contact = await source.VerifyPermanentContactAsync(fresh.Candidate, default);
            return await SenderCompactionOwner().DeliverRouteReintroductionAsync(1_000, pq, scope, operation,
                contact, source, grants, transport, default);
        }
    }

    [Theory]
    [InlineData("foreign-peer")]
    [InlineData("expired-proof")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteReintroduction_UnrelatedPublicationOrElapsedProofCannotAuthorizeExistingScope(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.CheckReintroductionPreflightFault(sender, fault));
        Assert.True(fixture.ReintroductionPreflightReached); // Valid publication reached the actual scope/time guard.
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    private sealed partial class Fixture
    {
        internal bool ReintroductionPreflightReached { get; private set; }
        internal async Task CheckReintroductionPreflightFault(Did2MessagingSessionScope scope, string fault)
        {
            var source = Source(); var address = nativeMessagingContact!.Candidate.Address;
            var publication = nativeMessagingPublication;
            if (fault == "foreign-peer")
            {
                var plan = await accounts.ReadOwnPermanentContactPlanAsync();
                using var state = await RouteState();
                var entry = state.Entries[Convert.ToHexString(plan.Intent.Span)];
                var request = Deep.Protocol.ContactV1.ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
                publication = Deep.Protocol.ContactV1.ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span).ExactXpu1;
                address = (await accounts.GetCurrentAsync())!.PermanentId;
            }
            var fresh = await accounts.ResolvePermanentContactAsync(address, source, new SyntheticPermanentRead(this, source, publication));
            var resolved = await source.VerifyPermanentContactAsync(fresh.Candidate, default);
            ReintroductionPreflightReached = true;
            if (fault == "expired-proof") Sample = resolved.Own.Proof.FreshnessDeadlineMonotonicSeconds;
            await SenderCompactionOwner().RequireRouteReintroductionAsync(1_000, pq, scope, resolved, source, default);
        }
    }
}
