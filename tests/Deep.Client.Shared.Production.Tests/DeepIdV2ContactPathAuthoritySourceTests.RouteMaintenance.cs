using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteMaintenance_NoChangeOrExactPendingControlSelectedAcrossNativeCommitAndStore()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        var health = await fixture.Accounts.ReadContactRouteHealthAsync(new(sender), fixture.Source());
        Assert.True(health.AdvertisementIntervalCoversNow); Assert.True(health.UpdateIntervalCoversNow);
        Assert.False(health.RouteFaultRetained);
        fixture.TrackMailboxDispatchClock();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync();
        var before = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        Assert.Empty((await fixture.SelectRouteMaintenance(sender))!);
        Assert.Equal(before, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray()); // selection never authors
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var op = command.OperationId.ToArray();
        Assert.Equal(op, await fixture.SelectRouteMaintenance(sender));
        byte[] cipher;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, op)) cipher = sent.ExactEnvelope.ToArray();
        Assert.Equal(op, await fixture.SelectRouteMaintenance(sender)); // committed but not stored remains original work
        using (var received = await fixture.ReceiveOwnedMessage(receiver, cipher)) Assert.Equal(1, received.RouteProcessing[0]);
        var terminal = new OwnedStoreFixture(fixture, sender, op, cipher);
        _ = await fixture.DeliverNativeMessage(sender, op, new OwnedGrantTransport(fixture, ownerOnPrimary: true), terminal);
        Assert.Null(await fixture.SelectRouteMaintenance(sender));
        Assert.Equal(1, terminal.Calls);
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]?> SelectRouteMaintenance(Did2MessagingSessionScope scope)
        {
            var source = Source(); var pair = await source.VerifyForOwnMessagingAsync(accounts, scope, default);
            return await SenderCompactionOwner().SelectOwnRouteMaintenanceAsync(1_000, pq, scope,
                pair.Own, pair.Peer, source, default);
        }
    }
}
