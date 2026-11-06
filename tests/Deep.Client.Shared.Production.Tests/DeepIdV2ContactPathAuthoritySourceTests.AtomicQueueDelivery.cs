using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AtomicQueue_DeliveryObservationFollowsNativeReadbackAndColdExactResume()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, objectHorizonWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var observations = new DeliveryEventListener
        {
            AckCalls = () => { fixture.CheckCounterObservationLease(); return 0; }
        };
        var operation = await fixture.QueueNativeText(sender, "observed native original");
        Assert.Equal(1, Assert.Single(observations.Events).Phase);
        observations.Events.Clear();
        await StoreOriginal(operation, "observed native original");
        CheckOutboxThenStore();

        using (Did2TextOutboxTestHooks.Push(point =>
        { if (point == Did2TextOutboxFailpoint.AfterStable) throw new IOException("Interrupted after native observation capture."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.QueueNativeText(sender, "observed cold original"));
        Assert.Empty(observations.Events); // Capturing private facts cannot publish a failed command.
        var original = Assert.Single(await fixture.ListNativePendingText());
        var before = await fixture.ReadMessagingFloor(sender);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage();
        await StoreOriginal(original.LogicalOperation.ToArray(), "observed cold original");
        CheckOutboxThenStore();
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());

        using var cancelled = new CancellationTokenSource();
        using (Did2TextOutboxTestHooks.Push(point =>
        { if (point == Did2TextOutboxFailpoint.AfterStable) cancelled.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.QueueAtomicCounterText(sender,
                "cancelled observation", cancelled.Token));
        Assert.Empty(observations.Events);

        async Task StoreOriginal(byte[] selected, string text)
        {
            var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
            var terminal = new OwnedStoreFixture(fixture, sender, selected, null);
            _ = await fixture.SendNativeText(sender, selected, text, grants, terminal);
            Assert.Equal(1, terminal.Calls);
        }
        void CheckOutboxThenStore()
        {
            Assert.Equal(new[] { 1, 2 }, observations.Events.Select(item => item.Phase));
            Assert.Equal(observations.Events[0].MessageHash, observations.Events[1].MessageHash);
            Assert.Equal(observations.Events[0].DeliveryHash, observations.Events[1].DeliveryHash);
            Assert.All(observations.Events, item => Assert.Equal(0, item.AckCalls));
            observations.Events.Clear();
        }
    }
}
