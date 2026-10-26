using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2DeliveryEvents_FinalFreshnessPrecedesObservationAndObserverCannotChangeDurableReceive(bool rejectFinalFreshness)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xb7));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xb8)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using var draft = await fixture.CreateOwnedText(sender, "diagnostic boundary");
        using var outgoing = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
        var cipher = outgoing.ExactEnvelope.ToArray();
        using var observations = new DeliveryEventListener { ThrowAfterObservation = !rejectFinalFreshness };
        var reachedCommit = false;
        using (DirectDmc2InboxTestHooks.Push(point =>
        {
            if (point != DirectDmc2InboxFaultPoint.AfterCommit) return;
            reachedCommit = true;
            if (rejectFinalFreshness) fixture.Sample += 1000; // The final independent freshness guard must reject.
        }))
        {
            if (rejectFinalFreshness)
                await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedMessage(receiver, cipher));
            else
                using (var received = await fixture.ReceiveOwnedMessage(receiver, cipher)) Assert.Equal(2, received.Direction);
        }
        Assert.True(reachedCommit);
        if (rejectFinalFreshness) Assert.Empty(observations.Events);
        else
        {
            var visible = Assert.Single(observations.Events);
            Assert.Equal(3, visible.Phase);
            observations.ThrowAfterObservation = false;
            using (var replay = await fixture.ReceiveOwnedMessage(receiver, cipher)) { }
            Assert.Single(observations.Events);
            Assert.Single(await fixture.ListOwnedMessages(receiver), message => !message.IsLocalAuthor);
        }
    }
}
