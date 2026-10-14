using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2StoreCompletionRecovery_ColdAdoptsOriginalDurableFactWithoutReadmission(bool expireOriginal)
    {
        // Actual two-account PQ/ratchet/SQLCipher and signed original Store;
        // in-process authorities/transport, NOT sockets or physical delivery.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x71));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x72)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using var text = await fixture.CreateOwnedText(sender, "original durable fact is not a new attempt");
        var operation = text.OperationId.ToArray();
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        fixture.TrackMailboxDispatchClock();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        var reached = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.BeforeOrdinaryCompletion) return;
            reached = true; throw new IOException("Interrupted before protected Store completion.");
        }))
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
                fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.True(reached); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        byte[] exactSend;
        using (var sends = await fixture.ReadMailboxSends())
        {
            exactSend = Assert.Single(sends.Entries).Value.Exact.ToArray();
            Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter);
        }
        if (expireOriginal) await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenCompactionStorage();
        // Missing/substituted evidence or coordinator cannot be repaired from
        // a private holder/current replacement policy or a bare SQL Durable flag.
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(sender,
            () => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        await fixture.AssertCompactedStoreRejectsMissingOrChangedCoordinatorStatement(sender,
            () => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);

        // The same original SQL fact crosses both local completion handovers.
        // No dispatch/grant callback, root reset or explicit completion API.
        foreach (var point in new[] { Did2MailboxSendFailpoint.BeforeOrdinaryCompletion, Did2MailboxSendFailpoint.AfterOrdinaryCompletion })
        {
            var hit = false;
            using (Did2MailboxSendTestHooks.Push(actual =>
            { if (actual == point) { hit = true; throw new IOException("Interrupted local Store adoption."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
            Assert.True(hit); Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
            Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            if (point == Did2MailboxSendFailpoint.BeforeOrdinaryCompletion)
                Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
            else Assert.Empty(await fixture.ListNativePendingText());
            fixture.ColdReopenCompactionStorage();
        }
        var result = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.False(result.IngressDispatched); Assert.Equal(1UL, result.Cursor);
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Empty(await fixture.ListNativePendingText()); Assert.Single(await fixture.ListOwnedMessages(sender));
        Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        using (var sends = await fixture.ReadMailboxSends())
        {
            Assert.Equal(exactSend, Assert.Single(sends.Entries).Value.Exact.ToArray());
            Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter);
        }
        foreach (var bytes in new[] { authored, application, floor, exactSend }) CryptographicOperations.ZeroMemory(bytes);
    }
}
