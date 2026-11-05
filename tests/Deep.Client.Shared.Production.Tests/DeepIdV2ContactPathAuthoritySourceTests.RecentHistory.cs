using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RecentHistory_ColdOwnedPagesKeepOnlyNewestAuthenticatedMessages()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x66));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var acceptance = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x67)))
        using (var sent = await fixture.SendOwnedMessage(receiver, acceptance.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(acceptance.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        for (var index = 0; index < 3; index++)
        {
            using var draft = await fixture.CreateOwnedText(sender, "bounded recent " + index);
            using var sent = await fixture.SendOwnedMessage(sender, draft.OperationId.ToArray(), ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
        }
        foreach (var account in new[] { fixture.ReopenAccount(), fixture.ReopenGrantReader() })
        {
            var conversation = Assert.Single(await account.ListConversationsAsync()).Conversation;
            var full = await account.ListMessagesAsync(conversation);
            Assert.Equal(3, full.Count);
            var requests = fixture.ProofRequests;
            Assert.Equal(full.TakeLast(2).Reverse(), await account.ListRecentMessagesAsync(conversation, 2));
            Assert.Equal(full.TakeLast(1), await account.ListRecentMessagesAsync(conversation, 1));
            Assert.Equal(full.Reverse(), await account.ListRecentMessagesAsync(conversation, 100));
            Assert.Equal(full.TakeLast(2).Reverse(), await account.ListRecentMessagesAsync(conversation.ConversationId, 2));
            Assert.Equal(full.TakeLast(1), await account.ListRecentMessagesAsync(conversation.ConversationId, 1));
            Assert.Equal(full.Reverse(), await account.ListRecentMessagesAsync(conversation.ConversationId, 100));
            Assert.Equal(requests, fixture.ProofRequests);
        }
        await fixture.VerifySelectedRecentConsentTampering(sender, receiver);
    }
}
