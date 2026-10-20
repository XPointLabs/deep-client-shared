using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Text_QueueBorrowsOneVerifiedEndpointPairForConsentAndAuthoringOnly()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x73));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x74)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var nativeBefore = await fixture.ReadMessagingFloor(sender);
        var before = fixture.ProofRequests;
        var first = await fixture.QueueNativeText(sender, "one scoped queue");
        Assert.Equal(before + 2, fixture.ProofRequests); // Own + peer, not one pair per internal step.
        before = fixture.ProofRequests;
        var second = await fixture.QueueNativeText(sender, "another independent queue");
        Assert.Equal(before + 2, fixture.ProofRequests); // No leaked command scope.
        Assert.NotEqual(first, second);
        Assert.Equal(nativeBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(2, (await fixture.ListNativePendingText()).Count);
    }

    private sealed partial class Fixture
    {
        internal Task<DeepIdV2ContactStartResult> StartNativeContact(byte[] intent, IDid2MailboxGrantTransport grants,
            IDid2OwnedMailboxTransportFactory transport)
        {
            var account = ReopenAccount(); var source = Source(account);
            return account.StartContactAsync(nativeMessagingContact!.Candidate.Address, intent, source,
                new SyntheticPermanentRead(this, source, nativeMessagingPublication), null, grants, transport);
        }
        internal async Task VerifyNativeApplicationStartOperation(byte[] intent)
        {
            var account = ReopenAccount();
            var retained = Assert.Single(await account.ListContactStartOperationsAsync());
            Assert.Equal(intent, retained.LogicalIntent.ToArray());
            Assert.Equal(Convert.ToHexString(nativeMessagingContact!.Candidate.Address.ExactDid2Hash.Span), retained.PeerDid2Hash);
            Assert.True(retained.CreatedAtUnixMilliseconds < retained.ExpiresAtUnixMilliseconds);
            var callerCopy = retained.LogicalIntent.ToArray(); callerCopy.AsSpan().Clear();
            Assert.Equal(intent, retained.LogicalIntent.ToArray());
        }
        private async Task<(DeepIdV2AccountService Account, DeepIdV2ContactPathAuthoritySource Source, DeepIdV2Conversation Handle)>
            ReadApplicationConversation(Did2MessagingSessionScope scope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            var list = await account.ListConversationsAsync();
            var selected = Assert.Single(list, value => value.Conversation.ConversationId == Convert.ToHexString(scope.Conversation)).Conversation;
            Assert.Equal(Convert.ToHexString(scope.RemoteAccount), selected.PeerAccountId);
            Assert.Equal(scope.IsInitiator, selected.IsInitiator);
            return (account, source, selected);
        }
        internal async Task<ClientMailboxStoreResult> AcceptNativeContact(Did2MessagingSessionScope scope, byte[] op,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var selected = await ReadApplicationConversation(scope);
            return await selected.Account.AcceptContactAsync(selected.Handle, op, selected.Source, grants, transport);
        }
        internal async Task<ClientMailboxStoreResult> SendNativeText(Did2MessagingSessionScope scope, byte[] op, string text,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var selected = await ReadApplicationConversation(scope);
            return await selected.Account.RetryTextAsync(selected.Handle, op, text, selected.Source, grants, transport);
        }
        internal async Task<byte[]> QueueNativeText(Did2MessagingSessionScope scope, string text)
        {
            var selected = await ReadApplicationConversation(scope);
            return (await selected.Account.QueueTextAsync(selected.Handle, text, selected.Source)).ToArray();
        }
        internal async Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListNativeApplicationMessages(Did2MessagingSessionScope scope)
        {
            var selected = await ReadApplicationConversation(scope);
            return await selected.Account.ListMessagesAsync(selected.Handle);
        }
        internal Task<IReadOnlyList<DeepIdV2PendingTextSnapshot>> ListNativePendingText(bool own = true)
            => (own ? ReopenAccount() : ReopenGrantReader()).ListPendingTextOperationsAsync();
    }
}
