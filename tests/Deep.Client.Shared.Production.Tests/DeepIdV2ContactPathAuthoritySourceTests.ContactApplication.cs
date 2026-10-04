using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
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
            return await selected.Account.SendTextAsync(selected.Handle, op, text, selected.Source, grants, transport);
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
