using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record InboxSyncResult(
    int DirectMessages,
    int GroupUpdates,
    int GroupMessages,
    int DispatchedMessages);

public sealed class InboxSyncService(
    SessionAccountService accounts,
    ConversationService conversations,
    MessageService messages)
{
    private readonly SemaphoreSlim syncGate = new(1, 1);

    public async Task<InboxSyncResult> SynchronizeAsync(CancellationToken cancellationToken = default)
    {
        await syncGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var account = await accounts.GetActiveAccountAsync(cancellationToken).ConfigureAwait(false);
            if (account is null)
            {
                return new InboxSyncResult(0, 0, 0, 0);
            }

            var directMessages = await messages.ReceiveAsync(account.SessionId, cancellationToken).ConfigureAwait(false);
            var groupUpdates = await conversations.ReceiveGroupUpdatesAsync(account.SessionId, cancellationToken).ConfigureAwait(false);
            var groups = await conversations.ListGroupsAsync(cancellationToken).ConfigureAwait(false);
            var groupMessageCount = 0;

            foreach (var group in groups)
            {
                if (group.IsDestroyed || group.IsKicked || group.Members.All(member => member.SessionId != account.SessionId))
                {
                    continue;
                }

                var groupMessages = await messages.ReceiveGroupAsync(account.SessionId, group.Id, cancellationToken)
                    .ConfigureAwait(false);
                groupMessageCount += groupMessages.Count;
            }

            var dispatched = await messages.DispatchPendingMessagesAsync(account.SessionId, cancellationToken)
                .ConfigureAwait(false);

            return new InboxSyncResult(
                directMessages.Count,
                groupUpdates.Count,
                groupMessageCount,
                dispatched);
        }
        finally
        {
            syncGate.Release();
        }
    }
}
