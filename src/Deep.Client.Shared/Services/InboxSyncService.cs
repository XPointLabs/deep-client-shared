using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record InboxSyncResult(
    int DirectMessages,
    int GroupUpdates,
    int GroupMessages,
    int DispatchedMessages);

public sealed class InboxSyncService : IAccountGenerationLifecycle, IDisposable
{
    private static readonly InboxSyncResult EmptyResult = new(0, 0, 0, 0);

    private readonly SessionAccountService accounts;
    private readonly ConversationService conversations;
    private readonly MessageService messages;
    private readonly object inFlightGate = new();
    private readonly Dictionary<SessionId, InFlightSync> inFlightSyncs = [];
    private readonly SemaphoreSlim syncGate = new(1, 1);
    private CancellationTokenSource accountEpochCancellation = new();
    private int disposed;

    public InboxSyncService(
        SessionAccountService accounts,
        ConversationService conversations,
        MessageService messages)
    {
        this.accounts = accounts;
        this.conversations = conversations;
        this.messages = messages;
        accounts.AccountStateChanged += OnAccountStateChanged;
    }

    public async Task<InboxSyncResult> SynchronizeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var account = await accounts.GetActiveAccountAsync(cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return EmptyResult;
        }

        InFlightSync operation;
        var shouldStart = false;
        lock (inFlightGate)
        {
            if (!inFlightSyncs.TryGetValue(account.SessionId, out operation!))
            {
                operation = new InFlightSync(account.SessionId, accountEpochCancellation.Token);
                inFlightSyncs.Add(account.SessionId, operation);
                shouldStart = true;
            }
        }

        if (shouldStart)
        {
            _ = ExecuteAsync(operation);
        }

        var result = await operation.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await IsActiveAccountAsync(operation.Account, cancellationToken).ConfigureAwait(false)
            ? result
            : EmptyResult;
    }

    private async Task ExecuteAsync(InFlightSync operation)
    {
        try
        {
            var result = await RunSerializedAsync(operation.Account, operation.AccountEpoch).ConfigureAwait(false);
            operation.Completion.TrySetResult(result);
            Remove(operation);
        }
        catch (OperationCanceledException) when (operation.AccountEpoch.IsCancellationRequested)
        {
            operation.Completion.TrySetResult(EmptyResult);
            Remove(operation);
        }
        catch (OperationCanceledException exception)
        {
            operation.Completion.TrySetCanceled(exception.CancellationToken);
            Remove(operation);
        }
        catch (Exception exception)
        {
            operation.Completion.TrySetException(exception);
            Remove(operation);
        }
    }

    private async Task<InboxSyncResult> RunSerializedAsync(
        SessionId account,
        CancellationToken accountEpoch)
    {
        await syncGate.WaitAsync(accountEpoch).ConfigureAwait(false);
        try
        {
            accountEpoch.ThrowIfCancellationRequested();
            if (!await IsActiveAccountAsync(account, accountEpoch).ConfigureAwait(false))
            {
                return EmptyResult;
            }

            var result = await SynchronizeAccountAsync(account, accountEpoch).ConfigureAwait(false);
            accountEpoch.ThrowIfCancellationRequested();
            return await IsActiveAccountAsync(account, accountEpoch).ConfigureAwait(false)
                ? result
                : EmptyResult;
        }
        finally
        {
            syncGate.Release();
        }
    }

    private async Task<InboxSyncResult> SynchronizeAccountAsync(
        SessionId account,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Message> directMessages;
        IReadOnlyList<Group> groups;
        var groupUpdateCount = 0;
        if (messages.SupportsDurableGroupInboxMaintenance)
        {
            var stagedGroupUpdates = await conversations.ReceiveGroupUpdatesAsync(
                account,
                cancellationToken).ConfigureAwait(false);
            groupUpdateCount += stagedGroupUpdates.Count;
            groups = await conversations.ListGroupsAsync(cancellationToken).ConfigureAwait(false);
            await messages.DiscardUnknownGroupInboxMessagesAsync(
                account,
                ActiveGroupIds(groups, account),
                cancellationToken).ConfigureAwait(false);

            directMessages = await messages.ReceiveAsync(account, cancellationToken).ConfigureAwait(false);

            var newlyRetrievedGroupUpdates = await conversations.ReceiveGroupUpdatesAsync(
                account,
                cancellationToken).ConfigureAwait(false);
            groupUpdateCount += newlyRetrievedGroupUpdates.Count;
            groups = await conversations.ListGroupsAsync(cancellationToken).ConfigureAwait(false);
            await messages.DiscardUnknownGroupInboxMessagesAsync(
                account,
                ActiveGroupIds(groups, account),
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            directMessages = await messages.ReceiveAsync(account, cancellationToken).ConfigureAwait(false);
            var groupUpdates = await conversations.ReceiveGroupUpdatesAsync(account, cancellationToken)
                .ConfigureAwait(false);
            groupUpdateCount = groupUpdates.Count;
            groups = await conversations.ListGroupsAsync(cancellationToken).ConfigureAwait(false);
        }

        var groupMessages = await messages.ReceiveGroupsAsync(account, groups, cancellationToken)
            .ConfigureAwait(false);

        var dispatched = await messages.DispatchPendingMessagesAsync(account, cancellationToken)
            .ConfigureAwait(false);

        return new InboxSyncResult(
            directMessages.Count,
            groupUpdateCount,
            groupMessages.Count,
            dispatched);
    }

    private async Task<bool> IsActiveAccountAsync(SessionId account, CancellationToken cancellationToken)
    {
        var activeAccount = await accounts.GetActiveAccountAsync(cancellationToken).ConfigureAwait(false);
        return activeAccount?.SessionId == account;
    }

    private void Remove(InFlightSync operation)
    {
        lock (inFlightGate)
        {
            if (inFlightSyncs.TryGetValue(operation.Account, out var current)
                && ReferenceEquals(current, operation))
            {
                inFlightSyncs.Remove(operation.Account);
            }
        }
    }

    private void OnAccountStateChanged()
    {
        RotateAccountEpoch();
    }

    async Task IAccountGenerationLifecycle.StopAsync(
        SessionId account,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CancellationTokenSource cancellation;
        Task[] operations;
        lock (inFlightGate)
        {
            cancellation = accountEpochCancellation;
            operations = inFlightSyncs.Values
                .Where(operation => operation.Account == account)
                .Select(operation => operation.Completion.Task)
                .ToArray();
        }

        cancellation.Cancel();
        await Task.WhenAll(operations).ConfigureAwait(false);
    }

    void IAccountGenerationLifecycle.Resume(SessionId account)
    {
        RotateAccountEpoch();
    }

    private void RotateAccountEpoch()
    {
        CancellationTokenSource previous;
        lock (inFlightGate)
        {
            if (disposed != 0)
            {
                return;
            }

            previous = accountEpochCancellation;
            accountEpochCancellation = new CancellationTokenSource();
        }

        previous.Cancel();
        previous.Dispose();
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        accounts.AccountStateChanged -= OnAccountStateChanged;
        CancellationTokenSource cancellation;
        lock (inFlightGate)
        {
            cancellation = accountEpochCancellation;
        }

        cancellation.Cancel();
        cancellation.Dispose();
    }

    private static IReadOnlyCollection<ConversationId> ActiveGroupIds(
        IEnumerable<Group> groups,
        SessionId account) =>
        groups
            .Where(group =>
                !group.IsDestroyed
                && !group.IsKicked
                && group.Members.Any(member => member.SessionId == account && !member.IsPendingRemoval))
            .Select(static group => group.Id)
            .Distinct()
            .ToArray();

    private sealed class InFlightSync(SessionId account, CancellationToken accountEpoch)
    {
        public SessionId Account { get; } = account;

        public CancellationToken AccountEpoch { get; } = accountEpoch;

        public TaskCompletionSource<InboxSyncResult> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
