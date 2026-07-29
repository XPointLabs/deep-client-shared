namespace Deep.Client.Shared.Persistence;

using Deep.Protocol.DeepExtension.MailboxCapabilities;

public sealed class InMemoryClientMailboxStateRepository :
    IClientMailboxStateRepository
{
    private readonly Dictionary<string, ClientMailboxStoredState> states =
        new(StringComparer.Ordinal);
    private readonly object gate = new();

    public Task<ulong> ReadAfterCursorAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            return Task.FromResult(Get(scope).AfterCursor);
        }
    }

    public Task<ClientMailboxMergeResult> MergeRetrievePageAsync(
        ClientMailboxScope scope,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            return Task.FromResult(ClientMailboxStateMachine.Merge(Get(scope), page));
        }
    }

    public Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            return Task.FromResult(ClientMailboxStateMachine.Check(
                Get(scope),
                acknowledgements));
        }
    }

    public Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            return Task.FromResult(ClientMailboxStateMachine.Commit(
                Get(scope),
                acknowledgements));
        }
    }

    private ClientMailboxStoredState Get(ClientMailboxScope scope)
    {
        var key = Convert.ToHexString(scope.Value);
        if (!states.TryGetValue(key, out var state))
        {
            state = new ClientMailboxStoredState();
            states.Add(key, state);
        }

        return state;
    }
}
