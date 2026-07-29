using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemoryClientMailboxStateRepository :
    IClientMailboxStateRepository
{
    private readonly Dictionary<string, ClientMailboxStoredState> states =
        new(StringComparer.Ordinal);
    private readonly object gate = new();
    private readonly Action<ClientMailboxCommitFaultPoint>? commitFault;

    public InMemoryClientMailboxStateRepository()
    {
    }

    internal InMemoryClientMailboxStateRepository(
        Action<ClientMailboxCommitFaultPoint>? commitFault)
    {
        this.commitFault = commitFault;
    }

    public Task<ClientMailboxTraversal> ReadTraversalAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        Read(scope, ClientMailboxStateMachine.Traversal, cancellationToken);

    public Task<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
        ClientMailboxScope scope,
        CancellationToken cancellationToken = default) =>
        Read(scope, ClientMailboxStateMachine.DurableInbox, cancellationToken);

    public Task<ClientMailboxReceiveCommitResult> CommitRetrievePageAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expectedTraversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default) =>
        Mutate(
            scope,
            state => ClientMailboxStateMachine.CommitPage(
                state,
                expectedTraversal,
                page),
            cancellationToken);

    public Task<ClientMailboxAckState> CheckAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        Read(
            scope,
            state => ClientMailboxStateMachine.Check(state, acknowledgements),
            cancellationToken);

    public Task<IReadOnlyList<ClientMailboxAckExpectation>> ReadAckExpectationsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        Read(
            scope,
            state => ClientMailboxStateMachine.AckExpectations(
                state,
                acknowledgements),
            cancellationToken);

    public Task<ClientMailboxAckState> CommitAcknowledgementsAsync(
        ClientMailboxScope scope,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken = default) =>
        Mutate(
            scope,
            state => ClientMailboxStateMachine.CommitAck(state, acknowledgements),
            cancellationToken);

    public Task<ClientMailboxCoordinatorRecordResult> RecordCoordinatorStatementAsync(
        ClientMailboxScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        Mutate(
            scope,
            state => ClientMailboxStateMachine.RecordCoordinator(
                state,
                membershipCommitment.Span,
                epoch,
                coordinatorId.Span,
                coordinatorSequence,
                statementDigest.Span,
                expiresAtUnixSeconds,
                nowUnixSeconds),
            cancellationToken);

    internal byte[] ExportStateForTests(ClientMailboxScope scope)
    {
        lock (gate)
        {
            return ClientMailboxStateCodec.Encode(Get(scope));
        }
    }

    internal void ImportStateForTests(
        ClientMailboxScope scope,
        ReadOnlySpan<byte> encoded)
    {
        lock (gate)
        {
            states[Key(scope)] = ClientMailboxStateCodec.Decode(encoded);
        }
    }

    private Task<TResult> Read<TResult>(
        ClientMailboxScope scope,
        Func<ClientMailboxStoredState, TResult> read,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            return Task.FromResult(read(Get(scope).Clone()));
        }
    }

    private Task<TResult> Mutate<TResult>(
        ClientMailboxScope scope,
        Func<ClientMailboxStoredState, TResult> mutation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            var candidate = Get(scope).Clone();
            var result = mutation(candidate);
            _ = ClientMailboxStateCodec.Encode(candidate);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            states[Key(scope)] = candidate;
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result);
        }
    }

    private ClientMailboxStoredState Get(ClientMailboxScope scope)
    {
        var key = Key(scope);
        if (!states.TryGetValue(key, out var state))
        {
            state = new ClientMailboxStoredState();
            states.Add(key, state);
        }

        return state;
    }

    private static string Key(ClientMailboxScope scope) =>
        Convert.ToHexString(scope.Value);
}
