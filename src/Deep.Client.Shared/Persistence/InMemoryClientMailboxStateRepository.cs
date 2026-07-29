using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemoryClientMailboxStateRepository :
    IClientMailboxStateRepository
{
    private readonly Dictionary<string, ClientMailboxStoredState> states =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, ClientMailboxJournalState> journals =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<ClientMailboxStoredEntry>> expiredQuarantine =
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

    public Task<ClientMailboxExpiryReconciliationResult> ReconcileExpiredAsync(
        ClientMailboxScope scope,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            var key = Key(scope);
            var candidate = Get(scope).Clone();
            var quarantine = expiredQuarantine.TryGetValue(key, out var current)
                ? current.Select(static entry => entry.Clone()).ToList()
                : [];
            var result = ClientMailboxStateMachine.ReconcileExpired(
                candidate,
                nowUnixSeconds,
                quarantine);
            if (result.QuarantinedUnacknowledged == 0 &&
                result.RemovedAcknowledged == 0)
            {
                return Task.FromResult(result);
            }

            while (quarantine.Count >
                       ClientMailboxStateLimits.MaximumExpiredQuarantineEntries ||
                   quarantine.Sum(static entry =>
                       (long)entry.CanonicalEnvelope.Length) >
                       ClientMailboxStateLimits.MaximumExpiredQuarantineBytes)
            {
                quarantine.Remove(quarantine
                    .OrderBy(static entry => entry.ExpiresAtUnixSeconds)
                    .ThenBy(static entry => entry.Cursor)
                    .First());
            }

            _ = ClientMailboxStateCodec.Encode(candidate);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            states[key] = candidate;
            expiredQuarantine[key] = quarantine;
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result);
        }
    }

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
        ClientMailboxJournalScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        MutateJournal(
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

    internal ClientMailboxJournalState ExportJournalForTests(
        ClientMailboxJournalScope scope)
    {
        lock (gate)
        {
            var key = Convert.ToHexString(scope.Value);
            return journals.TryGetValue(key, out var state)
                ? state.Clone()
                : new ClientMailboxJournalState();
        }
    }

    internal void ImportJournalForTests(
        ClientMailboxJournalScope scope,
        ClientMailboxJournalState journal)
    {
        ArgumentNullException.ThrowIfNull(journal);
        lock (gate)
        {
            var candidate = journal.Clone();
            ClientMailboxStateMachine.ValidateJournal(candidate);
            journals[Convert.ToHexString(scope.Value)] = candidate;
        }
    }

    internal int ExpiredQuarantineCountForTests(ClientMailboxScope scope)
    {
        lock (gate)
        {
            return expiredQuarantine.TryGetValue(Key(scope), out var entries)
                ? entries.Count
                : 0;
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

    private Task<TResult> MutateJournal<TResult>(
        ClientMailboxJournalScope scope,
        Func<ClientMailboxJournalState, TResult> mutation,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        lock (gate)
        {
            var key = Convert.ToHexString(scope.Value);
            if (!journals.TryGetValue(key, out var current))
            {
                current = new ClientMailboxJournalState();
            }

            var candidate = current.Clone();
            var result = mutation(candidate);
            ClientMailboxStateMachine.ValidateJournal(candidate);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            journals[key] = candidate;
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
