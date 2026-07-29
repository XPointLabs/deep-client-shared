using Deep.Protocol.DeepExtension.MailboxCapabilities;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemoryClientMailboxStateRepository :
    IClientMailboxStateRepository,
    IClientMailboxCredentialStateRepository
{
    private readonly Dictionary<string, ClientMailboxStoredState> states =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, ClientMailboxJournalState> journals =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>
        expiredQuarantine =
        new(StringComparer.Ordinal);
    private readonly object gate = new();
    private readonly Action<ClientMailboxCommitFaultPoint>? commitFault;
    private MailboxCredentialStoredState? credentials;

    public InMemoryClientMailboxStateRepository()
    {
    }

    internal InMemoryClientMailboxStateRepository(
        Action<ClientMailboxCommitFaultPoint>? commitFault)
    {
        this.commitFault = commitFault;
    }

    public Task ImportCredentialGenerationAsync(
        MailboxCredentialGeneration generation,
        MailboxCredentialImportPolicy policy,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var candidate = MailboxCredentialStateMachine.Import(generation, policy);
        lock (gate)
        {
            if (credentials is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(
                        MailboxCredentialBinaryCodec.Encode(credentials.Generation),
                        MailboxCredentialBinaryCodec.Encode(candidate.Generation)))
                {
                    throw new InvalidOperationException("Mailbox credential generation changed unexpectedly.");
                }
                return Task.CompletedTask;
            }
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            credentials = candidate;
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.CompletedTask;
        }
    }

    public Task<MailboxCredentialGeneration> ReadCredentialGenerationAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            return Task.FromResult(MailboxCredentialStateMachine.Read(RequireCredentials()));
        }
    }

    public Task<ulong> ReadActiveCredentialEpochAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate) return Task.FromResult(RequireCredentials().ActiveEpoch);
    }

    public Task SwitchCredentialEpochAsync(ulong epoch, ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var candidate = RequireCredentials().Clone();
            MailboxCredentialStateMachine.Switch(candidate, epoch, nowUnixSeconds);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            credentials = candidate;
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.CompletedTask;
        }
    }

    public Task<MailboxCredentialGrantLease> AllocateReplayCounterAsync(
        MailboxCredentialGrantKind kind, ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var candidate = RequireCredentials().Clone();
            var lease = MailboxCredentialStateMachine.Allocate(candidate, kind, nowUnixSeconds);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            credentials = candidate;
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(lease);
        }
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
            var candidateStates = CloneStates();
            var candidateQuarantine = CloneExpiredQuarantine();
            var result = SweepInstallation(
                candidateStates,
                candidateQuarantine,
                nowUnixSeconds);
            if (!result.Changed)
            {
                return Task.FromResult(result.Result);
            }

            ValidateInstallationInbox(candidateStates);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            Replace(states, candidateStates);
            Replace(expiredQuarantine, candidateQuarantine);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result.Result);
        }
    }

    public Task<ClientMailboxReceiveCommitResult> CommitRetrievePageAsync(
        ClientMailboxScope scope,
        ClientMailboxTraversal expectedTraversal,
        MailboxRetrievePage page,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(expectedTraversal);
        ArgumentNullException.ThrowIfNull(page);
        lock (gate)
        {
            var candidateStates = CloneStates();
            var candidateQuarantine = CloneExpiredQuarantine();
            if (page.Items.Count > 0)
            {
                _ = SweepInstallation(
                    candidateStates,
                    candidateQuarantine,
                    page.Items.Max(static item =>
                        item.Envelope.CreatedAtUnixSeconds));
            }

            var key = Key(scope);
            if (!candidateStates.TryGetValue(key, out var candidate))
            {
                candidate = new ClientMailboxStoredState();
                candidateStates.Add(key, candidate);
            }

            var result = ClientMailboxStateMachine.CommitPage(
                candidate,
                expectedTraversal,
                page);
            EnforceInstallationInboxCapacity(
                candidateStates, candidateQuarantine);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            Replace(states, candidateStates);
            Replace(expiredQuarantine, candidateQuarantine);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result);
        }
    }

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
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(acknowledgements);
        lock (gate)
        {
            var candidateStates = CloneStates();
            var candidateQuarantine = CloneExpiredQuarantine();
            var key = Key(scope);
            var existed = candidateStates.TryGetValue(key, out var candidate);
            candidate ??= new ClientMailboxStoredState();
            var result = ClientMailboxStateMachine.CommitAck(
                candidate, acknowledgements);
            if (existed)
            {
                candidateStates[key] = candidate;
            }

            RemoveRetiredScopes(candidateStates, candidateQuarantine);
            ValidateInstallationInbox(candidateStates);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            Replace(states, candidateStates);
            Replace(expiredQuarantine, candidateQuarantine);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result);
        }
    }

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
        RecordCoordinatorGlobal(
            scope,
            membershipCommitment,
            epoch,
            coordinatorId,
            coordinatorSequence,
            statementDigest,
            expiresAtUnixSeconds,
            nowUnixSeconds,
            cancellationToken);

    internal int InstallationTraversalCountForTests()
    {
        lock (gate)
        {
            return states.Count;
        }
    }

    internal void SeedCurrentStatesForTests(
        IReadOnlyList<(ClientMailboxScope Scope, ClientMailboxStoredState State)> snapshots)
    {
        lock (gate)
        {
            var candidate = CloneStates();
            foreach (var snapshot in snapshots)
            {
                candidate[Key(snapshot.Scope)] = snapshot.State.Clone();
            }

            ValidateInstallationInbox(candidate);
            Replace(states, candidate);
        }
    }

    internal long InstallationTraversalTokenBytesForTests()
    {
        lock (gate)
        {
            return states.Values.Sum(static state =>
                (long)state.ContinuationToken.Length);
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
            var key = Convert.ToHexString(scope.Value);
            var existingCount = journals
                .Where(pair => !StringComparer.Ordinal.Equals(pair.Key, key))
                .Sum(static pair => pair.Value.CoordinatorStatements.Count);
            if (existingCount + candidate.CoordinatorStatements.Count >
                ClientMailboxStateLimits.MaximumCoordinatorStatements)
            {
                throw new InvalidDataException(
                    "Installation-global coordinator journal capacity is exceeded.");
            }

            journals[key] = candidate;
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

    internal int InstallationInboxCountForTests()
    {
        lock (gate)
        {
            return states.Values.Sum(static state => state.Entries.Count);
        }
    }

    internal int InboxEntryCountForTests(ClientMailboxScope scope)
    {
        lock (gate)
        {
            return states.TryGetValue(Key(scope), out var state)
                ? state.Entries.Count
                : 0;
        }
    }

    internal int InstallationExpiredQuarantineCountForTests()
    {
        lock (gate)
        {
            return expiredQuarantine.Values.Sum(static entries => entries.Count);
        }
    }

    internal int CoordinatorJournalCountForTests()
    {
        lock (gate)
        {
            return journals.Values.Sum(static journal =>
                journal.CoordinatorStatements.Count);
        }
    }

    internal void SeedCoordinatorJournalForTests(
        int count,
        ulong expiresAtUnixSeconds)
    {
        if (count < 0 || expiresAtUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        lock (gate)
        {
            journals.Clear();
            for (var index = 0; index < count; index++)
            {
                var key = $"test-scope-{index % 17:D2}";
                if (!journals.TryGetValue(key, out var journal))
                {
                    journal = new ClientMailboxJournalState();
                    journals.Add(key, journal);
                }

                journal.CoordinatorStatements.Add(
                    new ClientMailboxCoordinatorStatement
                    {
                        MembershipCommitment = SHA256.HashData([
                            .. "test-membership"u8,
                            .. UInt64Bytes(checked((ulong)index + 1))
                        ]),
                        Epoch = 7,
                        CoordinatorId = SHA256.HashData([
                            .. "test-coordinator"u8,
                            .. UInt64Bytes(checked((ulong)index + 1))
                        ]),
                        CoordinatorSequence = checked((ulong)index + 1),
                        StatementDigest = SHA256.HashData([
                            .. "test-statement"u8,
                            .. UInt64Bytes(checked((ulong)index + 1))
                        ]),
                        ExpiresAtUnixSeconds = expiresAtUnixSeconds
                    });
            }
        }
    }

    internal InMemoryClientMailboxStateRepository RestartInstallationForTests()
    {
        lock (gate)
        {
            var restarted = new InMemoryClientMailboxStateRepository();
            Replace(restarted.states, CloneStates());
            Replace(restarted.expiredQuarantine, CloneExpiredQuarantine());
            Replace(
                restarted.journals,
                journals.ToDictionary(
                    static pair => pair.Key,
                    static pair => pair.Value.Clone(),
                    StringComparer.Ordinal));
            restarted.credentials = credentials?.Clone();
            return restarted;
        }
    }

    private MailboxCredentialStoredState RequireCredentials() => credentials?.Clone()
        ?? throw new InvalidOperationException("Mailbox credentials are not installed.");

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

    private Task<ClientMailboxCoordinatorRecordResult> RecordCoordinatorGlobal(
        ClientMailboxJournalScope scope,
        ReadOnlyMemory<byte> membershipCommitment,
        ulong epoch,
        ReadOnlyMemory<byte> coordinatorId,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> statementDigest,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(scope);
        var probe = new ClientMailboxJournalState();
        _ = ClientMailboxStateMachine.RecordCoordinator(
            probe,
            membershipCommitment.Span,
            epoch,
            coordinatorId.Span,
            coordinatorSequence,
            statementDigest.Span,
            expiresAtUnixSeconds,
            nowUnixSeconds);
        lock (gate)
        {
            var key = Convert.ToHexString(scope.Value);
            var candidates = journals.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value.Clone(),
                StringComparer.Ordinal);
            foreach (var journal in candidates.Values)
            {
                journal.CoordinatorStatements.RemoveAll(statement =>
                    statement.ExpiresAtUnixSeconds <= nowUnixSeconds);
            }
            foreach (var retired in candidates
                         .Where(static pair =>
                             pair.Value.CoordinatorStatements.Count == 0)
                         .Select(static pair => pair.Key)
                         .ToArray())
            {
                candidates.Remove(retired);
            }

            var matches = candidates.Values
                .SelectMany(static journal => journal.CoordinatorStatements)
                .Where(statement =>
                    statement.Epoch == epoch &&
                    statement.CoordinatorSequence == coordinatorSequence &&
                    Fixed(statement.MembershipCommitment, membershipCommitment.Span) &&
                    Fixed(statement.CoordinatorId, coordinatorId.Span))
                .ToArray();
            ClientMailboxCoordinatorRecordResult result;
            if (matches.Length > 0)
            {
                result = matches.All(statement =>
                        Fixed(statement.StatementDigest, statementDigest.Span))
                    ? ClientMailboxCoordinatorRecordResult.Idempotent
                    : ClientMailboxCoordinatorRecordResult.Equivocation;
            }
            else if (candidates.Values.Sum(static journal =>
                         journal.CoordinatorStatements.Count) >=
                     ClientMailboxStateLimits.MaximumCoordinatorStatements)
            {
                result = ClientMailboxCoordinatorRecordResult.CapacityExceeded;
            }
            else
            {
                if (!candidates.TryGetValue(key, out var candidate))
                {
                    candidate = new ClientMailboxJournalState();
                    candidates.Add(key, candidate);
                }

                candidate.CoordinatorStatements.Add(
                    new ClientMailboxCoordinatorStatement
                    {
                        MembershipCommitment = membershipCommitment.ToArray(),
                        Epoch = epoch,
                        CoordinatorId = coordinatorId.ToArray(),
                        CoordinatorSequence = coordinatorSequence,
                        StatementDigest = statementDigest.ToArray(),
                        ExpiresAtUnixSeconds = expiresAtUnixSeconds
                    });
                result = ClientMailboxCoordinatorRecordResult.Applied;
            }

            foreach (var candidate in candidates.Values)
            {
                ClientMailboxStateMachine.ValidateJournal(candidate);
            }

            commitFault?.Invoke(ClientMailboxCommitFaultPoint.BeforeCommit);
            Replace(journals, candidates);
            commitFault?.Invoke(ClientMailboxCommitFaultPoint.AfterCommit);
            return Task.FromResult(result);
        }
    }

    private Dictionary<string, ClientMailboxStoredState> CloneStates() =>
        states.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value.Clone(),
            StringComparer.Ordinal);

    private Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>
        CloneExpiredQuarantine() =>
        expiredQuarantine.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value
                .Select(static entry => entry.Clone())
                .ToList(),
            StringComparer.Ordinal);

    private static (
        ClientMailboxExpiryReconciliationResult Result,
        bool Changed) SweepInstallation(
            Dictionary<string, ClientMailboxStoredState> candidateStates,
            Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>
                candidateQuarantine,
            ulong nowUnixSeconds)
    {
        if (nowUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nowUnixSeconds));
        }

        var quarantined = 0;
        var acknowledged = 0;
        var changed = false;
        foreach (var pair in candidateStates)
        {
            var expired = new List<ClientMailboxStoredEntry>();
            var result = ClientMailboxStateMachine.ReconcileExpired(
                pair.Value,
                nowUnixSeconds,
                expired);
            quarantined += result.QuarantinedUnacknowledged;
            acknowledged += result.RemovedAcknowledged;
            if (expired.Count > 0)
            {
                if (!candidateQuarantine.TryGetValue(pair.Key, out var quarantine))
                {
                    quarantine = [];
                    candidateQuarantine.Add(pair.Key, quarantine);
                }

                quarantine.AddRange(expired.Select(entry =>
                    new ClientMailboxExpiredQuarantineEntry
                    {
                        Entry = entry,
                        QuarantinedAtUnixSeconds = nowUnixSeconds
                    }));
                changed = true;
            }
            else if (result.RemovedAcknowledged > 0)
            {
                changed = true;
            }
        }

        var cutoff = nowUnixSeconds >
            ClientMailboxStateLimits.ExpiredQuarantineRetentionSeconds
            ? nowUnixSeconds -
              ClientMailboxStateLimits.ExpiredQuarantineRetentionSeconds
            : 0;
        foreach (var quarantine in candidateQuarantine.Values)
        {
            changed |= quarantine.RemoveAll(entry =>
                entry.QuarantinedAtUnixSeconds <= cutoff) > 0;
        }

        EnforceExpiredQuarantineCapacity(candidateQuarantine);
        RemoveRetiredScopes(candidateStates, candidateQuarantine);
        return (new(quarantined, acknowledged), changed);
    }

    private static void EnforceInstallationInboxCapacity(
        Dictionary<string, ClientMailboxStoredState> candidateStates,
        Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>
            candidateQuarantine)
    {
        while (InstallationInboxCount(candidateStates) >
                   ClientMailboxStateLimits.MaximumInstallationInboxEntries ||
               InstallationInboxBytes(candidateStates) >
                   ClientMailboxStateLimits.MaximumInstallationInboxBytes)
        {
            var oldest = candidateStates
                .SelectMany(pair => pair.Value.Entries
                    .Where(static entry => entry.Acknowledged)
                    .Select(entry => new
                    {
                        Scope = pair.Key,
                        State = pair.Value,
                        Entry = entry
                    }))
                .OrderBy(static item => item.State.AfterCursor == 0 ? 0 : 1)
                .ThenBy(static item => item.Entry.ExpiresAtUnixSeconds)
                .ThenBy(static item => item.Entry.Cursor)
                .ThenBy(static item => item.Scope, StringComparer.Ordinal)
                .FirstOrDefault();
            if (oldest is null)
            {
                throw new InvalidDataException(
                    "Installation-global unacknowledged mailbox inbox exceeded its persistent bound.");
            }

            oldest.State.Entries.Remove(oldest.Entry);
        }

        RemoveRetiredScopes(candidateStates, candidateQuarantine);
        ValidateInstallationInbox(candidateStates);
    }

    private static void EnforceExpiredQuarantineCapacity(
        Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>
            candidateQuarantine)
    {
        foreach (var quarantine in candidateQuarantine.Values)
        {
            while (quarantine.Count >
                       ClientMailboxStateLimits.MaximumExpiredQuarantineEntries ||
                   quarantine.Sum(static entry =>
                       (long)entry.Entry.CanonicalEnvelope.Length) >
                       ClientMailboxStateLimits.MaximumExpiredQuarantineBytes)
            {
                quarantine.Remove(quarantine
                    .OrderBy(static entry => entry.QuarantinedAtUnixSeconds)
                    .ThenBy(static entry => entry.Entry.ExpiresAtUnixSeconds)
                    .ThenBy(static entry => entry.Entry.Cursor)
                    .First());
            }
        }

        while (candidateQuarantine.Values.Sum(static entries => entries.Count) >
                   ClientMailboxStateLimits
                       .MaximumInstallationExpiredQuarantineEntries ||
               candidateQuarantine.Values
                   .SelectMany(static entries => entries)
                   .Sum(static entry =>
                       (long)entry.Entry.CanonicalEnvelope.Length) >
                   ClientMailboxStateLimits
                       .MaximumInstallationExpiredQuarantineBytes)
        {
            var oldest = candidateQuarantine
                .SelectMany(pair => pair.Value.Select(entry => new
                {
                    Scope = pair.Key,
                    Entries = pair.Value,
                    Entry = entry
                }))
                .OrderBy(static item => item.Entry.QuarantinedAtUnixSeconds)
                .ThenBy(static item => item.Entry.Entry.ExpiresAtUnixSeconds)
                .ThenBy(static item => item.Entry.Entry.Cursor)
                .ThenBy(static item => item.Scope, StringComparer.Ordinal)
                .First();
            oldest.Entries.Remove(oldest.Entry);
        }
    }

    private static void ValidateInstallationInbox(
        IReadOnlyDictionary<string, ClientMailboxStoredState> candidateStates)
    {
        foreach (var state in candidateStates.Values)
        {
            ClientMailboxStateMachine.Validate(state);
        }

        if (InstallationInboxCount(candidateStates) >
                ClientMailboxStateLimits.MaximumInstallationInboxEntries ||
            InstallationInboxBytes(candidateStates) >
                ClientMailboxStateLimits.MaximumInstallationInboxBytes ||
            candidateStates.Count >
                ClientMailboxStateLimits.MaximumInstallationScopes ||
            candidateStates.Values.Sum(static state =>
                (long)state.ContinuationToken.Length) >
                ClientMailboxStateLimits
                    .MaximumInstallationTraversalTokenBytes)
        {
            throw new InvalidDataException(
                "Installation-global mailbox inbox bounds are invalid.");
        }
    }

    private static int InstallationInboxCount(
        IReadOnlyDictionary<string, ClientMailboxStoredState> candidateStates) =>
        candidateStates.Values.Sum(static state => state.Entries.Count);

    private static long InstallationInboxBytes(
        IReadOnlyDictionary<string, ClientMailboxStoredState> candidateStates) =>
        candidateStates.Values
            .SelectMany(static state => state.Entries)
            .Sum(static entry => (long)entry.CanonicalEnvelope.Length);

    private static void RemoveRetiredScopes(
        Dictionary<string, ClientMailboxStoredState> candidateStates,
        Dictionary<string, List<ClientMailboxExpiredQuarantineEntry>>?
            candidateQuarantine)
    {
        foreach (var key in candidateStates
                     .Where(static pair =>
                         pair.Value.AfterCursor == 0 &&
                         pair.Value.ContinuationToken.Length == 0 &&
                         pair.Value.Entries.Count == 0)
                     .Select(static pair => pair.Key)
                     .ToArray())
        {
            if (candidateQuarantine is null ||
                !candidateQuarantine.TryGetValue(key, out var evidence) ||
                evidence.Count == 0)
            {
                candidateStates.Remove(key);
            }
        }

        if (candidateQuarantine is null)
        {
            return;
        }

        foreach (var key in candidateQuarantine
                     .Where(static pair => pair.Value.Count == 0)
                     .Select(static pair => pair.Key)
                     .ToArray())
        {
            candidateQuarantine.Remove(key);
        }
    }

    private static void Replace<TValue>(
        Dictionary<string, TValue> target,
        IReadOnlyDictionary<string, TValue> source)
    {
        target.Clear();
        foreach (var pair in source)
        {
            target.Add(pair.Key, pair.Value);
        }
    }

    private static bool Fixed(
        ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] UInt64Bytes(ulong value)
    {
        var encoded = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            encoded,
            value);
        return encoded;
    }

    private ClientMailboxStoredState Get(ClientMailboxScope scope)
    {
        var key = Key(scope);
        if (!states.TryGetValue(key, out var state))
        {
            state = new ClientMailboxStoredState();
        }

        return state;
    }

    private static string Key(ClientMailboxScope scope) =>
        Convert.ToHexString(scope.Value);

}
