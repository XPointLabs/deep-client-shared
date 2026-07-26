namespace Deep.Client.Shared.Persistence;

public sealed partial class InMemorySessionStore
{
    private readonly Dictionary<string, TransportOutboxStoredItem> transportOutbox =
        new(StringComparer.Ordinal);
    private readonly Action<TransportOutboxCommitFaultPoint>? transportOutboxFaultInjector;

    internal InMemorySessionStore(
        string? statePath,
        Action<TransportOutboxCommitFaultPoint> outboxFaultInjector)
        : this(statePath, faultInjector: null)
    {
        transportOutboxFaultInjector =
            outboxFaultInjector ?? throw new ArgumentNullException(nameof(outboxFaultInjector));
    }

    public Task<TransportOutboxCommitResult> PrepareTransportOutboxAsync(
        TransportOutboxPreparedItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        cancellationToken.ThrowIfCancellationRequested();
        var candidate = TransportOutboxStateMachine.Prepared(item);
        var key = OutboxKey(candidate.AccountScope, candidate.LogicalId);
        lock (durableStateGate)
        {
            if (transportOutbox.TryGetValue(key, out var existing))
            {
                try
                {
                    return Task.FromResult(
                        TransportOutboxStateMachine.SamePrepared(existing, item)
                            ? TransportOutboxCommitResult.Idempotent
                            : TransportOutboxCommitResult.Conflict);
                }
                catch (TransportOutboxCorruptException)
                {
                    return Task.FromResult(TransportOutboxCommitResult.Corrupt);
                }
            }

            var admission = ValidateInMemoryOutboxAdmission(candidate);
            if (admission is not null)
            {
                return Task.FromResult(admission.Value);
            }

            transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transportOutbox[key] = candidate;
            try
            {
                PersistState();
            }
            catch
            {
                transportOutbox.Remove(key);
                throw;
            }

            ThrowIfOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(TransportOutboxCommitResult.Applied);
        }
    }

    public Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(
        OutboxAccountScope accountScope,
        OutboxLogicalId logicalId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(logicalId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            if (!transportOutbox.TryGetValue(
                    OutboxKey(accountScope.Value, logicalId.Value),
                    out var item))
            {
                return Task.FromResult(
                    new TransportOutboxReadSnapshot(TransportOutboxReadResult.Missing, null));
            }

            try
            {
                return Task.FromResult(
                    new TransportOutboxReadSnapshot(
                        TransportOutboxReadResult.Found,
                        TransportOutboxStateMachine.Snapshot(item)));
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(
                    new TransportOutboxReadSnapshot(TransportOutboxReadResult.Corrupt, null));
            }
        }
    }

    public Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
        OutboxAccountScope accountScope,
        TransportOutboxTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(transition);
        if (!accountScope.Value.SequenceEqual(transition.AccountScope.Value))
        {
            return Task.FromResult(TransportOutboxCommitResult.Conflict);
        }
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var key = OutboxKey(accountScope.Value, transition.LogicalId.Value);
            if (!transportOutbox.TryGetValue(key, out var existing))
            {
                return Task.FromResult(TransportOutboxCommitResult.Conflict);
            }

            TransportOutboxStoredItem candidate;
            TransportOutboxCommitResult result;
            try
            {
                candidate = existing.Clone();
                result = TransportOutboxStateMachine.Apply(candidate, transition);
            }
            catch (TransportOutboxCorruptException)
            {
                return Task.FromResult(TransportOutboxCommitResult.Corrupt);
            }
            if (result != TransportOutboxCommitResult.Applied)
            {
                return Task.FromResult(result);
            }

            transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transportOutbox[key] = candidate;
            try
            {
                PersistState();
            }
            catch
            {
                transportOutbox[key] = existing;
                throw;
            }

            ThrowIfOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(TransportOutboxCommitResult.Applied);
        }
    }

    public Task<IReadOnlyList<TransportOutboxItemSnapshot>> ListReadyTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateOutboxList(accountScope, now, limit);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            try
            {
                IReadOnlyList<TransportOutboxItemSnapshot> result = transportOutbox.Values
                    .Where(item =>
                        item.AccountScope.AsSpan().SequenceEqual(accountScope.Value)
                        && item.State is TransportOutboxState.Prepared
                            or TransportOutboxState.Accepted
                        && item.NotBefore <= now
                        && item.ExpiresAt > now
                        && item.Attempts.Count < TransportOutboxLimits.MaxAttemptsPerItem)
                    .OrderBy(static item => item.NotBefore)
                    .ThenBy(static item => item.CreatedAt)
                    .ThenBy(static item => Convert.ToHexString(item.LogicalId), StringComparer.Ordinal)
                    .Take(limit)
                    .Select(TransportOutboxStateMachine.Snapshot)
                    .ToArray();
                return Task.FromResult(result);
            }
            catch (TransportOutboxCorruptException)
            {
                throw new TransportOutboxCorruptException();
            }
        }
    }

    public Task<int> ExpireDueTransportOutboxAsync(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateOutboxList(accountScope, now, limit);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var due = transportOutbox
                .Where(item =>
                    item.Value.AccountScope.AsSpan().SequenceEqual(accountScope.Value)
                    && item.Value.State is not (TransportOutboxState.Delivered or TransportOutboxState.Expired)
                    && item.Value.ExpiresAt <= now)
                .OrderBy(static item => item.Value.ExpiresAt)
                .ThenBy(static item => item.Key, StringComparer.Ordinal)
                .Take(limit)
                .ToArray();
            if (due.Length == 0)
            {
                return Task.FromResult(0);
            }

            var replacements = new Dictionary<string, TransportOutboxStoredItem>(StringComparer.Ordinal);
            try
            {
                foreach (var (key, existing) in due)
                {
                    var candidate = existing.Clone();
                    var result = TransportOutboxStateMachine.Apply(
                        candidate,
                        TransportOutboxTransition.Expired(
                            OutboxAccountScope.FromBytes(existing.AccountScope),
                            OutboxLogicalId.FromBytes(existing.LogicalId),
                            existing.Revision,
                            now));
                    if (result != TransportOutboxCommitResult.Applied)
                    {
                        throw new TransportOutboxCorruptException();
                    }
                    replacements[key] = candidate;
                }
            }
            catch (TransportOutboxCorruptException)
            {
                throw new TransportOutboxCorruptException();
            }

            transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var replacement in replacements)
            {
                transportOutbox[replacement.Key] = replacement.Value;
            }
            try
            {
                PersistState();
            }
            catch
            {
                foreach (var (key, existing) in due)
                {
                    transportOutbox[key] = existing;
                }
                throw;
            }

            ThrowIfOutboxOutcomeUnknown(cancellationToken);
            return Task.FromResult(replacements.Count);
        }
    }

    public Task PurgeTransportOutboxScopeAsync(
        OutboxAccountScope accountScope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var removed = transportOutbox
                .Where(item => item.Value.AccountScope.AsSpan().SequenceEqual(accountScope.Value))
                .ToArray();
            foreach (var item in removed)
            {
                transportOutbox.Remove(item.Key);
            }
            try
            {
                PersistState();
            }
            catch
            {
                foreach (var item in removed)
                {
                    transportOutbox[item.Key] = item.Value;
                }
                throw;
            }
        }
        return Task.CompletedTask;
    }

    private void ThrowIfOutboxOutcomeUnknown(CancellationToken cancellationToken)
    {
        try
        {
            transportOutboxFaultInjector?.Invoke(TransportOutboxCommitFaultPoint.AfterDurableCommit);
        }
        catch (Exception exception) when (exception is not TransportOutboxCommitOutcomeUnknownException)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new TransportOutboxCommitOutcomeUnknownException();
        }
    }

    private IReadOnlyList<TransportOutboxPersistenceSnapshot> TransportOutboxSnapshots() =>
        transportOutbox.Values
            .OrderBy(static item => Convert.ToHexString(item.LogicalId), StringComparer.Ordinal)
            .Select(static item => new TransportOutboxPersistenceSnapshot(
                item.AccountScope,
                item.LogicalId,
                item.DedupMaterial,
                item.CiphertextBundle,
                item.CreatedAt,
                item.ExpiresAt,
                item.NotBefore,
                item.State,
                item.Revision,
                item.Source,
                item.Reason,
                item.TransitionedAt,
                item.Attempts.Select(static attempt => new TransportOutboxAttemptPersistenceSnapshot(
                    attempt.AttemptId,
                    attempt.State,
                    attempt.Source,
                    attempt.Reason,
                    attempt.OccurredAt,
                    attempt.Evidence)).ToArray(),
                item.LastTransitionState,
                item.LastTransitionAttemptId,
                item.LastTransitionRetryNotBefore,
                item.AcknowledgementEvidence,
                item.AcknowledgedAt))
            .ToArray();

    private void RestoreTransportOutboxSnapshots(
        IReadOnlyList<TransportOutboxPersistenceSnapshot> snapshots)
    {
        var restored = new Dictionary<string, TransportOutboxStoredItem>(StringComparer.Ordinal);
        foreach (var snapshot in snapshots)
        {
            if (snapshot.Attempts is null
                || snapshot.Attempts.Count > TransportOutboxLimits.MaxAttemptsPerItem)
            {
                throw new TransportOutboxCorruptException();
            }
            var item = new TransportOutboxStoredItem
            {
                AccountScope = snapshot.AccountScope?.ToArray() ?? [],
                LogicalId = snapshot.LogicalId?.ToArray() ?? [],
                DedupMaterial = snapshot.DedupMaterial?.ToArray() ?? [],
                CiphertextBundle = snapshot.CiphertextBundle?.ToArray() ?? [],
                CreatedAt = snapshot.CreatedAt,
                ExpiresAt = snapshot.ExpiresAt,
                NotBefore = snapshot.NotBefore,
                State = snapshot.State,
                Revision = snapshot.Revision,
                Source = snapshot.Source,
                Reason = snapshot.Reason,
                TransitionedAt = snapshot.TransitionedAt,
                Attempts = snapshot.Attempts.Select(static attempt => new TransportOutboxStoredAttempt
                {
                    AttemptId = attempt.AttemptId?.ToArray() ?? [],
                    State = attempt.State,
                    Source = attempt.Source,
                    Reason = attempt.Reason,
                    OccurredAt = attempt.OccurredAt,
                    Evidence = attempt.Evidence?.ToArray() ?? []
                }).ToList(),
                LastTransitionState = snapshot.LastTransitionState,
                LastTransitionAttemptId = snapshot.LastTransitionAttemptId?.ToArray(),
                LastTransitionRetryNotBefore = snapshot.LastTransitionRetryNotBefore,
                AcknowledgementEvidence = snapshot.AcknowledgementEvidence?.ToArray(),
                AcknowledgedAt = snapshot.AcknowledgedAt
            };
            TransportOutboxStateMachine.Validate(item);
            if (!restored.TryAdd(OutboxKey(item.AccountScope, item.LogicalId), item))
            {
                throw new TransportOutboxCorruptException();
            }
        }
        foreach (var item in restored)
        {
            transportOutbox.Add(item.Key, item.Value);
        }
    }

    private static void ValidateOutboxList(
        OutboxAccountScope accountScope,
        DateTimeOffset now,
        int limit)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        RecipientDeviceAcknowledgement.ValidateOccurredAt(now);
        if (limit is <= 0 or > TransportOutboxLimits.MaxListCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static string OutboxKey(
        ReadOnlySpan<byte> accountScope,
        ReadOnlySpan<byte> logicalId) =>
        $"{Convert.ToHexString(accountScope)}:{Convert.ToHexString(logicalId)}";

    private TransportOutboxCommitResult? ValidateInMemoryOutboxAdmission(
        TransportOutboxStoredItem candidate)
    {
        var count = 0;
        long logicalBytes = 0;
        foreach (var item in transportOutbox.Values)
        {
            if (!item.AccountScope.AsSpan().SequenceEqual(candidate.AccountScope))
            {
                continue;
            }

            try
            {
                TransportOutboxStateMachine.Validate(item);
            }
            catch (TransportOutboxCorruptException)
            {
                return TransportOutboxCommitResult.Corrupt;
            }

            count++;
            if (count >= TransportOutboxLimits.MaxItemsPerScope)
            {
                return TransportOutboxCommitResult.CapacityExceeded;
            }
            logicalBytes += item.CiphertextBundle.Length;
            if (logicalBytes >
                TransportOutboxLimits.MaxLogicalCiphertextBytesPerScope -
                candidate.CiphertextBundle.Length)
            {
                return TransportOutboxCommitResult.CapacityExceeded;
            }
        }

        return candidate.CiphertextBundle.Length >
            TransportOutboxLimits.MaxLogicalCiphertextBytesPerScope - logicalBytes
                ? TransportOutboxCommitResult.CapacityExceeded
                : null;
    }

    private sealed record TransportOutboxPersistenceSnapshot(
        byte[] AccountScope,
        byte[] LogicalId,
        byte[] DedupMaterial,
        byte[] CiphertextBundle,
        DateTimeOffset CreatedAt,
        DateTimeOffset ExpiresAt,
        DateTimeOffset NotBefore,
        TransportOutboxState State,
        ulong Revision,
        OutboxTransitionSource Source,
        OutboxTransitionReason Reason,
        DateTimeOffset TransitionedAt,
        IReadOnlyList<TransportOutboxAttemptPersistenceSnapshot> Attempts,
        TransportOutboxState LastTransitionState,
        byte[]? LastTransitionAttemptId,
        DateTimeOffset? LastTransitionRetryNotBefore,
        byte[]? AcknowledgementEvidence,
        DateTimeOffset? AcknowledgedAt);

    private sealed record TransportOutboxAttemptPersistenceSnapshot(
        byte[] AttemptId,
        TransportOutboxAttemptState State,
        OutboxTransitionSource Source,
        OutboxTransitionReason Reason,
        DateTimeOffset OccurredAt,
        byte[] Evidence);
}
