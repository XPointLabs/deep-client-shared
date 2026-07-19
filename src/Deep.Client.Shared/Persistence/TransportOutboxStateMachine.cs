namespace Deep.Client.Shared.Persistence;

internal sealed class TransportOutboxStoredAttempt
{
    public required byte[] AttemptId { get; init; }
    public required TransportOutboxAttemptState State { get; set; }
    public required OutboxTransitionSource Source { get; set; }
    public required OutboxTransitionReason Reason { get; set; }
    public required DateTimeOffset OccurredAt { get; set; }
    public required byte[] Evidence { get; set; }

    public TransportOutboxStoredAttempt Clone() => new()
    {
        AttemptId = AttemptId.ToArray(),
        State = State,
        Source = Source,
        Reason = Reason,
        OccurredAt = OccurredAt,
        Evidence = Evidence.ToArray()
    };
}

internal sealed class TransportOutboxStoredItem
{
    public required byte[] AccountScope { get; init; }
    public required byte[] LogicalId { get; init; }
    public required byte[] DedupMaterial { get; init; }
    public required byte[] CiphertextBundle { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required DateTimeOffset NotBefore { get; set; }
    public required TransportOutboxState State { get; set; }
    public required ulong Revision { get; set; }
    public required OutboxTransitionSource Source { get; set; }
    public required OutboxTransitionReason Reason { get; set; }
    public required DateTimeOffset TransitionedAt { get; set; }
    public required List<TransportOutboxStoredAttempt> Attempts { get; init; }
    public byte[]? AcknowledgementEvidence { get; set; }

    public TransportOutboxStoredItem Clone() => new()
    {
        AccountScope = AccountScope.ToArray(),
        LogicalId = LogicalId.ToArray(),
        DedupMaterial = DedupMaterial.ToArray(),
        CiphertextBundle = CiphertextBundle.ToArray(),
        CreatedAt = CreatedAt,
        ExpiresAt = ExpiresAt,
        NotBefore = NotBefore,
        State = State,
        Revision = Revision,
        Source = Source,
        Reason = Reason,
        TransitionedAt = TransitionedAt,
        Attempts = Attempts.Select(static attempt => attempt.Clone()).ToList(),
        AcknowledgementEvidence = AcknowledgementEvidence?.ToArray()
    };
}

internal static class TransportOutboxStateMachine
{
    public static TransportOutboxStoredItem Prepared(TransportOutboxPreparedItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var stored = new TransportOutboxStoredItem
        {
            AccountScope = item.AccountScope.ToArray(),
            LogicalId = item.LogicalId.ToArray(),
            DedupMaterial = item.DedupMaterial.ToArray(),
            CiphertextBundle = item.GetCiphertextBundleCopy(),
            CreatedAt = item.CreatedAt,
            ExpiresAt = item.ExpiresAt,
            NotBefore = item.NotBefore,
            State = TransportOutboxState.Prepared,
            Revision = 1,
            Source = OutboxTransitionSource.LocalQueue,
            Reason = OutboxTransitionReason.Prepared,
            TransitionedAt = item.CreatedAt,
            Attempts = []
        };
        Validate(stored);
        return stored;
    }

    public static bool SamePrepared(
        TransportOutboxStoredItem existing,
        TransportOutboxPreparedItem candidate)
    {
        Validate(existing);
        return existing.State == TransportOutboxState.Prepared
            && existing.Revision == 1
            && existing.Attempts.Count == 0
            && existing.AccountScope.AsSpan().SequenceEqual(candidate.AccountScope.Value)
            && existing.LogicalId.AsSpan().SequenceEqual(candidate.LogicalId.Value)
            && existing.DedupMaterial.AsSpan().SequenceEqual(candidate.DedupMaterial.Value)
            && existing.CiphertextBundle.AsSpan().SequenceEqual(candidate.CiphertextBundle)
            && existing.CreatedAt == candidate.CreatedAt
            && existing.ExpiresAt == candidate.ExpiresAt
            && existing.NotBefore == candidate.NotBefore;
    }

    public static TransportOutboxCommitResult Apply(
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        Validate(item);
        if (!item.LogicalId.AsSpan().SequenceEqual(transition.LogicalId.Value))
        {
            return TransportOutboxCommitResult.Conflict;
        }

        if (transition.ExpectedRevision != item.Revision)
        {
            return IsPreviouslyApplied(item, transition)
                ? TransportOutboxCommitResult.Idempotent
                : TransportOutboxCommitResult.Conflict;
        }

        if (item.State is TransportOutboxState.Delivered or TransportOutboxState.Expired)
        {
            return TransportOutboxCommitResult.Conflict;
        }
        if (item.Revision >= long.MaxValue)
        {
            return TransportOutboxCommitResult.Conflict;
        }

        if (transition.OccurredAt < item.TransitionedAt)
        {
            return TransportOutboxCommitResult.Conflict;
        }

        var result = transition.TargetState switch
        {
            TransportOutboxState.Attempted => ApplyAttempt(item, transition, TransportOutboxAttemptState.Attempted),
            TransportOutboxState.Accepted => ApplyAttempt(item, transition, TransportOutboxAttemptState.Accepted),
            TransportOutboxState.Durable => ApplyAttempt(item, transition, TransportOutboxAttemptState.Durable),
            TransportOutboxState.Delivered => ApplyDelivered(item, transition),
            TransportOutboxState.Expired => ApplyExpired(item, transition),
            _ => TransportOutboxCommitResult.Conflict
        };
        if (result == TransportOutboxCommitResult.Applied)
        {
            checked
            {
                item.Revision++;
            }
            item.Source = transition.Source;
            item.Reason = transition.Reason;
            item.TransitionedAt = transition.OccurredAt;
            Validate(item);
        }

        return result;
    }

    public static TransportOutboxItemSnapshot Snapshot(TransportOutboxStoredItem item)
    {
        Validate(item);
        return new(
            OutboxAccountScope.FromBytes(item.AccountScope),
            OutboxLogicalId.FromBytes(item.LogicalId),
            OutboxDedupMaterial.FromBytes(item.DedupMaterial),
            item.CiphertextBundle,
            item.CreatedAt,
            item.ExpiresAt,
            item.NotBefore,
            item.State,
            item.Revision,
            item.Source,
            item.Reason,
            item.TransitionedAt,
            item.Attempts
                .OrderBy(static attempt => Convert.ToHexString(attempt.AttemptId), StringComparer.Ordinal)
                .Select(static attempt => new TransportOutboxAttemptSnapshot(
                    OutboxAttemptId.FromBytes(attempt.AttemptId),
                    attempt.State,
                    attempt.Source,
                    attempt.Reason,
                    attempt.OccurredAt,
                    attempt.Evidence))
                .ToArray(),
            item.AcknowledgementEvidence);
    }

    public static void Validate(TransportOutboxStoredItem item)
    {
        if (item.AccountScope.Length != TransportOutboxLimits.AccountScopeBytes
            || item.LogicalId.Length != TransportOutboxLimits.LogicalIdBytes
            || item.DedupMaterial.Length != TransportOutboxLimits.DedupMaterialBytes
            || item.CiphertextBundle.Length is <= 0 or > TransportOutboxLimits.MaxCiphertextBundleBytes
            || item.Revision is 0 or > long.MaxValue
            || !Enum.IsDefined(item.State)
            || !Enum.IsDefined(item.Source)
            || !Enum.IsDefined(item.Reason))
        {
            throw new TransportOutboxCorruptException();
        }

        try
        {
            TransportOutboxPreparedItem.ValidateTimeline(item.CreatedAt, item.ExpiresAt, item.NotBefore);
            RecipientDeviceAcknowledgement.ValidateOccurredAt(item.TransitionedAt);
        }
        catch (ArgumentException)
        {
            throw new TransportOutboxCorruptException();
        }

        if (item.TransitionedAt < item.CreatedAt
            || item.Attempts.Count > TransportOutboxLimits.MaxAttemptsPerItem)
        {
            throw new TransportOutboxCorruptException();
        }

        var attemptIds = new HashSet<string>(StringComparer.Ordinal);
        var maximumAttemptState = TransportOutboxAttemptState.Attempted;
        foreach (var attempt in item.Attempts)
        {
            if (attempt.AttemptId.Length != TransportOutboxLimits.AttemptIdBytes
                || !attemptIds.Add(Convert.ToHexString(attempt.AttemptId))
                || !Enum.IsDefined(attempt.State)
                || !Enum.IsDefined(attempt.Source)
                || attempt.Source is not (OutboxTransitionSource.Adapter or OutboxTransitionSource.Recovery)
                || !Enum.IsDefined(attempt.Reason)
                || attempt.OccurredAt < item.CreatedAt
                || attempt.OccurredAt > item.TransitionedAt
                || attempt.Evidence.Length > TransportOutboxLimits.MaxEvidenceBytes
                || attempt.State != TransportOutboxAttemptState.Attempted && attempt.Evidence.Length == 0
                || attempt.State == TransportOutboxAttemptState.Attempted && attempt.Evidence.Length != 0)
            {
                throw new TransportOutboxCorruptException();
            }
            maximumAttemptState = (TransportOutboxAttemptState)Math.Max(
                (int)maximumAttemptState,
                (int)attempt.State);
        }

        if (item.State == TransportOutboxState.Prepared && item.Attempts.Count != 0
            || item.State is TransportOutboxState.Attempted or TransportOutboxState.Accepted or TransportOutboxState.Durable
                && (item.Attempts.Count == 0 || (int)maximumAttemptState < (int)item.State - 1)
            || item.State == TransportOutboxState.Delivered
                && (item.AcknowledgementEvidence is not { Length: > 0 }
                    || item.AcknowledgementEvidence.Length > TransportOutboxLimits.MaxEvidenceBytes
                    || maximumAttemptState != TransportOutboxAttemptState.Durable)
            || item.State != TransportOutboxState.Delivered && item.AcknowledgementEvidence is not null)
        {
            throw new TransportOutboxCorruptException();
        }
    }

    private static TransportOutboxCommitResult ApplyAttempt(
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition,
        TransportOutboxAttemptState target)
    {
        if (transition.AttemptId is null
            || transition.OccurredAt >= item.ExpiresAt
            || transition.RetryNotBefore is { } retry
                && (retry < transition.OccurredAt || retry > item.ExpiresAt))
        {
            return TransportOutboxCommitResult.Conflict;
        }

        var attempt = item.Attempts.SingleOrDefault(
            existing => existing.AttemptId.AsSpan().SequenceEqual(transition.AttemptId.Value));
        if (target == TransportOutboxAttemptState.Attempted)
        {
            if (attempt is not null || item.Attempts.Count >= TransportOutboxLimits.MaxAttemptsPerItem)
            {
                return TransportOutboxCommitResult.Conflict;
            }
            item.Attempts.Add(new TransportOutboxStoredAttempt
            {
                AttemptId = transition.AttemptId.ToArray(),
                State = target,
                Source = transition.Source,
                Reason = transition.Reason,
                OccurredAt = transition.OccurredAt,
                Evidence = []
            });
        }
        else
        {
            if (attempt is null || (int)target != (int)attempt.State + 1)
            {
                return TransportOutboxCommitResult.Conflict;
            }
            attempt.State = target;
            attempt.Source = transition.Source;
            attempt.Reason = transition.Reason;
            attempt.OccurredAt = transition.OccurredAt;
            attempt.Evidence = transition.GetEvidenceCopy();
        }

        item.State = (TransportOutboxState)Math.Max((int)item.State, (int)target + 1);
        if (transition.RetryNotBefore is { } notBefore)
        {
            item.NotBefore = notBefore;
        }
        return TransportOutboxCommitResult.Applied;
    }

    private static TransportOutboxCommitResult ApplyDelivered(
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition)
    {
        var acknowledgement = transition.Acknowledgement;
        if (item.State != TransportOutboxState.Durable
            || acknowledgement is null
            || !acknowledgement.LogicalId.Value.SequenceEqual(item.LogicalId)
            || !acknowledgement.DedupMaterial.Value.SequenceEqual(item.DedupMaterial)
            || acknowledgement.AcknowledgedAt > transition.OccurredAt
            || acknowledgement.AcknowledgedAt < item.CreatedAt
            || acknowledgement.AcknowledgedAt > item.ExpiresAt)
        {
            return TransportOutboxCommitResult.Conflict;
        }

        item.State = TransportOutboxState.Delivered;
        item.AcknowledgementEvidence = acknowledgement.GetEvidenceCopy();
        return TransportOutboxCommitResult.Applied;
    }

    private static TransportOutboxCommitResult ApplyExpired(
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition)
    {
        if (transition.OccurredAt < item.ExpiresAt)
        {
            return TransportOutboxCommitResult.Conflict;
        }
        item.State = TransportOutboxState.Expired;
        return TransportOutboxCommitResult.Applied;
    }

    private static bool IsPreviouslyApplied(
        TransportOutboxStoredItem item,
        TransportOutboxTransition transition)
    {
        if (transition.ExpectedRevision == ulong.MaxValue
            || item.Revision != transition.ExpectedRevision + 1
            || item.State != transition.TargetState
                && transition.TargetState is TransportOutboxState.Delivered or TransportOutboxState.Expired
            || item.Source != transition.Source
            || item.Reason != transition.Reason
            || item.TransitionedAt != transition.OccurredAt)
        {
            return false;
        }

        if (transition.TargetState == TransportOutboxState.Delivered)
        {
            return transition.Acknowledgement is { } acknowledgement
                && item.AcknowledgementEvidence is { } stored
                && stored.AsSpan().SequenceEqual(acknowledgement.Evidence);
        }
        if (transition.TargetState == TransportOutboxState.Expired)
        {
            return true;
        }
        if (transition.AttemptId is null)
        {
            return false;
        }

        var attempt = item.Attempts.SingleOrDefault(
            existing => existing.AttemptId.AsSpan().SequenceEqual(transition.AttemptId.Value));
        return attempt is not null
            && (int)attempt.State == (int)transition.TargetState - 1
            && attempt.Source == transition.Source
            && attempt.Reason == transition.Reason
            && attempt.OccurredAt == transition.OccurredAt
            && attempt.Evidence.AsSpan().SequenceEqual(transition.Evidence);
    }
}
