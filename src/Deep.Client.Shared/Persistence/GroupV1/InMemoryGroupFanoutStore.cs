using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public sealed class InMemoryGroupFanoutStore : IGroupFanoutStore, IDisposable
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, BatchEntry> batches = new(StringComparer.Ordinal);
    private int disposed;

    public InMemoryGroupFanoutStore(GroupStoreScope scope) =>
        Scope = new GroupStoreScope(
            (scope ?? throw new ArgumentNullException(nameof(scope))).AccountId,
            scope.AccountGeneration,
            scope.StoreGeneration);

    public GroupStoreScope Scope { get; }

    public async ValueTask<GroupFanoutStageResult> StageAsync(
        GroupFanoutBatchPlan plan,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(plan);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var key = Key(plan.BatchId);
            if (batches.TryGetValue(key, out var existing))
            {
                if (!CryptographicOperations.FixedTimeEquals(existing.Fingerprint, plan.Fingerprint))
                    existing.ConflictLatched = true;
                return new(
                    existing.ConflictLatched
                        ? GroupFanoutStageDisposition.ConflictLatched
                        : GroupFanoutStageDisposition.Idempotent,
                    Snapshot(existing));
            }

            var created = new BatchEntry(plan);
            batches.Add(key, created);
            return new(GroupFanoutStageDisposition.Staged, Snapshot(created));
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutBatchSnapshot?> ReadAsync(
        GroupFanoutBatchId32 batchId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return batches.TryGetValue(Key(batchId), out var batch) ? Snapshot(batch) : null;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<IReadOnlyList<GroupFanoutDispatchLease>> ClaimReadyAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        int maximumTargets,
        CancellationToken cancellationToken = default)
    {
        GroupFanoutContractValidation.ValidateClaim(batchId, leaseOwner, now, leaseDuration, maximumTargets);
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        var until = GroupFanoutBatchPlan.CanonicalTime(now + leaseDuration);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!batches.TryGetValue(Key(batchId), out var batch) || batch.ConflictLatched)
                return [];

            Recover(batch, now);
            var claimed = batch.Targets.Values
                .Where(target => target.LeaseOwner is not null
                    && target.LeaseOwner.AsSpan().SequenceEqual(leaseOwner.Span)
                    && target.State is GroupFanoutTargetState.Ready or GroupFanoutTargetState.OutcomeUnknown)
                .OrderBy(static target => Convert.ToHexString(target.TargetId), StringComparer.Ordinal)
                .Take(maximumTargets)
                .Select(target => Lease(batch, target))
                .ToList();
            var active = batch.Targets.Values.Count(target => target.LeaseOwner is not null);
            var available = Math.Min(maximumTargets - claimed.Count,
                GroupFanoutLimits.MaximumConcurrentLeases - active);
            if (available <= 0) return claimed;

            foreach (var target in batch.Targets.Values
                         .Where(static target => target.LeaseOwner is null
                             && target.State is GroupFanoutTargetState.Ready or GroupFanoutTargetState.OutcomeUnknown)
                         .OrderBy(static target => Convert.ToHexString(target.TargetId), StringComparer.Ordinal)
                         .Take(available))
            {
                target.LeaseOwner = leaseOwner.ToArray();
                target.LeaseGeneration = checked(target.LeaseGeneration + 1);
                target.LeaseExpiresAt = until;
                claimed.Add(Lease(batch, target));
            }

            return claimed;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutNetworkWorkResult> BeginNetworkWorkAsync(
        GroupFanoutDispatchLease lease,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ValidateScope(lease.Scope, nameof(lease));
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!TryTarget(lease, out var batch, out var target)) return new(GroupFanoutMutationDisposition.NotFound, null);
            if (batch.ConflictLatched) return new(GroupFanoutMutationDisposition.ConflictLatched, null);
            Recover(batch, now);
            var attempt = CurrentAttempt(target);
            if (target.State == GroupFanoutTargetState.RevokedBeforeSend)
                return new(GroupFanoutMutationDisposition.RevokedBeforeSend, null);
            if (target.State is GroupFanoutTargetState.Accepted or GroupFanoutTargetState.DefiniteRejected)
                return new(GroupFanoutMutationDisposition.AlreadyTerminal, null);
            if (target.State == GroupFanoutTargetState.NetworkWorkReleased
                && attempt.ReleasedLeaseGeneration == lease.LeaseGeneration
                && LeaseMatches(target, lease))
                return new(GroupFanoutMutationDisposition.Idempotent, Work(lease, target));
            if (!LeaseMatches(target, lease)) return new(GroupFanoutMutationDisposition.LeaseLost, null);

            target.State = GroupFanoutTargetState.NetworkWorkReleased;
            attempt.State = GroupFanoutTargetState.NetworkWorkReleased;
            attempt.ReleasedLeaseGeneration = lease.LeaseGeneration;
            return new(GroupFanoutMutationDisposition.Applied, Work(lease, target));
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutMutationDisposition> RecordOutcomeAsync(
        GroupFanoutNetworkWork work,
        GroupFanoutAttemptOutcome outcome,
        GroupFanoutDefiniteRejectRule rejectRule = GroupFanoutDefiniteRejectRule.Terminal,
        GroupFanoutNetworkOperationId32? nextNetworkOperationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(work);
        var lease = work.Lease;
        ValidateScope(lease.Scope, nameof(work));
        GroupFanoutContractValidation.ValidateOutcome(outcome, rejectRule, nextNetworkOperationId, work);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!TryTarget(lease, out var batch, out var target)) return GroupFanoutMutationDisposition.NotFound;
            if (batch.ConflictLatched) return GroupFanoutMutationDisposition.ConflictLatched;
            var attempt = target.Attempts.SingleOrDefault(value => value.Number == lease.AttemptNumber);
            if (attempt is null || !attempt.NetworkOperationId.AsSpan().SequenceEqual(work.NetworkOperationId.Span)
                || !target.Envelope.AsSpan().SequenceEqual(work.EnvelopeSpan))
                return GroupFanoutMutationDisposition.LeaseLost;
            var canRecordReleasedAttempt = target.CurrentAttemptNumber == attempt.Number
                && attempt.ReleasedLeaseGeneration is not null
                && lease.LeaseGeneration <= attempt.ReleasedLeaseGeneration
                && target.State is GroupFanoutTargetState.NetworkWorkReleased
                    or GroupFanoutTargetState.OutcomeUnknown;

            if (attempt.LastOutcome == outcome
                && attempt.RejectRule == rejectRule
                && Equal(attempt.NextNetworkOperationId, nextNetworkOperationId))
            {
                if (outcome == GroupFanoutAttemptOutcome.OutcomeUnknown
                    && target.CurrentAttemptNumber == attempt.Number
                    && target.State == GroupFanoutTargetState.NetworkWorkReleased
                    && canRecordReleasedAttempt)
                {
                    target.State = GroupFanoutTargetState.OutcomeUnknown;
                    attempt.State = GroupFanoutTargetState.OutcomeUnknown;
                    ClearLease(target);
                    return GroupFanoutMutationDisposition.Applied;
                }
                return GroupFanoutMutationDisposition.Idempotent;
            }

            if (attempt.LastOutcome is GroupFanoutAttemptOutcome.Accepted
                or GroupFanoutAttemptOutcome.DefiniteRejected)
            {
                if (outcome == GroupFanoutAttemptOutcome.OutcomeUnknown)
                    return GroupFanoutMutationDisposition.AlreadyTerminal;
                batch.ConflictLatched = true;
                return GroupFanoutMutationDisposition.ConflictLatched;
            }
            if (!canRecordReleasedAttempt)
                return GroupFanoutMutationDisposition.LeaseLost;

            if (outcome == GroupFanoutAttemptOutcome.DefiniteRejected
                && rejectRule == GroupFanoutDefiniteRejectRule.RetryWithNewOperation
                && target.Attempts.Any(value => value.NetworkOperationId.AsSpan()
                    .SequenceEqual(nextNetworkOperationId!.Span)))
            {
                batch.ConflictLatched = true;
                return GroupFanoutMutationDisposition.ConflictLatched;
            }

            attempt.LastOutcome = outcome;
            attempt.RejectRule = rejectRule;
            attempt.NextNetworkOperationId = nextNetworkOperationId?.ToArray();
            switch (outcome)
            {
                case GroupFanoutAttemptOutcome.OutcomeUnknown:
                    target.State = GroupFanoutTargetState.OutcomeUnknown;
                    attempt.State = GroupFanoutTargetState.OutcomeUnknown;
                    ClearLease(target);
                    break;
                case GroupFanoutAttemptOutcome.Accepted:
                    target.State = GroupFanoutTargetState.Accepted;
                    attempt.State = GroupFanoutTargetState.Accepted;
                    ClearLease(target);
                    break;
                case GroupFanoutAttemptOutcome.DefiniteRejected
                    when rejectRule == GroupFanoutDefiniteRejectRule.Terminal:
                    target.State = GroupFanoutTargetState.DefiniteRejected;
                    attempt.State = GroupFanoutTargetState.DefiniteRejected;
                    ClearLease(target);
                    break;
                case GroupFanoutAttemptOutcome.DefiniteRejected:
                    attempt.State = GroupFanoutTargetState.DefiniteRejected;
                    var nextNumber = checked(target.CurrentAttemptNumber + 1);
                    target.Attempts.Add(new AttemptEntry(nextNumber, nextNetworkOperationId!));
                    target.CurrentAttemptNumber = nextNumber;
                    target.State = GroupFanoutTargetState.Ready;
                    ClearLease(target);
                    break;
                default:
                    throw new InvalidOperationException("Unsupported GroupV1 fanout outcome.");
            }

            return GroupFanoutMutationDisposition.Applied;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutMutationDisposition> RevokeBeforeSendAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(targetId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!batches.TryGetValue(Key(batchId), out var batch)
                || !batch.Targets.TryGetValue(Key(targetId), out var target))
                return GroupFanoutMutationDisposition.NotFound;
            if (batch.ConflictLatched) return GroupFanoutMutationDisposition.ConflictLatched;
            if (target.State == GroupFanoutTargetState.RevokedBeforeSend)
                return GroupFanoutMutationDisposition.Idempotent;
            if (target.State is GroupFanoutTargetState.NetworkWorkReleased or GroupFanoutTargetState.OutcomeUnknown)
                return GroupFanoutMutationDisposition.MayHaveForwarded;
            if (target.State is GroupFanoutTargetState.Accepted or GroupFanoutTargetState.DefiniteRejected)
                return GroupFanoutMutationDisposition.AlreadyTerminal;

            target.State = GroupFanoutTargetState.RevokedBeforeSend;
            CurrentAttempt(target).State = GroupFanoutTargetState.RevokedBeforeSend;
            ClearLease(target);
            return GroupFanoutMutationDisposition.Applied;
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<GroupFanoutRecoveryResult> RecoverStaleLeasesAsync(
        GroupFanoutBatchId32 batchId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        now = GroupFanoutBatchPlan.CanonicalTime(now);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            return batches.TryGetValue(Key(batchId), out var batch)
                ? Recover(batch, now)
                : new(0, 0);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        gate.Wait();
        try { batches.Clear(); }
        finally { gate.Release(); }
    }

    private void ValidatePlan(GroupFanoutBatchPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ValidateScope(plan.Scope, nameof(plan));
    }

    private void ValidateScope(GroupStoreScope scope, string parameter)
    {
        if (!Scope.Equals(scope)) throw new ArgumentException("Fanout operation belongs to another account store scope.", parameter);
    }

    private static GroupFanoutRecoveryResult Recover(BatchEntry batch, DateTimeOffset now)
    {
        var beforeSend = 0;
        var unknown = 0;
        foreach (var target in batch.Targets.Values.Where(
                     target => target.LeaseOwner is not null && target.LeaseExpiresAt <= now))
        {
            if (target.State == GroupFanoutTargetState.NetworkWorkReleased)
            {
                target.State = GroupFanoutTargetState.OutcomeUnknown;
                var attempt = CurrentAttempt(target);
                attempt.State = GroupFanoutTargetState.OutcomeUnknown;
                attempt.LastOutcome = GroupFanoutAttemptOutcome.OutcomeUnknown;
                attempt.RejectRule = GroupFanoutDefiniteRejectRule.Terminal;
                unknown++;
            }
            else
            {
                beforeSend++;
            }
            ClearLease(target);
        }
        return new(beforeSend, unknown);
    }

    private bool TryTarget(
        GroupFanoutDispatchLease lease,
        out BatchEntry batch,
        out TargetEntry target)
    {
        if (!batches.TryGetValue(Key(lease.BatchId), out batch!))
        {
            target = null!;
            return false;
        }
        return batch.Targets.TryGetValue(Key(lease.TargetId), out target!);
    }

    private static bool LeaseMatches(TargetEntry target, GroupFanoutDispatchLease lease) =>
        target.CurrentAttemptNumber == lease.AttemptNumber
        && target.LeaseOwner is not null
        && target.LeaseOwner.AsSpan().SequenceEqual(lease.LeaseOwner.Span)
        && target.LeaseGeneration == lease.LeaseGeneration;

    private static bool Equal(byte[]? stored, GroupFanoutNetworkOperationId32? supplied) =>
        (stored is null) == (supplied is null)
        && (stored is null || stored.AsSpan().SequenceEqual(supplied!.Span));

    private static void ClearLease(TargetEntry target)
    {
        target.LeaseOwner = null;
        target.LeaseExpiresAt = null;
    }

    private static AttemptEntry CurrentAttempt(TargetEntry target) =>
        target.Attempts.Single(value => value.Number == target.CurrentAttemptNumber);

    private GroupFanoutBatchSnapshot Snapshot(BatchEntry batch) => new(
        Scope,
        batch.BatchId,
        batch.TransitionOperationId,
        batch.GroupId,
        batch.MemberCount,
        batch.VerifiedDeviceCount,
        batch.ConflictLatched,
        batch.StagedAt,
        batch.Targets.Values
            .OrderBy(static target => Convert.ToHexString(target.TargetId), StringComparer.Ordinal)
            .Select(static target => new GroupFanoutTargetSnapshot(
                GroupFanoutTargetId32.FromOpaqueBytes(target.TargetId),
                target.State,
                target.CurrentAttemptNumber,
                target.LeaseOwner is null ? null : GroupFanoutLeaseOwnerId16.FromBytes(target.LeaseOwner),
                target.LeaseGeneration,
                target.LeaseExpiresAt,
                target.Attempts.OrderBy(static attempt => attempt.Number).Select(static attempt =>
                    new GroupFanoutAttemptSnapshot(
                        attempt.Number,
                        attempt.State,
                        attempt.NextNetworkOperationId is not null)))));

    private GroupFanoutDispatchLease Lease(BatchEntry batch, TargetEntry target)
    {
        var attempt = CurrentAttempt(target);
        return new(
            Scope,
            batch.BatchId,
            GroupFanoutTargetId32.FromOpaqueBytes(target.TargetId),
            attempt.Number,
            GroupFanoutLeaseOwnerId16.FromBytes(target.LeaseOwner!),
            target.LeaseGeneration,
            target.LeaseExpiresAt!.Value,
            target.State == GroupFanoutTargetState.OutcomeUnknown);
    }

    private static GroupFanoutNetworkWork Work(GroupFanoutDispatchLease lease, TargetEntry target) =>
        new(lease, GroupFanoutNetworkOperationId32.FromBytes(CurrentAttempt(target).NetworkOperationId), target.Envelope);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
    private static string Key(GroupBytes32 value) => Convert.ToHexString(value.Bytes.Span);

    private sealed class BatchEntry
    {
        internal BatchEntry(GroupFanoutBatchPlan plan)
        {
            BatchId = GroupFanoutBatchId32.FromBytes(plan.BatchId.Span);
            TransitionOperationId = GroupOperationId32.FromBytes(plan.TransitionOperationId.Span);
            GroupId = GroupId32.FromBytes(plan.GroupId.Span);
            Fingerprint = plan.Fingerprint.ToArray();
            PackageHash = plan.PackageHash.ToArray();
            VerifiedPackageHash = plan.VerifiedPackageHash.ToArray();
            MemberCount = plan.MemberCount;
            VerifiedDeviceCount = plan.VerifiedDeviceCount;
            StagedAt = plan.StagedAt;
            Targets = plan.TargetRows.ToDictionary(
                static target => Key(target.TargetId),
                static target => new TargetEntry(target),
                StringComparer.Ordinal);
        }

        internal GroupFanoutBatchId32 BatchId { get; }
        internal GroupOperationId32 TransitionOperationId { get; }
        internal GroupId32 GroupId { get; }
        internal byte[] Fingerprint { get; }
        internal byte[] PackageHash { get; }
        internal byte[] VerifiedPackageHash { get; }
        internal ushort MemberCount { get; }
        internal ushort VerifiedDeviceCount { get; }
        internal DateTimeOffset StagedAt { get; }
        internal Dictionary<string, TargetEntry> Targets { get; }
        internal bool ConflictLatched { get; set; }
    }

    private sealed class TargetEntry
    {
        internal TargetEntry(GroupFanoutTargetEnvelope target)
        {
            TargetId = target.TargetId.ToArray();
            Envelope = target.ExactCanonicalEnvelope.ToArray();
            CurrentAttemptNumber = 1;
            State = GroupFanoutTargetState.Ready;
            Attempts = [new AttemptEntry(1, target.InitialNetworkOperationId)];
        }

        internal byte[] TargetId { get; }
        internal byte[] Envelope { get; }
        internal uint CurrentAttemptNumber { get; set; }
        internal GroupFanoutTargetState State { get; set; }
        internal byte[]? LeaseOwner { get; set; }
        internal ulong LeaseGeneration { get; set; }
        internal DateTimeOffset? LeaseExpiresAt { get; set; }
        internal List<AttemptEntry> Attempts { get; }
    }

    private sealed class AttemptEntry
    {
        internal AttemptEntry(uint number, GroupFanoutNetworkOperationId32 networkOperationId)
        {
            Number = number;
            NetworkOperationId = networkOperationId.ToArray();
            State = GroupFanoutTargetState.Ready;
            RejectRule = GroupFanoutDefiniteRejectRule.Terminal;
        }

        internal uint Number { get; }
        internal byte[] NetworkOperationId { get; }
        internal GroupFanoutTargetState State { get; set; }
        internal ulong? ReleasedLeaseGeneration { get; set; }
        internal GroupFanoutAttemptOutcome? LastOutcome { get; set; }
        internal GroupFanoutDefiniteRejectRule RejectRule { get; set; }
        internal byte[]? NextNetworkOperationId { get; set; }
    }
}
