using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Persistence.MessagingV1;

internal static class LogicalOutboxStateMachine
{
    internal static LogicalOutboxSnapshot Queued(LogicalOutboxSeed seed) => new(seed.StoreScope, seed.ClaimKey,
        seed.AuthorDeviceId, seed.EventHash, seed.CanonicalPayload, seed.CreatedAt, seed.ExpiresAt,
        LogicalOutboxState.Queued, 1, [], payloadKind: seed.PayloadKind);

    internal static LogicalOutboxSnapshot Apply(LogicalOutboxSnapshot current, PreparedMessageMutation plan)
    {
        if (!current.StoreScope.Equals(plan.Scope) || !current.ClaimKey.Equals(plan.ClaimKey)
            || current.Revision != plan.ExpectedRevision || plan.OccurredAt < current.CreatedAt) throw new InvalidOperationException("MSG-01 mutation is not bound to the current head.");
        if (current.Revision == ulong.MaxValue) throw new MessageRevisionExhaustedException();
        var targets = current.Targets.Select(LogicalOutboxSnapshot.CloneTarget).ToList();
        var state = current.State;
        switch (plan.Kind)
        {
            case MessageMutationKind.PrepareFanout:
                Require(state == LogicalOutboxState.Queued && targets.Count == 0 && plan.Fanout.Count is > 0 and <= MessagingV1Limits.MaxFanoutTargets);
                Require(plan.Fanout.Select(x => x.Target).Distinct().Count() == plan.Fanout.Count);
                targets = plan.Fanout.Select(x => new LogicalTargetSnapshot(x.Target, x.DirectoryHeadHash, LogicalTargetState.Pending, null, null, null, null, null, false, x.OperationId, x.BindingHash)).OrderBy(x => x.Target).ToList();
                state = LogicalOutboxState.FanoutPrepared; break;
            case MessageMutationKind.StartSending:
                Require(state is LogicalOutboxState.FanoutPrepared or LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted);
                Require(plan.Attempts.Count is > 0 and <= MessagingV1Limits.MaxFanoutTargets);
                foreach (var a in plan.Attempts)
                {
                    var i = Find(targets, a.Target); var t = targets[i];
                    Require(t.State == LogicalTargetState.Pending && t.ActiveAttemptId is null && t.UnresolvedAttemptId is null && (t.LastAttemptId is null || !t.LastAttemptId.Equals(a.AttemptId)));
                    Require(t.DirectoryHeadHash.Equals(a.DirectoryHeadHash));
                    Require(!targets.Where((_, n) => n != i).Any(x => x.ActiveAttemptId?.Equals(a.AttemptId) == true || x.LastAttemptId?.Equals(a.AttemptId) == true));
                    Require(t.OperationId is not null && t.BindingHash is not null && t.OperationId.Equals(a.OperationId) && t.BindingHash.Equals(a.BindingHash));
                    targets[i] = new(t.Target, t.DirectoryHeadHash, t.State, a.AttemptId, t.LastAttemptId, a.AttemptId, a.RequestHash, a.RatchetTransitionHash, false, t.OperationId, t.BindingHash, a.Ciphertext.Span, a.RatchetBeforeHash);
                }
                state = Aggregate(targets); break;
            case MessageMutationKind.TargetOutcome:
                Require(plan.Outcome is not null && Bound(plan.Outcome, current));
                ApplyOutcome(targets, plan.Outcome!);
                // Each reconciliation result carries its own exact-context peer/session
                // signature, so the latch closes as soon as the final unresolved target
                // is cryptographically resolved.
                state = Aggregate(targets);
                break;
            case MessageMutationKind.MarkOutcomeUnknown:
                Require(plan.Uncertainty is not null && Bound(plan.Uncertainty, current)); MarkUnknown(targets, plan.Uncertainty!); state = LogicalOutboxState.OutcomeUnknown; break;
            case MessageMutationKind.ReconcileOutcomeUnknown:
                Require(state is LogicalOutboxState.Sending or LogicalOutboxState.PartiallyAccepted or LogicalOutboxState.OutcomeUnknown
                    && plan.Reconciliation is not null && Bound(plan.Reconciliation, current));
                ApplyReconciliation(targets, plan.Reconciliation!); state = Aggregate(targets); break;
            case MessageMutationKind.LateMaterializationReceipt:
                Require(plan.LateReceipt is not null && Bound(plan.LateReceipt, current)); LateMaterialize(targets, plan.LateReceipt!);
                state = state is LogicalOutboxState.OutcomeUnknown or LogicalOutboxState.Cancelled
                    or LogicalOutboxState.Expired ? state : Aggregate(targets); break;
            case MessageMutationKind.LocalGroupDispatchBlock:
                Require(plan.GroupDispatchBlock is not null
                    && Bound(plan.GroupDispatchBlock, current));
                ApplyLocalGroupDispatchBlock(targets, plan.GroupDispatchBlock!);
                state = Aggregate(targets);
                break;
            case MessageMutationKind.Cancel:
                Require(state is not LogicalOutboxState.Expired and not LogicalOutboxState.TerminalRejected && targets.All(x => x.ActiveAttemptId is null && x.UnresolvedAttemptId is null));
                ReplacePending(targets, LogicalTargetState.TerminalRejected); state = LogicalOutboxState.Cancelled; break;
            case MessageMutationKind.Expire:
                Require(plan.OccurredAt >= current.ExpiresAt && state is not LogicalOutboxState.Cancelled and not LogicalOutboxState.TerminalRejected && targets.All(x => x.ActiveAttemptId is null && x.UnresolvedAttemptId is null));
                ReplacePending(targets, LogicalTargetState.Expired); state = LogicalOutboxState.Expired; break;
            default: throw new InvalidOperationException("Unknown MSG-01 mutation.");
        }
        var candidate = new LogicalOutboxSnapshot(current.StoreScope, current.ClaimKey,
            current.AuthorDeviceId, current.EventHash, current.CanonicalPayload,
            current.CreatedAt, current.ExpiresAt, state, current.Revision + 1,
            targets, current.RecoveryLease, current.PayloadKind);
        Validate(candidate); return candidate;
    }

    private static int Find(IReadOnlyList<LogicalTargetSnapshot> t, RecipientDeviceTarget target) { var i=t.ToList().FindIndex(x=>x.Target.Equals(target)); Require(i>=0); return i; }
    private static void ApplyOutcome(List<LogicalTargetSnapshot> targets, VerifiedTransportTargetOutcome outcome)
    {
        ApplyResolvedOutcome(targets, outcome.Target, outcome.AttemptId, outcome.Kind);
    }
    private static void ApplyReconciliation(List<LogicalTargetSnapshot> targets,
        VerifiedTransportAttemptReconciliation reconciliation) =>
        ApplyResolvedOutcome(targets, reconciliation.Target, reconciliation.AttemptId,
            reconciliation.Kind);
    private static void ApplyResolvedOutcome(List<LogicalTargetSnapshot> targets,
        RecipientDeviceTarget target, TransportAttemptId16 attempt,
        VerifiedTargetOutcomeKind outcome)
    {
        var i=Find(targets,target); var t=targets[i];
        Require(t.ActiveAttemptId is not null && t.ActiveAttemptId.Equals(attempt)
            && t.UnresolvedAttemptId is not null && t.UnresolvedAttemptId.Equals(attempt));
        var state=outcome switch { VerifiedTargetOutcomeKind.Accepted=>LogicalTargetState.Accepted, VerifiedTargetOutcomeKind.Materialized=>LogicalTargetState.Materialized, VerifiedTargetOutcomeKind.Expired=>LogicalTargetState.Expired, VerifiedTargetOutcomeKind.Revoked=>LogicalTargetState.RevokedTarget, VerifiedTargetOutcomeKind.TerminalRejected=>LogicalTargetState.TerminalRejected, VerifiedTargetOutcomeKind.NotAccepted=>LogicalTargetState.Pending, _=>throw new InvalidOperationException() };
        targets[i]=new(t.Target,t.DirectoryHeadHash,state,null,attempt,null,t.RequestHash,t.RatchetTransitionHash,false,t.OperationId,t.BindingHash,t.Ciphertext??[],t.RatchetBeforeHash);
    }
    private static void MarkUnknown(List<LogicalTargetSnapshot> targets, VerifiedTransportAttemptUncertainty u)
    { var i=Find(targets,u.Target); var t=targets[i]; Require(t.ActiveAttemptId is not null && t.ActiveAttemptId.Equals(u.AttemptId) && t.UnresolvedAttemptId is not null); targets[i]=new(t.Target,t.DirectoryHeadHash,t.State,t.ActiveAttemptId,t.LastAttemptId,t.UnresolvedAttemptId,t.RequestHash,t.RatchetTransitionHash,true,t.OperationId,t.BindingHash,t.Ciphertext??[],t.RatchetBeforeHash); }
    private static void LateMaterialize(List<LogicalTargetSnapshot> targets, VerifiedLateMaterializationReceipt r)
    { var i=Find(targets,r.Target); var t=targets[i]; Require(t.State==LogicalTargetState.Accepted && t.LastAttemptId is not null && t.LastAttemptId.Equals(r.AcceptedAttemptId)); targets[i]=new(t.Target,t.DirectoryHeadHash,LogicalTargetState.Materialized,t.ActiveAttemptId,t.LastAttemptId,t.UnresolvedAttemptId,t.RequestHash,t.RatchetTransitionHash,t.OutcomeUnknown,t.OperationId,t.BindingHash,t.Ciphertext??[],t.RatchetBeforeHash); }
    private static void ApplyLocalGroupDispatchBlock(
        List<LogicalTargetSnapshot> targets,
        VerifiedLocalGroupDispatchBlock block)
    {
        var index = Find(targets, block.Target);
        var target = targets[index];
        Require(target.State == LogicalTargetState.Pending
            && target.ActiveAttemptId?.Equals(block.AttemptId) == true
            && target.UnresolvedAttemptId?.Equals(block.AttemptId) == true
            && target.LastAttemptId is null
            && !target.OutcomeUnknown);
        var terminal = block.Disposition == GroupMessageFirstDispatchDisposition.TargetRemoved
            ? LogicalTargetState.RevokedTarget
            : LogicalTargetState.TerminalRejected;
        targets[index] = new LogicalTargetSnapshot(
            target.Target,
            target.DirectoryHeadHash,
            terminal,
            null,
            null,
            null,
            null,
            null,
            false,
            target.OperationId,
            target.BindingHash);
    }
    private static void ReplacePending(List<LogicalTargetSnapshot> t, LogicalTargetState s) { for(var i=0;i<t.Count;i++) if(t[i].State==LogicalTargetState.Pending && t[i].ActiveAttemptId is null) { var x=t[i]; t[i]=new(x.Target,x.DirectoryHeadHash,s,null,x.LastAttemptId,null,x.RequestHash,x.RatchetTransitionHash,false,x.OperationId,x.BindingHash,x.Ciphertext??[],x.RatchetBeforeHash); } }
    private static LogicalOutboxState Aggregate(IReadOnlyList<LogicalTargetSnapshot> t)
    {
        if(t.Any(x=>x.OutcomeUnknown)) return LogicalOutboxState.OutcomeUnknown;
        if(t.Any(x=>x.ActiveAttemptId is not null || x.UnresolvedAttemptId is not null)) return t.Any(x=>x.State is LogicalTargetState.Accepted or LogicalTargetState.Materialized)?LogicalOutboxState.PartiallyAccepted:LogicalOutboxState.Sending;
        if(t.Any(x=>x.State==LogicalTargetState.Pending)) return t.Any(x=>x.State is LogicalTargetState.Accepted or LogicalTargetState.Materialized)?LogicalOutboxState.PartiallyAccepted:LogicalOutboxState.FanoutPrepared;
        if(t.Any(x=>x.State==LogicalTargetState.Materialized)) return LogicalOutboxState.RecipientMaterialized;
        if(t.Any(x=>x.State==LogicalTargetState.Accepted)) return LogicalOutboxState.Accepted;
        if(t.All(x=>x.State is LogicalTargetState.TerminalRejected or LogicalTargetState.RevokedTarget))
            return LogicalOutboxState.TerminalRejected;
        return LogicalOutboxState.Expired;
    }
    internal static void Validate(LogicalOutboxSnapshot s)
    {
        ArgumentNullException.ThrowIfNull(s);
        if (s.Revision == 0 || s.CreatedAt <= DateTimeOffset.UnixEpoch
            || s.ExpiresAt <= s.CreatedAt
            || s.ExpiresAt - s.CreatedAt > MessagingV1Limits.MaxEventLifetime
            || s.CreatedAt.Ticks % TimeSpan.TicksPerMillisecond != 0
            || s.ExpiresAt.Ticks % TimeSpan.TicksPerMillisecond != 0
            || !Enum.IsDefined(s.State)
            || s.Targets.Count > MessagingV1Limits.MaxFanoutTargets
            || !s.AuthorAccountId.Equals(s.LocalAccountId)
            || s.ClaimKey.AuthorDeviceId is null
            || !s.ClaimKey.AuthorDeviceId.Equals(s.AuthorDeviceId))
            throw Corrupt();

        var targets = s.Targets.ToArray();
        var ordered = targets.Select(static x => x.Target).OrderBy(static x => x).ToArray();
        if (!ordered.SequenceEqual(targets.Select(static x => x.Target))
            || ordered.Zip(ordered.Skip(1)).Any(static x => x.First.Equals(x.Second))
            || targets.Select(static x => x.OperationId).Distinct().Count() != targets.Length
            || targets.Select(static x => x.BindingHash).Distinct().Count() != targets.Length)
            throw Corrupt();

        var attemptOwners = new Dictionary<TransportAttemptId16, RecipientDeviceTarget>();
        foreach (var target in targets)
        {
            if (!Enum.IsDefined(target.State) || target.OperationId is null || target.BindingHash is null)
                throw Corrupt();
            if ((target.ActiveAttemptId is null) != (target.UnresolvedAttemptId is null)
                || target.ActiveAttemptId is not null
                    && !target.ActiveAttemptId.Equals(target.UnresolvedAttemptId)
                || target.OutcomeUnknown && target.UnresolvedAttemptId is null)
                throw Corrupt();

            var hasDispatchMaterial = target.RequestHash is not null
                || target.RatchetBeforeHash is not null
                || target.RatchetTransitionHash is not null || target.LastAttemptId is not null
                || target.ActiveAttemptId is not null;
            if (hasDispatchMaterial
                && (target.RequestHash is null || target.RatchetBeforeHash is null || target.RatchetTransitionHash is null
                    || target.LastAttemptId is null && target.ActiveAttemptId is null)
                || !hasDispatchMaterial
                    && (target.RequestHash is not null || target.RatchetBeforeHash is not null || target.RatchetTransitionHash is not null))
                throw Corrupt();
            if (target.State is LogicalTargetState.Accepted or LogicalTargetState.Materialized
                && (target.LastAttemptId is null || target.ActiveAttemptId is not null))
                throw Corrupt();
            if (target.State is not LogicalTargetState.Pending && target.ActiveAttemptId is not null)
                throw Corrupt();

            RecordOwner(target.ActiveAttemptId, target.Target, attemptOwners);
            RecordOwner(target.LastAttemptId, target.Target, attemptOwners);
            RecordOwner(target.UnresolvedAttemptId, target.Target, attemptOwners);
        }

        if (s.State == LogicalOutboxState.Queued)
        {
            if (targets.Length != 0) throw Corrupt();
        }
        else if (targets.Length == 0) throw Corrupt();

        if (s.State is LogicalOutboxState.Cancelled or LogicalOutboxState.Expired)
        {
            if (targets.Any(static x => x.State == LogicalTargetState.Pending
                || x.ActiveAttemptId is not null || x.UnresolvedAttemptId is not null
                || x.OutcomeUnknown)) throw Corrupt();
        }
        else if (s.State == LogicalOutboxState.OutcomeUnknown)
        {
            if (!targets.Any(static target => target.OutcomeUnknown
                && target.ActiveAttemptId is not null)) throw Corrupt();
        }
        else if (s.State != LogicalOutboxState.Queued && s.State != Aggregate(targets))
            throw Corrupt();

        if (s.RecoveryLease is not null
            && (s.RecoveryLease.ExpiresAt <= DateTimeOffset.UnixEpoch
                || s.RecoveryLease.ExpiresAt.Ticks % TimeSpan.TicksPerMillisecond != 0))
            throw Corrupt();
    }

    private static void RecordOwner(TransportAttemptId16? attemptId,
        RecipientDeviceTarget target,
        IDictionary<TransportAttemptId16, RecipientDeviceTarget> owners)
    {
        if (attemptId is null) return;
        if (owners.TryGetValue(attemptId, out var existing) && !existing.Equals(target))
            throw Corrupt();
        owners[attemptId] = target;
    }

    private static InvalidOperationException Corrupt() =>
        new("Persisted MSG-01 outbox is corrupt.");
    private static bool Bound(VerifiedTransportTargetOutcome x, LogicalOutboxSnapshot h)=>x.Scope.Equals(h.StoreScope)&&x.ClaimKey.Equals(h.ClaimKey);
    private static bool Bound(VerifiedTransportAttemptUncertainty x, LogicalOutboxSnapshot h)=>x.Scope.Equals(h.StoreScope)&&x.ClaimKey.Equals(h.ClaimKey);
    private static bool Bound(VerifiedTransportAttemptReconciliation x, LogicalOutboxSnapshot h)=>x.Scope.Equals(h.StoreScope)&&x.ClaimKey.Equals(h.ClaimKey);
    private static bool Bound(VerifiedLateMaterializationReceipt x, LogicalOutboxSnapshot h)=>x.Scope.Equals(h.StoreScope)&&x.ClaimKey.Equals(h.ClaimKey);
    private static bool Bound(VerifiedLocalGroupDispatchBlock x, LogicalOutboxSnapshot h) =>
        x.Scope.Equals(h.StoreScope)
        && x.ClaimKey.Equals(h.ClaimKey)
        && x.ClaimKey.AuthorDeviceId?.Equals(h.AuthorDeviceId) == true
        && x.OutboxRevision == h.Revision;
    private static void Require(bool c) { if(!c) throw new InvalidOperationException("MSG-01 transition is not allowed."); }
}
