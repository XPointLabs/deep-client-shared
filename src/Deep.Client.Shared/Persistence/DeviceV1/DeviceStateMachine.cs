using Deep.Client.Shared.Domain.DeviceV1;

namespace Deep.Client.Shared.Persistence.DeviceV1;

internal static class DeviceStateMachine
{
    internal static DeviceCommitResult Apply(DeviceAccountStateSnapshot? current, DeviceTransactionPlan plan)
    {
        if (plan.Kind == DeviceTransactionKind.Bootstrap) return Bootstrap(current, plan);
        if (current is null) return new(DeviceCommitDisposition.Missing, null);
        if (!current.Directory.Head.AccountId.Equals(plan.AccountId)
            || current.Directory.Head.AccountGeneration != plan.AccountGeneration)
            return new(DeviceCommitDisposition.Conflict, current);
        if (plan.ExpectedRevision != current.Revision) return new(DeviceCommitDisposition.StaleRevision, current);
        if (current.Revision == ulong.MaxValue) return new(DeviceCommitDisposition.InvalidTransition, current);
        return plan.Kind switch
        {
            DeviceTransactionKind.InstallDirectory => InstallDirectory(current, plan.Candidate!),
            DeviceTransactionKind.CommitEnrollment => CommitEnrollment(current, plan),
            DeviceTransactionKind.PrepareRevocation => PrepareRevocation(current, plan),
            DeviceTransactionKind.CommitRevocationFloor => CommitFloor(current, plan),
            DeviceTransactionKind.AdvanceRevocation => Advance(current, plan),
            DeviceTransactionKind.AbortPreparedRevocation => Abort(current, plan),
            DeviceTransactionKind.AuthorizeRepairAttempt => AuthorizeRepair(current, plan.RepairKey!),
            DeviceTransactionKind.CompleteRepair => CompleteRepair(current, plan.RepairKey!),
            _ => new(DeviceCommitDisposition.InvalidTransition, current)
        };
    }

    private static DeviceCommitResult Bootstrap(DeviceAccountStateSnapshot? current, DeviceTransactionPlan plan)
    {
        if (current is not null) return new(DeviceCommitDisposition.Conflict, current);
        try
        {
            var directory = DeviceDirectoryState.Start(plan.Candidate!).Next;
            return Applied(new DeviceAccountStateSnapshot(1, directory, []));
        }
        catch (InvalidOperationException) { return new(DeviceCommitDisposition.InvalidTransition, null); }
    }

    private static DeviceCommitResult InstallDirectory(DeviceAccountStateSnapshot current,
        VerifiedDeviceDirectoryFacts candidate)
    {
        var transition = current.Directory.PrepareTransition(candidate);
        if (transition.Disposition == DeviceDirectoryTransitionDisposition.ExactReplay)
            return new(DeviceCommitDisposition.Idempotent, current);
        if (transition.Disposition is DeviceDirectoryTransitionDisposition.ForkLatched
            or DeviceDirectoryTransitionDisposition.RevokedDeviceReuse)
            return new(DeviceCommitDisposition.ForkLatched, Clone(current, transition.Next));
        if (transition.Disposition != DeviceDirectoryTransitionDisposition.AcceptedSuccessor)
            return new(DeviceCommitDisposition.InvalidTransition, current);
        return Applied(Clone(current, transition.Next));
    }

    private static DeviceCommitResult CommitEnrollment(DeviceAccountStateSnapshot current, DeviceTransactionPlan plan)
    {
        var intent = plan.Intent!;
        if (!IntentStillCurrent(current, intent) || !MatchesEnrollment(plan.Candidate!, intent)
            || current.Directory.IsLocallyRevoked(intent.Enrollment!.DeviceId))
            return new(DeviceCommitDisposition.InvalidTransition, current);
        var transition = current.Directory.PrepareTransition(plan.Candidate!);
        if (transition.Disposition is DeviceDirectoryTransitionDisposition.ForkLatched
            or DeviceDirectoryTransitionDisposition.RevokedDeviceReuse)
            return new(DeviceCommitDisposition.ForkLatched, Clone(current, transition.Next));
        if (transition.Disposition != DeviceDirectoryTransitionDisposition.AcceptedSuccessor)
            return new(DeviceCommitDisposition.InvalidTransition, current);
        return Applied(Clone(current, transition.Next,
            history: current.HistoryDecisions.Append(DeviceHistoryDecisionSnapshot.FromIntent(intent.RecoveryIntent!))));
    }

    private static DeviceCommitResult PrepareRevocation(DeviceAccountStateSnapshot current, DeviceTransactionPlan plan)
    {
        var intent = plan.Intent!;
        if (!IntentStillCurrent(current, intent)
            || current.RevocationSagas.Any(static x => !x.IsTerminal)
            || current.RevocationSagas.Any(x => x.OperationId.Equals(plan.SagaOperationId!))
            || !ValidRevocationIntent(current, intent))
            return new(DeviceCommitDisposition.InvalidTransition, current);
        var saga = new DeviceRevocationSagaSnapshot(plan.SagaOperationId!, intent,
            DeviceRevocationPhase.Prepared, DeviceRemoteOutcome.None);
        return Applied(Clone(current, current.Directory, sagas: current.RevocationSagas.Append(saga)));
    }

    private static DeviceCommitResult CommitFloor(DeviceAccountStateSnapshot current, DeviceTransactionPlan plan)
    {
        var saga = FindSaga(current, plan);
        if (saga is null || saga.Phase != DeviceRevocationPhase.Prepared
            || !IntentStillCurrent(current, saga.Intent) || !ValidRevocationIntent(current, saga.Intent))
            return new(DeviceCommitDisposition.InvalidTransition, current);
        var commitment = saga.Intent.Revocation!;
        var entry = new DeviceLocalRevocationFloorEntry(commitment.AccountId, commitment.AccountGeneration,
            commitment.RevokedDeviceId, commitment.RevokedDpdReference.ToArray(),
            commitment.PriorDrsRevision, commitment.PriorDrsHash, commitment.SuccessorDrsRevision,
            commitment.SuccessorDrsHash, saga.OperationId);
        DeviceDirectoryState directory;
        try { directory = current.Directory.CommitRevocation(commitment.SuccessorDirectory, entry); }
        catch (InvalidOperationException) { return new(DeviceCommitDisposition.InvalidTransition, current); }
        var updated = ReplaceSaga(current, saga, DeviceRevocationPhase.LocalFloorCommitted,
            DeviceRemoteOutcome.None);
        var history = saga.Intent.Kind == DeviceMutationKind.Rekey
            ? current.HistoryDecisions.Append(DeviceHistoryDecisionSnapshot.FromIntent(saga.Intent.RecoveryIntent!))
            : current.HistoryDecisions;
        return Applied(Clone(current, directory, updated, history));
    }

    private static DeviceCommitResult Advance(DeviceAccountStateSnapshot current, DeviceTransactionPlan plan)
    {
        var saga = FindSaga(current, plan);
        if (saga is null || saga.Phase != plan.ExpectedPhase || plan.NextPhase is null
            || plan.ExternalOperationId is null || !AllowedNext(saga, plan))
            return new(DeviceCommitDisposition.InvalidTransition, current);
        var unknown = plan.RemoteOutcome == DeviceRemoteOutcome.OutcomeUnknown;
        var updated = ReplaceSaga(current, saga,
            unknown ? DeviceRevocationPhase.ReconcileRequired : plan.NextPhase.Value,
            plan.RemoteOutcome, unknown ? plan.NextPhase : null, unknown ? plan.ExternalOperationId : null);
        return Applied(Clone(current, current.Directory, updated));
    }

    private static DeviceCommitResult Abort(DeviceAccountStateSnapshot current, DeviceTransactionPlan plan)
    {
        var saga = FindSaga(current, plan);
        if (saga is null || saga.Phase != DeviceRevocationPhase.Prepared)
            return new(DeviceCommitDisposition.InvalidTransition, current);
        return Applied(Clone(current, current.Directory,
            ReplaceSaga(current, saga, DeviceRevocationPhase.Aborted, DeviceRemoteOutcome.None)));
    }

    private static DeviceCommitResult AuthorizeRepair(DeviceAccountStateSnapshot current, DeviceRepairKey key)
    {
        if (!KeyBelongs(current, key)) return new(DeviceCommitDisposition.InvalidTransition, current);
        var old = current.FindRepair(key);
        if (old?.Status == DeviceRepairStatus.Completed) return new(DeviceCommitDisposition.Idempotent, current);
        if (old is not null && old.AttemptsUsed >= 2)
            return new(DeviceCommitDisposition.RepairExhausted, current);
        var attempts = (old?.AttemptsUsed ?? 0) + 1;
        var next = new DeviceRepairSnapshot(key, attempts,
            attempts == 2 ? DeviceRepairStatus.Exhausted : DeviceRepairStatus.Active);
        var repairs = current.Repairs.Where(x => !x.Key.Equals(key)).Append(next);
        return Applied(Clone(current, current.Directory, repairs: repairs));
    }

    private static DeviceCommitResult CompleteRepair(DeviceAccountStateSnapshot current, DeviceRepairKey key)
    {
        if (!KeyBelongs(current, key)) return new(DeviceCommitDisposition.InvalidTransition, current);
        var old = current.FindRepair(key);
        if (old is null) return new(DeviceCommitDisposition.InvalidTransition, current);
        if (old.Status == DeviceRepairStatus.Completed) return new(DeviceCommitDisposition.Idempotent, current);
        var repairs = current.Repairs.Where(x => !x.Key.Equals(key))
            .Append(new DeviceRepairSnapshot(key, old.AttemptsUsed, DeviceRepairStatus.Completed));
        return Applied(Clone(current, current.Directory, repairs: repairs));
    }

    private static bool AllowedNext(DeviceRevocationSagaSnapshot saga, DeviceTransactionPlan plan)
    {
        if (saga.Phase == DeviceRevocationPhase.ReconcileRequired)
            return plan.RemoteOutcome == DeviceRemoteOutcome.Confirmed
                && saga.PendingPhase == plan.NextPhase
                && saga.PendingExternalOperationId is not null
                && saga.PendingExternalOperationId.Equals(plan.ExternalOperationId);
        if (plan.RemoteOutcome is not (DeviceRemoteOutcome.Confirmed or DeviceRemoteOutcome.OutcomeUnknown))
            return false;
        return (saga.Phase, plan.NextPhase) switch
        {
            (DeviceRevocationPhase.LocalFloorCommitted, DeviceRevocationPhase.PrekeysFenced) => true,
            (DeviceRevocationPhase.PrekeysFenced, DeviceRevocationPhase.DirectoryCommitted) => true,
            (DeviceRevocationPhase.DirectoryCommitted, DeviceRevocationPhase.CapabilitiesRotated) => true,
            (DeviceRevocationPhase.CapabilitiesRotated, DeviceRevocationPhase.ContactsNotified) => true,
            (DeviceRevocationPhase.ContactsNotified, DeviceRevocationPhase.GroupsConverging) => true,
            (DeviceRevocationPhase.GroupsConverging, DeviceRevocationPhase.Complete) => true,
            _ => false
        };
    }

    private static bool IntentStillCurrent(DeviceAccountStateSnapshot current, DeviceMutationIntent intent) =>
        !current.Directory.ForkLatched && current.Directory.Head.AccountId.Equals(intent.AccountId)
        && current.Directory.Head.AccountGeneration == intent.AccountGeneration
        && current.Directory.Head.DirectoryGeneration == intent.ExpectedDirectoryGeneration
        && current.Directory.Head.DirectoryHash.Equals(intent.ExpectedDirectoryHash);
    private static bool MatchesEnrollment(VerifiedDeviceDirectoryFacts candidate, DeviceMutationIntent intent)
    {
        if (!candidate.AccountId.Equals(intent.AccountId) || candidate.AccountGeneration != intent.AccountGeneration
            || intent.ExpectedDirectoryGeneration == ulong.MaxValue
            || candidate.DirectoryGeneration != intent.ExpectedDirectoryGeneration + 1
            || !candidate.PredecessorSpan.SequenceEqual(intent.ExpectedDirectoryHash.Span)
            || candidate.RevocationRevision != intent.Enrollment!.RevocationRevision
            || !candidate.RevocationHash.Equals(intent.Enrollment.RevocationHash)) return false;
        var expected = intent.DesiredDevices.OrderBy(static x => x).ToArray();
        var actual = candidate.ActiveDevices.OrderBy(static x => x).ToArray();
        return expected.SequenceEqual(actual);
    }
    private static bool ValidRevocationIntent(DeviceAccountStateSnapshot current, DeviceMutationIntent intent)
    {
        var commitment = intent.Revocation;
        if (commitment is null || intent.PlaneOperations is null
            || !commitment.AccountId.Equals(current.Directory.Head.AccountId)
            || commitment.AccountGeneration != current.Directory.Head.AccountGeneration
            || commitment.PriorDrsRevision != current.Directory.Head.RevocationRevision
            || !commitment.PriorDrsHash.Equals(current.Directory.Head.RevocationHash)
            || commitment.PriorDrsRevision == ulong.MaxValue
            || commitment.SuccessorDrsRevision != commitment.PriorDrsRevision + 1
            || commitment.SuccessorDirectory.RevocationRevision != commitment.SuccessorDrsRevision
            || !commitment.SuccessorDirectory.RevocationHash.Equals(commitment.SuccessorDrsHash)
            || !current.Directory.Head.Contains(commitment.RevokedDeviceId)
            || current.Directory.IsLocallyRevoked(commitment.RevokedDeviceId))
            return false;
        var expected = current.Directory.Head.ActiveDevices
            .Where(value => !value.DeviceId.Equals(commitment.RevokedDeviceId)).ToList();
        if (intent.Kind == DeviceMutationKind.Rekey)
        {
            var enrollment = intent.Enrollment; var recovery = intent.RecoveryIntent;
            if (enrollment is null || recovery is null
                || !enrollment.AccountId.Equals(commitment.AccountId)
                || enrollment.AccountGeneration != commitment.AccountGeneration
                || enrollment.RevocationRevision != commitment.SuccessorDrsRevision
                || !enrollment.RevocationHash.Equals(commitment.SuccessorDrsHash)
                || enrollment.DeviceId.Equals(commitment.RevokedDeviceId)
                || current.Directory.Head.Contains(enrollment.DeviceId)
                || current.Directory.IsLocallyRevoked(enrollment.DeviceId)
                || !RecoveryMatches(current.Directory, enrollment, recovery))
                return false;
            expected.Add(new VerifiedActiveDeviceFacts(enrollment.DeviceId, enrollment.CertificateHash));
        }
        else if (intent.Kind != DeviceMutationKind.Revoke || expected.Count == 0)
            return false;
        return expected.OrderBy(static value => value)
            .SequenceEqual(commitment.SuccessorDirectory.ActiveDevices.OrderBy(static value => value))
            && intent.DesiredDevices.OrderBy(static value => value)
                .SequenceEqual(commitment.SuccessorDirectory.ActiveDevices.OrderBy(static value => value));
    }
    private static bool RecoveryMatches(DeviceDirectoryState current, VerifiedEnrollmentDeviceFacts enrollment,
        DeviceRecoveryIntent recovery) =>
        recovery.CreatesNewDevice && recovery.AccountId.Equals(current.Head.AccountId)
        && recovery.AccountGeneration == current.Head.AccountGeneration
        && recovery.TargetDeviceId.Equals(enrollment.DeviceId)
        && (recovery.SourceDeviceId is null || current.Head.Contains(recovery.SourceDeviceId));
    private static bool KeyBelongs(DeviceAccountStateSnapshot current, DeviceRepairKey key) =>
        key.AccountId.Equals(current.Directory.Head.AccountId)
        && key.AccountGeneration == current.Directory.Head.AccountGeneration;
    private static DeviceRevocationSagaSnapshot? FindSaga(DeviceAccountStateSnapshot current,
        DeviceTransactionPlan plan) => current.RevocationSagas.SingleOrDefault(x => x.OperationId.Equals(plan.SagaOperationId!));
    private static IEnumerable<DeviceRevocationSagaSnapshot> ReplaceSaga(DeviceAccountStateSnapshot current,
        DeviceRevocationSagaSnapshot old, DeviceRevocationPhase phase, DeviceRemoteOutcome outcome,
        DeviceRevocationPhase? pending = null, DeviceOperationId32? external = null) =>
        current.RevocationSagas.Select(x => x.OperationId.Equals(old.OperationId)
            ? new DeviceRevocationSagaSnapshot(x.OperationId, x.Intent, phase, outcome, pending, external) : x);
    private static DeviceAccountStateSnapshot Clone(DeviceAccountStateSnapshot current,
        DeviceDirectoryState directory, IEnumerable<DeviceRevocationSagaSnapshot>? sagas = null,
        IEnumerable<DeviceHistoryDecisionSnapshot>? history = null,
        IEnumerable<DeviceRepairSnapshot>? repairs = null) =>
        new(checked(current.Revision + 1), directory, sagas ?? current.RevocationSagas,
            history ?? current.HistoryDecisions, repairs ?? current.Repairs);
    private static DeviceCommitResult Applied(DeviceAccountStateSnapshot snapshot) =>
        new(DeviceCommitDisposition.Applied, snapshot);
}
