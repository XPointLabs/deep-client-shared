using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.DeviceV1;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public enum DeviceRevocationPhase
{
    Prepared = 1, LocalFloorCommitted = 2, PrekeysFenced = 3, DirectoryCommitted = 4,
    CapabilitiesRotated = 5, ContactsNotified = 6, GroupsConverging = 7, Complete = 8,
    ReconcileRequired = 9, Aborted = 10
}
public enum DeviceRemoteOutcome { None = 1, Confirmed = 2, OutcomeUnknown = 3 }
public enum DeviceCommitDisposition
{
    Applied = 1, Idempotent = 2, Missing = 3, StaleRevision = 4, Conflict = 5,
    ForkLatched = 6, InvalidTransition = 7, RepairExhausted = 8
}
public enum DeviceRepairStatus { Active = 1, Completed = 2, Exhausted = 3 }

public sealed class DeviceRepairKey : IEquatable<DeviceRepairKey>
{
    public DeviceRepairKey(DeviceAccountId32 accountId, ulong accountGeneration,
        LogicalMessageId32 logicalMessageId, DeviceAccountId32 recipientAccountId,
        ulong recipientAccountGeneration, DeviceIdentifier32 recipientDeviceId)
    {
        if (accountGeneration == 0 || recipientAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        LogicalMessageId = LogicalMessageId32.FromBytes(logicalMessageId.Span);
        RecipientAccountId = DeviceAccountId32.FromBytes(recipientAccountId.Span);
        RecipientAccountGeneration = recipientAccountGeneration;
        RecipientDeviceId = DeviceIdentifier32.FromBytes(recipientDeviceId.Span);
    }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public LogicalMessageId32 LogicalMessageId { get; }
    public DeviceAccountId32 RecipientAccountId { get; }
    public ulong RecipientAccountGeneration { get; }
    public DeviceIdentifier32 RecipientDeviceId { get; }
    public bool Equals(DeviceRepairKey? other) => other is not null && AccountId.Equals(other.AccountId)
        && AccountGeneration == other.AccountGeneration && LogicalMessageId.Equals(other.LogicalMessageId)
        && RecipientAccountId.Equals(other.RecipientAccountId)
        && RecipientAccountGeneration == other.RecipientAccountGeneration
        && RecipientDeviceId.Equals(other.RecipientDeviceId);
    public override bool Equals(object? obj) => Equals(obj as DeviceRepairKey);
    public override int GetHashCode() => HashCode.Combine(AccountId, AccountGeneration, LogicalMessageId,
        RecipientAccountId, RecipientAccountGeneration, RecipientDeviceId);
    internal string Fingerprint() => string.Join(':', Hex(AccountId), AccountGeneration, Hex(LogicalMessageId),
        Hex(RecipientAccountId), RecipientAccountGeneration, Hex(RecipientDeviceId));
    private static string Hex(DeviceBinaryValue value) => Convert.ToHexString(value.ToArray());
}

public sealed class DeviceRepairSnapshot
{
    internal DeviceRepairSnapshot(DeviceRepairKey key, int attemptsUsed, DeviceRepairStatus status)
    {
        if (attemptsUsed is < 0 or > 2) throw new ArgumentOutOfRangeException(nameof(attemptsUsed));
        Key = key; AttemptsUsed = attemptsUsed; Status = status;
    }
    public DeviceRepairKey Key { get; }
    public int AttemptsUsed { get; }
    public DeviceRepairStatus Status { get; }
}

public sealed class DeviceRevocationSagaSnapshot
{
    internal DeviceRevocationSagaSnapshot(DeviceOperationId32 operationId, DeviceMutationIntent intent,
        DeviceRevocationPhase phase, DeviceRemoteOutcome remoteOutcome,
        DeviceRevocationPhase? pendingPhase = null, DeviceOperationId32? pendingExternalOperationId = null)
    {
        OperationId = DeviceOperationId32.FromBytes(operationId.Span); Intent = intent; Phase = phase;
        RemoteOutcome = remoteOutcome; PendingPhase = pendingPhase;
        PendingExternalOperationId = pendingExternalOperationId is null ? null
            : DeviceOperationId32.FromBytes(pendingExternalOperationId.Span);
    }
    public DeviceOperationId32 OperationId { get; }
    public DeviceMutationIntent Intent { get; }
    public DeviceIdentifier32 RevokedDevice => Intent.ReplacedOrRevokedDevice!;
    public DeviceRevocationPhase Phase { get; }
    public DeviceRemoteOutcome RemoteOutcome { get; }
    public DeviceRevocationPhase? PendingPhase { get; }
    public DeviceOperationId32? PendingExternalOperationId { get; }
    public bool IsTerminal => Phase is DeviceRevocationPhase.Complete or DeviceRevocationPhase.Aborted;
}

public sealed class DeviceHistoryDecisionSnapshot
{
    private readonly byte[]? backup;
    internal DeviceHistoryDecisionSnapshot(DeviceAccountId32 accountId, ulong accountGeneration,
        DeviceIdentifier32 deviceId, DeviceRecoveryMode recoveryMode, DeviceRecoveryOutcome recoveryOutcome,
        DeviceHistoryPolicy historyPolicy, DeviceIdentifier32? sourceDeviceId, byte[]? backupManifestHash)
    {
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        DeviceId = DeviceIdentifier32.FromBytes(deviceId.Span); RecoveryMode = recoveryMode;
        RecoveryOutcome = recoveryOutcome; HistoryPolicy = historyPolicy;
        SourceDeviceId = sourceDeviceId is null ? null : DeviceIdentifier32.FromBytes(sourceDeviceId.Span);
        backup = backupManifestHash?.ToArray();
    }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public DeviceIdentifier32 DeviceId { get; }
    public DeviceRecoveryMode RecoveryMode { get; }
    public DeviceRecoveryOutcome RecoveryOutcome { get; }
    public DeviceHistoryPolicy HistoryPolicy { get; }
    public DeviceIdentifier32? SourceDeviceId { get; }
    public ReadOnlyMemory<byte>? BackupManifestHash => backup is null ? null : backup.ToArray();
    public bool IncludesPrivateDeviceKeysOrRatchetDatabase => false;
    internal static DeviceHistoryDecisionSnapshot FromIntent(DeviceRecoveryIntent intent) =>
        new(intent.AccountId, intent.AccountGeneration, intent.TargetDeviceId, intent.Mode, intent.Outcome,
            intent.HistoryPolicy, intent.SourceDeviceId, intent.BackupManifestHash?.ToArray());
}

public sealed class DeviceAccountStateSnapshot
{
    private readonly DeviceRevocationSagaSnapshot[] sagas;
    private readonly DeviceHistoryDecisionSnapshot[] history;
    private readonly DeviceRepairSnapshot[] repairs;
    internal DeviceAccountStateSnapshot(ulong revision, DeviceDirectoryState directory,
        IEnumerable<DeviceRevocationSagaSnapshot> sagas,
        IEnumerable<DeviceHistoryDecisionSnapshot>? history = null,
        IEnumerable<DeviceRepairSnapshot>? repairs = null)
    {
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        Revision = revision; Directory = directory;
        this.sagas = sagas.Select(Clone).ToArray(); this.history = (history ?? []).ToArray();
        this.repairs = (repairs ?? []).Select(static x => new DeviceRepairSnapshot(x.Key, x.AttemptsUsed, x.Status)).ToArray();
    }
    public ulong Revision { get; }
    public DeviceDirectoryState Directory { get; }
    public IReadOnlyList<DeviceLocalRevocationFloorEntry> LocalRevocationFloor => Directory.LocalRevocationFloor;
    public IReadOnlyList<DeviceRevocationSagaSnapshot> RevocationSagas => Array.AsReadOnly(sagas.Select(Clone).ToArray());
    public IReadOnlyList<DeviceHistoryDecisionSnapshot> HistoryDecisions => Array.AsReadOnly(history.ToArray());
    public IReadOnlyList<DeviceRepairSnapshot> Repairs => Array.AsReadOnly(repairs.Select(static x =>
        new DeviceRepairSnapshot(x.Key, x.AttemptsUsed, x.Status)).ToArray());
    public bool IsLocallyRevoked(DeviceIdentifier32 deviceId) => Directory.IsLocallyRevoked(deviceId);
    internal DeviceRepairSnapshot? FindRepair(DeviceRepairKey key) => repairs.SingleOrDefault(x => x.Key.Equals(key));
    private static DeviceRevocationSagaSnapshot Clone(DeviceRevocationSagaSnapshot x) =>
        new(x.OperationId, x.Intent, x.Phase, x.RemoteOutcome, x.PendingPhase, x.PendingExternalOperationId);
}

public sealed class DeviceStoreReadResult
{
    internal DeviceStoreReadResult(DeviceAccountStateSnapshot? snapshot) => Snapshot = snapshot;
    public bool Found => Snapshot is not null;
    public DeviceAccountStateSnapshot? Snapshot { get; }
}
public sealed class DeviceCommitResult
{
    internal DeviceCommitResult(DeviceCommitDisposition disposition, DeviceAccountStateSnapshot? snapshot)
    { Disposition = disposition; Snapshot = snapshot; }
    public DeviceCommitDisposition Disposition { get; }
    public DeviceAccountStateSnapshot? Snapshot { get; }
}

internal enum DeviceTransactionKind
{
    Bootstrap = 1, InstallDirectory = 2, CommitEnrollment = 3, PrepareRevocation = 4,
    CommitRevocationFloor = 5, AdvanceRevocation = 6, AbortPreparedRevocation = 7,
    AuthorizeRepairAttempt = 8, CompleteRepair = 9
}

public sealed class DeviceTransactionPlan
{
    private DeviceTransactionPlan(DeviceTransactionKind kind, DeviceOperationId32 operationId,
        DeviceAccountId32 accountId, ulong accountGeneration, ulong? expectedRevision,
        VerifiedDeviceDirectoryFacts? candidate = null, DeviceMutationIntent? intent = null,
        DeviceOperationId32? sagaOperationId = null, DeviceRevocationPhase? expectedPhase = null,
        DeviceRevocationPhase? nextPhase = null, DeviceRemoteOutcome outcome = DeviceRemoteOutcome.None,
        DeviceOperationId32? externalOperationId = null, DeviceRepairKey? repairKey = null)
    {
        Kind = kind; OperationId = DeviceOperationId32.FromBytes(operationId.Span);
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        ExpectedRevision = expectedRevision; Candidate = candidate; Intent = intent;
        SagaOperationId = sagaOperationId is null ? null : DeviceOperationId32.FromBytes(sagaOperationId.Span);
        ExpectedPhase = expectedPhase; NextPhase = nextPhase; RemoteOutcome = outcome;
        ExternalOperationId = externalOperationId is null ? null : DeviceOperationId32.FromBytes(externalOperationId.Span);
        RepairKey = repairKey;
    }
    internal DeviceTransactionKind Kind { get; }
    internal DeviceOperationId32 OperationId { get; }
    internal DeviceAccountId32 AccountId { get; }
    internal ulong AccountGeneration { get; }
    internal ulong? ExpectedRevision { get; }
    internal VerifiedDeviceDirectoryFacts? Candidate { get; }
    internal DeviceMutationIntent? Intent { get; }
    internal DeviceOperationId32? SagaOperationId { get; }
    internal DeviceRevocationPhase? ExpectedPhase { get; }
    internal DeviceRevocationPhase? NextPhase { get; }
    internal DeviceRemoteOutcome RemoteOutcome { get; }
    internal DeviceOperationId32? ExternalOperationId { get; }
    internal DeviceRepairKey? RepairKey { get; }

    public static DeviceTransactionPlan Bootstrap(DeviceOperationId32 operationId,
        VerifiedDeviceDirectoryFacts verifiedGenesis) =>
        new(DeviceTransactionKind.Bootstrap, operationId, verifiedGenesis.AccountId,
            verifiedGenesis.AccountGeneration, null, candidate: verifiedGenesis);
    public static DeviceTransactionPlan InstallDirectory(DeviceAccountStateSnapshot current,
        DeviceOperationId32 operationId, VerifiedDeviceDirectoryFacts candidate) =>
        Current(DeviceTransactionKind.InstallDirectory, current, operationId, candidate: candidate);
    public static DeviceTransactionPlan CommitEnrollment(DeviceAccountStateSnapshot current,
        DeviceOperationId32 operationId, DeviceMutationIntent intent, VerifiedDeviceDirectoryFacts successor)
    {
        if (intent.Kind != DeviceMutationKind.Enroll) throw new ArgumentException("Enrollment intent required.", nameof(intent));
        return Current(DeviceTransactionKind.CommitEnrollment, current, operationId, candidate: successor, intent: intent);
    }
    public static DeviceTransactionPlan PrepareRevocation(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceOperationId32 sagaOperationId,
        DeviceMutationIntent intent)
    {
        if (intent.Kind is not (DeviceMutationKind.Revoke or DeviceMutationKind.Rekey))
            throw new ArgumentException("Revocation or rekey intent required.", nameof(intent));
        return Current(DeviceTransactionKind.PrepareRevocation, current, transactionOperationId,
            intent: intent, sagaOperationId: sagaOperationId);
    }
    public static DeviceTransactionPlan CommitRevocationFloor(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceOperationId32 sagaOperationId) =>
        Current(DeviceTransactionKind.CommitRevocationFloor, current, transactionOperationId,
            sagaOperationId: sagaOperationId, expectedPhase: DeviceRevocationPhase.Prepared,
            nextPhase: DeviceRevocationPhase.LocalFloorCommitted);
    public static DeviceTransactionPlan AdvanceRevocation(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceOperationId32 sagaOperationId,
        DeviceRevocationPhase expectedPhase, DeviceRevocationPhase nextPhase, DeviceRemoteOutcome outcome)
    {
        var saga = current.RevocationSagas.SingleOrDefault(x => x.OperationId.Equals(sagaOperationId))
            ?? throw new ArgumentException("Unknown saga.", nameof(sagaOperationId));
        var external = OperationFor(saga.Intent.PlaneOperations!, nextPhase);
        return Current(DeviceTransactionKind.AdvanceRevocation, current, transactionOperationId,
            sagaOperationId: sagaOperationId, expectedPhase: expectedPhase, nextPhase: nextPhase,
            outcome: outcome, externalOperationId: external);
    }
    public static DeviceTransactionPlan AbortPreparedRevocation(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceOperationId32 sagaOperationId) =>
        Current(DeviceTransactionKind.AbortPreparedRevocation, current, transactionOperationId,
            sagaOperationId: sagaOperationId, expectedPhase: DeviceRevocationPhase.Prepared,
            nextPhase: DeviceRevocationPhase.Aborted);
    public static DeviceTransactionPlan AuthorizeRepairAttempt(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceRepairKey key) =>
        Current(DeviceTransactionKind.AuthorizeRepairAttempt, current, transactionOperationId, repairKey: key);
    public static DeviceTransactionPlan CompleteRepair(DeviceAccountStateSnapshot current,
        DeviceOperationId32 transactionOperationId, DeviceRepairKey key) =>
        Current(DeviceTransactionKind.CompleteRepair, current, transactionOperationId, repairKey: key);

    internal string Fingerprint()
    {
        var builder = new StringBuilder();
        builder.Append((int)Kind).Append('|').Append(Hex(AccountId)).Append('|').Append(AccountGeneration)
            .Append('|').Append(ExpectedRevision?.ToString() ?? "-").Append('|').Append(Candidate is null ? "-" : Hex(Candidate.DirectoryHash))
            .Append('|').Append(SagaOperationId is null ? "-" : Hex(SagaOperationId))
            .Append('|').Append(ExternalOperationId is null ? "-" : Hex(ExternalOperationId))
            .Append('|').Append((int?)ExpectedPhase).Append('|').Append((int?)NextPhase).Append('|').Append((int)RemoteOutcome)
            .Append('|').Append(RepairKey?.Fingerprint() ?? "-");
        if (Intent is not null)
        {
            builder.Append('|').Append((int)Intent.Kind).Append(':').Append(Intent.AccountGeneration)
                .Append(':').Append(Hex(Intent.ExpectedDirectoryHash)).Append(':').Append((int)Intent.HistoryPolicy);
            var recovery = Intent.RecoveryIntent;
            builder.Append(':').Append(recovery is null ? "-" : string.Join(',',
                (int)recovery.Mode, (int)recovery.Outcome, recovery.AccountGeneration,
                Hex(recovery.TargetDeviceId), recovery.SourceDeviceId is null ? "-" : Hex(recovery.SourceDeviceId),
                recovery.BackupManifestHash is null ? "-" : Convert.ToHexString(recovery.BackupManifestHash.Value.Span)));
            var revoke = Intent.Revocation;
            builder.Append(':').Append(revoke is null ? "-" : string.Join(',',
                Hex(revoke.PriorDrsHash), Hex(revoke.SuccessorDrsHash),
                Convert.ToHexString(revoke.RevokedDpdReference.Span),
                Convert.ToHexString(revoke.PriorAdcHash.Span), Convert.ToHexString(revoke.SuccessorAdcHash.Span),
                Hex(revoke.SuccessorDirectory.DirectoryHash)));
            var enrollment = Intent.Enrollment;
            builder.Append(':').Append(enrollment is null ? "-" : string.Join(',',
                enrollment.AccountGeneration, enrollment.RevocationRevision, Hex(enrollment.RevocationHash),
                Hex(enrollment.DeviceId), Hex(enrollment.CertificateHash)));
            var operations = Intent.PlaneOperations;
            builder.Append(':').Append(operations is null ? "-" : string.Join(',',
                Hex(operations.Prekeys), Hex(operations.Directory), Hex(operations.Capabilities),
                Hex(operations.Contacts), Hex(operations.Groups), Hex(operations.Completion)));
            builder.Append(':').Append(string.Join(',', Intent.ContactWorklist.Select(Hex)))
                .Append(':').Append(string.Join(',', Intent.GroupWorklist.Select(Hex)))
                .Append(':').Append(string.Join(',', Intent.DesiredDevices.Select(static device =>
                    $"{Hex(device.DeviceId)}.{Hex(device.CertificateHash)}")));
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }

    private static DeviceTransactionPlan Current(DeviceTransactionKind kind, DeviceAccountStateSnapshot current,
        DeviceOperationId32 operationId, VerifiedDeviceDirectoryFacts? candidate = null,
        DeviceMutationIntent? intent = null, DeviceOperationId32? sagaOperationId = null,
        DeviceRevocationPhase? expectedPhase = null, DeviceRevocationPhase? nextPhase = null,
        DeviceRemoteOutcome outcome = DeviceRemoteOutcome.None, DeviceOperationId32? externalOperationId = null,
        DeviceRepairKey? repairKey = null) =>
        new(kind, operationId, current.Directory.Head.AccountId, current.Directory.Head.AccountGeneration,
            current.Revision, candidate, intent, sagaOperationId, expectedPhase, nextPhase,
            outcome, externalOperationId, repairKey);
    private static DeviceOperationId32 OperationFor(DeviceRevocationPlaneOperations operations,
        DeviceRevocationPhase phase) => phase switch
    {
        DeviceRevocationPhase.PrekeysFenced => operations.Prekeys,
        DeviceRevocationPhase.DirectoryCommitted => operations.Directory,
        DeviceRevocationPhase.CapabilitiesRotated => operations.Capabilities,
        DeviceRevocationPhase.ContactsNotified => operations.Contacts,
        DeviceRevocationPhase.GroupsConverging => operations.Groups,
        DeviceRevocationPhase.Complete => operations.Completion,
        _ => throw new ArgumentOutOfRangeException(nameof(phase))
    };
    private static string Hex(DeviceBinaryValue value) => Convert.ToHexString(value.ToArray());
}

public interface IDeviceStateStore
{
    ValueTask<DeviceStoreReadResult> ReadAsync(DeviceAccountId32 accountId, ulong accountGeneration,
        CancellationToken cancellationToken);
    ValueTask<DeviceCommitResult> CommitAsync(DeviceTransactionPlan plan, CancellationToken cancellationToken);
}
