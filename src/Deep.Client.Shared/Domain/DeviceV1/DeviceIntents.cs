using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity.DeviceV1;

namespace Deep.Client.Shared.Domain.DeviceV1;

public enum DeviceHistoryPolicy
{ NoHistory = 1, AuthenticatedEncryptedDeviceTransfer = 2, AuthenticatedEncryptedBackup = 3 }
public enum DeviceRecoveryMode
{ ReturningProtectedDevice = 1, PhraseCreatesNewDevice = 2, ExistingDeviceEnrollsNewDevice = 3 }
public enum DeviceRecoveryOutcome
{
    ReturningDeviceLocalStateRequired = 1, NewDeviceWithoutHistory = 2,
    NewDeviceWithEncryptedTransfer = 3, NewDeviceWithEncryptedBackup = 4
}

public sealed class DeviceRecoveryIntent
{
    private readonly byte[]? backupManifestHash;
    private DeviceRecoveryIntent(DeviceRecoveryMode mode, DeviceRecoveryOutcome outcome,
        DeviceAccountId32 accountId, ulong accountGeneration, DeviceIdentifier32 targetDeviceId,
        DeviceIdentifier32? sourceDeviceId, DeviceHistoryPolicy historyPolicy, byte[]? backupManifestHash)
    {
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        if (backupManifestHash is not null && (backupManifestHash.Length != 32
                || backupManifestHash.AsSpan().IndexOfAnyExcept((byte)0) < 0))
            throw new ArgumentException("A verified backup manifest hash must be nonzero and 32 bytes.", nameof(backupManifestHash));
        Mode = mode; Outcome = outcome; AccountId = DeviceAccountId32.FromBytes(accountId.Span);
        AccountGeneration = accountGeneration; TargetDeviceId = DeviceIdentifier32.FromBytes(targetDeviceId.Span);
        SourceDeviceId = sourceDeviceId is null ? null : DeviceIdentifier32.FromBytes(sourceDeviceId.Span);
        HistoryPolicy = historyPolicy; this.backupManifestHash = backupManifestHash?.ToArray();
    }

    public DeviceRecoveryMode Mode { get; }
    public DeviceRecoveryOutcome Outcome { get; }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public DeviceIdentifier32 TargetDeviceId { get; }
    public DeviceIdentifier32? SourceDeviceId { get; }
    public DeviceHistoryPolicy HistoryPolicy { get; }
    public ReadOnlyMemory<byte>? BackupManifestHash => backupManifestHash is null ? null : backupManifestHash.ToArray();
    public bool CreatesNewDevice => Mode != DeviceRecoveryMode.ReturningProtectedDevice;
    public bool ClonesPrivateKeysOrRatchetDatabase => false;

    public static DeviceRecoveryIntent ReturningDevice(DeviceAccountId32 accountId, ulong accountGeneration,
        DeviceIdentifier32 existingDeviceId) =>
        new(DeviceRecoveryMode.ReturningProtectedDevice, DeviceRecoveryOutcome.ReturningDeviceLocalStateRequired,
            accountId, accountGeneration, existingDeviceId, null, DeviceHistoryPolicy.NoHistory, null);

    public static DeviceRecoveryIntent FromPhrase(DeviceAccountId32 accountId, ulong accountGeneration,
        DeviceIdentifier32 independentlyGeneratedNewDeviceId) =>
        new(DeviceRecoveryMode.PhraseCreatesNewDevice, DeviceRecoveryOutcome.NewDeviceWithoutHistory,
            accountId, accountGeneration, independentlyGeneratedNewDeviceId, null, DeviceHistoryPolicy.NoHistory, null);

    public static DeviceRecoveryIntent FromPhrase(VerifiedDeviceBackupAuthorization authorization)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(DeviceRecoveryMode.PhraseCreatesNewDevice, DeviceRecoveryOutcome.NewDeviceWithEncryptedBackup,
            DeviceAccountId32.FromBytes(authorization.AccountId.Span), authorization.AccountGeneration,
            DeviceIdentifier32.FromBytes(authorization.TargetDeviceId.Span), null,
            DeviceHistoryPolicy.AuthenticatedEncryptedBackup, authorization.ManifestHash.ToArray());
    }

    public static DeviceRecoveryIntent FromExistingDeviceWithoutHistory(
        VerifiedDeviceHistoryTransferAuthorization authorization) => FromTransfer(authorization, false);

    public static DeviceRecoveryIntent FromExistingDevice(
        VerifiedDeviceHistoryTransferAuthorization authorization) => FromTransfer(authorization, true);

    private static DeviceRecoveryIntent FromTransfer(VerifiedDeviceHistoryTransferAuthorization authorization,
        bool transferHistory)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        return new(DeviceRecoveryMode.ExistingDeviceEnrollsNewDevice,
            transferHistory ? DeviceRecoveryOutcome.NewDeviceWithEncryptedTransfer : DeviceRecoveryOutcome.NewDeviceWithoutHistory,
            DeviceAccountId32.FromBytes(authorization.AccountId.Span), authorization.AccountGeneration,
            DeviceIdentifier32.FromBytes(authorization.TargetDeviceId.Span),
            DeviceIdentifier32.FromBytes(authorization.SourceDeviceId.Span),
            transferHistory ? DeviceHistoryPolicy.AuthenticatedEncryptedDeviceTransfer : DeviceHistoryPolicy.NoHistory, null);
    }

    internal static DeviceRecoveryIntent RestorePersisted(DeviceRecoveryMode mode, DeviceRecoveryOutcome outcome,
        DeviceAccountId32 accountId, ulong accountGeneration, DeviceIdentifier32 targetDeviceId,
        DeviceIdentifier32? sourceDeviceId, DeviceHistoryPolicy historyPolicy, byte[]? backupManifestHash) =>
        new(mode, outcome, accountId, accountGeneration, targetDeviceId, sourceDeviceId, historyPolicy, backupManifestHash);
}

public sealed class DeviceRevocationPlaneOperations
{
    public DeviceRevocationPlaneOperations(DeviceOperationId32 prekeys, DeviceOperationId32 directory,
        DeviceOperationId32 capabilities, DeviceOperationId32 contacts, DeviceOperationId32 groups,
        DeviceOperationId32 completion)
    {
        var values = new[] { prekeys, directory, capabilities, contacts, groups, completion };
        if (values.Any(static x => x is null) || values.Distinct().Count() != values.Length)
            throw new ArgumentException("Every revocation plane requires one distinct durable operation ID.");
        Prekeys = Copy(prekeys); Directory = Copy(directory); Capabilities = Copy(capabilities);
        Contacts = Copy(contacts); Groups = Copy(groups); Completion = Copy(completion);
    }
    public DeviceOperationId32 Prekeys { get; }
    public DeviceOperationId32 Directory { get; }
    public DeviceOperationId32 Capabilities { get; }
    public DeviceOperationId32 Contacts { get; }
    public DeviceOperationId32 Groups { get; }
    public DeviceOperationId32 Completion { get; }
    private static DeviceOperationId32 Copy(DeviceOperationId32 value)
    { ArgumentNullException.ThrowIfNull(value); return DeviceOperationId32.FromBytes(value.Span); }
}

public sealed class DeviceRevocationCommitment
{
    private readonly byte[] revokedDpdReference;
    private readonly byte[] priorAdcHash;
    private readonly byte[] successorAdcHash;

    private DeviceRevocationCommitment(DeviceAccountId32 accountId, ulong accountGeneration,
        DeviceIdentifier32 revokedDeviceId, byte[] revokedDpdReference, ulong priorDrsRevision,
        DeviceRevocationHash32 priorDrsHash, ulong successorDrsRevision,
        DeviceRevocationHash32 successorDrsHash, VerifiedDeviceDirectoryFacts successorDirectory,
        byte[] priorAdcHash, byte[] successorAdcHash)
    {
        if (revokedDpdReference.Length != ArtifactReference.Length
            || BinaryPrimitives.ReadUInt16BigEndian(revokedDpdReference) != (ushort)ArtifactType.Dpd1
            || BinaryPrimitives.ReadUInt32BigEndian(revokedDpdReference.AsSpan(2)) == 0
            || revokedDpdReference.AsSpan(6).IndexOfAnyExcept((byte)0) < 0
            || priorAdcHash.Length != 32 || priorAdcHash.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || successorAdcHash.Length != 32 || successorAdcHash.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Persisted revocation commitment is malformed.");
        AccountId = DeviceAccountId32.FromBytes(accountId.Span); AccountGeneration = accountGeneration;
        RevokedDeviceId = DeviceIdentifier32.FromBytes(revokedDeviceId.Span);
        this.revokedDpdReference = revokedDpdReference.ToArray(); PriorDrsRevision = priorDrsRevision;
        PriorDrsHash = DeviceRevocationHash32.FromBytes(priorDrsHash.Span);
        SuccessorDrsRevision = successorDrsRevision;
        SuccessorDrsHash = DeviceRevocationHash32.FromBytes(successorDrsHash.Span);
        SuccessorDirectory = successorDirectory;
        this.priorAdcHash = priorAdcHash.ToArray(); this.successorAdcHash = successorAdcHash.ToArray();
    }

    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public DeviceIdentifier32 RevokedDeviceId { get; }
    public ReadOnlyMemory<byte> RevokedDpdReference => revokedDpdReference.ToArray();
    public ulong PriorDrsRevision { get; }
    public DeviceRevocationHash32 PriorDrsHash { get; }
    public ulong SuccessorDrsRevision { get; }
    public DeviceRevocationHash32 SuccessorDrsHash { get; }
    public VerifiedDeviceDirectoryFacts SuccessorDirectory { get; }
    public ReadOnlyMemory<byte> PriorAdcHash => priorAdcHash.ToArray();
    public ReadOnlyMemory<byte> SuccessorAdcHash => successorAdcHash.ToArray();

    internal static DeviceRevocationCommitment FromVerified(VerifiedDeviceControlSuccessor verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        return new(DeviceAccountId32.FromBytes(verified.Revocation.AccountId.Span),
            verified.Revocation.AccountGeneration, DeviceIdentifier32.FromBytes(verified.Revocation.RevokedDeviceId.Span),
            Encode(verified.Revocation.RevokedDpdReference), verified.Revocation.PriorDrsRevision,
            DeviceRevocationHash32.FromBytes(verified.Revocation.PriorDrsHash.Span),
            verified.Revocation.SuccessorDrsRevision,
            DeviceRevocationHash32.FromBytes(verified.Revocation.SuccessorDrsHash.Span),
            VerifiedDeviceDirectoryFacts.FromVerified(verified.Directory),
            verified.AccountDirectory.PriorAdcHash.ToArray(), verified.AccountDirectory.SuccessorAdcHash.ToArray());
    }

    internal static DeviceRevocationCommitment RestorePersisted(DeviceAccountId32 accountId,
        ulong accountGeneration, DeviceIdentifier32 revokedDeviceId, byte[] revokedDpdReference,
        ulong priorDrsRevision, DeviceRevocationHash32 priorDrsHash, ulong successorDrsRevision,
        DeviceRevocationHash32 successorDrsHash, VerifiedDeviceDirectoryFacts successorDirectory,
        byte[] priorAdcHash, byte[] successorAdcHash) =>
        new(accountId, accountGeneration, revokedDeviceId, revokedDpdReference, priorDrsRevision,
            priorDrsHash, successorDrsRevision, successorDrsHash, successorDirectory, priorAdcHash, successorAdcHash);

    private static byte[] Encode(ArtifactReference reference)
    {
        var bytes = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)reference.Type);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(2), reference.CanonicalLength);
        reference.CanonicalHash.Span.CopyTo(bytes.AsSpan(6)); return bytes;
    }
}

public enum DeviceMutationKind { Enroll = 1, Revoke = 2, Rekey = 3 }

public sealed class DeviceMutationIntent
{
    private readonly VerifiedActiveDeviceFacts[] desiredDevices;
    private readonly DeviceContactWorkItemId32[] contactWorklist;
    private readonly DeviceGroupWorkItemId32[] groupWorklist;
    private DeviceMutationIntent(DeviceMutationKind kind, DeviceDirectoryState current,
        VerifiedEnrollmentDeviceFacts? enrollment, DeviceRevocationCommitment? revocation,
        DeviceRecoveryIntent? recovery, DeviceRevocationPlaneOperations? planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups,
        IEnumerable<VerifiedActiveDeviceFacts> desired)
        : this(kind, current.Head.AccountId, current.Head.AccountGeneration, current.Head.DirectoryGeneration,
            current.Head.DirectoryHash, enrollment, revocation, recovery, planeOperations, contacts, groups, desired)
    { }

    private DeviceMutationIntent(DeviceMutationKind kind, DeviceAccountId32 accountId, ulong accountGeneration,
        ulong expectedDirectoryGeneration, DeviceDirectoryHash32 expectedDirectoryHash,
        VerifiedEnrollmentDeviceFacts? enrollment, DeviceRevocationCommitment? revocation,
        DeviceRecoveryIntent? recovery, DeviceRevocationPlaneOperations? planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups,
        IEnumerable<VerifiedActiveDeviceFacts> desired)
    {
        Kind = kind; AccountId = DeviceAccountId32.FromBytes(accountId.Span);
        AccountGeneration = accountGeneration; ExpectedDirectoryGeneration = expectedDirectoryGeneration;
        ExpectedDirectoryHash = DeviceDirectoryHash32.FromBytes(expectedDirectoryHash.Span);
        Enrollment = enrollment; Revocation = revocation; RecoveryIntent = recovery; PlaneOperations = planeOperations;
        desiredDevices = desired.OrderBy(static x => x).ToArray();
        contactWorklist = CanonicalContacts(contacts); groupWorklist = CanonicalGroups(groups);
    }
    public DeviceMutationKind Kind { get; }
    public DeviceAccountId32 AccountId { get; }
    public ulong AccountGeneration { get; }
    public ulong ExpectedDirectoryGeneration { get; }
    public DeviceDirectoryHash32 ExpectedDirectoryHash { get; }
    public DeviceIdentifier32? ReplacedOrRevokedDevice => Revocation?.RevokedDeviceId;
    public VerifiedEnrollmentDeviceFacts? Enrollment { get; }
    public DeviceRevocationCommitment? Revocation { get; }
    public DeviceRecoveryIntent? RecoveryIntent { get; }
    public DeviceHistoryPolicy HistoryPolicy => RecoveryIntent?.HistoryPolicy ?? DeviceHistoryPolicy.NoHistory;
    public DeviceRevocationPlaneOperations? PlaneOperations { get; }
    public IReadOnlyList<DeviceContactWorkItemId32> ContactWorklist => Array.AsReadOnly(contactWorklist.ToArray());
    public IReadOnlyList<DeviceGroupWorkItemId32> GroupWorklist => Array.AsReadOnly(groupWorklist.ToArray());
    public IReadOnlyList<VerifiedActiveDeviceFacts> DesiredDevices => Array.AsReadOnly(desiredDevices.ToArray());
    public bool ClonesPrivateKeysOrRatchetDatabase => false;

    internal static DeviceMutationIntent RestorePersisted(DeviceMutationKind kind, DeviceAccountId32 accountId,
        ulong accountGeneration, ulong expectedDirectoryGeneration, DeviceDirectoryHash32 expectedDirectoryHash,
        VerifiedEnrollmentDeviceFacts? enrollment, DeviceRevocationCommitment? revocation,
        DeviceRecoveryIntent? recovery, DeviceRevocationPlaneOperations? planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups,
        IEnumerable<VerifiedActiveDeviceFacts> desired) =>
        new(kind, accountId, accountGeneration, expectedDirectoryGeneration, expectedDirectoryHash,
            enrollment, revocation, recovery, planeOperations, contacts, groups, desired);

    public static DeviceMutationIntent Enroll(DeviceDirectoryState current,
        VerifiedEnrollmentDeviceFacts newDevice, DeviceRecoveryIntent recovery)
    {
        ValidateCurrent(current); ValidateEnrollment(current, newDevice, false); ValidateRecovery(current, newDevice, recovery);
        if (current.Head.ActiveDevices.Count >= 16) throw new InvalidOperationException("DMD1 permits at most sixteen active devices.");
        return new(DeviceMutationKind.Enroll, current, newDevice, null, recovery, null, [], [],
            current.Head.ActiveDevices.Append(new VerifiedActiveDeviceFacts(newDevice.DeviceId, newDevice.CertificateHash)));
    }

    public static DeviceMutationIntent Revoke(DeviceDirectoryState current,
        VerifiedDeviceControlSuccessor verifiedControl, DeviceRevocationPlaneOperations planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups)
        => RevokeCore(DeviceMutationKind.Revoke, current, verifiedControl, null, null, planeOperations, contacts, groups);

    public static DeviceMutationIntent Rekey(DeviceDirectoryState current,
        VerifiedDeviceControlSuccessor verifiedControl, VerifiedEnrollmentDeviceFacts independentlyKeyedReplacement,
        DeviceRecoveryIntent recovery, DeviceRevocationPlaneOperations planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups)
        => RevokeCore(DeviceMutationKind.Rekey, current, verifiedControl, independentlyKeyedReplacement,
            recovery, planeOperations, contacts, groups);

    private static DeviceMutationIntent RevokeCore(DeviceMutationKind kind, DeviceDirectoryState current,
        VerifiedDeviceControlSuccessor verifiedControl, VerifiedEnrollmentDeviceFacts? replacement,
        DeviceRecoveryIntent? recovery, DeviceRevocationPlaneOperations planeOperations,
        IEnumerable<DeviceContactWorkItemId32> contacts, IEnumerable<DeviceGroupWorkItemId32> groups)
    {
        ValidateCurrent(current); ArgumentNullException.ThrowIfNull(verifiedControl);
        ArgumentNullException.ThrowIfNull(planeOperations); ArgumentNullException.ThrowIfNull(contacts);
        ArgumentNullException.ThrowIfNull(groups);
        var commitment = DeviceRevocationCommitment.FromVerified(verifiedControl);
        if (!commitment.AccountId.Equals(current.Head.AccountId)
            || commitment.AccountGeneration != current.Head.AccountGeneration
            || commitment.PriorDrsRevision != current.Head.RevocationRevision
            || !commitment.PriorDrsHash.Equals(current.Head.RevocationHash)
            || commitment.SuccessorDrsRevision != commitment.PriorDrsRevision + 1
            || !current.Head.Contains(commitment.RevokedDeviceId)
            || current.IsLocallyRevoked(commitment.RevokedDeviceId))
            throw new InvalidOperationException("The sealed revocation successor is not the exact current account closure.");
        var transition = current.PrepareTransition(commitment.SuccessorDirectory);
        if (transition.Disposition != DeviceDirectoryTransitionDisposition.AcceptedSuccessor)
            throw new InvalidOperationException("The sealed DMD1 is not the exact next directory successor.");
        if (kind == DeviceMutationKind.Revoke)
        {
            var expected = current.Head.ActiveDevices
                .Where(value => !value.DeviceId.Equals(commitment.RevokedDeviceId))
                .OrderBy(static value => value).ToArray();
            if (expected.Length == 0)
                throw new InvalidOperationException("Revocation cannot remove the final device.");
            if (!expected.SequenceEqual(commitment.SuccessorDirectory.ActiveDevices.OrderBy(static value => value)))
                throw new InvalidOperationException("A revoke successor must remove exactly one device and change no other membership.");
        }
        else
        {
            ArgumentNullException.ThrowIfNull(replacement); ArgumentNullException.ThrowIfNull(recovery);
            ValidateEnrollment(current, replacement, true); ValidateRecovery(current, replacement, recovery);
            if (replacement.DeviceId.Equals(commitment.RevokedDeviceId) || current.IsLocallyRevoked(replacement.DeviceId)
                || !commitment.SuccessorDrsHash.Equals(replacement.RevocationHash)
                || commitment.SuccessorDrsRevision != replacement.RevocationRevision
                || !commitment.SuccessorDirectory.Contains(replacement.DeviceId))
                throw new InvalidOperationException("Rekey must use a distinct independently verified replacement in the exact successor closure.");
            var expected = current.Head.ActiveDevices
                .Where(value => !value.DeviceId.Equals(commitment.RevokedDeviceId))
                .Append(new VerifiedActiveDeviceFacts(replacement.DeviceId, replacement.CertificateHash))
                .OrderBy(static value => value).ToArray();
            if (!expected.SequenceEqual(commitment.SuccessorDirectory.ActiveDevices.OrderBy(static value => value)))
                throw new InvalidOperationException("A rekey successor must replace exactly one device and change no other membership.");
        }
        var desired = commitment.SuccessorDirectory.ActiveDevices;
        return new(kind, current, replacement, commitment, recovery, planeOperations, contacts, groups, desired);
    }

    private static void ValidateCurrent(DeviceDirectoryState current)
    { ArgumentNullException.ThrowIfNull(current); if (current.ForkLatched) throw new InvalidOperationException("Fork-latched state cannot authorize mutation."); }
    private static void ValidateEnrollment(DeviceDirectoryState current, VerifiedEnrollmentDeviceFacts enrollment, bool successor)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        if (!current.Head.AccountId.Equals(enrollment.AccountId) || current.Head.AccountGeneration != enrollment.AccountGeneration
            || current.Head.Contains(enrollment.DeviceId) || current.IsLocallyRevoked(enrollment.DeviceId)
            || (!successor && (current.Head.RevocationRevision != enrollment.RevocationRevision
                || !current.Head.RevocationHash.Equals(enrollment.RevocationHash))))
            throw new InvalidOperationException("The verified enrollment DPD1 is not eligible for this account generation.");
    }
    private static void ValidateRecovery(DeviceDirectoryState current, VerifiedEnrollmentDeviceFacts enrollment,
        DeviceRecoveryIntent recovery)
    {
        ArgumentNullException.ThrowIfNull(recovery);
        if (!recovery.CreatesNewDevice || !recovery.AccountId.Equals(current.Head.AccountId)
            || recovery.AccountGeneration != current.Head.AccountGeneration
            || !recovery.TargetDeviceId.Equals(enrollment.DeviceId)
            || (recovery.SourceDeviceId is not null && !current.Head.Contains(recovery.SourceDeviceId)))
            throw new InvalidOperationException("Enrollment requires an exact sealed new-device recovery intent.");
    }
    private static DeviceContactWorkItemId32[] CanonicalContacts(IEnumerable<DeviceContactWorkItemId32> values)
    {
        var result = values.Select(static x => DeviceContactWorkItemId32.FromBytes(x.Span)).OrderBy(static x => x).ToArray();
        if (result.Length > 4096 || result.Distinct().Count() != result.Length) throw new ArgumentException("Contact worklist is duplicate or exceeds 4096 entries.");
        return result;
    }
    private static DeviceGroupWorkItemId32[] CanonicalGroups(IEnumerable<DeviceGroupWorkItemId32> values)
    {
        var result = values.Select(static x => DeviceGroupWorkItemId32.FromBytes(x.Span)).OrderBy(static x => x).ToArray();
        if (result.Length > 500 || result.Distinct().Count() != result.Length) throw new ArgumentException("Group worklist is duplicate or exceeds 500 entries.");
        return result;
    }
}
