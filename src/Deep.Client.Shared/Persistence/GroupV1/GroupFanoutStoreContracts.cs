using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public enum GroupFanoutStageDisposition
{
    Staged = 1,
    Idempotent = 2,
    ConflictLatched = 3,
}

public enum GroupFanoutMutationDisposition
{
    Applied = 1,
    Idempotent = 2,
    NotFound = 3,
    LeaseLost = 4,
    AlreadyTerminal = 5,
    RevokedBeforeSend = 6,
    MayHaveForwarded = 7,
    ConflictLatched = 8,
}

public sealed record GroupFanoutStageResult(
    GroupFanoutStageDisposition Disposition,
    GroupFanoutBatchSnapshot Snapshot);

public sealed record GroupFanoutRecoveryResult(
    int RecoveredBeforeSendCount,
    int PromotedToOutcomeUnknownCount);

public sealed record GroupFanoutNetworkWorkResult(
    GroupFanoutMutationDisposition Disposition,
    GroupFanoutNetworkWork? Work);

public sealed class GroupFanoutBatchPlan
{
    private readonly byte[] fingerprint;
    private readonly byte[] packageHash;
    private readonly byte[] verifiedPackageHash;
    private readonly GroupFanoutTargetEnvelope[] targets;

    internal GroupFanoutBatchPlan(
        GroupTransitionCommitPlan transition,
        GroupFanoutBatchId32 batchId,
        IEnumerable<GroupFanoutTargetEnvelope> targets,
        DateTimeOffset stagedAt)
        : this(
            transition?.Scope ?? throw new ArgumentNullException(nameof(transition)),
            transition.OperationId,
            transition.GroupId,
            transition.PackageHash,
            transition.ExactVerifiedGcp1Sha256,
            transition.MemberCount,
            transition.DeviceCount,
            batchId,
            targets,
            stagedAt)
    {
    }

    private GroupFanoutBatchPlan(
        GroupStoreScope scope,
        GroupOperationId32 transitionOperationId,
        GroupId32 groupId,
        ReadOnlySpan<byte> exactPackageHash,
        ReadOnlySpan<byte> exactVerifiedPackageHash,
        ushort memberCount,
        ushort verifiedDeviceCount,
        GroupFanoutBatchId32 batchId,
        IEnumerable<GroupFanoutTargetEnvelope> targets,
        DateTimeOffset stagedAt)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(transitionOperationId);
        ArgumentNullException.ThrowIfNull(groupId);
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(targets);
        if (exactPackageHash.Length != 32) throw new ArgumentException("A 32-byte package hash is required.", nameof(exactPackageHash));
        if (exactVerifiedPackageHash.Length != 32) throw new ArgumentException("A 32-byte verified package hash is required.", nameof(exactVerifiedPackageHash));
        if (memberCount is < 1 or > GroupFanoutLimits.MaximumMembers)
            throw new ArgumentOutOfRangeException(nameof(memberCount));
        if (verifiedDeviceCount is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new ArgumentOutOfRangeException(nameof(verifiedDeviceCount));

        BatchId = GroupFanoutBatchId32.FromBytes(batchId.Span);
        Scope = new GroupStoreScope(
            scope.AccountId,
            scope.AccountGeneration,
            scope.StoreGeneration);
        TransitionOperationId = GroupOperationId32.FromBytes(transitionOperationId.Span);
        GroupId = GroupId32.FromBytes(groupId.Span);
        packageHash = exactPackageHash.ToArray();
        verifiedPackageHash = exactVerifiedPackageHash.ToArray();
        MemberCount = memberCount;
        VerifiedDeviceCount = verifiedDeviceCount;
        this.targets = targets.Select(static target => target.Copy()).ToArray();
        if (this.targets.Length is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new ArgumentOutOfRangeException(nameof(targets));
        if (this.targets.Length > verifiedDeviceCount)
            throw new ArgumentException("Fanout targets exceed the verified active-device count.", nameof(targets));
        if (this.targets.Select(static target => Convert.ToHexString(target.TargetId.Bytes.Span))
            .Distinct(StringComparer.Ordinal).Count() != this.targets.Length)
            throw new ArgumentException("A target device occurs more than once.", nameof(targets));
        if (this.targets.Select(static target => Convert.ToHexString(target.InitialNetworkOperationId.Bytes.Span))
            .Distinct(StringComparer.Ordinal).Count() != this.targets.Length)
            throw new ArgumentException("A network operation identity cannot be shared by two targets.", nameof(targets));

        StagedAt = CanonicalTime(stagedAt);
        fingerprint = ComputeFingerprint(
            Scope,
            BatchId,
            TransitionOperationId,
            GroupId,
            packageHash,
            verifiedPackageHash,
            MemberCount,
            VerifiedDeviceCount,
            this.targets);
    }

#if DEEP_TEST_INTERNALS
    internal static GroupFanoutBatchPlan FromVerifiedTransitionFactsForTests(
        GroupStoreScope scope,
        GroupOperationId32 transitionOperationId,
        GroupId32 groupId,
        ReadOnlySpan<byte> exactPackageHash,
        ReadOnlySpan<byte> exactVerifiedPackageHash,
        ushort memberCount,
        ushort verifiedDeviceCount,
        GroupFanoutBatchId32 batchId,
        IEnumerable<GroupFanoutTargetEnvelope> targets,
        DateTimeOffset stagedAt) => new(
            scope,
            transitionOperationId,
            groupId,
            exactPackageHash,
            exactVerifiedPackageHash,
            memberCount,
            verifiedDeviceCount,
            batchId,
            targets,
            stagedAt);
#endif

    public GroupStoreScope Scope { get; }
    public GroupFanoutBatchId32 BatchId { get; }
    public GroupOperationId32 TransitionOperationId { get; }
    public GroupId32 GroupId { get; }
    public ushort MemberCount { get; }
    public ushort VerifiedDeviceCount { get; }
    public DateTimeOffset StagedAt { get; }
    internal IReadOnlyList<GroupFanoutTargetEnvelope> Targets =>
        Array.AsReadOnly(targets.Select(static target => target.Copy()).ToArray());
    internal ReadOnlySpan<byte> PackageHash => packageHash;
    internal ReadOnlySpan<byte> VerifiedPackageHash => verifiedPackageHash;
    internal ReadOnlySpan<byte> Fingerprint => fingerprint;
    internal IReadOnlyList<GroupFanoutTargetEnvelope> TargetRows => targets;

    internal static byte[] ComputeFingerprint(
        GroupStoreScope scope,
        GroupFanoutBatchId32 batchId,
        GroupOperationId32 transitionOperationId,
        GroupId32 groupId,
        ReadOnlySpan<byte> packageHash,
        ReadOnlySpan<byte> verifiedPackageHash,
        ushort memberCount,
        ushort verifiedDeviceCount,
        IEnumerable<GroupFanoutTargetEnvelope> targets)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, scope.AccountId.Bytes.Span);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, scope.AccountGeneration);
        Append(hash, scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)scope.StoreGeneration));
        Append(hash, scalar);
        Append(hash, batchId.Span);
        Append(hash, transitionOperationId.Span);
        Append(hash, groupId.Span);
        Append(hash, packageHash);
        Append(hash, verifiedPackageHash);
        BinaryPrimitives.WriteUInt16BigEndian(scalar, memberCount);
        hash.AppendData(scalar[..2]);
        BinaryPrimitives.WriteUInt16BigEndian(scalar, verifiedDeviceCount);
        hash.AppendData(scalar[..2]);

        foreach (var target in targets.OrderBy(
                     static target => Convert.ToHexString(target.TargetId.Bytes.Span),
                     StringComparer.Ordinal))
        {
            Append(hash, target.TargetId.Bytes.Span);
            Append(hash, target.InitialNetworkOperationId.Bytes.Span);
            Append(hash, target.EnvelopeSpan);
        }

        return hash.GetHashAndReset();
    }

    internal static DateTimeOffset CanonicalTime(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length);
        hash.AppendData(value);
    }
}

public interface IGroupFanoutStore
{
    GroupStoreScope Scope { get; }

    ValueTask<GroupFanoutStageResult> StageAsync(
        GroupFanoutBatchPlan plan,
        CancellationToken cancellationToken = default);

    ValueTask<GroupFanoutBatchSnapshot?> ReadAsync(
        GroupFanoutBatchId32 batchId,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<GroupFanoutDispatchLease>> ClaimReadyAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        int maximumTargets,
        CancellationToken cancellationToken = default);

    ValueTask<GroupFanoutNetworkWorkResult> BeginNetworkWorkAsync(
        GroupFanoutDispatchLease lease,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    ValueTask<GroupFanoutMutationDisposition> RecordOutcomeAsync(
        GroupFanoutNetworkWork work,
        GroupFanoutAttemptOutcome outcome,
        GroupFanoutDefiniteRejectRule rejectRule = GroupFanoutDefiniteRejectRule.Terminal,
        GroupFanoutNetworkOperationId32? nextNetworkOperationId = null,
        CancellationToken cancellationToken = default);

    ValueTask<GroupFanoutMutationDisposition> RevokeBeforeSendAsync(
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId,
        CancellationToken cancellationToken = default);

    ValueTask<GroupFanoutRecoveryResult> RecoverStaleLeasesAsync(
        GroupFanoutBatchId32 batchId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

internal static class GroupFanoutContractValidation
{
    internal static void ValidateClaim(
        GroupFanoutBatchId32 batchId,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        DateTimeOffset now,
        TimeSpan leaseDuration,
        int maximumTargets)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(leaseOwner);
        _ = GroupFanoutBatchPlan.CanonicalTime(now);
        if (leaseDuration <= TimeSpan.Zero || leaseDuration > GroupFanoutLimits.MaximumLeaseDuration)
            throw new ArgumentOutOfRangeException(nameof(leaseDuration));
        if (maximumTargets is < 1 or > GroupFanoutLimits.MaximumConcurrentLeases)
            throw new ArgumentOutOfRangeException(nameof(maximumTargets));
    }

    internal static void ValidateOutcome(
        GroupFanoutAttemptOutcome outcome,
        GroupFanoutDefiniteRejectRule rejectRule,
        GroupFanoutNetworkOperationId32? nextNetworkOperationId,
        GroupFanoutNetworkWork work)
    {
        if (!Enum.IsDefined(outcome)) throw new ArgumentOutOfRangeException(nameof(outcome));
        if (!Enum.IsDefined(rejectRule)) throw new ArgumentOutOfRangeException(nameof(rejectRule));
        var retry = outcome == GroupFanoutAttemptOutcome.DefiniteRejected
            && rejectRule == GroupFanoutDefiniteRejectRule.RetryWithNewOperation;
        if (retry != (nextNetworkOperationId is not null))
            throw new ArgumentException("A retry requires exactly one explicit next network operation identity.",
                nameof(nextNetworkOperationId));
        if (retry && nextNetworkOperationId!.Equals(work.NetworkOperationId))
            throw new ArgumentException("A definite-reject retry must use a new network operation identity.",
                nameof(nextNetworkOperationId));
        if (outcome != GroupFanoutAttemptOutcome.DefiniteRejected
            && rejectRule != GroupFanoutDefiniteRejectRule.Terminal)
            throw new ArgumentException("Reject retry policy applies only to a definite rejection.", nameof(rejectRule));
    }
}
