using System.Buffers.Binary;

namespace Deep.Client.Shared.Domain.GroupV1;

public static class GroupFanoutLimits
{
    public const int MaximumMembers = 100;
    public const int MaximumTargets = 500;
    public const int MaximumConcurrentLeases = 16;
    public const int MaximumCanonicalEnvelopeBytes = 50_705;
    public static readonly TimeSpan MaximumLeaseDuration = TimeSpan.FromMinutes(5);
}

public sealed class GroupFanoutBatchId32 : GroupBytes32
{
    private GroupFanoutBatchId32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupFanoutBatchId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupFanoutTargetId32 : GroupBytes32
{
    private GroupFanoutTargetId32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupFanoutTargetId32 FromOpaqueBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupFanoutNetworkOperationId32 : GroupBytes32
{
    private GroupFanoutNetworkOperationId32(ReadOnlySpan<byte> value) : base(value, nameof(value)) { }
    public static GroupFanoutNetworkOperationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class GroupFanoutLeaseOwnerId16 : IEquatable<GroupFanoutLeaseOwnerId16>
{
    private readonly byte[] bytes;

    private GroupFanoutLeaseOwnerId16(ReadOnlySpan<byte> value)
    {
        if (value.Length != 16 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 16-byte lease owner is required.", nameof(value));
        bytes = value.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => bytes.ToArray();
    internal ReadOnlySpan<byte> Span => bytes;
    internal byte[] ToArray() => bytes.ToArray();
    public static GroupFanoutLeaseOwnerId16 FromBytes(ReadOnlySpan<byte> value) => new(value);
    public bool Equals(GroupFanoutLeaseOwnerId16? other) =>
        other is not null && bytes.AsSpan().SequenceEqual(other.bytes);
    public override bool Equals(object? obj) => Equals(obj as GroupFanoutLeaseOwnerId16);
    public override int GetHashCode() => BinaryPrimitives.ReadInt32BigEndian(bytes);
    public override string ToString() => "[GroupFanoutLeaseOwnerId16]";
}

public enum GroupFanoutTargetState
{
    Ready = 1,
    NetworkWorkReleased = 2,
    OutcomeUnknown = 3,
    Accepted = 4,
    DefiniteRejected = 5,
    RevokedBeforeSend = 6,
}

public enum GroupFanoutAttemptOutcome
{
    OutcomeUnknown = 1,
    Accepted = 2,
    DefiniteRejected = 3,
}

public enum GroupFanoutDefiniteRejectRule
{
    Terminal = 1,
    RetryWithNewOperation = 2,
}

public sealed class GroupFanoutTargetEnvelope
{
    private readonly byte[] exactCanonicalEnvelope;

    internal GroupFanoutTargetEnvelope(
        GroupFanoutTargetId32 targetId,
        GroupFanoutNetworkOperationId32 initialNetworkOperationId,
        ReadOnlySpan<byte> exactCanonicalEnvelope)
    {
        ArgumentNullException.ThrowIfNull(targetId);
        ArgumentNullException.ThrowIfNull(initialNetworkOperationId);
        if (exactCanonicalEnvelope.Length is < 1 or > GroupFanoutLimits.MaximumCanonicalEnvelopeBytes)
            throw new ArgumentOutOfRangeException(nameof(exactCanonicalEnvelope));

        TargetId = GroupFanoutTargetId32.FromOpaqueBytes(targetId.Span);
        InitialNetworkOperationId = GroupFanoutNetworkOperationId32.FromBytes(initialNetworkOperationId.Span);
        this.exactCanonicalEnvelope = exactCanonicalEnvelope.ToArray();
    }

    internal GroupFanoutTargetId32 TargetId { get; }
    internal GroupFanoutNetworkOperationId32 InitialNetworkOperationId { get; }
    internal ReadOnlyMemory<byte> ExactCanonicalEnvelope => exactCanonicalEnvelope.ToArray();
    internal ReadOnlySpan<byte> EnvelopeSpan => exactCanonicalEnvelope;
    internal GroupFanoutTargetEnvelope Copy() => new(TargetId, InitialNetworkOperationId, exactCanonicalEnvelope);

    /// <summary>
    /// Copies caller-authored canonical envelope bytes into a staging value. This
    /// value is data only and grants no authority to perform network work.
    /// </summary>
    public static GroupFanoutTargetEnvelope FromExactCanonicalEnvelope(
        GroupFanoutTargetId32 targetId,
        GroupFanoutNetworkOperationId32 initialNetworkOperationId,
        ReadOnlySpan<byte> exactCanonicalEnvelope) =>
        new(targetId, initialNetworkOperationId, exactCanonicalEnvelope);
}

public sealed class GroupFanoutAttemptSnapshot
{
    internal GroupFanoutAttemptSnapshot(
        uint attemptNumber,
        GroupFanoutTargetState state,
        bool hasNextAttempt)
    {
        if (attemptNumber == 0) throw new ArgumentOutOfRangeException(nameof(attemptNumber));
        AttemptNumber = attemptNumber;
        State = state;
        HasNextAttempt = hasNextAttempt;
    }

    public uint AttemptNumber { get; }
    public GroupFanoutTargetState State { get; }
    public bool HasNextAttempt { get; }
    internal GroupFanoutAttemptSnapshot Copy() =>
        new(AttemptNumber, State, HasNextAttempt);
}

public sealed class GroupFanoutTargetSnapshot
{
    private readonly GroupFanoutAttemptSnapshot[] attempts;

    internal GroupFanoutTargetSnapshot(
        GroupFanoutTargetId32 targetId,
        GroupFanoutTargetState state,
        uint currentAttemptNumber,
        GroupFanoutLeaseOwnerId16? leaseOwner,
        ulong leaseGeneration,
        DateTimeOffset? leaseExpiresAt,
        IEnumerable<GroupFanoutAttemptSnapshot> attempts)
    {
        TargetId = GroupFanoutTargetId32.FromOpaqueBytes(targetId.Span);
        State = state;
        CurrentAttemptNumber = currentAttemptNumber;
        LeaseOwner = leaseOwner is null ? null : GroupFanoutLeaseOwnerId16.FromBytes(leaseOwner.Span);
        LeaseGeneration = leaseGeneration;
        LeaseExpiresAt = leaseExpiresAt;
        this.attempts = attempts.Select(static value => value.Copy()).ToArray();
    }

    public GroupFanoutTargetId32 TargetId { get; }
    public GroupFanoutTargetState State { get; }
    public uint CurrentAttemptNumber { get; }
    public GroupFanoutLeaseOwnerId16? LeaseOwner { get; }
    public ulong LeaseGeneration { get; }
    public DateTimeOffset? LeaseExpiresAt { get; }
    public IReadOnlyList<GroupFanoutAttemptSnapshot> Attempts =>
        Array.AsReadOnly(attempts.Select(static value => value.Copy()).ToArray());
    internal GroupFanoutTargetSnapshot Copy() => new(
        TargetId, State, CurrentAttemptNumber,
        LeaseOwner, LeaseGeneration, LeaseExpiresAt, attempts);
}

public sealed class GroupFanoutBatchSnapshot
{
    private readonly GroupFanoutTargetSnapshot[] targets;

    internal GroupFanoutBatchSnapshot(
        GroupStoreScope scope,
        GroupFanoutBatchId32 batchId,
        GroupOperationId32 transitionOperationId,
        GroupId32 groupId,
        ushort memberCount,
        ushort verifiedDeviceCount,
        bool conflictLatched,
        DateTimeOffset stagedAt,
        IEnumerable<GroupFanoutTargetSnapshot> targets)
    {
        Scope = new GroupStoreScope(scope.AccountId, scope.AccountGeneration, scope.StoreGeneration);
        BatchId = GroupFanoutBatchId32.FromBytes(batchId.Span);
        TransitionOperationId = GroupOperationId32.FromBytes(transitionOperationId.Span);
        GroupId = GroupId32.FromBytes(groupId.Span);
        MemberCount = memberCount;
        VerifiedDeviceCount = verifiedDeviceCount;
        ConflictLatched = conflictLatched;
        StagedAt = stagedAt;
        this.targets = targets.Select(static value => value.Copy()).ToArray();
    }

    public GroupStoreScope Scope { get; }
    public GroupFanoutBatchId32 BatchId { get; }
    public GroupOperationId32 TransitionOperationId { get; }
    public GroupId32 GroupId { get; }
    public ushort MemberCount { get; }
    public ushort VerifiedDeviceCount { get; }
    public bool ConflictLatched { get; }
    public DateTimeOffset StagedAt { get; }
    public IReadOnlyList<GroupFanoutTargetSnapshot> Targets =>
        Array.AsReadOnly(targets.Select(static value => value.Copy()).ToArray());
    internal GroupFanoutBatchSnapshot Copy() => new(
        Scope, BatchId, TransitionOperationId, GroupId, MemberCount,
        VerifiedDeviceCount, ConflictLatched, StagedAt, targets);
}

/// <summary>
/// Non-forgeable local authority to release one exact target attempt to network work.
/// </summary>
public sealed class GroupFanoutDispatchLease
{
    internal GroupFanoutDispatchLease(
        GroupStoreScope scope,
        GroupFanoutBatchId32 batchId,
        GroupFanoutTargetId32 targetId,
        uint attemptNumber,
        GroupFanoutLeaseOwnerId16 leaseOwner,
        ulong leaseGeneration,
        DateTimeOffset leaseExpiresAt,
        bool retriesOutcomeUnknown)
    {
        Scope = new GroupStoreScope(scope.AccountId, scope.AccountGeneration, scope.StoreGeneration);
        BatchId = GroupFanoutBatchId32.FromBytes(batchId.Span);
        TargetId = GroupFanoutTargetId32.FromOpaqueBytes(targetId.Span);
        AttemptNumber = attemptNumber;
        LeaseOwner = GroupFanoutLeaseOwnerId16.FromBytes(leaseOwner.Span);
        LeaseGeneration = leaseGeneration;
        LeaseExpiresAt = leaseExpiresAt;
        RetriesOutcomeUnknown = retriesOutcomeUnknown;
    }

    public GroupStoreScope Scope { get; }
    public GroupFanoutBatchId32 BatchId { get; }
    public GroupFanoutTargetId32 TargetId { get; }
    public uint AttemptNumber { get; }
    public GroupFanoutLeaseOwnerId16 LeaseOwner { get; }
    public ulong LeaseGeneration { get; }
    public DateTimeOffset LeaseExpiresAt { get; }
    public bool RetriesOutcomeUnknown { get; }
}

/// <summary>
/// Non-forgeable authority returned only after the durable revoke fence has
/// atomically released this exact attempt to network work.
/// </summary>
public sealed class GroupFanoutNetworkWork
{
    private readonly byte[] exactCanonicalEnvelope;

    internal GroupFanoutNetworkWork(
        GroupFanoutDispatchLease lease,
        GroupFanoutNetworkOperationId32 networkOperationId,
        ReadOnlySpan<byte> exactCanonicalEnvelope)
    {
        Lease = lease ?? throw new ArgumentNullException(nameof(lease));
        NetworkOperationId = GroupFanoutNetworkOperationId32.FromBytes(networkOperationId.Span);
        this.exactCanonicalEnvelope = exactCanonicalEnvelope.ToArray();
    }

    internal GroupFanoutDispatchLease Lease { get; }
    public GroupFanoutBatchId32 BatchId => Lease.BatchId;
    public GroupFanoutTargetId32 TargetId => Lease.TargetId;
    public uint AttemptNumber => Lease.AttemptNumber;
    public GroupFanoutNetworkOperationId32 NetworkOperationId { get; }
    public ReadOnlyMemory<byte> ExactCanonicalEnvelope => exactCanonicalEnvelope.ToArray();
    public bool RetriesOutcomeUnknown => Lease.RetriesOutcomeUnknown;
    internal ReadOnlySpan<byte> EnvelopeSpan => exactCanonicalEnvelope;
}
