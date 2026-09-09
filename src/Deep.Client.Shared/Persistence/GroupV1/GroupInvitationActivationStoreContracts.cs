using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public enum GroupInvitationActivationJournalState
{
    Sending = 1,
    ReadyToCommit = 2,
    Committed = 3,
    ConflictLatched = 4,
}

public enum GroupInvitationActivationStageDisposition
{
    Staged = 1,
    Idempotent = 2,
    ConflictLatched = 3,
}

public sealed record GroupInvitationActivationStageResult(
    GroupInvitationActivationStageDisposition Disposition,
    GroupInvitationActivationSnapshot Snapshot);

public sealed record GroupInvitationActivationSnapshot(
    GroupOperationId32 ActivationId,
    GroupId32 GroupId,
    GroupInvitationActivationJournalState State,
    int ControlCount,
    int AcceptedControlCount,
    int NetworkAttemptCount);

/// <summary>
/// Durable, capability-free lease for one exact GSW1 operation. The verified
/// request capability is deliberately supplied again by the current process
/// and must match these sealed bytes before it can be used.
/// </summary>
public sealed class GroupInvitationControlDispatchLease
{
    private readonly byte[] operationId;
    private readonly byte[] exactGsw1;

    internal GroupInvitationControlDispatchLease(
        GroupOperationId32 activationId,
        int ordinal,
        ulong controlSequence,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactGsw1,
        int attempt)
    {
        ActivationId = GroupOperationId32.FromBytes(activationId.Span);
        Ordinal = ordinal;
        ControlSequence = controlSequence;
        this.operationId = operationId.ToArray();
        this.exactGsw1 = exactGsw1.ToArray();
        Attempt = attempt;
    }

    public GroupOperationId32 ActivationId { get; }
    public int Ordinal { get; }
    public ulong ControlSequence { get; }
    public int Attempt { get; }
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> ExactGsw1 => exactGsw1;
}

public interface IGroupInvitationActivationStore
{
    GroupStoreScope Scope { get; }

    ValueTask<GroupInvitationActivationStageResult> StageAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default);

    ValueTask<GroupInvitationActivationSnapshot?> ReadAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default);

    ValueTask<GroupInvitationControlDispatchLease?> ClaimNextAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default);

    ValueTask RecordVerifiedAsync(
        GroupInvitationControlDispatchLease lease,
        VerifiedGroupControlResult verifiedResult,
        CancellationToken cancellationToken = default);

    ValueTask MarkStateCommittedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default);

    ValueTask MarkConflictLatchedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default);
}

public sealed class GroupInvitationActivationPlan
{
    private readonly byte[] fingerprint;
    private readonly byte[] exactInvitation;
    private readonly byte[] exactAcceptance;
    private readonly GroupInvitationControlPlan[] controls;

    internal GroupInvitationActivationPlan(
        GroupOperationId32 activationId,
        GroupTransitionCommitPlan transition,
        ReadOnlySpan<byte> exactInvitation,
        ReadOnlySpan<byte> exactAcceptance,
        IReadOnlyList<GroupInvitationControlPlan> controls)
    {
        ActivationId = GroupOperationId32.FromBytes(activationId.Span);
        Transition = transition ?? throw new ArgumentNullException(nameof(transition));
        GroupId = GroupId32.FromBytes(transition.GroupId.Span);
        this.exactInvitation = exactInvitation.ToArray();
        this.exactAcceptance = exactAcceptance.ToArray();
        this.controls = controls.Select(static value => value.Copy()).ToArray();
        fingerprint = ComputeFingerprint(
            Scope, ActivationId, transition.Fingerprint, this.exactInvitation,
            this.exactAcceptance, this.controls);
    }

    public GroupOperationId32 ActivationId { get; }
    public GroupId32 GroupId { get; }
    public int ControlCount => controls.Length;
    internal GroupStoreScope Scope => Transition.Scope;
    internal GroupTransitionCommitPlan Transition { get; }
    internal ReadOnlySpan<byte> Fingerprint => fingerprint;
    internal ReadOnlySpan<byte> TransitionFingerprint => Transition.Fingerprint;
    internal ReadOnlySpan<byte> ExactInvitation => exactInvitation;
    internal ReadOnlySpan<byte> ExactAcceptance => exactAcceptance;
    internal IReadOnlyList<GroupInvitationControlPlan> Controls => controls;

    internal VerifiedGroupControlWriteRequest RequireCapability(
        GroupInvitationControlDispatchLease lease)
    {
        if (!ActivationId.Equals(lease.ActivationId)
            || lease.Ordinal < 0
            || lease.Ordinal >= controls.Length)
            throw new InvalidDataException("The activation dispatch lease is foreign.");
        var control = controls[lease.Ordinal];
        if (control.ControlSequence != lease.ControlSequence
            || !Fixed(control.OperationId, lease.OperationId)
            || !Fixed(control.ExactGsw1, lease.ExactGsw1))
            throw new InvalidDataException("The restored GroupControl capability differs from the durable GSW1 operation.");
        return control.Request;
    }

    internal static byte[] ComputeFingerprint(
        GroupStoreScope scope,
        GroupOperationId32 activationId,
        ReadOnlySpan<byte> transitionFingerprint,
        ReadOnlySpan<byte> invitation,
        ReadOnlySpan<byte> acceptance,
        IReadOnlyList<GroupInvitationControlPlan> controls)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, scope.AccountId.Bytes.Span);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, scope.AccountGeneration); Append(hash, scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)scope.StoreGeneration)); Append(hash, scalar);
        Append(hash, activationId.Span); Append(hash, transitionFingerprint);
        Append(hash, invitation); Append(hash, acceptance);
        foreach (var control in controls.OrderBy(static value => value.Ordinal))
        {
            BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)control.Ordinal)); Append(hash, scalar);
            BinaryPrimitives.WriteUInt64BigEndian(scalar, control.ControlSequence); Append(hash, scalar);
            Append(hash, control.OperationId); Append(hash, control.ExactGsw1); Append(hash, control.ExactGcf1);
        }
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, value.Length);
        hash.AppendData(length); hash.AppendData(value);
    }

    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class GroupInvitationControlPlan
{
    private readonly byte[] operationId;
    private readonly byte[] exactGsw1;
    private readonly byte[] exactGcf1;

    internal GroupInvitationControlPlan(
        int ordinal,
        ulong controlSequence,
        VerifiedGroupControlWriteRequest request,
        ReadOnlySpan<byte> exactGcf1)
    {
        Ordinal = ordinal;
        ControlSequence = controlSequence;
        Request = request ?? throw new ArgumentNullException(nameof(request));
        operationId = request.OperationId.ToArray();
        exactGsw1 = request.CanonicalBytes.ToArray();
        this.exactGcf1 = exactGcf1.ToArray();
    }

    internal int Ordinal { get; }
    internal ulong ControlSequence { get; }
    internal VerifiedGroupControlWriteRequest Request { get; }
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> ExactGsw1 => exactGsw1;
    internal ReadOnlySpan<byte> ExactGcf1 => exactGcf1;
    internal GroupInvitationControlPlan Copy() => new(Ordinal, ControlSequence, Request, exactGcf1);
}
