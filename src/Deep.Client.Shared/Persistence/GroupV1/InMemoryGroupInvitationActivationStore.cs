using System.Buffers.Binary;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public sealed class InMemoryGroupInvitationActivationStore : IGroupInvitationActivationStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, ActivationRow> rows = new(StringComparer.Ordinal);

    public InMemoryGroupInvitationActivationStore(GroupStoreScope scope) =>
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));

    public GroupStoreScope Scope { get; }

    public async ValueTask<GroupInvitationActivationStageResult> StageAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default)
    {
        Validate(plan);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var key = Key(plan.ActivationId);
            if (rows.TryGetValue(key, out var current))
            {
                if (!GroupInvitationActivationPlan.Fixed(current.Fingerprint, plan.Fingerprint))
                    current.ConflictLatched = true;
                return new(current.ConflictLatched
                        ? GroupInvitationActivationStageDisposition.ConflictLatched
                        : GroupInvitationActivationStageDisposition.Idempotent,
                    Snapshot(current));
            }

            var row = ActivationRow.From(plan);
            rows.Add(key, row);
            return new(GroupInvitationActivationStageDisposition.Staged, Snapshot(row));
        }
        finally { gate.Release(); }
    }

    public async ValueTask<GroupInvitationActivationSnapshot?> ReadAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return rows.TryGetValue(Key(activationId), out var row) ? Snapshot(row) : null; }
        finally { gate.Release(); }
    }

    public async ValueTask<GroupInvitationControlDispatchLease?> ClaimNextAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!rows.TryGetValue(Key(activationId), out var row))
                throw new InvalidOperationException("The activation journal entry is absent.");
            if (row.ConflictLatched || row.Committed) return null;
            var next = row.Controls.FirstOrDefault(static control => !control.Accepted);
            if (next is null) return null;
            if (row.Controls.Take(next.Ordinal).Any(static control => !control.Accepted))
                throw new InvalidDataException("The activation control journal is out of order.");
            next.Attempts = checked(next.Attempts + 1);
            return new GroupInvitationControlDispatchLease(
                row.ActivationId, next.Ordinal, next.ControlSequence,
                next.OperationId, next.ExactGsw1, next.Attempts);
        }
        finally { gate.Release(); }
    }

    public async ValueTask RecordVerifiedAsync(
        GroupInvitationControlDispatchLease lease,
        VerifiedGroupControlResult verifiedResult,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(verifiedResult);
        var independentlyVerified = GroupControlProductionClient.VerifyResult(
            verifiedResult.Request, verifiedResult.CanonicalBytes);
        if (independentlyVerified.Status is not (GroupControlResultStatus.Committed
                or GroupControlResultStatus.ExactReplay))
            throw new InvalidDataException("Only a verified terminal GSS1 write result may advance activation.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!rows.TryGetValue(Key(lease.ActivationId), out var row))
                throw new InvalidOperationException("The activation journal entry is absent.");
            if (row.ConflictLatched || row.Committed)
                throw new InvalidOperationException("The activation journal is terminal.");
            if (lease.Ordinal < 0 || lease.Ordinal >= row.Controls.Count)
                throw new InvalidDataException("The activation lease ordinal is invalid.");
            var control = row.Controls[lease.Ordinal];
            if (!GroupInvitationActivationPlan.Fixed(control.OperationId, lease.OperationId)
                || !GroupInvitationActivationPlan.Fixed(control.ExactGsw1, lease.ExactGsw1)
                || !GroupInvitationActivationPlan.Fixed(
                    independentlyVerified.Request.OperationId.Span, control.OperationId)
                || !GroupInvitationActivationPlan.Fixed(
                    independentlyVerified.Request.CanonicalBytes.Span, control.ExactGsw1))
                throw new InvalidDataException("GSS1 does not acknowledge the exact durable GSW1 operation.");
            if (row.Controls.Take(control.Ordinal).Any(static earlier => !earlier.Accepted))
                throw new InvalidDataException("A GroupControl result arrived out of order.");
            control.Accepted = true;
            control.ExactGss1 ??= independentlyVerified.CanonicalBytes.ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask MarkStateCommittedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!rows.TryGetValue(Key(activationId), out var row))
                throw new InvalidOperationException("The activation journal entry is absent.");
            if (row.ConflictLatched) throw new InvalidOperationException("The activation journal is fork-latched.");
            if (row.Controls.Any(static control => !control.Accepted))
                throw new InvalidOperationException("GroupClientState cannot commit before all exact GSS1 acknowledgements.");
            row.Committed = true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask MarkConflictLatchedAsync(
        GroupOperationId32 activationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activationId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!rows.TryGetValue(Key(activationId), out var row))
                throw new InvalidOperationException("The activation journal entry is absent.");
            if (!row.Committed) row.ConflictLatched = true;
        }
        finally { gate.Release(); }
    }

    private void Validate(GroupInvitationActivationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!Scope.Equals(plan.Scope))
            throw new ArgumentException("Activation belongs to another account store scope.", nameof(plan));
    }

    private static string Key(GroupOperationId32 activationId) => Convert.ToHexString(activationId.Span);

    private static GroupInvitationActivationSnapshot Snapshot(ActivationRow row)
    {
        var accepted = row.Controls.Count(static control => control.Accepted);
        return new(
            GroupOperationId32.FromBytes(row.ActivationId.Span),
            GroupId32.FromBytes(row.GroupId.Span),
            row.ConflictLatched ? GroupInvitationActivationJournalState.ConflictLatched
                : row.Committed ? GroupInvitationActivationJournalState.Committed
                : accepted == row.Controls.Count ? GroupInvitationActivationJournalState.ReadyToCommit
                : GroupInvitationActivationJournalState.Sending,
            row.Controls.Count,
            accepted,
            row.Controls.Sum(static control => control.Attempts));
    }

    private sealed class ActivationRow
    {
        internal required GroupOperationId32 ActivationId { get; init; }
        internal required GroupId32 GroupId { get; init; }
        internal required byte[] Fingerprint { get; init; }
        internal required byte[] ExactInvitation { get; init; }
        internal required byte[] ExactAcceptance { get; init; }
        internal required byte[] TransitionFingerprint { get; init; }
        internal required List<ControlRow> Controls { get; init; }
        internal bool ConflictLatched { get; set; }
        internal bool Committed { get; set; }

        internal static ActivationRow From(GroupInvitationActivationPlan plan) => new()
        {
            ActivationId = GroupOperationId32.FromBytes(plan.ActivationId.Span),
            GroupId = GroupId32.FromBytes(plan.GroupId.Span),
            Fingerprint = plan.Fingerprint.ToArray(),
            ExactInvitation = plan.ExactInvitation.ToArray(),
            ExactAcceptance = plan.ExactAcceptance.ToArray(),
            TransitionFingerprint = plan.TransitionFingerprint.ToArray(),
            Controls = plan.Controls.Select(static control => new ControlRow
            {
                Ordinal = control.Ordinal,
                ControlSequence = control.ControlSequence,
                OperationId = control.OperationId.ToArray(),
                ExactGsw1 = control.ExactGsw1.ToArray(),
                ExactGcf1 = control.ExactGcf1.ToArray(),
            }).ToList(),
        };
    }

    private sealed class ControlRow
    {
        internal required int Ordinal { get; init; }
        internal required ulong ControlSequence { get; init; }
        internal required byte[] OperationId { get; init; }
        internal required byte[] ExactGsw1 { get; init; }
        internal required byte[] ExactGcf1 { get; init; }
        internal int Attempts { get; set; }
        internal bool Accepted { get; set; }
        internal byte[]? ExactGss1 { get; set; }
    }
}
