using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

public enum GroupInvitationActivationDisposition
{
    Activated = 1,
    Idempotent = 2,
    Deferred = 3,
    OutOfOrder = 4,
    StateChanged = 5,
    ConflictLatched = 6,
}

public sealed record GroupInvitationActivationResult(
    GroupInvitationActivationDisposition Disposition,
    GroupInvitationActivationSnapshot Journal,
    GroupCommitResult? StateCommit,
    GroupControlResultStatus? LastControlStatus);

internal enum GroupInvitationActivationFailpoint
{
    AfterStage = 1,
    AfterVerifiedControlBeforeAck = 2,
    BeforeStateCommit = 3,
    AfterStateCommitBeforeJournalCommit = 4,
}

internal interface IGroupInvitationActivationFailpoint
{
    ValueTask HitAsync(
        GroupInvitationActivationFailpoint point,
        CancellationToken cancellationToken);
}

/// <summary>
/// Verifies the complete activation authoring closure and produces one bounded
/// restart-safe plan. It never seals GCF1 or accepts caller-supplied trust.
/// </summary>
public sealed class GroupInvitationActivationPlanner
{
    private const int MaximumControlChunks = 64;
    private readonly GroupClientStateService stateService = new();

    public GroupInvitationActivationPlan Prepare(
        GroupStoreScope scope,
        GroupOperationId32 activationId,
        ulong expectedRevision,
        VerifiedGroupInvitation invitation,
        VerifiedGroupInvitationAcceptance acceptance,
        VerifiedAuthoredGroupTransition activation,
        IReadOnlyList<GroupCommitChunkRecord> exactChunks,
        IReadOnlyList<VerifiedGroupControlWriteRequest> controlWrites)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(activationId);
        ArgumentNullException.ThrowIfNull(invitation);
        ArgumentNullException.ThrowIfNull(acceptance);
        ArgumentNullException.ThrowIfNull(activation);
        ArgumentNullException.ThrowIfNull(exactChunks);
        ArgumentNullException.ThrowIfNull(controlWrites);
        if (expectedRevision == 0) throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        if (exactChunks.Count is < 1 or > MaximumControlChunks
            || controlWrites.Count != exactChunks.Count)
            throw new ArgumentException("Activation requires one bounded GSW1 operation per exact GCF1 chunk.");

        var transition = activation.Transition;
        var predecessor = transition.Predecessor ?? throw new ArgumentException(
            "Invitation activation cannot be a genesis transition.", nameof(activation));
        if (!Fixed(invitation.BaseState.Commit.ArtifactHash.Span, predecessor.ArtifactHash.Span)
            || !Fixed(acceptance.Invitation.Record.CanonicalBytes.Span, invitation.Record.CanonicalBytes.Span)
            || !Fixed(invitation.Record.Field(1).Span, predecessor.Field(1).Span)
            || !Fixed(invitation.Record.Field(2).Span, predecessor.Field(2).Span)
            || !Fixed(invitation.Record.Field(5).Span, predecessor.ArtifactHash.Span)
            || !Fixed(acceptance.Record.Field(1).Span, invitation.Record.Field(1).Span)
            || !Fixed(acceptance.Record.Field(2).Span, invitation.Record.Field(2).Span)
            || !Fixed(acceptance.Record.Field(3).Span, invitation.Record.Field(3).Span)
            || acceptance.Record.Field(4).Length != 38
            || !Fixed(acceptance.Record.Field(4).Span[6..], invitation.Record.ArtifactHash.Span))
            throw new ArgumentException("The invitation/acceptance capabilities do not bind the activation predecessor.");

        var commitPlan = stateService.PrepareVerifiedTransition(
            scope, activationId, expectedRevision, transition, activation.Package, exactChunks);
        RequireExactEmbeddedArtifact(commitPlan, "GIV1", invitation.Record);
        RequireExactEmbeddedArtifact(commitPlan, "GIA1", acceptance.Record);

        var orderedChunks = exactChunks
            .OrderBy(static chunk => U32(chunk.Field(4).Span))
            .ToArray();
        var controls = new GroupInvitationControlPlan[controlWrites.Count];
        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        byte[]? priorWriteHash = null;
        ulong? priorSequence = null;
        for (var index = 0; index < controlWrites.Count; index++)
        {
            var request = controlWrites[index] ?? throw new ArgumentException(
                "A GroupControl write capability is absent.", nameof(controlWrites));
            if (request.Kind != GroupControlRequestKind.Write
                || !Fixed(request.Group.Commit.ArtifactHash.Span, predecessor.ArtifactHash.Span)
                || !Fixed(request.GroupId.Span, commitPlan.GroupId.Span)
                || !Fixed(request.Group.Commit.Field(1).Span, commitPlan.NetworkId)
                || !Fixed(request.CanonicalBytes.Span, request.Record.CanonicalBytes.Span))
                throw new ArgumentException("GSW1 is not bound to the exact activation base state.", nameof(controlWrites));
            var sequence = U64(request.Record.Field(18).Span);
            if (priorSequence.HasValue && (sequence != priorSequence.Value + 1
                    || priorWriteHash is null
                    || !Fixed(request.Record.Field(19).Span, priorWriteHash)))
                throw new ArgumentException("GSW1 controls are not one canonical predecessor-linked sequence.", nameof(controlWrites));
            if (!operationIds.Add(Convert.ToHexString(request.OperationId.Span)))
                throw new ArgumentException("GSW1 operation IDs must be unique and stable.", nameof(controlWrites));
            controls[index] = new GroupInvitationControlPlan(
                index, sequence, request, orderedChunks[index].CanonicalBytes.Span);
            priorSequence = sequence;
            priorWriteHash = request.Record.ArtifactHash.ToArray();
        }

        return new GroupInvitationActivationPlan(
            activationId, commitPlan, invitation.Record.CanonicalBytes.Span,
            acceptance.Record.CanonicalBytes.Span, controls);
    }

    private static void RequireExactEmbeddedArtifact(
        GroupTransitionCommitPlan plan,
        string magic,
        GroupRecord record)
    {
        if (!plan.Artifacts.Any(artifact => artifact.Magic == magic
                && Fixed(artifact.Hash.Span, record.ArtifactHash.Span)
                && Fixed(artifact.ExactCanonicalBytes.Span, record.CanonicalBytes.Span)))
            throw new ArgumentException($"The exact {magic} capability is absent from verified GCP1.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static uint U32(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt32BigEndian(value);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}

/// <summary>
/// At-least-once GroupControl delivery followed by one monotonic GroupClientState
/// commit. A process crash can only cause the same exact operation ID/GSW1 to be
/// retried; it cannot skip GSS1 verification or commit an unstored chunk.
/// </summary>
public sealed class GroupInvitationActivationOrchestrator
{
    private readonly IGroupInvitationActivationStore journal;
    private readonly IGroupStateStore groups;
    private readonly IDeepGroupControlTransport transport;
    private readonly IGroupInvitationActivationFailpoint? failpoint;

    public GroupInvitationActivationOrchestrator(
        IGroupInvitationActivationStore journal,
        IGroupStateStore groups,
        IDeepGroupControlTransport transport)
        : this(journal, groups, transport, null) { }

    internal GroupInvitationActivationOrchestrator(
        IGroupInvitationActivationStore journal,
        IGroupStateStore groups,
        IDeepGroupControlTransport transport,
        IGroupInvitationActivationFailpoint? failpoint)
    {
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        this.groups = groups ?? throw new ArgumentNullException(nameof(groups));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.failpoint = failpoint;
        if (!journal.Scope.Equals(groups.Scope))
            throw new ArgumentException("Activation journal and GroupClientState belong to different account generations.");
    }

    public async ValueTask<GroupInvitationActivationResult> RunAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!journal.Scope.Equals(plan.Scope))
            throw new ArgumentException("The activation plan belongs to another account generation.", nameof(plan));
        var staged = await journal.StageAsync(plan, cancellationToken).ConfigureAwait(false);
        if (staged.Disposition == GroupInvitationActivationStageDisposition.ConflictLatched)
            return new(GroupInvitationActivationDisposition.ConflictLatched, staged.Snapshot, null, null);
        if (staged.Snapshot.State == GroupInvitationActivationJournalState.Committed)
            return new(GroupInvitationActivationDisposition.Idempotent, staged.Snapshot, null, null);
        await HitAsync(GroupInvitationActivationFailpoint.AfterStage, cancellationToken).ConfigureAwait(false);

        if (staged.Snapshot.State == GroupInvitationActivationJournalState.Sending)
        {
            var predecessorDisposition = await RequireCurrentPredecessorAsync(
                plan, staged.Snapshot, cancellationToken).ConfigureAwait(false);
            if (predecessorDisposition is not null)
                return predecessorDisposition;
        }

        GroupControlResultStatus? lastStatus = null;
        while (true)
        {
            var lease = await journal.ClaimNextAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false);
            if (lease is null) break;
            var request = plan.RequireCapability(lease);
            var exactGss1 = await transport.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
            var verified = GroupControlProductionClient.VerifyResult(request, exactGss1);
            lastStatus = verified.Status;
            if (verified.Status is not (GroupControlResultStatus.Committed or GroupControlResultStatus.ExactReplay))
            {
                var deferred = (await journal.ReadAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false))!;
                return new(GroupInvitationActivationDisposition.Deferred, deferred, null, lastStatus);
            }
            await HitAsync(GroupInvitationActivationFailpoint.AfterVerifiedControlBeforeAck, cancellationToken).ConfigureAwait(false);
            await journal.RecordVerifiedAsync(lease, verified, cancellationToken).ConfigureAwait(false);
        }

        var ready = (await journal.ReadAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false))
            ?? throw new InvalidDataException("The durable activation vanished.");
        if (ready.State == GroupInvitationActivationJournalState.Committed)
            return new(GroupInvitationActivationDisposition.Idempotent, ready, null, lastStatus);
        if (ready.State != GroupInvitationActivationJournalState.ReadyToCommit)
            return new(GroupInvitationActivationDisposition.Deferred, ready, null, lastStatus);

        await HitAsync(GroupInvitationActivationFailpoint.BeforeStateCommit, cancellationToken).ConfigureAwait(false);
        var committed = await groups.CommitVerifiedTransitionAsync(plan.Transition, cancellationToken).ConfigureAwait(false);
        if (committed.Disposition is GroupCommitDisposition.Applied or GroupCommitDisposition.Idempotent)
        {
            await HitAsync(GroupInvitationActivationFailpoint.AfterStateCommitBeforeJournalCommit, cancellationToken).ConfigureAwait(false);
            await journal.MarkStateCommittedAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false);
            var done = (await journal.ReadAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false))!;
            return new(committed.Disposition == GroupCommitDisposition.Applied
                    ? GroupInvitationActivationDisposition.Activated
                    : GroupInvitationActivationDisposition.Idempotent,
                done, committed, lastStatus);
        }

        var disposition = committed.Disposition switch
        {
            GroupCommitDisposition.NotFound => GroupInvitationActivationDisposition.OutOfOrder,
            GroupCommitDisposition.StaleRevision => GroupInvitationActivationDisposition.StateChanged,
            GroupCommitDisposition.Conflict or GroupCommitDisposition.ForkLatched
                or GroupCommitDisposition.InvalidTransition => GroupInvitationActivationDisposition.ConflictLatched,
            _ => GroupInvitationActivationDisposition.Deferred,
        };
        if (disposition is GroupInvitationActivationDisposition.StateChanged
            or GroupInvitationActivationDisposition.ConflictLatched)
        {
            await journal.MarkConflictLatchedAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false);
            ready = (await journal.ReadAsync(plan.ActivationId, cancellationToken).ConfigureAwait(false))!;
        }
        return new(disposition, ready, committed, lastStatus);
    }

    private ValueTask HitAsync(
        GroupInvitationActivationFailpoint point,
        CancellationToken cancellationToken) =>
        failpoint?.HitAsync(point, cancellationToken) ?? ValueTask.CompletedTask;

    private async ValueTask<GroupInvitationActivationResult?> RequireCurrentPredecessorAsync(
        GroupInvitationActivationPlan plan,
        GroupInvitationActivationSnapshot staged,
        CancellationToken cancellationToken)
    {
        var head = await groups.ReadHeadAsync(plan.GroupId, cancellationToken).ConfigureAwait(false);
        if (head is null)
            return new(GroupInvitationActivationDisposition.OutOfOrder, staged, null, null);

        if (head.ForkLatched)
            return await LatchPreDispatchConflictAsync(plan, null, cancellationToken).ConfigureAwait(false);

        var transition = plan.Transition;
        var expectedRevision = transition.ExpectedRevision;
        var predecessor = transition.VerifiedTransition.Predecessor;
        if (expectedRevision.HasValue
            && head.Revision == expectedRevision.Value
            && predecessor is not null
            && head.Epoch != ulong.MaxValue
            && transition.Epoch == head.Epoch + 1
            && Fixed(head.NetworkId.Span, transition.NetworkId)
            && Fixed(head.CommitHash.Span, transition.PredecessorHash)
            && Fixed(head.ExactCanonicalCommit.Span, predecessor.CanonicalBytes.Span))
            return null;

        if (head.Epoch == transition.Epoch
            && Fixed(head.PredecessorHash.Span, transition.PredecessorHash)
            && !Fixed(head.CommitHash.Span, transition.CommitHash))
        {
            var fork = await groups.CommitVerifiedTransitionAsync(
                transition, cancellationToken).ConfigureAwait(false);
            if (fork.Disposition is not (GroupCommitDisposition.ForkLatched
                    or GroupCommitDisposition.Conflict))
                throw new InvalidDataException(
                    "A known GroupV1 sibling did not produce a durable fork latch.");
            return await LatchPreDispatchConflictAsync(plan, fork, cancellationToken).ConfigureAwait(false);
        }

        return await LatchPreDispatchAsync(
            plan,
            GroupInvitationActivationDisposition.StateChanged,
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<GroupInvitationActivationResult> LatchPreDispatchConflictAsync(
        GroupInvitationActivationPlan plan,
        GroupCommitResult? stateCommit,
        CancellationToken cancellationToken)
    {
        return await LatchPreDispatchAsync(
            plan,
            GroupInvitationActivationDisposition.ConflictLatched,
            stateCommit,
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<GroupInvitationActivationResult> LatchPreDispatchAsync(
        GroupInvitationActivationPlan plan,
        GroupInvitationActivationDisposition disposition,
        GroupCommitResult? stateCommit,
        CancellationToken cancellationToken)
    {
        try
        {
            await journal.MarkConflictLatchedAsync(
                plan.ActivationId, cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            var raced = await journal.ReadAsync(
                plan.ActivationId, cancellationToken).ConfigureAwait(false);
            if (raced?.State != GroupInvitationActivationJournalState.Committed)
                throw;
        }

        var latched = (await journal.ReadAsync(
            plan.ActivationId, cancellationToken).ConfigureAwait(false))
            ?? throw new InvalidDataException("The durable activation vanished while latching a conflict.");
        return latched.State == GroupInvitationActivationJournalState.Committed
            ? new(GroupInvitationActivationDisposition.Idempotent, latched, stateCommit, null)
            : latched.State == GroupInvitationActivationJournalState.ConflictLatched
                ? new(disposition, latched, stateCommit, null)
                : throw new InvalidDataException("The durable activation conflict latch did not become terminal.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
