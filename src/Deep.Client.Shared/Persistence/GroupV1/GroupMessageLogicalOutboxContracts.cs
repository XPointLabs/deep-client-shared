using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Persistence.GroupV1;

public sealed class GroupMessageLogicalOutboxPlan
{
    private readonly byte[] commitHash;
    private readonly byte[] canonicalEvent;
    private readonly GroupMessageFanoutTarget[] targets;

    internal GroupMessageLogicalOutboxPlan(
        GroupFanoutBatchId32 batchId,
        GroupId32 groupId,
        ulong epoch,
        ReadOnlySpan<byte> commitHash,
        MessagingAccountId32 authorAccountId,
        MessagingDeviceId32 authorDeviceId,
        SemanticMessageId32 semanticMessageId,
        ReadOnlySpan<byte> canonicalEvent,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        IEnumerable<GroupMessageFanoutTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(groupId);
        ArgumentNullException.ThrowIfNull(authorAccountId);
        ArgumentNullException.ThrowIfNull(authorDeviceId);
        ArgumentNullException.ThrowIfNull(semanticMessageId);
        ArgumentNullException.ThrowIfNull(targets);
        if (commitHash.Length != 32 || commitHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero exact commit hash is required.", nameof(commitHash));
        if (canonicalEvent.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes)
            throw new ArgumentOutOfRangeException(nameof(canonicalEvent));

        BatchId = GroupFanoutBatchId32.FromBytes(batchId.Span);
        GroupId = GroupId32.FromBytes(groupId.Span);
        Epoch = epoch;
        this.commitHash = commitHash.ToArray();
        AuthorAccountId = MessagingAccountId32.FromBytes(authorAccountId.Span);
        AuthorDeviceId = MessagingDeviceId32.FromBytes(authorDeviceId.Span);
        SemanticMessageId = SemanticMessageId32.FromBytes(semanticMessageId.Span);
        this.canonicalEvent = canonicalEvent.ToArray();
        CreatedAt = LogicalOutboxSeed.Canonical(createdAt);
        ExpiresAt = LogicalOutboxSeed.Canonical(expiresAt);
        this.targets = targets.Select(static target => new GroupMessageFanoutTarget(
            target.Target, target.AccountGeneration, target.DirectoryHeadHash,
            target.OperationId, target.BindingHash)).OrderBy(static target => target.Target).ToArray();
        if (this.targets.Length is < 1 or > MessagingV1Limits.MaxFanoutTargets
            || this.targets.Select(static target => target.Target).Distinct().Count() != this.targets.Length
            || this.targets.Select(static target => target.OperationId).Distinct().Count() != this.targets.Length
            || this.targets.Select(static target => target.BindingHash).Distinct().Count() != this.targets.Length)
            throw new ArgumentException("The exact GroupV1 target set is invalid.", nameof(targets));
    }

    public GroupFanoutBatchId32 BatchId { get; }
    public GroupId32 GroupId { get; }
    public ulong Epoch { get; }
    public ReadOnlyMemory<byte> CommitHash => commitHash.ToArray();
    public MessagingAccountId32 AuthorAccountId { get; }
    public MessagingDeviceId32 AuthorDeviceId { get; }
    public SemanticMessageId32 SemanticMessageId { get; }
    public ReadOnlyMemory<byte> CanonicalEvent => canonicalEvent.ToArray();
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public IReadOnlyList<GroupMessageFanoutTarget> Targets => Array.AsReadOnly(
        targets.Select(static target => new GroupMessageFanoutTarget(
            target.Target, target.AccountGeneration, target.DirectoryHeadHash,
            target.OperationId, target.BindingHash)).ToArray());

    internal IReadOnlyList<GroupMessageFanoutTarget> TargetRows => targets;
}

public sealed record GroupMessageLogicalOutboxWriteResult(
    GroupMessageFanoutDisposition Disposition,
    LogicalOutboxSnapshot? Snapshot);

public interface IGroupMessageLogicalOutbox
{
    ValueTask<GroupMessageLogicalOutboxWriteResult> StageAsync(
        GroupMessageLogicalOutboxPlan plan,
        CancellationToken cancellationToken = default);
}
