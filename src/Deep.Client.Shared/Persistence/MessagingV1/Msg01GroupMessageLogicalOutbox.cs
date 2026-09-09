using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;

namespace Deep.Client.Shared.Persistence.MessagingV1;

/// <summary>
/// Narrow GROUP-CLIENT-01 to MSG-01 materialization seam. It writes one logical
/// event and its complete immutable device fanout, but never prepares ratchet
/// ciphertext or calls a delivery transport.
/// </summary>
internal sealed class Msg01GroupMessageLogicalOutbox : IGroupMessageLogicalOutbox
{
    private readonly IMessageTransactionStore store;

    internal Msg01GroupMessageLogicalOutbox(IMessageTransactionStore store) =>
        this.store = store ?? throw new ArgumentNullException(nameof(store));

    public async ValueTask<GroupMessageLogicalOutboxWriteResult> StageAsync(
        GroupMessageLogicalOutboxPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        cancellationToken.ThrowIfCancellationRequested();
        if (!store.Scope.LocalAccountId.Equals(plan.AuthorAccountId))
            throw new ArgumentException("The GroupV1 event belongs to another MSG-01 account scope.", nameof(plan));

        var eventHash = MessageEventHash32.FromBytes(SHA256.HashData(plan.CanonicalEvent.Span));
        var conversationId = ConversationId32.FromBytes(plan.GroupId.Span);
        var seed = LogicalOutboxSeed.CreateOutbound(
            store.Scope,
            plan.AuthorDeviceId,
            conversationId,
            plan.SemanticMessageId,
            eventHash,
            plan.CanonicalEvent.Span,
            plan.CreatedAt,
            plan.ExpiresAt,
            MessagePayloadKind.GroupMessage);
        var claim = new SemanticClaimCandidate(
            plan.AuthorAccountId,
            plan.AuthorDeviceId,
            conversationId,
            plan.SemanticMessageId,
            eventHash);

        var begin = await store.BeginOutboundAsync(
            MutationId("begin", plan), claim, seed, cancellationToken).ConfigureAwait(false);
        if (begin.ClaimResult == SemanticClaimResult.ForkLatched
            || begin.CommitResult == MessageCommitResult.ForkLatched)
            return new(GroupMessageFanoutDisposition.MessageForkLatched, begin.Snapshot);
        if (begin.CommitResult is MessageCommitResult.Conflict or MessageCommitResult.Missing)
            return new(GroupMessageFanoutDisposition.Conflict, begin.Snapshot);

        var head = begin.Snapshot
            ?? await store.ReadAsync(seed.ClaimKey, cancellationToken).ConfigureAwait(false);
        if (head is null)
            return new(GroupMessageFanoutDisposition.Conflict, null);
        if (!MatchesPlan(head, plan))
            return new(GroupMessageFanoutDisposition.Conflict, head);

        var staged = begin.ClaimResult == SemanticClaimResult.First;
        if (head.State == LogicalOutboxState.Queued)
        {
            var fanout = plan.TargetRows.Select(static target => new FanoutTargetSeed(
                target.Target,
                target.DirectoryHeadHash,
                target.OperationId,
                target.BindingHash)).ToArray();
            var applied = await store.ApplyAsync(
                PreparedMessageMutation.PrepareFanout(
                    head, MutationId("fanout", plan), fanout, plan.CreatedAt),
                cancellationToken).ConfigureAwait(false);
            if (applied.CommitResult == MessageCommitResult.ForkLatched)
                return new(GroupMessageFanoutDisposition.MessageForkLatched, applied.Snapshot);
            if (applied.CommitResult == MessageCommitResult.StaleRevision)
            {
                head = await store.ReadAsync(seed.ClaimKey, cancellationToken).ConfigureAwait(false);
            }
            else if (applied.CommitResult is MessageCommitResult.Applied
                or MessageCommitResult.Idempotent)
            {
                head = applied.Snapshot;
            }
            else
            {
                return new(GroupMessageFanoutDisposition.Conflict, applied.Snapshot);
            }
        }

        if (head is null || !MatchesPlan(head, plan) || head.State == LogicalOutboxState.Queued)
            return new(GroupMessageFanoutDisposition.Conflict, head);
        return new(
            staged ? GroupMessageFanoutDisposition.Staged : GroupMessageFanoutDisposition.Idempotent,
            head);
    }

    private static bool MatchesPlan(
        LogicalOutboxSnapshot snapshot,
        GroupMessageLogicalOutboxPlan plan)
    {
        if (!snapshot.StoreScope.LocalAccountId.Equals(plan.AuthorAccountId)
            || !snapshot.AuthorDeviceId.Equals(plan.AuthorDeviceId)
            || !snapshot.ConversationId.Span.SequenceEqual(plan.GroupId.Span)
            || !snapshot.SemanticMessageId.Equals(plan.SemanticMessageId)
            || snapshot.PayloadKind != MessagePayloadKind.GroupMessage
            || snapshot.CreatedAt != plan.CreatedAt
            || snapshot.ExpiresAt != plan.ExpiresAt
            || !snapshot.CanonicalPayload.AsSpan().SequenceEqual(plan.CanonicalEvent.Span))
            return false;

        if (snapshot.State == LogicalOutboxState.Queued)
            return snapshot.Targets.Count == 0;
        if (snapshot.Targets.Count != plan.TargetRows.Count)
            return false;
        return snapshot.Targets.Zip(plan.TargetRows).All(static pair =>
            pair.First.Target.Equals(pair.Second.Target)
            && pair.First.DirectoryHeadHash.Equals(pair.Second.DirectoryHeadHash)
            && pair.First.OperationId?.Equals(pair.Second.OperationId) == true
            && pair.First.BindingHash?.Equals(pair.Second.BindingHash) == true);
    }

    private static MessageMutationId32 MutationId(
        string purpose,
        GroupMessageLogicalOutboxPlan plan)
    {
        if (string.Equals(purpose, "begin", StringComparison.Ordinal))
            return MessageMutationId32.FromBytes(plan.BatchId.Span);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Group/V1/msg01-mutation/v1\0"u8);
        hash.AppendData(System.Text.Encoding.ASCII.GetBytes(purpose));
        hash.AppendData(plan.BatchId.Span);
        hash.AppendData(plan.SemanticMessageId.Span);
        hash.AppendData(plan.CommitHash.Span);
        return MessageMutationId32.FromBytes(hash.GetHashAndReset());
    }
}
