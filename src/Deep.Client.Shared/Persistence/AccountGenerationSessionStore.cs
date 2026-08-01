using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using System.Runtime.CompilerServices;

namespace Deep.Client.Shared.Persistence;

internal sealed class AccountGenerationMutationCanceledException :
    OperationCanceledException
{
    public AccountGenerationMutationCanceledException(
        CancellationToken cancellationToken)
        : base(
            "Account-generation operation was canceled.",
            cancellationToken)
    {
    }
}

internal class AccountGenerationSessionStore : ILocalSessionStore, IDisposable
{
    protected readonly ILocalSessionStore Inner;
    protected readonly AccountGenerationMutationBarrier Barrier;

    public AccountGenerationSessionStore(
        ILocalSessionStore inner,
        AccountGenerationMutationBarrier barrier)
    {
        Inner = inner;
        Barrier = barrier;
    }

    public static ILocalSessionStore Create(
        ILocalSessionStore inner,
        AccountGenerationMutationBarrier barrier) =>
        (inner is IOneToOneConversationOpenRepository, inner is IMessageSyncRepository) switch
        {
            (true, true) => new OptimizedAccountGenerationSessionStore(inner, barrier),
            (true, false) => new OneToOneAccountGenerationSessionStore(inner, barrier),
            (false, true) => new MessageSyncAccountGenerationSessionStore(inner, barrier),
            _ => new AccountGenerationSessionStore(inner, barrier)
        };

    public Task UpsertAsync(Conversation value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.UpsertAsync(value, innerToken), token);

    public Task<Conversation?> GetAsync(ConversationId id, CancellationToken token = default) =>
        MutateAsync(innerToken => ((IConversationRepository)Inner).GetAsync(id, innerToken), token);

    IAsyncEnumerable<Conversation> IConversationRepository.ListAsync(CancellationToken token) =>
        EnumerateAsync(innerToken => ((IConversationRepository)Inner).ListAsync(innerToken), token);

    public Task UpsertAsync(Contact value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.UpsertAsync(value, innerToken), token);

    public Task DeleteAsync(SessionId id, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.DeleteAsync(id, innerToken), token);

    public Task<Contact?> GetAsync(SessionId id, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.GetAsync(id, innerToken), token);

    IAsyncEnumerable<Contact> IContactRepository.ListAsync(CancellationToken token) =>
        EnumerateAsync(innerToken => ((IContactRepository)Inner).ListAsync(innerToken), token);

    public Task UpsertAsync(Group value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.UpsertAsync(value, innerToken), token);

    Task<Group?> IGroupRepository.GetAsync(ConversationId id, CancellationToken token) =>
        MutateAsync(innerToken => ((IGroupRepository)Inner).GetAsync(id, innerToken), token);

    IAsyncEnumerable<Group> IGroupRepository.ListAsync(CancellationToken token) =>
        EnumerateAsync(innerToken => ((IGroupRepository)Inner).ListAsync(innerToken), token);

    public Task AppendAsync(Message value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.AppendAsync(value, innerToken), token);

    public Task UpdateAsync(Message value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.UpdateAsync(value, innerToken), token);

    public Task EnsureLogicalDispatchPlanAsync(
        DurableLogicalDispatchPlan plan,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.EnsureLogicalDispatchPlanAsync(plan, innerToken),
            token);

    public Task DeleteAsync(MessageId id, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.DeleteAsync(id, innerToken), token);

    public Task<Message?> GetAsync(MessageId id, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.GetAsync(id, innerToken), token);

    public IAsyncEnumerable<Message> ListForConversationAsync(
        ConversationId id,
        CancellationToken token = default) =>
        EnumerateAsync(innerToken => Inner.ListForConversationAsync(id, innerToken), token);

    public IAsyncEnumerable<Message> ListRecentForConversationAsync(
        ConversationId id,
        DateTimeOffset now,
        int limit,
        CancellationToken token = default) =>
        EnumerateAsync(innerToken => Inner.ListRecentForConversationAsync(id, now, limit, innerToken), token);

    public IAsyncEnumerable<Message> ListBeforeForConversationAsync(
        ConversationId id,
        DateTimeOffset before,
        MessageId beforeId,
        DateTimeOffset now,
        int limit,
        CancellationToken token = default) =>
        EnumerateAsync(
            innerToken => Inner.ListBeforeForConversationAsync(id, before, beforeId, now, limit, innerToken),
            token);

    public Task<int> CountUnreadForConversationAsync(
        ConversationId id,
        DateTimeOffset? cursor,
        DateTimeOffset now,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.CountUnreadForConversationAsync(id, cursor, now, innerToken), token);

    public Task MarkConversationReadAsync(
        ConversationId id,
        DateTimeOffset at,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.MarkConversationReadAsync(id, at, innerToken), token);

    public Task AppendMessageAndTouchConversationAsync(
        Message message,
        Conversation conversation,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.AppendMessageAndTouchConversationAsync(message, conversation, innerToken),
            token);

    public Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.ListPendingIncomingMessageNotificationIdsAsync(limit, innerToken),
            token);

    public Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        IReadOnlyCollection<ConversationId> excludedConversationIds,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.ListPendingIncomingMessageNotificationIdsAsync(
                limit,
                excludedConversationIds,
                innerToken),
            token);

    public Task MarkIncomingMessageNotificationsPresentedAsync(
        IReadOnlyCollection<MessageId> ids,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.MarkIncomingMessageNotificationsPresentedAsync(ids, innerToken),
            token);

    public Task<int> DeleteExpiredMessagesAsync(
        ConversationId id,
        DateTimeOffset now,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.DeleteExpiredMessagesAsync(id, now, innerToken), token);

    public Task<int> ClearConversationMessagesAsync(
        ConversationId id,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.ClearConversationMessagesAsync(id, innerToken), token);

    public Task<MessageReplayClaimResult> TryClaimAsync(
        SessionId sender,
        MessageId id,
        string digest,
        DateTimeOffset expiresAt,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.TryClaimAsync(sender, id, digest, expiresAt, innerToken), token);

    public Task<int> PruneExpiredAsync(DateTimeOffset now, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.PruneExpiredAsync(now, innerToken), token);

    public Task<string?> GetInboxCursorAsync(
        DurableInboxScope scope,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.GetInboxCursorAsync(scope, innerToken), token);

    public Task<DurableInboxStageResult> StageInboxBatchAsync(
        DurableInboxScope scope,
        string? expected,
        string? next,
        IReadOnlyList<DurableInboxWireEntry> entries,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.StageInboxBatchAsync(scope, expected, next, entries, innerToken),
            token);

    public Task<IReadOnlyList<DurableInboxItem>> ListStagedInboxItemsAsync(
        DurableInboxScope scope,
        int limit,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.ListStagedInboxItemsAsync(scope, limit, innerToken), token);

    public Task<DurableInboxPrepareResult> PrepareInboxItemAsync(
        DurableInboxScope scope,
        string hash,
        DurableInboxDecodedMetadata decoded,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.PrepareInboxItemAsync(scope, hash, decoded, innerToken), token);

    public Task<IReadOnlyList<DurableInboxItem>> ListDecodedInboxItemsAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        string? route,
        int limit,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.ListDecodedInboxItemsAsync(scope, kind, route, limit, innerToken), token);

    public Task<DurableInboxAckResult> AcknowledgeInboxItemAsync(
        DurableInboxScope scope,
        string hash,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.AcknowledgeInboxItemAsync(scope, hash, innerToken), token);

    public Task DiscardInboxItemAsync(
        DurableInboxScope scope,
        string hash,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.DiscardInboxItemAsync(scope, hash, innerToken), token);

    public Task<int> CountPendingInboxItemsAsync(
        DurableInboxScope scope,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.CountPendingInboxItemsAsync(scope, innerToken), token);

    public Task<int> DiscardDecodedInboxItemsOutsideRoutesAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        IReadOnlySet<string> routes,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.DiscardDecodedInboxItemsOutsideRoutesAsync(scope, kind, routes, innerToken),
            token);

    public Task PersistGroupStateAsync(
        Group group,
        Conversation conversation,
        DateTimeOffset at,
        GroupStateOutboxItem? item,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => Inner.PersistGroupStateAsync(group, conversation, at, item, innerToken),
            token);

    public Task<IReadOnlyList<GroupStateOutboxItem>> ListPendingGroupStatePublishesAsync(
        int limit,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.ListPendingGroupStatePublishesAsync(limit, innerToken), token);

    public Task AcknowledgeGroupStatePublishAsync(string id, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.AcknowledgeGroupStatePublishAsync(id, innerToken), token);

    public Task<IReadOnlyDictionary<ConversationId, ConversationListSummary>> GetConversationSummariesAsync(
        IReadOnlyCollection<ConversationId> ids,
        DateTimeOffset now,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.GetConversationSummariesAsync(ids, now, innerToken), token);

    public Task<ConversationListOpenSnapshot> OpenConversationListAsync(
        DateTimeOffset now,
        CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.OpenConversationListAsync(now, innerToken), token);

    public Task<GroupConversationOpenSnapshot?> OpenGroupConversationAsync(
        ConversationId id,
        int limit,
        DateTimeOffset now,
        CancellationToken token = default,
        bool markAsRead = true) =>
        MutateAsync(
            innerToken => Inner.OpenGroupConversationAsync(id, limit, now, innerToken, markAsRead),
            token);

    public Task SetAsync<T>(string key, T value, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.SetAsync(key, value, innerToken), token);

    public Task<T?> GetAsync<T>(string key, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.GetAsync<T>(key, innerToken), token);

    public Task DeleteAsync(string key, CancellationToken token = default) =>
        MutateAsync(innerToken => Inner.DeleteAsync(key, innerToken), token);

    public Task<AtomicBoundedSettingReadOutcome> ReadAtomicBoundedSettingAsync(
        string key,
        int maximumValueUtf8Bytes,
        CancellationToken token = default) =>
        MutateAtomicBoundedAsync(
            innerToken => Inner.ReadAtomicBoundedSettingAsync(
                key,
                maximumValueUtf8Bytes,
                innerToken),
            token);

    public Task<AtomicBoundedSettingMutationResult> CreateAtomicBoundedSettingAsync(
        string key,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken token = default) =>
        MutateAtomicBoundedAsync(
            innerToken => Inner.CreateAtomicBoundedSettingAsync(
                key,
                utf8Json,
                maximumValueUtf8Bytes,
                innerToken),
            token);

    public Task<AtomicBoundedSettingMutationResult> ReplaceAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        ReadOnlyMemory<byte> utf8Json,
        int maximumValueUtf8Bytes,
        CancellationToken token = default) =>
        MutateAtomicBoundedAsync(
            innerToken => Inner.ReplaceAtomicBoundedSettingAsync(
                key,
                expectedRevision,
                utf8Json,
                maximumValueUtf8Bytes,
                innerToken),
            token);

    public Task<AtomicBoundedSettingMutationResult> DeleteAtomicBoundedSettingAsync(
        string key,
        AtomicBoundedSettingRevision expectedRevision,
        int maximumValueUtf8Bytes,
        CancellationToken token = default) =>
        MutateAtomicBoundedAsync(
            innerToken => Inner.DeleteAtomicBoundedSettingAsync(
                key,
                expectedRevision,
                maximumValueUtf8Bytes,
                innerToken),
            token);

    public Task PurgeAccountDataAsync(CancellationToken token = default) => Inner.PurgeAccountDataAsync(token);

    protected async Task MutateAsync(
        Func<CancellationToken, Task> mutation,
        CancellationToken token)
    {
        using var lease = Barrier.Enter(token);
        await mutation(lease.CancellationToken).ConfigureAwait(false);
    }

    protected async Task<T> MutateAsync<T>(
        Func<CancellationToken, Task<T>> mutation,
        CancellationToken token)
    {
        using var lease = Barrier.Enter(token);
        return await mutation(lease.CancellationToken).ConfigureAwait(false);
    }

    private async Task<T> MutateAtomicBoundedAsync<T>(
        Func<CancellationToken, Task<T>> mutation,
        CancellationToken token)
    {
        using var lease = Barrier.Enter(token);
        try
        {
            return await mutation(lease.CancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            lease.CancellationToken.IsCancellationRequested)
        {
            throw new AccountGenerationMutationCanceledException(
                lease.CancellationToken);
        }
    }

    protected async IAsyncEnumerable<T> EnumerateAsync<T>(
        Func<CancellationToken, IAsyncEnumerable<T>> enumeration,
        [EnumeratorCancellation] CancellationToken token)
    {
        using var lease = Barrier.Enter(token);
        await foreach (var item in enumeration(lease.CancellationToken)
                           .WithCancellation(lease.CancellationToken)
                           .ConfigureAwait(false))
        {
            yield return item;
        }
    }

    public void Dispose()
    {
        if (Inner is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
}

internal sealed class OneToOneAccountGenerationSessionStore(
    ILocalSessionStore inner,
    AccountGenerationMutationBarrier barrier) :
    AccountGenerationSessionStore(inner, barrier),
    IOneToOneConversationOpenRepository
{
    private IOneToOneConversationOpenRepository OneToOneStore =>
        (IOneToOneConversationOpenRepository)Inner;

    public Task<OneToOneConversationOpenSnapshot?> OpenOneToOneConversationAsync(
        SessionId recipient,
        string? name,
        int limit,
        DateTimeOffset now,
        CancellationToken token = default,
        bool markAsRead = true) =>
        MutateAsync(
            innerToken => OneToOneStore.OpenOneToOneConversationAsync(
                recipient,
                name,
                limit,
                now,
                innerToken,
                markAsRead),
            token);
}

internal class MessageSyncAccountGenerationSessionStore(
    ILocalSessionStore inner,
    AccountGenerationMutationBarrier barrier) :
    AccountGenerationSessionStore(inner, barrier),
    IMessageSyncRepository
{
    private IMessageSyncRepository SyncStore => (IMessageSyncRepository)Inner;

    public Task<bool> ContainsServerHashAsync(
        ConversationId id,
        string hash,
        CancellationToken token = default) =>
        MutateAsync(innerToken => SyncStore.ContainsServerHashAsync(id, hash, innerToken), token);

    public Task<bool> ContainsMatchingSelfOutgoingAsync(
        ConversationId id,
        SessionId account,
        DateTimeOffset at,
        string body,
        IReadOnlyList<AttachmentMetadata> attachments,
        CancellationToken token = default) =>
        MutateAsync(
            innerToken => SyncStore.ContainsMatchingSelfOutgoingAsync(
                id,
                account,
                at,
                body,
                attachments,
                innerToken),
            token);

    public Task<int> DeleteDuplicateSelfIncomingAsync(
        ConversationId id,
        SessionId account,
        CancellationToken token = default) =>
        MutateAsync(innerToken => SyncStore.DeleteDuplicateSelfIncomingAsync(id, account, innerToken), token);

    public Task<IReadOnlyList<Message>> ListPendingOutgoingAsync(
        SessionId sender,
        CancellationToken token = default) =>
        MutateAsync(innerToken => SyncStore.ListPendingOutgoingAsync(sender, innerToken), token);

    public Task<ConversationReadResult> MarkConversationReadIfUnreadAsync(
        ConversationId id,
        DateTimeOffset at,
        CancellationToken token = default) =>
        MutateAsync(innerToken => SyncStore.MarkConversationReadIfUnreadAsync(id, at, innerToken), token);

    public Task<int> ApplyReadCursorAsync(
        ConversationId id,
        DateTimeOffset at,
        CancellationToken token = default) =>
        MutateAsync(innerToken => SyncStore.ApplyReadCursorAsync(id, at, innerToken), token);
}

internal sealed class OptimizedAccountGenerationSessionStore(
    ILocalSessionStore inner,
    AccountGenerationMutationBarrier barrier) :
    MessageSyncAccountGenerationSessionStore(inner, barrier),
    IOneToOneConversationOpenRepository
{
    private IOneToOneConversationOpenRepository OneToOneStore =>
        (IOneToOneConversationOpenRepository)Inner;

    public Task<OneToOneConversationOpenSnapshot?> OpenOneToOneConversationAsync(
        SessionId recipient,
        string? name,
        int limit,
        DateTimeOffset now,
        CancellationToken token = default,
        bool markAsRead = true) =>
        MutateAsync(
            innerToken => OneToOneStore.OpenOneToOneConversationAsync(
                recipient,
                name,
                limit,
                now,
                innerToken,
                markAsRead),
            token);
}
