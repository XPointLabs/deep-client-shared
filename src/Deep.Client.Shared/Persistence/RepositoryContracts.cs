using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

public interface IConversationRepository
{
    Task UpsertAsync(Conversation conversation, CancellationToken cancellationToken = default);

    Task<Conversation?> GetAsync(ConversationId id, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Conversation> ListAsync(CancellationToken cancellationToken = default);
}

public interface IContactRepository
{
    Task UpsertAsync(Contact contact, CancellationToken cancellationToken = default);

    Task DeleteAsync(SessionId id, CancellationToken cancellationToken = default);

    Task<Contact?> GetAsync(SessionId id, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Contact> ListAsync(CancellationToken cancellationToken = default);
}

public interface IGroupRepository
{
    Task UpsertAsync(Group group, CancellationToken cancellationToken = default);

    Task<Group?> GetAsync(ConversationId id, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Group> ListAsync(CancellationToken cancellationToken = default);
}

public interface IMessageRepository
{
    Task AppendAsync(Message message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing message. Implementations must not insert the message when its row was deleted.
    /// </summary>
    Task UpdateAsync(Message message, CancellationToken cancellationToken = default);

    Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default);

    Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListForConversationAsync(ConversationId conversationId, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListRecentForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListBeforeForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        MessageId beforeMessageId,
        DateTimeOffset now,
        int limit,
        CancellationToken cancellationToken = default);

    Task<int> CountUnreadForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset? readCursor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public interface IConversationReadRepository
{
    Task MarkConversationReadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default);
}

public sealed record ConversationReadResult(
    int ChangedMessageCount,
    DateTimeOffset? ReadCursor)
{
    public bool Changed => ChangedMessageCount > 0;
}

/// <summary>
/// Indexed message operations used by foreground and background synchronization. Keeping these
/// operations separate from the basic repository contract lets decorators opt in explicitly.
/// </summary>
public interface IMessageSyncRepository
{
    Task<bool> ContainsServerHashAsync(
        ConversationId conversationId,
        string serverHash,
        CancellationToken cancellationToken = default);

    Task<bool> ContainsMatchingSelfOutgoingAsync(
        ConversationId conversationId,
        SessionId account,
        DateTimeOffset createdAt,
        string body,
        IReadOnlyList<AttachmentMetadata> attachments,
        CancellationToken cancellationToken = default);

    Task<int> DeleteDuplicateSelfIncomingAsync(
        ConversationId conversationId,
        SessionId account,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Message>> ListPendingOutgoingAsync(
        SessionId sender,
        CancellationToken cancellationToken = default);

    Task<ConversationReadResult> MarkConversationReadIfUnreadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default);

    Task<int> ApplyReadCursorAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default);
}

internal static class MessagePersistenceKeys
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static string SelfEcho(
        DateTimeOffset createdAt,
        string body,
        IReadOnlyList<AttachmentMetadata> attachments)
    {
        var canonical = JsonSerializer.SerializeToUtf8Bytes(
            new SelfEchoPayload(createdAt.UtcDateTime.Ticks, body, attachments),
            SerializerOptions);
        return Convert.ToHexStringLower(SHA256.HashData(canonical));
    }

    public static string SelfEcho(Message message) =>
        SelfEcho(message.CreatedAt, message.Body, message.Attachments);

    private sealed record SelfEchoPayload(
        long CreatedAtUtcTicks,
        string Body,
        IReadOnlyList<AttachmentMetadata> Attachments);
}

public interface IMessageConversationPersistenceRepository
{
    Task AppendMessageAndTouchConversationAsync(
        Message message,
        Conversation conversation,
        CancellationToken cancellationToken = default);

    Task<int> DeleteExpiredMessagesAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    Task<int> ClearConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default);
}

public static class IncomingMessageNotificationLimits
{
    public const int MaxBatchCount = 256;
}

public readonly record struct PendingIncomingMessageNotification(
    MessageId MessageId,
    ConversationId ConversationId);

/// <summary>
/// Durable handoff of newly persisted incoming messages to platform notification presenters.
/// A message remains pending until the platform explicitly acknowledges its ID after presentation
/// or intentional foreground suppression.
/// </summary>
public interface IIncomingMessageNotificationRepository
{
    Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        CancellationToken cancellationToken = default);

    Task MarkIncomingMessageNotificationsPresentedAsync(
        IReadOnlyCollection<MessageId> ids,
        CancellationToken cancellationToken = default);
}

public enum MessageReplayClaimResult
{
    Accepted,
    DuplicateSameDigest,
    RejectedDigestMismatch
}

public interface IMessageReplayRepository
{
    Task<MessageReplayClaimResult> TryClaimAsync(
        SessionId sender,
        MessageId messageId,
        string envelopeDigest,
        DateTimeOffset protocolExpiresAt,
        CancellationToken cancellationToken = default);

    Task<int> PruneExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}

public static class DurableInboxLimits
{
    public const int MaxBatchCount = 256;
    public const int MaxPendingItemCount = 4096;
    public const int MaxServerHashChars = 512;
    public const int MaxWirePayloadChars = 2 * 1024 * 1024;
}

public readonly record struct DurableInboxScope(SessionId Account, int Namespace);

public sealed record DurableInboxWireEntry(
    string ServerHash,
    long StorageTimestamp,
    string WirePayload,
    string WireDigest)
{
    public static DurableInboxWireEntry Create(string serverHash, long storageTimestamp, string wirePayload)
    {
        ArgumentNullException.ThrowIfNull(wirePayload);
        return new DurableInboxWireEntry(
            serverHash,
            storageTimestamp,
            wirePayload,
            ComputeDigest(wirePayload));
    }

    public static DurableInboxWireEntry CreateBounded(
        string serverHash,
        long storageTimestamp,
        string wirePayload)
    {
        ArgumentNullException.ThrowIfNull(wirePayload);
        if (wirePayload.Length <= DurableInboxLimits.MaxWirePayloadChars)
        {
            return Create(serverHash, storageTimestamp, wirePayload);
        }

        var rejectionMarker = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"deep-inbox-rejected:v1:oversized:{wirePayload.Length}:{ComputeDigest(wirePayload)}");
        return Create(serverHash, storageTimestamp, rejectionMarker);
    }

    public static string ComputeDigest(string wirePayload) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(wirePayload)));
}

public enum DurableInboxItemKind
{
    DirectMessage = 1,
    GroupState = 2,
    GroupMessage = 3
}

public sealed record DurableInboxDecodedMetadata(
    DurableInboxItemKind Kind,
    string RouteKey,
    SessionId Sender,
    MessageId MessageId,
    string EnvelopeDigest,
    DateTimeOffset ProtocolExpiresAt);

public sealed record DurableInboxItem(
    long Sequence,
    DurableInboxScope Scope,
    string ServerHash,
    long StorageTimestamp,
    string WirePayload,
    string WireDigest,
    DurableInboxDecodedMetadata? Decoded = null);

public sealed record DurableInboxStageResult(int StagedCount, int ExistingCount);

public enum DurableInboxPrepareResult
{
    Ready,
    DuplicateSameDigest,
    RejectedDigestMismatch,
    NotFound
}

public enum DurableInboxAckResult
{
    Applied,
    DuplicateSameDigest,
    RejectedDigestMismatch,
    NotFound
}

public sealed class DurableInboxDigestMismatchException(string message) : InvalidOperationException(message);

public interface IDurableInboxRepository : IMessageReplayRepository
{
    Task<string?> GetInboxCursorAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists all wire entries and advances the raw storage cursor as one atomic operation.
    /// </summary>
    Task<DurableInboxStageResult> StageInboxBatchAsync(
        DurableInboxScope scope,
        string? expectedCursor,
        string? nextCursor,
        IReadOnlyList<DurableInboxWireEntry> entries,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DurableInboxItem>> ListStagedInboxItemsAsync(
        DurableInboxScope scope,
        int limit,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Classifies a staged item without claiming its logical message ID. A replay claim is committed by ack only.
    /// </summary>
    Task<DurableInboxPrepareResult> PrepareInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        DurableInboxDecodedMetadata decoded,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DurableInboxItem>> ListDecodedInboxItemsAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        string? routeKey,
        int limit,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically creates/verifies the replay claim and removes the staged item after domain application succeeds.
    /// </summary>
    Task<DurableInboxAckResult> AcknowledgeInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default);

    Task DiscardInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default);

    Task<int> CountPendingInboxItemsAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes decoded items whose route is not locally recognized. Implementations should perform
    /// this as one bounded/bulk operation so untrusted group routes cannot consume the personal inbox.
    /// </summary>
    async Task<int> DiscardDecodedInboxItemsOutsideRoutesAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        IReadOnlySet<string> retainedRouteKeys,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(retainedRouteKeys);
        var discarded = 0;
        while (true)
        {
            var batch = await ListDecodedInboxItemsAsync(
                scope,
                kind,
                routeKey: null,
                DurableInboxLimits.MaxBatchCount,
                cancellationToken).ConfigureAwait(false);
            var unknown = batch
                .Where(item => item.Decoded is { } decoded && !retainedRouteKeys.Contains(decoded.RouteKey))
                .ToArray();
            if (unknown.Length == 0)
            {
                return discarded;
            }

            foreach (var item in unknown)
            {
                await DiscardInboxItemAsync(scope, item.ServerHash, cancellationToken).ConfigureAwait(false);
            }

            discarded += unknown.Length;
        }
    }
}

public interface IAccountDataPurger
{
    /// <summary>
    /// Removes all account-owned local state while preserving schema metadata required to reopen the store.
    /// Implementations must either complete the purge or report failure without reporting a successful sign-out.
    /// Maintenance performed after the account-data commit is best-effort and must not make that commit appear reversible.
    /// </summary>
    Task PurgeAccountDataAsync(CancellationToken cancellationToken = default);
}

public static class GroupStateOutboxLimits
{
    public const int MaxPendingItems = 1024;
    public const int MaxPublishBatch = 128;
}

public sealed record GroupStateOutboxItem(
    string OperationId,
    Group Group,
    DateTimeOffset UpdatedAt,
    IReadOnlyList<SessionId> Recipients);

public interface IGroupStatePersistenceRepository
{
    /// <summary>
    /// Commits the group, conversation metadata, sync timestamp, and optional publish item atomically.
    /// </summary>
    Task PersistGroupStateAsync(
        Group group,
        Conversation conversation,
        DateTimeOffset updatedAt,
        GroupStateOutboxItem? outboxItem,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<GroupStateOutboxItem>> ListPendingGroupStatePublishesAsync(
        int limit,
        CancellationToken cancellationToken = default);

    Task AcknowledgeGroupStatePublishAsync(
        string operationId,
        CancellationToken cancellationToken = default);
}

public sealed record ConversationListSummary(
    ConversationId ConversationId,
    DateTimeOffset? ReadCursor,
    Message? LastMessage,
    int UnreadCount,
    Contact? Contact);

public interface IConversationListSummaryRepository
{
    Task<IReadOnlyDictionary<ConversationId, ConversationListSummary>> GetConversationSummariesAsync(
        IReadOnlyCollection<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed record ConversationListOpenSnapshot(
    SessionAccount? ActiveAccount,
    IReadOnlyList<Conversation> Conversations,
    IReadOnlyDictionary<ConversationId, ConversationListSummary> Summaries);

public interface IConversationListOpenRepository
{
    Task<ConversationListOpenSnapshot> OpenConversationListAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed record OneToOneConversationOpenSnapshot(
    SessionAccount ActiveAccount,
    Conversation Conversation,
    Contact? Contact,
    IReadOnlyList<Message> RecentMessages,
    DateTimeOffset ReadAt);

public interface IOneToOneConversationOpenRepository
{
    Task<OneToOneConversationOpenSnapshot?> OpenOneToOneConversationAsync(
        SessionId recipient,
        string? displayName,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true);
}

public sealed record GroupConversationOpenSnapshot(
    SessionAccount ActiveAccount,
    Group Group,
    IReadOnlyList<Message> RecentMessages,
    IReadOnlyDictionary<SessionId, Contact> SenderContacts,
    DateTimeOffset ReadAt);

public interface IGroupConversationOpenRepository
{
    Task<GroupConversationOpenSnapshot?> OpenGroupConversationAsync(
        ConversationId groupId,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true);
}

public interface ISettingsRepository
{
    Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default);

    Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default);

    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}

public static class LocalSettingsKeys
{
    public const string ActiveAccount = "account.active";
    public const string ActiveRecoveryPhrase = "account.recovery-phrase";
}

public interface ILocalSessionStore :
    IConversationRepository,
    IContactRepository,
    IGroupRepository,
    IMessageRepository,
    IConversationReadRepository,
    IMessageConversationPersistenceRepository,
    IIncomingMessageNotificationRepository,
    IDurableInboxRepository,
    IAccountDataPurger,
    IGroupStatePersistenceRepository,
    IConversationListSummaryRepository,
    IConversationListOpenRepository,
    IGroupConversationOpenRepository,
    ISettingsRepository,
    ISchemaStore;
