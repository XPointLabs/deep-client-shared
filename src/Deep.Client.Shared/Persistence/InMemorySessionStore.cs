using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Persistence;

public sealed partial class InMemorySessionStore :
    ILocalSessionStore,
    ITransportOutboxRepository,
    IOneToOneConversationOpenRepository,
    IMessageSyncRepository,
    IMembershipTrustRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly ConcurrentDictionary<string, Conversation> conversations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Contact> contacts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Group> groups = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Message> messages = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> settings = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> schemaValues = new(StringComparer.Ordinal);
    private readonly Dictionary<ReplayClaimKey, ReplayClaim> replayClaims = [];
    private readonly Dictionary<InboxScopeKey, string> inboxCursors = [];
    private readonly Dictionary<InboxItemKey, InboxItemState> inboxItems = [];
    private readonly Dictionary<string, GroupStateOutboxItem> groupStateOutbox = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> incomingMessageNotifications = new(StringComparer.Ordinal);
    private readonly Dictionary<MembershipTrustKey, SortedDictionary<ulong, MembershipTrustRecord>> membershipTrustRecords = [];
    private readonly Dictionary<MembershipTrustKey, ulong> membershipTrustHeads = [];
    private readonly Dictionary<string, MembershipTrustClockRecord> membershipTrustClocks = new(StringComparer.Ordinal);
    private readonly object durableStateGate = new();
    private readonly object accountDataPurgeGate = new();
    private readonly string? statePath;
    private readonly Action<MembershipTrustCommitFaultPoint>? membershipTrustFaultInjector;
    private long nextInboxSequence;
    private long nextIncomingMessageNotificationSequence;
    private int schemaVersion;

    private const int ReplayPruneBatchSize = 256;

    public InMemorySessionStore(string? statePath = null)
        : this(statePath, (Action<MembershipTrustCommitFaultPoint>?)null)
    {
    }

    internal InMemorySessionStore(
        string? statePath,
        Action<MembershipTrustCommitFaultPoint>? faultInjector)
    {
        this.statePath = string.IsNullOrWhiteSpace(statePath) ? null : statePath;
        membershipTrustFaultInjector = faultInjector;
        LoadState();
    }

    public Task UpsertAsync(Conversation conversation, CancellationToken cancellationToken = default)
    {
        conversations[conversation.Id.Value] = conversation;
        PersistState();
        return Task.CompletedTask;
    }

    public Task<Conversation?> GetAsync(ConversationId id, CancellationToken cancellationToken = default) =>
        Task.FromResult(conversations.GetValueOrDefault(id.Value));

    async IAsyncEnumerable<Conversation> IConversationRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in conversations.Values.OrderByDescending(item => item.UpdatedAt))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    public Task UpsertAsync(Contact contact, CancellationToken cancellationToken = default)
    {
        contacts[contact.Id.Value] = contact;
        PersistState();
        return Task.CompletedTask;
    }

    public Task DeleteAsync(SessionId id, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            if (!contacts.TryRemove(id.Value, out var previous))
            {
                return Task.CompletedTask;
            }

            try
            {
                PersistState();
            }
            catch
            {
                contacts[id.Value] = previous;
                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task<Contact?> GetAsync(SessionId id, CancellationToken cancellationToken = default) =>
        Task.FromResult(contacts.GetValueOrDefault(id.Value));

    async IAsyncEnumerable<Contact> IContactRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in contacts.Values.OrderBy(item => item.DisplayName ?? item.Id.Value))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    public Task UpsertAsync(Group group, CancellationToken cancellationToken = default)
    {
        groups[group.Id.Value] = group;
        PersistState();
        return Task.CompletedTask;
    }

    Task<Group?> IGroupRepository.GetAsync(ConversationId id, CancellationToken cancellationToken) =>
        Task.FromResult(groups.GetValueOrDefault(id.Value));

    async IAsyncEnumerable<Group> IGroupRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in groups.Values.OrderBy(item => item.Name))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    public Task AppendAsync(Message message, CancellationToken cancellationToken = default)
    {
        messages[message.Id.Value] = message;
        PersistState();
        return Task.CompletedTask;
    }

    public Task UpdateAsync(Message message, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            if (!messages.TryGetValue(message.Id.Value, out var previous))
            {
                return Task.CompletedTask;
            }

            if (!messages.TryUpdate(message.Id.Value, message, previous))
            {
                return Task.CompletedTask;
            }

            try
            {
                PersistState();
            }
            catch
            {
                messages.TryUpdate(message.Id.Value, previous, message);
                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default)
    {
        messages.TryRemove(id.Value, out _);
        PersistState();
        return Task.CompletedTask;
    }

    public Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default) =>
        Task.FromResult(messages.GetValueOrDefault(id.Value));

    async IAsyncEnumerable<Message> IMessageRepository.ListForConversationAsync(
        ConversationId conversationId,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in messages.Values
                     .Where(item => item.ConversationId == conversationId)
                     .OrderBy(item => item.CreatedAt)
                     .ThenBy(item => item.Id.Value, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListRecentForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in messages.Values
                     .Where(item => item.ConversationId == conversationId && !item.IsExpired(now))
                     .OrderByDescending(item => item.CreatedAt)
                     .ThenByDescending(item => item.Id.Value, StringComparer.Ordinal)
                     .Take(limit)
                     .OrderBy(item => item.CreatedAt)
                     .ThenBy(item => item.Id.Value, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListBeforeForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        MessageId beforeMessageId,
        DateTimeOffset now,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in messages.Values
                     .Where(item =>
                         item.ConversationId == conversationId
                         && !item.IsExpired(now)
                         && (item.CreatedAt < beforeCreatedAt
                             || (item.CreatedAt == beforeCreatedAt
                                 && string.CompareOrdinal(item.Id.Value, beforeMessageId.Value) < 0)))
                     .OrderByDescending(item => item.CreatedAt)
                     .ThenByDescending(item => item.Id.Value, StringComparer.Ordinal)
                     .Take(limit)
                     .OrderBy(item => item.CreatedAt)
                     .ThenBy(item => item.Id.Value, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return item;
            await Task.Yield();
        }
    }

    Task<int> IMessageRepository.CountUnreadForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset? readCursor,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var count = messages.Values.Count(message =>
            message.ConversationId == conversationId
            && message.Direction == MessageDirection.Incoming
            && message.DeliveryState != MessageDeliveryState.Read
            && !message.IsExpired(now));

        return Task.FromResult(count);
    }

    public Task<bool> ContainsServerHashAsync(
        ConversationId conversationId,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(serverHash))
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(messages.Values.Any(message =>
            message.ConversationId == conversationId
            && string.Equals(message.ServerHash, serverHash, StringComparison.Ordinal)));
    }

    public Task<bool> ContainsMatchingSelfOutgoingAsync(
        ConversationId conversationId,
        SessionId account,
        DateTimeOffset createdAt,
        string body,
        IReadOnlyList<AttachmentMetadata> attachments,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = MessagePersistenceKeys.SelfEcho(createdAt, body, attachments);
        return Task.FromResult(messages.Values.Any(message =>
            message.ConversationId == conversationId
            && message.Sender == account
            && message.Recipient == account
            && message.Direction == MessageDirection.Outgoing
            && string.Equals(MessagePersistenceKeys.SelfEcho(message), key, StringComparison.Ordinal)));
    }

    public Task<int> DeleteDuplicateSelfIncomingAsync(
        ConversationId conversationId,
        SessionId account,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var outgoingKeys = messages.Values
                .Where(message =>
                    message.ConversationId == conversationId
                    && message.Sender == account
                    && message.Recipient == account
                    && message.Direction == MessageDirection.Outgoing)
                .Select(MessagePersistenceKeys.SelfEcho)
                .ToHashSet(StringComparer.Ordinal);
            var duplicates = messages.Values
                .Where(message =>
                    message.ConversationId == conversationId
                    && message.Sender == account
                    && message.Recipient == account
                    && message.Direction == MessageDirection.Incoming
                    && outgoingKeys.Contains(MessagePersistenceKeys.SelfEcho(message)))
                .ToArray();
            if (duplicates.Length == 0)
            {
                return Task.FromResult(0);
            }

            foreach (var duplicate in duplicates)
            {
                messages.TryRemove(duplicate.Id.Value, out _);
            }

            try
            {
                PersistState();
            }
            catch
            {
                foreach (var duplicate in duplicates)
                {
                    messages[duplicate.Id.Value] = duplicate;
                }

                throw;
            }

            return Task.FromResult(duplicates.Length);
        }
    }

    public Task<IReadOnlyList<Message>> ListPendingOutgoingAsync(
        SessionId sender,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<Message>>(messages.Values
            .Where(message =>
                message.Sender == sender
                && message.Direction == MessageDirection.Outgoing
                && message.DeliveryState is MessageDeliveryState.Sending or MessageDeliveryState.Failed)
            .OrderBy(static message => message.CreatedAt)
            .ThenBy(static message => message.Id.Value, StringComparer.Ordinal)
            .ToArray());
    }

    public Task<ConversationReadResult> MarkConversationReadIfUnreadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var changedMessages = messages.Values
                .Where(message =>
                    message.ConversationId == conversationId
                    && message.Direction == MessageDirection.Incoming
                    && message.DeliveryState != MessageDeliveryState.Read)
                .ToArray();
            var existingReadAt = ReadCursorFor(conversationId);
            if (changedMessages.Length == 0)
            {
                return Task.FromResult(new ConversationReadResult(0, existingReadAt));
            }

            var effectiveReadAt = existingReadAt is not null && existingReadAt > readAt
                ? existingReadAt.Value
                : readAt;
            var settingKey = ReadCursorSettingKey(conversationId);
            var hadSetting = settings.TryGetValue(settingKey, out var previousSetting);
            try
            {
                foreach (var message in changedMessages)
                {
                    messages[message.Id.Value] = message.Mark(MessageDeliveryState.Read, effectiveReadAt);
                }

                settings[settingKey] = JsonSerializer.Serialize(effectiveReadAt.ToString("O"), SerializerOptions);
                PersistState();
            }
            catch
            {
                foreach (var message in changedMessages)
                {
                    messages[message.Id.Value] = message;
                }

                if (hadSetting)
                {
                    settings[settingKey] = previousSetting!;
                }
                else
                {
                    settings.TryRemove(settingKey, out _);
                }

                throw;
            }

            return Task.FromResult(new ConversationReadResult(changedMessages.Length, effectiveReadAt));
        }
    }

    public Task<int> ApplyReadCursorAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var changedMessages = messages.Values
                .Where(message =>
                    message.ConversationId == conversationId
                    && message.Direction == MessageDirection.Incoming
                    && message.DeliveryState != MessageDeliveryState.Read
                    && message.CreatedAt <= readAt)
                .ToArray();
            var existingReadAt = ReadCursorFor(conversationId);
            var shouldAdvanceCursor = existingReadAt is null || readAt > existingReadAt;
            if (changedMessages.Length == 0 && !shouldAdvanceCursor)
            {
                return Task.FromResult(0);
            }

            var settingKey = ReadCursorSettingKey(conversationId);
            var hadSetting = settings.TryGetValue(settingKey, out var previousSetting);
            try
            {
                foreach (var message in changedMessages)
                {
                    messages[message.Id.Value] = message.Mark(MessageDeliveryState.Read, readAt);
                }

                if (shouldAdvanceCursor)
                {
                    settings[settingKey] = JsonSerializer.Serialize(readAt.ToString("O"), SerializerOptions);
                }

                PersistState();
            }
            catch
            {
                foreach (var message in changedMessages)
                {
                    messages[message.Id.Value] = message;
                }

                if (hadSetting)
                {
                    settings[settingKey] = previousSetting!;
                }
                else
                {
                    settings.TryRemove(settingKey, out _);
                }

                throw;
            }

            return Task.FromResult(changedMessages.Length);
        }
    }

    public Task MarkConversationReadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default) =>
        MarkConversationReadIfUnreadAsync(conversationId, readAt, cancellationToken);

    public Task AppendMessageAndTouchConversationAsync(
        Message message,
        Conversation conversation,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var hadMessage = messages.TryGetValue(message.Id.Value, out var previousMessage);
            var hadConversation = conversations.TryGetValue(conversation.Id.Value, out var previousConversation);
            var hadNotification = incomingMessageNotifications.TryGetValue(
                message.Id.Value,
                out var previousNotificationSequence);
            var previousNextNotificationSequence = nextIncomingMessageNotificationSequence;
            try
            {
                messages[message.Id.Value] = message;
                conversations[conversation.Id.Value] = conversation;
                if (!hadMessage && !hadNotification && message.Direction == MessageDirection.Incoming)
                {
                    incomingMessageNotifications[message.Id.Value] =
                        ++nextIncomingMessageNotificationSequence;
                }

                PersistState();
            }
            catch
            {
                Restore(messages, message.Id.Value, hadMessage ? previousMessage : null);
                Restore(conversations, conversation.Id.Value, hadConversation ? previousConversation : null);
                if (hadNotification)
                {
                    incomingMessageNotifications[message.Id.Value] = previousNotificationSequence;
                }
                else
                {
                    incomingMessageNotifications.Remove(message.Id.Value);
                }

                nextIncomingMessageNotificationSequence = previousNextNotificationSequence;
                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        CancellationToken cancellationToken = default) =>
        ListPendingIncomingMessageNotificationIdsAsync(limit, [], cancellationToken);

    public Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        IReadOnlyCollection<ConversationId> excludedConversationIds,
        CancellationToken cancellationToken = default)
    {
        ValidateIncomingMessageNotificationLimit(limit);
        ArgumentNullException.ThrowIfNull(excludedConversationIds);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var excluded = excludedConversationIds
                .Select(static id => id.Value)
                .ToHashSet(StringComparer.Ordinal);
            var now = DateTimeOffset.UtcNow;
            var stale = incomingMessageNotifications
                .Where(item => !IsPendingIncomingMessageNotification(item.Key, now))
                .ToArray();
            if (stale.Length > 0)
            {
                foreach (var item in stale)
                {
                    incomingMessageNotifications.Remove(item.Key);
                }

                try
                {
                    PersistState();
                }
                catch
                {
                    foreach (var item in stale)
                    {
                        incomingMessageNotifications[item.Key] = item.Value;
                    }

                    throw;
                }
            }

            return Task.FromResult<IReadOnlyList<PendingIncomingMessageNotification>>(incomingMessageNotifications
                .OrderBy(static item => item.Value)
                .Where(item => !excluded.Contains(messages[item.Key].ConversationId.Value))
                .Take(limit)
                .Select(item => new PendingIncomingMessageNotification(
                    messages[item.Key].Id,
                    messages[item.Key].ConversationId))
                .ToArray());
        }
    }

    private bool IsPendingIncomingMessageNotification(string messageId, DateTimeOffset now) =>
        messages.TryGetValue(messageId, out var message)
        && message.Direction == MessageDirection.Incoming
        && message.DeliveryState != MessageDeliveryState.Read
        && message.ReadAt is null
        && !message.IsExpired(now);

    public Task MarkIncomingMessageNotificationsPresentedAsync(
        IReadOnlyCollection<MessageId> ids,
        CancellationToken cancellationToken = default)
    {
        var messageIds = ValidateIncomingMessageNotificationIds(ids);
        cancellationToken.ThrowIfCancellationRequested();
        if (messageIds.Length == 0)
        {
            return Task.CompletedTask;
        }

        lock (durableStateGate)
        {
            var removed = new List<KeyValuePair<string, long>>(messageIds.Length);
            foreach (var messageId in messageIds)
            {
                if (incomingMessageNotifications.Remove(messageId, out var sequence))
                {
                    removed.Add(new KeyValuePair<string, long>(messageId, sequence));
                }
            }

            if (removed.Count == 0)
            {
                return Task.CompletedTask;
            }

            try
            {
                PersistState();
            }
            catch
            {
                foreach (var item in removed)
                {
                    incomingMessageNotifications[item.Key] = item.Value;
                }

                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task<int> DeleteExpiredMessagesAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var expired = messages.Values
                .Where(message => message.ConversationId == conversationId && message.IsExpired(now))
                .ToArray();
            if (expired.Length == 0)
            {
                return Task.FromResult(0);
            }

            try
            {
                foreach (var message in expired)
                {
                    messages.TryRemove(message.Id.Value, out _);
                }

                PersistState();
            }
            catch
            {
                foreach (var message in expired)
                {
                    messages[message.Id.Value] = message;
                }

                throw;
            }

            return Task.FromResult(expired.Length);
        }
    }

    public Task<int> ClearConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var removed = messages.Values
                .Where(message => message.ConversationId == conversationId)
                .ToArray();
            if (removed.Length == 0)
            {
                return Task.FromResult(0);
            }

            try
            {
                foreach (var message in removed)
                {
                    messages.TryRemove(message.Id.Value, out _);
                }

                PersistState();
            }
            catch
            {
                foreach (var message in removed)
                {
                    messages[message.Id.Value] = message;
                }

                throw;
            }

            return Task.FromResult(removed.Length);
        }
    }

    public Task<IReadOnlyDictionary<ConversationId, ConversationListSummary>> GetConversationSummariesAsync(
        IReadOnlyCollection<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var idSet = conversationIds
            .Select(static id => id.Value)
            .ToHashSet(StringComparer.Ordinal);
        var messagesByConversation = messages.Values
            .Where(message => idSet.Contains(message.ConversationId.Value))
            .GroupBy(static message => message.ConversationId.Value, StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group
                    .OrderBy(static message => message.CreatedAt)
                    .ThenBy(static message => message.Id.Value, StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);

        var result = new Dictionary<ConversationId, ConversationListSummary>();
        foreach (var conversationId in conversationIds)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var readCursor = ReadCursorFor(conversationId);
            messagesByConversation.TryGetValue(conversationId.Value, out var conversationMessages);
            conversationMessages ??= [];
            var lastMessage = conversationMessages
                .LastOrDefault(message => !message.IsExpired(now));
            var unreadCount = conversationMessages.Count(message =>
                message.Direction == MessageDirection.Incoming
                && message.DeliveryState != MessageDeliveryState.Read
                && !message.IsExpired(now));
            contacts.TryGetValue(conversationId.Value, out var contact);

            result[conversationId] = new ConversationListSummary(
                conversationId,
                readCursor,
                lastMessage,
                unreadCount,
                contact);
        }

        return Task.FromResult<IReadOnlyDictionary<ConversationId, ConversationListSummary>>(result);
    }

    public async Task<ConversationListOpenSnapshot> OpenConversationListAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SessionAccount? activeAccount = null;
        if (settings.TryGetValue(LocalSettingsKeys.ActiveAccount, out var accountJson))
        {
            activeAccount = JsonSerializer.Deserialize<SessionAccount>(accountJson, SerializerOptions);
        }

        var conversationItems = conversations.Values
            .OrderByDescending(static conversation => conversation.UpdatedAt)
            .ToArray();
        var summaries = await GetConversationSummariesAsync(
            conversationItems.Select(static conversation => conversation.Id).ToArray(),
            now,
            cancellationToken).ConfigureAwait(false);
        return new ConversationListOpenSnapshot(activeAccount, conversationItems, summaries);
    }

    public Task<OneToOneConversationOpenSnapshot?> OpenOneToOneConversationAsync(
        SessionId recipient,
        string? displayName,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true)
    {
        if (messageLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(messageLimit), "Message limit must be greater than zero.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!settings.TryGetValue(LocalSettingsKeys.ActiveAccount, out var accountJson))
        {
            return Task.FromResult<OneToOneConversationOpenSnapshot?>(null);
        }

        var account = JsonSerializer.Deserialize<SessionAccount>(accountJson, SerializerOptions);
        if (account is null)
        {
            return Task.FromResult<OneToOneConversationOpenSnapshot?>(null);
        }

        var conversationId = ConversationId.ForOneToOne(recipient);
        var normalizedDisplayName = ConversationService.NormalizeDisplayName(recipient, displayName);
        var contact = contacts.GetValueOrDefault(recipient.Value) ?? Contact.Request(recipient, normalizedDisplayName, now);
        var normalizedContactDisplayName = ConversationService.NormalizeDisplayName(recipient, contact.DisplayName);
        var desiredContactDisplayName = normalizedContactDisplayName ?? normalizedDisplayName;
        if (!string.Equals(contact.DisplayName, desiredContactDisplayName, StringComparison.Ordinal))
        {
            contact = contact with
            {
                DisplayName = desiredContactDisplayName,
                UpdatedAt = now
            };
        }

        contacts[recipient.Value] = contact;

        var desiredDisplayName = contact.DisplayName ?? recipient.Value;
        var conversation = conversations.GetValueOrDefault(conversationId.Value);
        if (conversation is null)
        {
            conversation = new Conversation(
                conversationId,
                ConversationKind.OneToOne,
                desiredDisplayName,
                ConversationSettings.Default(ConversationKind.OneToOne),
                now,
                now);
        }
        else
        {
            if (!string.Equals(conversation.DisplayName, desiredDisplayName, StringComparison.Ordinal))
            {
                conversation = conversation with { DisplayName = desiredDisplayName };
            }

            if (conversation.IsHidden)
            {
                conversation = conversation with { IsHidden = false, UpdatedAt = now };
            }
        }

        conversations[conversationId.Value] = conversation;

        DateTimeOffset readAt;
        if (markAsRead)
        {
            var existingReadAt = ReadCursorFor(conversationId);
            var unreadMessages = messages.Values.Where(message =>
                    message.ConversationId == conversationId
                    && message.Direction == MessageDirection.Incoming
                    && message.DeliveryState != MessageDeliveryState.Read)
                .ToArray();
            if (unreadMessages.Length == 0)
            {
                readAt = existingReadAt ?? DateTimeOffset.MinValue;
            }
            else
            {
                readAt = existingReadAt is not null && existingReadAt > now ? existingReadAt.Value : now;
                foreach (var message in unreadMessages)
                {
                    messages[message.Id.Value] = message.Mark(MessageDeliveryState.Read, readAt);
                }

                settings[ReadCursorSettingKey(conversationId)] = JsonSerializer.Serialize(readAt.ToString("O"), SerializerOptions);
            }
        }
        else
        {
            readAt = ReadCursorFor(conversationId) ?? DateTimeOffset.MinValue;
        }

        var recentMessages = messages.Values
            .Where(message => message.ConversationId == conversationId && !message.IsExpired(now))
            .OrderByDescending(message => message.CreatedAt)
            .ThenByDescending(message => message.Id.Value, StringComparer.Ordinal)
            .Take(messageLimit)
            .OrderBy(message => message.CreatedAt)
            .ThenBy(message => message.Id.Value, StringComparer.Ordinal)
            .ToArray();

        PersistState();

        return Task.FromResult<OneToOneConversationOpenSnapshot?>(new OneToOneConversationOpenSnapshot(
            account,
            conversation,
            contact,
            recentMessages,
            readAt));
    }

    public Task<GroupConversationOpenSnapshot?> OpenGroupConversationAsync(
        ConversationId groupId,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true)
    {
        if (messageLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(messageLimit));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!settings.TryGetValue(LocalSettingsKeys.ActiveAccount, out var accountJson)
            || JsonSerializer.Deserialize<SessionAccount>(accountJson, SerializerOptions) is not { } account
            || !groups.TryGetValue(groupId.Value, out var group))
        {
            return Task.FromResult<GroupConversationOpenSnapshot?>(null);
        }

        var readAt = ReadCursorFor(groupId) ?? DateTimeOffset.MinValue;
        if (markAsRead)
        {
            var unreadMessages = messages.Values.Where(message =>
                    message.ConversationId == groupId
                    && message.Direction == MessageDirection.Incoming
                    && message.DeliveryState != MessageDeliveryState.Read)
                .ToArray();
            if (unreadMessages.Length > 0)
            {
                readAt = readAt > now ? readAt : now;
                foreach (var message in unreadMessages)
                {
                    messages[message.Id.Value] = message.Mark(MessageDeliveryState.Read, readAt);
                }

                settings[ReadCursorSettingKey(groupId)] = JsonSerializer.Serialize(readAt.ToString("O"), SerializerOptions);
            }
        }

        var recentMessages = messages.Values
            .Where(message => message.ConversationId == groupId && !message.IsExpired(now))
            .OrderByDescending(static message => message.CreatedAt)
            .ThenByDescending(static message => message.Id.Value, StringComparer.Ordinal)
            .Take(messageLimit)
            .OrderBy(static message => message.CreatedAt)
            .ThenBy(static message => message.Id.Value, StringComparer.Ordinal)
            .ToArray();
        var senderContacts = recentMessages
            .Where(static message => message.Direction == MessageDirection.Incoming)
            .Select(static message => message.Sender)
            .Distinct()
            .Where(sender => contacts.ContainsKey(sender.Value))
            .ToDictionary(sender => sender, sender => contacts[sender.Value]);

        if (markAsRead)
        {
            PersistState();
        }

        return Task.FromResult<GroupConversationOpenSnapshot?>(new GroupConversationOpenSnapshot(
            account,
            group,
            recentMessages,
            senderContacts,
            readAt));
    }

    public Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default)
    {
        settings[key] = JsonSerializer.Serialize(value);
        PersistState();
        return Task.CompletedTask;
    }

    public Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        if (!settings.TryGetValue(key, out var value))
        {
            return Task.FromResult<T?>(default);
        }

        return Task.FromResult(JsonSerializer.Deserialize<T>(value));
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        settings.TryRemove(key, out _);
        PersistState();
        return Task.CompletedTask;
    }

    public Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(schemaVersion);

    public Task SetSchemaVersionAsync(int version, CancellationToken cancellationToken = default)
    {
        schemaVersion = version;
        PersistState();
        return Task.CompletedTask;
    }

    public Task SetSchemaValueAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        schemaValues[key] = value;
        PersistState();
        return Task.CompletedTask;
    }

    public Task<string?> GetSchemaValueAsync(string key, CancellationToken cancellationToken = default) =>
        Task.FromResult(schemaValues.GetValueOrDefault(key));

    public Task<MembershipTrustCommitResult> CommitMembershipTrustAsync(
        MembershipTrustRecord record,
        ulong? expectedHeadRevision,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRecord.Validate(record);
        if (record.Revision >
            MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords)
        {
            return Task.FromResult(MembershipTrustCommitResult.Corrupt);
        }
        var storedRecord = MembershipTrustRepositoryValidation.Clone(record);
        cancellationToken.ThrowIfCancellationRequested();
        var key = new MembershipTrustKey(record.OpaqueProfileKey, record.Domain);

        lock (durableStateGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var history = ValidateMembershipTrustHistory(
                key,
                record.Revision);
            if (history.Snapshot.Result == MembershipTrustReadResult.Corrupt)
            {
                return Task.FromResult(MembershipTrustCommitResult.Corrupt);
            }

            if (history.SelectedRecord is { } existing)
            {
                return Task.FromResult(
                    MembershipTrustRepositoryValidation.Same(existing, record)
                        ? MembershipTrustCommitResult.Idempotent
                        : MembershipTrustCommitResult.Conflict);
            }
            var historyBytes = history.HistoryBytes;
            var recordBytes =
                MembershipTrustRepositoryValidation.HistoryBlobBytes(record);
            if (historyBytes >
                    MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryBytes -
                    recordBytes)
            {
                return Task.FromResult(MembershipTrustCommitResult.Corrupt);
            }

            var records = membershipTrustRecords.TryGetValue(key, out var existingRecords)
                ? existingRecords
                : [];
            var hasHead = membershipTrustHeads.TryGetValue(key, out var headRevision);
            if (hasHead != expectedHeadRevision.HasValue ||
                (hasHead && headRevision != expectedHeadRevision!.Value) ||
                record.Revision != (hasHead ? headRevision + 1 : 1))
            {
                return Task.FromResult(MembershipTrustCommitResult.Conflict);
            }
            if (!MembershipTrustRepositoryValidation.HasValidLinkage(
                    record,
                    history.Snapshot.Head))
            {
                return Task.FromResult(MembershipTrustCommitResult.Conflict);
            }

            if (!hasHead)
            {
                membershipTrustRecords[key] = records;
            }
            records.Add(storedRecord.Revision, storedRecord);
            membershipTrustHeads[key] = storedRecord.Revision;
            try
            {
                membershipTrustFaultInjector?.Invoke(
                    MembershipTrustCommitFaultPoint.BeforeDurableCommit);
                cancellationToken.ThrowIfCancellationRequested();
                PersistState();
            }
            catch
            {
                records.Remove(record.Revision);
                if (hasHead)
                {
                    membershipTrustHeads[key] = headRevision;
                }
                else
                {
                    membershipTrustHeads.Remove(key);
                    if (records.Count == 0)
                    {
                        membershipTrustRecords.Remove(key);
                    }
                }
                throw;
            }

            membershipTrustFaultInjector?.Invoke(
                MembershipTrustCommitFaultPoint.AfterDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(MembershipTrustCommitResult.Applied);
        }
    }

    public Task<MembershipTrustReadSnapshot> ReadMembershipTrustAsync(
        string opaqueProfileKey,
        MembershipTrustDomain domain,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRepositoryValidation.ValidateKey(opaqueProfileKey, domain);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = new MembershipTrustKey(opaqueProfileKey, domain);
            var history = ValidateMembershipTrustHistory(key, selectedRevision: null);
            if (history.Snapshot.Result != MembershipTrustReadResult.Found)
            {
                return Task.FromResult(history.Snapshot);
            }
            return Task.FromResult(new MembershipTrustReadSnapshot(
                MembershipTrustReadResult.Found,
                MembershipTrustRepositoryValidation.Clone(history.Snapshot.Head!),
                history.Snapshot.Predecessor is null
                    ? null
                    : MembershipTrustRepositoryValidation.Clone(
                        history.Snapshot.Predecessor)));
        }
    }

    private readonly record struct MembershipTrustHistoryValidation(
        MembershipTrustReadSnapshot Snapshot,
        MembershipTrustRecord? SelectedRecord,
        long HistoryBytes);

    private MembershipTrustHistoryValidation ValidateMembershipTrustHistory(
        MembershipTrustKey key,
        ulong? selectedRevision)
    {
        var hasRecords = membershipTrustRecords.TryGetValue(key, out var records);
        var hasHead = membershipTrustHeads.TryGetValue(key, out var headRevision);
        if (!hasRecords && !hasHead)
        {
            return new MembershipTrustHistoryValidation(
                MembershipTrustRepositoryValidation.Missing(),
                null,
                0);
        }
        if (!hasRecords || !hasHead || records is null || headRevision == 0 ||
            headRevision >
                MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords ||
            headRevision != checked((ulong)records.Count))
        {
            return new MembershipTrustHistoryValidation(
                MembershipTrustRepositoryValidation.Corrupt(),
                null,
                0);
        }

        MembershipTrustRecord? head = null;
        MembershipTrustRecord? predecessor = null;
        MembershipTrustRecord? previous = null;
        MembershipTrustRecord? selected = null;
        var historyBytes = 0L;
        for (var revision = 1UL; revision <= headRevision; revision++)
        {
            if (!records.TryGetValue(revision, out var record) ||
                !MembershipTrustRepositoryValidation.IsValid(record) ||
                !MembershipTrustRepositoryValidation.HasValidLinkage(record, previous))
            {
                return new MembershipTrustHistoryValidation(
                    MembershipTrustRepositoryValidation.Corrupt(),
                    null,
                    0);
            }
            var recordBytes =
                MembershipTrustRepositoryValidation.HistoryBlobBytes(record);
            if (historyBytes >
                MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryBytes -
                recordBytes)
            {
                return new MembershipTrustHistoryValidation(
                    MembershipTrustRepositoryValidation.Corrupt(),
                    null,
                    0);
            }
            historyBytes += recordBytes;
            if (revision == headRevision - 1)
            {
                predecessor = record;
            }
            if (revision == selectedRevision)
            {
                selected = record;
            }
            previous = record;
            head = record;
        }

        return new MembershipTrustHistoryValidation(
            new MembershipTrustReadSnapshot(
                MembershipTrustReadResult.Found,
                head,
                predecessor),
            selected,
            historyBytes);
    }

    public Task<MembershipTrustClockCommitResult> CommitMembershipTrustClockAsync(
        MembershipTrustClockRecord record,
        ulong? expectedRevision,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustClockRecord.Validate(record);
        var storedRecord = MembershipTrustRepositoryValidation.Clone(record);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var hasCurrent = membershipTrustClocks.TryGetValue(record.OpaqueProfileKey, out var current);
            if (hasCurrent)
            {
                try
                {
                    MembershipTrustClockRecord.Validate(current!);
                }
                catch (InvalidDataException)
                {
                    return Task.FromResult(MembershipTrustClockCommitResult.Corrupt);
                }
            }
            if (hasCurrent != expectedRevision.HasValue ||
                (hasCurrent && current!.Revision != expectedRevision!.Value) ||
                record.Revision != (hasCurrent ? current!.Revision + 1 : 1))
            {
                if (hasCurrent &&
                    current!.Revision == record.Revision &&
                    current.Digest.AsSpan().SequenceEqual(record.Digest))
                {
                    return Task.FromResult(MembershipTrustClockCommitResult.Idempotent);
                }
                return Task.FromResult(MembershipTrustClockCommitResult.Conflict);
            }
            if (hasCurrent && record.ObservedAt < current!.ObservedAt)
            {
                return Task.FromResult(MembershipTrustClockCommitResult.Rollback);
            }

            membershipTrustClocks[storedRecord.OpaqueProfileKey] = storedRecord;
            try
            {
                PersistState();
            }
            catch
            {
                if (hasCurrent)
                {
                    membershipTrustClocks[record.OpaqueProfileKey] = current!;
                }
                else
                {
                    membershipTrustClocks.Remove(record.OpaqueProfileKey);
                }
                throw;
            }
            return Task.FromResult(MembershipTrustClockCommitResult.Applied);
        }
    }

    public Task<MembershipTrustClockReadSnapshot> ReadMembershipTrustClockAsync(
        string opaqueProfileKey,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRepositoryValidation.ValidateProfileKey(opaqueProfileKey);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            if (!membershipTrustClocks.TryGetValue(opaqueProfileKey, out var record))
            {
                return Task.FromResult(new MembershipTrustClockReadSnapshot(
                    MembershipTrustClockReadResult.Missing,
                    null));
            }
            try
            {
                MembershipTrustClockRecord.Validate(record);
                return Task.FromResult(new MembershipTrustClockReadSnapshot(
                    MembershipTrustClockReadResult.Found,
                    MembershipTrustRepositoryValidation.Clone(record)));
            }
            catch (InvalidDataException)
            {
                return Task.FromResult(new MembershipTrustClockReadSnapshot(
                    MembershipTrustClockReadResult.Corrupt,
                    null));
            }
        }
    }

    public Task<MessageReplayClaimResult> TryClaimAsync(
        SessionId sender,
        MessageId messageId,
        string envelopeDigest,
        DateTimeOffset protocolExpiresAt,
        CancellationToken cancellationToken = default)
    {
        ValidateReplayClaim(sender, messageId, envelopeDigest, protocolExpiresAt);
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var key = new ReplayClaimKey(sender.Value, messageId.Value);
            if (!replayClaims.TryGetValue(key, out var existing))
            {
                replayClaims[key] = new ReplayClaim(envelopeDigest, protocolExpiresAt);
                PersistState();
                return Task.FromResult(MessageReplayClaimResult.Accepted);
            }

            return Task.FromResult(string.Equals(existing.EnvelopeDigest, envelopeDigest, StringComparison.Ordinal)
                ? MessageReplayClaimResult.DuplicateSameDigest
                : MessageReplayClaimResult.RejectedDigestMismatch);
        }
    }

    public Task<int> PruneExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var expired = replayClaims
                .Where(item => item.Value.ProtocolExpiresAt <= now)
                .Select(static item => item.Key)
                .Take(ReplayPruneBatchSize)
                .ToArray();

            foreach (var key in expired)
            {
                replayClaims.Remove(key);
            }

            if (expired.Length > 0)
            {
                PersistState();
            }

            return Task.FromResult(expired.Length);
        }
    }

    public Task<string?> GetInboxCursorAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            return Task.FromResult(inboxCursors.GetValueOrDefault(ToScopeKey(scope)));
        }
    }

    public Task<DurableInboxStageResult> StageInboxBatchAsync(
        DurableInboxScope scope,
        string? expectedCursor,
        string? nextCursor,
        IReadOnlyList<DurableInboxWireEntry> entries,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxBatch(scope, expectedCursor, nextCursor, entries);
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var scopeKey = ToScopeKey(scope);
            inboxCursors.TryGetValue(scopeKey, out var currentCursor);
            if (!string.Equals(currentCursor, expectedCursor, StringComparison.Ordinal))
            {
                if (string.Equals(currentCursor, nextCursor, StringComparison.Ordinal))
                {
                    foreach (var entry in entries)
                    {
                        var key = new InboxItemKey(scope.Account.Value, scope.Namespace, entry.ServerHash);
                        if (inboxItems.TryGetValue(key, out var existing)
                            && (existing.StorageTimestamp != entry.StorageTimestamp
                                || !string.Equals(existing.WireDigest, entry.WireDigest, StringComparison.Ordinal)))
                        {
                            throw new DurableInboxDigestMismatchException(
                                $"Inbox server hash '{entry.ServerHash}' was reused with different wire data.");
                        }
                    }

                    return Task.FromResult(new DurableInboxStageResult(0, entries.Count));
                }

                throw new InvalidOperationException("The durable inbox cursor changed before the retrieved batch could be staged.");
            }

            var existingCount = 0;
            var newEntries = new List<DurableInboxWireEntry>(entries.Count);
            var batchEntries = new Dictionary<string, DurableInboxWireEntry>(StringComparer.Ordinal);
            foreach (var entry in entries)
            {
                if (batchEntries.TryGetValue(entry.ServerHash, out var priorBatchEntry))
                {
                    if (priorBatchEntry.StorageTimestamp != entry.StorageTimestamp
                        || !string.Equals(priorBatchEntry.WireDigest, entry.WireDigest, StringComparison.Ordinal))
                    {
                        throw new DurableInboxDigestMismatchException(
                            $"Inbox server hash '{entry.ServerHash}' was repeated with a different wire digest.");
                    }

                    existingCount++;
                    continue;
                }

                batchEntries.Add(entry.ServerHash, entry);
                var key = new InboxItemKey(scope.Account.Value, scope.Namespace, entry.ServerHash);
                if (!inboxItems.TryGetValue(key, out var existing))
                {
                    newEntries.Add(entry);
                    continue;
                }

                if (existing.StorageTimestamp != entry.StorageTimestamp
                    || !string.Equals(existing.WireDigest, entry.WireDigest, StringComparison.Ordinal))
                {
                    throw new DurableInboxDigestMismatchException(
                        $"Inbox server hash '{entry.ServerHash}' was reused with a different wire digest.");
                }

                existingCount++;
            }

            var pendingCount = inboxItems.Keys.Count(key =>
                string.Equals(key.AccountSessionId, scope.Account.Value, StringComparison.Ordinal)
                && key.Namespace == scope.Namespace);
            if (pendingCount + newEntries.Count > DurableInboxLimits.MaxPendingItemCount)
            {
                throw new InvalidOperationException("The durable inbox pending-item limit has been reached.");
            }

            var addedKeys = new List<InboxItemKey>(newEntries.Count);
            var previousSequence = nextInboxSequence;
            var hadCursor = inboxCursors.TryGetValue(scopeKey, out var previousCursor);
            try
            {
                foreach (var entry in newEntries)
                {
                    var key = new InboxItemKey(scope.Account.Value, scope.Namespace, entry.ServerHash);
                    inboxItems.Add(key, new InboxItemState(
                        ++nextInboxSequence,
                        entry.StorageTimestamp,
                        entry.WirePayload,
                        entry.WireDigest,
                        null));
                    addedKeys.Add(key);
                }

                if (nextCursor is not null)
                {
                    inboxCursors[scopeKey] = nextCursor;
                }

                PersistState();
            }
            catch
            {
                foreach (var key in addedKeys)
                {
                    inboxItems.Remove(key);
                }

                nextInboxSequence = previousSequence;
                if (hadCursor)
                {
                    inboxCursors[scopeKey] = previousCursor!;
                }
                else
                {
                    inboxCursors.Remove(scopeKey);
                }

                throw;
            }

            return Task.FromResult(new DurableInboxStageResult(newEntries.Count, existingCount));
        }
    }

    public Task<IReadOnlyList<DurableInboxItem>> ListStagedInboxItemsAsync(
        DurableInboxScope scope,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxList(scope, limit);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            return Task.FromResult<IReadOnlyList<DurableInboxItem>>(inboxItems
                .Where(item => IsInScope(item.Key, scope) && item.Value.Decoded is null)
                .OrderBy(static item => item.Value.Sequence)
                .Take(limit)
                .Select(item => ToDurableInboxItem(item.Key, item.Value))
                .ToArray());
        }
    }

    public Task<DurableInboxPrepareResult> PrepareInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        DurableInboxDecodedMetadata decoded,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);
        ValidateDecodedMetadata(decoded);
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var key = new InboxItemKey(scope.Account.Value, scope.Namespace, serverHash);
            if (!inboxItems.TryGetValue(key, out var item))
            {
                return Task.FromResult(DurableInboxPrepareResult.NotFound);
            }

            if (item.Decoded is not null && !Equals(item.Decoded, decoded))
            {
                inboxItems.Remove(key);
                PersistState();
                return Task.FromResult(DurableInboxPrepareResult.RejectedDigestMismatch);
            }

            var replayKey = new ReplayClaimKey(decoded.Sender.Value, decoded.MessageId.Value);
            if (replayClaims.TryGetValue(replayKey, out var replay))
            {
                inboxItems.Remove(key);
                PersistState();
                return Task.FromResult(string.Equals(replay.EnvelopeDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                    ? DurableInboxPrepareResult.DuplicateSameDigest
                    : DurableInboxPrepareResult.RejectedDigestMismatch);
            }

            var prior = inboxItems
                .Where(candidate => IsInScope(candidate.Key, scope)
                    && candidate.Value.Sequence < item.Sequence
                    && candidate.Value.Decoded is { } priorDecoded
                    && priorDecoded.Sender == decoded.Sender
                    && priorDecoded.MessageId == decoded.MessageId)
                .OrderBy(static candidate => candidate.Value.Sequence)
                .Select(static candidate => candidate.Value.Decoded!)
                .FirstOrDefault();
            if (prior is not null)
            {
                inboxItems.Remove(key);
                PersistState();
                return Task.FromResult(string.Equals(prior.EnvelopeDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                    ? DurableInboxPrepareResult.DuplicateSameDigest
                    : DurableInboxPrepareResult.RejectedDigestMismatch);
            }

            if (item.Decoded is null)
            {
                inboxItems[key] = item with { Decoded = decoded };
                PersistState();
            }

            return Task.FromResult(DurableInboxPrepareResult.Ready);
        }
    }

    public Task<IReadOnlyList<DurableInboxItem>> ListDecodedInboxItemsAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        string? routeKey,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxList(scope, limit);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            return Task.FromResult<IReadOnlyList<DurableInboxItem>>(inboxItems
                .Where(item =>
                    IsInScope(item.Key, scope)
                    && item.Value.Decoded?.Kind == kind
                    && (routeKey is null || string.Equals(item.Value.Decoded.RouteKey, routeKey, StringComparison.Ordinal)))
                .OrderBy(static item => item.Value.Sequence)
                .Take(limit)
                .Select(item => ToDurableInboxItem(item.Key, item.Value))
                .ToArray());
        }
    }

    public Task<DurableInboxAckResult> AcknowledgeInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var key = new InboxItemKey(scope.Account.Value, scope.Namespace, serverHash);
            if (!inboxItems.TryGetValue(key, out var item) || item.Decoded is null)
            {
                return Task.FromResult(DurableInboxAckResult.NotFound);
            }

            var decoded = item.Decoded;
            var replayKey = new ReplayClaimKey(decoded.Sender.Value, decoded.MessageId.Value);
            var result = DurableInboxAckResult.Applied;
            if (replayClaims.TryGetValue(replayKey, out var replay))
            {
                result = string.Equals(replay.EnvelopeDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                    ? DurableInboxAckResult.DuplicateSameDigest
                    : DurableInboxAckResult.RejectedDigestMismatch;
            }
            else
            {
                replayClaims.Add(replayKey, new ReplayClaim(decoded.EnvelopeDigest, decoded.ProtocolExpiresAt));
            }

            inboxItems.Remove(key);
            PersistState();
            return Task.FromResult(result);
        }
    }

    public Task DiscardInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var key = new InboxItemKey(scope.Account.Value, scope.Namespace, serverHash);
            if (inboxItems.Remove(key))
            {
                PersistState();
            }
        }

        return Task.CompletedTask;
    }

    public Task<int> CountPendingInboxItemsAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            return Task.FromResult(inboxItems.Keys.Count(key => IsInScope(key, scope)));
        }
    }

    public Task<int> DiscardDecodedInboxItemsOutsideRoutesAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        IReadOnlySet<string> retainedRouteKeys,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ArgumentNullException.ThrowIfNull(retainedRouteKeys);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            var discarded = inboxItems
                .Where(item =>
                    IsInScope(item.Key, scope)
                    && item.Value.Decoded?.Kind == kind
                    && !retainedRouteKeys.Contains(item.Value.Decoded.RouteKey))
                .ToArray();
            if (discarded.Length == 0)
            {
                return Task.FromResult(0);
            }

            foreach (var item in discarded)
            {
                inboxItems.Remove(item.Key);
            }

            try
            {
                PersistState();
            }
            catch
            {
                foreach (var item in discarded)
                {
                    inboxItems[item.Key] = item.Value;
                }

                throw;
            }

            return Task.FromResult(discarded.Length);
        }
    }

    public Task PersistGroupStateAsync(
        Group group,
        Conversation conversation,
        DateTimeOffset updatedAt,
        GroupStateOutboxItem? outboxItem,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupStatePersistence(group, conversation, updatedAt, outboxItem);
        cancellationToken.ThrowIfCancellationRequested();

        lock (durableStateGate)
        {
            var groupKey = group.Id.Value;
            var settingKey = GroupStateUpdatedAtSettingKey(group.Id);
            groups.TryGetValue(groupKey, out var previousGroup);
            conversations.TryGetValue(groupKey, out var previousConversation);
            settings.TryGetValue(settingKey, out var previousSetting);
            GroupStateOutboxItem? previousOutbox = null;
            if (outboxItem is not null)
            {
                groupStateOutbox.TryGetValue(outboxItem.OperationId, out previousOutbox);
                if (previousOutbox is not null && !SameOutboxItem(previousOutbox, outboxItem))
                {
                    throw new InvalidOperationException("A group outbox operation ID was reused with different state.");
                }

                if (previousOutbox is null && groupStateOutbox.Count >= GroupStateOutboxLimits.MaxPendingItems)
                {
                    throw new InvalidOperationException("The group state outbox limit has been reached.");
                }
            }

            ValidateGroupRevision(previousGroup, group);
            groups[groupKey] = group;
            conversations[groupKey] = conversation;
            settings[settingKey] = JsonSerializer.Serialize(updatedAt.ToString("O"), SerializerOptions);
            if (outboxItem is not null)
            {
                groupStateOutbox[outboxItem.OperationId] = outboxItem;
            }

            try
            {
                PersistState();
            }
            catch
            {
                Restore(groups, groupKey, previousGroup);
                Restore(conversations, groupKey, previousConversation);
                Restore(settings, settingKey, previousSetting);
                if (outboxItem is not null)
                {
                    Restore(groupStateOutbox, outboxItem.OperationId, previousOutbox);
                }

                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<GroupStateOutboxItem>> ListPendingGroupStatePublishesAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupOutboxLimit(limit);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            return Task.FromResult<IReadOnlyList<GroupStateOutboxItem>>(groupStateOutbox.Values
                .OrderBy(static item => item.Group.Id.Value, StringComparer.Ordinal)
                .ThenBy(static item => item.Group.Revision)
                .Take(limit)
                .ToArray());
        }
    }

    public Task AcknowledgeGroupStatePublishAsync(
        string operationId,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupOutboxOperationId(operationId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (durableStateGate)
        {
            if (!groupStateOutbox.Remove(operationId, out var previous))
            {
                return Task.CompletedTask;
            }

            try
            {
                PersistState();
            }
            catch
            {
                groupStateOutbox[operationId] = previous;
                throw;
            }
        }

        return Task.CompletedTask;
    }

    public Task PurgeAccountDataAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (accountDataPurgeGate)
        {
            lock (durableStateGate)
            {
                // Persist the empty account state before mutating memory so a failed write leaves the active
                // account and its durable state intact for an observable retry.
                PersistSnapshot(new SessionStoreSnapshot(
                    [],
                    [],
                    [],
                    [],
                    [],
                    schemaValues.OrderBy(static item => item.Key).ToArray(),
                    schemaVersion,
                    MembershipTrustRecords: MembershipTrustRecordSnapshots(),
                    MembershipTrustHeads: MembershipTrustHeadSnapshots(),
                    MembershipTrustClocks: MembershipTrustClockSnapshots(),
                    TransportOutboxItems: []));

                conversations.Clear();
                contacts.Clear();
                groups.Clear();
                messages.Clear();
                settings.Clear();
                replayClaims.Clear();
                inboxCursors.Clear();
                inboxItems.Clear();
                groupStateOutbox.Clear();
                incomingMessageNotifications.Clear();
                transportOutbox.Clear();
                nextInboxSequence = 0;
                nextIncomingMessageNotificationSequence = 0;
            }
        }

        return Task.CompletedTask;
    }

    private DateTimeOffset? ReadCursorFor(ConversationId conversationId)
    {
        if (!settings.TryGetValue(ReadCursorSettingKey(conversationId), out var raw))
        {
            return null;
        }

        var value = JsonSerializer.Deserialize<string>(raw);
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;
    }

    private static string ReadCursorSettingKey(ConversationId conversationId) =>
        $"sync.read-cursor.{conversationId.Value}";

    private void LoadState()
    {
        if (statePath is null || !File.Exists(statePath))
        {
            return;
        }

        SessionStoreSnapshot? snapshot;
        try
        {
            snapshot = JsonSerializer.Deserialize<SessionStoreSnapshot>(
                File.ReadAllText(statePath),
                SerializerOptions);
        }
        catch (JsonException)
        {
            throw new TransportOutboxCorruptException();
        }
        if (snapshot is null)
        {
            return;
        }

        schemaVersion = snapshot.SchemaVersion;

        foreach (var conversation in snapshot.Conversations)
        {
            conversations[conversation.Id.Value] = conversation;
        }

        foreach (var contact in snapshot.Contacts)
        {
            contacts[contact.Id.Value] = contact;
        }

        foreach (var group in snapshot.Groups)
        {
            groups[group.Id.Value] = group;
        }

        foreach (var message in snapshot.Messages)
        {
            messages[message.Id.Value] = message;
        }

        foreach (var setting in snapshot.Settings)
        {
            settings[setting.Key] = setting.Value;
        }

        foreach (var schemaValue in snapshot.SchemaValues)
        {
            schemaValues[schemaValue.Key] = schemaValue.Value;
        }

        foreach (var replayClaim in snapshot.ReplayClaims ?? [])
        {
            replayClaims[new ReplayClaimKey(replayClaim.SenderSessionId, replayClaim.MessageId)] =
                new ReplayClaim(replayClaim.EnvelopeDigest, replayClaim.ProtocolExpiresAt);
        }

        foreach (var cursor in snapshot.InboxCursors ?? [])
        {
            inboxCursors[new InboxScopeKey(cursor.AccountSessionId, cursor.Namespace)] = cursor.Cursor;
        }

        foreach (var item in snapshot.InboxItems ?? [])
        {
            inboxItems[new InboxItemKey(item.AccountSessionId, item.Namespace, item.ServerHash)] =
                new InboxItemState(
                    item.Sequence,
                    item.StorageTimestamp,
                    item.WirePayload,
                    item.WireDigest,
                    item.Decoded);
        }

        nextInboxSequence = Math.Max(
            snapshot.NextInboxSequence,
            inboxItems.Count == 0 ? 0 : inboxItems.Values.Max(static item => item.Sequence));

        foreach (var item in snapshot.GroupStateOutbox ?? [])
        {
            groupStateOutbox[item.OperationId] = item;
        }

        foreach (var item in snapshot.IncomingMessageNotifications ?? [])
        {
            incomingMessageNotifications[item.MessageId] = item.Sequence;
        }

        nextIncomingMessageNotificationSequence = Math.Max(
            snapshot.NextIncomingMessageNotificationSequence,
            incomingMessageNotifications.Count == 0
                ? 0
                : incomingMessageNotifications.Values.Max());

        foreach (var item in snapshot.MembershipTrustRecords ?? [])
        {
            var key = new MembershipTrustKey(item.Record.OpaqueProfileKey, item.Record.Domain);
            if (!membershipTrustRecords.TryGetValue(key, out var records))
            {
                records = [];
                membershipTrustRecords[key] = records;
            }
            records[item.Record.Revision] = item.Record;
        }

        foreach (var item in snapshot.MembershipTrustHeads ?? [])
        {
            membershipTrustHeads[
                new MembershipTrustKey(item.OpaqueProfileKey, item.Domain)] = item.Revision;
        }

        foreach (var item in snapshot.MembershipTrustClocks ?? [])
        {
            membershipTrustClocks[item.OpaqueProfileKey] = item;
        }

        RestoreTransportOutboxSnapshots(snapshot.TransportOutboxItems ?? []);
    }

    private void PersistState()
    {
        lock (durableStateGate)
        {
            var replayClaimSnapshots = replayClaims.Select(static item => new ReplayClaimSnapshot(
                item.Key.SenderSessionId,
                item.Key.MessageId,
                item.Value.EnvelopeDigest,
                item.Value.ProtocolExpiresAt)).ToArray();
            var inboxCursorSnapshots = inboxCursors.Select(static item => new InboxCursorSnapshot(
                item.Key.AccountSessionId,
                item.Key.Namespace,
                item.Value)).ToArray();
            var inboxItemSnapshots = inboxItems.Select(static item => new InboxItemSnapshot(
                item.Key.AccountSessionId,
                item.Key.Namespace,
                item.Key.ServerHash,
                item.Value.Sequence,
                item.Value.StorageTimestamp,
                item.Value.WirePayload,
                item.Value.WireDigest,
                item.Value.Decoded)).ToArray();
            var groupOutboxSnapshots = groupStateOutbox.Values
                .OrderBy(static item => item.Group.Id.Value, StringComparer.Ordinal)
                .ThenBy(static item => item.Group.Revision)
                .ToArray();
            var incomingMessageNotificationSnapshots = incomingMessageNotifications
                .OrderBy(static item => item.Value)
                .Select(static item => new IncomingMessageNotificationSnapshot(item.Key, item.Value))
                .ToArray();

            PersistSnapshot(new SessionStoreSnapshot(
                conversations.Values.OrderByDescending(item => item.UpdatedAt).ToArray(),
                contacts.Values.OrderBy(item => item.DisplayName ?? item.Id.Value).ToArray(),
                groups.Values.OrderBy(item => item.Name).ToArray(),
                messages.Values.OrderBy(item => item.CreatedAt).ToArray(),
                settings.OrderBy(item => item.Key).ToArray(),
                schemaValues.OrderBy(item => item.Key).ToArray(),
                schemaVersion,
                replayClaimSnapshots,
                inboxCursorSnapshots,
                inboxItemSnapshots,
                nextInboxSequence,
                groupOutboxSnapshots,
                incomingMessageNotificationSnapshots,
                nextIncomingMessageNotificationSequence,
                MembershipTrustRecordSnapshots(),
                MembershipTrustHeadSnapshots(),
                MembershipTrustClockSnapshots(),
                TransportOutboxSnapshots()));
        }
    }

    private IReadOnlyList<MembershipTrustRecordSnapshot> MembershipTrustRecordSnapshots() =>
        membershipTrustRecords
            .OrderBy(static item => item.Key.OpaqueProfileKey, StringComparer.Ordinal)
            .ThenBy(static item => item.Key.Domain)
            .SelectMany(static item => item.Value.Values)
            .Select(static record => new MembershipTrustRecordSnapshot(record))
            .ToArray();

    private IReadOnlyList<MembershipTrustHeadSnapshot> MembershipTrustHeadSnapshots() =>
        membershipTrustHeads
            .OrderBy(static item => item.Key.OpaqueProfileKey, StringComparer.Ordinal)
            .ThenBy(static item => item.Key.Domain)
            .Select(static item => new MembershipTrustHeadSnapshot(
                item.Key.OpaqueProfileKey,
                item.Key.Domain,
                item.Value))
            .ToArray();

    private IReadOnlyList<MembershipTrustClockRecord> MembershipTrustClockSnapshots() =>
        membershipTrustClocks.Values
            .OrderBy(static item => item.OpaqueProfileKey, StringComparer.Ordinal)
            .ToArray();

    private void PersistSnapshot(SessionStoreSnapshot snapshot)
    {
        if (statePath is null)
        {
            return;
        }

        var directory = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(snapshot, SerializerOptions));
            File.Move(temporaryPath, statePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private sealed record SessionStoreSnapshot(
        IReadOnlyList<Conversation> Conversations,
        IReadOnlyList<Contact> Contacts,
        IReadOnlyList<Group> Groups,
        IReadOnlyList<Message> Messages,
        IReadOnlyList<KeyValuePair<string, string>> Settings,
        IReadOnlyList<KeyValuePair<string, string>> SchemaValues,
        int SchemaVersion,
        IReadOnlyList<ReplayClaimSnapshot>? ReplayClaims = null,
        IReadOnlyList<InboxCursorSnapshot>? InboxCursors = null,
        IReadOnlyList<InboxItemSnapshot>? InboxItems = null,
        long NextInboxSequence = 0,
        IReadOnlyList<GroupStateOutboxItem>? GroupStateOutbox = null,
        IReadOnlyList<IncomingMessageNotificationSnapshot>? IncomingMessageNotifications = null,
        long NextIncomingMessageNotificationSequence = 0,
        IReadOnlyList<MembershipTrustRecordSnapshot>? MembershipTrustRecords = null,
        IReadOnlyList<MembershipTrustHeadSnapshot>? MembershipTrustHeads = null,
        IReadOnlyList<MembershipTrustClockRecord>? MembershipTrustClocks = null,
        IReadOnlyList<TransportOutboxPersistenceSnapshot>? TransportOutboxItems = null);

    private sealed record IncomingMessageNotificationSnapshot(string MessageId, long Sequence);

    private sealed record MembershipTrustRecordSnapshot(MembershipTrustRecord Record);

    private sealed record MembershipTrustHeadSnapshot(
        string OpaqueProfileKey,
        MembershipTrustDomain Domain,
        ulong Revision);

    private sealed record MembershipTrustKey(
        string OpaqueProfileKey,
        MembershipTrustDomain Domain);

    private sealed record ReplayClaimKey(string SenderSessionId, string MessageId);

    private sealed record ReplayClaim(string EnvelopeDigest, DateTimeOffset ProtocolExpiresAt);

    private sealed record ReplayClaimSnapshot(
        string SenderSessionId,
        string MessageId,
        string EnvelopeDigest,
        DateTimeOffset ProtocolExpiresAt);

    private sealed record InboxScopeKey(string AccountSessionId, int Namespace);

    private sealed record InboxItemKey(string AccountSessionId, int Namespace, string ServerHash);

    private sealed record InboxItemState(
        long Sequence,
        long StorageTimestamp,
        string WirePayload,
        string WireDigest,
        DurableInboxDecodedMetadata? Decoded);

    private sealed record InboxCursorSnapshot(string AccountSessionId, int Namespace, string Cursor);

    private sealed record InboxItemSnapshot(
        string AccountSessionId,
        int Namespace,
        string ServerHash,
        long Sequence,
        long StorageTimestamp,
        string WirePayload,
        string WireDigest,
        DurableInboxDecodedMetadata? Decoded);

    private static string GroupStateUpdatedAtSettingKey(ConversationId groupId) =>
        $"sync.group-state-updated.{groupId.Value}";

    private static bool SameOutboxItem(GroupStateOutboxItem left, GroupStateOutboxItem right) =>
        string.Equals(
            JsonSerializer.Serialize(left, SerializerOptions),
            JsonSerializer.Serialize(right, SerializerOptions),
            StringComparison.Ordinal);

    private static void ValidateGroupStatePersistence(
        Group group,
        Conversation conversation,
        DateTimeOffset updatedAt,
        GroupStateOutboxItem? outboxItem)
    {
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(conversation);
        if (group.Revision < 1 || group.Id != conversation.Id || conversation.Kind != ConversationKind.GroupV2
            || updatedAt <= DateTimeOffset.UnixEpoch)
        {
            throw new ArgumentException("Group persistence state is invalid.");
        }

        if (outboxItem is null)
        {
            return;
        }

        ValidateGroupOutboxOperationId(outboxItem.OperationId);
        if (!string.Equals(
                JsonSerializer.Serialize(outboxItem.Group, SerializerOptions),
                JsonSerializer.Serialize(group, SerializerOptions),
                StringComparison.Ordinal)
            || outboxItem.UpdatedAt != updatedAt
            || outboxItem.Recipients.Count == 0 || outboxItem.Recipients.Count > 4096
            || outboxItem.Recipients.Any(static recipient => string.IsNullOrWhiteSpace(recipient.Value)))
        {
            throw new ArgumentException("Group outbox state is invalid.", nameof(outboxItem));
        }
    }

    private static void ValidateGroupRevision(Group? existing, Group candidate)
    {
        if (existing is null)
        {
            return;
        }

        if (candidate.Revision < existing.Revision
            || (candidate.Revision == existing.Revision
                && !string.Equals(
                    JsonSerializer.Serialize(existing, SerializerOptions),
                    JsonSerializer.Serialize(candidate, SerializerOptions),
                    StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("A group revision cannot be overwritten by divergent or older state.");
        }
    }

    private static void ValidateGroupOutboxLimit(int limit)
    {
        if (limit is <= 0 or > GroupStateOutboxLimits.MaxPublishBatch)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static void ValidateIncomingMessageNotificationLimit(int limit)
    {
        if (limit is <= 0 or > IncomingMessageNotificationLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static string[] ValidateIncomingMessageNotificationIds(IReadOnlyCollection<MessageId> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        var values = ids
            .Select(static id => id.Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (values.Length > IncomingMessageNotificationLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(ids));
        }

        if (values.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Message IDs must not be empty.", nameof(ids));
        }

        return values;
    }

    private static void ValidateGroupOutboxOperationId(string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId) || operationId.Length > 256)
        {
            throw new ArgumentException("Group outbox operation ID is invalid.", nameof(operationId));
        }
    }

    private static void Restore<T>(IDictionary<string, T> dictionary, string key, T? previous)
        where T : class
    {
        if (previous is null)
        {
            dictionary.Remove(key);
        }
        else
        {
            dictionary[key] = previous;
        }
    }

    private static InboxScopeKey ToScopeKey(DurableInboxScope scope) =>
        new(scope.Account.Value, scope.Namespace);

    private static bool IsInScope(InboxItemKey key, DurableInboxScope scope) =>
        key.Namespace == scope.Namespace
        && string.Equals(key.AccountSessionId, scope.Account.Value, StringComparison.Ordinal);

    private static DurableInboxItem ToDurableInboxItem(InboxItemKey key, InboxItemState item) =>
        new(
            item.Sequence,
            new DurableInboxScope(SessionId.Parse(key.AccountSessionId), key.Namespace),
            key.ServerHash,
            item.StorageTimestamp,
            item.WirePayload,
            item.WireDigest,
            item.Decoded);

    private static void ValidateInboxBatch(
        DurableInboxScope scope,
        string? expectedCursor,
        string? nextCursor,
        IReadOnlyList<DurableInboxWireEntry> entries)
    {
        ValidateInboxScope(scope);
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(entries), "Inbox batches must be bounded.");
        }

        ValidateOptionalCursor(expectedCursor, nameof(expectedCursor));
        ValidateOptionalCursor(nextCursor, nameof(nextCursor));
        if (entries.Count == 0)
        {
            if (!string.Equals(expectedCursor, nextCursor, StringComparison.Ordinal))
            {
                throw new ArgumentException("An empty inbox batch cannot advance the cursor.", nameof(nextCursor));
            }

            return;
        }

        if (!string.Equals(entries[^1].ServerHash, nextCursor, StringComparison.Ordinal))
        {
            throw new ArgumentException("The next cursor must be the final staged server hash.", nameof(nextCursor));
        }

        foreach (var entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry);
            ValidateServerHash(entry.ServerHash);
            if (entry.WirePayload is null || entry.WirePayload.Length > DurableInboxLimits.MaxWirePayloadChars)
            {
                throw new ArgumentOutOfRangeException(nameof(entries), "An inbox wire payload exceeds the durable staging limit.");
            }

            var computedDigest = DurableInboxWireEntry.ComputeDigest(entry.WirePayload);
            if (!string.Equals(computedDigest, entry.WireDigest, StringComparison.Ordinal))
            {
                throw new DurableInboxDigestMismatchException(
                    $"Inbox entry '{entry.ServerHash}' does not match its declared wire digest.");
            }
        }
    }

    private static void ValidateInboxList(DurableInboxScope scope, int limit)
    {
        ValidateInboxScope(scope);
        if (limit is <= 0 or > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static void ValidateInboxScope(DurableInboxScope scope)
    {
        if (string.IsNullOrWhiteSpace(scope.Account.Value))
        {
            throw new ArgumentException("Inbox account session ID is required.", nameof(scope));
        }
    }

    private static void ValidateOptionalCursor(string? cursor, string parameterName)
    {
        if (cursor is not null && (string.IsNullOrWhiteSpace(cursor) || cursor.Length > DurableInboxLimits.MaxServerHashChars))
        {
            throw new ArgumentException("Inbox cursor is invalid.", parameterName);
        }
    }

    private static void ValidateServerHash(string serverHash)
    {
        if (string.IsNullOrWhiteSpace(serverHash) || serverHash.Length > DurableInboxLimits.MaxServerHashChars)
        {
            throw new ArgumentException("Inbox server hash is invalid.", nameof(serverHash));
        }
    }

    private static void ValidateDecodedMetadata(DurableInboxDecodedMetadata decoded)
    {
        ArgumentNullException.ThrowIfNull(decoded);
        if (!Enum.IsDefined(decoded.Kind))
        {
            throw new ArgumentOutOfRangeException(nameof(decoded));
        }

        if (string.IsNullOrWhiteSpace(decoded.RouteKey))
        {
            throw new ArgumentException("Decoded inbox route is required.", nameof(decoded));
        }

        ValidateReplayClaim(
            decoded.Sender,
            decoded.MessageId,
            decoded.EnvelopeDigest,
            decoded.ProtocolExpiresAt);
    }

    private static void ValidateReplayClaim(
        SessionId sender,
        MessageId messageId,
        string envelopeDigest,
        DateTimeOffset protocolExpiresAt)
    {
        if (string.IsNullOrWhiteSpace(sender.Value))
        {
            throw new ArgumentException("Sender session ID is required.", nameof(sender));
        }

        if (string.IsNullOrWhiteSpace(messageId.Value))
        {
            throw new ArgumentException("Message ID is required.", nameof(messageId));
        }

        if (envelopeDigest is null
            || envelopeDigest.Length != 64
            || envelopeDigest.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Envelope digest must be 64 lowercase hexadecimal characters.", nameof(envelopeDigest));
        }

        if (protocolExpiresAt <= DateTimeOffset.UnixEpoch)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolExpiresAt), "Protocol expiry must be after the Unix epoch.");
        }
    }
}
