using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemorySessionStore : ILocalSessionStore, IOneToOneConversationOpenRepository
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
    private readonly string? statePath;
    private int schemaVersion;

    public InMemorySessionStore(string? statePath = null)
    {
        this.statePath = string.IsNullOrWhiteSpace(statePath) ? null : statePath;
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
        messages[message.Id.Value] = message;
        PersistState();
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
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in messages.Values
                     .Where(item => item.ConversationId == conversationId)
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
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in messages.Values
                     .Where(item => item.ConversationId == conversationId && item.CreatedAt < beforeCreatedAt)
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
            && (readCursor is null || message.CreatedAt > readCursor.Value)
            && !message.IsExpired(now));

        return Task.FromResult(count);
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
                && (readCursor is null || message.CreatedAt > readCursor.Value)
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
        if (!string.Equals(contact.DisplayName, normalizedContactDisplayName, StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(normalizedDisplayName) && contact.DisplayName != normalizedDisplayName))
        {
            contact = contact with
            {
                DisplayName = string.IsNullOrWhiteSpace(normalizedDisplayName) ? normalizedContactDisplayName : normalizedDisplayName,
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

        var recentMessages = messages.Values
            .Where(message => message.ConversationId == conversationId)
            .OrderByDescending(message => message.CreatedAt)
            .ThenByDescending(message => message.Id.Value, StringComparer.Ordinal)
            .Take(messageLimit)
            .OrderBy(message => message.CreatedAt)
            .ThenBy(message => message.Id.Value, StringComparer.Ordinal)
            .Where(message => !message.IsExpired(now))
            .ToArray();
        DateTimeOffset readAt;
        if (markAsRead)
        {
            readAt = LatestIncomingOrNow(recentMessages, now);
            settings[ReadCursorSettingKey(conversationId)] = JsonSerializer.Serialize(readAt.ToString("O"), SerializerOptions);
        }
        else
        {
            readAt = ReadCursorFor(conversationId) ?? DateTimeOffset.MinValue;
        }

        PersistState();

        return Task.FromResult<OneToOneConversationOpenSnapshot?>(new OneToOneConversationOpenSnapshot(
            account,
            conversation,
            contact,
            recentMessages,
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

    private static DateTimeOffset LatestIncomingOrNow(IEnumerable<Message> messages, DateTimeOffset now)
    {
        var readAt = now;
        foreach (var message in messages)
        {
            if (message.Direction == MessageDirection.Incoming && message.CreatedAt > readAt)
            {
                readAt = message.CreatedAt;
            }
        }

        return readAt;
    }

    private void LoadState()
    {
        if (statePath is null || !File.Exists(statePath))
        {
            return;
        }

        var snapshot = JsonSerializer.Deserialize<SessionStoreSnapshot>(File.ReadAllText(statePath), SerializerOptions);
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
    }

    private void PersistState()
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

        var snapshot = new SessionStoreSnapshot(
            conversations.Values.OrderByDescending(item => item.UpdatedAt).ToArray(),
            contacts.Values.OrderBy(item => item.DisplayName ?? item.Id.Value).ToArray(),
            groups.Values.OrderBy(item => item.Name).ToArray(),
            messages.Values.OrderBy(item => item.CreatedAt).ToArray(),
            settings.OrderBy(item => item.Key).ToArray(),
            schemaValues.OrderBy(item => item.Key).ToArray(),
            schemaVersion);

        File.WriteAllText(statePath, JsonSerializer.Serialize(snapshot, SerializerOptions));
    }

    private sealed record SessionStoreSnapshot(
        IReadOnlyList<Conversation> Conversations,
        IReadOnlyList<Contact> Contacts,
        IReadOnlyList<Group> Groups,
        IReadOnlyList<Message> Messages,
        IReadOnlyList<KeyValuePair<string, string>> Settings,
        IReadOnlyList<KeyValuePair<string, string>> SchemaValues,
        int SchemaVersion);
}
