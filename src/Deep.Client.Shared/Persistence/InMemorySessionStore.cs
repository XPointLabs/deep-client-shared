using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Persistence;

public sealed class InMemorySessionStore : ILocalSessionStore
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
