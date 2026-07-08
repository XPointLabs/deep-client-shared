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

    Task UpdateAsync(Message message, CancellationToken cancellationToken = default);

    Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default);

    Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListForConversationAsync(ConversationId conversationId, CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListRecentForConversationAsync(
        ConversationId conversationId,
        int limit,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<Message> ListBeforeForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        int limit,
        CancellationToken cancellationToken = default);

    Task<int> CountUnreadForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset? readCursor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public interface ISettingsRepository
{
    Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default);

    Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default);

    Task DeleteAsync(string key, CancellationToken cancellationToken = default);
}

public interface ILocalSessionStore :
    IConversationRepository,
    IContactRepository,
    IGroupRepository,
    IMessageRepository,
    ISettingsRepository,
    ISchemaStore;
