using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record OutboundGroupMessageEnvelope(
    MessageId Id,
    ConversationId GroupId,
    SessionId Sender,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null,
    IReadOnlyList<SessionId>? NotifyRecipients = null);

public sealed record InboundGroupMessageEnvelope(
    MessageId Id,
    ConversationId GroupId,
    SessionId Sender,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    string ServerHash,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public sealed record InboundGroupStateEnvelope(
    Group Group,
    DateTimeOffset UpdatedAt,
    string ServerHash,
    SessionId Sender = default);

public interface IGroupSyncTransport
{
    Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default);

    Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default);
}

public sealed class DisabledGroupSyncTransport : IGroupSyncTransport
{
    public Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>([]);
    }

    public Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>([]);
    }
}
