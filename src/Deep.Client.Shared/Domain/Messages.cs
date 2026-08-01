namespace Deep.Client.Shared.Domain;

public sealed record MessageReply(
    MessageId MessageId,
    SessionId Sender,
    string Body);

public sealed record MessageReaction(
    string Emoji,
    SessionId Reactor);

public sealed record MessageReactionUpdate(
    MessageId TargetMessageId,
    string Emoji,
    bool Remove);

public sealed record Message(
    MessageId Id,
    ConversationId ConversationId,
    SessionId Sender,
    SessionId? Recipient,
    string Body,
    MessageDirection Direction,
    MessageDeliveryState DeliveryState,
    DateTimeOffset CreatedAt,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset? ExpiresAt = null,
    DateTimeOffset? ReadAt = null,
    string? ServerHash = null,
    MessageReply? ReplyTo = null,
    IReadOnlyList<MessageReaction>? Reactions = null,
    IReadOnlyList<SessionId>? NotifyRecipients = null)
{
    public bool HasAttachments => Attachments.Count > 0;

    public IReadOnlyList<MessageReaction> ReactionItems => Reactions ?? [];

    public bool IsExpired(DateTimeOffset now) => ExpiresAt is not null && ExpiresAt <= now;

    public Message Mark(MessageDeliveryState state, DateTimeOffset? readAt = null) =>
        this with { DeliveryState = state, ReadAt = readAt ?? ReadAt };
}
