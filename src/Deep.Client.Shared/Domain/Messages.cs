namespace Deep.Client.Shared.Domain;

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
    string? ServerHash = null)
{
    public bool HasAttachments => Attachments.Count > 0;

    public bool IsExpired(DateTimeOffset now) => ExpiresAt is not null && ExpiresAt <= now;

    public Message Mark(MessageDeliveryState state, DateTimeOffset? readAt = null) =>
        this with { DeliveryState = state, ReadAt = readAt ?? ReadAt };
}
