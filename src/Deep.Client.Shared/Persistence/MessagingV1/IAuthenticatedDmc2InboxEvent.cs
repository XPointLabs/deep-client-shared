using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.MessagingV1;

// Transaction data shared by the two closed handoffs, not an authentication API.
internal interface IAuthenticatedDmc2InboxEvent
{
    ReadOnlyMemory<byte> ExactDmc2 { get; }
    ReadOnlyMemory<byte> LocalAccountId { get; }
    ulong LocalAccountGeneration { get; }
    ReadOnlyMemory<byte> ConversationId { get; }
    ReadOnlyMemory<byte> LogicalMessageId { get; }
    ReadOnlyMemory<byte> AuthorAccountId { get; }
    ReadOnlyMemory<byte> AuthorDeviceId { get; }
    Dmc2ContentKind ContentKind { get; }
}
