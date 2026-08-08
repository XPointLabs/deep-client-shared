using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public enum MailboxDispatchRouteOutcome
{
    Started = 1,
    Durable = 2,
    NoDispatch = 3,
    Failed = 4,
    Canceled = 5
}

/// <summary>
/// Immutable evidence for one concrete native mailbox dispatch attempt. A durable
/// observation names the coordinator from the authenticated MQR3 receipt; it is
/// never inferred from a candidate route or endpoint string.
/// </summary>
public sealed class MailboxDispatchRouteUsage
{
    private const int RouterIdLength = 32;
    private readonly byte[] entryRouterId;

    public MailboxDispatchRouteUsage(
        MessageId messageId,
        ConversationId conversationId,
        SessionId recipient,
        Guid attemptId,
        MailboxDispatchRouteOutcome outcome,
        ReadOnlySpan<byte> entryRouterId)
    {
        if (string.IsNullOrWhiteSpace(messageId.Value))
            throw new ArgumentException("A dispatch usage requires a message ID.", nameof(messageId));
        if (string.IsNullOrWhiteSpace(conversationId.Value))
            throw new ArgumentException("A dispatch usage requires a conversation ID.", nameof(conversationId));
        if (string.IsNullOrWhiteSpace(recipient.Value))
            throw new ArgumentException("A dispatch usage requires a recipient.", nameof(recipient));
        if (attemptId == Guid.Empty)
            throw new ArgumentException("A dispatch usage requires a non-empty attempt ID.", nameof(attemptId));
        if (!Enum.IsDefined(outcome))
            throw new ArgumentOutOfRangeException(nameof(outcome));
        if (outcome == MailboxDispatchRouteOutcome.Durable)
        {
            if (entryRouterId.Length != RouterIdLength ||
                entryRouterId.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException(
                    "A durable dispatch usage requires an exact non-zero router ID.",
                    nameof(entryRouterId));
            }
        }
        else if (!entryRouterId.IsEmpty)
        {
            throw new ArgumentException(
                "A non-durable dispatch usage cannot claim a router ID.",
                nameof(entryRouterId));
        }

        MessageId = messageId;
        ConversationId = conversationId;
        Recipient = recipient;
        AttemptId = attemptId;
        Outcome = outcome;
        this.entryRouterId = entryRouterId.ToArray();
    }

    public MessageId MessageId { get; }
    public ConversationId ConversationId { get; }
    public SessionId Recipient { get; }
    public Guid AttemptId { get; }
    public MailboxDispatchRouteOutcome Outcome { get; }
    public ReadOnlyMemory<byte> EntryRouterId => entryRouterId.ToArray();
}

/// <summary>
/// Receives immutable diagnostic snapshots. Implementations must be thread-safe,
/// non-blocking, and must not throw; transport also contains observer exceptions.
/// </summary>
public interface IMailboxDispatchRouteUsageObserver
{
    void Observe(MailboxDispatchRouteUsage usage);
}
