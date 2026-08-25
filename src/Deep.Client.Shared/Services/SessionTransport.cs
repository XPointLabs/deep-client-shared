using System.Collections.Concurrent;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record OutboundMessageEnvelope(
    SessionId Sender,
    SessionId Recipient,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    MessageId? Id = null,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public sealed record InboundMessageEnvelope(
    MessageId Id,
    SessionId Sender,
    SessionId Recipient,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    string ServerHash,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public interface ISessionMessageTransport
{
    Task SendAsync(
        OutboundMessageEnvelope envelope,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default);
}

public interface IRecoveryProfileLookup
{
    Task<string?> TryGetDisplayNameAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default);
}

/// <summary>Deterministic in-memory test transport. Never registered by release composition.</summary>
public sealed class StubSessionBackend : ISessionMessageTransport, IRecoveryProfileLookup
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<InboundMessageEnvelope>>
        inboxes = new(StringComparer.Ordinal);

    public Task SendAsync(
        OutboundMessageEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        cancellationToken.ThrowIfCancellationRequested();
        var serverHash = Convert.ToHexString(Guid.NewGuid().ToByteArray())
            .ToLowerInvariant();
        var inbound = new InboundMessageEnvelope(
            envelope.Id ?? MessageId.NewId(),
            envelope.Sender,
            envelope.Recipient,
            envelope.Body,
            envelope.Attachments,
            envelope.CreatedAt,
            envelope.ExpiresAt,
            serverHash,
            envelope.ReplyTo,
            envelope.Reaction);

        inboxes.GetOrAdd(
                envelope.Recipient.Value,
                static _ => new ConcurrentQueue<InboundMessageEnvelope>())
            .Enqueue(inbound);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!inboxes.TryGetValue(recipient.Value, out var queue))
        {
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        }

        var result = new List<InboundMessageEnvelope>();
        while (queue.TryDequeue(out var item))
        {
            result.Add(item);
        }

        return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(result);
    }

    public Task<string?> TryGetDisplayNameAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<string?>(null);
    }
}
