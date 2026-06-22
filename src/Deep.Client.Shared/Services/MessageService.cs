using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed class MessageService(
    ConversationService conversationService,
    IConversationRepository conversations,
    IMessageRepository messages,
    ISettingsRepository settings,
    ISessionMessageTransport transport,
    IGroupSyncTransport groupSync,
    IClock clock)
{
    public async Task<Message> SendOneToOneAsync(
        SessionId sender,
        SessionId recipient,
        string body,
        IEnumerable<AttachmentMetadata>? attachments = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(body);

        var conversation = await conversationService.GetOrCreateOneToOneAsync(recipient, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        var now = clock.UtcNow;
        var expiresAt = CalculateExpiry(conversation.Settings.DisappearingMessages, now);
        var attachmentList = attachments?.ToArray() ?? [];
        var pending = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender,
            recipient,
            body.Trim(),
            MessageDirection.Outgoing,
            MessageDeliveryState.Sending,
            now,
            attachmentList,
            expiresAt);

        await messages.AppendAsync(pending, cancellationToken).ConfigureAwait(false);
        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, pending.Body, attachmentList, now, expiresAt), cancellationToken)
            .ConfigureAwait(false);

        var sent = pending.Mark(MessageDeliveryState.Sent);
        await messages.UpdateAsync(sent, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        await PruneExpiredConversationMessagesAsync(conversation.Id, cancellationToken).ConfigureAwait(false);
        return sent;
    }

    public async Task<IReadOnlyList<Message>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        var envelopes = await transport.ReceiveAsync(recipient, cancellationToken).ConfigureAwait(false);
        var received = new List<Message>(envelopes.Count);

        foreach (var envelope in envelopes)
        {
            if (envelope.ExpiresAt is { } expiry && expiry <= clock.UtcNow)
            {
                continue;
            }

            var conversation = await conversationService.GetOrCreateOneToOneAsync(envelope.Sender, cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            if (await HasMessageWithServerHashAsync(conversation.Id, envelope.ServerHash, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            var message = new Message(
                envelope.Id,
                conversation.Id,
                envelope.Sender,
                recipient,
                envelope.Body,
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                envelope.CreatedAt,
                envelope.Attachments,
                envelope.ExpiresAt,
                ServerHash: envelope.ServerHash);

            await messages.AppendAsync(message, cancellationToken).ConfigureAwait(false);
            await conversations.UpsertAsync(conversation.Touch(clock.UtcNow), cancellationToken).ConfigureAwait(false);
            received.Add(message);
        }

        if (received.Count > 0)
        {
            await PruneExpiredConversationMessagesAsync(received[0].ConversationId, cancellationToken).ConfigureAwait(false);
        }

        return received;
    }

    private async Task<bool> HasMessageWithServerHashAsync(
        ConversationId conversationId,
        string serverHash,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(serverHash))
        {
            return false;
        }

        await foreach (var existing in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (string.Equals(existing.ServerHash, serverHash, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public async Task<Message> SendGroupAsync(
        SessionId sender,
        ConversationId groupId,
        string body,
        IEnumerable<AttachmentMetadata>? attachments = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(body);

        var group = await conversationService.GetGroupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || group.IsDestroyed)
        {
            throw new InvalidOperationException("Group was not found.");
        }

        if (group.Members.All(member => member.SessionId != sender))
        {
            throw new InvalidOperationException("Only group members can send group messages.");
        }

        var now = clock.UtcNow;
        var conversation = await conversations.GetAsync(groupId, cancellationToken).ConfigureAwait(false)
            ?? new Conversation(
                group.Id,
                ConversationKind.GroupV2,
                group.Name,
                ConversationSettings.Default(ConversationKind.GroupV2),
                now,
                now);

        var expiresAt = CalculateExpiry(conversation.Settings.DisappearingMessages, now);
        var attachmentList = attachments?.ToArray() ?? [];
        var pending = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender,
            Recipient: null,
            body.Trim(),
            MessageDirection.Outgoing,
            MessageDeliveryState.Sending,
            now,
            attachmentList,
            expiresAt);

        await messages.AppendAsync(pending, cancellationToken).ConfigureAwait(false);
        await groupSync.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            pending.Id,
            conversation.Id,
            sender,
            pending.Body,
            attachmentList,
            now,
            expiresAt), cancellationToken).ConfigureAwait(false);

        var sent = pending.Mark(MessageDeliveryState.Sent);
        await messages.UpdateAsync(sent, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        await PruneExpiredConversationMessagesAsync(conversation.Id, cancellationToken).ConfigureAwait(false);
        return sent;
    }

    public async Task<IReadOnlyList<Message>> ReceiveGroupAsync(
        SessionId recipient,
        ConversationId groupId,
        CancellationToken cancellationToken = default)
    {
        var group = await conversationService.GetGroupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || group.IsDestroyed || group.IsKicked)
        {
            return [];
        }

        if (group.Members.All(member => member.SessionId != recipient))
        {
            return [];
        }

        var conversation = await conversations.GetAsync(groupId, cancellationToken).ConfigureAwait(false)
            ?? new Conversation(
                group.Id,
                ConversationKind.GroupV2,
                group.Name,
                ConversationSettings.Default(ConversationKind.GroupV2),
                group.CreatedAt,
                clock.UtcNow);

        var envelopes = await groupSync.ReceiveGroupMessagesAsync(groupId, cancellationToken).ConfigureAwait(false);
        var received = new List<Message>(envelopes.Count);

        foreach (var envelope in envelopes)
        {
            if (envelope.ExpiresAt is { } expiry && expiry <= clock.UtcNow)
            {
                continue;
            }

            if (envelope.Sender == recipient)
            {
                continue;
            }

            if (await HasMessageWithServerHashAsync(groupId, envelope.ServerHash, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            var message = new Message(
                envelope.Id,
                groupId,
                envelope.Sender,
                Recipient: null,
                envelope.Body,
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                envelope.CreatedAt,
                envelope.Attachments,
                envelope.ExpiresAt,
                ServerHash: envelope.ServerHash);

            await messages.AppendAsync(message, cancellationToken).ConfigureAwait(false);
            received.Add(message);
        }

        if (received.Count > 0)
        {
            await conversations.UpsertAsync(conversation.Touch(clock.UtcNow), cancellationToken).ConfigureAwait(false);
            await PruneExpiredConversationMessagesAsync(groupId, cancellationToken).ConfigureAwait(false);
        }

        return received;
    }

    public async Task<IReadOnlyList<Message>> ListConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default)
    {
        var result = new List<Message>();
        await foreach (var message in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (message.IsExpired(clock.UtcNow))
            {
                continue;
            }

            result.Add(message);
        }

        return result;
    }

    public async Task<IReadOnlyList<Message>> ListRecentConversationMessagesAsync(
        ConversationId conversationId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Message limit must be greater than zero.");
        }

        var result = new List<Message>(limit);
        await foreach (var message in messages.ListRecentForConversationAsync(conversationId, limit, cancellationToken).ConfigureAwait(false))
        {
            if (message.IsExpired(clock.UtcNow))
            {
                continue;
            }

            result.Add(message);
        }

        return result;
    }

    public async Task<IReadOnlyList<Message>> ListConversationMessagesBeforeAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Message limit must be greater than zero.");
        }

        var result = new List<Message>(limit);
        await foreach (var message in messages.ListBeforeForConversationAsync(conversationId, beforeCreatedAt, limit, cancellationToken).ConfigureAwait(false))
        {
            if (message.IsExpired(clock.UtcNow))
            {
                continue;
            }

            result.Add(message);
        }

        return result;
    }

    public async Task<Message?> MarkAsReadAsync(MessageId messageId, CancellationToken cancellationToken = default)
    {
        var existing = await messages.GetAsync(messageId, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            return null;
        }

        var readAt = clock.UtcNow;
        var updated = existing.Mark(MessageDeliveryState.Read, readAt);
        await messages.UpdateAsync(updated, cancellationToken).ConfigureAwait(false);
        await settings.SetAsync(ReadCursorSettingKey(updated.ConversationId), readAt.ToString("O"), cancellationToken).ConfigureAwait(false);
        return updated;
    }

    public async Task<DateTimeOffset> MarkConversationAsReadAsync(
        ConversationId conversationId,
        DateTimeOffset? readAt = null,
        CancellationToken cancellationToken = default)
    {
        var cursor = readAt ?? clock.UtcNow;
        await settings.SetAsync(ReadCursorSettingKey(conversationId), cursor.ToString("O"), cancellationToken).ConfigureAwait(false);
        return cursor;
    }

    public async Task<int> ApplyReadCursorAsync(ConversationId conversationId, DateTimeOffset readAt, CancellationToken cancellationToken = default)
    {
        var changed = 0;
        await foreach (var message in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (message.Direction != MessageDirection.Incoming || message.CreatedAt > readAt)
            {
                continue;
            }

            if (message.DeliveryState == MessageDeliveryState.Read && message.ReadAt is not null && message.ReadAt >= readAt)
            {
                continue;
            }

            await messages.UpdateAsync(message.Mark(MessageDeliveryState.Read, readAt), cancellationToken).ConfigureAwait(false);
            changed++;
        }

        if (changed > 0)
        {
            await settings.SetAsync(ReadCursorSettingKey(conversationId), readAt.ToString("O"), cancellationToken).ConfigureAwait(false);
        }

        return changed;
    }

    public async Task<DateTimeOffset?> GetReadCursorAsync(ConversationId conversationId, CancellationToken cancellationToken = default)
    {
        var raw = await settings.GetAsync<string>(ReadCursorSettingKey(conversationId), cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTimeOffset.TryParse(raw, out var parsed) ? parsed : null;
    }

    public async Task<int> PruneExpiredConversationMessagesAsync(ConversationId conversationId, CancellationToken cancellationToken = default)
    {
        var removed = 0;
        await foreach (var message in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (!message.IsExpired(clock.UtcNow))
            {
                continue;
            }

            await messages.DeleteAsync(message.Id, cancellationToken).ConfigureAwait(false);
            removed++;
        }

        return removed;
    }

    private static string ReadCursorSettingKey(ConversationId conversationId) => $"sync.read-cursor.{conversationId.Value}";

    private static DateTimeOffset? CalculateExpiry(DisappearingMessageSettings settings, DateTimeOffset now) =>
        settings.Mode == DisappearingMode.Disabled ? null : now.Add(settings.Duration!.Value);
}
