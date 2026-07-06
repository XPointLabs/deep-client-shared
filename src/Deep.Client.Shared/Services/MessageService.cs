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
        MessageId? replyToMessageId = null,
        CancellationToken cancellationToken = default)
    {
        var pending = await QueueOneToOneAsync(sender, recipient, body, attachments, replyToMessageId, cancellationToken).ConfigureAwait(false);
        return await DispatchOneToOneAsync(pending, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Message> QueueOneToOneAsync(
        SessionId sender,
        SessionId recipient,
        string body,
        IEnumerable<AttachmentMetadata>? attachments = null,
        MessageId? replyToMessageId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(body);

        var conversation = await conversationService.GetOrCreateOneToOneAsync(recipient, approve: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        var contact = await conversationService.GetContactAsync(recipient, cancellationToken).ConfigureAwait(false);
        if (contact?.IsBlocked == true)
        {
            throw new InvalidOperationException("Cannot send a message to a blocked contact.");
        }
        var now = clock.UtcNow;
        var replyTo = await CreateReplyAsync(conversation.Id, replyToMessageId, cancellationToken).ConfigureAwait(false);
        var pending = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender,
            recipient,
            body.Trim(),
            MessageDirection.Outgoing,
            MessageDeliveryState.Sending,
            now,
            attachments?.ToArray() ?? [],
            CalculateExpiry(conversation.Settings.DisappearingMessages, now),
            ReplyTo: replyTo);

        await messages.AppendAsync(pending, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        await PruneExpiredConversationMessagesAsync(conversation.Id, cancellationToken).ConfigureAwait(false);
        return pending;
    }

    public async Task<Message> DispatchOneToOneAsync(Message pending, CancellationToken cancellationToken = default)
    {
        if (pending.Direction != MessageDirection.Outgoing || pending.Recipient is null)
        {
            throw new ArgumentException("Only queued one-to-one messages can be dispatched.", nameof(pending));
        }

        try
        {
            await transport.SendAsync(new OutboundMessageEnvelope(
                pending.Sender,
                pending.Recipient.Value,
                pending.Body,
                pending.Attachments,
                pending.CreatedAt,
                pending.ExpiresAt,
                pending.Id,
                pending.ReplyTo), cancellationToken).ConfigureAwait(false);

            var sent = pending.Mark(MessageDeliveryState.Sent);
            await messages.UpdateAsync(sent, cancellationToken).ConfigureAwait(false);
            return sent;
        }
        catch
        {
            await messages.UpdateAsync(pending.Mark(MessageDeliveryState.Failed), CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<IReadOnlyList<Message>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        await RepairSelfConversationAsync(recipient, cancellationToken).ConfigureAwait(false);
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
            var contact = await conversationService.GetContactAsync(envelope.Sender, cancellationToken).ConfigureAwait(false);
            if (contact?.IsBlocked == true)
            {
                continue;
            }

            if (envelope.Reaction is not null)
            {
                var reacted = await ApplyReactionAsync(conversation.Id, envelope.Sender, envelope.Reaction, cancellationToken)
                    .ConfigureAwait(false);
                if (reacted is not null)
                {
                    received.Add(reacted);
                }
                continue;
            }

            var isSelfMessage = envelope.Sender == recipient;
            if (isSelfMessage && await HasMatchingSelfOutgoingAsync(conversation.Id, envelope, cancellationToken).ConfigureAwait(false))
            {
                continue;
            }

            if (await messages.GetAsync(envelope.Id, cancellationToken).ConfigureAwait(false) is not null)
            {
                continue;
            }

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
                isSelfMessage ? MessageDirection.Outgoing : MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                envelope.CreatedAt,
                envelope.Attachments,
                envelope.ExpiresAt,
                ServerHash: envelope.ServerHash,
                ReplyTo: envelope.ReplyTo);

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

    public async Task<int> RepairSelfConversationAsync(
        SessionId account,
        CancellationToken cancellationToken)
    {
        var conversation = await conversations.GetAsync(ConversationId.ForOneToOne(account), cancellationToken)
            .ConfigureAwait(false);
        if (conversation is null)
        {
            return 0;
        }

        var selfMessages = new List<Message>();

        await foreach (var message in messages.ListForConversationAsync(conversation.Id, cancellationToken).ConfigureAwait(false))
        {
            if (message.Sender == account && message.Recipient == account)
            {
                selfMessages.Add(message);
            }
        }

        var outgoing = selfMessages
            .Where(static message => message.Direction == MessageDirection.Outgoing)
            .ToArray();
        var duplicates = selfMessages
            .Where(message =>
                message.Direction == MessageDirection.Incoming &&
                outgoing.Any(candidate => IsSameSelfMessage(candidate, message)))
            .ToArray();

        foreach (var duplicate in duplicates)
        {
            await messages.DeleteAsync(duplicate.Id, cancellationToken).ConfigureAwait(false);
        }

        return duplicates.Length;
    }

    private static bool IsSameSelfMessage(Message outgoing, Message incoming) =>
        outgoing.CreatedAt == incoming.CreatedAt &&
        string.Equals(outgoing.Body, incoming.Body, StringComparison.Ordinal) &&
        outgoing.Attachments.SequenceEqual(incoming.Attachments);

    private async Task<bool> HasMatchingSelfOutgoingAsync(
        ConversationId conversationId,
        InboundMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        await foreach (var existing in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (existing.Direction == MessageDirection.Outgoing &&
                existing.CreatedAt == envelope.CreatedAt &&
                string.Equals(existing.Body, envelope.Body, StringComparison.Ordinal) &&
                existing.Attachments.SequenceEqual(envelope.Attachments))
            {
                return true;
            }
        }

        return false;
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
        MessageId? replyToMessageId = null,
        CancellationToken cancellationToken = default)
    {
        var pending = await QueueGroupAsync(sender, groupId, body, attachments, replyToMessageId, cancellationToken).ConfigureAwait(false);
        return await DispatchGroupAsync(pending, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Message> QueueGroupAsync(
        SessionId sender,
        ConversationId groupId,
        string body,
        IEnumerable<AttachmentMetadata>? attachments = null,
        MessageId? replyToMessageId = null,
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
        var replyTo = await CreateReplyAsync(conversation.Id, replyToMessageId, cancellationToken).ConfigureAwait(false);

        var pending = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender,
            Recipient: null,
            body.Trim(),
            MessageDirection.Outgoing,
            MessageDeliveryState.Sending,
            now,
            attachments?.ToArray() ?? [],
            CalculateExpiry(conversation.Settings.DisappearingMessages, now),
            ReplyTo: replyTo);

        await messages.AppendAsync(pending, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        await PruneExpiredConversationMessagesAsync(conversation.Id, cancellationToken).ConfigureAwait(false);
        return pending;
    }

    public async Task<Message> DispatchGroupAsync(Message pending, CancellationToken cancellationToken = default)
    {
        if (pending.Direction != MessageDirection.Outgoing || pending.Recipient is not null)
        {
            throw new ArgumentException("Only queued group messages can be dispatched.", nameof(pending));
        }

        try
        {
            await groupSync.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
                pending.Id,
                pending.ConversationId,
                pending.Sender,
                pending.Body,
                pending.Attachments,
                pending.CreatedAt,
                pending.ExpiresAt,
                pending.ReplyTo,
                NotifyRecipients: await ResolveGroupNotifyRecipientsAsync(
                    pending.ConversationId,
                    pending.Sender,
                    cancellationToken).ConfigureAwait(false)), cancellationToken).ConfigureAwait(false);

            var sent = pending.Mark(MessageDeliveryState.Sent);
            await messages.UpdateAsync(sent, cancellationToken).ConfigureAwait(false);
            return sent;
        }
        catch
        {
            await messages.UpdateAsync(pending.Mark(MessageDeliveryState.Failed), CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<int> DispatchPendingMessagesAsync(
        SessionId sender,
        CancellationToken cancellationToken = default)
    {
        var dispatched = 0;
        await foreach (var conversation in conversations.ListAsync(cancellationToken).ConfigureAwait(false))
        {
            var pendingMessages = new List<Message>();
            await foreach (var message in messages.ListForConversationAsync(conversation.Id, cancellationToken).ConfigureAwait(false))
            {
                if (message.Sender == sender &&
                    message.Direction == MessageDirection.Outgoing &&
                    message.DeliveryState is MessageDeliveryState.Sending or MessageDeliveryState.Failed)
                {
                    pendingMessages.Add(message);
                }
            }

            foreach (var pending in pendingMessages.OrderBy(static message => message.CreatedAt))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (pending.Recipient is null)
                    {
                        await DispatchGroupAsync(pending, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await DispatchOneToOneAsync(pending, cancellationToken).ConfigureAwait(false);
                    }

                    dispatched++;
                }
                catch when (!cancellationToken.IsCancellationRequested)
                {
                    // Keep the failed message persisted for the next retry cycle.
                }
            }
        }

        return dispatched;
    }

    public async Task<Message?> SendReactionOneToOneAsync(
        SessionId sender,
        SessionId recipient,
        MessageId targetMessageId,
        string emoji,
        bool remove = false,
        CancellationToken cancellationToken = default)
    {
        var conversationId = ConversationId.ForOneToOne(recipient);
        var update = new MessageReactionUpdate(targetMessageId, NormalizeEmoji(emoji), remove);
        await transport.SendAsync(new OutboundMessageEnvelope(
            sender,
            recipient,
            string.Empty,
            [],
            clock.UtcNow,
            null,
            MessageId.NewId(),
            Reaction: update), cancellationToken).ConfigureAwait(false);
        return await ApplyReactionAsync(conversationId, sender, update, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Message?> SendGroupReactionAsync(
        SessionId sender,
        ConversationId groupId,
        MessageId targetMessageId,
        string emoji,
        bool remove = false,
        CancellationToken cancellationToken = default)
    {
        var group = await conversationService.GetGroupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || group.IsDestroyed || group.Members.All(member => member.SessionId != sender))
        {
            throw new InvalidOperationException("Only active group members can react to messages.");
        }

        var update = new MessageReactionUpdate(targetMessageId, NormalizeEmoji(emoji), remove);
        await groupSync.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            MessageId.NewId(),
            groupId,
            sender,
            string.Empty,
            [],
            clock.UtcNow,
            null,
            Reaction: update,
            NotifyRecipients: GroupNotifyRecipients(group, sender)), cancellationToken).ConfigureAwait(false);
        return await ApplyReactionAsync(groupId, sender, update, cancellationToken).ConfigureAwait(false);
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

            if (envelope.Reaction is not null)
            {
                var reacted = await ApplyReactionAsync(groupId, envelope.Sender, envelope.Reaction, cancellationToken)
                    .ConfigureAwait(false);
                if (reacted is not null)
                {
                    received.Add(reacted);
                }
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
                ServerHash: envelope.ServerHash,
                ReplyTo: envelope.ReplyTo);

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

    public async Task<int> ClearConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default)
    {
        var messageIds = new List<MessageId>();
        await foreach (var message in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            messageIds.Add(message.Id);
        }

        foreach (var messageId in messageIds)
        {
            await messages.DeleteAsync(messageId, cancellationToken).ConfigureAwait(false);
        }

        return messageIds.Count;
    }

    private static string ReadCursorSettingKey(ConversationId conversationId) => $"sync.read-cursor.{conversationId.Value}";

    private async Task<IReadOnlyList<SessionId>> ResolveGroupNotifyRecipientsAsync(
        ConversationId groupId,
        SessionId sender,
        CancellationToken cancellationToken)
    {
        var group = await conversationService.GetGroupAsync(groupId, cancellationToken).ConfigureAwait(false);
        return group is null ? [] : GroupNotifyRecipients(group, sender);
    }

    private static IReadOnlyList<SessionId> GroupNotifyRecipients(Group group, SessionId sender) =>
        group.Members
            .Select(static member => member.SessionId)
            .Where(member => member != sender)
            .Distinct()
            .ToArray();

    private async Task<MessageReply?> CreateReplyAsync(
        ConversationId conversationId,
        MessageId? replyToMessageId,
        CancellationToken cancellationToken)
    {
        if (replyToMessageId is null)
        {
            return null;
        }

        var target = await messages.GetAsync(replyToMessageId.Value, cancellationToken).ConfigureAwait(false);
        if (target is null || target.ConversationId != conversationId)
        {
            throw new InvalidOperationException("The replied-to message does not belong to this conversation.");
        }

        var quote = string.IsNullOrWhiteSpace(target.Body) ? "[Вложение]" : target.Body.Trim();
        if (quote.Length > 240)
        {
            quote = quote[..240] + "...";
        }

        return new MessageReply(target.Id, target.Sender, quote);
    }

    private async Task<Message?> ApplyReactionAsync(
        ConversationId conversationId,
        SessionId reactor,
        MessageReactionUpdate update,
        CancellationToken cancellationToken)
    {
        var target = await messages.GetAsync(update.TargetMessageId, cancellationToken).ConfigureAwait(false);
        if (target is null || target.ConversationId != conversationId)
        {
            return null;
        }

        var reactions = target.ReactionItems
            .Where(item => item.Reactor != reactor)
            .ToList();
        if (!update.Remove)
        {
            reactions.Add(new MessageReaction(NormalizeEmoji(update.Emoji), reactor));
        }

        var updated = target with { Reactions = reactions };
        await messages.UpdateAsync(updated, cancellationToken).ConfigureAwait(false);
        return updated;
    }

    private static string NormalizeEmoji(string emoji)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(emoji);
        var normalized = emoji.Trim();
        if (normalized.Length > 16)
        {
            throw new ArgumentException("Reaction emoji is too long.", nameof(emoji));
        }

        return normalized;
    }

    private static DateTimeOffset? CalculateExpiry(DisappearingMessageSettings settings, DateTimeOffset now) =>
        settings.Mode == DisappearingMode.Disabled ? null : now.Add(settings.Duration!.Value);
}
