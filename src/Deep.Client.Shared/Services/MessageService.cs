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
    IClock clock) : IAccountGenerationLifecycle
{
    private readonly object outboxGate = new();
    private readonly Dictionary<MessageId, OutboxDispatch> inFlightDispatches = [];
    private readonly Dictionary<SessionId, Queue<OutboxDispatch>> senderDispatchQueues = [];
    private readonly HashSet<SessionId> stoppedAccountGenerations = [];
    private readonly Dictionary<ConversationId, int> conversationDispatchBarriers = [];
    private readonly Dictionary<MessageId, int> messageDispatchBarriers = [];

    public bool SupportsDurableGroupInboxMaintenance => groupSync is IGroupInboxMaintenance;

    public Task<int> DiscardUnknownGroupInboxMessagesAsync(
        SessionId account,
        IReadOnlyCollection<ConversationId> knownGroupIds,
        CancellationToken cancellationToken = default) =>
        groupSync is IGroupInboxMaintenance maintenance
            ? maintenance.DiscardUnknownGroupMessagesAsync(account, knownGroupIds, cancellationToken)
            : Task.FromResult(0);

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
        CancellationToken cancellationToken = default) =>
        await QueueOneToOneAsync(
            sender,
            recipient,
            body,
            attachments,
            replyToMessageId,
            MessageId.NewId(),
            clock.UtcNow,
            cancellationToken).ConfigureAwait(false);

    public async Task<Message> QueueOneToOneAsync(
        SessionId sender,
        SessionId recipient,
        string body,
        IEnumerable<AttachmentMetadata>? attachments,
        MessageId? replyToMessageId,
        MessageId messageId,
        DateTimeOffset createdAt,
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
        var now = createdAt;
        var replyTo = await CreateReplyAsync(conversation.Id, replyToMessageId, cancellationToken).ConfigureAwait(false);
        var pending = new Message(
            messageId,
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

        await AppendAndTouchAsync(pending, conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        return pending;
    }

    public async Task<Message> DispatchOneToOneAsync(Message pending, CancellationToken cancellationToken = default)
    {
        if (pending.Direction != MessageDirection.Outgoing || pending.Recipient is null)
        {
            throw new ArgumentException("Only queued one-to-one messages can be dispatched.", nameof(pending));
        }

        // Foreground cancellation belongs to this waiter; durable dispatch may still serve another caller.
        return await DispatchAsync(
            pending,
            groupNotifyRecipients: null,
            dispatchCancellationToken: CancellationToken.None,
            waiterCancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<Message>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        await RepairSelfConversationAsync(recipient, cancellationToken).ConfigureAwait(false);
        var envelopes = await transport.ReceiveAsync(recipient, cancellationToken).ConfigureAwait(false);
        var received = new List<Message>(envelopes.Count);

        foreach (var envelope in envelopes.OrderBy(static envelope => envelope.Reaction is not null))
        {
            var applied = await ApplyDirectEnvelopeAsync(recipient, envelope, cancellationToken).ConfigureAwait(false);
            if (applied.ShouldAcknowledge)
            {
                await AcknowledgeInboxItemAsync(transport, recipient, envelope.ServerHash, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (applied.Message is not null)
            {
                received.Add(applied.Message);
            }
        }

        if (received.Count > 0)
        {
            foreach (var conversationId in received.Select(static message => message.ConversationId).Distinct())
            {
                await PruneExpiredConversationMessagesAsync(conversationId, cancellationToken).ConfigureAwait(false);
            }
        }

        return received;
    }

    private async Task<InboxApplicationResult> ApplyDirectEnvelopeAsync(
        SessionId recipient,
        InboundMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        if (envelope.ExpiresAt is { } expiry && expiry <= clock.UtcNow)
        {
            return InboxApplicationResult.Handled();
        }

        var isSelfMessage = envelope.Sender == recipient;
        var counterpart = isSelfMessage && envelope.Recipient != recipient
            ? envelope.Recipient
            : envelope.Sender;
        var conversation = await conversationService.GetOrCreateOneToOneAsync(counterpart, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        var contact = await conversationService.GetContactAsync(counterpart, cancellationToken).ConfigureAwait(false);
        if (contact?.IsBlocked == true)
        {
            return InboxApplicationResult.Handled();
        }

        if (envelope.Reaction is not null)
        {
            var reacted = await ApplyReactionAsync(conversation.Id, envelope.Sender, envelope.Reaction, cancellationToken)
                .ConfigureAwait(false);
            return reacted is null
                ? InboxApplicationResult.Deferred()
                : InboxApplicationResult.Handled(reacted);
        }

        if (isSelfMessage && await HasMatchingSelfOutgoingAsync(conversation.Id, envelope, cancellationToken).ConfigureAwait(false))
        {
            return InboxApplicationResult.Handled();
        }

        var existing = await messages.GetAsync(envelope.Id, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            return InboxApplicationResult.Handled();
        }

        if (await HasMessageWithServerHashAsync(conversation.Id, envelope.ServerHash, cancellationToken).ConfigureAwait(false))
        {
            return InboxApplicationResult.Handled();
        }

        var message = new Message(
            envelope.Id,
            conversation.Id,
            envelope.Sender,
            envelope.Recipient,
            envelope.Body,
            isSelfMessage ? MessageDirection.Outgoing : MessageDirection.Incoming,
            isSelfMessage ? MessageDeliveryState.Sent : MessageDeliveryState.Delivered,
            envelope.CreatedAt,
            envelope.Attachments,
            envelope.ExpiresAt,
            ServerHash: envelope.ServerHash,
            ReplyTo: envelope.ReplyTo);

        await AppendAndTouchAsync(message, conversation.Touch(clock.UtcNow), cancellationToken).ConfigureAwait(false);
        return InboxApplicationResult.Handled(message);
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

        if (messages is IMessageSyncRepository syncRepository)
        {
            return await syncRepository.DeleteDuplicateSelfIncomingAsync(
                conversation.Id,
                account,
                cancellationToken).ConfigureAwait(false);
        }

        var selfMessages = new List<Message>();

        await foreach (var message in messages.ListForConversationAsync(conversation.Id, cancellationToken).ConfigureAwait(false))
        {
            if (message.Sender == account && message.Recipient == account)
            {
                selfMessages.Add(message);
            }
        }

        var outgoingKeys = selfMessages
            .Where(static message => message.Direction == MessageDirection.Outgoing)
            .Select(MessagePersistenceKeys.SelfEcho)
            .ToHashSet(StringComparer.Ordinal);
        var duplicates = selfMessages
            .Where(message =>
                message.Direction == MessageDirection.Incoming &&
                outgoingKeys.Contains(MessagePersistenceKeys.SelfEcho(message)))
            .ToArray();

        foreach (var duplicate in duplicates)
        {
            await messages.DeleteAsync(duplicate.Id, cancellationToken).ConfigureAwait(false);
        }

        return duplicates.Length;
    }

    private async Task<bool> HasMatchingSelfOutgoingAsync(
        ConversationId conversationId,
        InboundMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        if (messages is IMessageSyncRepository syncRepository)
        {
            return await syncRepository.ContainsMatchingSelfOutgoingAsync(
                conversationId,
                envelope.Sender,
                envelope.CreatedAt,
                envelope.Body,
                envelope.Attachments,
                cancellationToken).ConfigureAwait(false);
        }

        var expectedKey = MessagePersistenceKeys.SelfEcho(
            envelope.CreatedAt,
            envelope.Body,
            envelope.Attachments);
        await foreach (var existing in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (existing.Direction == MessageDirection.Outgoing &&
                string.Equals(MessagePersistenceKeys.SelfEcho(existing), expectedKey, StringComparison.Ordinal))
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

        if (messages is IMessageSyncRepository syncRepository)
        {
            return await syncRepository.ContainsServerHashAsync(
                conversationId,
                serverHash,
                cancellationToken).ConfigureAwait(false);
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
        CancellationToken cancellationToken = default) =>
        await QueueGroupAsync(
            sender,
            groupId,
            body,
            attachments,
            replyToMessageId,
            MessageId.NewId(),
            clock.UtcNow,
            cancellationToken).ConfigureAwait(false);

    public async Task<Message> QueueGroupAsync(
        SessionId sender,
        ConversationId groupId,
        string body,
        IEnumerable<AttachmentMetadata>? attachments,
        MessageId? replyToMessageId,
        MessageId messageId,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(body);

        var group = await conversationService.GetGroupAsync(groupId, cancellationToken).ConfigureAwait(false);
        if (group is null || !IsActiveGroupMember(group, sender))
        {
            throw new InvalidOperationException("Only active group members can send group messages.");
        }

        var now = createdAt;
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
            messageId,
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

        await AppendAndTouchAsync(pending, conversation.Touch(now), cancellationToken).ConfigureAwait(false);
        return pending;
    }

    public async Task<Message> DispatchGroupAsync(Message pending, CancellationToken cancellationToken = default)
    {
        if (pending.Direction != MessageDirection.Outgoing || pending.Recipient is not null)
        {
            throw new ArgumentException("Only queued group messages can be dispatched.", nameof(pending));
        }

        return await DispatchAsync(
            pending,
            groupNotifyRecipients: null,
            dispatchCancellationToken: CancellationToken.None,
            waiterCancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> DispatchPendingMessagesAsync(
        SessionId sender,
        CancellationToken cancellationToken = default)
    {
        var dispatched = 0;
        IReadOnlyList<Message> pendingMessages;
        if (messages is IMessageSyncRepository syncRepository)
        {
            pendingMessages = await syncRepository.ListPendingOutgoingAsync(sender, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var fallback = new List<Message>();
            await foreach (var conversation in conversations.ListAsync(cancellationToken).ConfigureAwait(false))
            {
                await foreach (var message in messages.ListForConversationAsync(conversation.Id, cancellationToken).ConfigureAwait(false))
                {
                    if (message.Sender == sender &&
                        message.Direction == MessageDirection.Outgoing &&
                        message.DeliveryState is MessageDeliveryState.Sending or MessageDeliveryState.Failed)
                    {
                        fallback.Add(message);
                    }
                }
            }

            pendingMessages = fallback
                .OrderBy(static message => message.CreatedAt)
                .ThenBy(static message => message.Id.Value, StringComparer.Ordinal)
                .ToArray();
        }

        var groupRecipients = new Dictionary<ConversationId, IReadOnlyList<SessionId>>();
        foreach (var pending in pendingMessages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (pending.Recipient is null)
                {
                    if (!groupRecipients.TryGetValue(pending.ConversationId, out var notifyRecipients))
                    {
                        notifyRecipients = await ResolveGroupNotifyRecipientsAsync(
                            pending.ConversationId,
                            pending.Sender,
                            cancellationToken).ConfigureAwait(false);
                        groupRecipients[pending.ConversationId] = notifyRecipients;
                    }

                    await DispatchAsync(
                        pending,
                        notifyRecipients,
                        dispatchCancellationToken: cancellationToken,
                        waiterCancellationToken: cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await DispatchAsync(
                        pending,
                        groupNotifyRecipients: null,
                        dispatchCancellationToken: cancellationToken,
                        waiterCancellationToken: cancellationToken).ConfigureAwait(false);
                }

                dispatched++;
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                // Keep the failed message persisted for the next retry cycle.
            }
        }

        return dispatched;
    }

    async Task IAccountGenerationLifecycle.StopAsync(
        SessionId account,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<OutboxDispatch> operations;
        lock (outboxGate)
        {
            stoppedAccountGenerations.Add(account);
            operations = inFlightDispatches.Values
                .Where(operation => operation.Pending.Sender == account)
                .ToArray();
        }

        await CancelAndAwaitDispatchesAsync(operations, cancellationToken).ConfigureAwait(false);
    }

    void IAccountGenerationLifecycle.Resume(SessionId account)
    {
        lock (outboxGate)
        {
            stoppedAccountGenerations.Remove(account);
        }
    }

    private async Task<Message> DispatchAsync(
        Message pending,
        IReadOnlyList<SessionId>? groupNotifyRecipients,
        CancellationToken dispatchCancellationToken,
        CancellationToken waiterCancellationToken)
    {
        waiterCancellationToken.ThrowIfCancellationRequested();

        OutboxDispatch operation;
        var startSenderQueue = false;
        lock (outboxGate)
        {
            ThrowIfDispatchBlocked(pending);

            if (inFlightDispatches.TryGetValue(pending.Id, out operation!))
            {
                EnsureCompatibleDispatch(operation.Pending, pending);
            }
            else
            {
                operation = new OutboxDispatch(pending, groupNotifyRecipients, dispatchCancellationToken);
                inFlightDispatches.Add(pending.Id, operation);

                if (!senderDispatchQueues.TryGetValue(pending.Sender, out var senderQueue))
                {
                    senderQueue = new Queue<OutboxDispatch>();
                    senderDispatchQueues.Add(pending.Sender, senderQueue);
                    startSenderQueue = true;
                }

                senderQueue.Enqueue(operation);
            }
        }

        if (startSenderQueue)
        {
            _ = ProcessSenderDispatchQueueAsync(pending.Sender);
        }

        return await operation.Completion.Task.WaitAsync(waiterCancellationToken).ConfigureAwait(false);
    }

    private async Task ProcessSenderDispatchQueueAsync(SessionId sender)
    {
        while (TryTakeNextSenderDispatch(sender, out var operation))
        {
            await ExecuteDispatchAsync(operation).ConfigureAwait(false);
        }
    }

    private bool TryTakeNextSenderDispatch(SessionId sender, out OutboxDispatch operation)
    {
        lock (outboxGate)
        {
            if (senderDispatchQueues.TryGetValue(sender, out var senderQueue) && senderQueue.Count > 0)
            {
                operation = senderQueue.Dequeue();
                return true;
            }

            senderDispatchQueues.Remove(sender);
            operation = null!;
            return false;
        }
    }

    private async Task ExecuteDispatchAsync(OutboxDispatch operation)
    {
        try
        {
            var result = await ExecuteOwnedDispatchAsync(operation).ConfigureAwait(false);
            operation.Completion.TrySetResult(result);
        }
        catch (OperationCanceledException exception)
        {
            operation.Completion.TrySetCanceled(exception.CancellationToken);
        }
        catch (Exception exception)
        {
            operation.Completion.TrySetException(exception);
        }
        finally
        {
            lock (outboxGate)
            {
                if (inFlightDispatches.TryGetValue(operation.Pending.Id, out var current) &&
                    ReferenceEquals(current, operation))
                {
                    inFlightDispatches.Remove(operation.Pending.Id);
                }
            }

            operation.Dispose();
        }
    }

    private async Task<Message> ExecuteOwnedDispatchAsync(OutboxDispatch operation)
    {
        var cancellationToken = operation.DispatchCancellationToken;
        var physicalDispatchCompleted = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var stored = await messages.GetAsync(operation.Pending.Id, cancellationToken).ConfigureAwait(false);
            if (stored is null)
            {
                throw new OperationCanceledException(
                    $"Message '{operation.Pending.Id}' is no longer present in the durable outbox.",
                    cancellationToken);
            }

            if (IsSuccessfulTerminal(stored))
            {
                return stored;
            }

            var pending = stored;
            if (pending.Recipient is null)
            {
                var notifyRecipients = operation.GroupNotifyRecipients
                    ?? await ResolveGroupNotifyRecipientsAsync(
                        pending.ConversationId,
                        pending.Sender,
                        cancellationToken).ConfigureAwait(false);
                await groupSync.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
                    pending.Id,
                    pending.ConversationId,
                    pending.Sender,
                    pending.Body,
                    pending.Attachments,
                    pending.CreatedAt,
                    pending.ExpiresAt,
                    pending.ReplyTo,
                    NotifyRecipients: notifyRecipients), cancellationToken).ConfigureAwait(false);
                physicalDispatchCompleted = true;
            }
            else
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
                physicalDispatchCompleted = true;
            }

            return await MarkSentUnlessTerminalAsync(pending).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch when (!physicalDispatchCompleted)
        {
            var terminal = await MarkFailedUnlessTerminalAsync(operation.Pending).ConfigureAwait(false);
            if (terminal is not null)
            {
                return terminal;
            }

            throw;
        }
    }

    private async Task<Message> MarkSentUnlessTerminalAsync(Message pending)
    {
        var stored = await messages.GetAsync(pending.Id, CancellationToken.None).ConfigureAwait(false);
        if (stored is null)
        {
            return pending.Mark(MessageDeliveryState.Sent);
        }

        if (IsSuccessfulTerminal(stored))
        {
            return stored;
        }

        var sent = stored.Mark(MessageDeliveryState.Sent);
        await messages.UpdateAsync(sent, CancellationToken.None).ConfigureAwait(false);
        return sent;
    }

    private async Task<Message?> MarkFailedUnlessTerminalAsync(Message pending)
    {
        var stored = await messages.GetAsync(pending.Id, CancellationToken.None).ConfigureAwait(false);
        if (stored is null)
        {
            return null;
        }

        if (IsSuccessfulTerminal(stored))
        {
            return stored;
        }

        await messages.UpdateAsync(
            stored.Mark(MessageDeliveryState.Failed),
            CancellationToken.None).ConfigureAwait(false);
        return null;
    }

    private static bool IsSuccessfulTerminal(Message message) =>
        message.DeliveryState is
            MessageDeliveryState.Sent or
            MessageDeliveryState.Delivered or
            MessageDeliveryState.Read;

    private void ThrowIfDispatchBlocked(Message pending)
    {
        if (stoppedAccountGenerations.Contains(pending.Sender)
            || conversationDispatchBarriers.ContainsKey(pending.ConversationId)
            || messageDispatchBarriers.ContainsKey(pending.Id))
        {
            throw new OperationCanceledException(
                $"Message '{pending.Id}' was invalidated by an account or conversation lifecycle barrier.");
        }
    }

    private IReadOnlyList<OutboxDispatch> BeginMessageDispatchBarrier(MessageId messageId)
    {
        lock (outboxGate)
        {
            IncrementBarrier(messageDispatchBarriers, messageId);
            return inFlightDispatches.TryGetValue(messageId, out var operation)
                ? [operation]
                : [];
        }
    }

    private void EndMessageDispatchBarrier(MessageId messageId)
    {
        lock (outboxGate)
        {
            DecrementBarrier(messageDispatchBarriers, messageId);
        }
    }

    private IReadOnlyList<OutboxDispatch> BeginConversationDispatchBarrier(ConversationId conversationId)
    {
        lock (outboxGate)
        {
            IncrementBarrier(conversationDispatchBarriers, conversationId);
            return inFlightDispatches.Values
                .Where(operation => operation.Pending.ConversationId == conversationId)
                .ToArray();
        }
    }

    private void EndConversationDispatchBarrier(ConversationId conversationId)
    {
        lock (outboxGate)
        {
            DecrementBarrier(conversationDispatchBarriers, conversationId);
        }
    }

    private static async Task CancelAndAwaitDispatchesAsync(
        IReadOnlyList<OutboxDispatch> operations,
        CancellationToken cancellationToken)
    {
        foreach (var operation in operations)
        {
            operation.Cancel();
        }

        foreach (var operation in operations)
        {
            try
            {
                await operation.Completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // The destructive lifecycle operation only needs dispatch quiescence, not its result.
            }
        }
    }

    private static void IncrementBarrier<TKey>(Dictionary<TKey, int> barriers, TKey key)
        where TKey : notnull =>
        barriers[key] = barriers.GetValueOrDefault(key) + 1;

    private static void DecrementBarrier<TKey>(Dictionary<TKey, int> barriers, TKey key)
        where TKey : notnull
    {
        if (barriers[key] == 1)
        {
            barriers.Remove(key);
        }
        else
        {
            barriers[key]--;
        }
    }

    private static void EnsureCompatibleDispatch(Message owner, Message waiter)
    {
        if (owner.Sender != waiter.Sender ||
            owner.ConversationId != waiter.ConversationId ||
            owner.Recipient != waiter.Recipient ||
            owner.Direction != waiter.Direction)
        {
            throw new InvalidOperationException(
                $"Message '{waiter.Id}' is already being dispatched with a different envelope.");
        }
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
        if (group is null || !IsActiveGroupMember(group, sender))
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
        if (group is null || !IsActiveGroupMember(group, recipient))
        {
            return [];
        }

        var envelopes = await groupSync.ReceiveGroupMessagesAsync(groupId, cancellationToken).ConfigureAwait(false);
        return await ApplyGroupEnvelopesAsync(recipient, group, envelopes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<Message>> ReceiveGroupsAsync(
        SessionId recipient,
        IReadOnlyCollection<Group> groups,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(groups);
        var activeGroups = groups
            .Where(group => IsActiveGroupMember(group, recipient))
            .DistinctBy(static group => group.Id)
            .ToArray();
        if (activeGroups.Length == 0)
        {
            return [];
        }

        if (groupSync is IKnownGroupInboxReceiver batchReceiver)
        {
            var byId = activeGroups.ToDictionary(static group => group.Id);
            var envelopes = await batchReceiver.ReceiveKnownGroupMessagesAsync(
                recipient,
                byId.Keys.ToArray(),
                cancellationToken).ConfigureAwait(false);
            var received = new List<Message>(envelopes.Count);
            foreach (var groupEnvelopes in envelopes
                         .Where(envelope => byId.ContainsKey(envelope.GroupId))
                         .GroupBy(static envelope => envelope.GroupId))
            {
                received.AddRange(await ApplyGroupEnvelopesAsync(
                    recipient,
                    byId[groupEnvelopes.Key],
                    groupEnvelopes.ToArray(),
                    cancellationToken).ConfigureAwait(false));
            }

            return received;
        }

        var fallbackReceived = new List<Message>();
        var fallbackGate = new object();
        await Parallel.ForEachAsync(
            activeGroups,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = 4,
                CancellationToken = cancellationToken
            },
            async (group, itemCancellationToken) =>
            {
                var envelopes = await groupSync.ReceiveGroupMessagesAsync(group.Id, itemCancellationToken).ConfigureAwait(false);
                var received = await ApplyGroupEnvelopesAsync(
                    recipient,
                    group,
                    envelopes,
                    itemCancellationToken).ConfigureAwait(false);
                lock (fallbackGate)
                {
                    fallbackReceived.AddRange(received);
                }
            }).ConfigureAwait(false);
        return fallbackReceived;
    }

    private async Task<IReadOnlyList<Message>> ApplyGroupEnvelopesAsync(
        SessionId recipient,
        Group group,
        IReadOnlyList<InboundGroupMessageEnvelope> envelopes,
        CancellationToken cancellationToken)
    {
        var received = new List<Message>(envelopes.Count);

        foreach (var envelope in envelopes.OrderBy(static envelope => envelope.Reaction is not null))
        {
            var applied = await ApplyGroupEnvelopeAsync(recipient, group, envelope, cancellationToken).ConfigureAwait(false);
            if (applied.ShouldAcknowledge)
            {
                await AcknowledgeInboxItemAsync(groupSync, recipient, envelope.ServerHash, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (applied.Message is not null)
            {
                received.Add(applied.Message);
            }
        }

        if (received.Count > 0)
        {
            await PruneExpiredConversationMessagesAsync(group.Id, cancellationToken).ConfigureAwait(false);
        }

        return received;
    }

    private async Task<InboxApplicationResult> ApplyGroupEnvelopeAsync(
        SessionId recipient,
        Group group,
        InboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken)
    {
        if (envelope.GroupId != group.Id || !IsActiveGroupMember(group, envelope.Sender))
        {
            return InboxApplicationResult.Handled();
        }

        if (envelope.ExpiresAt is { } expiry && expiry <= clock.UtcNow)
        {
            return InboxApplicationResult.Handled();
        }

        if (envelope.Sender == recipient)
        {
            return InboxApplicationResult.Handled();
        }

        if (envelope.Reaction is not null)
        {
            var reacted = await ApplyReactionAsync(group.Id, envelope.Sender, envelope.Reaction, cancellationToken)
                .ConfigureAwait(false);
            return reacted is null
                ? InboxApplicationResult.Deferred()
                : InboxApplicationResult.Handled(reacted);
        }

        var existing = await messages.GetAsync(envelope.Id, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            await EnsureGroupConversationExistsAsync(group, cancellationToken).ConfigureAwait(false);
            return InboxApplicationResult.Handled();
        }

        if (await HasMessageWithServerHashAsync(group.Id, envelope.ServerHash, cancellationToken).ConfigureAwait(false))
        {
            await EnsureGroupConversationExistsAsync(group, cancellationToken).ConfigureAwait(false);
            return InboxApplicationResult.Handled();
        }

        var message = new Message(
            envelope.Id,
            group.Id,
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

        var groupConversation = await GetOrCreateGroupConversationAsync(group, cancellationToken).ConfigureAwait(false);
        await AppendAndTouchAsync(message, groupConversation.Touch(clock.UtcNow), cancellationToken).ConfigureAwait(false);
        return InboxApplicationResult.Handled(message);
    }

    private async Task EnsureGroupConversationExistsAsync(Group group, CancellationToken cancellationToken)
    {
        if (await conversations.GetAsync(group.Id, cancellationToken).ConfigureAwait(false) is not null)
        {
            return;
        }

        await conversations.UpsertAsync(
            new Conversation(
                group.Id,
                ConversationKind.GroupV2,
                group.Name,
                ConversationSettings.Default(ConversationKind.GroupV2),
                group.CreatedAt,
                clock.UtcNow),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<Conversation> GetOrCreateGroupConversationAsync(Group group, CancellationToken cancellationToken) =>
        await conversations.GetAsync(group.Id, cancellationToken).ConfigureAwait(false)
            ?? new Conversation(
                group.Id,
                ConversationKind.GroupV2,
                group.Name,
                ConversationSettings.Default(ConversationKind.GroupV2),
                group.CreatedAt,
                clock.UtcNow);

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

        var now = clock.UtcNow;
        var result = new List<Message>(limit);
        await foreach (var message in messages.ListRecentForConversationAsync(conversationId, now, limit, cancellationToken).ConfigureAwait(false))
        {
            if (message.IsExpired(now))
            {
                continue;
            }

            result.Add(message);
        }

        return result;
    }

    public Task<int> CountUnreadConversationMessagesAsync(
        ConversationId conversationId,
        DateTimeOffset? readCursor,
        CancellationToken cancellationToken = default) =>
        messages.CountUnreadForConversationAsync(
            conversationId,
            readCursor,
            clock.UtcNow,
            cancellationToken);

    public async Task<IReadOnlyList<Message>> ListConversationMessagesBeforeAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        MessageId beforeMessageId,
        int limit,
        CancellationToken cancellationToken = default)
    {
        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Message limit must be greater than zero.");
        }

        var now = clock.UtcNow;
        var result = new List<Message>(limit);
        await foreach (var message in messages.ListBeforeForConversationAsync(conversationId, beforeCreatedAt, beforeMessageId, now, limit, cancellationToken).ConfigureAwait(false))
        {
            if (message.IsExpired(now))
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
        if (messages is IMessageSyncRepository syncRepository)
        {
            var result = await syncRepository.MarkConversationReadIfUnreadAsync(
                conversationId,
                cursor,
                cancellationToken).ConfigureAwait(false);
            return result.ReadCursor ?? cursor;
        }

        if (messages is IConversationReadRepository readRepository)
        {
            await readRepository.MarkConversationReadAsync(conversationId, cursor, cancellationToken).ConfigureAwait(false);
            return cursor;
        }

        var changed = 0;
        await foreach (var message in messages.ListForConversationAsync(conversationId, cancellationToken).ConfigureAwait(false))
        {
            if (message.Direction == MessageDirection.Incoming
                && message.DeliveryState != MessageDeliveryState.Read)
            {
                await messages.UpdateAsync(message.Mark(MessageDeliveryState.Read, cursor), cancellationToken).ConfigureAwait(false);
                changed++;
            }
        }

        if (changed > 0)
        {
            await settings.SetAsync(ReadCursorSettingKey(conversationId), cursor.ToString("O"), cancellationToken).ConfigureAwait(false);
        }

        return cursor;
    }

    public async Task<int> ApplyReadCursorAsync(ConversationId conversationId, DateTimeOffset readAt, CancellationToken cancellationToken = default)
    {
        if (messages is IMessageSyncRepository syncRepository)
        {
            return await syncRepository.ApplyReadCursorAsync(
                conversationId,
                readAt,
                cancellationToken).ConfigureAwait(false);
        }

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
        if (messages is IMessageConversationPersistenceRepository persistenceRepository)
        {
            return await persistenceRepository.DeleteExpiredMessagesAsync(
                conversationId,
                clock.UtcNow,
                cancellationToken).ConfigureAwait(false);
        }

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

    public async Task<bool> DeleteMessageAsync(MessageId messageId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var operations = BeginMessageDispatchBarrier(messageId);
        try
        {
            await CancelAndAwaitDispatchesAsync(operations, cancellationToken).ConfigureAwait(false);
            var existing = await messages.GetAsync(messageId, cancellationToken).ConfigureAwait(false);
            if (existing is null)
            {
                return false;
            }

            await messages.DeleteAsync(messageId, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            EndMessageDispatchBarrier(messageId);
        }
    }

    public async Task<int> ClearConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var operations = BeginConversationDispatchBarrier(conversationId);
        try
        {
            await CancelAndAwaitDispatchesAsync(operations, cancellationToken).ConfigureAwait(false);
            if (messages is IMessageConversationPersistenceRepository persistenceRepository)
            {
                return await persistenceRepository.ClearConversationMessagesAsync(conversationId, cancellationToken)
                    .ConfigureAwait(false);
            }

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
        finally
        {
            EndConversationDispatchBarrier(conversationId);
        }
    }

    private Task AppendAndTouchAsync(
        Message message,
        Conversation conversation,
        CancellationToken cancellationToken)
    {
        if (ReferenceEquals(messages, conversations)
            && messages is IMessageConversationPersistenceRepository persistenceRepository)
        {
            return persistenceRepository.AppendMessageAndTouchConversationAsync(
                message,
                conversation,
                cancellationToken);
        }

        return AppendAndTouchFallbackAsync(message, conversation, cancellationToken);
    }

    private async Task AppendAndTouchFallbackAsync(
        Message message,
        Conversation conversation,
        CancellationToken cancellationToken)
    {
        await messages.AppendAsync(message, cancellationToken).ConfigureAwait(false);
        await conversations.UpsertAsync(conversation, cancellationToken).ConfigureAwait(false);
    }

    private static string ReadCursorSettingKey(ConversationId conversationId) => $"sync.read-cursor.{conversationId.Value}";

    private static Task AcknowledgeInboxItemAsync(
        object source,
        SessionId account,
        string serverHash,
        CancellationToken cancellationToken) =>
        source is IDurableInboxAcknowledger acknowledger
            ? acknowledger.AcknowledgeInboxItemAsync(account, serverHash, cancellationToken)
            : Task.CompletedTask;

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
            .Where(member => member.SessionId != sender && !member.IsPendingRemoval)
            .Select(static member => member.SessionId)
            .Distinct()
            .ToArray();

    private static bool IsActiveGroupMember(Group group, SessionId sessionId) =>
        group.Revision >= 1 &&
        !group.IsDestroyed &&
        !group.IsKicked &&
        group.Members.Any(member => member.SessionId == sessionId && !member.IsPendingRemoval);

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

    private sealed class OutboxDispatch(
        Message pending,
        IReadOnlyList<SessionId>? groupNotifyRecipients,
        CancellationToken dispatchCancellationToken) : IDisposable
    {
        private readonly CancellationTokenSource dispatchCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(dispatchCancellationToken);

        public Message Pending { get; } = pending;

        public IReadOnlyList<SessionId>? GroupNotifyRecipients { get; } = groupNotifyRecipients?.ToArray();

        public CancellationToken DispatchCancellationToken => dispatchCancellation.Token;

        public TaskCompletionSource<Message> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Cancel()
        {
            try
            {
                dispatchCancellation.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // Completion won the race with lifecycle cancellation.
            }
        }

        public void Dispose() => dispatchCancellation.Dispose();
    }

    private sealed record InboxApplicationResult(Message? Message, bool ShouldAcknowledge)
    {
        public static InboxApplicationResult Handled(Message? message = null) => new(message, true);

        public static InboxApplicationResult Deferred() => new(null, false);
    }
}
