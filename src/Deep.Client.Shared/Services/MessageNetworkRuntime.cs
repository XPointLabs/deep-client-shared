using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Coordinates ephemeral UI projections and lifecycle barriers. When backed by
/// <see cref="Msg01AuthoritativeTransport"/>, durable payload, attempts,
/// reconciliation and ACK ownership remain exclusively in MSG-01.
/// </summary>
public sealed class MessageNetworkRuntime : IAsyncDisposable
{
    private readonly IMessageRepository messages;
    private readonly ISessionMessageTransport transport;
    private readonly IGroupSyncTransport groupSync;
    private readonly Msg01AuthoritativeTransport? authoritativeMsg01;
    private readonly IMessageDispatchFailureObserver? failureObserver;
    private readonly object gate = new();
    private readonly Dictionary<MessageId, DispatchOperation> inFlight = [];
    private readonly Dictionary<SessionId, Queue<DispatchOperation>> senderQueues = [];
    private readonly HashSet<SessionId> stoppedAccounts = [];
    private readonly Dictionary<ConversationId, int> conversationBarriers = [];
    private readonly Dictionary<MessageId, int> messageBarriers = [];
    private readonly TaskCompletionSource<bool> disposalCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool accepting = true;
    private int disposed;

    internal MessageNetworkRuntime(IMessageRepository messages, ISessionMessageTransport transport,
        IGroupSyncTransport groupSync, IMessageDispatchFailureObserver? failureObserver)
    {
        this.messages = messages;
        this.transport = transport;
        this.groupSync = groupSync;
        authoritativeMsg01 = transport as Msg01AuthoritativeTransport;
        this.failureObserver = failureObserver;
    }

    internal bool SupportsDurableGroupInboxMaintenance => groupSync is IGroupInboxMaintenance;
    internal bool UsesAuthoritativeMsg01 => authoritativeMsg01 is not null;
    internal bool UsesOrderedDirectInbox => transport is IDurableInboxAcknowledger;
    internal Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveDirectAsync(SessionId recipient, CancellationToken ct)
    { EnsureAccepting(); return transport.ReceiveAsync(recipient, ct); }
    internal Task AcknowledgeDirectAsync(SessionId account, string hash, CancellationToken ct)
    { EnsureAccepting(); return AcknowledgeAsync(transport, account, hash, ct); }
    internal Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupAsync(ConversationId groupId, CancellationToken ct)
    { EnsureAccepting(); return groupSync.ReceiveGroupMessagesAsync(groupId, ct); }
    internal Task AcknowledgeGroupAsync(SessionId account, string hash, CancellationToken ct)
    { EnsureAccepting(); return AcknowledgeAsync(groupSync, account, hash, ct); }
    internal Task<int> DiscardUnknownGroupsAsync(SessionId account, IReadOnlyCollection<ConversationId> groups, CancellationToken ct)
    { EnsureAccepting(); return groupSync is IGroupInboxMaintenance maintenance ? maintenance.DiscardUnknownGroupMessagesAsync(account, groups, ct) : Task.FromResult(0); }

    internal Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveKnownGroupsAsync(
        SessionId account, IReadOnlyCollection<ConversationId> groupIds, CancellationToken ct) =>
        AcceptKnownGroupReceive(account, groupIds, ct);

    private Task<IReadOnlyList<InboundGroupMessageEnvelope>> AcceptKnownGroupReceive(
        SessionId account, IReadOnlyCollection<ConversationId> groupIds, CancellationToken ct)
    {
        EnsureAccepting();
        return groupSync is IKnownGroupInboxReceiver receiver
            ? receiver.ReceiveKnownGroupMessagesAsync(account, groupIds, ct)
            : Task.FromException<IReadOnlyList<InboundGroupMessageEnvelope>>(
                new NotSupportedException("The message network has no known-group batch receiver."));
    }
    internal bool HasKnownGroupReceiver => groupSync is IKnownGroupInboxReceiver;

    internal Task SendDirectControlAsync(OutboundMessageEnvelope envelope, CancellationToken ct)
    { EnsureAccepting(); return transport.SendAsync(envelope, ct); }
    internal Task SendGroupControlAsync(OutboundGroupMessageEnvelope envelope, CancellationToken ct)
    { EnsureAccepting(); return groupSync.SendGroupMessageAsync(envelope, ct); }

    internal Task<int> RecoverAuthoritativeAsync(SessionId account, CancellationToken ct)
    {
        EnsureAccepting();
        return authoritativeMsg01?.RecoverNowAsync(account, ct)
            ?? Task.FromException<int>(new InvalidOperationException(
                "The configured runtime has no authoritative MSG-01 recovery owner."));
    }

    internal async Task PrepareAuthoritativeAsync(
        Message pending,
        IReadOnlyList<SessionId>? groupRecipients,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pending);
        EnsureAccepting();
        if (authoritativeMsg01 is null) return;
        if (pending.Direction != MessageDirection.Outgoing)
            throw new ArgumentException("Only outgoing messages can enter MSG-01.", nameof(pending));

        if (pending.Recipient is { } recipient)
        {
            await authoritativeMsg01.PrepareDirectAsync(new OutboundMessageEnvelope(
                pending.Sender, recipient, pending.Body, pending.Attachments,
                pending.CreatedAt, pending.ExpiresAt, pending.Id, pending.ReplyTo),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var recipients = groupRecipients ?? pending.NotifyRecipients
            ?? throw new InvalidDataException(
                "Outgoing group message has no immutable recipient snapshot.");
        await authoritativeMsg01.PrepareGroupAsync(new OutboundGroupMessageEnvelope(
            pending.Id, pending.ConversationId, pending.Sender, pending.Body,
            pending.Attachments, pending.CreatedAt, pending.ExpiresAt,
            pending.ReplyTo, NotifyRecipients: recipients), cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<Message> DispatchAsync(Message pending, IReadOnlyList<SessionId>? groupRecipients,
        CancellationToken dispatchCancellationToken, CancellationToken waiterCancellationToken)
    {
        waiterCancellationToken.ThrowIfCancellationRequested();
        DispatchOperation operation;
        var startQueue = false;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(!accepting, this);
            ThrowIfBlocked(pending);
            if (inFlight.TryGetValue(pending.Id, out operation!)) EnsureCompatible(operation.Pending, pending);
            else
            {
                operation = new(pending, groupRecipients, dispatchCancellationToken);
                inFlight.Add(pending.Id, operation);
                if (!senderQueues.TryGetValue(pending.Sender, out var queue))
                {
                    queue = new(); senderQueues.Add(pending.Sender, queue); startQueue = true;
                }
                queue.Enqueue(operation);
            }
        }
        if (startQueue) _ = ProcessQueueAsync(pending.Sender);
        return await operation.Completion.Task.WaitAsync(waiterCancellationToken).ConfigureAwait(false);
    }

    internal async Task StopAsync(SessionId account, CancellationToken cancellationToken)
    {
        IReadOnlyList<DispatchOperation> operations;
        lock (gate)
        {
            stoppedAccounts.Add(account);
            operations = inFlight.Values.Where(operation => operation.Pending.Sender == account).ToArray();
        }
        await CancelAndAwaitAsync(operations, cancellationToken).ConfigureAwait(false);
    }

    internal void Resume(SessionId account) { lock (gate) stoppedAccounts.Remove(account); }

    public async ValueTask DisposeAsync()
    {
        IReadOnlyList<DispatchOperation> operations;
        var first = false;
        lock (gate)
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
            {
                operations = [];
            }
            else
            {
                first = true;
                accepting = false;
                operations = inFlight.Values.ToArray();
            }
        }
        if (!first)
        {
            await disposalCompletion.Task.ConfigureAwait(false);
            return;
        }
        try
        {
            await CancelAndAwaitAsync(operations, CancellationToken.None).ConfigureAwait(false);
            disposalCompletion.TrySetResult(true);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
    }

    internal DispatchBarrier BeginMessageBarrier(MessageId id)
    {
        lock (gate)
        {
            Increment(messageBarriers, id);
            return new(inFlight.TryGetValue(id, out var operation) ? [operation] : [],
                () => { lock (gate) Decrement(messageBarriers, id); });
        }
    }

    internal DispatchBarrier BeginConversationBarrier(ConversationId id)
    {
        lock (gate)
        {
            Increment(conversationBarriers, id);
            return new(inFlight.Values.Where(operation => operation.Pending.ConversationId == id).ToArray(),
                () => { lock (gate) Decrement(conversationBarriers, id); });
        }
    }

    private async Task ProcessQueueAsync(SessionId sender)
    {
        while (TryTake(sender, out var operation)) await ExecuteAsync(operation).ConfigureAwait(false);
    }

    private bool TryTake(SessionId sender, out DispatchOperation operation)
    {
        lock (gate)
        {
            if (senderQueues.TryGetValue(sender, out var queue) && queue.Count > 0)
            { operation = queue.Dequeue(); return true; }
            senderQueues.Remove(sender); operation = null!; return false;
        }
    }

    private async Task ExecuteAsync(DispatchOperation operation)
    {
        try { operation.Completion.TrySetResult(await ExecuteOwnedAsync(operation).ConfigureAwait(false)); }
        catch (OperationCanceledException exception) { operation.Completion.TrySetCanceled(exception.CancellationToken); }
        catch (Exception exception) { operation.Completion.TrySetException(exception); }
        finally
        {
            lock (gate) if (inFlight.TryGetValue(operation.Pending.Id, out var current) && ReferenceEquals(current, operation)) inFlight.Remove(operation.Pending.Id);
            operation.Dispose();
        }
    }

    private async Task<Message> ExecuteOwnedAsync(DispatchOperation operation)
    {
        var cancellationToken = operation.Token;
        cancellationToken.ThrowIfCancellationRequested();
        var dispatched = false;
        try
        {
            var stored = await messages.GetAsync(operation.Pending.Id, cancellationToken).ConfigureAwait(false)
                ?? throw new OperationCanceledException($"Message '{operation.Pending.Id}' is no longer present.", cancellationToken);
            if (authoritativeMsg01 is null && IsTerminal(stored)) return stored;
            if (stored.Recipient is null)
            {
                var recipients = operation.GroupRecipients ?? stored.NotifyRecipients
                    ?? throw new InvalidDataException("Outgoing group message has no durable recipient snapshot.");
                await groupSync.SendGroupMessageAsync(new(stored.Id, stored.ConversationId, stored.Sender,
                    stored.Body, stored.Attachments, stored.CreatedAt, stored.ExpiresAt, stored.ReplyTo,
                    NotifyRecipients: recipients), cancellationToken).ConfigureAwait(false);
            }
            else
                await transport.SendAsync(new(stored.Sender, stored.Recipient.Value, stored.Body,
                    stored.Attachments, stored.CreatedAt, stored.ExpiresAt, stored.Id, stored.ReplyTo),
                    cancellationToken).ConfigureAwait(false);
            dispatched = true;
            var current = await messages.GetAsync(stored.Id, CancellationToken.None).ConfigureAwait(false);
            if (current is null) return stored.Mark(MessageDeliveryState.Sent);
            if (IsTerminal(current)) return current;
            var sent = current.Mark(MessageDeliveryState.Sent);
            await messages.UpdateAsync(sent, CancellationToken.None).ConfigureAwait(false);
            return sent;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Msg01DeliveryPendingException) when (authoritativeMsg01 is not null)
        {
            var current = await messages.GetAsync(
                operation.Pending.Id, CancellationToken.None).ConfigureAwait(false);
            if (current is null) return operation.Pending;
            if (current.DeliveryState == MessageDeliveryState.Failed)
            {
                current = current.Mark(MessageDeliveryState.Sending);
                await messages.UpdateAsync(current, CancellationToken.None).ConfigureAwait(false);
            }
            return current;
        }
        catch (Exception exception) when (!dispatched)
        {
            var current = await messages.GetAsync(operation.Pending.Id, CancellationToken.None).ConfigureAwait(false);
            if (current is not null && IsTerminal(current)) return current;
            try { failureObserver?.Observe(exception); } catch { }
            if (current is not null && authoritativeMsg01 is not null
                && current.DeliveryState == MessageDeliveryState.Failed)
                await messages.UpdateAsync(current.Mark(MessageDeliveryState.Sending), CancellationToken.None).ConfigureAwait(false);
            else if (current is not null && authoritativeMsg01 is null && !IsTerminal(current))
                await messages.UpdateAsync(current.Mark(MessageDeliveryState.Failed), CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private void ThrowIfBlocked(Message pending)
    {
        if (stoppedAccounts.Contains(pending.Sender) || conversationBarriers.ContainsKey(pending.ConversationId)
            || messageBarriers.ContainsKey(pending.Id))
            throw new OperationCanceledException($"Message '{pending.Id}' was invalidated by a lifecycle barrier.");
    }

    private void EnsureAccepting()
    {
        lock (gate) ObjectDisposedException.ThrowIf(!accepting, this);
    }

    private static bool IsTerminal(Message message) => message.DeliveryState is MessageDeliveryState.Sent or MessageDeliveryState.Delivered or MessageDeliveryState.Read;
    private static void EnsureCompatible(Message first, Message second)
    {
        if (first.Sender != second.Sender || first.ConversationId != second.ConversationId
            || first.Recipient != second.Recipient || first.Direction != second.Direction
            || first.Body != second.Body || first.CreatedAt != second.CreatedAt || first.ExpiresAt != second.ExpiresAt
            || first.ReplyTo != second.ReplyTo || !first.Attachments.SequenceEqual(second.Attachments)
            || !(first.NotifyRecipients ?? []).SequenceEqual(second.NotifyRecipients ?? []))
            throw new InvalidOperationException("A message is already being dispatched with a different envelope.");
    }
    private static Task AcknowledgeAsync(object candidate, SessionId account, string hash, CancellationToken ct) =>
        candidate is IDurableInboxAcknowledger acknowledger
            ? acknowledger.AcknowledgeInboxItemAsync(account, hash, ct)
            : Task.CompletedTask;
    private static void Increment<TKey>(Dictionary<TKey, int> values, TKey key) where TKey : notnull => values[key] = values.GetValueOrDefault(key) + 1;
    private static void Decrement<TKey>(Dictionary<TKey, int> values, TKey key) where TKey : notnull
    { if (values[key] == 1) values.Remove(key); else values[key]--; }

    internal sealed class DispatchBarrier(IReadOnlyList<DispatchOperation> operations, Action release) : IAsyncDisposable
    {
        private int disposed;
        internal Task QuiesceAsync(CancellationToken ct) => CancelAndAwaitAsync(operations, ct);
        public ValueTask DisposeAsync() { if (Interlocked.Exchange(ref disposed, 1) == 0) release(); return ValueTask.CompletedTask; }
    }

    private static async Task CancelAndAwaitAsync(IReadOnlyList<DispatchOperation> operations, CancellationToken ct)
    {
        foreach (var operation in operations) operation.Cancel();
        foreach (var operation in operations)
        {
            try { await operation.Completion.Task.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { }
        }
    }

    internal sealed class DispatchOperation(Message pending, IReadOnlyList<SessionId>? recipients, CancellationToken token) : IDisposable
    {
        private readonly CancellationTokenSource cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        internal Message Pending { get; } = pending;
        internal IReadOnlyList<SessionId>? GroupRecipients { get; } = recipients?.ToArray();
        internal CancellationToken Token => cancellation.Token;
        internal TaskCompletionSource<Message> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Cancel() { try { cancellation.Cancel(); } catch (ObjectDisposedException) { } }
        public void Dispose() => cancellation.Dispose();
    }
}
