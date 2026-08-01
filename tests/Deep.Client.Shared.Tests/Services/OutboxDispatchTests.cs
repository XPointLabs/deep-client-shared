using System.Collections.Concurrent;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class OutboxDispatchTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-11T00:00:00Z");

    [Fact]
    public async Task ForegroundAndBackgroundDirectDispatchesShareOnePhysicalSend()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "coalesced direct");

        var foreground = runtime.Messages.DispatchOneToOneAsync(pending);
        await transport.WaitForSendAsync(1);
        var background = runtime.Messages.DispatchPendingMessagesAsync(sender.SessionId);

        Assert.False(background.IsCompleted);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        var sent = await foreground.WaitAsync(TestTimeout);
        var dispatched = await background.WaitAsync(TestTimeout);
        var stored = await runtime.Store.GetAsync(pending.Id);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Equal(1, dispatched);
        Assert.Equal(MessageDeliveryState.Sent, stored?.DeliveryState);
        Assert.Equal([pending.Id], transport.DispatchedMessageIds);
    }

    [Fact]
    public async Task ForegroundAndBackgroundGroupDispatchesShareOnePhysicalSend()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var group = await runtime.Conversations.CreateGroupScaffoldAsync(
            sender.SessionId,
            "Dispatch group",
            [SessionId.CreateNew()]);
        var pending = await runtime.Messages.QueueGroupAsync(sender.SessionId, group.Id, "coalesced group");

        var foreground = runtime.Messages.DispatchGroupAsync(pending);
        await transport.WaitForSendAsync(1);
        var background = runtime.Messages.DispatchPendingMessagesAsync(sender.SessionId);

        Assert.False(background.IsCompleted);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        var sent = await foreground.WaitAsync(TestTimeout);
        var dispatched = await background.WaitAsync(TestTimeout);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Equal(1, dispatched);
        Assert.Equal([pending.Id], transport.DispatchedMessageIds);
    }

    [Fact]
    public async Task DifferentMessagesFromSameSenderDispatchSequentiallyAcrossTransports()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var direct = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "first");
        var group = await runtime.Conversations.CreateGroupScaffoldAsync(
            sender.SessionId,
            "Sequential group",
            [SessionId.CreateNew()]);
        var groupMessage = await runtime.Messages.QueueGroupAsync(sender.SessionId, group.Id, "second");

        var firstDispatch = runtime.Messages.DispatchOneToOneAsync(direct);
        await transport.WaitForSendAsync(1);
        var secondDispatch = runtime.Messages.DispatchGroupAsync(groupMessage);

        Assert.Equal(1, transport.PhysicalSendCount);
        Assert.False(secondDispatch.IsCompleted);

        transport.CompleteSend(1);
        await transport.WaitForSendAsync(2);

        Assert.Equal(1, transport.MaxConcurrentSends);
        Assert.Equal([direct.Id, groupMessage.Id], transport.DispatchedMessageIds);

        transport.CompleteSend(2);
        var results = await Task.WhenAll(firstDispatch, secondDispatch).WaitAsync(TestTimeout);

        Assert.All(results, message => Assert.Equal(MessageDeliveryState.Sent, message.DeliveryState));
        Assert.Equal(1, transport.MaxConcurrentSends);
    }

    [Fact]
    public async Task SameMessageIdCannotJoinSingleFlightWithChangedSemanticEnvelope()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId, SessionId.CreateNew(), "immutable original");

        var dispatch = runtime.Messages.DispatchOneToOneAsync(pending);
        await transport.WaitForSendAsync(1);
        var rejected = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            runtime.Messages.DispatchOneToOneAsync(
                pending with { Body = "changed body" }));
        Assert.DoesNotContain(pending.Id.Value, rejected.Message, StringComparison.Ordinal);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        Assert.Equal(
            MessageDeliveryState.Sent,
            (await dispatch.WaitAsync(TestTimeout)).DeliveryState);
    }

    [Fact]
    public async Task CancelingForegroundWaiterDoesNotCancelSharedBackgroundDispatch()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "wait independently");
        using var waiterCancellation = new CancellationTokenSource();

        var foreground = runtime.Messages.DispatchOneToOneAsync(pending, waiterCancellation.Token);
        await transport.WaitForSendAsync(1);
        var background = runtime.Messages.DispatchPendingMessagesAsync(sender.SessionId);

        waiterCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await foreground);
        Assert.False(background.IsCompleted);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        var dispatched = await background.WaitAsync(TestTimeout);
        var stored = await runtime.Store.GetAsync(pending.Id);

        Assert.Equal(1, dispatched);
        Assert.Equal(MessageDeliveryState.Sent, stored?.DeliveryState);
    }

    [Fact]
    public async Task CancelingBackgroundOwnerTerminatesSharedDispatchAndAllowsRetry()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "cancel lifecycle owner");
        using var lifecycleCancellation = new CancellationTokenSource();

        var background = runtime.Messages.DispatchPendingMessagesAsync(
            sender.SessionId,
            lifecycleCancellation.Token);
        await transport.WaitForSendAsync(1);
        var foreground = runtime.Messages.DispatchOneToOneAsync(pending);

        lifecycleCancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await background.WaitAsync(TestTimeout));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await foreground.WaitAsync(TestTimeout));
        Assert.Equal(MessageDeliveryState.Sending, (await runtime.Store.GetAsync(pending.Id))?.DeliveryState);

        var retry = runtime.Messages.DispatchOneToOneAsync(pending);
        await transport.WaitForSendAsync(2);
        transport.CompleteSend(2);
        var sent = await retry.WaitAsync(TestTimeout);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Equal(2, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task LatePhysicalFailureDoesNotOverwritePersistedSentState()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "terminal sent wins");

        var dispatch = runtime.Messages.DispatchOneToOneAsync(pending);
        await transport.WaitForSendAsync(1);
        await runtime.Store.UpdateAsync(pending.Mark(MessageDeliveryState.Sent));

        transport.FailSend(1, new HttpRequestException("late failure"));
        var result = await dispatch.WaitAsync(TestTimeout);
        var stored = await runtime.Store.GetAsync(pending.Id);

        Assert.Equal(MessageDeliveryState.Sent, result.DeliveryState);
        Assert.Equal(MessageDeliveryState.Sent, stored?.DeliveryState);
        Assert.Equal(1, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task LifecycleCancellationAfterPhysicalSendStillPersistsSentState()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "accepted before lifecycle cancellation");
        using var lifecycleCancellation = new CancellationTokenSource();
        transport.BeforeSuccessfulReturn = lifecycleCancellation.Cancel;

        var dispatch = runtime.Messages.DispatchPendingMessagesAsync(
            sender.SessionId,
            lifecycleCancellation.Token);
        await transport.WaitForSendAsync(1);
        transport.CompleteSend(1);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await dispatch.WaitAsync(TestTimeout));
        var terminal = await runtime.Messages.DispatchOneToOneAsync(pending).WaitAsync(TestTimeout);
        var stored = await runtime.Store.GetAsync(pending.Id);

        Assert.Equal(MessageDeliveryState.Sent, terminal.DeliveryState);
        Assert.Equal(MessageDeliveryState.Sent, stored?.DeliveryState);
        Assert.Equal(1, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task SignOutWaitsForDispatchQuiescenceAndPurgesQueuedMessages()
    {
        var transport = new BarrierDispatchTransport { IgnoreCancellationWhileBlocked = true };
        var innerStore = new InMemorySessionStore();
        using var runtime = CreateRuntime(transport, innerStore);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var first = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, recipient, "first before logout");
        var second = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, recipient, "queued before logout");

        var firstDispatch = runtime.Messages.DispatchOneToOneAsync(first);
        await transport.WaitForSendAsync(1);
        var secondDispatch = runtime.Messages.DispatchOneToOneAsync(second);
        var signOut = runtime.Accounts.SignOutAsync();

        await transport.WaitForCancellationAsync(1);
        Assert.False(signOut.IsCompleted);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        await signOut.WaitAsync(TestTimeout);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await firstDispatch.WaitAsync(TestTimeout));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await secondDispatch.WaitAsync(TestTimeout));

        Assert.Null(await innerStore.GetAsync(first.Id));
        Assert.Null(await innerStore.GetAsync(second.Id));
        Assert.Empty(await ToListAsync(
            ((IMessageRepository)innerStore).ListForConversationAsync(first.ConversationId)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await runtime.Messages.DispatchOneToOneAsync(second).WaitAsync(TestTimeout));
        Assert.Equal(1, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task ClearConversationWaitsForDispatchQuiescenceAndPreventsStaleSend()
    {
        var transport = new BarrierDispatchTransport { IgnoreCancellationWhileBlocked = true };
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var first = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, recipient, "first before clear");
        var second = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, recipient, "queued before clear");

        var firstDispatch = runtime.Messages.DispatchOneToOneAsync(first);
        await transport.WaitForSendAsync(1);
        var secondDispatch = runtime.Messages.DispatchOneToOneAsync(second);
        var clear = runtime.Messages.ClearConversationMessagesAsync(first.ConversationId);

        await transport.WaitForCancellationAsync(1);
        Assert.False(clear.IsCompleted);
        Assert.Equal(1, transport.PhysicalSendCount);

        transport.CompleteSend(1);
        Assert.Equal(2, await clear.WaitAsync(TestTimeout));
        Assert.Equal(MessageDeliveryState.Sent, (await firstDispatch.WaitAsync(TestTimeout)).DeliveryState);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await secondDispatch.WaitAsync(TestTimeout));

        Assert.Empty(await ToListAsync(
            ((IMessageRepository)runtime.Store).ListForConversationAsync(first.ConversationId)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await runtime.Messages.DispatchOneToOneAsync(second).WaitAsync(TestTimeout));
        Assert.Equal(1, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task DeleteMessageWaitsForDispatchQuiescenceAndDoesNotResurrectRow()
    {
        var transport = new BarrierDispatchTransport { IgnoreCancellationWhileBlocked = true };
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId,
            SessionId.CreateNew(),
            "delete while sending");

        var dispatch = runtime.Messages.DispatchOneToOneAsync(pending);
        await transport.WaitForSendAsync(1);
        var delete = runtime.Messages.DeleteMessageAsync(pending.Id);

        await transport.WaitForCancellationAsync(1);
        Assert.False(delete.IsCompleted);
        transport.CompleteSend(1);

        Assert.True(await delete.WaitAsync(TestTimeout));
        Assert.Equal(MessageDeliveryState.Sent, (await dispatch.WaitAsync(TestTimeout)).DeliveryState);
        Assert.Null(await runtime.Store.GetAsync(pending.Id));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await runtime.Messages.DispatchOneToOneAsync(pending).WaitAsync(TestTimeout));
        Assert.Equal(1, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task MessageUpdateNeverRecreatesDeletedRow()
    {
        await AssertUpdateDoesNotRecreateDeletedRowAsync(new InMemorySessionStore());

        var statePath = Path.Combine(Path.GetTempPath(), $"deep-outbox-update-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(statePath);
            await AssertUpdateDoesNotRecreateDeletedRowAsync(store);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task ManualAndAutomaticRetryShareOnePhysicalSendAndExactEnvelope()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var attachment = new AttachmentMetadata(
            "attachment-token", "opaque.bin", "application/octet-stream", 7);
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId, SessionId.CreateNew(), "exact retry", [attachment]);
        await runtime.Store.UpdateAsync(pending.Mark(MessageDeliveryState.Failed));

        var automatic = runtime.Messages.DispatchPendingMessagesAsync(sender.SessionId);
        await transport.WaitForSendAsync(1);
        var manual = runtime.Messages.RetryOutgoingAsync(sender.SessionId, pending.Id);

        Assert.Equal(1, transport.PhysicalSendCount);
        transport.CompleteSend(1);
        Assert.Equal(1, await automatic.WaitAsync(TestTimeout));
        var result = await manual.WaitAsync(TestTimeout);
        Assert.Equal(MessageDeliveryState.Sent, result.DeliveryState);
        Assert.Equal(pending.Id, result.Id);
        Assert.Equal(pending.Body, result.Body);
        Assert.Equal(pending.Attachments, result.Attachments);
        Assert.Equal(pending.CreatedAt, result.CreatedAt);
        Assert.Equal(pending.ExpiresAt, result.ExpiresAt);
    }

    [Fact]
    public async Task ManualRetryIsTerminalIdempotentAndRejectsNonOwnerWithoutIdentifiers()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId, SessionId.CreateNew(), "terminal retry");
        await runtime.Store.UpdateAsync(pending.Mark(MessageDeliveryState.Sent));

        var terminal = await runtime.Messages.RetryOutgoingAsync(sender.SessionId, pending.Id);
        Assert.Equal(MessageDeliveryState.Sent, terminal.DeliveryState);
        Assert.Equal(0, transport.PhysicalSendCount);

        var rejected = await Assert.ThrowsAsync<MessageRetryRejectedException>(() =>
            runtime.Messages.RetryOutgoingAsync(SessionId.CreateNew(), pending.Id));
        Assert.Equal(MessageRetryRejection.NotOwned, rejected.Reason);
        Assert.DoesNotContain(pending.Id.Value, rejected.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(sender.SessionId.Value, rejected.Message, StringComparison.Ordinal);

        var missingId = new MessageId("missing-retry-id");
        var missing = await Assert.ThrowsAsync<MessageRetryRejectedException>(() =>
            runtime.Messages.RetryOutgoingAsync(sender.SessionId, missingId));
        Assert.Equal(MessageRetryRejection.NotFound, missing.Reason);
        Assert.DoesNotContain(missingId.Value, missing.Message, StringComparison.Ordinal);

        var incoming = pending with
        {
            Id = new MessageId("incoming-retry-id"),
            Direction = MessageDirection.Incoming,
            DeliveryState = MessageDeliveryState.Delivered
        };
        await runtime.Store.AppendAsync(incoming);
        var wrongDirection = await Assert.ThrowsAsync<MessageRetryRejectedException>(() =>
            runtime.Messages.RetryOutgoingAsync(sender.SessionId, incoming.Id));
        Assert.Equal(MessageRetryRejection.NotOutgoing, wrongDirection.Reason);

        var draft = pending with
        {
            Id = new MessageId("draft-retry-id"),
            DeliveryState = MessageDeliveryState.Draft
        };
        await runtime.Store.AppendAsync(draft);
        var notRetryable = await Assert.ThrowsAsync<MessageRetryRejectedException>(() =>
            runtime.Messages.RetryOutgoingAsync(sender.SessionId, draft.Id));
        Assert.Equal(MessageRetryRejection.NotRetryable, notRetryable.Reason);
        Assert.Equal(0, transport.PhysicalSendCount);
    }

    [Fact]
    public async Task FailedManualRetryRemainsFailed()
    {
        var transport = new BarrierDispatchTransport();
        using var runtime = CreateRuntime(transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(
            sender.SessionId, SessionId.CreateNew(), "retry failure");
        await runtime.Store.UpdateAsync(pending.Mark(MessageDeliveryState.Failed));

        var retry = runtime.Messages.RetryOutgoingAsync(sender.SessionId, pending.Id);
        await transport.WaitForSendAsync(1);
        transport.FailSend(1, new HttpRequestException("synthetic"));
        await Assert.ThrowsAsync<HttpRequestException>(() => retry);
        Assert.Equal(
            MessageDeliveryState.Failed,
            (await runtime.Store.GetAsync(pending.Id))?.DeliveryState);
    }

    private static async Task AssertUpdateDoesNotRecreateDeletedRowAsync(IMessageRepository repository)
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var pending = new Message(
            MessageId.NewId(),
            ConversationId.ForOneToOne(recipient),
            sender,
            recipient,
            "conditional terminal update",
            MessageDirection.Outgoing,
            MessageDeliveryState.Sending,
            Now,
            []);
        await repository.AppendAsync(pending);
        await repository.DeleteAsync(pending.Id);

        await repository.UpdateAsync(pending.Mark(MessageDeliveryState.Sent));

        Assert.Null(await repository.GetAsync(pending.Id));
    }

    private static async Task<IReadOnlyList<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var items = new List<T>();
        await foreach (var item in source)
        {
            items.Add(item);
        }

        return items;
    }

    private static void DeleteSqliteFiles(string statePath)
    {
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static ClientRuntime CreateRuntime(
        BarrierDispatchTransport transport,
        ILocalSessionStore? store = null) =>
        new(
            store ?? new InMemorySessionStore(),
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            transport,
            transport);

    private sealed class BarrierDispatchTransport : ISessionMessageTransport, IGroupSyncTransport
    {
        private readonly ConcurrentDictionary<int, TaskCompletionSource> sendStarted = [];
        private readonly ConcurrentDictionary<int, TaskCompletionSource> sendReleases = [];
        private readonly ConcurrentDictionary<int, TaskCompletionSource> cancellationObserved = [];
        private readonly ConcurrentDictionary<int, Exception> sendFailures = [];
        private readonly ConcurrentQueue<MessageId> dispatchedMessageIds = [];
        private int physicalSendCount;
        private int activeSends;
        private int maxConcurrentSends;

        public int PhysicalSendCount => Volatile.Read(ref physicalSendCount);

        public int MaxConcurrentSends => Volatile.Read(ref maxConcurrentSends);

        public IReadOnlyList<MessageId> DispatchedMessageIds => dispatchedMessageIds.ToArray();

        public Action? BeforeSuccessfulReturn { get; set; }

        public bool IgnoreCancellationWhileBlocked { get; init; }

        public Task WaitForSendAsync(int callNumber) =>
            Signal(sendStarted, callNumber).Task.WaitAsync(TestTimeout);

        public Task WaitForCancellationAsync(int callNumber) =>
            Signal(cancellationObserved, callNumber).Task.WaitAsync(TestTimeout);

        public void CompleteSend(int callNumber) => Signal(sendReleases, callNumber).TrySetResult();

        public void FailSend(int callNumber, Exception exception)
        {
            sendFailures[callNumber] = exception;
            CompleteSend(callNumber);
        }

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            SendCoreAsync(
                envelope.Id ?? throw new InvalidOperationException("Outbox message ID is required."),
                cancellationToken);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>([]);

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            SendCoreAsync(envelope.Id, cancellationToken);

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>([]);

        private async Task SendCoreAsync(MessageId messageId, CancellationToken cancellationToken)
        {
            var callNumber = Interlocked.Increment(ref physicalSendCount);
            dispatchedMessageIds.Enqueue(messageId);
            var concurrentSends = Interlocked.Increment(ref activeSends);
            UpdateMaximum(ref maxConcurrentSends, concurrentSends);
            using var cancellationRegistration = cancellationToken.Register(
                static state => ((TaskCompletionSource)state!).TrySetResult(),
                Signal(cancellationObserved, callNumber));
            Signal(sendStarted, callNumber).TrySetResult();

            try
            {
                var release = Signal(sendReleases, callNumber).Task;
                if (IgnoreCancellationWhileBlocked)
                {
                    await release.ConfigureAwait(false);
                }
                else
                {
                    await release.WaitAsync(cancellationToken).ConfigureAwait(false);
                }
                if (sendFailures.TryRemove(callNumber, out var exception))
                {
                    throw exception;
                }

                BeforeSuccessfulReturn?.Invoke();
            }
            finally
            {
                Interlocked.Decrement(ref activeSends);
            }
        }

        private static TaskCompletionSource Signal(
            ConcurrentDictionary<int, TaskCompletionSource> signals,
            int callNumber) =>
            signals.GetOrAdd(
                callNumber,
                static _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        private static void UpdateMaximum(ref int maximum, int candidate)
        {
            var current = Volatile.Read(ref maximum);
            while (candidate > current)
            {
                var observed = Interlocked.CompareExchange(ref maximum, candidate, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }
}
