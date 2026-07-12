using System.Collections.Concurrent;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class InboxSyncCoalescingTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-11T00:00:00Z");

    [Fact]
    public async Task ConcurrentSynchronizationsForSameAccountShareCurrentCycleAndResult()
    {
        var transport = new BlockingInboxTransport();
        using var runtime = CreateRuntime(transport);
        var account = await runtime.Accounts.RegisterAsync("Alice");
        transport.Enqueue(account.SessionId, CreateMessage(account.SessionId, "shared-result"));

        var foregroundSync = runtime.Inbox.SynchronizeAsync();
        await transport.ReceiveStarted.WaitAsync(TestTimeout);
        var pushSync = runtime.Inbox.SynchronizeAsync();

        Assert.False(pushSync.IsCompleted);
        transport.Release();
        var results = await Task.WhenAll(foregroundSync, pushSync).WaitAsync(TestTimeout);

        Assert.Equal(new InboxSyncResult(1, 0, 0, 0), results[0]);
        Assert.Equal(results[0], results[1]);
        Assert.Equal(1, transport.ReceiveCallCount);
    }

    [Fact]
    public async Task CancelingOneCallerDoesNotCancelCycleSharedWithAnotherCaller()
    {
        var transport = new BlockingInboxTransport();
        using var runtime = CreateRuntime(transport);
        var account = await runtime.Accounts.RegisterAsync("Alice");
        transport.Enqueue(account.SessionId, CreateMessage(account.SessionId, "survives-cancellation"));
        using var cancellation = new CancellationTokenSource();

        var canceledCaller = runtime.Inbox.SynchronizeAsync(cancellation.Token);
        await transport.ReceiveStarted.WaitAsync(TestTimeout);
        var survivingCaller = runtime.Inbox.SynchronizeAsync();

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await canceledCaller);
        Assert.False(survivingCaller.IsCompleted);

        transport.Release();
        var result = await survivingCaller.WaitAsync(TestTimeout);

        Assert.Equal(new InboxSyncResult(1, 0, 0, 0), result);
        Assert.Equal(1, transport.ReceiveCallCount);
    }

    [Fact]
    public async Task LogoutWhileCycleIsRunningSuppressesItsResultForAllCallers()
    {
        var transport = new BlockingInboxTransport();
        using var runtime = CreateRuntime(transport);
        var account = await runtime.Accounts.RegisterAsync("Alice");
        transport.Enqueue(account.SessionId, CreateMessage(account.SessionId, "signed-out-message"));

        var foregroundSync = runtime.Inbox.SynchronizeAsync();
        await transport.ReceiveStarted.WaitAsync(TestTimeout);
        var pushSync = runtime.Inbox.SynchronizeAsync();
        await runtime.Accounts.SignOutAsync();

        transport.Release();
        var results = await Task.WhenAll(foregroundSync, pushSync).WaitAsync(TestTimeout);

        Assert.All(results, result => Assert.Equal(new InboxSyncResult(0, 0, 0, 0), result));
        Assert.Equal(1, transport.ReceiveCallCount);
    }

    [Fact]
    public async Task AccountSwitchDoesNotLetOldCallerSynchronizeOrReturnNewAccountData()
    {
        var transport = new BlockingInboxTransport();
        using var runtime = CreateRuntime(transport);
        var oldAccount = await runtime.Accounts.RegisterAsync("Alice");
        var oldMessage = CreateMessage(oldAccount.SessionId, "old-account-message");
        transport.Enqueue(oldAccount.SessionId, oldMessage);

        var foregroundSync = runtime.Inbox.SynchronizeAsync();
        await transport.ReceiveStarted.WaitAsync(TestTimeout);
        var pushSync = runtime.Inbox.SynchronizeAsync();

        await runtime.Accounts.SignOutAsync();
        var newAccount = await runtime.Accounts.RegisterAsync("Bob");
        transport.Enqueue(newAccount.SessionId, CreateMessage(newAccount.SessionId, "bob-only"));
        transport.Release();

        var oldResults = await Task.WhenAll(foregroundSync, pushSync).WaitAsync(TestTimeout);
        Assert.All(oldResults, result => Assert.Equal(new InboxSyncResult(0, 0, 0, 0), result));
        Assert.Equal([oldAccount.SessionId], transport.ReceivedAccounts);
        Assert.Null(await runtime.Store.GetAsync(oldMessage.Id));

        var newResult = await runtime.Inbox.SynchronizeAsync().WaitAsync(TestTimeout);

        Assert.Equal(new InboxSyncResult(1, 0, 0, 0), newResult);
        Assert.Equal([oldAccount.SessionId, newAccount.SessionId], transport.ReceivedAccounts);
    }

    private static ClientRuntime CreateRuntime(ISessionMessageTransport transport) =>
        new(
            new InMemorySessionStore(),
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            transport);

    private static InboundMessageEnvelope CreateMessage(SessionId recipient, string body) =>
        new(
            MessageId.NewId(),
            SessionId.CreateNew(),
            recipient,
            body,
            [],
            Now,
            ExpiresAt: null,
            $"hash-{body}");

    private sealed class BlockingInboxTransport : ISessionMessageTransport
    {
        private readonly ConcurrentDictionary<SessionId, ConcurrentQueue<InboundMessageEnvelope>> inboxes = [];
        private readonly ConcurrentQueue<SessionId> receivedAccounts = [];
        private readonly TaskCompletionSource receiveStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource releaseReceive =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int receiveCallCount;

        public Task ReceiveStarted => receiveStarted.Task;

        public int ReceiveCallCount => Volatile.Read(ref receiveCallCount);

        public IReadOnlyList<SessionId> ReceivedAccounts => receivedAccounts.ToArray();

        public void Enqueue(SessionId recipient, InboundMessageEnvelope envelope) =>
            inboxes.GetOrAdd(recipient, static _ => new ConcurrentQueue<InboundMessageEnvelope>()).Enqueue(envelope);

        public void Release() => releaseReceive.TrySetResult();

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref receiveCallCount);
            receivedAccounts.Enqueue(recipient);
            receiveStarted.TrySetResult();
            await releaseReceive.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

            if (!inboxes.TryGetValue(recipient, out var inbox))
            {
                return [];
            }

            var messages = new List<InboundMessageEnvelope>();
            while (inbox.TryDequeue(out var message))
            {
                messages.Add(message);
            }

            return messages;
        }
    }
}
