using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using System.Diagnostics;

namespace Deep.Client.Shared.Tests.Services;

public sealed class TransportOutboxDispatcherTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-22T09:00:00Z");

    [Fact]
    public void RuntimeFailsClosedWhenEnabledAdapterIsMissing()
    {
        var flags = ClientFeatureFlags.Defaults with { PersistentTransportOutboxEnabled = true };

        var exception = Assert.Throws<InvalidOperationException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            flags,
            new FrozenClock(Now),
            new StubSessionBackend()));

        Assert.Contains("no transport outbox adapter", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RuntimeRejectsDormantAdapterToAvoidFalseActivation()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend(),
            transportOutboxAdapter: new RecordingAdapter()));

        Assert.Contains("is disabled", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DurableReceiptPersistsExactOpaqueBundleAndDoesNotRedispatch()
    {
        var store = new InMemorySessionStore();
        var adapter = new RecordingAdapter();
        using var runtime = CreateRuntime(store, adapter, new FrozenClock(Now));
        var item = Prepared();

        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await runtime.TransportOutbox!.PrepareAsync(item));
        var result = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var second = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var persisted = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, result.DurableCount);
        Assert.Equal(1, result.AttemptedCount);
        Assert.Equal(0, second.AttemptedCount);
        Assert.Equal(1, adapter.Calls);
        Assert.Equal(item.GetCiphertextBundleCopy(), adapter.LastBundle);
        Assert.Equal(item.DedupMaterial.ToArray(), adapter.LastDedupMaterial);
        Assert.Equal(TransportOutboxState.Durable, persisted.Item?.State);
        Assert.Equal(TransportOutboxAttemptState.Durable, persisted.Item?.Attempts.Single().State);

        adapter.LastBundle![0] ^= 0xff;
        Assert.Equal(item.GetCiphertextBundleCopy(), persisted.Item?.GetCiphertextBundleCopy());
    }

    [Fact]
    public async Task AdapterFailureIsRedactedAndRetriedWithNewAttemptAfterBackoff()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new RecordingAdapter
        {
            Failure = new InvalidOperationException("https://secret-bridge.invalid raw-session-id")
        };
        using var runtime = CreateRuntime(store, adapter, clock);
        var item = Prepared();
        await runtime.TransportOutbox!.PrepareAsync(item);

        var failed = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var deferred = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var afterFailure = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, failed.RetryScheduledCount);
        Assert.Equal(0, deferred.AttemptedCount);
        Assert.Equal(TransportOutboxState.Attempted, afterFailure.Item?.State);
        Assert.Single(afterFailure.Item!.Attempts);

        adapter.Failure = null;
        clock.Advance(TransportOutboxDispatcher.DefaultRetryDelay);
        var retried = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var durable = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, retried.DurableCount);
        Assert.Equal(2, adapter.Calls);
        Assert.Equal(TransportOutboxState.Durable, durable.Item?.State);
        Assert.Equal(2, durable.Item?.Attempts.Count);
        Assert.NotEqual(
            durable.Item!.Attempts[0].AttemptId.ToArray(),
            durable.Item.Attempts[1].AttemptId.ToArray());
    }

    [Fact]
    public async Task AcceptedReceiptRemainsRetryableAndNeverClaimsDurability()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new RecordingAdapter { AcceptedOnly = true };
        using var runtime = CreateRuntime(store, adapter, clock);
        var item = Prepared();
        await runtime.TransportOutbox!.PrepareAsync(item);

        var accepted = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var persisted = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, accepted.AcceptedCount);
        Assert.Equal(TransportOutboxState.Accepted, persisted.Item?.State);

        adapter.AcceptedOnly = false;
        clock.Advance(TransportOutboxDispatcher.DefaultRetryDelay);
        var retried = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        persisted = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, retried.DurableCount);
        Assert.Equal(TransportOutboxState.Durable, persisted.Item?.State);
        Assert.Equal(2, persisted.Item?.Attempts.Count);
    }

    [Fact]
    public async Task ReceiptAfterLifetimeExpiresRatherThanClaimingAcceptedOrDurable()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new RecordingAdapter { BeforeReturn = () => clock.Advance(TimeSpan.FromMinutes(2)) };
        using var runtime = CreateRuntime(store, adapter, clock);
        var item = Prepared(Now.AddMinutes(1));
        await runtime.TransportOutbox!.PrepareAsync(item);

        var result = await runtime.TransportOutbox.DispatchReadyAsync(item.AccountScope);
        var persisted = await store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, result.ExpiredCount);
        Assert.Equal(0, result.AcceptedCount);
        Assert.Equal(0, result.DurableCount);
        Assert.Equal(TransportOutboxState.Expired, persisted.Item?.State);
    }

    [Fact]
    public async Task CooperativeAttemptTimeoutStopsAdapterAndNextPassCanRetry()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new TimeoutThenSuccessAdapter();
        var dispatcher = new TransportOutboxDispatcher(
            store,
            adapter,
            clock,
            retryDelay: TimeSpan.Zero,
            attemptTimeout: TimeSpan.FromMilliseconds(50));
        var item = Prepared();
        await dispatcher.PrepareAsync(item);

        var stopwatch = Stopwatch.StartNew();
        var timedOut = await dispatcher.DispatchReadyAsync(item.AccountScope);
        stopwatch.Stop();

        Assert.Equal(1, timedOut.RetryScheduledCount);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
        await adapter.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(1, adapter.CompletedCalls);

        var retried = await dispatcher.DispatchReadyAsync(item.AccountScope);
        var persisted = await dispatcher.ReadAsync(item.AccountScope, item.LogicalId);

        Assert.Equal(1, retried.DurableCount);
        Assert.Equal(2, adapter.Calls);
        Assert.Equal(2, adapter.CompletedCalls);
        Assert.Equal(TransportOutboxState.Durable, persisted.Item?.State);
    }

    [Fact]
    public async Task CooperativeAttemptTimeoutIsCappedByRemainingItemLifetime()
    {
        var clock = new ElapsedClock();
        var store = new InMemorySessionStore();
        var adapter = new AlwaysWaitingAdapter();
        var dispatcher = new TransportOutboxDispatcher(
            store,
            adapter,
            clock,
            attemptTimeout: TimeSpan.FromSeconds(2));
        var createdAt = clock.UtcNow;
        var item = TransportOutboxPreparedItem.Create(
            OutboxAccountScope.FromBytes(Bytes(TransportOutboxLimits.AccountScopeBytes, 0x11)),
            OutboxLogicalId.FromBytes(Bytes(TransportOutboxLimits.LogicalIdBytes, 0x23)),
            OutboxDedupMaterial.FromBytes(Bytes(TransportOutboxLimits.DedupMaterialBytes, 0x33)),
            Bytes(96, 0x44),
            createdAt,
            createdAt.AddMilliseconds(100),
            createdAt);
        await dispatcher.PrepareAsync(item);

        var stopwatch = Stopwatch.StartNew();
        var result = await dispatcher.DispatchReadyAsync(item.AccountScope);
        stopwatch.Stop();

        Assert.Equal(1, result.RetryScheduledCount);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
        await adapter.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CallerCancellationPropagatesAndStillStopsCooperativeAdapter()
    {
        var store = new InMemorySessionStore();
        var adapter = new AlwaysWaitingAdapter();
        var dispatcher = new TransportOutboxDispatcher(
            store,
            adapter,
            new FrozenClock(Now),
            attemptTimeout: TimeSpan.FromMinutes(1));
        var item = Prepared();
        await dispatcher.PrepareAsync(item);
        using var cancellation = new CancellationTokenSource();

        var dispatch = dispatcher.DispatchReadyAsync(item.AccountScope, cancellationToken: cancellation.Token);
        await adapter.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await dispatch);
        await adapter.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task FreshClockExpiresLaterItemBeforeAdapterIo()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new RecordingAdapter
        {
            BeforeReturn = () =>
            {
                if (clock.UtcNow == Now)
                {
                    clock.Advance(TimeSpan.FromMinutes(2));
                }
            }
        };
        var dispatcher = new TransportOutboxDispatcher(store, adapter, clock);
        var first = Prepared(logical: 0x21, expiresAt: Now.AddDays(1));
        var second = Prepared(logical: 0x22, expiresAt: Now.AddMinutes(1));
        await dispatcher.PrepareAsync(first);
        await dispatcher.PrepareAsync(second);

        var result = await dispatcher.DispatchReadyAsync(first.AccountScope, limit: 2);
        var expired = await dispatcher.ReadAsync(second.AccountScope, second.LogicalId);

        Assert.Equal(1, result.DurableCount);
        Assert.Equal(1, result.ExpiredCount);
        Assert.Equal(1, adapter.Calls);
        Assert.Equal(TransportOutboxState.Expired, expired.Item?.State);
        Assert.Empty(expired.Item!.Attempts);
    }

    [Fact]
    public async Task CorruptAttemptCommitFailsClosedBeforeAdapterIo()
    {
        var store = new InMemorySessionStore();
        var adapter = new RecordingAdapter();
        var repository = new ApplyResultRepository(
            store,
            transition => transition.TargetState == TransportOutboxState.Attempted);
        var dispatcher = new TransportOutboxDispatcher(repository, adapter, new FrozenClock(Now));
        var item = Prepared();
        await dispatcher.PrepareAsync(item);

        await Assert.ThrowsAsync<TransportOutboxCorruptException>(
            () => dispatcher.DispatchReadyAsync(item.AccountScope));
        Assert.Equal(0, adapter.Calls);
    }

    [Fact]
    public async Task CorruptExpiryCommitFailsClosed()
    {
        var store = new InMemorySessionStore();
        var clock = new FrozenClock(Now);
        var adapter = new RecordingAdapter { BeforeReturn = () => clock.Advance(TimeSpan.FromMinutes(2)) };
        var repository = new ApplyResultRepository(
            store,
            transition => transition.TargetState == TransportOutboxState.Expired);
        var dispatcher = new TransportOutboxDispatcher(repository, adapter, clock);
        var item = Prepared(expiresAt: Now.AddMinutes(1));
        await dispatcher.PrepareAsync(item);

        await Assert.ThrowsAsync<TransportOutboxCorruptException>(
            () => dispatcher.DispatchReadyAsync(item.AccountScope));
        Assert.Equal(1, adapter.Calls);
    }

    [Fact]
    public async Task SqliteRestartDispatchesPreviouslyPreparedBundle()
    {
        var path = Path.Combine(Path.GetTempPath(), $"deep-p11-runtime-{Guid.NewGuid():N}.db");
        var flags = ClientFeatureFlags.Defaults with { PersistentTransportOutboxEnabled = true };
        var item = Prepared();
        try
        {
            using (var first = ClientRuntime.CreatePersistentForTests(
                path,
                flags,
                new FrozenClock(Now),
                transportOutboxAdapter: new RecordingAdapter()))
            {
                await first.TransportOutbox!.PrepareAsync(item);
            }

            var adapter = new RecordingAdapter();
            using (var restarted = ClientRuntime.CreatePersistentForTests(
                path,
                flags,
                new FrozenClock(Now),
                transportOutboxAdapter: adapter))
            {
                var result = await restarted.TransportOutbox!.DispatchReadyAsync(item.AccountScope);
                var read = await restarted.TransportOutbox.ReadAsync(item.AccountScope, item.LogicalId);

                Assert.Equal(1, result.DurableCount);
                Assert.Equal(1, adapter.Calls);
                Assert.Equal(TransportOutboxState.Durable, read.Item?.State);
            }
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    private static ClientRuntime CreateRuntime(
        InMemorySessionStore store,
        ITransportOutboxAdapter adapter,
        IClock clock) =>
        new(
            store,
            ClientFeatureFlags.Defaults with { PersistentTransportOutboxEnabled = true },
            clock,
            new StubSessionBackend(),
            transportOutboxAdapter: adapter);

    private static TransportOutboxPreparedItem Prepared(
        DateTimeOffset? expiresAt = null,
        byte logical = 0x22) =>
        TransportOutboxPreparedItem.Create(
            OutboxAccountScope.FromBytes(Bytes(TransportOutboxLimits.AccountScopeBytes, 0x11)),
            OutboxLogicalId.FromBytes(Bytes(TransportOutboxLimits.LogicalIdBytes, logical)),
            OutboxDedupMaterial.FromBytes(Bytes(TransportOutboxLimits.DedupMaterialBytes, 0x33)),
            Bytes(96, 0x44),
            Now,
            expiresAt ?? Now.AddDays(1),
            Now);

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

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

    private sealed class RecordingAdapter : ITransportOutboxAdapter
    {
        public int Calls { get; private set; }

        public byte[]? LastBundle { get; private set; }

        public byte[]? LastDedupMaterial { get; private set; }

        public Exception? Failure { get; set; }

        public bool AcceptedOnly { get; set; }

        public Action? BeforeReturn { get; set; }

        public Task<TransportOutboxAdapterReceipt> DispatchAsync(
            TransportOutboxDispatchRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            LastBundle = request.GetCiphertextBundleCopy();
            LastDedupMaterial = request.GetDedupMaterialCopy();
            if (Failure is not null)
            {
                return Task.FromException<TransportOutboxAdapterReceipt>(Failure);
            }

            BeforeReturn?.Invoke();

            return Task.FromResult(AcceptedOnly
                ? TransportOutboxAdapterReceipt.Accepted([0x51])
                : TransportOutboxAdapterReceipt.Durable([0x51], [0x52]));
        }
    }

    private sealed class TimeoutThenSuccessAdapter : ITransportOutboxAdapter
    {
        private int calls;
        private int completedCalls;

        public int Calls => Volatile.Read(ref calls);

        public int CompletedCalls => Volatile.Read(ref completedCalls);

        public TaskCompletionSource CancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<TransportOutboxAdapterReceipt> DispatchAsync(
            TransportOutboxDispatchRequest request,
            CancellationToken cancellationToken = default)
        {
            var call = Interlocked.Increment(ref calls);
            try
            {
                if (call == 1)
                {
                    try
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                    }
                    finally
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            CancellationObserved.TrySetResult();
                        }
                    }
                }

                return TransportOutboxAdapterReceipt.Durable([0x61], [0x62]);
            }
            finally
            {
                Interlocked.Increment(ref completedCalls);
            }
        }
    }

    private sealed class AlwaysWaitingAdapter : ITransportOutboxAdapter
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource CancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<TransportOutboxAdapterReceipt> DispatchAsync(
            TransportOutboxDispatchRequest request,
            CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("The cooperative wait returned without cancellation.");
            }
            finally
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    CancellationObserved.TrySetResult();
                }
            }
        }
    }

    private sealed class ElapsedClock : IClock
    {
        private readonly DateTimeOffset origin = DateTimeOffset.UtcNow;
        private readonly Stopwatch stopwatch = Stopwatch.StartNew();

        public DateTimeOffset UtcNow => origin.Add(stopwatch.Elapsed);
    }

    private sealed class ApplyResultRepository(
        ITransportOutboxRepository inner,
        Func<TransportOutboxTransition, bool> returnCorrupt) : ITransportOutboxRepository
    {
        public Task<TransportOutboxCommitResult> PrepareTransportOutboxAsync(
            TransportOutboxPreparedItem item,
            CancellationToken cancellationToken = default) =>
            inner.PrepareTransportOutboxAsync(item, cancellationToken);

        public Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(
            OutboxAccountScope accountScope,
            OutboxLogicalId logicalId,
            CancellationToken cancellationToken = default) =>
            inner.ReadTransportOutboxAsync(accountScope, logicalId, cancellationToken);

        public Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(
            OutboxAccountScope accountScope,
            TransportOutboxTransition transition,
            CancellationToken cancellationToken = default) =>
            returnCorrupt(transition)
                ? Task.FromResult(TransportOutboxCommitResult.Corrupt)
                : inner.ApplyTransportOutboxTransitionAsync(accountScope, transition, cancellationToken);

        public Task<IReadOnlyList<TransportOutboxItemSnapshot>> ListReadyTransportOutboxAsync(
            OutboxAccountScope accountScope,
            DateTimeOffset now,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListReadyTransportOutboxAsync(accountScope, now, limit, cancellationToken);

        public Task<int> ExpireDueTransportOutboxAsync(
            OutboxAccountScope accountScope,
            DateTimeOffset now,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ExpireDueTransportOutboxAsync(accountScope, now, limit, cancellationToken);

        public Task PurgeTransportOutboxScopeAsync(
            OutboxAccountScope accountScope,
            CancellationToken cancellationToken = default) =>
            inner.PurgeTransportOutboxScopeAsync(accountScope, cancellationToken);
    }
}
