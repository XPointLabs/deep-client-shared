using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV2;
using Xunit.Sdk;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ContactPathTestSchedulingTests
{
    [Fact]
    public async Task IndependentMethodsOverlapWithoutExceedingTwoWorkers()
    {
        using var release = new ManualResetEventSlim();
        var bothStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var active = 0;
        var started = 0;
        var peak = 0;
        var execution = ContactPathTestScheduling.RunAsync(Enumerable.Range(0, 6), method =>
        {
            var current = Interlocked.Increment(ref active);
            InterlockedExtensions.UpdateMaximum(ref peak, current);
            if (Interlocked.Increment(ref started) == 2) bothStarted.SetResult();
            try
            {
                Assert.True(release.Wait(TimeSpan.FromSeconds(10)));
                return Task.FromResult(new RunSummary
                {
                    Total = 1, Failed = method == 2 ? 1 : 0, Time = method
                });
            }
            finally { Interlocked.Decrement(ref active); }
        }, 2);

        try { await bothStarted.Task.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { release.Set(); }
        var results = await execution;
        Assert.Equal(2, peak);
        Assert.Equal(6, started);
        Assert.Equal(0, active);
        Assert.Equal(Enumerable.Range(0, 6).Select(value => (decimal)value),
            results.Select(result => result.Time));
        Assert.Equal(6, results.Sum(result => result.Total));
        Assert.Equal(1, results.Sum(result => result.Failed));
    }

    [Fact]
    public async Task CrashHooksStayInsideTheirOwnAsyncMethodContext()
    {
        var outerCalls = 0;
        using var outer = Did2CompactionTestHooks.Push(_ => Interlocked.Increment(ref outerCalls));
        var results = await ContactPathTestScheduling.RunAsync(Enumerable.Range(0, 8), async method =>
        {
            var hits = 0;
            using var hook = Did2CompactionTestHooks.Push(_ => hits++);
            await Task.Yield();
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
            await Task.Yield();
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
            Assert.Equal(2, hits);
            return new RunSummary { Total = 1 };
        }, 2);
        Assert.Equal(8, results.Sum(result => result.Total));
        Assert.Equal(0, outerCalls);
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
        Assert.Equal(1, outerCalls);
    }

    [Fact]
    public async Task DeviceCrashHooksDoNotCrossConcurrentMethodContexts()
    {
        var bothInstalled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var installed = 0;
        var results = await ContactPathTestScheduling.RunAsync(Enumerable.Range(0, 2), async method =>
        {
            var hits = 0;
            using var hook = DeviceStateStoreTestHooks.Push(_ => hits++);
            if (Interlocked.Increment(ref installed) == 2) bothInstalled.TrySetResult();
            await bothInstalled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
            await Task.Yield();
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.AfterHeadWritten);
            Assert.Equal(2, hits);
            return new RunSummary { Total = 1 };
        }, 2);
        Assert.Equal(2, results.Sum(result => result.Total));
        DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
    }

    [Fact]
    public async Task DeviceCrashHooksRejectNestedInstallationWithoutLosingTheOwner()
    {
        var hits = 0;
        var hook = DeviceStateStoreTestHooks.Push(_ => hits++);
        try
        {
            Assert.Throws<InvalidOperationException>(() => DeviceStateStoreTestHooks.Push(_ => { }));
            await Task.Yield();
            DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
            Assert.Equal(1, hits);
        }
        finally { hook.Dispose(); }
        using var next = DeviceStateStoreTestHooks.Push(_ => hits++);
        hook.Dispose();
        DeviceStateStoreTestHooks.Hit(DeviceStateStoreFailpoint.BeforeCommit);
        Assert.Equal(2, hits);
    }

    [Fact]
    public async Task FaultsPropagateAfterEveryQueuedMethodFinishes()
    {
        var completed = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ContactPathTestScheduling.RunAsync(Enumerable.Range(0, 6), async method =>
            {
                await Task.Yield();
                Interlocked.Increment(ref completed);
                if (method == 2) throw new InvalidOperationException("Injected scheduler failure.");
                return new RunSummary { Total = 1 };
            }, 2));
        Assert.Equal(6, completed);
    }

    [Fact]
    public async Task InvalidMethodEnumerationDoesNotStartBackgroundWork()
    {
        var started = 0;
        static IEnumerable<int> BrokenMethods()
        {
            yield return 0;
            throw new InvalidOperationException("Injected discovery failure.");
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ContactPathTestScheduling.RunAsync(BrokenMethods(), method =>
            {
                Interlocked.Increment(ref started);
                return Task.FromResult(new RunSummary());
            }, 2));
        Assert.Equal(0, started);
    }

    [Fact]
    public async Task SerialModeDoesNotOverlapMethods()
    {
        var active = 0;
        var peak = 0;
        await ContactPathTestScheduling.RunAsync(Enumerable.Range(0, 6), async method =>
        {
            var current = Interlocked.Increment(ref active);
            InterlockedExtensions.UpdateMaximum(ref peak, current);
            try
            {
                await Task.Yield();
                return new RunSummary { Total = 1 };
            }
            finally { Interlocked.Decrement(ref active); }
        }, 1);
        Assert.Equal(1, peak);
        Assert.Equal(0, active);
    }

    [Theory]
    [InlineData(false, 12, 2)]
    [InlineData(false, 0, 2)]
    [InlineData(false, -1, 2)]
    [InlineData(false, 1, 1)]
    [InlineData(true, 12, 1)]
    public void RunnerSerialSettingsAreHonored(bool disabled, int maximumThreads, int expected) =>
        Assert.Equal(expected, ContactPathTestScheduling.Parallelism(disabled, maximumThreads));

    [Fact]
    public void OnlyStatelessClassesAreEligibleForMethodConcurrency()
    {
        Assert.True(ContactPathTestScheduling.IsIsolated(typeof(DeepIdV2ContactPathAuthoritySourceTests)));
        Assert.False(ContactPathTestScheduling.IsIsolated(typeof(SharedState)));
        Assert.False(ContactPathTestScheduling.IsIsolated(typeof(SharedFixture)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task UnsupportedWorkerCountsReject(int workers) =>
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            ContactPathTestScheduling.RunAsync(Array.Empty<int>(),
                _ => Task.FromResult(new RunSummary()), workers));

    private sealed class SharedState
    {
        public int Value { get; set; }
    }

    private sealed class SharedFixture : IClassFixture<SharedState>;

    private static class InterlockedExtensions
    {
        internal static void UpdateMaximum(ref int target, int value)
        {
            var previous = Volatile.Read(ref target);
            while (previous < value)
            {
                var observed = Interlocked.CompareExchange(ref target, value, previous);
                if (observed == previous) return;
                previous = observed;
            }
        }
    }
}
