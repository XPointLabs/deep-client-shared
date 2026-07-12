using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class RouterCancellationTests
{
    private const string TargetKey = "05target";

    private static readonly string[] RouterIds =
    [
        new('1', 64),
        new('2', 64),
        new('3', 64)
    ];

    [Fact]
    public async Task RefreshRouteAsync_CallerCancellation_StopsFailoverAndPropagatesCancellation()
    {
        var requestStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var requestCount = 0;
        using var httpClient = new HttpClient(new AsyncHandler(async (_, cancellationToken) =>
        {
            Interlocked.Increment(ref requestCount);
            requestStarted.TrySetResult(true);
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            return new HttpResponseMessage();
        }));
        var client = CreateClient(httpClient);
        using var cancellation = new CancellationTokenSource();

        var refresh = client.RefreshRouteAsync(TargetKey, cancellation.Token);
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh);
        Assert.Equal(1, Volatile.Read(ref requestCount));
    }

    [Fact]
    public async Task RefreshRouteAsync_OperationCanceledException_StopsFailoverWithoutWrapping()
    {
        var requestCount = 0;
        using var httpClient = new HttpClient(new AsyncHandler((_, _) =>
        {
            Interlocked.Increment(ref requestCount);
            return Task.FromException<HttpResponseMessage>(new OperationCanceledException("request canceled"));
        }));
        var client = CreateClient(httpClient);

        var exception = await Assert.ThrowsAsync<OperationCanceledException>(
            () => client.RefreshRouteAsync(TargetKey));

        Assert.Equal("request canceled", exception.Message);
        Assert.Equal(1, Volatile.Read(ref requestCount));
    }

    [Fact]
    public async Task RefreshRouteAsync_InternalNodeTimeout_ContinuesFailover()
    {
        var requestCount = 0;
        using var httpClient = new HttpClient(new AsyncHandler((_, _) =>
        {
            Interlocked.Increment(ref requestCount);
            return Task.FromException<HttpResponseMessage>(
                new TaskCanceledException("node timed out", new TimeoutException()));
        }));
        var client = CreateClient(httpClient);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.RefreshRouteAsync(TargetKey));

        Assert.Equal("All configured XNodes failed.", exception.Message);
        Assert.IsType<TaskCanceledException>(exception.InnerException);
        Assert.Equal(RouterIds.Length, Volatile.Read(ref requestCount));
    }

    private static XNodeRpcClient CreateClient(HttpClient httpClient)
    {
        var routers = RouterIds
            .Select((routerId, index) => new PinnedRouterEndpoint($"http://router-{index}.local", routerId))
            .ToArray();
        return new XNodeRpcClient(
            httpClient,
            new XNodeRpcClientOptions(routers, TrustedRouterIds: RouterIds));
    }

    private sealed class AsyncHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;

        public AsyncHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return _handler(request, cancellationToken);
        }
    }
}
