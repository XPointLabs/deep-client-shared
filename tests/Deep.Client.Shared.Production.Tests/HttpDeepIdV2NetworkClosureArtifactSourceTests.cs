using System.Net;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

// Raw transport shape tests; authenticated acceptance is covered by the native
// DID2/SQLCipher fixture in DeepIdV2ContactPathAuthoritySourceTests.
public sealed class HttpDeepIdV2NetworkClosureArtifactSourceTests
{
    private static readonly byte[] Network = Enumerable.Repeat((byte)0x34, 16).ToArray();

    [Fact]
    public void FactoryRejectsUntrustedOriginAndUnboundedTimeout()
    {
        var factory = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production);
        using var source = factory.CreateDeepIdV2NetworkClosureArtifactSource("https://registry.example/");
        Assert.Throws<ArgumentException>(() => factory.CreateDeepIdV2NetworkClosureArtifactSource("http://registry.example/"));
        Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateDeepIdV2NetworkClosureArtifactSource(
            "https://registry.example/", requestTimeout: TimeSpan.FromSeconds(31)));
        var options = HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://registry.example/");
        Assert.Equal([HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath], options.AllowedPostPaths);
        Assert.Equal(28, options.MaximumRequestBytes);
        Assert.Equal(XPointNetworkClosureWireCodec.MaximumResponseLength, options.MaximumResponseBytes);
        Assert.Null(options.RequestCharset);
        Assert.Null(options.ResponseCharset);
    }

    [Fact]
    public async Task FetchHasOnlyPublicScopeAndOwnsResponseAfterTransportDisposal()
    {
        using var handler = new DistributionHandler();
        using var source = Create(handler);
        var raw = await source.FetchCurrentAsync(Network, null);
        source.Dispose();
        Assert.Equal(1, handler.Requests);
        Assert.Equal("XNA1"u8.ToArray(), raw.ExactXna1AuthorityChain[0].Span[..4].ToArray());
        Assert.Equal("PMA2"u8.ToArray(), raw.ExactOrderedPma2Chain[0].Span[..4].ToArray());
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await source.FetchCurrentAsync(Network, null));
    }

    [Fact]
    public async Task WrongScopeFailsBeforeReturningRawClosure()
    {
        using var handler = new DistributionHandler { WrongScope = true };
        using var source = Create(handler);
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task MissingMailboxAuthorityRejectsInsteadOfReturningPartialClosure()
    {
        using var handler = new DistributionHandler { RetiredSevenChain = true };
        using var source = Create(handler);
        await Assert.ThrowsAsync<FormatException>(async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task UnavailableMediaAndCancellationDoNotReuseCachedAuthority()
    {
        using var handler = new DistributionHandler { Unavailable = true };
        using var source = Create(handler);
        await Assert.ThrowsAsync<Deep.Client.Shared.Services.AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException>(
            async () => await source.FetchCurrentAsync(Network, null));
        handler.Unavailable = false;
        handler.WrongMedia = true;
        await Assert.ThrowsAsync<HttpServiceRequestTransportException>(async () => await source.FetchCurrentAsync(Network, null));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await source.FetchCurrentAsync(Network, null, cancelled.Token));
        Assert.Equal(2, handler.Requests);
    }

    [Fact]
    public async Task ContendedPublicRead_RetriesSameScopeWithoutCachingAuthority()
    {
        using var handler = new DistributionHandler { RejectionsRemaining = 2 };
        using var source = Create(handler);
        _ = await source.FetchCurrentAsync(Network, null);
        Assert.Equal(3, handler.Requests);
        handler.WrongScope = true;
        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
            async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(4, handler.Requests);
    }

    [Fact]
    public async Task PersistentContention_StopsAfterEightPublicReads()
    {
        using var handler = new DistributionHandler { RejectionsRemaining = int.MaxValue };
        using var source = Create(handler);
        var error = await Assert.ThrowsAsync<Deep.Client.Shared.Services.AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException>(
            async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(HttpStatusCode.TooManyRequests, error.StatusCode);
        Assert.Equal(8, handler.Requests);
    }

    [Fact]
    public async Task RetryAfterBeyondOriginalBudget_RejectsWithoutExtraRequest()
    {
        using var handler = new DistributionHandler { RejectionsRemaining = 1, RetryAfterSeconds = 2 };
        using var source = Create(handler, TimeSpan.FromSeconds(1));
        var error = await Assert.ThrowsAsync<Deep.Client.Shared.Services.AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException>(
            async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(TimeSpan.FromSeconds(2), error.RetryAfter);
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task RetryAfterIsHonoredBeforeTheNextPublicRead()
    {
        using var handler = new DistributionHandler { RejectionsRemaining = 1, RetryAfterSeconds = 1 };
        using var source = Create(handler);
        _ = await source.FetchCurrentAsync(Network, null);
        Assert.Equal(2, handler.Requests);
        Assert.True(handler.RequestTimes[1] - handler.RequestTimes[0] >= TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task CancellationAfterRejectedRead_DoesNotRetry()
    {
        using var cancelled = new CancellationTokenSource();
        using var handler = new DistributionHandler { RejectionsRemaining = 1, AfterRejection = cancelled.Cancel };
        using var source = Create(handler);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await source.FetchCurrentAsync(Network, null, cancelled.Token));
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task RetryOwnsOriginalNetworkBeforeResponseCallbacks()
    {
        var callerScope = Network.ToArray();
        using var handler = new DistributionHandler { RejectionsRemaining = 1, AfterRejection = () => callerScope[0] ^= 1 };
        using var source = Create(handler);
        _ = await source.FetchCurrentAsync(callerScope, null);
        Assert.Equal(2, handler.Requests);
        Assert.NotEqual(Network, callerScope);
    }

    [Fact]
    public async Task OriginalDeadline_StillReportsTimeoutNotCallerCancellation()
    {
        using var handler = new DistributionHandler { BlockResponse = true };
        using var source = Create(handler, TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAsync<TimeoutException>(async () => await source.FetchCurrentAsync(Network, null));
        Assert.Equal(1, handler.Requests);
    }

    private static HttpDeepIdV2NetworkClosureArtifactSource Create(HttpMessageHandler handler, TimeSpan timeout = default) =>
        new(new HttpServiceRequestTransport(new HttpClient(handler, disposeHandler: false),
            HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://registry.example/", timeout),
            HttpServiceEndpointPolicy.Production));

    private sealed class DistributionHandler : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        internal bool WrongScope { get; set; }
        internal bool Unavailable { get; set; }
        internal bool WrongMedia { get; set; }
        internal bool RetiredSevenChain { get; set; }
        internal int RejectionsRemaining { get; set; }
        internal int RetryAfterSeconds { get; set; }
        internal Action? AfterRejection { get; set; }
        internal bool BlockResponse { get; set; }
        internal List<TimeSpan> RequestTimes { get; } = [];
        private readonly long started = System.Diagnostics.Stopwatch.GetTimestamp();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests++;
            RequestTimes.Add(System.Diagnostics.Stopwatch.GetElapsedTime(started));
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath, request.RequestUri!.AbsolutePath);
            Assert.Equal(XPointNetworkClosureWireCodec.RequestMediaType, request.Content!.Headers.ContentType!.MediaType);
            Assert.Equal(Network, XPointNetworkClosureWireCodec.DecodeRequest(await request.Content.ReadAsByteArrayAsync(ct)));
            if (BlockResponse) await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            if (Unavailable) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
            if (RejectionsRemaining > 0)
            {
                RejectionsRemaining--;
                var rejected = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { RequestMessage = request };
                if (RetryAfterSeconds > 0) rejected.Headers.RetryAfter = new(TimeSpan.FromSeconds(RetryAfterSeconds));
                AfterRejection?.Invoke();
                return rejected;
            }
            var scope = Network.ToArray();
            if (WrongScope) scope[0] ^= 1;
            var chains = new[] { "XNA1", "DTS1", "XVP1", "XNV1", "XNH1", "XND1", "PMT2", "PMA2" }
                .Select(magic => { var record = new byte[12]; System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(record, 0);
                    return (IReadOnlyList<ReadOnlyMemory<byte>>)new ReadOnlyMemory<byte>[] { record }; }).ToArray();
            var bytes = XPointNetworkClosureWireCodec.EncodeResponse(scope,
                chains[0], chains[1], chains[2], chains[3], chains[4], chains[5], chains[6], chains[7]);
            if (RetiredSevenChain)
            {
                bytes = bytes[..^20];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 7);
            }
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { RequestMessage = request, Content = new ByteArrayContent(bytes) };
            response.Content.Headers.ContentType = new(WrongMedia ? "application/octet-stream" : XPointNetworkClosureWireCodec.ResponseMediaType);
            return response;
        }
    }
}
