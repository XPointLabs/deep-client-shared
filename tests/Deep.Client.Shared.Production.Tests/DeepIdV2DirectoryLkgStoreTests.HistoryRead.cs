using System.Net;
using System.Net.Http.Headers;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2DirectoryLkgStoreTests
{
    [Fact]
    public async Task HistoryRead_One503RepeatPreservesExactRequestAndCannotAuthorizeHistory()
    {
        var request = await NewHistoryReadRequestAsync(); var original = request.ToArray();
        var handler = new HistoryRetryHandler(call =>
        {
            if (call == 1) { request[12] ^= 1; return HistoryReply(HttpStatusCode.ServiceUnavailable, 1); }
            return HistoryReply(call == 2 ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, 1);
        });
        using var transport = HistoryRetryTransport(handler);
        var reads = new DirectoryHistoryReadScope(transport);
        using var response = await reads.ReadAsync(request, default);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, handler.Calls);
        Assert.All(handler.Requests, sent => Assert.Equal(original, sent));
        // A successful HTTP retry is still untrusted bytes, not a history capability.
        Assert.Throws<FormatException>(() => DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(response.Body.Span, original));
        using var laterPage = await reads.ReadAsync(original, default);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, laterPage.StatusCode);
        Assert.Equal(3, handler.Calls); // one repeat in the whole catchup, not per page
    }

    [Theory]
    [InlineData(429, 0)]
    [InlineData(400, 0)]
    [InlineData(503, -1)]
    [InlineData(503, 0)]
    [InlineData(503, 6)]
    public async Task HistoryRead_DoesNotRepeatRateLimitRejectOrMissingUnboundedHint(int status, int seconds)
    {
        var request = await NewHistoryReadRequestAsync();
        var handler = new HistoryRetryHandler(_ => HistoryReply((HttpStatusCode)status, seconds));
        using var transport = HistoryRetryTransport(handler);
        using var response = await new DirectoryHistoryReadScope(transport).ReadAsync(request, default);
        Assert.Equal((HttpStatusCode)status, response.StatusCode); Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task HistoryRead_Repeated503RemainsFailureWithoutLoop()
    {
        var request = await NewHistoryReadRequestAsync();
        var handler = new HistoryRetryHandler(_ => HistoryReply(HttpStatusCode.ServiceUnavailable, 1));
        using var transport = HistoryRetryTransport(handler);
        using var response = await new DirectoryHistoryReadScope(transport).ReadAsync(request, default);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task HistoryRead_CancellationNeverCreatesAnotherAttempt()
    {
        var request = await NewHistoryReadRequestAsync(); using var cancel = new CancellationTokenSource();
        var handler = new HistoryRetryHandler(_ =>
        { cancel.CancelAfter(50); return HistoryReply(HttpStatusCode.ServiceUnavailable, 1); });
        using var transport = HistoryRetryTransport(handler);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await new DirectoryHistoryReadScope(transport).ReadAsync(request, cancel.Token));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task HistoryRead_MalformedShapeRejectsBeforeTransport()
    {
        var handler = new HistoryRetryHandler(_ => throw new InvalidOperationException());
        using var transport = HistoryRetryTransport(handler);
        await Assert.ThrowsAsync<FormatException>(async () =>
            await new DirectoryHistoryReadScope(transport).ReadAsync(new byte[1], default));
        Assert.Equal(0, handler.Calls);
    }

    private static async Task<byte[]> NewHistoryReadRequestAsync()
    {
        Assert.True(SupportedProvider());
        var signed = await SignedV2Genesis.CreateAsync(Bytes(16, 0x20));
        var floor = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(signed.Verified, signed.ExactHead, signed.HeadHash);
        return DeepIdV2DirectoryHistoryWireCodec.EncodeRequest(floor);
    }

    private static HttpServiceRequestTransport HistoryRetryTransport(HttpMessageHandler handler) => new(
        new HttpClient(handler), DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://registry.example/"),
        HttpServiceEndpointPolicy.Production);

    private static HttpResponseMessage HistoryReply(HttpStatusCode status, int seconds)
    {
        var response = new HttpResponseMessage(status) { Content = new ByteArrayContent([0x42]) };
        response.Content.Headers.ContentType = new(DeepIdV2DirectoryHistoryWireCodec.ResponseMediaType);
        if (seconds >= 0) response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));
        return response;
    }

    private sealed class HistoryRetryHandler(Func<int, HttpResponseMessage> reply) : HttpMessageHandler
    {
        internal int Calls; internal readonly List<byte[]> Requests = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add((await request.Content!.ReadAsByteArrayAsync(ct)).ToArray());
            var response = reply(++Calls); response.RequestMessage = request; return response;
        }
    }
}
