using System.Net;
using System.Net.Http.Headers;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class HttpServiceRequestTransportTests
{
    [Fact]
    public async Task PostAsync_UsesExactAllowedEndpointAndReturnsOwnedBoundedBody()
    {
        HttpRequestMessage? observed = null;
        using var transport = Transport(async (request, cancellationToken) =>
        {
            observed = request;
            Assert.Equal("payload"u8.ToArray(),
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            return Json("response"u8.ToArray());
        });

        using var response = await transport.PostAsync("/api/request", "payload"u8.ToArray());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("response"u8.ToArray(), response.Body.ToArray());
        Assert.Equal("https://service.example/api/request", observed!.RequestUri!.AbsoluteUri);
        Assert.Equal("application/json", observed.Content!.Headers.ContentType!.MediaType);
        Assert.Equal("utf-8", observed.Content.Headers.ContentType.CharSet);
    }

    [Fact]
    public async Task UnknownPathAndOversizeRequestRejectBeforeNetwork()
    {
        var calls = 0;
        using var transport = Transport((_, _) =>
        {
            calls++;
            return Task.FromResult(Json([1]));
        });

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await transport.PostAsync("/api/other", new byte[] { 1 }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await transport.PostAsync("/api/request", new byte[1025]));
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task ChangedEndpointWrongMediaAndOversizeResponseFailClosed()
    {
        using var changed = Transport((request, _) =>
        {
            var response = Json([1]);
            response.RequestMessage = new HttpRequestMessage(
                request.Method, "https://other.example/api/request");
            return Task.FromResult(response);
        });
        var endpointError = await Assert.ThrowsAsync<HttpServiceRequestTransportException>(async () =>
            await changed.PostAsync("/api/request", new byte[] { 1 }));
        Assert.Equal(HttpServiceRequestTransportError.EndpointChanged, endpointError.Error);

        using var wrongMedia = Transport((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([1])
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("text/plain") }
                }
            }));
        var mediaError = await Assert.ThrowsAsync<HttpServiceRequestTransportException>(async () =>
            await wrongMedia.PostAsync("/api/request", new byte[] { 1 }));
        Assert.Equal(HttpServiceRequestTransportError.UnexpectedMediaType, mediaError.Error);

        using var oversize = Transport((_, _) => Task.FromResult(Json(new byte[4097])));
        var sizeError = await Assert.ThrowsAsync<HttpServiceRequestTransportException>(async () =>
            await oversize.PostAsync("/api/request", new byte[] { 1 }));
        Assert.Equal(HttpServiceRequestTransportError.ResponseTooLarge, sizeError.Error);
    }

    [Fact]
    public async Task NonSuccessDoesNotReadBodyAndDisposedTransportRejectsUse()
    {
        var content = new TrackingContent();
        var transport = Transport((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = content
            }));

        using var response = await transport.PostAsync("/api/request", new byte[] { 1 });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.False(content.WasSerialized);

        transport.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await transport.PostAsync("/api/request", new byte[] { 1 }));
    }

    private static HttpServiceRequestTransport Transport(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) =>
        new(
            new HttpClient(new Handler(callback)),
            new HttpServiceRequestTransportOptions(
                "https://service.example/",
                ["/api/request"],
                "application/json",
                "application/json",
                1024,
                4096,
                TimeSpan.FromSeconds(5),
                RequestCharset: "utf-8",
                ResponseCharset: "utf-8"),
            HttpServiceEndpointPolicy.Production);

    private static HttpResponseMessage Json(byte[] body) =>
        new(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(body)
            {
                Headers =
                {
                    ContentType = new MediaTypeHeaderValue("application/json")
                    {
                        CharSet = "utf-8"
                    }
                }
            }
        };

    private sealed class Handler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback)
        : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = await callback(request, cancellationToken);
            response.RequestMessage ??= request;
            return response;
        }
    }

    private sealed class TrackingContent : HttpContent
    {
        internal bool WasSerialized { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            WasSerialized = true;
            return Task.CompletedTask;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
