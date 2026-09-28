using System.Net;
using System.Net.Http.Headers;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class HttpServiceRequestTransportTests
{
    [Theory]
    [InlineData("https://registry.example/", 2, 0)]
    [InlineData("http://127.0.0.1:38081/", 1, 1)]
    public async Task BinaryRequestsUseExactProtocolWithoutNegotiationFallback(string origin, int major, int minor)
    {
        var calls = 0;
        using var handler = new Handler(request =>
        {
            calls++;
            Assert.Equal(new Version(major, minor), request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            return Reply(request, new ByteArrayContent([3, 4]));
        });
        using var transport = Transport(handler, origin);
        using var first = await transport.PostAsync("/proof", new byte[] { 1, 2 });
        using var second = await transport.PostAsync("/proof", new byte[] { 5, 6 });
        Assert.Equal(new byte[] { 3, 4 }, first.Body.ToArray());
        Assert.Equal(new byte[] { 3, 4 }, second.Body.ToArray());
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task FailedH2NegotiationDoesNotDispatchAnH1Retry()
    {
        var calls = 0;
        using var handler = new Handler(request =>
        {
            calls++;
            Assert.Equal(HttpVersion.Version20, request.Version);
            throw new HttpRequestException(HttpRequestError.VersionNegotiationError, "Test negotiation failure.");
        });
        using var transport = Transport(handler, "https://registry.example/");
        var failure = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.PostAsync("/proof", new byte[] { 1, 2 }));
        Assert.Equal(HttpRequestError.VersionNegotiationError, failure.HttpRequestError);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task SuccessfulHeadersWithStalledBodyStillExpireWithoutRetryOrPartialSuccess()
    {
        var calls = 0;
        using var handler = new Handler(request =>
        {
            calls++;
            var content = new StreamContent(new StalledBody());
            content.Headers.ContentLength = 4;
            return Reply(request, content);
        });
        using var transport = Transport(handler, "https://registry.example/", TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAsync<TimeoutException>(async () =>
            await transport.PostAsync("/proof", new byte[] { 1, 2 }));
        Assert.Equal(1, calls);
    }

    private static HttpServiceRequestTransport Transport(HttpMessageHandler handler, string origin, TimeSpan timeout = default) =>
        new(new HttpClient(handler, disposeHandler: false),
            new(origin, ["/proof"], "application/octet-stream", "application/octet-stream", 16, 16,
                timeout == default ? TimeSpan.FromSeconds(1) : timeout), HttpServiceEndpointPolicy.Production);

    private static HttpResponseMessage Reply(HttpRequestMessage request, HttpContent content)
    {
        content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        return new(HttpStatusCode.OK) { RequestMessage = request, Version = request.Version, Content = content };
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> reply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(reply(request));
    }

    private sealed class StalledBody : Stream
    {
        private bool readPartial;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!readPartial)
            {
                readPartial = true;
                buffer.Span[0] = 3;
                buffer.Span[1] = 4;
                return 2;
            }
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
