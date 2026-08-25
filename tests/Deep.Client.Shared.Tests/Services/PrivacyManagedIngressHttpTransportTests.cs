using System.Net;
using System.Net.Http.Headers;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.ManagedIngress;

namespace Deep.Client.Shared.Tests.Services;

public sealed class PrivacyManagedIngressHttpTransportTests
{
    [Fact]
    public async Task CanonicalBeforeForwardError_IsDefinite()
    {
        using var ingress = Runtime(request => Error(
            request,
            HttpStatusCode.ServiceUnavailable,
            ManagedIngressErrorClass.Unavailable,
            ManagedIngressOutcomeCertainty.BeforeForward,
            retryable: true,
            retryAfter: 7));

        var exception = await Assert.ThrowsAsync<PrivacyIngressRejectedBeforeForwardException>(
            () => ingress.ForwardAsync(Frame(), CancellationToken.None));

        Assert.True(exception.Retryable);
    }

    [Fact]
    public async Task CanonicalUnknownAfterForwardError_IsSpecializedUnknown()
    {
        using var ingress = Runtime(request => Error(
            request,
            HttpStatusCode.GatewayTimeout,
            ManagedIngressErrorClass.UpstreamOutcomeUnknown,
            ManagedIngressOutcomeCertainty.UnknownAfterForward,
            retryable: true,
            retryAfter: 0));

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.ForwardAsync(Frame(), CancellationToken.None));
    }

    [Fact]
    public async Task CanonicalOpaqueSuccess_IsReturnedExactly()
    {
        var responseFrame = Enumerable.Repeat((byte)0x5a, 128).ToArray();
        using var ingress = Runtime(request => Response(
            request,
            HttpStatusCode.OK,
            ManagedIngressH2Contract.OpaqueMediaType,
            responseFrame));

        var actual = await ingress.ForwardAsync(Frame(), CancellationToken.None);

        Assert.Equal(responseFrame, actual.ToArray());
    }

    [Fact]
    public async Task DateHeaderOnSuccess_IsOutcomeUnknown()
    {
        using var ingress = Runtime(request =>
        {
            var response = Response(
                request,
                HttpStatusCode.OK,
                ManagedIngressH2Contract.OpaqueMediaType,
                Frame());
            response.Headers.Date = DateTimeOffset.UtcNow;
            return response;
        });

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.ForwardAsync(Frame(), CancellationToken.None));
    }

    [Fact]
    public async Task NameResolutionFailure_IsDefinitelyBeforeForward()
    {
        using var ingress = Runtime(_ => throw new HttpRequestException(
            HttpRequestError.NameResolutionError,
            "unavailable",
            null));

        await Assert.ThrowsAsync<PrivacyIngressRejectedBeforeForwardException>(
            () => ingress.ForwardAsync(Frame(), CancellationToken.None));
    }

    [Fact]
    public async Task ConnectionReset_IsOutcomeUnknown()
    {
        using var ingress = Runtime(_ => throw new HttpRequestException(
            HttpRequestError.ConnectionError,
            "reset",
            null));

        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(
            () => ingress.ForwardAsync(Frame(), CancellationToken.None));
    }

    private static PrivacyManagedIngressHttpTransport Runtime(
        Func<HttpRequestMessage, HttpResponseMessage> response)
    {
        var client = new HttpClient(new Handler(response))
        {
            BaseAddress = new Uri("https://entry.example/")
        };
        return new PrivacyManagedIngressHttpTransport(client);
    }

    private static HttpResponseMessage Error(
        HttpRequestMessage request,
        HttpStatusCode status,
        ManagedIngressErrorClass errorClass,
        ManagedIngressOutcomeCertainty certainty,
        bool retryable,
        int retryAfter)
    {
        var frame = ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
            errorClass,
            certainty,
            retryable,
            retryAfter));
        var response = Response(
            request,
            status,
            ManagedIngressH2Contract.ErrorMediaType,
            frame);
        if (retryAfter != 0)
        {
            response.Headers.RetryAfter = new RetryConditionHeaderValue(
                TimeSpan.FromSeconds(retryAfter));
        }

        return response;
    }

    private static HttpResponseMessage Response(
        HttpRequestMessage request,
        HttpStatusCode status,
        string mediaType,
        byte[] body)
    {
        var response = new HttpResponseMessage(status)
        {
            Version = HttpVersion.Version20,
            RequestMessage = request,
            Content = new ByteArrayContent(body)
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        response.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
        return response;
    }

    private static byte[] Frame() => Enumerable.Repeat((byte)0x51, 64).ToArray();

    private sealed class Handler(
        Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(HttpVersion.Version20, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            Assert.Equal(ManagedIngressH2Contract.FramePath, request.RequestUri!.AbsolutePath);
            Assert.Equal(
                ManagedIngressH2Contract.OpaqueMediaType,
                request.Content!.Headers.ContentType!.MediaType);
            return Task.FromResult(response(request));
        }
    }
}
