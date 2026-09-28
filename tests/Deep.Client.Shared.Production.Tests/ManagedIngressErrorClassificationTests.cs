using System.Net;
using System.Net.Http.Headers;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.ManagedIngress;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ManagedIngressErrorClassificationTests
{
    [Theory]
    [InlineData(HttpStatusCode.BadRequest, ManagedIngressErrorClass.MalformedFrame, false, 0)]
    [InlineData(HttpStatusCode.MisdirectedRequest, ManagedIngressErrorClass.WrongOrigin, true, 0)]
    [InlineData(HttpStatusCode.ServiceUnavailable, ManagedIngressErrorClass.Unavailable, true, 1)]
    public async Task CanonicalRejectionReportsOnlyVerifiedClosedErrorClass(HttpStatusCode status,
        ManagedIngressErrorClass error, bool retryable, int retryAfter)
    {
        using var ingress = Runtime(status, error, ManagedIngressOutcomeCertainty.BeforeForward, retryable, retryAfter);
        var failure = await Assert.ThrowsAsync<PrivacyIngressRejectedBeforeForwardException>(() => ingress.ForwardAsync(new byte[128], default));
        Assert.Equal(retryable, failure.Retryable);
        Assert.Equal($"Privacy ingress rejected the request before forwarding ({error}).", failure.Message);
        Assert.DoesNotContain("entry.example", failure.Message);
    }

    [Fact]
    public async Task UnknownAfterForwardIsNeverClassifiedAsDefiniteRejection()
    {
        using var ingress = Runtime(HttpStatusCode.GatewayTimeout, ManagedIngressErrorClass.UpstreamOutcomeUnknown,
            ManagedIngressOutcomeCertainty.UnknownAfterForward, true, 0);
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => ingress.ForwardAsync(new byte[128], default));
    }

    private static PrivacyManagedIngressHttpTransport Runtime(HttpStatusCode status, ManagedIngressErrorClass error,
        ManagedIngressOutcomeCertainty certainty, bool retryable, int retryAfter) => new(new HttpClient(
            new Handler(status, ManagedIngressErrorCodec.Encode(new(error, certainty, retryable, retryAfter)), retryAfter))
        { BaseAddress = new Uri("https://entry.example/") });

    private sealed class Handler(HttpStatusCode status, byte[] body, int retryAfter) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal(HttpVersion.Version20, request.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionExact, request.VersionPolicy);
            var response = new HttpResponseMessage(status) { RequestMessage = request, Version = HttpVersion.Version20, Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(ManagedIngressH2Contract.ErrorMediaType);
            response.Headers.CacheControl = new() { NoStore = true };
            if (retryAfter > 0) response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(retryAfter));
            return Task.FromResult(response);
        }
    }
}
