using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Client.Shared.Persistence;
using System.Net;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2GenesisAdmissionClientTests
{
    [Fact]
    public void UnavailableAdmissionHasOnlyClosedBoundedSchedulingMetadata()
    {
        var error = new DeepIdV2GenesisAdmissionUnavailableException(HttpStatusCode.ServiceUnavailable, TimeSpan.FromSeconds(10));
        Assert.IsAssignableFrom<IOException>(error);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, error.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(10), error.RetryAfter);
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2GenesisAdmissionUnavailableException(HttpStatusCode.OK, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2GenesisAdmissionUnavailableException(HttpStatusCode.Forbidden, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2GenesisAdmissionUnavailableException(HttpStatusCode.TooManyRequests, TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DeepIdV2GenesisAdmissionUnavailableException(HttpStatusCode.TooManyRequests, TimeSpan.FromMinutes(6)));
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests, 10, 10)]
    [InlineData(HttpStatusCode.ServiceUnavailable, 600, 300)]
    public async Task GenuineAccountAdmissionPreservesUnavailableStatusWithoutRetryOrReceipt(
        HttpStatusCode status, int retrySeconds, int expectedSeconds)
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-did2-admission-status-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var account = new DeepIdV2AccountService(new InMemoryDeepSecureStorage(), directory,
                Enumerable.Repeat((byte)0x11, 16).ToArray(), 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await account.CreateAsync("Admission status QA");
            var exact = await account.PrepareGenesisAdmissionAsync();
            var handler = new UnavailableAdmissionHandler(status, retrySeconds);
            using var transport = new HttpServiceRequestTransport(new HttpClient(handler),
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions("https://registry.example/"), HttpServiceEndpointPolicy.Production);
            using var client = new DeepIdV2GenesisAdmissionClient(transport);
            var error = await Assert.ThrowsAsync<DeepIdV2GenesisAdmissionUnavailableException>(async () => await client.AdmitAsync(exact));
            Assert.Equal(status, error.StatusCode);
            Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), error.RetryAfter);
            Assert.Equal(1, handler.Calls);
            Assert.DoesNotContain("private", error.Message);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void TransportIsBoundedToOnlyTheV2AdmissionEndpoint()
    {
        var options = DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
            "https://registry.example/");

        Assert.Equal([DeepIdV2GenesisAdmissionClient.EndpointPath],
            options.AllowedPostPaths);
        Assert.Equal(DeepIdV2GenesisAdmissionWireCodec.RequestMediaType,
            options.RequestMediaType);
        Assert.Equal(DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType,
            options.ResponseMediaType);
        Assert.Equal(DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength,
            options.MaximumRequestBytes);
        Assert.Equal(DeepIdV2GenesisAdmissionWireCodec.MaximumResponseLength,
            options.MaximumResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Null(options.RequestCharset);
        Assert.Null(options.ResponseCharset);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                "https://registry.example/", TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2GenesisAdmissionClient.CreateTransportOptions(" "));
    }

    [Fact]
    public async Task InvalidEnvelopeFailsBeforeAnyNetworkExchange()
    {
        using var transport = new HttpServiceRequestTransport(
            new HttpClient(new RejectEveryRequestHandler()),
            DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                "https://registry.example/"),
            HttpServiceEndpointPolicy.Production);
        using var client = new DeepIdV2GenesisAdmissionClient(transport);

        await Assert.ThrowsAsync<FormatException>(async () =>
            await client.AdmitAsync("DGA1"u8.ToArray()));
    }

    private sealed class RejectEveryRequestHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "Malformed DID2 admission must not reach the network.");
    }

    private sealed class UnavailableAdmissionHandler(HttpStatusCode status, int retrySeconds) : HttpMessageHandler
    {
        internal int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            Assert.Equal(DeepIdV2GenesisAdmissionClient.EndpointPath, request.RequestUri!.AbsolutePath);
            var response = new HttpResponseMessage(status)
            { RequestMessage = request, Content = new StringContent("private endpoint, account and payload") };
            response.Headers.RetryAfter = new(TimeSpan.FromSeconds(retrySeconds));
            return Task.FromResult(response);
        }
    }

    private sealed class FrozenClock(DateTimeOffset now) : IClock
    { public DateTimeOffset UtcNow => now; }
}
