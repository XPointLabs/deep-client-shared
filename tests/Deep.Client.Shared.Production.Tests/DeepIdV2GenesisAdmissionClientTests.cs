using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2GenesisAdmissionClientTests
{
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
}
