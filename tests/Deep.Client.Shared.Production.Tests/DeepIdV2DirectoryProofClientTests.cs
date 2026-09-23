using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2DirectoryProofClientTests
{
    [Fact]
    public void TransportOptionsAreV2OnlyBoundedAndSingleEndpoint()
    {
        var options = DeepIdV2DirectoryProofClient.CreateTransportOptions(
            "https://registry.example/");

        Assert.Equal("https://registry.example/", options.BaseUrl);
        Assert.Equal([DeepIdV2DirectoryProofClient.EndpointPath],
            options.AllowedPostPaths);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestMediaType,
            options.RequestMediaType);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.ResponseMediaType,
            options.ResponseMediaType);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestLength,
            options.MaximumRequestBytes);
        Assert.Equal(DeepIdV2DirectoryProofWireCodec.MaximumResponseLength,
            options.MaximumResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Null(options.RequestCharset);
        Assert.Null(options.ResponseCharset);
    }

    [Fact]
    public void TransportOptionsRejectUnboundedTimeoutAndMissingEndpoint()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepIdV2DirectoryProofClient.CreateTransportOptions(
                "https://registry.example/", TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectoryProofClient.CreateTransportOptions(" "));
    }

    [Fact]
    public void ProofClientRequiresProtectedFloorStoreAtConstruction()
    {
        using var transport = new HttpServiceRequestTransport(
            new HttpClient(),
            DeepIdV2DirectoryProofClient.CreateTransportOptions(
                "https://registry.example/"),
            HttpServiceEndpointPolicy.Production);
        Assert.Throws<ArgumentNullException>(() =>
            new DeepIdV2DirectoryProofClient(transport, new FixedClock(),
                new DenyingVerifier(), null!));
    }

    private sealed class FixedClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new OnionMonotonicReading(
                Enumerable.Repeat((byte)0x41, 16).ToArray(), 5));
    }

    private sealed class DenyingVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }
}
