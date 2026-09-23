using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;

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
}
