using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ContactRouteAuthorityClientTests
{
    [Fact]
    public void TransportOptionsAreExactBoundedAndSingleEndpoint()
    {
        var options = ContactRouteAuthorityClient.CreateTransportOptions(
            "https://registry.example/");

        Assert.Equal("https://registry.example/", options.BaseUrl);
        Assert.Equal([ContactRouteAuthorityClient.EndpointPath], options.AllowedPostPaths);
        Assert.Equal(ContactRouteAuthorityWireCodec.RequestMediaType, options.RequestMediaType);
        Assert.Equal(ContactRouteAuthorityWireCodec.ResponseMediaType, options.ResponseMediaType);
        Assert.Equal(ContactRouteAuthorityWireCodec.RequestBytes, options.MaximumRequestBytes);
        Assert.Equal(ContactRouteAuthorityWireCodec.MaximumResponseBytes,
            options.MaximumResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
        Assert.Null(options.RequestCharset);
        Assert.Null(options.ResponseCharset);
    }

    [Fact]
    public void TransportOptionsRejectUnboundedTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ContactRouteAuthorityClient.CreateTransportOptions(
                "https://registry.example/", TimeSpan.FromSeconds(31)));
        Assert.Throws<ArgumentException>(() =>
            ContactRouteAuthorityClient.CreateTransportOptions(" "));
    }
}
