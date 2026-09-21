using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed class ContactPublicationAuthorityClientTests
{
    [Fact]
    public void TransportOptions_AreExactAndBounded()
    {
        var options = ContactPublicationAuthorityClient.CreateTransportOptions(
            "https://registry.example/");

        Assert.Equal("https://registry.example/", options.BaseUrl);
        Assert.Equal([ContactPublicationAuthorityClient.EndpointPath], options.AllowedPostPaths);
        Assert.Equal(ContactPublicationAuthorityWireCodec.RequestMediaType,
            options.RequestMediaType);
        Assert.Equal(ContactPublicationAuthorityWireCodec.ResponseMediaType,
            options.ResponseMediaType);
        Assert.Equal(ContactPublicationAuthorityWireCodec.MaximumRequestBytes,
            options.MaximumRequestBytes);
        Assert.Equal(ContactPublicationAuthorityWireCodec.MaximumResponseBytes,
            options.MaximumResponseBytes);
        Assert.Equal(TimeSpan.FromSeconds(30), options.RequestTimeout);
    }

    [Fact]
    public void TransportOptions_RejectBlankOriginAndUnboundedTimeout()
    {
        Assert.Throws<ArgumentException>(() =>
            ContactPublicationAuthorityClient.CreateTransportOptions(" "));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ContactPublicationAuthorityClient.CreateTransportOptions(
                "https://registry.example", TimeSpan.FromSeconds(31)));
    }
}
