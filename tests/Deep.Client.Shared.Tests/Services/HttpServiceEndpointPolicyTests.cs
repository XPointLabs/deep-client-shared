using System.Reflection;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class HttpServiceEndpointPolicyTests
{
    [Fact]
    public void PhysicalFactory_ConstructsEverySurvivalHttpTransportForCanonicalLanOrigins()
    {
        var factory = new HttpServiceTransportFactory(
            HttpServiceEndpointPolicy.PhysicalE2eDevelopment);

        var avatar = factory.CreateAvatar(
            new HttpClient(),
            new HttpAvatarProfileTransportOptions("http://192.168.1.44:41821/"));
        var attachment = factory.CreateAttachment(
            new HttpClient(),
            new HttpAttachmentFileTransportOptions("http://192.168.1.44:41821/"));
        var push = factory.CreatePush(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("http://192.168.1.44:41822/"));
        var calls = factory.CreateCallSignaling(
            new HttpClient(),
            new HttpCallSignalingTransportOptions("http://192.168.1.44:41823/"));
        var session = factory.CreateSession(
            new HttpClient(),
            new HttpSessionTransportOptions("http://192.168.1.44:41820/"));
        var storage = factory.CreateStorage(
            new HttpClient(),
            new SessionStorageMessageTransportOptions(
                "http://192.168.1.44:41820/",
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));
        var groups = factory.CreateGroupSync(
            new HttpClient(),
            new SessionStorageGroupSyncTransportOptions("http://192.168.1.44:41820/"));

        Assert.NotNull(avatar);
        Assert.True(attachment.IsEnabled);
        Assert.True(push.IsEnabled);
        Assert.NotNull(calls);
        Assert.NotNull(session);
        Assert.False(storage.UsesOpaqueMetadata);
        Assert.NotNull(groups);
    }

    [Theory]
    [InlineData("http://service.local:41822/")]
    [InlineData("http://8.8.8.8:41822/")]
    [InlineData("http://0.0.0.0:41822/")]
    [InlineData("http://224.0.0.1:41822/")]
    [InlineData("http://192.168.001.044:41822/")]
    [InlineData("http://user:password@192.168.1.44:41822/")]
    [InlineData("http://192.168.1.44:41822/?mode=dev")]
    [InlineData("http://192.168.1.44:41822/#dev")]
    [InlineData("http://192.168.1.44:41822/not-an-origin")]
    public void PhysicalFactory_RejectsNonCanonicalOrNonLocalHttp(string baseUrl)
    {
        var factory = new HttpServiceTransportFactory(
            HttpServiceEndpointPolicy.PhysicalE2eDevelopment);

        Assert.Throws<ArgumentException>(() => factory.CreatePush(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions(baseUrl)));
    }

    [Fact]
    public void PhysicalFactory_RejectsPreconfiguredBaseAddressPartialBypass()
    {
        var factory = new HttpServiceTransportFactory(
            HttpServiceEndpointPolicy.PhysicalE2eDevelopment);
        using var client = new HttpClient
        {
            BaseAddress = new Uri("https://push.example.test/")
        };

        Assert.Throws<ArgumentException>(() => factory.CreatePush(
            client,
            new HttpPushSubscriptionTransportOptions("http://192.168.1.44:41822/")));
    }

    [Fact]
    public void ProductionDefault_RemainsHttpsOrExplicitLoopbackOnly()
    {
        Assert.NotNull(new HttpPushSubscriptionTransport(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("https://push.example.test/")));
        Assert.NotNull(new HttpPushSubscriptionTransport(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("http://127.0.0.1:41822/")));
        Assert.Throws<ArgumentException>(() => new HttpPushSubscriptionTransport(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("http://192.168.1.44:41822/")));
    }

    [Fact]
    public void DevelopmentAuthority_IsNotPubliclyAcquirable()
    {
        var type = typeof(HttpServiceEndpointPolicy);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            type.GetMembers(BindingFlags.Public | BindingFlags.Static),
            member => member.Name.Contains("Development", StringComparison.OrdinalIgnoreCase) ||
                      member.Name.Contains("DevLocal", StringComparison.OrdinalIgnoreCase) ||
                      member.Name.Contains("Physical", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            type.GetProperties(BindingFlags.Public | BindingFlags.Instance),
            property => property.PropertyType == typeof(bool));
    }
}
