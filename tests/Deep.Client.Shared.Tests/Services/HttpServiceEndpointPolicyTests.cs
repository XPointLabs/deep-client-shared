using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

[Collection("HTTP default proxy isolation")]
public sealed class HttpServiceEndpointPolicyTests
{
    [Fact]
    public void PhysicalFactory_ConstructsAllSevenTransportsWithPlatformNeutralDefaultPaths()
    {
        var factory = new HttpServiceTransportFactory(
            HttpServiceEndpointPolicy.PhysicalE2eDevelopment);

        Assert.NotNull(factory.CreateAvatar(
            new HttpAvatarProfileTransportOptions("http://192.168.1.44:41821/")));
        Assert.True(factory.CreateAttachment(
            new HttpAttachmentFileTransportOptions("http://192.168.1.44:41821/")).IsEnabled);
        Assert.True(factory.CreatePush(
            new HttpPushSubscriptionTransportOptions("http://192.168.1.44:41822/")).IsEnabled);
        Assert.NotNull(factory.CreateCallSignaling(
            new HttpCallSignalingTransportOptions("http://192.168.1.44:41823/")));
        Assert.NotNull(factory.CreateSession(
            new HttpSessionTransportOptions("http://192.168.1.44:41820/")));
        Assert.False(factory.CreateStorage(
            new SessionStorageMessageTransportOptions(
                "http://192.168.1.44:41820/",
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility)).UsesOpaqueMetadata);
        Assert.NotNull(factory.CreateGroupSync(
            new SessionStorageGroupSyncTransportOptions("http://192.168.1.44:41820/")));
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
            new HttpPushSubscriptionTransportOptions(baseUrl)));
    }

    [Fact]
    public async Task AbsoluteRequests_IgnorePostConstructionBaseAddressMutation()
    {
        Uri? observed = null;
        using var client = new HttpClient(new CaptureHandler(request =>
        {
            observed = request.RequestUri;
            return SuccessResponse();
        }));
        var transport = new HttpPushSubscriptionTransport(
            client,
            new HttpPushSubscriptionTransportOptions("https://push.example.test/"));

        client.BaseAddress = new Uri("https://attacker.example/");
        await transport.SubscribeAsync(CreatePushRequest());

        Assert.Equal(new Uri("https://push.example.test/subscribe"), observed);
    }

    [Theory]
    [InlineData("https://attacker.example/{0}")]
    [InlineData("https:{0}")]
    [InlineData("file:{0}")]
    [InlineData("//attacker.example/{0}")]
    [InlineData("/safe/../{0}")]
    [InlineData("/safe/%2e%2e/{0}")]
    [InlineData("/safe\\{0}")]
    [InlineData("/safe/{0}?token=leak")]
    [InlineData("/safe/{0}#fragment")]
    [InlineData("/safe//{0}")]
    public void EveryTransport_RejectsNonCanonicalPathsAndTemplates(string pattern)
    {
        var path = pattern.Replace("{0}", "operation", StringComparison.Ordinal);
        var recipientTemplate = pattern.Replace("{0}", "{recipient}", StringComparison.Ordinal);
        var sessionTemplate = pattern.Replace("{0}", "{sessionId}", StringComparison.Ordinal);
        var fileTemplate = pattern.Replace("{0}", "{fileId}", StringComparison.Ordinal);

        Assert.Throws<ArgumentException>(() => new HttpAttachmentFileTransport(
            new HttpClient(),
            new HttpAttachmentFileTransportOptions("https://file.example/", UploadPath: path)));
        Assert.Throws<ArgumentException>(() => new HttpAttachmentFileTransport(
            new HttpClient(),
            new HttpAttachmentFileTransportOptions(
                "https://file.example/",
                DownloadPathFormat: fileTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpAvatarProfileTransport(
            new HttpClient(),
            new HttpAvatarProfileTransportOptions(
                "https://file.example/",
                AvatarPathFormat: sessionTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpAvatarProfileTransport(
            new HttpClient(),
            new HttpAvatarProfileTransportOptions(
                "https://file.example/",
                AvatarInfoPathFormat: sessionTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpPushSubscriptionTransport(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("https://push.example/", SubscribePath: path)));
        Assert.Throws<ArgumentException>(() => new HttpPushSubscriptionTransport(
            new HttpClient(),
            new HttpPushSubscriptionTransportOptions("https://push.example/", UnsubscribePath: path)));
        Assert.Throws<ArgumentException>(() => new HttpCallSignalingTransport(
            new HttpClient(),
            new HttpCallSignalingTransportOptions("https://calls.example/", SignalPath: path)));
        Assert.Throws<ArgumentException>(() => new HttpCallSignalingTransport(
            new HttpClient(),
            new HttpCallSignalingTransportOptions(
                "https://calls.example/",
                InboxPathFormat: recipientTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpCallSignalingTransport(
            new HttpClient(),
            new HttpCallSignalingTransportOptions(
                "https://calls.example/",
                IceServersPathFormat: recipientTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpSessionTransport(
            new HttpClient(),
            new HttpSessionTransportOptions("https://session.example/", SendPath: path)));
        Assert.Throws<ArgumentException>(() => new HttpSessionTransport(
            new HttpClient(),
            new HttpSessionTransportOptions(
                "https://session.example/",
                InboxPathFormat: recipientTemplate)));
        Assert.Throws<ArgumentException>(() => new HttpSessionTransport(
            new HttpClient(),
            new HttpSessionTransportOptions(
                "https://session.example/",
                ProfilePathFormat: sessionTemplate)));
        Assert.Throws<ArgumentException>(() => new SessionStorageMessageTransport(
            new HttpClient(),
            new SessionStorageMessageTransportOptions(
                "https://storage.example/",
                StorePath: path,
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility)));
        Assert.Throws<ArgumentException>(() => new SessionStorageMessageTransport(
            new HttpClient(),
            new SessionStorageMessageTransportOptions(
                "https://storage.example/",
                RetrievePath: path,
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility)));
        Assert.Throws<ArgumentException>(() => new SessionStorageGroupSyncTransport(
            new HttpClient(),
            new SessionStorageGroupSyncTransportOptions(
                "https://storage.example/",
                StorePath: path)));
        Assert.Throws<ArgumentException>(() => new SessionStorageGroupSyncTransport(
            new HttpClient(),
            new SessionStorageGroupSyncTransportOptions(
                "https://storage.example/",
                RetrievePath: path)));
    }

    [Theory]
    [InlineData("../x")]
    [InlineData("..\\x")]
    [InlineData("%2e%2e%2f")]
    [InlineData("%252e%252e%252f")]
    [InlineData("/")]
    [InlineData("\\")]
    [InlineData(".")]
    [InlineData("..")]
    public async Task SessionAndCall_RejectUnsafePlaceholderValuesBeforeNetwork(
        string value)
    {
        var networkRequests = 0;
        using var sessionClient = new HttpClient(new CaptureHandler(_ =>
        {
            Interlocked.Increment(ref networkRequests);
            return SuccessResponse();
        }));
        using var callClient = new HttpClient(new CaptureHandler(_ =>
        {
            Interlocked.Increment(ref networkRequests);
            return SuccessResponse();
        }));
        var session = new HttpSessionTransport(
            sessionClient,
            new HttpSessionTransportOptions("https://session.example/"));
        var calls = new HttpCallSignalingTransport(
            callClient,
            new HttpCallSignalingTransportOptions("https://calls.example/"));
        var unsafeSessionId = new Deep.Client.Shared.Domain.SessionId(value);

        await Assert.ThrowsAsync<ArgumentException>(
            () => session.ReceiveAsync(unsafeSessionId));
        await Assert.ThrowsAsync<ArgumentException>(
            () => calls.ReceiveAsync(unsafeSessionId));
        Assert.Equal(0, networkRequests);
    }

    [Fact]
    public void PublicFactorySurface_DoesNotExposeMutableClientsOrHandlers()
    {
        Type[] transportTypes =
        [
            typeof(HttpAvatarProfileTransport),
            typeof(HttpAttachmentFileTransport),
            typeof(HttpPushSubscriptionTransport),
            typeof(HttpCallSignalingTransport),
            typeof(HttpSessionTransport),
            typeof(SessionStorageMessageTransport),
            typeof(SessionStorageGroupSyncTransport)
        ];
        Assert.All(
            transportTypes,
            type =>
            {
                Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
                Assert.True(typeof(IDisposable).IsAssignableFrom(type));
            });

        var surfaceTypes = new[]
            {
                typeof(HttpServiceTransportFactory),
                typeof(HttpServiceClientOptions)
            }
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance))
            .SelectMany(GetSurfaceTypes)
            .ToArray();
        Assert.DoesNotContain(typeof(HttpClient), surfaceTypes);
        Assert.DoesNotContain(typeof(HttpMessageHandler), surfaceTypes);
        Assert.DoesNotContain(typeof(SocketsHttpHandler), surfaceTypes);
        Assert.DoesNotContain(
            surfaceTypes,
            type => typeof(Delegate).IsAssignableFrom(UnwrapSurfaceType(type)));
    }

    [Fact]
    public async Task FactoryOwnedClient_DoesNotFollowRedirectOrLeakPushBodyToSecondOrigin()
    {
        using var redirectOrigin = new TcpListener(IPAddress.Loopback, 0);
        using var secondOrigin = new TcpListener(IPAddress.Loopback, 0);
        redirectOrigin.Start();
        secondOrigin.Start();
        var redirectPort = ((IPEndPoint)redirectOrigin.LocalEndpoint).Port;
        var secondPort = ((IPEndPoint)secondOrigin.LocalEndpoint).Port;
        var redirectServed = ServeRedirectOnceAsync(
            redirectOrigin,
            new Uri($"http://127.0.0.1:{secondPort}/capture"));
        var transport = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .CreatePush(new HttpPushSubscriptionTransportOptions(
                $"http://127.0.0.1:{redirectPort}/"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => transport.SubscribeAsync(CreatePushRequest()));
        await redirectServed;
        await Task.Delay(150);

        Assert.False(
            secondOrigin.Pending(),
            "Redirect handling leaked the push request to a second origin.");
    }

    [Fact]
    public async Task FactoryOwnedClient_DoesNotPersistServerCookies()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var observedSecondRequest = ServeCookieProbeAsync(listener);
        var transport = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production)
            .CreatePush(new HttpPushSubscriptionTransportOptions(
                $"http://127.0.0.1:{port}/"));

        await transport.SubscribeAsync(CreatePushRequest());
        await transport.UnsubscribeAsync(CreatePushUnsubscribeRequest());
        var secondRequest = await observedSecondRequest;

        Assert.DoesNotContain(
            "\r\nCookie:",
            secondRequest,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PhysicalFactory_IgnoresSystemProxyAndConnectsConfiguredAuthority()
    {
        using var backend = new TcpListener(IPAddress.Loopback, 0);
        using var hostileProxy = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();
        hostileProxy.Start();
        var backendPort = ((IPEndPoint)backend.LocalEndpoint).Port;
        var proxyPort = ((IPEndPoint)hostileProxy.LocalEndpoint).Port;
        DnsEndPoint? connectedAuthority = null;
        var backendRequest = ServeSuccessOnceAsync(backend);
        var originalProxy = HttpClient.DefaultProxy;
        try
        {
            HttpClient.DefaultProxy = new WebProxy(
                $"http://127.0.0.1:{proxyPort}/");
            var factory = new HttpServiceTransportFactory(
                    HttpServiceEndpointPolicy.PhysicalE2eDevelopment)
                .BindNetwork(new HttpServiceNetworkHooks(
                    async (context, cancellationToken) =>
                    {
                        connectedAuthority = context.DnsEndPoint;
                        var socket = new Socket(
                            AddressFamily.InterNetwork,
                            SocketType.Stream,
                            ProtocolType.Tcp);
                        try
                        {
                            await socket.ConnectAsync(
                                IPAddress.Loopback,
                                backendPort,
                                cancellationToken);
                            return new NetworkStream(socket, ownsSocket: true);
                        }
                        catch
                        {
                            socket.Dispose();
                            throw;
                        }
                    }));
            using var transport = factory.CreatePush(
                new HttpPushSubscriptionTransportOptions(
                    $"http://192.168.1.44:{backendPort}/"));

            await transport.SubscribeAsync(CreatePushRequest());
            var request = await backendRequest;
            await Task.Delay(100);

            Assert.Equal("192.168.1.44", connectedAuthority?.Host);
            Assert.Equal(backendPort, connectedAuthority?.Port);
            Assert.Contains("\"token\":\"token\"", request, StringComparison.Ordinal);
            Assert.False(
                hostileProxy.Pending(),
                "System proxy received a physical HTTP request.");
        }
        finally
        {
            HttpClient.DefaultProxy = originalProxy;
        }
    }

    [Fact]
    public void ProductionDefault_RemainsHttpsOrExplicitLoopbackOnly()
    {
        var factory = new HttpServiceTransportFactory(HttpServiceEndpointPolicy.Production);
        Assert.NotNull(factory.CreatePush(
            new HttpPushSubscriptionTransportOptions("https://push.example.test/")));
        Assert.NotNull(factory.CreatePush(
            new HttpPushSubscriptionTransportOptions("http://127.0.0.1:41822/")));
        Assert.Throws<ArgumentException>(() => factory.CreatePush(
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

    private static IEnumerable<Type> GetSurfaceTypes(MemberInfo member) =>
        member switch
        {
            MethodInfo method =>
                method.GetParameters().Select(parameter => parameter.ParameterType)
                    .Append(method.ReturnType),
            PropertyInfo property => [property.PropertyType],
            ConstructorInfo constructor =>
                constructor.GetParameters().Select(parameter => parameter.ParameterType),
            _ => []
        };

    private static Type UnwrapSurfaceType(Type type)
    {
        while (type.HasElementType)
        {
            type = type.GetElementType()!;
        }

        return type;
    }

    private static PushSubscriptionRequest CreatePushRequest() =>
        new(
            "05abc",
            "ed25519pub",
            [0],
            true,
            "firebase",
            123,
            "signature",
            new PushSubscriptionServiceInfo("token"),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

    private static HttpResponseMessage SuccessResponse() =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(
                "{\"success\":true}",
                Encoding.UTF8,
                "application/json")
        };

    private static async Task ServeRedirectOnceAsync(
        TcpListener listener,
        Uri location)
    {
        using var client = await listener.AcceptTcpClientAsync();
        await using var stream = client.GetStream();
        _ = await ReadRequestAsync(stream);
        var response = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 307 Temporary Redirect\r\nLocation: {location.AbsoluteUri}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(response);
    }

    private static async Task<string> ServeCookieProbeAsync(TcpListener listener)
    {
        using (var firstClient = await listener.AcceptTcpClientAsync())
        {
            await using var firstStream = firstClient.GetStream();
            _ = await ReadRequestAsync(firstStream);
            var firstResponse = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nSet-Cookie: sensitive=must-not-return; Path=/\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"success\":true}");
            await firstStream.WriteAsync(firstResponse);
        }

        using var secondClient = await listener.AcceptTcpClientAsync();
        await using var secondStream = secondClient.GetStream();
        var secondRequest = await ReadRequestAsync(secondStream);
        var secondResponse = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"success\":true}");
        await secondStream.WriteAsync(secondResponse);
        return secondRequest;
    }

    private static async Task<string> ServeSuccessOnceAsync(TcpListener listener)
    {
        using var client = await listener.AcceptTcpClientAsync();
        await using var stream = client.GetStream();
        var request = await ReadRequestAsync(stream);
        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"success\":true}");
        await stream.WriteAsync(response);
        return request;
    }

    private static async Task<string> ReadRequestAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        using var request = new MemoryStream();
        var headerLength = -1;
        var contentLength = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0)
            {
                return Encoding.UTF8.GetString(request.ToArray());
            }

            request.Write(buffer, 0, read);
            var bytes = request.GetBuffer().AsSpan(0, checked((int)request.Length));
            if (headerLength < 0)
            {
                headerLength = bytes.IndexOf("\r\n\r\n"u8);
                if (headerLength >= 0)
                {
                    headerLength += 4;
                    var headers = Encoding.ASCII.GetString(bytes[..headerLength]);
                    var contentLengthHeader = headers
                        .Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault(line =>
                            line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                    if (contentLengthHeader is not null)
                    {
                        contentLength = int.Parse(
                            contentLengthHeader["Content-Length:".Length..].Trim(),
                            System.Globalization.CultureInfo.InvariantCulture);
                    }
                }
            }

            if (headerLength >= 0 && request.Length >= headerLength + contentLength)
            {
                return Encoding.UTF8.GetString(request.ToArray());
            }
        }
    }

    private static PushUnsubscribeRequest CreatePushUnsubscribeRequest() =>
        new(
            "05abc",
            "ed25519pub",
            "firebase",
            124,
            "signature-2",
            new PushSubscriptionServiceInfo("token"));

    private sealed class CaptureHandler(
        Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}

[CollectionDefinition("HTTP default proxy isolation", DisableParallelization = true)]
public sealed class HttpDefaultProxyIsolationCollection;
