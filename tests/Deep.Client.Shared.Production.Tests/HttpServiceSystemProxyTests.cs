using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Production.Tests;

public sealed class HttpServiceSystemProxyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProxyIsExplicitAndDoesNotRelaxOtherHandlerPolicies(bool enabled)
    {
        using var handler = HttpServiceTransportFactory.CreateHttpHandler(
            new HttpServiceClientOptions(UseSystemProxy: enabled), null);
        Assert.Equal(enabled, handler.UseProxy);
        Assert.Null(handler.Proxy);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Equal(X509RevocationMode.Online, handler.SslOptions.CertificateRevocationCheckMode);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

    [Fact]
    public void OwnedConnectionAndSystemProxyCannotBeCombined()
    {
        var calls = 0;
        var hooks = new HttpServiceNetworkHooks((_, _) =>
        {
            calls++;
            throw new InvalidOperationException("Should not run.");
        });
        Assert.Throws<ArgumentException>(() => HttpServiceTransportFactory.CreateHttpHandler(
            new HttpServiceClientOptions(UseSystemProxy: true), hooks));
        Assert.Equal(0, calls);
        using var direct = HttpServiceTransportFactory.CreateHttpHandler(null, hooks);
        Assert.False(direct.UseProxy);
        Assert.NotNull(direct.ConnectCallback);
    }

    [Fact]
    public async Task RejectedConnectTunnelDoesNotSendBinaryBodyOrRetryDirect()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxyEndpoint = (IPEndPoint)listener.LocalEndpoint;
        var observed = Task.Run(async () =>
        {
            using var connection = await listener.AcceptTcpClientAsync(deadline.Token);
            await using var stream = connection.GetStream();
            using var bytes = new MemoryStream();
            var buffer = new byte[1];
            while (bytes.Length < 4096)
            {
                var read = await stream.ReadAsync(buffer, deadline.Token);
                if (read == 0) break;
                bytes.WriteByte(buffer[0]);
                if (bytes.Length >= 4 && bytes.GetBuffer().AsSpan((int)bytes.Length - 4, 4)
                    .SequenceEqual("\r\n\r\n"u8)) break;
            }
            await stream.WriteAsync("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), deadline.Token);
            return Encoding.ASCII.GetString(bytes.ToArray());
        }, deadline.Token);
        using var handler = HttpServiceTransportFactory.CreateHttpHandler(
            new HttpServiceClientOptions(UseSystemProxy: true), null);
        // Test-owned proxy, not a mutable production handler or OS setting.
        handler.Proxy = new WebProxy(new Uri($"http://127.0.0.1:{proxyEndpoint.Port}/"));
        using var client = new HttpClient(handler);
        using var transport = new HttpServiceRequestTransport(client,
            new("https://registry.example/", ["/proof"], "application/test-request",
                "application/test-response", 32, 32, TimeSpan.FromSeconds(5)),
            HttpServiceEndpointPolicy.Production);
        var error = await Assert.ThrowsAsync<HttpRequestException>(async () =>
            await transport.PostAsync("/proof", "private-body"u8.ToArray(), deadline.Token));
        Assert.Equal(HttpRequestError.ProxyTunnelError, error.HttpRequestError);
        var header = await observed;
        Assert.StartsWith("CONNECT registry.example:443 HTTP/1.1\r\n", header);
        Assert.DoesNotContain("private-body", header);
        Assert.False(listener.Pending());
    }
}
