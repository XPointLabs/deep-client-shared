using System.Net;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class OpaqueMetadataTransportTests
{
    private const string AlicePhrase =
        "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";
    private const string BobPhrase =
        "cactus canyon cedar circle cloud comet coral crystal dawn delta dune ember";

    [Fact]
    public async Task Deposit_RequestContainsOnlyOpaqueCapabilityAndAttemptLocalCorrelation()
    {
        using var sender = new SessionIdentityProvider(AlicePhrase);
        using var recipient = new SessionIdentityProvider(BobPhrase);
        var requests = new List<string>();
        using var client = CreateClient(async request =>
        {
            requests.Add(await request.Content!.ReadAsStringAsync());
            return Json(new { hash = "opaque-store-hash" });
        });
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"));
        var envelope = new OutboundMessageEnvelope(
            sender.SessionId,
            recipient.SessionId,
            "deep-e2ee-v1:" + Convert.ToBase64String("DPE1synthetic-red"u8),
            [],
            DateTimeOffset.Parse("2026-07-22T00:00:00Z"),
            null,
            new MessageId("logical-message-red"));

        await transport.SendAsync(envelope);
        await transport.SendAsync(envelope);

        Assert.Equal(2, requests.Count);
        Assert.All(requests, request =>
        {
            Assert.DoesNotContain(sender.SessionId.Value, request, StringComparison.Ordinal);
            Assert.DoesNotContain(recipient.SessionId.Value, request, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(request);
            Assert.False(json.RootElement.TryGetProperty("pubkey", out _));
            Assert.True(json.RootElement.TryGetProperty("deposit_capability", out _));
            Assert.True(json.RootElement.TryGetProperty("attempt_id", out _));
            Assert.StartsWith(
                "DPB1",
                Encoding.ASCII.GetString(
                    Convert.FromBase64String(json.RootElement.GetProperty("data").GetString()!)),
                StringComparison.Ordinal);
        });
        using var first = JsonDocument.Parse(requests[0]);
        using var second = JsonDocument.Parse(requests[1]);
        Assert.NotEqual(
            first.RootElement.GetProperty("attempt_id").GetString(),
            second.RootElement.GetProperty("attempt_id").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("idempotency_key").GetString(),
            second.RootElement.GetProperty("idempotency_key").GetString());
    }

    [Fact]
    public async Task Retrieve_RequestUsesRotatingOpaqueHandleWithoutAccountAuthenticationMaterial()
    {
        using var recipient = new SessionIdentityProvider(BobPhrase);
        var requests = new List<string>();
        using var client = CreateClient(async request =>
        {
            requests.Add(await request.Content!.ReadAsStringAsync());
            return Json(new { messages = Array.Empty<object>() });
        });
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.test"));

        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);
        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);

        Assert.Equal(2, requests.Count);
        Assert.All(requests, request =>
        {
            Assert.DoesNotContain(recipient.SessionId.Value, request, StringComparison.Ordinal);
            using var json = JsonDocument.Parse(request);
            Assert.False(json.RootElement.TryGetProperty("pubkey", out _));
            Assert.False(json.RootElement.TryGetProperty("pubkey_ed25519", out _));
            Assert.False(json.RootElement.TryGetProperty("signature", out _));
            Assert.True(json.RootElement.TryGetProperty("retrieve_capability", out _));
            Assert.True(json.RootElement.TryGetProperty("attempt_id", out _));
        });
        using var first = JsonDocument.Parse(requests[0]);
        using var second = JsonDocument.Parse(requests[1]);
        Assert.NotEqual(
            first.RootElement.GetProperty("retrieve_capability").GetString(),
            second.RootElement.GetProperty("retrieve_capability").GetString());
        Assert.NotEqual(
            first.RootElement.GetProperty("attempt_id").GetString(),
            second.RootElement.GetProperty("attempt_id").GetString());
    }

    private static HttpClient CreateClient(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) =>
        new(new CaptureHandler(handler))
        {
            BaseAddress = new Uri("http://storage.test/")
        };

    private static HttpResponseMessage Json<T>(T payload) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

    private sealed class CaptureHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            handler(request);
    }
}
