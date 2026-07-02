using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class HttpCallSignalingTransportTests
{
    [Fact]
    public async Task SendAsync_PostsEnvelopeToConfiguredPath()
    {
        var handler = new RecordingHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("http://localhost:18082/api/calls/signal", request.RequestUri?.ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Accepted));
        });

        var transport = new HttpCallSignalingTransport(
            new HttpClient(handler),
            new HttpCallSignalingTransportOptions("http://localhost:18082"));

        await transport.SendAsync(BuildEnvelope());

        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task ReceiveAsync_ReadsInboxUsingRecipientPath()
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();

        var handler = new RecordingHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Contains(Uri.EscapeDataString(recipient.Value), request.RequestUri?.ToString(), StringComparison.Ordinal);

            var json = $$"""
            [
              {
                "callId": "call-1",
                "conversationId": "03conversation",
                "sender": { "value": "{{sender.Value}}" },
                "recipient": { "value": "{{recipient.Value}}" },
                "type": 0,
                "payload": "{\"sdp\":\"offer\"}",
                "createdAt": "2026-05-30T00:00:00Z"
              }
            ]
            """;

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
        });

        var transport = new HttpCallSignalingTransport(
            new HttpClient(handler),
            new HttpCallSignalingTransportOptions("http://localhost:18082"));

        var inbound = await transport.ReceiveAsync(recipient);

        Assert.Single(inbound);
        Assert.Equal("call-1", inbound[0].CallId);
        Assert.Equal(CallSignalType.Offer, inbound[0].Type);
        Assert.Equal(sender, inbound[0].Sender);
        Assert.Equal(recipient, inbound[0].Recipient);
    }

    [Fact]
    public async Task AuthenticatedTransportEncryptsAndDecryptsSignalingPayload()
    {
        string? storedEnvelope = null;
        var handler = new RecordingHandler(async (request, cancellationToken) =>
        {
            if (request.Method == HttpMethod.Post)
            {
                storedEnvelope = await request.Content!.ReadAsStringAsync(cancellationToken);
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"[{storedEnvelope}]", Encoding.UTF8, "application/json")
            };
        });
        var aliceRuntime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var bobRuntime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var alice = await aliceRuntime.Accounts.RegisterAsync("Alice");
        var bob = await bobRuntime.Accounts.RegisterAsync("Bob");
        var alicePhrase = await aliceRuntime.Accounts.GetRecoveryPhraseAsync();
        var bobPhrase = await bobRuntime.Accounts.GetRecoveryPhraseAsync();
        var client = new HttpClient(handler);
        var options = new HttpCallSignalingTransportOptions("http://localhost:18082");
        var aliceTransport = new HttpCallSignalingTransport(client, options, _ => Task.FromResult(alicePhrase));
        var bobTransport = new HttpCallSignalingTransport(client, options, _ => Task.FromResult(bobPhrase));
        var envelope = new CallSignalEnvelope(
            "call-private",
            bob.SessionId.Value,
            alice.SessionId,
            bob.SessionId,
            CallSignalType.Offer,
            "{\"sdp\":\"private-offer\"}",
            DateTimeOffset.UtcNow);

        await aliceTransport.SendAsync(envelope);
        var wire = JsonDocument.Parse(storedEnvelope!).RootElement;
        var received = Assert.Single(await bobTransport.ReceiveAsync(bob.SessionId));

        Assert.StartsWith("sealed-v1:", wire.GetProperty("payload").GetString());
        Assert.DoesNotContain("private-offer", storedEnvelope, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(wire.GetProperty("signature").GetString()));
        Assert.Equal(envelope.Payload, received.Payload);
    }

    private static CallSignalEnvelope BuildEnvelope()
    {
        return new CallSignalEnvelope(
            "call-1",
            "03conversation",
            SessionId.CreateNew(),
            SessionId.CreateNew(),
            CallSignalType.Offer,
            "{\"sdp\":\"offer\"}",
            DateTimeOffset.Parse("2026-05-30T00:00:00Z"));
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _responder;

        public RecordingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
        {
            _responder = responder;
        }

        public int RequestCount { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return await _responder(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
