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
    public async Task SendAsyncWithoutIdentityFailsClosedBeforeNetwork()
    {
        var handler = new RecordingHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("http://localhost:18082/api/calls/signal", request.RequestUri?.ToString());
            Assert.NotEqual(true, request.Headers.ConnectionClose);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Accepted));
        });

        var transport = new HttpCallSignalingTransport(
            new HttpClient(handler),
            new HttpCallSignalingTransportOptions("http://localhost:18082"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.SendAsync(BuildEnvelope()));

        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task ReceiveAsyncWithoutIdentityFailsClosedBeforeNetwork()
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

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.ReceiveAsync(recipient));

        Assert.Equal(0, handler.RequestCount);
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
        var nonce = wire.GetProperty("nonce").GetString();
        Assert.True(CallSignalAuthentication.IsNonce(nonce));
        var signedEnvelope = JsonSerializer.Deserialize<CallSignalEnvelope>(
            storedEnvelope!,
            CallSignalAuthentication.JsonOptions);
        Assert.NotNull(signedEnvelope);
        Assert.True(Sodium.PublicKeyAuth.VerifyDetached(
            Convert.FromBase64String(signedEnvelope.Signature!),
            CallSignalAuthentication.BuildSigningPayload(signedEnvelope with { Signature = null }),
            Convert.FromHexString(signedEnvelope.SenderEd25519!)));
        Assert.Equal(envelope.Payload, received.Payload);
    }

    [Fact]
    public async Task AuthenticatedTransport_RejectsReplayAndStaleSignal()
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
        var now = DateTimeOffset.Parse("2026-07-11T00:00:00Z");
        var client = new HttpClient(handler);
        var options = new HttpCallSignalingTransportOptions("http://localhost:18082");
        var aliceTransport = new HttpCallSignalingTransport(client, options, _ => Task.FromResult(alicePhrase));
        var bobTransport = new HttpCallSignalingTransport(
            client,
            options,
            _ => Task.FromResult(bobPhrase),
            new FixedTimeProvider(now));

        await aliceTransport.SendAsync(new CallSignalEnvelope(
            "call-replay",
            bob.SessionId.Value,
            alice.SessionId,
            bob.SessionId,
            CallSignalType.Offer,
            "{\"sdp\":\"offer\"}",
            now));

        Assert.Single(await bobTransport.ReceiveAsync(bob.SessionId));
        Assert.Empty(await bobTransport.ReceiveAsync(bob.SessionId));

        await aliceTransport.SendAsync(new CallSignalEnvelope(
            "call-stale",
            bob.SessionId.Value,
            alice.SessionId,
            bob.SessionId,
            CallSignalType.Offer,
            "{\"sdp\":\"stale\"}",
            now.Subtract(TimeSpan.FromMinutes(6))));
        Assert.Empty(await bobTransport.ReceiveAsync(bob.SessionId));
    }

    [Fact]
    public async Task GetAsyncAuthenticatesAndReadsEphemeralIceConfiguration()
    {
        var runtime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var account = await runtime.Accounts.RegisterAsync("Alice");
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();
        var handler = new RecordingHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Contains("/api/calls/ice-servers/", request.RequestUri?.AbsolutePath, StringComparison.Ordinal);
            Assert.Equal(64, request.Headers.GetValues("X-Deep-Ed25519").Single().Length);
            var timestamp = long.Parse(request.Headers.GetValues("X-Deep-Timestamp").Single(), System.Globalization.CultureInfo.InvariantCulture);
            var nonce = request.Headers.GetValues(CallSignalAuthentication.NonceHeader).Single();
            Assert.True(CallSignalAuthentication.IsNonce(nonce));
            Assert.True(Sodium.PublicKeyAuth.VerifyDetached(
                Convert.FromBase64String(request.Headers.GetValues("X-Deep-Signature").Single()),
                CallSignalAuthentication.BuildIceSigningPayload(
                    account.SessionId,
                    timestamp,
                    nonce,
                    request.RequestUri!.AbsolutePath),
                Convert.FromHexString(request.Headers.GetValues("X-Deep-Ed25519").Single())));

            const string json = """
                {
                  "iceServers": [
                    {
                      "urls": ["turn:registry.xpoint.network:3478?transport=udp"],
                      "username": "1800000000:05abc",
                      "credential": "temporary"
                    }
                  ],
                  "expiresAt": "2027-01-15T08:00:00Z"
                }
                """;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
        });
        var transport = new HttpCallSignalingTransport(
            new HttpClient(handler),
            new HttpCallSignalingTransportOptions("http://localhost:18082"),
            _ => Task.FromResult(phrase));

        var configuration = await transport.GetAsync(account.SessionId);

        var server = Assert.Single(configuration.IceServers);
        Assert.Equal("temporary", server.Credential);
    }

    [Fact]
    public async Task ReceiveAsyncUsesFreshNonceAndPathBoundCanonicalSignature()
    {
        var runtime = Deep.Client.Shared.State.ClientRuntime.CreateStubbed();
        var account = await runtime.Accounts.RegisterAsync("Alice");
        var phrase = await runtime.Accounts.GetRecoveryPhraseAsync();
        var observedNonces = new List<string>();
        var handler = new RecordingHandler((request, _) =>
        {
            var timestamp = long.Parse(
                request.Headers.GetValues("X-Deep-Timestamp").Single(),
                System.Globalization.CultureInfo.InvariantCulture);
            var nonce = request.Headers.GetValues(CallSignalAuthentication.NonceHeader).Single();
            observedNonces.Add(nonce);
            Assert.True(Sodium.PublicKeyAuth.VerifyDetached(
                Convert.FromBase64String(request.Headers.GetValues("X-Deep-Signature").Single()),
                CallSignalAuthentication.BuildInboxSigningPayload(
                    account.SessionId,
                    timestamp,
                    nonce,
                    request.RequestUri!.AbsolutePath),
                Convert.FromHexString(request.Headers.GetValues("X-Deep-Ed25519").Single())));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[]", Encoding.UTF8, "application/json")
            });
        });
        var transport = new HttpCallSignalingTransport(
            new HttpClient(handler),
            new HttpCallSignalingTransportOptions("http://localhost:18082"),
            _ => Task.FromResult(phrase));

        await transport.ReceiveAsync(account.SessionId);
        await transport.ReceiveAsync(account.SessionId);

        Assert.Equal(2, observedNonces.Distinct(StringComparer.Ordinal).Count());
        Assert.All(observedNonces, nonce => Assert.True(CallSignalAuthentication.IsNonce(nonce)));
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

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
