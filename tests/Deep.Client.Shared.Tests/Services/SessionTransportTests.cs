using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class SessionTransportTests
{
    [Fact]
    public async Task HttpSessionTransport_SendAndReceive_UsesConfiguredPaths()
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var sentBodies = new List<string>();
        var receivePayload = new[]
        {
            new
            {
                id = MessageId.NewId(),
                sender,
                recipient,
                body = "hello-http",
                attachments = Array.Empty<AttachmentMetadata>(),
                createdAt = DateTimeOffset.Parse("2026-05-28T00:00:00Z"),
                expiresAt = (DateTimeOffset?)null,
                serverHash = "abc123"
            }
        };

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/api/messages/send")
            {
                var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
                using var document = JsonDocument.Parse(json);
                sentBodies.Add(document.RootElement.GetProperty("body").GetString() ?? string.Empty);
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath.Contains("/api/messages/inbox/", StringComparison.Ordinal))
            {
                var payload = JsonSerializer.Serialize(receivePayload);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(payload, Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }))
        {
            BaseAddress = new Uri("http://transport.local/")
        };

        var transport = new HttpSessionTransport(client, new HttpSessionTransportOptions("http://transport.local"));

        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, "hello-http", [], DateTimeOffset.UtcNow, null));
        var received = await transport.ReceiveAsync(recipient);

        Assert.Single(sentBodies);
        Assert.Equal("hello-http", sentBodies[0]);
        Assert.Single(received);
        Assert.Equal("hello-http", received[0].Body);
        Assert.Equal("abc123", received[0].ServerHash);
    }

    [Fact]
    public async Task SessionStorageMessageTransport_SendAndReceive_UsesStorageStoreRetrieveContract()
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var storedMessages = new List<JsonElement>();
        var retrieveRequests = new List<JsonElement>();

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/storage/store")
            {
                var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement.Clone();
                Assert.Equal(recipient.Value, root.GetProperty("pubkey").GetString());
                Assert.Equal(0, root.GetProperty("namespace").GetInt32());
                Assert.True(root.TryGetProperty("idempotency_key", out var idempotencyKey));
                Assert.False(string.IsNullOrWhiteSpace(idempotencyKey.GetString()));
                storedMessages.Add(root);

                return Json(new
                {
                    hash = "storage-hash-1",
                    t = root.GetProperty("timestamp").GetInt64(),
                    swarm = new { relay = new { hash = "storage-hash-1", signature = "sig" } }
                });
            }

            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath == "/storage/retrieve")
            {
                var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement.Clone();
                Assert.Equal(recipient.Value, root.GetProperty("pubkey").GetString());
                Assert.Equal(0, root.GetProperty("namespace").GetInt32());
                Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("signature").GetString()));
                retrieveRequests.Add(root);

                var stored = storedMessages.Single();
                return Json(new
                {
                    messages = new[]
                    {
                        new
                        {
                            hash = "storage-hash-1",
                            pubkey = recipient.Value,
                            @namespace = 0,
                            timestamp = stored.GetProperty("timestamp").GetInt64(),
                            expiration = stored.GetProperty("timestamp").GetInt64() + 60_000,
                            data = stored.GetProperty("data").GetString()
                        }
                    }
                });
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }))
        {
            BaseAddress = new Uri("http://storage.local/")
        };

        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions("http://storage.local", TtlMilliseconds: 60_000));

        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, "hello-storage", [], DateTimeOffset.Parse("2026-06-10T00:00:00Z"), null));
        var received = await transport.ReceiveAsync(recipient);

        Assert.Single(storedMessages);
        Assert.Single(retrieveRequests);
        Assert.Single(received);
        Assert.Equal(sender, received[0].Sender);
        Assert.Equal(recipient, received[0].Recipient);
        Assert.Equal("hello-storage", received[0].Body);
        Assert.Equal("storage-hash-1", received[0].ServerHash);
    }

    [Fact]
    public async Task RoutedSessionStorageMessageTransport_SendAndReceive_UsesRouterRpcAndTracksRoute()
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        JsonElement? storedMessage = null;
        var rpcMethods = new List<string>();
        var onionRoute = new TestOnionRoute();

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/api/session/rpc", request.RequestUri!.AbsolutePath);

            var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var id = root.GetProperty("id").GetString()!;
            var method = root.GetProperty("method").GetString()!;
            rpcMethods.Add(method);

            if (method == "storage_route")
            {
                return RouterJson(id, new
                {
                    targetKey = recipient.Value,
                    route = onionRoute.RouteDocument()
                });
            }

            if (method == "onion_request")
            {
                var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"));
                if (final.StoragePath == "/storage/store")
                {
                    storedMessage = final.Body.Clone();
                    return RouterJson(id, new
                    {
                        onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                        {
                            storageStatusCode = 200,
                            storage = new { hash = "routed-storage-hash-1" },
                            storageError = (string?)null
                        })
                    });
                }

                Assert.Equal("/storage/retrieve", final.StoragePath);
                var stored = storedMessage!.Value;
                return RouterJson(id, new
                {
                    onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                    {
                        storageStatusCode = 200,
                        storage = new
                        {
                            messages = new[]
                            {
                                new
                                {
                                    hash = "routed-storage-hash-1",
                                    timestamp = stored.GetProperty("timestamp").GetInt64(),
                                    data = stored.GetProperty("data").GetString()
                                }
                            }
                        },
                        storageError = (string?)null
                    })
                });
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(["http://router-one.local", "http://router-two.local"]));
        var transport = new RoutedSessionStorageMessageTransport(
            router,
            new RoutedSessionStorageTransportOptions(TtlMilliseconds: 60_000));

        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, "hello-routed", [], DateTimeOffset.Parse("2026-06-10T00:00:00Z"), null));
        var received = await transport.ReceiveAsync(recipient);

        Assert.Equal(new[] { "storage_route", "onion_request", "storage_route", "onion_request" }, rpcMethods);
        Assert.Single(received);
        Assert.Equal("hello-routed", received[0].Body);
        Assert.NotNull(router.CurrentRoute);
        Assert.Equal(3, router.CurrentRoute!.Nodes.Count);
        Assert.Equal(TestOnionRoute.RouterIds[0], router.CurrentRoute.Nodes[0].RouterId);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(_handler(request, cancellationToken));
        }
    }

    private static HttpResponseMessage Json<T>(T payload) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };

    private static HttpResponseMessage RouterJson<T>(string id, T result) =>
        Json(new
        {
            id,
            success = true,
            result,
            error = (string?)null
        });

    private sealed class TestOnionRoute
    {
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static readonly KeyPair[] SigningKeys =
        [
            PublicKeyAuth.GenerateKeyPair(Seed(0xa1)),
            PublicKeyAuth.GenerateKeyPair(Seed(0xb2)),
            PublicKeyAuth.GenerateKeyPair(Seed(0xc3))
        ];

        public static readonly string[] RouterIds = SigningKeys
            .Select(static key => Convert.ToHexString(key.PublicKey).ToLowerInvariant())
            .ToArray();

        private readonly KeyPair[] _keys =
        [
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair()
        ];

        public object[] RouteDocument() =>
        [
            RouteNode(0, 20443),
            RouteNode(1, 20444),
            RouteNode(2, 20445)
        ];

        public FinalStorageLayer OpenStorageLayer(JsonElement payload)
        {
            var onion = payload.Deserialize<TestOnionRequest>(JsonOptions)!;
            var envelope = onion.Envelope;
            for (var index = 0; index < _keys.Length; index++)
            {
                var layer = DecryptLayer(envelope, _keys[index].PrivateKey);
                if (index < _keys.Length - 1)
                {
                    Assert.Equal("relay", layer.Type);
                    Assert.Equal(RouterIds[index + 1], layer.NextRouterId);
                    envelope = layer.Inner!;
                    continue;
                }

                Assert.Equal("storage", layer.Type);
                return new FinalStorageLayer(
                    layer.StoragePath!,
                    layer.Body!.Value,
                    layer.ResponsePublicKey!);
            }

            throw new InvalidOperationException("No final onion layer found.");
        }

        public TestOnionResponseEnvelope EncryptResponse(string responsePublicKey, object payload)
        {
            var responseKey = Convert.FromBase64String(responsePublicKey);
            using var keyPair = PublicKeyBox.GenerateKeyPair();
            var nonce = PublicKeyBox.GenerateNonce();
            var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            var ciphertext = PublicKeyBox.Create(payloadBytes, nonce, keyPair.PrivateKey, responseKey);
            return new TestOnionResponseEnvelope(
                "deep-onion-response-v1",
                Convert.ToBase64String(keyPair.PublicKey),
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext));
        }

        private object RouteNode(int index, int port)
        {
            var signedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            var expiresAt = signedAt.AddDays(30);
            var capabilities = new[] { "session-rpc", "onion-v1" };
            var publicHost = "192.168.1.44";
            var publicIp = "192.168.1.44";
            var x25519PublicKey = Convert.ToHexString(_keys[index].PublicKey).ToLowerInvariant();
            var rpcEndpoint = $"http://xnode-{index + 1}:8080";
            var routerVersion = "1.0.0";
            var payload = new
            {
                version = "deep-relay-contact-v1",
                routerId = RouterIds[index],
                publicHost,
                publicIp,
                publicPort = port,
                x25519PublicKey,
                rpcEndpoint,
                signedAtUnixMs = signedAt.ToUnixTimeMilliseconds(),
                expiresAtUnixMs = expiresAt.ToUnixTimeMilliseconds(),
                routerVersion,
                isReachable = true,
                capabilities = capabilities.Order(StringComparer.Ordinal).ToArray()
            };
            var signature = PublicKeyAuth.SignDetached(
                JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions),
                SigningKeys[index].PrivateKey);
            return new
            {
                index,
                routerId = RouterIds[index],
                publicHost,
                publicIp,
                publicPort = port,
                x25519PublicKey,
                rpcEndpoint,
                isReachable = true,
                capabilities,
                signedAt,
                expiresAt,
                routerVersion,
                signatureAlgorithm = "ed25519",
                signature = Convert.ToHexString(signature).ToLowerInvariant()
            };
        }

        private static byte[] Seed(byte value)
        {
            var seed = new byte[32];
            seed[^1] = value;
            return seed;
        }

        private static TestOnionLayer DecryptLayer(TestOnionEnvelope envelope, byte[] privateKey)
        {
            var ephemeralPublicKey = Convert.FromBase64String(envelope.EphemeralPublicKey);
            var nonce = Convert.FromBase64String(envelope.Nonce);
            var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            var plaintext = PublicKeyBox.Open(ciphertext, nonce, privateKey, ephemeralPublicKey);
            return JsonSerializer.Deserialize<TestOnionLayer>(plaintext, JsonOptions)!;
        }

        public sealed record FinalStorageLayer(
            string StoragePath,
            JsonElement Body,
            string ResponsePublicKey);

        private sealed record TestOnionRequest(TestOnionEnvelope Envelope);

        private sealed record TestOnionEnvelope(
            string Version,
            string EphemeralPublicKey,
            string Nonce,
            string Ciphertext);

        public sealed record TestOnionResponseEnvelope(
            string Version,
            string EphemeralPublicKey,
            string Nonce,
            string Ciphertext);

        private sealed record TestOnionLayer(
            string Type,
            string? NextRouterId,
            string? NextRpcEndpoint,
            TestOnionEnvelope? Inner,
            string? StoragePath,
            JsonElement? Body,
            string? ResponsePublicKey);
    }
}
