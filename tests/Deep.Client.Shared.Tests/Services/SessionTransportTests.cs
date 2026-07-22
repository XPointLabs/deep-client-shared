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
        using var recipientIdentity = new SessionIdentityProvider(
            "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade");
        var recipient = recipientIdentity.SessionId;
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
                Assert.Equal(64, root.GetProperty("pubkey_ed25519").GetString()!.Length);
                var signedTimestamp = root.GetProperty("timestamp").GetInt64();
                Assert.True(PublicKeyAuth.VerifyDetached(
                    Convert.FromBase64String(root.GetProperty("signature").GetString()!),
                    Encoding.UTF8.GetBytes($"retrieve{signedTimestamp}"),
                    Convert.FromHexString(root.GetProperty("pubkey_ed25519").GetString()!)));
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
            new SessionStorageMessageTransportOptions(
                "http://storage.local",
                TtlMilliseconds: 60_000,
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));

        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, "hello-storage", [], DateTimeOffset.Parse("2026-06-10T00:00:00Z"), null));
        var received = await transport.ReceiveAuthenticatedAsync(recipientIdentity);

        Assert.Single(storedMessages);
        Assert.Single(retrieveRequests);
        Assert.Single(received);
        Assert.Equal(sender, received[0].Sender);
        Assert.Equal(recipient, received[0].Recipient);
        Assert.Equal("hello-storage", received[0].Body);
        Assert.Equal("storage-hash-1", received[0].ServerHash);
    }

    [Fact]
    public async Task SessionStorageMessageTransport_RetrievePreservesServerCursorOrder()
    {
        using var recipientIdentity = new SessionIdentityProvider(
            "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade");
        var sender = SessionId.CreateNew();
        var stored = new List<JsonElement>();

        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            using var document = JsonDocument.Parse(json);
            if (request.RequestUri!.AbsolutePath == "/storage/store")
            {
                stored.Add(document.RootElement.Clone());
                return Json(new { hash = $"hash-{stored.Count}" });
            }

            if (request.RequestUri.AbsolutePath == "/storage/retrieve")
            {
                return Json(new
                {
                    messages = new[]
                    {
                        new
                        {
                            hash = "server-first",
                            timestamp = 2_000L,
                            data = stored[0].GetProperty("data").GetString()
                        },
                        new
                        {
                            hash = "server-second",
                            timestamp = 1_000L,
                            data = stored[1].GetProperty("data").GetString()
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
            new SessionStorageMessageTransportOptions(
                "http://storage.local",
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));

        await transport.SendAsync(new OutboundMessageEnvelope(
            sender,
            recipientIdentity.SessionId,
            "first on server",
            [],
            DateTimeOffset.Parse("2026-07-10T00:00:02Z"),
            null));
        await transport.SendAsync(new OutboundMessageEnvelope(
            sender,
            recipientIdentity.SessionId,
            "second on server",
            [],
            DateTimeOffset.Parse("2026-07-10T00:00:01Z"),
            null));

        var batch = await transport.RetrieveAuthenticatedAsync(recipientIdentity, null, 10);

        Assert.Equal(["server-first", "server-second"], batch.Entries.Select(static item => item.ServerHash));
        Assert.Equal("server-second", batch.NextCursor);
        Assert.True(transport.TryDecodeInboxEntry(batch.Entries[0], recipientIdentity.SessionId, out var first));
        Assert.True(transport.TryDecodeInboxEntry(batch.Entries[1], recipientIdentity.SessionId, out var second));
        Assert.Equal("first on server", first.Body);
        Assert.Equal("second on server", second.Body);
    }

    [Fact]
    public async Task RoutedSessionStorageMessageTransport_SendAndReceive_UsesRouterRpcAndTracksRoute()
    {
        var sender = SessionId.CreateNew();
        using var recipientIdentity = new SessionIdentityProvider(
            "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade");
        var recipient = recipientIdentity.SessionId;
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
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument()
                });
            }

            if (method == "onion_request")
            {
                var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"));
                if (final.StoragePath == "/storage/store")
                {
                    storedMessage = final.Body.Clone();
                    return onionRoute.RouterJson(root, new
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
                var retrieveTimestamp = final.Body.GetProperty("timestamp").GetInt64();
                Assert.True(PublicKeyAuth.VerifyDetached(
                    Convert.FromBase64String(final.Body.GetProperty("signature").GetString()!),
                    Encoding.UTF8.GetBytes($"retrieve{retrieveTimestamp}"),
                    Convert.FromHexString(final.Body.GetProperty("pubkey_ed25519").GetString()!)));
                var stored = storedMessage!.Value;
                return onionRoute.RouterJson(root, new
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
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://router-one.local", TestOnionRoute.RouterIds[0])],
                TrustedRouterIds: TestOnionRoute.RouterIds));
        var transport = new RoutedSessionStorageMessageTransport(
            router,
            new RoutedSessionStorageTransportOptions(
                TtlMilliseconds: 60_000,
                MetadataMode: SessionStorageMetadataMode.LegacyCompatibility));

        await transport.SendAsync(new OutboundMessageEnvelope(sender, recipient, "hello-routed", [], DateTimeOffset.Parse("2026-06-10T00:00:00Z"), null));
        var received = await transport.ReceiveAuthenticatedAsync(recipientIdentity);

        Assert.Equal(new[] { "storage_route", "onion_request", "storage_route", "onion_request" }, rpcMethods);
        Assert.Single(received);
        Assert.Equal("hello-routed", received[0].Body);
        Assert.NotNull(router.CurrentRoute);
        Assert.Equal(3, router.CurrentRoute!.Nodes.Count);
        Assert.Equal(TestOnionRoute.RouterIds[0], router.CurrentRoute.Nodes[0].RouterId);

        var storageRequest = Assert.IsType<JsonElement>(storedMessage);
        Assert.Equal(recipient.Value, storageRequest.GetProperty("pubkey").GetString());
        Assert.Equal(0, storageRequest.GetProperty("namespace").GetInt32());
        Assert.Equal(64, storageRequest.GetProperty("idempotency_key").GetString()!.Length);
        using var managedPayload = JsonDocument.Parse(
            Convert.FromBase64String(storageRequest.GetProperty("data").GetString()!));
        Assert.Equal(sender.Value, managedPayload.RootElement.GetProperty("sender").GetString());
        Assert.Equal(recipient.Value, managedPayload.RootElement.GetProperty("recipient").GetString());
    }

    [Fact]
    public async Task RoutedOpaqueStorage_DepositAndRetrieveHideRawIdentityAndRotateAttemptMaterial()
    {
        using var sender = new SessionIdentityProvider(
            "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade");
        using var recipient = new SessionIdentityProvider(
            "cactus canyon cedar circle cloud comet coral crystal dawn delta dune ember");
        var finalRequests = new List<JsonElement>();
        var outerRequests = new List<string>();
        var onionRoute = new TestOnionRoute();
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            var json = request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
            outerRequests.Add(json);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            var method = root.GetProperty("method").GetString();
            if (method == "storage_route")
            {
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument()
                });
            }

            var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"));
            finalRequests.Add(final.Body.Clone());
            var storage = final.StoragePath == "/storage/store"
                ? (object)new { hash = "opaque-routed-hash" }
                : new { messages = Array.Empty<object>() };
            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 200,
                    storage,
                    storageError = (string?)null
                })
            });
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://router-one.local", TestOnionRoute.RouterIds[0])],
                TrustedRouterIds: TestOnionRoute.RouterIds));
        var transport = new RoutedSessionStorageMessageTransport(
            router,
            new RoutedSessionStorageTransportOptions(),
            OpaqueMetadataTransportTests.TestOpaqueDependencies.Create());
        var wire = new OutboundMessageEnvelope(
            sender.SessionId,
            recipient.SessionId,
            E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String("DPE1routed-opaque"u8),
            [],
            DateTimeOffset.UtcNow,
            null,
            new MessageId("routed-opaque-logical"));

        await transport.SendAsync(wire);
        await transport.SendAsync(wire);
        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);
        await transport.RetrieveAuthenticatedAsync(recipient, null, 10);

        Assert.Equal(4, finalRequests.Count);
        Assert.All(outerRequests, request =>
        {
            Assert.DoesNotContain(sender.SessionId.Value, request, StringComparison.Ordinal);
            Assert.DoesNotContain(recipient.SessionId.Value, request, StringComparison.Ordinal);
        });
        Assert.All(finalRequests, request =>
        {
            Assert.False(request.TryGetProperty("pubkey", out _));
            Assert.False(request.TryGetProperty("pubkey_ed25519", out _));
            Assert.False(request.TryGetProperty("signature", out _));
            Assert.True(request.TryGetProperty("attempt_id", out _));
        });
        Assert.All(finalRequests.Take(2), request =>
        {
            Assert.Equal("DPB1", Encoding.ASCII.GetString(
                Convert.FromBase64String(request.GetProperty("data").GetString()!)[..4]));
            Assert.Equal("MCP1", Encoding.ASCII.GetString(
                Convert.FromBase64String(request.GetProperty("deposit_capability").GetString()!)[..4]));
        });
        Assert.All(finalRequests.Skip(2), request =>
            Assert.Equal("MCP1", Encoding.ASCII.GetString(
                Convert.FromBase64String(request.GetProperty("retrieve_capability").GetString()!)[..4])));
        Assert.Equal(4, finalRequests.Select(static request =>
            request.GetProperty("attempt_id").GetString()).Distinct(StringComparer.Ordinal).Count());
        Assert.NotEqual(
            finalRequests[2].GetProperty("retrieve_capability").GetString(),
            finalRequests[3].GetProperty("retrieve_capability").GetString());
    }

    [Fact]
    public async Task RoutedStorage_ServerErrorIsSanitizedBeforeCrossingClientBoundary()
    {
        const string secret = "storage-secret-account-and-token";
        var onionRoute = new TestOnionRoute();
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            if (root.GetProperty("method").GetString() == "storage_route")
            {
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument()
                });
            }

            var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"));
            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 403,
                    storage = (object?)null,
                    storageError = secret
                })
            });
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://router-one.local", TestOnionRoute.RouterIds[0])],
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            router.PostStorageAsync("storage_store", new { data = "opaque" }, "opaque-target"));

        Assert.DoesNotContain(secret, exception.ToString(), StringComparison.Ordinal);
        Assert.Contains("403", exception.Message, StringComparison.Ordinal);
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

        public HttpResponseMessage RouterJson<T>(JsonElement request, T result)
        {
            var id = request.GetProperty("id").GetString()!;
            var method = request.GetProperty("method").GetString()!;
            var nonce = request.GetProperty("nonce").GetString()!;
            var payload = request.GetProperty("payload");
            var resultElement = JsonSerializer.SerializeToElement(result, JsonOptions);
            var issuedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var requestPayloadSha256 = RpcCanonicalJson.Sha256Hex(payload);
            var outcomeSha256 = RpcCanonicalJson.Sha256Hex(resultElement);
            var signingPayload = JsonSerializer.SerializeToElement(new
            {
                version = "xpoint-rpc-response-v1",
                responderRouterId = RouterIds[0],
                requestId = id,
                method,
                nonce,
                requestPayloadSha256,
                issuedAtUnixMs,
                success = true,
                outcomeSha256
            }, JsonOptions);
            var signature = PublicKeyAuth.SignDetached(
                RpcCanonicalJson.Serialize(signingPayload),
                SigningKeys[0].PrivateKey);
            return Json(new
            {
                id,
                success = true,
                result = resultElement,
                error = (string?)null,
                version = "xpoint-rpc-response-v1",
                responderRouterId = RouterIds[0],
                method,
                nonce,
                requestPayloadSha256,
                issuedAtUnixMs,
                outcomeSha256,
                signatureAlgorithm = "ed25519",
                signature = Convert.ToHexString(signature).ToLowerInvariant()
            });
        }

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
