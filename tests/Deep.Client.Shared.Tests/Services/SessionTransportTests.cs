using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.MembershipRoutes;
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
            BaseAddress = new Uri("https://transport.local/")
        };

        var transport = new HttpSessionTransport(client, new HttpSessionTransportOptions("https://transport.local"));

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
            BaseAddress = new Uri("https://storage.local/")
        };

        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions(
                "https://storage.local",
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
            BaseAddress = new Uri("https://storage.local/")
        };
        var transport = new SessionStorageMessageTransport(
            client,
            new SessionStorageMessageTransportOptions(
                "https://storage.local",
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

        var exception = await Assert.ThrowsAnyAsync<HttpRequestException>(() =>
            router.PostStorageAsync("storage_store", new { data = "opaque" }, "opaque-target"));

        Assert.DoesNotContain(secret, exception.ToString(), StringComparison.Ordinal);
        Assert.Contains("403", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RoutedStorage_RetrievePostDispatchTransportFailureRetriesOnceOnStrictlyDisjointRoute()
    {
        const string targetKey = "six-node-disjoint-target";
        var onionRoute = new TestOnionRoute();
        var endpoints = OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3);
        var routeRequests = new List<JsonElement>();
        var storageBodies = new List<JsonElement>();
        var onionAttempts = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            var method = root.GetProperty("method").GetString();
            var responderIndex = request.RequestUri!.Host.StartsWith("router-4", StringComparison.Ordinal) ? 3 : 0;
            var routeIndices = responderIndex == 0
                ? ClientRouteOrder(targetKey, 0, 1, 2)
                : ClientRouteOrder(targetKey, 3, 4, 5);
            if (method == "storage_route")
            {
                routeRequests.Add(root.GetProperty("payload").Clone());
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument(routeIndices)
                }, responderIndex);
            }

            onionAttempts++;
            var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"), routeIndices);
            storageBodies.Add(final.Body.Clone());
            if (responderIndex == 0)
            {
                return onionRoute.RouterFailureJson(root, "onion-peer-transport-failed");
            }

            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 200,
                    storage = new { hash = "stored-once" },
                    storageError = (string?)null
                })
            }, responderIndex);
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(endpoints, TrustedRouterIds: TestOnionRoute.RouterIds));

        var result = await router.PostStorageAsync(
            "storage_retrieve",
            new { idempotency_key = new string('a', 64), data = "ciphertext" },
            targetKey);

        Assert.Equal("stored-once", result.GetProperty("hash").GetString());
        Assert.Equal(2, onionAttempts);
        Assert.Equal(2, routeRequests.Count);
        Assert.Equal(2, routeRequests.Select(static payload =>
            payload.GetProperty("attemptId").GetString()).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(2, routeRequests.Select(static payload =>
            payload.GetProperty("routeNonce").GetString()).Distinct(StringComparer.Ordinal).Count());
        Assert.Empty(routeRequests[0].GetProperty("excludedRouterIds").EnumerateArray());
        Assert.Equal(
            TestOnionRoute.RouterIds.Take(3).Order(StringComparer.Ordinal),
            routeRequests[1].GetProperty("excludedRouterIds").EnumerateArray()
                .Select(static value => value.GetString()!)
                .Order(StringComparer.Ordinal));
        Assert.Equal(2, storageBodies.Count);
        Assert.All(storageBodies, body =>
            Assert.Equal(new string('a', 64), body.GetProperty("idempotency_key").GetString()));
        Assert.Equal(ClientRouteOrder(targetKey, 3, 4, 5).Select(index => TestOnionRoute.RouterIds[index]),
            router.CurrentRoute!.Nodes.Select(static node => node.RouterId));
    }

    [Fact]
    public async Task RoutedStorage_StoreRouteAcquisitionFailureUsesFallbackBeforeSingleDispatch()
    {
        const string targetKey = "store-route-acquisition-fallback-target";
        var onionRoute = new TestOnionRoute();
        var routeRequests = new List<JsonElement>();
        var storageBodies = new List<JsonElement>();
        var onionAttempts = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            var method = root.GetProperty("method").GetString();
            var responderIndex = request.RequestUri!.Host.StartsWith("router-4", StringComparison.Ordinal) ? 3 : 0;
            if (method == "storage_route")
            {
                routeRequests.Add(root.GetProperty("payload").Clone());
                if (responderIndex == 0)
                {
                    throw new HttpRequestException("first route unavailable");
                }

                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument(ClientRouteOrder(targetKey, 3, 4, 5))
                }, responderIndex);
            }

            onionAttempts++;
            var final = onionRoute.OpenStorageLayer(
                root.GetProperty("payload"),
                ClientRouteOrder(targetKey, 3, 4, 5));
            storageBodies.Add(final.Body.Clone());
            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 200,
                    storage = new { hash = "stored-once" }
                })
            }, responderIndex);
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var result = await router.PostStorageAsync(
            "storage_store",
            new { idempotency_key = new string('e', 64), data = "ciphertext" },
            targetKey);

        Assert.Equal("stored-once", result.GetProperty("hash").GetString());
        Assert.Equal(2, routeRequests.Count);
        Assert.Equal(1, onionAttempts);
        Assert.Single(storageBodies);
        Assert.Equal(
            new string('e', 64),
            storageBodies[0].GetProperty("idempotency_key").GetString());
        Assert.Equal(2, routeRequests.Select(static payload =>
            payload.GetProperty("attemptId").GetString()).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(2, routeRequests.Select(static payload =>
            payload.GetProperty("routeNonce").GetString()).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            [TestOnionRoute.RouterIds[0]],
            routeRequests[1].GetProperty("excludedRouterIds").EnumerateArray()
                .Select(static value => value.GetString()!));
    }

    [Fact]
    public async Task RoutedStorage_StoreCommittedButResponseTransportFailsDoesNotRedispatch()
    {
        const string secret = "committed-store-secret-response";
        const string targetKey = "store-commit-response-lost-target";
        var onionRoute = new TestOnionRoute();
        var committedBodies = new List<JsonElement>();
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
                    route = onionRoute.RouteDocument(ClientRouteOrder(targetKey, 0, 1, 2))
                });
            }

            var final = onionRoute.OpenStorageLayer(
                root.GetProperty("payload"),
                ClientRouteOrder(targetKey, 0, 1, 2));
            committedBodies.Add(final.Body.Clone());
            throw new HttpRequestException(secret);
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var exception = await Assert.ThrowsAsync<StorageDispatchOutcomeUnknownException>(() =>
            router.PostStorageAsync(
                "storage_store",
                new { idempotency_key = new string('f', 64), data = "ciphertext" },
                targetKey));

        Assert.Single(committedBodies);
        Assert.DoesNotContain(secret, exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RoutedStorage_StoreSignedPeerTransportFailureDoesNotRedispatch()
    {
        const string targetKey = "store-signed-peer-failure-target";
        var onionRoute = new TestOnionRoute();
        var onionAttempts = 0;
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
                    route = onionRoute.RouteDocument(ClientRouteOrder(targetKey, 0, 1, 2))
                });
            }

            onionAttempts++;
            return onionRoute.RouterFailureJson(root, "onion-peer-transport-failed");
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        await Assert.ThrowsAsync<StorageDispatchOutcomeUnknownException>(() =>
            router.PostStorageAsync(
                "storage_store",
                new { idempotency_key = new string('9', 64), data = "ciphertext" },
                targetKey));

        Assert.Equal(1, onionAttempts);
    }

    [Fact]
    public async Task RoutedStorage_FailsClosedWhenFallbackRouteIgnoresExclusions()
    {
        const string targetKey = "fallback-exclusion-validation-target";
        var onionRoute = new TestOnionRoute();
        var calls = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            calls++;
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            var method = root.GetProperty("method").GetString();
            var responderIndex = request.RequestUri!.Host.StartsWith("router-4", StringComparison.Ordinal) ? 3 : 0;
            if (method == "storage_route")
            {
                var route = responderIndex == 0
                    ? onionRoute.RouteDocument(ClientRouteOrder(targetKey, 0, 1, 2))
                    : onionRoute.RouteDocument(3, 4, 0);
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route
                }, responderIndex);
            }

            return onionRoute.RouterFailureJson(root, "onion-peer-transport-failed");
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var exception = await Assert.ThrowsAnyAsync<HttpRequestException>(() => router.PostStorageAsync(
            "storage_retrieve",
            new { idempotency_key = new string('d', 64), data = "ciphertext" },
            targetKey));

        Assert.Contains("exclusions", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task RoutedStorage_DoesNotRetryPinnedResponseIdentityFailure()
    {
        const string targetKey = "no-security-downgrade-target";
        var onionRoute = new TestOnionRoute();
        var calls = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            calls++;
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            return onionRoute.RouterJson(root, new
            {
                routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                route = onionRoute.RouteDocument()
            }, responderIndex: 1);
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var exception = await Assert.ThrowsAnyAsync<HttpRequestException>(() => router.PostStorageAsync(
            "storage_store",
            new { idempotency_key = new string('b', 64), data = "ciphertext" },
            targetKey));

        Assert.Equal(1, calls);
        Assert.Contains("pinned request", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("unauthorized-onion-next-router")]
    [InlineData("onion-decrypt-failed:tamper")]
    [InlineData("replay-detected")]
    [InlineData("unsupported-onion-layer")]
    [InlineData("storage-rpc-failed:403")]
    public async Task RoutedStorage_DoesNotRetrySignedNonTransportFailures(string rpcError)
    {
        const string targetKey = "signed-failure-no-retry-target";
        var onionRoute = new TestOnionRoute();
        var calls = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            calls++;
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            if (root.GetProperty("method").GetString() == "storage_route")
            {
                return onionRoute.RouterJson(root, new
                {
                    routeNonce = root.GetProperty("payload").GetProperty("routeNonce").GetString(),
                    route = onionRoute.RouteDocument(ClientRouteOrder(targetKey, 0, 1, 2))
                });
            }

            return onionRoute.RouterFailureJson(root, rpcError);
        }));
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                OrderedPinnedEndpoints(targetKey, firstRouterIndex: 0, fallbackRouterIndex: 3),
                TrustedRouterIds: TestOnionRoute.RouterIds));

        var exception = await Assert.ThrowsAnyAsync<HttpRequestException>(() => router.PostStorageAsync(
            "storage_store",
            new { idempotency_key = new string('c', 64), data = "ciphertext" },
            targetKey));

        Assert.Equal(2, calls);
        Assert.Equal(rpcError, exception.Message);
    }

    [Fact]
    public async Task MembershipStore_ProvenPreDispatchFailureExcludesSelectedRouteAndStoresExactlyOnce()
    {
        const string targetKey = "private-mailbox-target-for-chaos-correlation";
        var onionRoute = new TestOnionRoute();
        var catalog = onionRoute.MembershipCatalog();
        var observer = new RecordingRouteEvidenceObserver();
        var onionAttempts = 0;
        var committedBodies = new List<JsonElement>();
        var failedRouterIndex = -1;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            onionAttempts++;
            var selected = observer.Events.Last(static evidence =>
                evidence.Event == TransportRouteEvidenceEvent.Selected);
            var routeIndices = TestOnionRoute.RouteIndices(selected.RouterIdDigests);
            if (onionAttempts == 1)
            {
                failedRouterIndex = routeIndices[0];
                throw new StorageRoutePreDispatchException();
            }

            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"), routeIndices);
            committedBodies.Add(final.Body.Clone());
            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 200,
                    storage = new { hash = "membership-stored-once" }
                })
            }, routeIndices[0]);
        }));
        var routerIds = catalog.Members.Select(static member =>
            Convert.ToHexStringLower(member.Descriptor.RouterId.Span)).ToArray();
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerIds[0])],
                TrustedRouterIds: routerIds,
                RequireMembershipRouteSelection: true),
            timeProvider: null,
            membershipRouteCatalogProvider: new StaticMembershipCatalogProvider(catalog),
            routeEvidenceObserver: observer);

        var result = await router.PostStorageAsync(
            "storage_store",
            new { idempotency_key = new string('7', 64), data = "ciphertext" },
            targetKey);

        Assert.Equal("membership-stored-once", result.GetProperty("hash").GetString());
        Assert.Equal(2, onionAttempts);
        var body = Assert.Single(committedBodies);
        Assert.Equal(new string('7', 64), body.GetProperty("idempotency_key").GetString());
        var selectedRoutes = observer.Events
            .Where(static evidence => evidence.Event == TransportRouteEvidenceEvent.Selected)
            .ToArray();
        Assert.Equal(2, selectedRoutes.Length);
        Assert.Contains(
            TestOnionRoute.RouterDigest(failedRouterIndex),
            selectedRoutes[0].RouterIdDigests);
        Assert.Empty(selectedRoutes[0].RouterIdDigests.Intersect(
            selectedRoutes[1].RouterIdDigests,
            StringComparer.Ordinal));
        Assert.Contains(observer.Events, static evidence =>
            evidence.Event == TransportRouteEvidenceEvent.PreDispatchFailure &&
            evidence.Attempt == 1);
        Assert.Contains(observer.Events, static evidence =>
            evidence.Event == TransportRouteEvidenceEvent.Completed &&
            evidence.Attempt == 2);
        Assert.Equal(4, observer.Events.Count);
        var correlationId = Assert.Single(observer.Events
            .Select(static evidence => evidence.CorrelationId)
            .Distinct(StringComparer.Ordinal));
        Assert.Matches("^[0-9a-f]{32}$", correlationId);
        Assert.DoesNotContain(
            targetKey,
            JsonSerializer.Serialize(observer.Events),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task MembershipRetrieve_TransportFailureRetainsDisjointFallbackBehavior()
    {
        var onionRoute = new TestOnionRoute();
        var catalog = onionRoute.MembershipCatalog();
        var observer = new RecordingRouteEvidenceObserver();
        var onionAttempts = 0;
        using var client = new HttpClient(new FakeHandler((request, cancellationToken) =>
        {
            onionAttempts++;
            if (onionAttempts == 1)
            {
                throw new HttpRequestException("first retrieve route unavailable");
            }

            var selected = observer.Events.Last(static evidence =>
                evidence.Event == TransportRouteEvidenceEvent.Selected);
            var routeIndices = TestOnionRoute.RouteIndices(selected.RouterIdDigests);
            using var document = JsonDocument.Parse(
                request.Content!.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
            var root = document.RootElement;
            var final = onionRoute.OpenStorageLayer(root.GetProperty("payload"), routeIndices);
            return onionRoute.RouterJson(root, new
            {
                onionResponse = onionRoute.EncryptResponse(final.ResponsePublicKey, new
                {
                    storageStatusCode = 200,
                    storage = new { messages = Array.Empty<object>() }
                })
            }, routeIndices[0]);
        }));
        var routerIds = catalog.Members.Select(static member =>
            Convert.ToHexStringLower(member.Descriptor.RouterId.Span)).ToArray();
        var router = new XNodeRpcClient(
            client,
            new XNodeRpcClientOptions(
                [new PinnedRouterEndpoint("http://bootstrap.invalid/", routerIds[0])],
                TrustedRouterIds: routerIds,
                RequireMembershipRouteSelection: true),
            timeProvider: null,
            membershipRouteCatalogProvider: new StaticMembershipCatalogProvider(catalog),
            routeEvidenceObserver: observer);

        var result = await router.PostStorageAsync(
            "storage_retrieve",
            new { last_hash = (string?)null },
            "opaque-retrieve-target");

        Assert.Empty(result.GetProperty("messages").EnumerateArray());
        Assert.Equal(2, onionAttempts);
        var selectedRoutes = observer.Events
            .Where(static evidence => evidence.Event == TransportRouteEvidenceEvent.Selected)
            .ToArray();
        Assert.Equal(2, selectedRoutes.Length);
        Assert.Empty(selectedRoutes[0].RouterIdDigests.Intersect(
            selectedRoutes[1].RouterIdDigests,
            StringComparer.Ordinal));
    }

    private static PinnedRouterEndpoint[] OrderedPinnedEndpoints(
        string targetKey,
        int firstRouterIndex,
        int fallbackRouterIndex)
    {
        var start = SHA256.HashData(Encoding.UTF8.GetBytes(targetKey.Trim().ToLowerInvariant()))[0] % 6;
        var remaining = Enumerable.Range(0, 6)
            .Where(index => index != firstRouterIndex && index != fallbackRouterIndex)
            .ToArray();
        var routerIndices = new int[6];
        routerIndices[start] = firstRouterIndex;
        routerIndices[(start + 1) % 6] = fallbackRouterIndex;
        var remainingOffset = 0;
        for (var offset = 2; offset < 6; offset++)
        {
            routerIndices[(start + offset) % 6] = remaining[remainingOffset++];
        }

        return routerIndices.Select(index => new PinnedRouterEndpoint(
            $"http://router-{index + 1}.local",
            TestOnionRoute.RouterIds[index])).ToArray();
    }

    private static int[] ClientRouteOrder(string targetKey, int first, params int[] remaining)
    {
        var targetDigest = SHA256.HashData(Encoding.UTF8.GetBytes(targetKey.Trim().ToLowerInvariant()));
        return new[] { first }
            .Concat(remaining.OrderBy(index =>
            {
                var routerBytes = Convert.FromHexString(TestOnionRoute.RouterIds[index]);
                var distance = new byte[32];
                for (var offset = 0; offset < distance.Length; offset++)
                {
                    distance[offset] = (byte)(routerBytes[offset] ^ targetDigest[offset]);
                }

                return Convert.ToHexString(distance);
            }, StringComparer.Ordinal))
            .ToArray();
    }

    private sealed class StaticMembershipCatalogProvider(MembershipRouteCatalogSnapshot catalog)
        : IMembershipRouteCatalogProvider
    {
        public Task<MembershipRouteCatalogSnapshot> GetCatalogAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(catalog);
        }
    }

    private sealed class RecordingRouteEvidenceObserver : ITransportRouteEvidenceObserver
    {
        public List<TransportRouteEvidence> Events { get; } = [];

        public void Observe(TransportRouteEvidence evidence) => Events.Add(evidence);
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
            PublicKeyAuth.GenerateKeyPair(Seed(0xc3)),
            PublicKeyAuth.GenerateKeyPair(Seed(0xd4)),
            PublicKeyAuth.GenerateKeyPair(Seed(0xe5)),
            PublicKeyAuth.GenerateKeyPair(Seed(0xf6))
        ];

        public static readonly string[] RouterIds = SigningKeys
            .Select(static key => Convert.ToHexString(key.PublicKey).ToLowerInvariant())
            .ToArray();

        private readonly KeyPair[] _keys =
        [
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair(),
            PublicKeyBox.GenerateKeyPair()
        ];

        public MembershipRouteCatalogSnapshot MembershipCatalog()
        {
            var members = Enumerable.Range(0, RouterIds.Length)
                .Select(index => new MembershipRouteCatalogMember(
                    new MembershipRouteDescriptor
                    {
                        RouterId = Convert.FromHexString(RouterIds[index]),
                        Ed25519PublicKey = SigningKeys[index].PublicKey.ToArray(),
                        X25519PublicKey = _keys[index].PublicKey.ToArray(),
                        RpcEndpoint = $"http://10.0.0.{index + 1}:8080",
                        Roles = MembershipRouteRole.Ingress |
                                MembershipRouteRole.Core |
                                MembershipRouteRole.Storage,
                        Capabilities = MembershipRouteCapability.SessionRpc |
                                       MembershipRouteCapability.OnionV1 |
                                       MembershipRouteCapability.Storage,
                        Epoch = 10,
                        ValidFromUnixSeconds = 1_700_000_000,
                        ValidUntilUnixSeconds = 1_900_000_000
                    },
                    new MembershipRouteInclusionProof
                    {
                        LeafIndex = checked((uint)index),
                        MemberCount = checked((uint)RouterIds.Length),
                        SiblingHashes = []
                    }))
                .ToArray();
            return new MembershipRouteCatalogSnapshot(
                10,
                DateTimeOffset.FromUnixTimeSeconds(1_900_000_000),
                members,
                SHA256.HashData("membership-route-test"u8))
            {
                EndpointPolicy = MembershipRouteEndpointPolicy.DevLocalHttp
            };
        }

        public static int[] RouteIndices(IReadOnlyList<string> routerIdDigests) =>
            routerIdDigests.Select(digest =>
                Array.FindIndex(
                    RouterIds,
                    routerId => string.Equals(
                        RouterDigest(routerId),
                        digest,
                        StringComparison.Ordinal))).ToArray();

        public static string RouterDigest(int routerIndex) => RouterDigest(RouterIds[routerIndex]);

        private static string RouterDigest(string routerId) =>
            Convert.ToHexStringLower(SHA256.HashData(
                Encoding.UTF8.GetBytes(routerId.Trim().ToLowerInvariant())));

        public object[] RouteDocument(params int[] routeIndices)
        {
            routeIndices = routeIndices.Length == 0 ? [0, 1, 2] : routeIndices;
            return routeIndices.Select((nodeIndex, routeIndex) =>
                RouteNode(nodeIndex, routeIndex, 20443 + nodeIndex)).ToArray();
        }

        public HttpResponseMessage RouterJson<T>(JsonElement request, T result, int responderIndex = 0) =>
            SignedRouterJson(request, success: true, result, error: null, responderIndex);

        public HttpResponseMessage RouterFailureJson(
            JsonElement request,
            string error,
            int responderIndex = 0) =>
            SignedRouterJson<object?>(request, success: false, result: null, error, responderIndex);

        private static HttpResponseMessage SignedRouterJson<T>(
            JsonElement request,
            bool success,
            T result,
            string? error,
            int responderIndex)
        {
            var id = request.GetProperty("id").GetString()!;
            var method = request.GetProperty("method").GetString()!;
            var nonce = request.GetProperty("nonce").GetString()!;
            var payload = request.GetProperty("payload");
            var resultElement = success
                ? JsonSerializer.SerializeToElement(result, JsonOptions)
                : default;
            var issuedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var requestPayloadSha256 = RpcCanonicalJson.Sha256Hex(payload);
            var outcome = success
                ? resultElement
                : JsonSerializer.SerializeToElement(error, JsonOptions);
            var outcomeSha256 = RpcCanonicalJson.Sha256Hex(outcome);
            var signingPayload = JsonSerializer.SerializeToElement(new
            {
                version = "xpoint-rpc-response-v1",
                responderRouterId = RouterIds[responderIndex],
                requestId = id,
                method,
                nonce,
                requestPayloadSha256,
                issuedAtUnixMs,
                success,
                outcomeSha256
            }, JsonOptions);
            var signature = PublicKeyAuth.SignDetached(
                RpcCanonicalJson.Serialize(signingPayload),
                SigningKeys[responderIndex].PrivateKey);
            return Json(new
            {
                id,
                success,
                result = success ? resultElement : (JsonElement?)null,
                error,
                version = "xpoint-rpc-response-v1",
                responderRouterId = RouterIds[responderIndex],
                method,
                nonce,
                requestPayloadSha256,
                issuedAtUnixMs,
                outcomeSha256,
                signatureAlgorithm = "ed25519",
                signature = Convert.ToHexString(signature).ToLowerInvariant()
            });
        }

        public FinalStorageLayer OpenStorageLayer(JsonElement payload, params int[] routeIndices)
        {
            routeIndices = routeIndices.Length == 0 ? [0, 1, 2] : routeIndices;
            var onion = payload.Deserialize<TestOnionRequest>(JsonOptions)!;
            var envelope = onion.Envelope;
            for (var routeIndex = 0; routeIndex < routeIndices.Length; routeIndex++)
            {
                var nodeIndex = routeIndices[routeIndex];
                var layer = DecryptLayer(envelope, _keys[nodeIndex].PrivateKey);
                if (routeIndex < routeIndices.Length - 1)
                {
                    Assert.Equal("relay", layer.Type);
                    Assert.Equal(RouterIds[routeIndices[routeIndex + 1]], layer.NextRouterId);
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

        private object RouteNode(int nodeIndex, int routeIndex, int port)
        {
            var signedAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            var expiresAt = signedAt.AddDays(30);
            var capabilities = new[] { "session-rpc", "onion-v1" };
            var publicHost = "192.168.1.44";
            var publicIp = "192.168.1.44";
            var x25519PublicKey = Convert.ToHexString(_keys[nodeIndex].PublicKey).ToLowerInvariant();
            var rpcEndpoint = $"http://xnode-{nodeIndex + 1}:8080";
            var routerVersion = "1.0.0";
            var payload = new
            {
                version = "deep-relay-contact-v1",
                routerId = RouterIds[nodeIndex],
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
                SigningKeys[nodeIndex].PrivateKey);
            return new
            {
                index = routeIndex,
                routerId = RouterIds[nodeIndex],
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
