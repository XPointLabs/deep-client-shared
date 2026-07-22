using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Client.Shared.Services;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class XNodeRpcClientTrustTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void CanonicalJson_MatchesServerVector()
    {
        using var document = JsonDocument.Parse("""
            { "z": 2, "a": [3, { "b": "x", "a": true }], "n": 1.25 }
            """);

        Assert.Equal("{\"a\":[3,{\"a\":true,\"b\":\"x\"}],\"n\":1.25,\"z\":2}", Encoding.UTF8.GetString(RpcCanonicalJson.Serialize(document.RootElement)));
        Assert.Equal("c886182f98d2dc8f244c7e6176fcb5ed7532c789220b2ccdb0540406b43e6147", RpcCanonicalJson.Sha256Hex(document.RootElement));
    }

    [Theory]
    [InlineData("id")]
    [InlineData("method")]
    [InlineData("nonce")]
    [InlineData("requestPayloadSha256")]
    [InlineData("result")]
    public async Task RefreshRouteAsync_RejectsTamperedResponseBinding(string field)
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient((request, _) =>
        {
            var result = fixture.RouteResult(RequestRouteNonce(request));
            return Task.FromResult(fixture.SignedResponse(request, result, tamper: response =>
            {
                if (field == "result")
                {
                    response["result"]!["routeNonce"] = new string('0', 64);
                }
                else
                {
                    response[field] = field == "requestPayloadSha256" ? new string('0', 64) : $"wrong-{field}";
                }
            }));
        });

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
        Assert.Null(client.CurrentRoute);
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsUnsignedResponse()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient((request, _) =>
        {
            return Task.FromResult(fixture.SignedResponse(
                request,
                fixture.RouteResult(RequestRouteNonce(request)),
                tamper: response => response.Remove("signature")));
        });

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsWrongRouterPin()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient(
            (request, _) => Task.FromResult(fixture.SignedResponse(request, fixture.RouteResult(RequestRouteNonce(request)))),
            pinnedRouterIndex: 1);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsAuthenticStaleResponse()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request)),
            issuedAt: Now.Subtract(TimeSpan.FromMinutes(3)))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsWrongSignedRouteNonce()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(new string('0', 64)))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
        Assert.Null(client.CurrentRoute);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public async Task RefreshRouteAsync_RejectsRouteWithWrongHopCount(int hopCount)
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request), fixture.Route(hopCount)))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Theory]
    [InlineData("routerId")]
    [InlineData("x25519PublicKey")]
    [InlineData("rpcEndpoint")]
    public async Task RefreshRouteAsync_RejectsDuplicateRouteIdentityMaterial(string duplicate)
    {
        var fixture = new RouteFixture();
        var signerMap = new[] { 0, duplicate == "routerId" ? 0 : 1, 2 };
        var onionMap = new[] { 0, duplicate == "x25519PublicKey" ? 0 : 1, 2 };
        var endpointMap = new[] { 0, duplicate == "rpcEndpoint" ? 0 : 1, 2 };
        var route = fixture.Route(3, signerMap, onionMap, endpointMap);
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request), route))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsFirstHopThatDoesNotMatchPinnedResponder()
    {
        var fixture = new RouteFixture();
        var route = fixture.Route(3, signerMap: [1, 2, 3], onionMap: [1, 2, 3], endpointMap: [1, 2, 3]);
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request), route))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsSelfSignedHopOutsideTrustedBootstrapSet()
    {
        var fixture = new RouteFixture();
        var route = fixture.Route(3, signerMap: [0, 1, 3], onionMap: [0, 1, 3], endpointMap: [0, 1, 3]);
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request), route))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_RejectsResponseBeforeParsingWhenByteLimitIsExceeded()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient(
            static (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(new string('x', 2_048), Encoding.UTF8, "application/json")
            }),
            maxResponseBytes: 1_024);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Theory]
    [InlineData("unreachable")]
    [InlineData("stale-contact")]
    [InlineData("missing-capability")]
    public async Task RefreshRouteAsync_RejectsUnusableSignedContact(string failure)
    {
        var fixture = new RouteFixture();
        var route = fixture.RouteWithSecondNode(
            reachable: failure != "unreachable",
            signedAt: failure == "stale-contact" ? Now.Subtract(TimeSpan.FromHours(13)) : null,
            capabilities: failure == "missing-capability" ? ["onion-v1"] : null);
        var client = fixture.CreateClient((request, _) => Task.FromResult(fixture.SignedResponse(
            request,
            fixture.RouteResult(RequestRouteNonce(request), route))));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.RefreshRouteAsync("05target"));
    }

    [Fact]
    public async Task RefreshRouteAsync_ConcurrentTargetsReturnTheirOwnValidatedSnapshots()
    {
        var fixture = new RouteFixture();
        var client = fixture.CreateClient(async (request, cancellationToken) =>
        {
            var routeNonce = RequestRouteNonce(request);
            await Task.Delay(routeNonce[^1] % 5, cancellationToken);
            return fixture.SignedResponse(request, fixture.RouteResult(routeNonce));
        });
        var targets = Enumerable.Range(0, 32).Select(index => $"05target-{index:D2}").ToArray();

        var snapshots = await Task.WhenAll(targets.Select(target => client.RefreshRouteAsync(target)));

        Assert.All(snapshots, snapshot =>
        {
            Assert.DoesNotContain(snapshot!.TargetKeyDigest, targets);
            Assert.Matches("^[0-9a-f]{64}$", snapshot.TargetKeyDigest);
        });
        Assert.DoesNotContain(client.CurrentRoute!.TargetKeyDigest, targets);
        Assert.All(snapshots, snapshot => Assert.Equal(3, snapshot!.Nodes.Count));
    }

    private static string RequestRouteNonce(JsonElement request)
    {
        return request.GetProperty("payload").GetProperty("routeNonce").GetString()!;
    }

    private sealed class RouteFixture
    {
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

        private readonly KeyPair[] _signingKeys = Enumerable.Range(1, 4)
            .Select(index => PublicKeyAuth.GenerateKeyPair(Seed((byte)(index * 17))))
            .ToArray();
        private readonly KeyPair[] _onionKeys = Enumerable.Range(1, 4)
            .Select(index => PublicKeyBox.GenerateKeyPair(Seed((byte)(index * 29))))
            .ToArray();

        public XNodeRpcClient CreateClient(
            Func<JsonElement, CancellationToken, Task<HttpResponseMessage>> responseFactory,
            int pinnedRouterIndex = 0,
            int maxResponseBytes = 8_388_608)
        {
            var handler = new AsyncHandler(async (request, cancellationToken) =>
            {
                var json = await request.Content!.ReadAsStringAsync(cancellationToken);
                using var document = JsonDocument.Parse(json);
                return await responseFactory(document.RootElement.Clone(), cancellationToken);
            });
            return new XNodeRpcClient(
                new HttpClient(handler),
                new XNodeRpcClientOptions(
                    [new PinnedRouterEndpoint("http://router-seed.local", RouterId(pinnedRouterIndex))],
                    TrustedRouterIds: [RouterId(0), RouterId(1), RouterId(2)],
                    MaxResponseBytes: maxResponseBytes),
                new FixedTimeProvider(Now));
        }

        public JsonObject RouteResult(string routeNonce, JsonArray? route = null)
        {
            return new JsonObject
            {
                ["routeNonce"] = routeNonce,
                ["route"] = route ?? Route(3)
            };
        }

        public JsonArray Route(
            int count,
            int[]? signerMap = null,
            int[]? onionMap = null,
            int[]? endpointMap = null)
        {
            signerMap ??= Enumerable.Range(0, count).ToArray();
            onionMap ??= Enumerable.Range(0, count).ToArray();
            endpointMap ??= Enumerable.Range(0, count).ToArray();
            var route = new JsonArray();
            for (var index = 0; index < count; index++)
            {
                route.Add(RouteNode(index, signerMap[index], onionMap[index], endpointMap[index]));
            }

            return route;
        }

        public JsonArray RouteWithSecondNode(
            bool reachable,
            DateTimeOffset? signedAt,
            string[]? capabilities)
        {
            return new JsonArray
            {
                RouteNode(0, 0, 0, 0),
                RouteNode(1, 1, 1, 1, reachable, signedAt, capabilities),
                RouteNode(2, 2, 2, 2)
            };
        }

        public HttpResponseMessage SignedResponse(
            JsonElement request,
            JsonNode result,
            int responderIndex = 0,
            DateTimeOffset? issuedAt = null,
            Action<JsonObject>? tamper = null)
        {
            var id = request.GetProperty("id").GetString()!;
            var method = request.GetProperty("method").GetString()!;
            var nonce = request.GetProperty("nonce").GetString()!;
            var payload = request.GetProperty("payload");
            var resultElement = JsonSerializer.SerializeToElement(result, JsonOptions);
            var issuedAtUnixMs = (issuedAt ?? Now).ToUnixTimeMilliseconds();
            var requestPayloadSha256 = RpcCanonicalJson.Sha256Hex(payload);
            var outcomeSha256 = RpcCanonicalJson.Sha256Hex(resultElement);
            var responderRouterId = RouterId(responderIndex);
            var signingPayload = JsonSerializer.SerializeToElement(new
            {
                version = "xpoint-rpc-response-v1",
                responderRouterId,
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
                _signingKeys[responderIndex].PrivateKey);
            var response = JsonSerializer.SerializeToNode(new
            {
                id,
                success = true,
                result = resultElement,
                error = (string?)null,
                version = "xpoint-rpc-response-v1",
                responderRouterId,
                method,
                nonce,
                requestPayloadSha256,
                issuedAtUnixMs,
                outcomeSha256,
                signatureAlgorithm = "ed25519",
                signature = Convert.ToHexString(signature).ToLowerInvariant()
            }, JsonOptions)!.AsObject();
            tamper?.Invoke(response);

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(JsonOptions), Encoding.UTF8, "application/json")
            };
        }

        private JsonObject RouteNode(
            int routeIndex,
            int signerIndex,
            int onionIndex,
            int endpointIndex,
            bool reachable = true,
            DateTimeOffset? signedAt = null,
            string[]? capabilities = null)
        {
            var contactSignedAt = signedAt ?? Now.Subtract(TimeSpan.FromMinutes(1));
            var expiresAt = contactSignedAt.AddDays(1);
            var contactCapabilities = capabilities ?? ["session-rpc", "onion-v1"];
            var routerId = RouterId(signerIndex);
            var publicHost = $"router-{endpointIndex}.example";
            var publicIp = $"203.0.113.{endpointIndex + 1}";
            var publicPort = 22020 + endpointIndex;
            var x25519PublicKey = Convert.ToHexString(_onionKeys[onionIndex].PublicKey).ToLowerInvariant();
            var rpcEndpoint = $"http://router-{endpointIndex}.example:8081/api/peer/onion";
            var routerVersion = "1.0.0";
            var signingPayload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = "deep-relay-contact-v1",
                routerId,
                publicHost,
                publicIp,
                publicPort,
                x25519PublicKey,
                rpcEndpoint,
                signedAtUnixMs = contactSignedAt.ToUnixTimeMilliseconds(),
                expiresAtUnixMs = expiresAt.ToUnixTimeMilliseconds(),
                routerVersion,
                isReachable = reachable,
                capabilities = contactCapabilities.Order(StringComparer.Ordinal).ToArray()
            }, JsonOptions);
            var signature = PublicKeyAuth.SignDetached(signingPayload, _signingKeys[signerIndex].PrivateKey);

            return JsonSerializer.SerializeToNode(new
            {
                index = routeIndex,
                routerId,
                publicHost,
                publicIp,
                publicPort,
                x25519PublicKey,
                rpcEndpoint,
                isReachable = reachable,
                capabilities = contactCapabilities,
                signedAt = contactSignedAt,
                expiresAt,
                routerVersion,
                signatureAlgorithm = "ed25519",
                signature = Convert.ToHexString(signature).ToLowerInvariant()
            }, JsonOptions)!.AsObject();
        }

        private string RouterId(int index)
        {
            return Convert.ToHexString(_signingKeys[index].PublicKey).ToLowerInvariant();
        }

        private static byte[] Seed(byte value)
        {
            var seed = new byte[32];
            seed[^1] = value;
            return seed;
        }
    }

    private sealed class AsyncHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;

        public AsyncHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return _handler(request, cancellationToken);
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
