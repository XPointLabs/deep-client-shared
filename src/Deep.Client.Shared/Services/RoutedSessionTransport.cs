using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Sodium;

namespace Deep.Client.Shared.Services;

public sealed record TransportRouteNode(
    int Index,
    string RouterId,
    string Endpoint,
    bool IsReachable,
    IReadOnlyList<string> Capabilities,
    string X25519PublicKey = "",
    string RpcEndpoint = "",
    string PublicHost = "",
    string PublicIp = "",
    int PublicPort = 0,
    DateTimeOffset SignedAt = default,
    DateTimeOffset ExpiresAt = default,
    string RouterVersion = "",
    string SignatureAlgorithm = "",
    string Signature = "");

public sealed record TransportRouteSnapshot(
    string Mode,
    string TargetKeyDigest,
    DateTimeOffset UpdatedAt,
    IReadOnlyList<TransportRouteNode> Nodes);

public interface ITransportRouteProvider
{
    TransportRouteSnapshot? CurrentRoute { get; }

    Task<TransportRouteSnapshot?> RefreshRouteAsync(string targetKey, CancellationToken cancellationToken = default);
}

public sealed class DirectStorageRouteProvider : ITransportRouteProvider
{
    private readonly string? _storageUrl;

    public DirectStorageRouteProvider(string? storageUrl)
    {
        _storageUrl = storageUrl;
    }

    public TransportRouteSnapshot? CurrentRoute => string.IsNullOrWhiteSpace(_storageUrl)
        ? null
        : new TransportRouteSnapshot(
            "direct-storage",
            RedactTargetKey(_storageUrl),
            DateTimeOffset.UtcNow,
            [
                new TransportRouteNode(0, "direct-storage", _storageUrl, true, ["storage"])
            ]);

    public Task<TransportRouteSnapshot?> RefreshRouteAsync(string targetKey, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(CurrentRoute);
    }

    private static string RedactTargetKey(string targetKey) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(targetKey)));
}

public sealed record PinnedRouterEndpoint(string BaseUrl, string ExpectedRouterId);

public sealed record XNodeRpcClientOptions(
    IReadOnlyList<PinnedRouterEndpoint> Routers,
    string RpcPath = "/api/session/rpc",
    TimeSpan ResponseFreshness = default,
    IReadOnlyList<string>? TrustedRouterIds = null,
    int MaxResponseBytes = 8_388_608);

public sealed class XNodeRpcClient : ITransportRouteProvider
{
    private const string ResponseVersion = "xpoint-rpc-response-v1";
    private const string SignatureAlgorithm = "ed25519";
    private const int RequiredRouteHops = 3;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly TimeSpan DefaultResponseFreshness = TimeSpan.FromMinutes(2);

    private readonly HttpClient _httpClient;
    private readonly XNodeRpcClientOptions _options;
    private readonly ConfiguredRouter[] _routers;
    private readonly HashSet<string> _trustedRouterIds;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _responseFreshness;
    private readonly int _maxResponseBytes;
    private TransportRouteSnapshot? _currentRoute;

    public XNodeRpcClient(
        HttpClient httpClient,
        XNodeRpcClientOptions options,
        TimeProvider? timeProvider = null)
    {
        _httpClient = httpClient;
        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _responseFreshness = options.ResponseFreshness == default
            ? DefaultResponseFreshness
            : options.ResponseFreshness;
        if (_responseFreshness <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Response freshness must be positive.");
        }

        _routers = _options.Routers
            .Select(ConfigureRouter)
            .ToArray();

        if (_routers.Length == 0)
        {
            throw new ArgumentException("At least one pinned router endpoint is required.", nameof(options));
        }

        var trustedRouterIds = options.TrustedRouterIds ?? _routers
            .Select(static router => router.ExpectedRouterId)
            .ToArray();
        _trustedRouterIds = trustedRouterIds
            .Select(static routerId => routerId.Trim().ToLowerInvariant())
            .ToHashSet(StringComparer.Ordinal);
        if (_trustedRouterIds.Count < RequiredRouteHops
            || _trustedRouterIds.Any(static routerId => !IsHex(routerId, 32)))
        {
            throw new ArgumentException(
                $"At least {RequiredRouteHops} unique trusted router IDs are required.",
                nameof(options));
        }

        _maxResponseBytes = options.MaxResponseBytes;
        if (_maxResponseBytes is < 1_024 or > 67_108_864)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "Router response byte limit must be between 1 KiB and 64 MiB.");
        }
    }

    public TransportRouteSnapshot? CurrentRoute => Volatile.Read(ref _currentRoute);

    public async Task<TransportRouteSnapshot?> RefreshRouteAsync(
        string targetKey,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var routeNonce = NewRouteNonce();
            var routeResult = await PostRouterRpcWithEndpointAsync(
                "storage_route",
                new { routeNonce },
                targetKey,
                cancellationToken).ConfigureAwait(false);
            var route = ParseRoute(
                "onion-storage",
                targetKey,
                routeNonce,
                routeResult.Router.ExpectedRouterId,
                routeResult.Result,
                _timeProvider.GetUtcNow(),
                _trustedRouterIds);
            Volatile.Write(ref _currentRoute, route);
            return route;
        }
        catch (RouterResponseValidationException exception)
        {
            // Preserve the public failure contract while retaining an internal
            // non-retryable classification for the storage continuity path.
            throw new HttpRequestException(exception.Message, exception);
        }
    }

    public async Task<JsonElement> PostStorageAsync(
        string method,
        object body,
        string targetKey,
        CancellationToken cancellationToken = default)
    {
        var storagePath = method switch
        {
            "storage_store" => "/storage/store",
            "storage_retrieve" => "/storage/retrieve",
            _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unsupported routed storage method.")
        };

        var excludedRouterIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Exception? firstFailure = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var router = OrderedRouters(targetKey)
                .FirstOrDefault(candidate => !excludedRouterIds.Contains(candidate.ExpectedRouterId))
                ?? throw new HttpRequestException("No disjoint pinned XNode remains for the bounded fallback.", firstFailure);
            TransportRouteSnapshot? routeSnapshot = null;
            try
            {
                var routeNonce = NewRouteNonce();
                var attemptId = NewRouteNonce();
                var routeResult = await PostRouterRpcAsync(
                    router,
                    "storage_route",
                    ToJsonElement(new
                    {
                        routeNonce,
                        attemptId,
                        excludedRouterIds = excludedRouterIds.Order(StringComparer.Ordinal).ToArray()
                    }),
                    cancellationToken).ConfigureAwait(false);
                routeSnapshot = ParseRoute(
                    "onion-storage",
                    targetKey,
                    routeNonce,
                    router.ExpectedRouterId,
                    routeResult,
                    _timeProvider.GetUtcNow(),
                    _trustedRouterIds);
                ValidateRouteExclusions(routeSnapshot, excludedRouterIds);
                Volatile.Write(ref _currentRoute, routeSnapshot);

                var onion = OnionRouting.BuildStorageRequest(routeSnapshot.Nodes, storagePath, body);
                var onionResult = await PostRouterRpcAsync(
                    router,
                    "onion_request",
                    ToJsonElement(onion.Request),
                    cancellationToken).ConfigureAwait(false);

                if (!onionResult.TryGetProperty("onionResponse", out var onionResponseElement))
                {
                    throw new RouterResponseValidationException(
                        "Deep onion route did not return an encrypted storage response.");
                }

                OnionResponseEnvelope onionResponse;
                try
                {
                    onionResponse = onionResponseElement.Deserialize<OnionResponseEnvelope>(JsonOptions)
                        ?? throw new JsonException("Missing onion response body.");
                }
                catch (JsonException exception)
                {
                    throw new RouterResponseValidationException(
                        "Deep onion route returned an invalid encrypted response.",
                        exception);
                }

                var decrypted = OnionRouting.DecryptResponse(onionResponse, onion.ResponsePrivateKey);
                if (decrypted.TryGetProperty("storageStatusCode", out var statusElement)
                    && statusElement.TryGetInt32(out var statusCode)
                    && statusCode is < 200 or > 299)
                {
                    throw new RouterResponseValidationException($"Storage RPC failed with status {statusCode}.");
                }

                return decrypted.TryGetProperty("storage", out var storage)
                    ? storage.Clone()
                    : JsonSerializer.SerializeToElement(new { });
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (attempt == 0 && IsRetryablePreDurableFailure(exception))
            {
                firstFailure = exception;
                excludedRouterIds.Add(router.ExpectedRouterId);
                if (routeSnapshot is not null)
                {
                    foreach (var node in routeSnapshot.Nodes)
                    {
                        excludedRouterIds.Add(node.RouterId);
                    }
                }
            }
        }

        throw new HttpRequestException("The bounded disjoint XNode fallback failed.", firstFailure);
    }

    private static bool IsRetryablePreDurableFailure(Exception exception) => exception switch
    {
        RouterRpcFailureException rpc => string.Equals(
            rpc.RpcError,
            "onion-peer-transport-failed",
            StringComparison.Ordinal),
        RouterResponseValidationException => false,
        TaskCanceledException => true,
        HttpRequestException => true,
        _ => false
    };

    private async Task<JsonElement> PostRouterRpcAsync(
        string method,
        object payload,
        string targetKey,
        CancellationToken cancellationToken)
    {
        var result = await PostRouterRpcWithEndpointAsync(method, payload, targetKey, cancellationToken)
            .ConfigureAwait(false);
        return result.Result;
    }

    private async Task<RouterRpcResult> PostRouterRpcWithEndpointAsync(
        string method,
        object payload,
        string targetKey,
        CancellationToken cancellationToken)
    {
        var payloadElement = ToJsonElement(payload);
        Exception? lastError = null;
        foreach (var router in OrderedRouters(targetKey))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new RouterRpcResult(
                    router,
                    await PostRouterRpcAsync(router, method, payloadElement, cancellationToken).ConfigureAwait(false));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (IsRetryablePreDurableFailure(ex))
            {
                lastError = ex;
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new HttpRequestException("All configured XNodes failed.", lastError);
    }

    private async Task<JsonElement> PostRouterRpcAsync(
        ConfiguredRouter router,
        string method,
        JsonElement payload,
        CancellationToken cancellationToken)
    {
        var rpcUri = new Uri(router.BaseUri, _options.RpcPath.TrimStart('/'));
        var request = new RouterRpcRequest(
            Guid.NewGuid().ToString("N"),
            method,
            payload,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
        using var response = await _httpClient.PostAsJsonAsync(rpcUri, request, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        var rpcBytes = await ReadBoundedAsync(response.Content, _maxResponseBytes, cancellationToken)
            .ConfigureAwait(false);
        RouterRpcResponse? rpc;
        try
        {
            rpc = JsonSerializer.Deserialize<RouterRpcResponse>(rpcBytes, JsonOptions);
        }
        catch (JsonException exception)
        {
            throw new RouterResponseValidationException("Router RPC response is malformed.", exception);
        }

        if (rpc is null)
        {
            throw new RouterResponseValidationException($"router-rpc-empty-response:{(int)response.StatusCode}");
        }

        VerifyRpcResponse(router, request, rpc, _timeProvider.GetUtcNow());

        if (!response.IsSuccessStatusCode || !rpc.Success || rpc.Result is null)
        {
            throw new RouterRpcFailureException(rpc.Error ?? $"router-rpc-failed:{(int)response.StatusCode}");
        }

        return rpc.Result.Value.Clone();
    }

    private IEnumerable<ConfiguredRouter> OrderedRouters(string targetKey)
    {
        var start = _routers.Length == 1
            ? 0
            : SHA256.HashData(Encoding.UTF8.GetBytes(targetKey.Trim().ToLowerInvariant()))[0] % _routers.Length;
        for (var i = 0; i < _routers.Length; i++)
        {
            yield return _routers[(start + i) % _routers.Length];
        }
    }

    private static TransportRouteSnapshot ParseRoute(
        string mode,
        string targetKey,
        string expectedRouteNonce,
        string expectedResponderRouterId,
        JsonElement result,
        DateTimeOffset now,
        IReadOnlySet<string> trustedRouterIds)
    {
        if (result.ValueKind != JsonValueKind.Object
            || !result.TryGetProperty("routeNonce", out var responseNonce)
            || responseNonce.ValueKind != JsonValueKind.String
            || !string.Equals(responseNonce.GetString(), expectedRouteNonce, StringComparison.Ordinal))
        {
            throw new RouterResponseValidationException("Router storage route nonce does not match the request.");
        }

        if (!result.TryGetProperty("route", out var routeElement) ||
            routeElement.ValueKind != JsonValueKind.Array)
        {
            throw new RouterResponseValidationException("Router storage route is missing.");
        }

        if (routeElement.GetArrayLength() != RequiredRouteHops)
        {
            throw new RouterResponseValidationException($"Router storage route must contain exactly {RequiredRouteHops} hops.");
        }

        var nodes = new List<TransportRouteNode>();
        var routerIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var onionKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rpcEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in routeElement.EnumerateArray())
        {
            var expectedIndex = nodes.Count;
            if (!node.TryGetProperty("index", out var indexElement)
                || !indexElement.TryGetInt32(out var index)
                || index != expectedIndex)
            {
                throw new RouterResponseValidationException("Router storage route indices must be exactly 0, 1, 2.");
            }

            var routerId = GetRequiredString(node, "routerId");
            var host = GetString(node, "publicHost") ?? "";
            var publicIp = GetString(node, "publicIp") ?? "";
            var port = node.TryGetProperty("publicPort", out var portElement) && portElement.TryGetInt32(out var parsedPort)
                ? parsedPort
                : 0;
            var endpoint = port > 0 && !string.IsNullOrWhiteSpace(host)
                ? $"{host}:{port}"
                : routerId;
            var x25519PublicKey = GetRequiredString(node, "x25519PublicKey");
            var rpcEndpoint = GetRequiredString(node, "rpcEndpoint");
            var reachable = node.TryGetProperty("isReachable", out var reachableElement) &&
                            reachableElement.ValueKind == JsonValueKind.True;
            var capabilities = node.TryGetProperty("capabilities", out var capabilitiesElement) &&
                               capabilitiesElement.ValueKind == JsonValueKind.Array
                ? capabilitiesElement.EnumerateArray()
                    .Select(static item => item.GetString())
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value!)
                    .ToArray()
                : [];
            var signedAt = GetRequiredDateTimeOffset(node, "signedAt");
            var expiresAt = GetRequiredDateTimeOffset(node, "expiresAt");
            var routeNode = new TransportRouteNode(
                index,
                routerId,
                endpoint,
                reachable,
                capabilities,
                x25519PublicKey,
                rpcEndpoint,
                host,
                publicIp,
                port,
                signedAt,
                expiresAt,
                GetString(node, "routerVersion") ?? "",
                GetRequiredString(node, "signatureAlgorithm"),
                GetRequiredString(node, "signature"));
            if (!reachable
                || !HasCapability(capabilities, "onion-v1")
                || !HasCapability(capabilities, "session-rpc")
                || !IsHex(routerId, 32)
                || !trustedRouterIds.Contains(routerId.ToLowerInvariant())
                || !IsHex(x25519PublicKey, 32)
                || !TryNormalizeRpcEndpoint(rpcEndpoint, out var normalizedRpcEndpoint)
                || !RelayContactSignatureVerifier.Verify(routeNode, now))
            {
                throw new RouterResponseValidationException($"Router returned an invalid signed relay contact for {routerId}.");
            }

            if (!routerIds.Add(routerId)
                || !onionKeys.Add(x25519PublicKey)
                || !rpcEndpoints.Add(normalizedRpcEndpoint))
            {
                throw new RouterResponseValidationException("Router storage route contains duplicate relay identities or endpoints.");
            }

            nodes.Add(routeNode);
        }

        if (!string.Equals(nodes[0].RouterId, expectedResponderRouterId, StringComparison.OrdinalIgnoreCase))
        {
            throw new RouterResponseValidationException("Router storage route first hop does not match the pinned responder.");
        }

        var orderedNodes = nodes
            .Take(1)
            .Concat(nodes
                .Skip(1)
                .OrderBy(node => TargetDistance(node.RouterId, targetKey), StringComparer.Ordinal)
                .ThenBy(static node => node.RouterId, StringComparer.Ordinal))
            .Select((node, index) => node with { Index = index })
            .ToArray();
        return new TransportRouteSnapshot(mode, RedactTargetKey(targetKey), now, orderedNodes);
    }

    private static void ValidateRouteExclusions(
        TransportRouteSnapshot route,
        IReadOnlySet<string> excludedRouterIds)
    {
        if (route.Nodes.Any(node => excludedRouterIds.Contains(node.RouterId)))
        {
            throw new RouterResponseValidationException(
                "Router storage route did not honor the requested relay exclusions.");
        }
    }

    private static string RedactTargetKey(string targetKey) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(targetKey)));

    private static string NewRouteNonce() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    private static string TargetDistance(string routerId, string targetKey)
    {
        var routerBytes = DecodeHex(routerId, 32);
        var targetDigest = SHA256.HashData(Encoding.UTF8.GetBytes(targetKey.Trim().ToLowerInvariant()));
        Span<byte> distance = stackalloc byte[32];
        for (var index = 0; index < distance.Length; index++)
        {
            distance[index] = (byte)(routerBytes[index] ^ targetDigest[index]);
        }

        return Convert.ToHexString(distance);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 and var declaredLength
            && declaredLength > maximumBytes)
        {
            throw new RouterResponseValidationException("Router RPC response exceeds the configured byte limit.");
        }

        await using var input = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(
            content.Headers.ContentLength is > 0 and <= int.MaxValue
                ? (int)Math.Min(content.Headers.ContentLength.Value, maximumBytes)
                : 0);
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }

            if (output.Length + read > maximumBytes)
            {
                throw new RouterResponseValidationException("Router RPC response exceeds the configured byte limit.");
            }

            output.Write(buffer, 0, read);
        }
    }

    private void VerifyRpcResponse(
        ConfiguredRouter router,
        RouterRpcRequest request,
        RouterRpcResponse response,
        DateTimeOffset now)
    {
        if (!string.Equals(response.Version, ResponseVersion, StringComparison.Ordinal)
            || !string.Equals(response.SignatureAlgorithm, SignatureAlgorithm, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(response.Id, request.Id, StringComparison.Ordinal)
            || !string.Equals(response.ResponderRouterId, router.ExpectedRouterId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(response.Method, request.Method, StringComparison.Ordinal)
            || !string.Equals(response.Nonce, request.Nonce, StringComparison.Ordinal)
            || response.IssuedAtUnixMs is null
            || string.IsNullOrWhiteSpace(response.Signature))
        {
            throw new RouterResponseValidationException("Router RPC response is unsigned or does not match its pinned request.");
        }

        DateTimeOffset issuedAt;
        try
        {
            issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(response.IssuedAtUnixMs.Value);
        }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new RouterResponseValidationException("Router RPC response has an invalid issuance time.", exception);
        }

        if ((now - issuedAt).Duration() > _responseFreshness)
        {
            throw new RouterResponseValidationException("Router RPC response is stale.");
        }

        var requestDigest = RpcCanonicalJson.Sha256Hex(request.Payload);
        var outcomeDigest = RpcCanonicalJson.Sha256Hex(ResponseOutcome(response));
        if (!FixedTimeHexEquals(response.RequestPayloadSha256, requestDigest, 32)
            || !FixedTimeHexEquals(response.OutcomeSha256, outcomeDigest, 32))
        {
            throw new RouterResponseValidationException("Router RPC response digest validation failed.");
        }

        try
        {
            var signingPayload = JsonSerializer.SerializeToElement(new RpcResponseSigningPayload(
                response.Version!,
                response.ResponderRouterId!,
                response.Id,
                response.Method!,
                response.Nonce!,
                response.RequestPayloadSha256!,
                response.IssuedAtUnixMs.Value,
                response.Success,
                response.OutcomeSha256!), JsonOptions);
            if (!PublicKeyAuth.VerifyDetached(
                    DecodeHex(response.Signature!, 64),
                    RpcCanonicalJson.Serialize(signingPayload),
                    DecodeHex(router.ExpectedRouterId, 32)))
            {
                throw new RouterResponseValidationException("Router RPC response signature validation failed.");
            }
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new RouterResponseValidationException("Router RPC response signature is malformed.", exception);
        }
    }

    private static ConfiguredRouter ConfigureRouter(PinnedRouterEndpoint endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint.BaseUrl)
            || !Uri.TryCreate(endpoint.BaseUrl.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Pinned router base URL must be an absolute http(s) URL.", nameof(endpoint));
        }

        var expectedRouterId = endpoint.ExpectedRouterId.Trim().ToLowerInvariant();
        _ = DecodeHex(expectedRouterId, 32);
        var baseUri = new Uri(uri.AbsoluteUri.EndsWith('/') ? uri.AbsoluteUri : uri.AbsoluteUri + "/", UriKind.Absolute);
        return new ConfiguredRouter(baseUri, expectedRouterId);
    }

    private static JsonElement ResponseOutcome(RouterRpcResponse response)
    {
        if (response.Success && response.Result is { } result)
        {
            return result;
        }

        return JsonSerializer.SerializeToElement(response.Success ? null : response.Error, JsonOptions);
    }

    private static JsonElement ToJsonElement(object value)
    {
        return value is JsonElement element
            ? element.Clone()
            : JsonSerializer.SerializeToElement(value, JsonOptions);
    }

    private static bool FixedTimeHexEquals(string? actual, string expected, int expectedBytes)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                DecodeHex(actual ?? "", expectedBytes),
                DecodeHex(expected, expectedBytes));
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static byte[] DecodeHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.", nameof(value));
        }

        return Convert.FromHexString(normalized);
    }

    private static bool IsHex(string value, int expectedBytes)
    {
        try
        {
            _ = DecodeHex(value, expectedBytes);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool TryNormalizeRpcEndpoint(string value, out string normalized)
    {
        normalized = "";
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var endpoint)
            || (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps))
        {
            return false;
        }

        normalized = endpoint.AbsoluteUri.TrimEnd('/');
        return true;
    }

    private static bool HasCapability(IEnumerable<string> capabilities, string required)
    {
        return capabilities.Any(value => string.Equals(value, required, StringComparison.OrdinalIgnoreCase));
    }

    private static string? GetString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private static string GetRequiredString(JsonElement element, string name)
    {
        return GetString(element, name) is { Length: > 0 } value
            ? value
            : throw new RouterResponseValidationException($"Router storage route is missing {name}.");
    }

    private static DateTimeOffset GetRequiredDateTimeOffset(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var property)
            && property.ValueKind == JsonValueKind.String
            && property.TryGetDateTimeOffset(out var value)
                ? value
                : throw new RouterResponseValidationException($"Router storage route has an invalid {name}.");
    }

    private sealed record RouterRpcRequest(string Id, string Method, JsonElement Payload, string Nonce);

    private sealed record RouterRpcResponse(string Id, bool Success, JsonElement? Result, string? Error)
    {
        public string? Version { get; init; }

        public string? ResponderRouterId { get; init; }

        public string? Method { get; init; }

        public string? Nonce { get; init; }

        public string? RequestPayloadSha256 { get; init; }

        public long? IssuedAtUnixMs { get; init; }

        public string? OutcomeSha256 { get; init; }

        public string? SignatureAlgorithm { get; init; }

        public string? Signature { get; init; }
    }

    private sealed record RpcResponseSigningPayload(
        string Version,
        string ResponderRouterId,
        string RequestId,
        string Method,
        string Nonce,
        string RequestPayloadSha256,
        long IssuedAtUnixMs,
        bool Success,
        string OutcomeSha256);

    private sealed class RouterResponseValidationException : HttpRequestException
    {
        public RouterResponseValidationException(string message, Exception? innerException = null)
            : base(message, innerException)
        {
        }
    }

    private sealed class RouterRpcFailureException : HttpRequestException
    {
        public RouterRpcFailureException(string rpcError)
            : base(rpcError)
        {
            RpcError = rpcError;
        }

        public string RpcError { get; }
    }

    private sealed record ConfiguredRouter(Uri BaseUri, string ExpectedRouterId);

    private sealed record RouterRpcResult(ConfiguredRouter Router, JsonElement Result);
}

public sealed record RoutedSessionStorageTransportOptions(
    int Namespace = 0,
    int TtlMilliseconds = 14 * 24 * 60 * 60 * 1000,
    SessionStorageMetadataMode MetadataMode = SessionStorageMetadataMode.OpaqueP03);

public sealed class RoutedSessionStorageMessageTransport :
    ISessionMessageTransport,
    IAuthenticatedInboxTransport
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly XNodeRpcClient _router;
    private readonly RoutedSessionStorageTransportOptions _options;
    private readonly OpaqueSessionStorageDependencies? _opaque;
    private readonly OpaqueInboxDecodeCache _opaqueDecodeCache = new();

    public RoutedSessionStorageMessageTransport(
        XNodeRpcClient router,
        RoutedSessionStorageTransportOptions options,
        OpaqueSessionStorageDependencies? opaque = null)
    {
        _router = router;
        _options = options;
        _opaque = opaque;
        if (_options.MetadataMode is not (
                SessionStorageMetadataMode.OpaqueP03 or
                SessionStorageMetadataMode.LegacyCompatibility))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The storage metadata mode is undefined.");
        }
        if (_options.MetadataMode == SessionStorageMetadataMode.OpaqueP03)
        {
            _opaque?.Validate();
            if (_opaque is null)
            {
                throw new InvalidOperationException(
                    "Opaque P03 routed storage requires explicit capability, crypto and replay dependencies.");
            }
        }
    }

    public bool UsesOpaqueMetadata => _options.MetadataMode == SessionStorageMetadataMode.OpaqueP03;

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        if (UsesOpaqueMetadata)
        {
            var opaque = OpaqueSessionStorageCodec.EncodeDeposit(envelope, _options.TtlMilliseconds, _opaque!);
            await _router.PostStorageAsync("storage_store", new
            {
                deposit_capability = opaque.Capability,
                placement_key = opaque.PlacementKey,
                @namespace = _options.Namespace,
                attempt_id = opaque.AttemptId,
                idempotency_key = opaque.IdempotencyKey,
                data = opaque.Data
            }, opaque.PlacementKey, cancellationToken).ConfigureAwait(false);
            return;
        }

        var payload = new StoredMessagePayload(
            (envelope.Id ?? MessageId.NewId()).Value,
            envelope.Sender.Value,
            envelope.Recipient.Value,
            envelope.Body,
            envelope.Attachments,
            envelope.CreatedAt,
            envelope.ExpiresAt,
            envelope.ReplyTo,
            envelope.Reaction);

        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        var timestamp = envelope.CreatedAt.ToUnixTimeMilliseconds();
        await _router.PostStorageAsync("storage_store", new
        {
            pubkey = envelope.Recipient.Value,
            @namespace = _options.Namespace,
            timestamp,
            ttl = _options.TtlMilliseconds,
            data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)),
            idempotency_key = BuildIdempotencyKey(envelope, payloadJson)
        }, envelope.Recipient.Value, cancellationToken).ConfigureAwait(false);
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default) =>
        Task.FromException<IReadOnlyList<InboundMessageEnvelope>>(
            new InvalidOperationException("Routed storage inbox retrieval requires the account signing identity."));

    public int InboxNamespace => _options.Namespace;

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
        SessionIdentityProvider identity,
        CancellationToken cancellationToken = default)
    {
        var batch = await RetrieveAuthenticatedAsync(
            identity,
            cursor: null,
            DurableInboxLimits.MaxBatchCount,
            cancellationToken).ConfigureAwait(false);
        var envelopes = new List<InboundMessageEnvelope>(batch.Entries.Count);
        foreach (var entry in batch.Entries)
        {
            if (TryDecodeInboxEntry(entry, identity.SessionId, out var envelope))
            {
                envelopes.Add(envelope);
            }
        }

        return envelopes;
    }

    public async Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
        SessionIdentityProvider identity,
        string? cursor,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (limit is <= 0 or > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }

        if (UsesOpaqueMetadata)
        {
            var opaque = OpaqueSessionStorageCodec.EncodeRetrieve(identity, _options.TtlMilliseconds, _opaque!);
            var storage = await _router.PostStorageAsync("storage_retrieve", new
            {
                retrieve_capability = opaque.Capability,
                placement_key = opaque.PlacementKey,
                @namespace = _options.Namespace,
                attempt_id = opaque.AttemptId,
                last_hash = cursor
            }, opaque.PlacementKey, cancellationToken).ConfigureAwait(false);
            var payload = storage.Deserialize<StorageRetrieveResponse>(JsonOptions) ?? new StorageRetrieveResponse([]);
            var entries = payload.Messages
                .Take(limit)
                .Where(static item =>
                    !string.IsNullOrWhiteSpace(item.Hash)
                    && item.Hash.Length <= DurableInboxLimits.MaxServerHashChars)
                .Select(static item => DurableInboxWireEntry.CreateBounded(
                    item.Hash,
                    item.Timestamp,
                    item.Data ?? string.Empty))
                .ToArray();
            return new AuthenticatedInboxBatch(
                entries,
                entries.Length == 0 ? cursor : entries[^1].ServerHash);
        }

        var recipient = identity.SessionId;
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var signatureMaterial = StorageSignatureCanonicalizer.CreateRetrieve(_options.Namespace, timestamp);
        var signature = identity.SignDetached(signatureMaterial);
        var ed25519PublicKey = identity.GetEd25519PublicKey();

        try
        {
            var storage = await _router.PostStorageAsync("storage_retrieve", new
            {
                pubkey = recipient.Value,
                pubkey_ed25519 = Convert.ToHexString(ed25519PublicKey).ToLowerInvariant(),
                @namespace = _options.Namespace,
                timestamp,
                signature = Convert.ToBase64String(signature),
                last_hash = cursor
            }, recipient.Value, cancellationToken).ConfigureAwait(false);

            var payload = storage.Deserialize<StorageRetrieveResponse>(JsonOptions) ?? new StorageRetrieveResponse([]);
            var entries = payload.Messages
                .Take(limit)
                .Where(static item =>
                    !string.IsNullOrWhiteSpace(item.Hash)
                    && item.Hash.Length <= DurableInboxLimits.MaxServerHashChars)
                .Select(static item => DurableInboxWireEntry.CreateBounded(
                    item.Hash,
                    item.Timestamp,
                    item.Data ?? string.Empty))
                .ToArray();
            return new AuthenticatedInboxBatch(
                entries,
                entries.Length == 0 ? cursor : entries[^1].ServerHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signatureMaterial);
            CryptographicOperations.ZeroMemory(signature);
            CryptographicOperations.ZeroMemory(ed25519PublicKey);
        }
    }

    public bool TryDecodeInboxEntry(
        DurableInboxWireEntry entry,
        SessionId recipient,
        out InboundMessageEnvelope envelope)
    {
        if (UsesOpaqueMetadata)
        {
            return _opaqueDecodeCache.TryDecode(
                entry,
                recipient,
                _options.TtlMilliseconds,
                _opaque!,
                out envelope);
        }

        envelope = default!;

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(entry.WirePayload));
            var payload = JsonSerializer.Deserialize<StoredMessagePayload>(json, JsonOptions);
            if (payload is null || !string.Equals(payload.Recipient, recipient.Value, StringComparison.Ordinal))
            {
                return false;
            }

            envelope = new InboundMessageEnvelope(
                MessageId.Parse(payload.MessageId),
                SessionId.Parse(payload.Sender),
                recipient,
                payload.Body,
                payload.Attachments,
                payload.CreatedAt,
                payload.ExpiresAt,
                entry.ServerHash,
                payload.ReplyTo,
                payload.Reaction);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string BuildIdempotencyKey(OutboundMessageEnvelope envelope, string payloadJson)
    {
        var material = string.Join('\n',
            "deep-storage-idempotency-v2",
            envelope.Sender.Value,
            envelope.Recipient.Value,
            envelope.Id?.Value ?? Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(payloadJson))));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private sealed record StoredMessagePayload(
        string MessageId,
        string Sender,
        string Recipient,
        string Body,
        IReadOnlyList<AttachmentMetadata> Attachments,
        DateTimeOffset CreatedAt,
        DateTimeOffset? ExpiresAt,
        MessageReply? ReplyTo,
        MessageReactionUpdate? Reaction);

    private sealed record StorageRetrieveResponse(
        [property: JsonPropertyName("messages")] IReadOnlyList<StorageMessageDto> Messages);

    private sealed record StorageMessageDto(
        [property: JsonPropertyName("hash")] string Hash,
        [property: JsonPropertyName("timestamp")] long Timestamp,
        [property: JsonPropertyName("data")] string Data);
}

public sealed record RoutedSessionStorageGroupSyncTransportOptions(
    int GroupStateNamespace = 10,
    int GroupMessagesNamespace = -10,
    int TtlMilliseconds = 14 * 24 * 60 * 60 * 1000);

public sealed class RoutedSessionStorageGroupSyncTransport : IGroupSyncTransport
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly XNodeRpcClient _router;
    private readonly RoutedSessionStorageGroupSyncTransportOptions _options;
    private readonly ConcurrentDictionary<string, string> _stateLastHashes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _messageLastHashes = new(StringComparer.Ordinal);

    public RoutedSessionStorageGroupSyncTransport(
        XNodeRpcClient router,
        RoutedSessionStorageGroupSyncTransportOptions options)
    {
        _router = router;
        _options = options;
    }

    public async Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default)
    {
        var targetMembers = (recipients ?? group.Members.Select(member => member.SessionId).Append(group.CreatedBy))
            .Distinct()
            .ToArray();
        if (targetMembers.Length == 0)
        {
            return;
        }

        var payload = ToPayload(group, updatedAt);
        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        var payloadData = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
        var timestamp = updatedAt.ToUnixTimeMilliseconds();

        foreach (var member in targetMembers)
        {
            await _router.PostStorageAsync("storage_store", new
            {
                pubkey = member.Value,
                @namespace = _options.GroupStateNamespace,
                timestamp,
                ttl = _options.TtlMilliseconds,
                data = payloadData,
                idempotency_key = BuildIdempotencyKey("group-state", member.Value, payloadJson)
            }, member.Value, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default)
    {
        _stateLastHashes.TryGetValue(member.Value, out var lastHash);
        var response = await RetrieveAsync(member.Value, _options.GroupStateNamespace, lastHash, cancellationToken)
            .ConfigureAwait(false);

        var envelopes = new List<InboundGroupStateEnvelope>();
        foreach (var stored in response.Messages.OrderBy(static item => item.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(stored.Hash))
            {
                continue;
            }

            _stateLastHashes[member.Value] = stored.Hash;
            if (TryDecodeGroupState(stored, out var envelope))
            {
                envelopes.Add(envelope);
            }
        }

        return envelopes;
    }

    public async Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        var payload = new StoredGroupMessagePayload(
            envelope.Id.Value,
            envelope.GroupId.Value,
            envelope.Sender.Value,
            envelope.Body,
            envelope.Attachments,
            envelope.CreatedAt,
            envelope.ExpiresAt,
            envelope.ReplyTo,
            envelope.Reaction);

        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        await _router.PostStorageAsync("storage_store", new
        {
            pubkey = envelope.GroupId.Value,
            @namespace = _options.GroupMessagesNamespace,
            timestamp = envelope.CreatedAt.ToUnixTimeMilliseconds(),
            ttl = _options.TtlMilliseconds,
            data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)),
            idempotency_key = BuildIdempotencyKey("group-message", envelope.GroupId.Value, payloadJson)
        }, envelope.GroupId.Value, cancellationToken).ConfigureAwait(false);

        await PublishGroupMessageWakeupsAsync(envelope, envelope.CreatedAt.ToUnixTimeMilliseconds(), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default)
    {
        _messageLastHashes.TryGetValue(groupId.Value, out var lastHash);
        var response = await RetrieveAsync(groupId.Value, _options.GroupMessagesNamespace, lastHash, cancellationToken)
            .ConfigureAwait(false);

        var envelopes = new List<InboundGroupMessageEnvelope>();
        foreach (var stored in response.Messages.OrderBy(static item => item.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(stored.Hash))
            {
                continue;
            }

            _messageLastHashes[groupId.Value] = stored.Hash;
            if (TryDecodeGroupMessage(stored, groupId, out var envelope))
            {
                envelopes.Add(envelope);
            }
        }

        return envelopes;
    }

    private async Task<StorageRetrieveResponse> RetrieveAsync(
        string pubkey,
        int @namespace,
        string? lastHash,
        CancellationToken cancellationToken)
    {
        object body = CanRetrieveWithoutSignature(@namespace)
            ? new
            {
                pubkey,
                @namespace,
                last_hash = lastHash
            }
            : new
            {
                pubkey,
                @namespace,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                signature = "deep-client-storage-group-sync",
                last_hash = lastHash
            };

        var storage = await _router.PostStorageAsync("storage_retrieve", body, pubkey, cancellationToken)
            .ConfigureAwait(false);
        return storage.Deserialize<StorageRetrieveResponse>(JsonOptions) ?? new StorageRetrieveResponse([]);
    }

    private static bool CanRetrieveWithoutSignature(int @namespace) =>
        @namespace == -10 || (@namespace < 0 && (-@namespace % 20) == 1);

    private static StoredGroupStatePayload ToPayload(Group group, DateTimeOffset updatedAt) =>
        new(
            group.Id.Value,
            group.Name,
            group.CreatedBy.Value,
            group.CreatedAt,
            group.Members
                .Select(static member => new StoredGroupMemberPayload(
                    member.SessionId.Value,
                    member.Role,
                    member.JoinedAt,
                    member.IsPendingRemoval))
                .ToArray(),
            group.IsDestroyed,
            group.IsKicked,
            updatedAt);

    private async Task PublishGroupMessageWakeupsAsync(
        OutboundGroupMessageEnvelope envelope,
        long timestamp,
        CancellationToken cancellationToken)
    {
        var recipients = envelope.NotifyRecipients?
            .Where(recipient => recipient != envelope.Sender)
            .Distinct()
            .ToArray() ?? [];
        if (recipients.Length == 0)
        {
            return;
        }

        var wake = new StoredGroupWakePayload(
            "group-message",
            envelope.GroupId.Value,
            envelope.Id.Value,
            envelope.CreatedAt);
        var payloadJson = JsonSerializer.Serialize(wake, JsonOptions);
        var data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));

        foreach (var recipient in recipients)
        {
            await _router.PostStorageAsync("storage_store", new
            {
                pubkey = recipient.Value,
                @namespace = _options.GroupStateNamespace,
                timestamp,
                ttl = _options.TtlMilliseconds,
                data,
                idempotency_key = BuildIdempotencyKey("group-message-wake", recipient.Value, payloadJson)
            }, recipient.Value, cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool TryDecodeGroupState(
        StorageMessageDto stored,
        out InboundGroupStateEnvelope envelope)
    {
        envelope = default!;

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(stored.Data));
            var payload = JsonSerializer.Deserialize<StoredGroupStatePayload>(json, JsonOptions);
            if (payload is null || string.IsNullOrWhiteSpace(payload.GroupId))
            {
                return false;
            }

            var group = new Group(
                ConversationId.Parse(payload.GroupId),
                payload.Name,
                SessionId.Parse(payload.CreatedBy),
                payload.CreatedAt,
                payload.Members.Select(static member => new GroupMember(
                    SessionId.Parse(member.SessionId),
                    member.Role,
                    member.JoinedAt,
                    member.IsPendingRemoval)).ToArray(),
                payload.IsDestroyed,
                payload.IsKicked);

            envelope = new InboundGroupStateEnvelope(group, payload.UpdatedAt, stored.Hash);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryDecodeGroupMessage(
        StorageMessageDto stored,
        ConversationId expectedGroupId,
        out InboundGroupMessageEnvelope envelope)
    {
        envelope = default!;

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(stored.Data));
            var payload = JsonSerializer.Deserialize<StoredGroupMessagePayload>(json, JsonOptions);
            if (payload is null || !string.Equals(payload.GroupId, expectedGroupId.Value, StringComparison.Ordinal))
            {
                return false;
            }

            envelope = new InboundGroupMessageEnvelope(
                MessageId.Parse(payload.MessageId),
                expectedGroupId,
                SessionId.Parse(payload.Sender),
                payload.Body,
                payload.Attachments,
                payload.CreatedAt,
                payload.ExpiresAt,
                stored.Hash,
                payload.ReplyTo,
                payload.Reaction);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string BuildIdempotencyKey(string scope, string target, string payloadJson)
    {
        var material = string.Join('\n', scope, target, payloadJson);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private sealed record StoredGroupStatePayload(
        string GroupId,
        string Name,
        string CreatedBy,
        DateTimeOffset CreatedAt,
        IReadOnlyList<StoredGroupMemberPayload> Members,
        bool IsDestroyed,
        bool IsKicked,
        DateTimeOffset UpdatedAt);

    private sealed record StoredGroupMemberPayload(
        string SessionId,
        GroupMemberRole Role,
        DateTimeOffset JoinedAt,
        bool IsPendingRemoval);

    private sealed record StoredGroupMessagePayload(
        string MessageId,
        string GroupId,
        string Sender,
        string Body,
        IReadOnlyList<AttachmentMetadata> Attachments,
        DateTimeOffset CreatedAt,
        DateTimeOffset? ExpiresAt,
        MessageReply? ReplyTo,
        MessageReactionUpdate? Reaction);

    private sealed record StoredGroupWakePayload(
        string Type,
        string GroupId,
        string MessageId,
        DateTimeOffset CreatedAt);

    private sealed record StorageRetrieveResponse(
        [property: JsonPropertyName("messages")] IReadOnlyList<StorageMessageDto> Messages);

    private sealed record StorageMessageDto(
        [property: JsonPropertyName("hash")] string Hash,
        [property: JsonPropertyName("timestamp")] long Timestamp,
        [property: JsonPropertyName("data")] string Data);
}
