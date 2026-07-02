using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;

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
    string TargetKey,
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
            _storageUrl,
            DateTimeOffset.UtcNow,
            [
                new TransportRouteNode(0, "direct-storage", _storageUrl, true, ["storage"])
            ]);

    public Task<TransportRouteSnapshot?> RefreshRouteAsync(string targetKey, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(CurrentRoute);
    }
}

public sealed record XNodeRpcClientOptions(
    IReadOnlyList<string> RouterBaseUrls,
    string RpcPath = "/api/session/rpc");

public sealed class XNodeRpcClient : ITransportRouteProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly XNodeRpcClientOptions _options;
    private readonly Uri[] _routerBaseUris;
    private TransportRouteSnapshot? _currentRoute;

    public XNodeRpcClient(HttpClient httpClient, XNodeRpcClientOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        _routerBaseUris = _options.RouterBaseUrls
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => new Uri(value.EndsWith('/') ? value : value + "/", UriKind.Absolute))
            .ToArray();

        if (_routerBaseUris.Length == 0)
        {
            throw new ArgumentException("At least one router base URL is required.", nameof(options));
        }
    }

    public TransportRouteSnapshot? CurrentRoute => _currentRoute;

    public async Task<TransportRouteSnapshot?> RefreshRouteAsync(
        string targetKey,
        CancellationToken cancellationToken = default)
    {
        var result = await PostRouterRpcAsync(
            "storage_route",
            new { targetKey },
            targetKey,
            cancellationToken).ConfigureAwait(false);
        UpdateRouteFromResult("onion-storage", targetKey, result);
        return _currentRoute;
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

        var routeResult = await PostRouterRpcWithEndpointAsync(
            "storage_route",
            new { targetKey },
            targetKey,
            cancellationToken).ConfigureAwait(false);
        UpdateRouteFromResult("onion-storage", targetKey, routeResult.Result);
        var route = _currentRoute?.Nodes ?? [];
        if (route.Count == 0)
        {
            throw new HttpRequestException("XNode did not return a storage onion route.");
        }

        var onion = OnionRouting.BuildStorageRequest(route, storagePath, body);
        var onionResult = await PostRouterRpcAsync(
            routeResult.RouterBaseUri,
            "onion_request",
            onion.Request,
            cancellationToken).ConfigureAwait(false);

        if (!onionResult.TryGetProperty("onionResponse", out var onionResponseElement))
        {
            throw new HttpRequestException("Deep onion route did not return an encrypted storage response.");
        }

        var onionResponse = onionResponseElement.Deserialize<OnionResponseEnvelope>(JsonOptions)
            ?? throw new HttpRequestException("Deep onion route returned an invalid encrypted response.");
        var decrypted = OnionRouting.DecryptResponse(onionResponse, onion.ResponsePrivateKey);
        if (decrypted.TryGetProperty("storageStatusCode", out var statusElement)
            && statusElement.TryGetInt32(out var statusCode)
            && statusCode is < 200 or > 299)
        {
            var error = decrypted.TryGetProperty("storageError", out var errorElement)
                ? errorElement.GetString()
                : $"storage-rpc-failed:{statusCode}";
            throw new HttpRequestException(error);
        }

        if (decrypted.TryGetProperty("storage", out var storage))
        {
            return storage.Clone();
        }

        return JsonSerializer.SerializeToElement(new { });
    }

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
        Exception? lastError = null;
        foreach (var routerBaseUri in OrderedRouterUris(targetKey))
        {
            try
            {
                return new RouterRpcResult(
                    routerBaseUri,
                    await PostRouterRpcAsync(routerBaseUri, method, payload, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
            {
                lastError = ex;
            }
        }

        throw new HttpRequestException("All configured XNodes failed.", lastError);
    }

    private async Task<JsonElement> PostRouterRpcAsync(
        Uri routerBaseUri,
        string method,
        object payload,
        CancellationToken cancellationToken)
    {
        var rpcUri = new Uri(routerBaseUri, _options.RpcPath.TrimStart('/'));
        var request = new RouterRpcRequest(Guid.NewGuid().ToString("N"), method, payload);
        using var response = await _httpClient.PostAsJsonAsync(rpcUri, request, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        var rpc = await response.Content.ReadFromJsonAsync<RouterRpcResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode || rpc is null || !rpc.Success || rpc.Result is null)
        {
            throw new HttpRequestException(rpc?.Error ?? $"router-rpc-failed:{(int)response.StatusCode}");
        }

        return rpc.Result.Value.Clone();
    }

    private IEnumerable<Uri> OrderedRouterUris(string targetKey)
    {
        var start = _routerBaseUris.Length == 1
            ? 0
            : SHA256.HashData(Encoding.UTF8.GetBytes(targetKey.Trim().ToLowerInvariant()))[0] % _routerBaseUris.Length;
        for (var i = 0; i < _routerBaseUris.Length; i++)
        {
            yield return _routerBaseUris[(start + i) % _routerBaseUris.Length];
        }
    }

    private void UpdateRouteFromResult(string mode, string targetKey, JsonElement result)
    {
        if (!result.TryGetProperty("route", out var routeElement) ||
            routeElement.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        var nodes = new List<TransportRouteNode>();
        foreach (var node in routeElement.EnumerateArray())
        {
            var index = node.TryGetProperty("index", out var indexElement) && indexElement.TryGetInt32(out var parsedIndex)
                ? parsedIndex
                : nodes.Count;
            var routerId = GetString(node, "routerId") ?? $"node-{index + 1}";
            var host = GetString(node, "publicHost") ?? "";
            var publicIp = GetString(node, "publicIp") ?? "";
            var port = node.TryGetProperty("publicPort", out var portElement) && portElement.TryGetInt32(out var parsedPort)
                ? parsedPort
                : 0;
            var endpoint = port > 0 && !string.IsNullOrWhiteSpace(host)
                ? $"{host}:{port}"
                : routerId;
            var x25519PublicKey = GetString(node, "x25519PublicKey") ?? "";
            var rpcEndpoint = GetString(node, "rpcEndpoint") ?? "";
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
            var signedAt = GetDateTimeOffset(node, "signedAt");
            var expiresAt = GetDateTimeOffset(node, "expiresAt");
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
                GetString(node, "signatureAlgorithm") ?? "",
                GetString(node, "signature") ?? "");
            if (!RelayContactSignatureVerifier.Verify(routeNode, DateTimeOffset.UtcNow))
            {
                throw new HttpRequestException($"Router returned an invalid signed relay contact for {routerId}.");
            }

            nodes.Add(routeNode);
        }

        if (nodes.Count > 0)
        {
            _currentRoute = new TransportRouteSnapshot(mode, targetKey, DateTimeOffset.UtcNow, nodes);
        }
    }

    private static string? GetString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private static DateTimeOffset GetDateTimeOffset(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var property)
            && property.ValueKind == JsonValueKind.String
            && property.TryGetDateTimeOffset(out var value)
                ? value
                : default;
    }

    private sealed record RouterRpcRequest(string Id, string Method, object Payload);

    private sealed record RouterRpcResponse(string Id, bool Success, JsonElement? Result, string? Error);

    private sealed record RouterRpcResult(Uri RouterBaseUri, JsonElement Result);
}

public sealed record RoutedSessionStorageTransportOptions(
    int Namespace = 0,
    int TtlMilliseconds = 14 * 24 * 60 * 60 * 1000);

public sealed class RoutedSessionStorageMessageTransport : ISessionMessageTransport
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly XNodeRpcClient _router;
    private readonly RoutedSessionStorageTransportOptions _options;
    private readonly ConcurrentDictionary<string, string> _lastHashes = new(StringComparer.Ordinal);

    public RoutedSessionStorageMessageTransport(
        XNodeRpcClient router,
        RoutedSessionStorageTransportOptions options)
    {
        _router = router;
        _options = options;
    }

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
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

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        _lastHashes.TryGetValue(recipient.Value, out var lastHash);
        var storage = await _router.PostStorageAsync("storage_retrieve", new
        {
            pubkey = recipient.Value,
            @namespace = _options.Namespace,
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            signature = "deep-client-storage-retrieve",
            last_hash = lastHash
        }, recipient.Value, cancellationToken).ConfigureAwait(false);

        var payload = storage.Deserialize<StorageRetrieveResponse>(JsonOptions) ?? new StorageRetrieveResponse([]);
        var envelopes = new List<InboundMessageEnvelope>();
        foreach (var stored in payload.Messages.OrderBy(static item => item.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(stored.Hash))
            {
                continue;
            }

            _lastHashes[recipient.Value] = stored.Hash;
            if (TryDecodePayload(stored, recipient, out var envelope))
            {
                envelopes.Add(envelope);
            }
        }

        return envelopes;
    }

    private static bool TryDecodePayload(
        StorageMessageDto stored,
        SessionId recipient,
        out InboundMessageEnvelope envelope)
    {
        envelope = default!;

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(stored.Data));
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

    private static string BuildIdempotencyKey(OutboundMessageEnvelope envelope, string payloadJson)
    {
        var material = string.Join('\n',
            envelope.Sender.Value,
            envelope.Recipient.Value,
            envelope.CreatedAt.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            payloadJson);
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

    private sealed record StorageRetrieveResponse(
        [property: JsonPropertyName("messages")] IReadOnlyList<StorageMessageDto> Messages);

    private sealed record StorageMessageDto(
        [property: JsonPropertyName("hash")] string Hash,
        [property: JsonPropertyName("timestamp")] long Timestamp,
        [property: JsonPropertyName("data")] string Data);
}
