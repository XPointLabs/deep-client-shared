using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

public sealed record OutboundMessageEnvelope(
    SessionId Sender,
    SessionId Recipient,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    MessageId? Id = null,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public sealed record InboundMessageEnvelope(
    MessageId Id,
    SessionId Sender,
    SessionId Recipient,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    string ServerHash,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public interface ISessionMessageTransport
{
    Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default);
}

public interface IRecoveryProfileLookup
{
    Task<string?> TryGetDisplayNameAsync(SessionId sessionId, CancellationToken cancellationToken = default);
}

public sealed record HttpSessionTransportOptions(
    string BaseUrl,
    string SendPath = "/api/messages/send",
    string InboxPathFormat = "/api/messages/inbox/{recipient}",
    string ProfilePathFormat = "/api/profiles/{sessionId}");

public sealed class HttpSessionTransport :
    ISessionMessageTransport,
    IRecoveryProfileLookup,
    IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly HttpSessionTransportOptions _options;
    private readonly HttpServiceOrigin _serviceOrigin;
    private readonly Uri _sendUri;
    private readonly string _inboxPathFormat;
    private readonly string _profilePathFormat;

    internal HttpSessionTransport(
        HttpClient httpClient,
        HttpSessionTransportOptions options,
        HttpServiceEndpointPolicy? endpointPolicy = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            throw new ArgumentException("Transport base URL is required.", nameof(options));
        }

        try
        {
            _serviceOrigin = (endpointPolicy ?? HttpServiceEndpointPolicy.Production)
                .RequireServiceOrigin(_options.BaseUrl, "Transport base URL");
            _sendUri = _serviceOrigin.Build(
                _serviceOrigin.RequirePath(_options.SendPath, "Session send path"),
                "Session send path");
            _inboxPathFormat = _serviceOrigin.RequireTemplate(
                _options.InboxPathFormat,
                "Session inbox path template",
                "recipient");
            _profilePathFormat = _serviceOrigin.RequireTemplate(
                _options.ProfilePathFormat,
                "Session profile path template",
                "sessionId");
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "Transport base URL violates the configured endpoint policy.",
                nameof(options),
                exception);
        }
    }

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.PostAsJsonAsync(_sendUri, new
        {
            id = envelope.Id?.Value,
            sender = envelope.Sender.Value,
            recipient = envelope.Recipient.Value,
            body = envelope.Body,
            attachments = envelope.Attachments,
            createdAt = envelope.CreatedAt,
            expiresAt = envelope.ExpiresAt,
            replyTo = envelope.ReplyTo,
            reaction = envelope.Reaction
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
    }

    public void Dispose() => _httpClient.Dispose();

    public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        var resource = _serviceOrigin.Format(
            _inboxPathFormat,
            "recipient",
            recipient.Value,
            "Session inbox resource");
        var payload = await _httpClient.GetFromJsonAsync<List<InboundMessageEnvelopeDto>>(resource, cancellationToken).ConfigureAwait(false)
            ?? [];

        return payload.Select(static item => new InboundMessageEnvelope(
            item.Id,
            item.Sender,
            item.Recipient,
            item.Body,
            item.Attachments,
            item.CreatedAt,
            item.ExpiresAt,
            item.ServerHash,
            item.ReplyTo,
            item.Reaction)).ToArray();
    }

    public async Task<string?> TryGetDisplayNameAsync(SessionId sessionId, CancellationToken cancellationToken = default)
    {
        var resource = _serviceOrigin.Format(
            _profilePathFormat,
            "sessionId",
            sessionId.Value,
            "Session profile resource");

        try
        {
            var payload = await _httpClient.GetFromJsonAsync<ProfileLookupDto>(resource, cancellationToken).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(payload?.DisplayName) ? null : payload.DisplayName.Trim();
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    private sealed record InboundMessageEnvelopeDto(
        MessageId Id,
        SessionId Sender,
        SessionId Recipient,
        string Body,
        IReadOnlyList<AttachmentMetadata> Attachments,
        DateTimeOffset CreatedAt,
        DateTimeOffset? ExpiresAt,
        string ServerHash,
        MessageReply? ReplyTo,
        MessageReactionUpdate? Reaction);

    private sealed record ProfileLookupDto(string? DisplayName);
}

public sealed record SessionStorageMessageTransportOptions(
    string BaseUrl,
    int Namespace = 0,
    int TtlMilliseconds = 14 * 24 * 60 * 60 * 1000,
    string StorePath = "/storage/store",
    string RetrievePath = "/storage/retrieve",
    SessionStorageMetadataMode MetadataMode = SessionStorageMetadataMode.OpaqueP03);

public sealed class SessionStorageMessageTransport :
    ISessionMessageTransport,
    IAuthenticatedInboxTransport,
    IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly SessionStorageMessageTransportOptions _options;
    private readonly OpaqueSessionStorageDependencies? _opaque;
    private readonly OpaqueInboxDecodeCache _opaqueDecodeCache = new();
    private readonly Uri _storeUri;
    private readonly Uri _retrieveUri;

    internal SessionStorageMessageTransport(
        HttpClient httpClient,
        SessionStorageMessageTransportOptions options,
        OpaqueSessionStorageDependencies? opaque = null,
        HttpServiceEndpointPolicy? endpointPolicy = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _opaque = opaque;

        if (_options.MetadataMode is not (
                SessionStorageMetadataMode.OpaqueP03 or
                SessionStorageMetadataMode.LegacyCompatibility))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The storage metadata mode is undefined.");
        }

        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            throw new ArgumentException("Storage base URL is required.", nameof(options));
        }

        try
        {
            var origin = (endpointPolicy ?? HttpServiceEndpointPolicy.Production)
                .RequireServiceOrigin(_options.BaseUrl, "Storage base URL");
            _storeUri = origin.Build(
                origin.RequirePath(_options.StorePath, "Storage deposit path"),
                "Storage deposit path");
            _retrieveUri = origin.Build(
                origin.RequirePath(_options.RetrievePath, "Storage retrieve path"),
                "Storage retrieve path");
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "Storage base URL violates the configured endpoint policy.",
                nameof(options),
                exception);
        }

        if (_options.MetadataMode == SessionStorageMetadataMode.OpaqueP03)
        {
            _opaque?.Validate();
            if (_opaque is null)
            {
                throw new InvalidOperationException(
                    "Opaque P03 storage requires explicit capability, crypto and replay dependencies.");
            }
        }
    }

    public bool UsesOpaqueMetadata => _options.MetadataMode == SessionStorageMetadataMode.OpaqueP03;

    public void Dispose() => _httpClient.Dispose();

    public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        if (UsesOpaqueMetadata)
        {
            var opaque = OpaqueSessionStorageCodec.EncodeDeposit(envelope, _options.TtlMilliseconds, _opaque!);
            using var opaqueResponse = await PostJsonAsync(_storeUri, new
            {
                deposit_capability = opaque.Capability,
                placement_key = opaque.PlacementKey,
                @namespace = _options.Namespace,
                attempt_id = opaque.AttemptId,
                idempotency_key = opaque.IdempotencyKey,
                data = opaque.Data
            }, cancellationToken).ConfigureAwait(false);
            opaqueResponse.EnsureSuccessStatusCode();
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
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var timestamp = envelope.CreatedAt.ToUnixTimeMilliseconds();
        var idempotencyKey = BuildIdempotencyKey(envelope, payloadJson);

        using var response = await PostJsonAsync(_storeUri, new
        {
            pubkey = envelope.Recipient.Value,
            @namespace = _options.Namespace,
            timestamp,
            ttl = _options.TtlMilliseconds,
            data = Convert.ToBase64String(payloadBytes),
            idempotency_key = idempotencyKey
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default) =>
        Task.FromException<IReadOnlyList<InboundMessageEnvelope>>(
            new InvalidOperationException("Storage inbox retrieval requires the account signing identity."));

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
            using var response = await PostJsonAsync(_retrieveUri, new
            {
                retrieve_capability = opaque.Capability,
                placement_key = opaque.PlacementKey,
                @namespace = _options.Namespace,
                attempt_id = opaque.AttemptId,
                last_hash = cursor
            }, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var payload = await response.Content.ReadFromJsonAsync<StorageRetrieveResponse>(JsonOptions, cancellationToken)
                .ConfigureAwait(false) ?? new StorageRetrieveResponse([]);
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
            using var response = await PostJsonAsync(_retrieveUri, new
            {
                pubkey = recipient.Value,
                pubkey_ed25519 = Convert.ToHexString(ed25519PublicKey).ToLowerInvariant(),
                @namespace = _options.Namespace,
                timestamp,
                signature = Convert.ToBase64String(signature),
                last_hash = cursor
            }, cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();
            var payload = await response.Content.ReadFromJsonAsync<StorageRetrieveResponse>(JsonOptions, cancellationToken)
                .ConfigureAwait(false) ?? new StorageRetrieveResponse([]);

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

    private async Task<HttpResponseMessage> PostJsonAsync<TPayload>(
        Uri resource,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await _httpClient.PostAsync(resource, content, cancellationToken).ConfigureAwait(false);
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

internal static class StorageSignatureCanonicalizer
{
    public static byte[] CreateRetrieve(int @namespace, long timestamp)
    {
        var namespaceValue = @namespace == 0
            ? string.Empty
            : @namespace.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Encoding.UTF8.GetBytes(
            $"retrieve{namespaceValue}{timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
    }
}

public sealed class StubSessionBackend : ISessionMessageTransport, IRecoveryProfileLookup
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<InboundMessageEnvelope>> inboxes = new(StringComparer.Ordinal);

    public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
    {
        var serverHash = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var inbound = new InboundMessageEnvelope(
            envelope.Id ?? MessageId.NewId(),
            envelope.Sender,
            envelope.Recipient,
            envelope.Body,
            envelope.Attachments,
            envelope.CreatedAt,
            envelope.ExpiresAt,
            serverHash,
            envelope.ReplyTo,
            envelope.Reaction);

        inboxes.GetOrAdd(envelope.Recipient.Value, _ => new ConcurrentQueue<InboundMessageEnvelope>()).Enqueue(inbound);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient, CancellationToken cancellationToken = default)
    {
        if (!inboxes.TryGetValue(recipient.Value, out var queue))
        {
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        }

        var result = new List<InboundMessageEnvelope>();
        while (queue.TryDequeue(out var item))
        {
            result.Add(item);
        }

        return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(result);
    }

    public Task<string?> TryGetDisplayNameAsync(SessionId sessionId, CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>(null);
}
