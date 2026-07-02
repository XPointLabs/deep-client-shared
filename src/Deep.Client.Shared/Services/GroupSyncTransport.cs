using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record OutboundGroupMessageEnvelope(
    MessageId Id,
    ConversationId GroupId,
    SessionId Sender,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public sealed record InboundGroupMessageEnvelope(
    MessageId Id,
    ConversationId GroupId,
    SessionId Sender,
    string Body,
    IReadOnlyList<AttachmentMetadata> Attachments,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    string ServerHash,
    MessageReply? ReplyTo = null,
    MessageReactionUpdate? Reaction = null);

public sealed record InboundGroupStateEnvelope(
    Group Group,
    DateTimeOffset UpdatedAt,
    string ServerHash);

public interface IGroupSyncTransport
{
    Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default);

    Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default);
}

public sealed class DisabledGroupSyncTransport : IGroupSyncTransport
{
    public Task PublishGroupStateAsync(
        Group group,
        DateTimeOffset updatedAt,
        IEnumerable<SessionId>? recipients = null,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>([]);

    public Task SendGroupMessageAsync(
        OutboundGroupMessageEnvelope envelope,
        CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>([]);
}

public sealed record SessionStorageGroupSyncTransportOptions(
    string BaseUrl,
    int GroupStateNamespace = 10,
    int GroupMessagesNamespace = -10,
    int TtlMilliseconds = 14 * 24 * 60 * 60 * 1000,
    string StorePath = "/storage/store",
    string RetrievePath = "/storage/retrieve");

public sealed class SessionStorageGroupSyncTransport : IGroupSyncTransport
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient httpClient;
    private readonly SessionStorageGroupSyncTransportOptions options;
    private readonly ConcurrentDictionary<string, string> stateLastHashes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> messageLastHashes = new(StringComparer.Ordinal);

    public SessionStorageGroupSyncTransport(HttpClient httpClient, SessionStorageGroupSyncTransportOptions options)
    {
        this.httpClient = httpClient;
        this.options = options;

        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            throw new ArgumentException("Storage base URL is required.", nameof(options));
        }

        if (httpClient.BaseAddress is null)
        {
            httpClient.BaseAddress = new Uri(options.BaseUrl.EndsWith('/')
                ? options.BaseUrl
                : options.BaseUrl + "/", UriKind.Absolute);
        }
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
            using var response = await PostJsonAsync(options.StorePath, new
            {
                pubkey = member.Value,
                @namespace = options.GroupStateNamespace,
                timestamp,
                ttl = options.TtlMilliseconds,
                data = payloadData,
                idempotency_key = BuildIdempotencyKey("group-state", member.Value, payloadJson)
            }, cancellationToken).ConfigureAwait(false);

            response.EnsureSuccessStatusCode();
        }
    }

    public async Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
        SessionId member,
        CancellationToken cancellationToken = default)
    {
        stateLastHashes.TryGetValue(member.Value, out var lastHash);
        var response = await RetrieveAsync(member.Value, options.GroupStateNamespace, lastHash, cancellationToken)
            .ConfigureAwait(false);

        var envelopes = new List<InboundGroupStateEnvelope>();
        foreach (var stored in response.Messages.OrderBy(static item => item.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(stored.Hash))
            {
                continue;
            }

            stateLastHashes[member.Value] = stored.Hash;
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
        var timestamp = envelope.CreatedAt.ToUnixTimeMilliseconds();

        using var response = await PostJsonAsync(options.StorePath, new
        {
            pubkey = envelope.GroupId.Value,
            @namespace = options.GroupMessagesNamespace,
            timestamp,
            ttl = options.TtlMilliseconds,
            data = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)),
            idempotency_key = BuildIdempotencyKey("group-message", envelope.GroupId.Value, payloadJson)
        }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
    }

    public async Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
        ConversationId groupId,
        CancellationToken cancellationToken = default)
    {
        messageLastHashes.TryGetValue(groupId.Value, out var lastHash);
        var response = await RetrieveAsync(groupId.Value, options.GroupMessagesNamespace, lastHash, cancellationToken)
            .ConfigureAwait(false);

        var envelopes = new List<InboundGroupMessageEnvelope>();
        foreach (var stored in response.Messages.OrderBy(static item => item.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(stored.Hash))
            {
                continue;
            }

            messageLastHashes[groupId.Value] = stored.Hash;
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
        using var response = CanRetrieveWithoutSignature(@namespace)
            ? await PostJsonAsync(options.RetrievePath, new
            {
                pubkey,
                @namespace,
                last_hash = lastHash
            }, cancellationToken).ConfigureAwait(false)
            : await PostJsonAsync(options.RetrievePath, new
            {
                pubkey,
                @namespace,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                signature = "deep-client-storage-group-sync",
                last_hash = lastHash
            }, cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<StorageRetrieveResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false) ?? new StorageRetrieveResponse([]);
    }

    private static bool CanRetrieveWithoutSignature(int @namespace) =>
        @namespace == -10 || (@namespace < 0 && (-@namespace % 20) == 1);

    private async Task<HttpResponseMessage> PostJsonAsync<TPayload>(
        string path,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await httpClient.PostAsync(path, content, cancellationToken).ConfigureAwait(false);
    }

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
