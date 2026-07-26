using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record AvatarProfileMetadata(
    string SessionId,
    string FileId,
    string ContentType,
    long Size,
    DateTimeOffset UpdatedAt,
    DateTimeOffset ExpiresAt);

public sealed record AvatarProfileImage(string ContentType, byte[] Content);

public interface IAvatarProfileTransport
{
    bool IsEnabled { get; }

    Task<AvatarProfileMetadata> UploadAsync(
        SessionIdentityProvider identity,
        Stream content,
        string contentType,
        CancellationToken cancellationToken = default);

    Task<AvatarProfileMetadata?> TryGetInfoAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default);

    Task<AvatarProfileImage?> TryDownloadAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default);
}

public sealed record HttpAvatarProfileTransportOptions(
    string BaseUrl,
    string AvatarPathFormat = "/avatar/{sessionId}",
    string AvatarInfoPathFormat = "/avatar/{sessionId}/info",
    int MaxAvatarBytes = 1_500_000,
    int MaxMetadataBytes = 65_536,
    TimeSpan RequestFreshness = default);

public sealed class HttpAvatarProfileTransport : IAvatarProfileTransport, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient httpClient;
    private readonly HttpAvatarProfileTransportOptions options;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan requestFreshness;
    private readonly HttpServiceOrigin serviceOrigin;
    private readonly string avatarPathFormat;
    private readonly string avatarInfoPathFormat;

    internal HttpAvatarProfileTransport(
        HttpClient httpClient,
        HttpAvatarProfileTransportOptions options,
        TimeProvider? timeProvider = null,
        HttpServiceEndpointPolicy? endpointPolicy = null)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        requestFreshness = options.RequestFreshness == default
            ? TimeSpan.FromMinutes(5)
            : options.RequestFreshness;

        if (string.IsNullOrWhiteSpace(this.options.BaseUrl))
        {
            throw new ArgumentException("Avatar transport base URL is required.", nameof(options));
        }

        try
        {
            serviceOrigin = (endpointPolicy ?? HttpServiceEndpointPolicy.Production)
                .RequireServiceOrigin(this.options.BaseUrl, "Avatar transport base URL");
            avatarPathFormat = serviceOrigin.RequireTemplate(
                options.AvatarPathFormat,
                "Avatar resource path template",
                "sessionId");
            avatarInfoPathFormat = serviceOrigin.RequireTemplate(
                options.AvatarInfoPathFormat,
                "Avatar metadata path template",
                "sessionId");
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "Avatar transport base URL violates the configured endpoint policy.",
                nameof(options),
                exception);
        }

        if (options.MaxAvatarBytes is < 1 or > 16_000_000
            || options.MaxMetadataBytes is < 1_024 or > 1_048_576
            || requestFreshness <= TimeSpan.Zero
            || requestFreshness > TimeSpan.FromMinutes(15))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Avatar transport limits are invalid.");
        }
    }

    public bool IsEnabled => true;

    public void Dispose() => httpClient.Dispose();

    public async Task<AvatarProfileMetadata> UploadAsync(
        SessionIdentityProvider identity,
        Stream content,
        string contentType,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);

        var sessionId = identity.SessionId;
        var resource = PathFor(avatarPathFormat, sessionId);
        var path = resource.AbsolutePath;
        var bytes = await ReadBoundedAsync(content, options.MaxAvatarBytes, cancellationToken).ConfigureAwait(false);
        if (bytes.Length == 0)
        {
            throw new InvalidOperationException("Avatar content is empty.");
        }

        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var timestamp = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var ed25519PublicKey = Convert.ToHexString(identity.GetEd25519PublicKey()).ToLowerInvariant();
        var signingPayload = AvatarProfileAuthentication.BuildUploadPayload(
            path,
            sessionId,
            ed25519PublicKey,
            timestamp,
            nonce,
            digest);
        var signature = identity.SignDetached(signingPayload);

        using var request = new HttpRequestMessage(HttpMethod.Put, resource);
        using var requestContent = new ByteArrayContent(bytes);
        requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Content = requestContent;
        request.Headers.TryAddWithoutValidation("X-Deep-Session-Id", sessionId.Value);
        request.Headers.TryAddWithoutValidation("X-Deep-Ed25519", ed25519PublicKey);
        request.Headers.TryAddWithoutValidation(
            "X-Deep-Timestamp",
            timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation("X-Deep-Nonce", nonce);
        request.Headers.TryAddWithoutValidation("X-Deep-Content-Sha256", digest);
        request.Headers.TryAddWithoutValidation("X-Deep-Signature", Convert.ToBase64String(signature));

        using var response = await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var payload = await ReadJsonAsync<AvatarProfileMetadataDto>(
            response.Content,
            options.MaxMetadataBytes,
            cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Avatar upload response was empty.");
        var metadata = payload.ToMetadata();
        if (!string.Equals(metadata.SessionId, sessionId.Value, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Avatar upload response owner does not match the authenticated account.");
        }

        return metadata;
    }

    public async Task<AvatarProfileMetadata?> TryGetInfoAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(
            PathFor(avatarInfoPathFormat, sessionId),
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var payload = await ReadJsonAsync<AvatarProfileMetadataDto>(
            response.Content,
            options.MaxMetadataBytes,
            cancellationToken).ConfigureAwait(false);
        return payload?.ToMetadata();
    }

    public async Task<AvatarProfileImage?> TryDownloadAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(
            PathFor(avatarPathFormat, sessionId),
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var contentType = response.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        var content = await ReadBoundedAsync(response.Content, options.MaxAvatarBytes, cancellationToken)
            .ConfigureAwait(false);
        return new AvatarProfileImage(contentType, content);
    }

    private static async Task<T?> ReadJsonAsync<T>(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadBoundedAsync(content, maximumBytes, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 and var declaredLength && declaredLength > maximumBytes)
        {
            throw new HttpRequestException("Avatar response exceeds the configured byte limit.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        return await ReadBoundedAsync(stream, maximumBytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadBoundedAsync(
        Stream stream,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }

            if (output.Length + read > maximumBytes)
            {
                throw new HttpRequestException("Avatar content exceeds the configured byte limit.");
            }

            output.Write(buffer, 0, read);
        }
    }

    private Uri PathFor(string pathFormat, SessionId sessionId) =>
        serviceOrigin.Format(
            pathFormat,
            "sessionId",
            sessionId.Value,
            "Avatar resource");

    private sealed record AvatarProfileMetadataDto(
        string SessionId,
        string FileId,
        string ContentType,
        long Size,
        long Updated,
        long Expires)
    {
        public AvatarProfileMetadata ToMetadata() =>
            new(
                SessionId,
                FileId,
                ContentType,
                Size,
                DateTimeOffset.FromUnixTimeSeconds(Updated),
                DateTimeOffset.FromUnixTimeSeconds(Expires));
    }
}

public sealed class DisabledAvatarProfileTransport : IAvatarProfileTransport
{
    public bool IsEnabled => false;

    public Task<AvatarProfileMetadata> UploadAsync(
        SessionIdentityProvider identity,
        Stream content,
        string contentType,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Avatar profile transport is disabled.");

    public Task<AvatarProfileMetadata?> TryGetInfoAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<AvatarProfileMetadata?>(null);

    public Task<AvatarProfileImage?> TryDownloadAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<AvatarProfileImage?>(null);
}

public static class AvatarProfileAuthentication
{
    private const string Version = "deep-avatar-upload-v1";

    public static byte[] BuildUploadPayload(
        string path,
        SessionId sessionId,
        string ed25519PublicKey,
        long timestamp,
        string nonce,
        string contentSha256) =>
        Encoding.UTF8.GetBytes(string.Join('\n',
            Version,
            "PUT",
            path,
            sessionId.Value,
            ed25519PublicKey.ToLowerInvariant(),
            timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            nonce.ToLowerInvariant(),
            contentSha256.ToLowerInvariant()));
}
