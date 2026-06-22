using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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
        SessionId sessionId,
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
    string AvatarInfoPathFormat = "/avatar/{sessionId}/info");

public sealed class HttpAvatarProfileTransport : IAvatarProfileTransport
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient httpClient;
    private readonly HttpAvatarProfileTransportOptions options;

    public HttpAvatarProfileTransport(HttpClient httpClient, HttpAvatarProfileTransportOptions options)
    {
        this.httpClient = httpClient;
        this.options = options;

        if (string.IsNullOrWhiteSpace(this.options.BaseUrl))
        {
            throw new ArgumentException("Avatar transport base URL is required.", nameof(options));
        }

        if (this.httpClient.BaseAddress is null)
        {
            this.httpClient.BaseAddress = new Uri(this.options.BaseUrl.EndsWith('/')
                ? this.options.BaseUrl
                : this.options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public bool IsEnabled => true;

    public async Task<AvatarProfileMetadata> UploadAsync(
        SessionId sessionId,
        Stream content,
        string contentType,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);

        using var requestContent = new StreamContent(content);
        requestContent.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

        using var response = await httpClient.PutAsync(PathFor(options.AvatarPathFormat, sessionId), requestContent, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<AvatarProfileMetadataDto>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return payload?.ToMetadata()
            ?? throw new InvalidOperationException("Avatar upload response was empty.");
    }

    public async Task<AvatarProfileMetadata?> TryGetInfoAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(PathFor(options.AvatarInfoPathFormat, sessionId), cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<AvatarProfileMetadataDto>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return payload?.ToMetadata();
    }

    public async Task<AvatarProfileImage?> TryDownloadAsync(
        SessionId sessionId,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(PathFor(options.AvatarPathFormat, sessionId), cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        var contentType = response.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        var content = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return new AvatarProfileImage(contentType, content);
    }

    private static string PathFor(string pathFormat, SessionId sessionId) =>
        pathFormat.Replace("{sessionId}", Uri.EscapeDataString(sessionId.Value), StringComparison.Ordinal);

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
        SessionId sessionId,
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
