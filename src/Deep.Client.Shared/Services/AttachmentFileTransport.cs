using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record AttachmentFileUpload(
    string FileName,
    string ContentType,
    Stream Content);

public sealed record AttachmentFileDownload(
    string FileName,
    string ContentType,
    byte[] Content);

public interface IAttachmentFileTransport
{
    bool IsEnabled { get; }

    Task<AttachmentMetadata> UploadAsync(
        AttachmentFileUpload upload,
        CancellationToken cancellationToken = default);

    Task<AttachmentFileDownload> DownloadAsync(
        AttachmentMetadata metadata,
        CancellationToken cancellationToken = default);
}

public sealed record HttpAttachmentFileTransportOptions(
    string BaseUrl,
    string UploadPath = "/file",
    string DownloadPathFormat = "/file/{fileId}");

public sealed class HttpAttachmentFileTransport : IAttachmentFileTransport
{
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient httpClient;
    private readonly HttpAttachmentFileTransportOptions options;

    public HttpAttachmentFileTransport(HttpClient httpClient, HttpAttachmentFileTransportOptions options)
    {
        this.httpClient = httpClient;
        this.options = options;

        if (string.IsNullOrWhiteSpace(options.BaseUrl))
        {
            throw new ArgumentException("Attachment file transport base URL is required.", nameof(options));
        }

        if (this.httpClient.BaseAddress is null)
        {
            this.httpClient.BaseAddress = new Uri(options.BaseUrl.EndsWith('/')
                ? options.BaseUrl
                : options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public bool IsEnabled => true;

    public async Task<AttachmentMetadata> UploadAsync(
        AttachmentFileUpload upload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(upload);
        ArgumentNullException.ThrowIfNull(upload.Content);
        ArgumentException.ThrowIfNullOrWhiteSpace(upload.FileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(upload.ContentType);

        var plain = await ReadAllBytesAsync(upload.Content, cancellationToken).ConfigureAwait(false);
        if (plain.Length == 0)
        {
            throw new InvalidOperationException("Attachment upload content is empty.");
        }

        var key = RandomNumberGenerator.GetBytes(KeySizeBytes);
        var encrypted = Encrypt(plain, key);
        using var content = new ByteArrayContent(encrypted);
        content.Headers.ContentType = new("application/octet-stream");

        using var response = await httpClient.PostAsync(options.UploadPath, content, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<FileUploadResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(payload?.Id))
        {
            throw new InvalidOperationException("Attachment upload response did not include a file id.");
        }

        return new AttachmentMetadata(
            payload.Id,
            Path.GetFileName(upload.FileName),
            upload.ContentType,
            plain.Length,
            new Uri(httpClient.BaseAddress!, PathFor(payload.Id)),
            Convert.ToBase64String(key),
            Convert.ToBase64String(SHA256.HashData(plain)));
    }

    public async Task<AttachmentFileDownload> DownloadAsync(
        AttachmentMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        if (metadata.RemoteUri is null)
        {
            throw new InvalidOperationException("Attachment metadata does not include a remote URI.");
        }

        using var response = await httpClient.GetAsync(metadata.RemoteUri, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw new FileNotFoundException("Remote attachment file was not found.", metadata.RemoteUri.ToString());
        }

        response.EnsureSuccessStatusCode();
        var remoteBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var content = string.IsNullOrWhiteSpace(metadata.EncryptionKeyBase64)
            ? remoteBytes
            : Decrypt(remoteBytes, Convert.FromBase64String(metadata.EncryptionKeyBase64));

        if (!string.IsNullOrWhiteSpace(metadata.DigestBase64))
        {
            var actualDigest = Convert.ToBase64String(SHA256.HashData(content));
            if (!string.Equals(actualDigest, metadata.DigestBase64, StringComparison.Ordinal))
            {
                throw new CryptographicException("Attachment digest verification failed.");
            }
        }

        return new AttachmentFileDownload(metadata.FileName, metadata.ContentType, content);
    }

    private string PathFor(string fileId) =>
        options.DownloadPathFormat.Replace("{fileId}", Uri.EscapeDataString(fileId), StringComparison.Ordinal);

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory, cancellationToken).ConfigureAwait(false);
        return memory.ToArray();
    }

    private static byte[] Encrypt(byte[] plain, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var tag = new byte[TagSizeBytes];
        var cipher = new byte[plain.Length];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, plain, cipher, tag);

        var payload = new byte[NonceSizeBytes + TagSizeBytes + cipher.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, payload, NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(cipher, 0, payload, NonceSizeBytes + TagSizeBytes, cipher.Length);
        return payload;
    }

    private static byte[] Decrypt(byte[] payload, byte[] key)
    {
        if (payload.Length <= NonceSizeBytes + TagSizeBytes)
        {
            throw new CryptographicException("Encrypted attachment payload is malformed.");
        }

        var nonce = payload[..NonceSizeBytes];
        var tag = payload[NonceSizeBytes..(NonceSizeBytes + TagSizeBytes)];
        var cipher = payload[(NonceSizeBytes + TagSizeBytes)..];
        var plain = new byte[cipher.Length];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private sealed record FileUploadResponse(
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("expires")] long Expires);
}

public sealed class DisabledAttachmentFileTransport : IAttachmentFileTransport
{
    public bool IsEnabled => false;

    public Task<AttachmentMetadata> UploadAsync(
        AttachmentFileUpload upload,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Attachment file transport is disabled.");

    public Task<AttachmentFileDownload> DownloadAsync(
        AttachmentMetadata metadata,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Attachment file transport is disabled.");
}
