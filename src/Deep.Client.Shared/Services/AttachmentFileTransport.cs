using System.Net;
using System.Buffers;
using System.Buffers.Binary;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Client.Shared.Domain;

namespace Deep.Client.Shared.Services;

public sealed record AttachmentFileUpload(
    string FileName,
    string ContentType,
    Stream Content,
    int? Width = null,
    int? Height = null,
    TimeSpan? Duration = null,
    bool IsDocument = false);

public sealed record AttachmentFileDownload(
    string FileName,
    string ContentType,
    byte[] Content);

public sealed record AttachmentFileDownloadInfo(
    string FileName,
    string ContentType);

public interface IAttachmentFileTransport
{
    bool IsEnabled { get; }

    Task<AttachmentMetadata> UploadAsync(
        AttachmentFileUpload upload,
        CancellationToken cancellationToken = default);

    Task<AttachmentFileDownload> DownloadAsync(
        AttachmentMetadata metadata,
        CancellationToken cancellationToken = default);

    Task<AttachmentFileDownloadInfo> DownloadToAsync(
        AttachmentMetadata metadata,
        Stream destination,
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
    private const int ChunkSizeBytes = 64 * 1024;
    private const long MaxAttachmentPlainBytes = 25L * 1024 * 1024;
    private const long MaxAttachmentEncryptedBytes = MaxAttachmentPlainBytes + 64 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly byte[] ChunkedPayloadMagic = Encoding.ASCII.GetBytes("DEEPATT2");

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

        var key = RandomNumberGenerator.GetBytes(KeySizeBytes);
        var tempPath = Path.Combine(Path.GetTempPath(), $"deep-attachment-{Guid.NewGuid():N}.bin");
        AttachmentEncryptionResult encrypted;
        await using (var encryptedOutput = File.Create(tempPath))
        {
            encrypted = await EncryptChunkedToAsync(upload.Content, encryptedOutput, key, cancellationToken).ConfigureAwait(false);
        }

        if (encrypted.PlainLength == 0)
        {
            TryDelete(tempPath);
            throw new InvalidOperationException("Attachment upload content is empty.");
        }

        try
        {
            await using var encryptedInput = File.OpenRead(tempPath);
            using var content = new StreamContent(encryptedInput);
            content.Headers.ContentType = new("application/octet-stream");
            content.Headers.ContentLength = encryptedInput.Length;

            using var request = new HttpRequestMessage(HttpMethod.Post, options.UploadPath)
            {
                Content = content,
                Version = HttpVersion.Version11,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            request.Headers.ExpectContinue = false;

            using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
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
                encrypted.PlainLength,
                new Uri(httpClient.BaseAddress!, PathFor(payload.Id)),
                Convert.ToBase64String(key),
                encrypted.DigestBase64,
                upload.Width,
                upload.Height,
                upload.Duration,
                upload.IsDocument);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    public async Task<AttachmentFileDownload> DownloadAsync(
        AttachmentMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        using var memory = new MemoryStream();
        var info = await DownloadToAsync(metadata, memory, cancellationToken).ConfigureAwait(false);
        return new AttachmentFileDownload(info.FileName, info.ContentType, memory.ToArray());
    }

    public async Task<AttachmentFileDownloadInfo> DownloadToAsync(
        AttachmentMetadata metadata,
        Stream destination,
        CancellationToken cancellationToken = default)
    {
        if (metadata.RemoteUri is null)
        {
            throw new InvalidOperationException("Attachment metadata does not include a remote URI.");
        }

        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("Destination stream must be writable.", nameof(destination));
        }

        using var response = await httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, metadata.RemoteUri),
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw new FileNotFoundException("Remote attachment file was not found.", metadata.RemoteUri.ToString());
        }

        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxAttachmentEncryptedBytes)
        {
            throw new InvalidOperationException("Remote attachment exceeds the maximum supported size.");
        }

        await using var remote = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (string.IsNullOrWhiteSpace(metadata.EncryptionKeyBase64))
        {
            await CopyWithDigestAsync(remote, destination, hash, metadata.SizeBytes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var key = Convert.FromBase64String(metadata.EncryptionKeyBase64);
            await DecryptToAsync(remote, destination, key, hash, metadata.SizeBytes, cancellationToken).ConfigureAwait(false);
        }

        VerifyDigest(metadata, hash.GetHashAndReset());
        return new AttachmentFileDownloadInfo(metadata.FileName, metadata.ContentType);
    }

    private string PathFor(string fileId) =>
        options.DownloadPathFormat.Replace("{fileId}", Uri.EscapeDataString(fileId), StringComparison.Ordinal);

    private static async Task<AttachmentEncryptionResult> EncryptChunkedToAsync(
        Stream plainInput,
        Stream encryptedOutput,
        byte[] key,
        CancellationToken cancellationToken)
    {
        await encryptedOutput.WriteAsync(ChunkedPayloadMagic, cancellationToken).ConfigureAwait(false);
        using var aes = new AesGcm(key, TagSizeBytes);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var plainBuffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        var headerBuffer = ArrayPool<byte>.Shared.Rent(sizeof(int) + NonceSizeBytes + TagSizeBytes);
        long total = 0;
        try
        {
            while (true)
            {
                var read = await plainInput.ReadAsync(plainBuffer.AsMemory(0, ChunkSizeBytes), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > MaxAttachmentPlainBytes)
                {
                    throw new InvalidOperationException("Attachment upload exceeds the maximum supported size.");
                }

                var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
                var header = headerBuffer.AsSpan(0, sizeof(int) + NonceSizeBytes + TagSizeBytes);
                BinaryPrimitives.WriteInt32BigEndian(header[..sizeof(int)], read);
                nonce.CopyTo(header.Slice(sizeof(int), NonceSizeBytes));

                var tag = header.Slice(sizeof(int) + NonceSizeBytes, TagSizeBytes);
                var plain = plainBuffer.AsSpan(0, read);
                var cipher = cipherBuffer.AsSpan(0, read);
                aes.Encrypt(nonce, plain, cipher, tag);
                hash.AppendData(plain);

                await encryptedOutput.WriteAsync(headerBuffer.AsMemory(0, header.Length), cancellationToken).ConfigureAwait(false);
                await encryptedOutput.WriteAsync(cipherBuffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            return new AttachmentEncryptionResult(total, Convert.ToBase64String(hash.GetHashAndReset()));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(plainBuffer);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
            ArrayPool<byte>.Shared.Return(headerBuffer);
        }
    }

    private static async Task DecryptToAsync(
        Stream encryptedInput,
        Stream plainOutput,
        byte[] key,
        IncrementalHash hash,
        long expectedPlainLength,
        CancellationToken cancellationToken)
    {
        var prefix = new byte[ChunkedPayloadMagic.Length];
        var prefixBytes = await ReadUpToAsync(encryptedInput, prefix, cancellationToken).ConfigureAwait(false);
        if (prefixBytes == ChunkedPayloadMagic.Length && prefix.SequenceEqual(ChunkedPayloadMagic))
        {
            await DecryptChunkedToAsync(encryptedInput, plainOutput, key, hash, expectedPlainLength, cancellationToken).ConfigureAwait(false);
            return;
        }

        using var legacyPayload = new MemoryStream();
        legacyPayload.Write(prefix, 0, prefixBytes);
        await CopyWithLimitAsync(encryptedInput, legacyPayload, MaxAttachmentEncryptedBytes - prefixBytes, cancellationToken).ConfigureAwait(false);
        var plain = DecryptLegacy(legacyPayload.ToArray(), key);
        if (expectedPlainLength > 0 && plain.LongLength != expectedPlainLength)
        {
            throw new CryptographicException("Attachment length verification failed.");
        }

        hash.AppendData(plain);
        await plainOutput.WriteAsync(plain, cancellationToken).ConfigureAwait(false);
    }

    private static async Task DecryptChunkedToAsync(
        Stream encryptedInput,
        Stream plainOutput,
        byte[] key,
        IncrementalHash hash,
        long expectedPlainLength,
        CancellationToken cancellationToken)
    {
        using var aes = new AesGcm(key, TagSizeBytes);
        var header = ArrayPool<byte>.Shared.Rent(sizeof(int) + NonceSizeBytes + TagSizeBytes);
        var cipherBuffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        var plainBuffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        long total = 0;
        try
        {
            while (true)
            {
                var length = await ReadChunkLengthAsync(encryptedInput, header, cancellationToken).ConfigureAwait(false);
                if (length is null)
                {
                    break;
                }

                if (length <= 0 || length > ChunkSizeBytes)
                {
                    throw new CryptographicException("Encrypted attachment chunk is malformed.");
                }

                await ReadExactAsync(
                    encryptedInput,
                    header.AsMemory(sizeof(int), NonceSizeBytes + TagSizeBytes),
                    cancellationToken).ConfigureAwait(false);
                await ReadExactAsync(encryptedInput, cipherBuffer.AsMemory(0, length.Value), cancellationToken).ConfigureAwait(false);

                var nonce = header.AsSpan(sizeof(int), NonceSizeBytes);
                var tag = header.AsSpan(sizeof(int) + NonceSizeBytes, TagSizeBytes);
                aes.Decrypt(nonce, cipherBuffer.AsSpan(0, length.Value), tag, plainBuffer.AsSpan(0, length.Value));

                total += length.Value;
                if (total > MaxAttachmentPlainBytes || (expectedPlainLength > 0 && total > expectedPlainLength))
                {
                    throw new InvalidOperationException("Remote attachment exceeds the maximum supported size.");
                }

                hash.AppendData(plainBuffer.AsSpan(0, length.Value));
                await plainOutput.WriteAsync(plainBuffer.AsMemory(0, length.Value), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
            ArrayPool<byte>.Shared.Return(cipherBuffer);
            ArrayPool<byte>.Shared.Return(plainBuffer);
        }

        if (expectedPlainLength > 0 && total != expectedPlainLength)
        {
            throw new CryptographicException("Attachment length verification failed.");
        }
    }

    private static byte[] DecryptLegacy(byte[] payload, byte[] key)
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

    private static async Task CopyWithDigestAsync(
        Stream source,
        Stream destination,
        IncrementalHash hash,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        long total = 0;
        try
        {
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > MaxAttachmentPlainBytes || (expectedLength > 0 && total > expectedLength))
                {
                    throw new InvalidOperationException("Remote attachment exceeds the maximum supported size.");
                }

                hash.AppendData(buffer.AsSpan(0, read));
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (expectedLength > 0 && total != expectedLength)
        {
            throw new CryptographicException("Attachment length verification failed.");
        }
    }

    private static async Task CopyWithLimitAsync(
        Stream source,
        Stream destination,
        long remainingBytes,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(ChunkSizeBytes);
        try
        {
            while (true)
            {
                if (remainingBytes <= 0)
                {
                    var probe = await source.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
                    if (probe == 0)
                    {
                        break;
                    }

                    throw new InvalidOperationException("Remote attachment exceeds the maximum supported size.");
                }

                var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remainingBytes)), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                remainingBytes -= read;
                if (remainingBytes < 0)
                {
                    throw new InvalidOperationException("Remote attachment exceeds the maximum supported size.");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<int?> ReadChunkLengthAsync(Stream stream, byte[] headerBuffer, CancellationToken cancellationToken)
    {
        var firstByte = new byte[1];
        var read = await stream.ReadAsync(firstByte, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        headerBuffer[0] = firstByte[0];
        await ReadExactAsync(stream, headerBuffer.AsMemory(1, sizeof(int) - 1), cancellationToken).ConfigureAwait(false);
        return BinaryPrimitives.ReadInt32BigEndian(headerBuffer.AsSpan(0, sizeof(int)));
    }

    private static async Task<int> ReadUpToAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        return offset;
    }

    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Encrypted attachment payload ended unexpectedly.");
            }

            offset += read;
        }
    }

    private static void VerifyDigest(AttachmentMetadata metadata, byte[] actualDigest)
    {
        if (string.IsNullOrWhiteSpace(metadata.DigestBase64))
        {
            return;
        }

        var expected = Convert.FromBase64String(metadata.DigestBase64);
        if (!CryptographicOperations.FixedTimeEquals(expected, actualDigest))
        {
            throw new CryptographicException("Attachment digest verification failed.");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private sealed record FileUploadResponse(
        [property: JsonPropertyName("id")] string? Id,
        [property: JsonPropertyName("expires")] long Expires);

    private sealed record AttachmentEncryptionResult(long PlainLength, string DigestBase64);
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

    public Task<AttachmentFileDownloadInfo> DownloadToAsync(
        AttachmentMetadata metadata,
        Stream destination,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Attachment file transport is disabled.");
}
