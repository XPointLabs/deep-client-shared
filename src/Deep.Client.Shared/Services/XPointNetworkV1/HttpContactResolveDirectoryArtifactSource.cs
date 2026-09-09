using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

internal sealed record HttpContactResolveDirectoryOptions(
    string BaseUrl,
    int MaximumResponseBytes = HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes);

internal sealed class HttpContactResolveDirectoryException : IOException
{
    internal HttpContactResolveDirectoryException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Bounded fail-closed HTTP transport for untrusted ContactResolve directory
/// artifacts. Protocol authority verification intentionally happens upstream.
/// </summary>
internal sealed class HttpContactResolveDirectoryArtifactSource :
    IContactResolveDirectoryArtifactSource,
    IDisposable
{
    public const string EndpointPath = "/api/v1/directory/contact-resolve-packages";
    public const string TargetedCurrentValueEndpointPath = "/api/v1/directory/current-values";

    private readonly HttpClient httpClient;
    private readonly IOnionMonotonicClock monotonicClock;
    private readonly Uri endpoint;
    private readonly Uri targetedCurrentValueEndpoint;
    private readonly int maximumResponseBytes;

    internal HttpContactResolveDirectoryArtifactSource(
        HttpClient httpClient,
        HttpContactResolveDirectoryOptions options,
        IOnionMonotonicClock monotonicClock)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        ArgumentNullException.ThrowIfNull(options);
        this.monotonicClock = monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));
        if (options.MaximumResponseBytes < 256
            || options.MaximumResponseBytes > HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes)
            throw new ArgumentOutOfRangeException(nameof(options), "The ContactResolve response byte limit is invalid.");
        maximumResponseBytes = options.MaximumResponseBytes;

        try
        {
            var origin = HttpServiceEndpointPolicy.Production.RequireServiceOrigin(
                options.BaseUrl, "ContactResolve directory base URL");
            endpoint = origin.Build(EndpointPath, "ContactResolve directory endpoint");
            targetedCurrentValueEndpoint = origin.Build(
                TargetedCurrentValueEndpointPath, "targeted current-value directory endpoint");
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException(
                "The ContactResolve directory base URL violates the endpoint policy.",
                nameof(options), exception);
        }
    }

    public async ValueTask<ContactResolveDirectoryArtifacts> FetchCurrentAsync(
        ContactResolveDirectoryFetchContext context,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        var created = await ReadClockAsync(cancellationToken).ConfigureAwait(false);
        var nonce = NewNonce();
        var targetedCurrentValue = !context.RequiredDirectoryLookupKey.IsEmpty;
        var selectedEndpoint = targetedCurrentValue ? targetedCurrentValueEndpoint : endpoint;
        var requestMediaType = targetedCurrentValue
            ? HttpTargetedCurrentValueDirectoryCodec.RequestMediaType
            : HttpContactResolveDirectoryCodec.RequestMediaType;
        var responseMediaType = targetedCurrentValue
            ? HttpTargetedCurrentValueDirectoryCodec.ResponseMediaType
            : HttpContactResolveDirectoryCodec.ResponseMediaType;
        var responseByteLimit = Math.Min(maximumResponseBytes, targetedCurrentValue
            ? HttpTargetedCurrentValueDirectoryCodec.AbsoluteMaximumEnvelopeBytes
            : HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes);
        byte[]? requestBytes = null;
        try
        {
            requestBytes = targetedCurrentValue
                ? HttpTargetedCurrentValueDirectoryCodec.EncodeRequest(context, nonce, created)
                : HttpContactResolveDirectoryCodec.EncodeRequest(context, nonce, created);
            using var request = new HttpRequestMessage(HttpMethod.Post, selectedEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                responseMediaType));
            request.Content = new ByteArrayContent(requestBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(requestMediaType);

            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            EnsureResponseHeaders(
                response, selectedEndpoint, responseMediaType, responseByteLimit, targetedCurrentValue);
            var responseBytes = await ReadExactBoundedAsync(
                response.Content, responseByteLimit, cancellationToken).ConfigureAwait(false);
            try
            {
                var received = await ReadClockAsync(cancellationToken).ConfigureAwait(false);
                var current = await ReadClockAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    return targetedCurrentValue
                        ? HttpTargetedCurrentValueDirectoryCodec.DecodeResponse(
                            responseBytes, context, nonce, created, received, current)
                        : HttpContactResolveDirectoryCodec.DecodeResponse(
                            responseBytes,
                            context.ExpectedNetworkId.Span,
                            nonce,
                            created,
                            received,
                            current);
                }
                catch (FormatException exception)
                {
                    throw Fail("invalid-envelope",
                        "The ContactResolve directory response is malformed or is not bound to this request.", exception);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBytes);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            if (requestBytes is not null)
                CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private int disposed;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            httpClient.Dispose();
    }

    private static void EnsureResponseHeaders(
        HttpResponseMessage response,
        Uri expectedEndpoint,
        string expectedMediaType,
        int responseByteLimit,
        bool targetedCurrentValue)
    {
        if (response.RequestMessage?.RequestUri is not { } finalUri
            || !Uri.Compare(finalUri, expectedEndpoint, UriComponents.AbsoluteUri,
                UriFormat.UriEscaped, StringComparison.Ordinal).Equals(0))
            throw Fail("endpoint-changed", "The ContactResolve directory request was redirected or changed endpoint.");
        if (targetedCurrentValue && response.StatusCode == HttpStatusCode.NotFound)
            throw Fail("target-not-found", "The directory target is unavailable without enumeration details.");
        if (targetedCurrentValue && response.StatusCode == HttpStatusCode.ServiceUnavailable)
            throw Fail("directory-unavailable", "The directory authority is temporarily unavailable.");
        if (response.StatusCode != HttpStatusCode.OK)
            throw Fail("unexpected-status", "The ContactResolve directory endpoint did not return HTTP 200.");

        var contentType = response.Content.Headers.ContentType;
        if (contentType is null
            || !string.Equals(contentType.MediaType,
                expectedMediaType,
                StringComparison.OrdinalIgnoreCase)
            || contentType.Parameters.Count != 0)
            throw Fail("unexpected-media-type", "The ContactResolve directory response media type is invalid.");

        if (response.Content.Headers.ContentLength is not { } contentLength)
            throw Fail("content-length-required", "The ContactResolve directory response requires Content-Length.");
        if (contentLength <= 0 || contentLength > responseByteLimit)
            throw Fail("response-too-large", "The ContactResolve directory response length is outside its bound.");
    }

    private static async Task<byte[]> ReadExactBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var declared = content.Headers.ContentLength
            ?? throw Fail("content-length-required", "The ContactResolve directory response requires Content-Length.");
        if (declared <= 0 || declared > maximumBytes
            || declared > HttpContactResolveDirectoryCodec.AbsoluteMaximumEnvelopeBytes)
            throw Fail("response-too-large", "The ContactResolve directory response length is outside its bound.");

        var bytes = new byte[checked((int)declared)];
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var offset = 0;
        try
        {
            while (offset < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(offset), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    throw Fail("truncated-response", "The ContactResolve directory response ended before Content-Length.");
                offset += read;
            }

            var extra = new byte[1];
            if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
                throw Fail("trailing-response", "The ContactResolve directory response exceeds Content-Length.");
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private async ValueTask<OnionMonotonicReading> ReadClockAsync(CancellationToken cancellationToken)
    {
        var reading = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false);
        return reading ?? throw Fail("monotonic-clock-invalid", "The local monotonic clock returned no reading.");
    }

    private static byte[] NewNonce()
    {
        var nonce = new byte[32];
        do RandomNumberGenerator.Fill(nonce);
        while (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return nonce;
    }

    private static HttpContactResolveDirectoryException Fail(
        string code, string message, Exception? inner = null) => new(code, message, inner);
}
