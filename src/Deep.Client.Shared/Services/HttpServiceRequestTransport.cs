using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Services;

public sealed record HttpServiceRequestTransportOptions(
    string BaseUrl,
    IReadOnlyList<string> AllowedPostPaths,
    string RequestMediaType,
    string ResponseMediaType,
    int MaximumRequestBytes,
    int MaximumResponseBytes,
    TimeSpan RequestTimeout,
    string? RequestCharset = null,
    string? ResponseCharset = null);

public enum HttpServiceRequestTransportError
{
    EndpointChanged = 1,
    UnexpectedMediaType = 2,
    ResponseTooLarge = 3,
    EmptyResponse = 4,
}

public sealed class HttpServiceRequestTransportException(
    HttpServiceRequestTransportError error,
    string message) : IOException(message)
{
    public HttpServiceRequestTransportError Error { get; } = error;
}

public sealed class HttpServiceResponse : IDisposable
{
    private byte[]? body;

    internal HttpServiceResponse(HttpStatusCode statusCode, byte[] body)
    {
        StatusCode = statusCode;
        this.body = body;
    }

    public HttpStatusCode StatusCode { get; }

    public ReadOnlyMemory<byte> Body => body is { } value
        ? value
        : throw new ObjectDisposedException(nameof(HttpServiceResponse));

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref body, null);
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Factory-owned, bounded POST transport for one configured HTTPS service origin.
/// It exposes neither its client nor its handler and accepts only a copied allow-list
/// of canonical paths.
/// </summary>
public sealed class HttpServiceRequestTransport : IDisposable
{
    private readonly HttpClient httpClient;
    private readonly IReadOnlyDictionary<string, Uri> allowedEndpoints;
    private readonly string requestMediaType;
    private readonly string responseMediaType;
    private readonly string? requestCharset;
    private readonly string? responseCharset;
    private readonly int maximumRequestBytes;
    private readonly int maximumResponseBytes;
    private readonly TimeSpan requestTimeout;
    private int disposed;

    internal HttpServiceRequestTransport(
        HttpClient httpClient,
        HttpServiceRequestTransportOptions options,
        HttpServiceEndpointPolicy endpointPolicy)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(endpointPolicy);
        if (options.MaximumRequestBytes <= 0 || options.MaximumResponseBytes <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(options), "HTTP request and response byte limits must be positive.");
        if (options.RequestTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(
                nameof(options), "HTTP request timeout must be positive.");
        if (options.AllowedPostPaths is null || options.AllowedPostPaths.Count == 0)
            throw new ArgumentException(
                "At least one HTTP POST path must be allowed.", nameof(options));

        requestMediaType = RequireMediaType(options.RequestMediaType, nameof(options.RequestMediaType));
        responseMediaType = RequireMediaType(options.ResponseMediaType, nameof(options.ResponseMediaType));
        requestCharset = RequireCharset(options.RequestCharset, nameof(options.RequestCharset));
        responseCharset = RequireCharset(options.ResponseCharset, nameof(options.ResponseCharset));
        maximumRequestBytes = options.MaximumRequestBytes;
        maximumResponseBytes = options.MaximumResponseBytes;
        requestTimeout = options.RequestTimeout;

        var origin = endpointPolicy.RequireServiceOrigin(options.BaseUrl, "HTTP request service base URL");
        var endpoints = new Dictionary<string, Uri>(StringComparer.Ordinal);
        foreach (var path in options.AllowedPostPaths)
        {
            var canonical = origin.RequirePath(path, "allowed HTTP POST path");
            if (!endpoints.TryAdd(canonical, origin.Build(canonical, "allowed HTTP POST endpoint")))
                throw new ArgumentException("Allowed HTTP POST paths must be unique.", nameof(options));
        }
        allowedEndpoints = endpoints;
    }

    public async ValueTask<HttpServiceResponse> PostAsync(
        string path,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        if (!allowedEndpoints.TryGetValue(path, out var endpoint))
            throw new ArgumentException("The HTTP POST path is not allowed by this transport.", nameof(path));
        if (body.IsEmpty || body.Length > maximumRequestBytes)
            throw new ArgumentOutOfRangeException(
                nameof(body), "The HTTP request body is outside its configured byte bound.");

        var requestBody = body.ToArray();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(responseMediaType));
            request.Content = new ByteArrayContent(requestBody);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(requestMediaType)
            {
                CharSet = requestCharset
            };

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(requestTimeout);
            try
            {
                using var response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token).ConfigureAwait(false);
                EnsureEndpoint(response, endpoint);
                if (response.StatusCode != HttpStatusCode.OK)
                    return new HttpServiceResponse(response.StatusCode, []);
                EnsureResponseSizeHeader(response.Content, maximumResponseBytes);
                EnsureResponseMediaType(response.Content.Headers.ContentType);
                var responseBody = await ReadBoundedAsync(
                    response.Content,
                    maximumResponseBytes,
                    timeout.Token).ConfigureAwait(false);
                return new HttpServiceResponse(response.StatusCode, responseBody);
            }
            catch (OperationCanceledException exception)
                when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    "The HTTP service request exceeded its bounded timeout.", exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBody);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            httpClient.Dispose();
    }

    private void EnsureResponseMediaType(MediaTypeHeaderValue? contentType)
    {
        if (!string.Equals(contentType?.MediaType, responseMediaType, StringComparison.OrdinalIgnoreCase)
            || responseCharset is null && !string.IsNullOrEmpty(contentType?.CharSet)
            || responseCharset is not null && contentType?.CharSet is { Length: > 0 } charset
                && !string.Equals(charset, responseCharset, StringComparison.OrdinalIgnoreCase))
        {
            throw Fail(
                HttpServiceRequestTransportError.UnexpectedMediaType,
                "The HTTP service response media type is invalid.");
        }
    }

    private static void EnsureEndpoint(HttpResponseMessage response, Uri expectedEndpoint)
    {
        if (response.RequestMessage?.RequestUri is not { } finalUri
            || Uri.Compare(
                finalUri,
                expectedEndpoint,
                UriComponents.AbsoluteUri,
                UriFormat.UriEscaped,
                StringComparison.Ordinal) != 0)
        {
            throw Fail(
                HttpServiceRequestTransportError.EndpointChanged,
                "The HTTP service request was redirected or changed endpoint.");
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > 0 and var declared && declared > maximumBytes)
            throw Fail(
                HttpServiceRequestTransportError.ResponseTooLarge,
                "The HTTP service response exceeded its configured byte bound.");

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(4096, maximumBytes));
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                if (output.Length + read > maximumBytes)
                    throw Fail(
                        HttpServiceRequestTransportError.ResponseTooLarge,
                        "The HTTP service response exceeded its configured byte bound.");
                output.Write(buffer, 0, read);
            }
            if (output.Length == 0)
                throw Fail(
                    HttpServiceRequestTransportError.EmptyResponse,
                    "The HTTP service response body is empty.");
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void EnsureResponseSizeHeader(HttpContent content, int maximumBytes)
    {
        if (content.Headers.ContentLength is { } declared && declared > maximumBytes)
        {
            throw Fail(
                HttpServiceRequestTransportError.ResponseTooLarge,
                "The HTTP service response exceeded its configured byte bound.");
        }
    }

    private static string RequireMediaType(string value, string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var parsed = new MediaTypeHeaderValue(value);
        if (parsed.Parameters.Count != 0 || !string.Equals(parsed.MediaType, value, StringComparison.Ordinal))
            throw new ArgumentException("HTTP media type must be canonical and parameter-free.", name);
        return value;
    }

    private static string? RequireCharset(string? value, string name)
    {
        if (value is null)
            return null;
        if (!string.Equals(value, "utf-8", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only the UTF-8 HTTP charset is supported.", name);
        return "utf-8";
    }

    private static HttpServiceRequestTransportException Fail(
        HttpServiceRequestTransportError error,
        string message) => new(error, message);
}
