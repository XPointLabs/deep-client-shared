using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.DeepExtension.ManagedIngress;

namespace Deep.Client.Shared.Services;

public sealed class ClientMailboxDispatchOutcomeUnknownException : IOException
{
    public ClientMailboxDispatchOutcomeUnknownException(
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

internal sealed class PrivacyIngressRejectedBeforeForwardException : IOException
{
    internal PrivacyIngressRejectedBeforeForwardException(
        bool retryable,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Retryable = retryable;
    }

    internal bool Retryable { get; }
}

internal interface IPrivacyManagedIngressTransport : IDisposable
{
    Task<ReadOnlyMemory<byte>> ForwardAsync(
        ReadOnlyMemory<byte> opaqueFrame,
        CancellationToken cancellationToken);
}

internal sealed class PrivacyManagedIngressHttpTransport :
    IPrivacyManagedIngressTransport
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);
    private readonly HttpClient httpClient;
    private int disposed;

    internal PrivacyManagedIngressHttpTransport(
        Uri origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ValidateOrigin(origin);

        var handler = HttpServiceTransportFactory.CreateHttpHandler(
            new HttpServiceClientOptions(Timeout: RequestTimeout),
            networkHooks: null);
        handler.AutomaticDecompression = DecompressionMethods.None;
        httpClient = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = origin,
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    internal PrivacyManagedIngressHttpTransport(HttpClient httpClient)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (httpClient.BaseAddress is null)
        {
            throw new ArgumentException(
                "Privacy ingress HTTP client requires a base address.",
                nameof(httpClient));
        }

        ValidateOrigin(httpClient.BaseAddress);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            httpClient.Dispose();
        }
    }

    public async Task<ReadOnlyMemory<byte>> ForwardAsync(
        ReadOnlyMemory<byte> opaqueFrame,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ManagedIngressH2Contract.ValidateOpaqueFrame(opaqueFrame.Span);
        var requestBytes = opaqueFrame.ToArray();
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            deadline.CancelAfter(RequestTimeout);
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                ManagedIngressH2Contract.FramePath)
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(requestBytes)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType);

            HttpResponseMessage response;
            try
            {
                response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException exception)
            {
                throw Unknown(
                    "Privacy ingress outcome is unknown because dispatch was cancelled.",
                    exception);
            }
            catch (HttpRequestException exception) when (IsDefinitelyBeforeForward(exception))
            {
                throw new PrivacyIngressRejectedBeforeForwardException(
                    retryable: true,
                    "Privacy ingress was unreachable before the opaque frame could be forwarded.",
                    exception);
            }
            catch (Exception exception) when (
                exception is HttpRequestException or IOException or OperationCanceledException)
            {
                throw Unknown("Privacy ingress outcome is unknown after dispatch began.", exception);
            }

            using (response)
            {
                EnsureUnchangedOrigin(request, response);
                var declaredLength = response.Content.Headers.ContentLength;
                if (declaredLength is null ||
                    declaredLength < 0 ||
                    declaredLength > ManagedIngressLimits.MaximumOpaqueFrameBytes)
                {
                    throw Unknown("Privacy ingress returned an invalid response length.");
                }

                byte[] body;
                try
                {
                    body = await ReadExactBoundedAsync(
                        response.Content,
                        declaredLength.Value,
                        deadline.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException exception)
                {
                    throw Unknown(
                        "Privacy ingress outcome is unknown because response reading was cancelled.",
                        exception);
                }
                catch (Exception exception) when (exception is IOException or HttpRequestException)
                {
                    throw Unknown("Privacy ingress response was truncated.", exception);
                }

                var metadata = Metadata(response, body.Length);
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    if (ManagedIngressH2Contract.ClassifyFrameResponse(metadata, body) !=
                        ManagedIngressTransportResult.TransitCompleted)
                    {
                        throw Unknown("Privacy ingress success response is not canonical.");
                    }

                    return body;
                }

                var classification = ManagedIngressH2Contract.ClassifyErrorResponse(
                    metadata,
                    body);
                if (classification.Result == ManagedIngressTransportResult.RejectedBeforeForward &&
                    classification.Error is { } error)
                {
                    throw new PrivacyIngressRejectedBeforeForwardException(
                        error.Retryable,
                        "Privacy ingress rejected the request before forwarding.");
                }

                throw Unknown("Privacy ingress returned an outcome-unknown error.");
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private static void ValidateOrigin(Uri origin)
    {
        if (!origin.IsAbsoluteUri ||
            origin.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(origin.UserInfo) ||
            origin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(origin.Query) ||
            !string.IsNullOrEmpty(origin.Fragment))
        {
            throw new ArgumentException(
                "Privacy ingress requires a clean absolute HTTPS origin.",
                nameof(origin));
        }
    }

    private static bool IsDefinitelyBeforeForward(HttpRequestException exception) =>
        exception.HttpRequestError is
            HttpRequestError.NameResolutionError or
            HttpRequestError.SecureConnectionError or
            HttpRequestError.ProxyTunnelError;

    private static void EnsureUnchangedOrigin(
        HttpRequestMessage request,
        HttpResponseMessage response)
    {
        var expected = request.RequestUri;
        var actual = response.RequestMessage?.RequestUri;
        if (expected is null ||
            actual is null ||
            Uri.Compare(
                expected,
                actual,
                UriComponents.SchemeAndServer,
                UriFormat.SafeUnescaped,
                StringComparison.OrdinalIgnoreCase) != 0 ||
            !string.Equals(
                expected.PathAndQuery,
                actual.PathAndQuery,
                StringComparison.Ordinal))
        {
            throw Unknown("Privacy ingress redirected or changed origin.");
        }
    }

    private static ManagedIngressResponseMetadata Metadata(
        HttpResponseMessage response,
        int bodyLength)
    {
        var headers = new List<ManagedIngressHeader>();
        AddSupplemental(headers, response.Headers);
        AddSupplemental(headers, response.Content.Headers);
        return new ManagedIngressResponseMetadata(
            (int)response.StatusCode,
            response.Version,
            response.Content.Headers.ContentType?.ToString(),
            response.Content.Headers.ContentEncoding.Count == 0
                ? null
                : string.Join(",", response.Content.Headers.ContentEncoding),
            bodyLength,
            headers);
    }

    private static void AddSupplemental(
        ICollection<ManagedIngressHeader> destination,
        HttpHeaders source)
    {
        foreach (var header in source)
        {
            var name = header.Key.ToLowerInvariant();
            if (name is "content-type" or "content-length" or "content-encoding")
            {
                continue;
            }

            var values = header.Value.ToArray();
            destination.Add(new ManagedIngressHeader(
                name,
                values.Length == 1 ? values[0] : string.Join(",", values)));
        }
    }

    private static async Task<byte[]> ReadExactBoundedAsync(
        HttpContent content,
        long declaredLength,
        CancellationToken cancellationToken)
    {
        if (declaredLength > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            throw new InvalidDataException("Privacy ingress response exceeds its hostile bound.");
        }

        var expected = checked((int)declaredLength);
        var result = new byte[expected];
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var offset = 0;
        while (offset < expected)
        {
            var read = await stream.ReadAsync(
                result.AsMemory(offset, expected - offset),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Privacy ingress response is truncated.");
            }

            offset += read;
        }

        var probe = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            if (await stream.ReadAsync(probe.AsMemory(0, 1), cancellationToken)
                    .ConfigureAwait(false) != 0)
            {
                throw new InvalidDataException(
                    "Privacy ingress response exceeds its declared length.");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(probe, clearArray: true);
        }

        return result;
    }

    private static ClientMailboxDispatchOutcomeUnknownException Unknown(
        string message,
        Exception? exception = null) => new(message, exception);
}
