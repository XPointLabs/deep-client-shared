using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

public enum ClientMailboxTransportFailure
{
    MalformedRequest = 1,
    AuthenticationRejected = 2,
    AuthorizationRejected = 3,
    ConflictOrExpired = 4,
    PayloadTooLarge = 5,
    UnsupportedMediaType = 6,
    Throttled = 7,
    DependencyUnavailable = 8,
    DeadlineExceeded = 9,
    MethodRejected = 10,
    LengthRequired = 11,
    ProtocolViolation = 12,
    NetworkUnavailable = 13
}

public sealed class ClientMailboxTransportException : IOException
{
    public ClientMailboxTransportException(
        ClientMailboxTransportFailure failure,
        bool retryable,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        if (!Enum.IsDefined(failure))
        {
            throw new ArgumentOutOfRangeException(nameof(failure));
        }

        Failure = failure;
        Retryable = retryable;
    }

    public ClientMailboxTransportFailure Failure { get; }

    public bool Retryable { get; }
}

/// <summary>
/// Sends only exact native MAU2 request frames to the three mailbox-v2 client routes.
/// The ingress never synthesizes an older request body and never accepts a response
/// with a different status, media type, frame length, canonical encoding, or binding.
/// Production construction owns a no-redirect handler and composes platform TLS
/// validation with an explicit SPKI pin set.
/// </summary>
public sealed class ClientMailboxTlsSpkiPinSet
{
    private readonly byte[][] pins;

    public ClientMailboxTlsSpkiPinSet(
        params ReadOnlyMemory<byte>[] sha256Pins)
    {
        ArgumentNullException.ThrowIfNull(sha256Pins);
        if (sha256Pins.Length is 0 or > 16 ||
            sha256Pins.Any(pin =>
                pin.Length != SHA256.HashSizeInBytes ||
                pin.Span.IndexOfAnyExcept((byte)0) < 0))
        {
            throw new ArgumentException(
                "Mailbox TLS pin set must contain 1-16 nonzero SHA-256 SPKI pins.",
                nameof(sha256Pins));
        }

        pins = sha256Pins.Select(static pin => pin.ToArray()).ToArray();
    }

    internal bool Matches(X509Certificate2 certificate)
    {
        var spki = ExportSubjectPublicKeyInfo(certificate);
        try
        {
            var digest = SHA256.HashData(spki);
            try
            {
                return pins.Any(pin =>
                    CryptographicOperations.FixedTimeEquals(pin, digest));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(digest);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(spki);
        }
    }

    public override string ToString() => "[configured-mailbox-tls-spki-pins]";

    private static byte[] ExportSubjectPublicKeyInfo(
        X509Certificate2 certificate)
    {
        using (var rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                return rsa.ExportSubjectPublicKeyInfo();
            }
        }
        using (var ecdsa = certificate.GetECDsaPublicKey())
        {
            if (ecdsa is not null)
            {
                return ecdsa.ExportSubjectPublicKeyInfo();
            }
        }
        using (var dsa = certificate.GetDSAPublicKey())
        {
            if (dsa is not null)
            {
                return dsa.ExportSubjectPublicKeyInfo();
            }
        }

        throw new CryptographicException(
            "Mailbox TLS certificate public-key algorithm is unsupported.");
    }
}

public sealed class HttpClientMailboxBinaryIngress :
    IClientMailboxBinaryIngress,
    IDisposable
{
    private readonly HttpClient httpClient;
    private readonly MailboxClientDecodePolicy decodePolicy;
    private readonly TimeSpan? requestTimeoutOverride;

    private HttpClientMailboxBinaryIngress(
        HttpClient httpClient,
        MailboxClientDecodePolicy decodePolicy)
        : this(httpClient, decodePolicy, requestTimeoutOverride: null)
    {
    }

    private HttpClientMailboxBinaryIngress(
        HttpClient httpClient,
        MailboxClientDecodePolicy decodePolicy,
        TimeSpan? requestTimeoutOverride)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        this.decodePolicy = decodePolicy ?? throw new ArgumentNullException(nameof(decodePolicy));
        if (requestTimeoutOverride is { } timeout &&
            (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1)))
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeoutOverride));
        }
        this.requestTimeoutOverride = requestTimeoutOverride;
        if (httpClient.BaseAddress is null ||
            !httpClient.BaseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException(
                "Mailbox HTTP ingress requires an absolute base address.",
                nameof(httpClient));
        }
    }

    public static HttpClientMailboxBinaryIngress CreateProduction(
        Uri baseAddress,
        MailboxClientDecodePolicy decodePolicy,
        ClientMailboxTlsSpkiPinSet pins)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(decodePolicy);
        ArgumentNullException.ThrowIfNull(pins);
        if (!baseAddress.IsAbsoluteUri ||
            baseAddress.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(baseAddress.UserInfo) ||
            baseAddress.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(baseAddress.Query) ||
            !string.IsNullOrEmpty(baseAddress.Fragment))
        {
            throw new ArgumentException(
                "Production mailbox ingress requires a clean absolute HTTPS origin.",
                nameof(baseAddress));
        }

        var handler = CreateHandler();
        handler.SslOptions.RemoteCertificateValidationCallback =
            (_, certificate, _, errors) =>
                ValidatePinnedCertificate(pins, certificate, errors);
        return CreateOwned(baseAddress, decodePolicy, handler);
    }

    public static HttpClientMailboxBinaryIngress CreateLoopbackDevelopment(
        Uri baseAddress,
        MailboxClientDecodePolicy decodePolicy)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(decodePolicy);
        if (!baseAddress.IsAbsoluteUri ||
            baseAddress.Scheme != Uri.UriSchemeHttp ||
            !baseAddress.IsLoopback ||
            !string.IsNullOrEmpty(baseAddress.UserInfo) ||
            baseAddress.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(baseAddress.Query) ||
            !string.IsNullOrEmpty(baseAddress.Fragment))
        {
            throw new ArgumentException(
                "Cleartext mailbox ingress is restricted to explicit loopback development.",
                nameof(baseAddress));
        }

        return CreateOwned(baseAddress, decodePolicy, CreateHandler());
    }

    /// <summary>
    /// Friend-assembly-only physical E2E lane. The exact private-LAN origin is intentionally
    /// fixed so a runtime setting cannot turn this into a general cleartext transport.
    /// Release composition never calls this entry point.
    /// </summary>
    internal static HttpClientMailboxBinaryIngress CreatePhysicalDevelopment(
        Uri baseAddress,
        MailboxClientDecodePolicy decodePolicy)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(decodePolicy);
        if (baseAddress != new Uri("http://192.168.1.44:41801/"))
        {
            throw new ArgumentException(
                "Physical mailbox HTTP is restricted to the exact DEV-local coordinator.",
                nameof(baseAddress));
        }

        return CreateOwned(baseAddress, decodePolicy, CreateHandler());
    }

    public void Dispose() => httpClient.Dispose();

    private static SocketsHttpHandler CreateHandler() =>
        new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false
        };

    private static bool ValidatePinnedCertificate(
        ClientMailboxTlsSpkiPinSet pins,
        X509Certificate? certificate,
        SslPolicyErrors errors)
    {
        if (certificate is null || errors != SslPolicyErrors.None)
        {
            return false;
        }

        try
        {
            using var certificate2 = new X509Certificate2(certificate);
            return pins.Matches(certificate2);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static HttpClientMailboxBinaryIngress CreateOwned(
        Uri baseAddress,
        MailboxClientDecodePolicy decodePolicy,
        HttpMessageHandler handler) =>
        new(
            new HttpClient(handler, disposeHandler: true)
            {
                BaseAddress = baseAddress
            },
            decodePolicy);

    public Task<ReadOnlyMemory<byte>> StoreAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Store,
            MailboxWireHttpContract.Store,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Retrieve,
            MailboxWireHttpContract.Retrieve,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Ack,
            MailboxWireHttpContract.Acknowledge,
            cancellationToken);

    private async Task<ReadOnlyMemory<byte>> SendAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        MailboxAuthenticatedOperation operation,
        MailboxHttpEndpointContract contract,
        CancellationToken cancellationToken)
    {
        var requestBytes = canonicalMau2.ToArray();
        try
        {
            ValidateRequest(requestBytes, operation, contract);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(
                requestTimeoutOverride ??
                TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
            try
            {
                using var request = new HttpRequestMessage(
                    HttpMethod.Post,
                    contract.Route);
                request.Headers.Accept.Add(
                    new MediaTypeWithQualityHeaderValue(contract.ResponseContentType));
                request.Content = new ByteArrayContent(requestBytes);
                request.Content.Headers.ContentType =
                    new MediaTypeHeaderValue(contract.RequestContentType);

                var response = await httpClient.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token).ConfigureAwait(false);

                using (response)
                {
                    EnsureExactResponseOrigin(request, response);
                    if ((int)response.StatusCode != contract.SuccessStatusCode)
                    {
                        await EnsureEmptyErrorBodyAsync(response, timeout.Token)
                            .ConfigureAwait(false);
                        throw MapStatus(response.StatusCode);
                    }

                    ValidateSuccessHeaders(response, contract);
                    var body = await ReadBoundedAsync(
                        response.Content,
                        contract.MaximumResponseBytes,
                        timeout.Token).ConfigureAwait(false);
                    if (body.Length < contract.MinimumResponseBytes)
                    {
                        throw Failure(
                            ClientMailboxTransportFailure.ProtocolViolation,
                            retryable: false,
                            "Mailbox response length is outside the exact contract.");
                    }

                    ValidateCanonicalResponse(body, operation);
                    return body;
                }
            }
            catch (OperationCanceledException exception)
                when (!cancellationToken.IsCancellationRequested)
            {
                throw Failure(
                    ClientMailboxTransportFailure.DeadlineExceeded,
                    retryable: true,
                    "Mailbox request deadline elapsed.",
                    exception);
            }
            catch (HttpRequestException exception)
            {
                throw Failure(
                    ClientMailboxTransportFailure.NetworkUnavailable,
                    retryable: true,
                    "Mailbox transport is unavailable.",
                    exception);
            }
            catch (IOException exception)
                when (exception is not ClientMailboxTransportException)
            {
                throw Failure(
                    ClientMailboxTransportFailure.NetworkUnavailable,
                    retryable: true,
                    "Mailbox response stream is unavailable.",
                    exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private static void ValidateRequest(
        ReadOnlySpan<byte> canonicalMau2,
        MailboxAuthenticatedOperation operation,
        MailboxHttpEndpointContract contract)
    {
        if (canonicalMau2.Length < contract.MinimumRequestBytes ||
            canonicalMau2.Length > contract.MaximumRequestBytes)
        {
            throw Failure(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "MAU2 request length is outside the endpoint contract.");
        }

        MailboxAuthenticatedClientRequest decoded;
        try
        {
            decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonicalMau2);
        }
        catch (Exception exception) when (
            exception is MailboxAuthenticatedCapabilityException or
                MailboxClientException or
                ArgumentException or
                OverflowException)
        {
            throw Failure(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "MAU2 request is not canonical.",
                exception);
        }

        if (decoded.Binding.Operation != operation ||
            decoded.Presentation.Operation != operation ||
            contract.AuthenticatedOperation != operation)
        {
            throw Failure(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "MAU2 operation does not match the selected endpoint.");
        }
    }

    private void ValidateCanonicalResponse(
        ReadOnlySpan<byte> canonical,
        MailboxAuthenticatedOperation operation)
    {
        byte[] roundTrip;
        try
        {
            roundTrip = operation switch
            {
                MailboxAuthenticatedOperation.Store =>
                    MailboxReceiptV3Codec.EncodeDurableQuorum(
                        MailboxReceiptV3Codec.DecodeDurableQuorum(canonical)),
                MailboxAuthenticatedOperation.Retrieve =>
                    MailboxClientCodec.EncodeRetrievePage(
                        MailboxClientCodec.DecodeRetrievePage(
                            canonical,
                            decodePolicy)),
                MailboxAuthenticatedOperation.Ack =>
                    MailboxAggregateAckCodec.EncodeMqr3(
                        MailboxAggregateAckCodec.DecodeMqr3(canonical)),
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
        }
        catch (Exception exception) when (
            exception is MailboxReceiptException or
                MailboxClientException or
                ArgumentException or
                OverflowException)
        {
            throw Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox response is not a canonical expected frame.",
                exception);
        }

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(roundTrip, canonical))
            {
                throw Failure(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "Mailbox response canonical round-trip failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roundTrip);
        }
    }

    private static void EnsureExactResponseOrigin(
        HttpRequestMessage request,
        HttpResponseMessage response)
    {
        var expected = request.RequestUri;
        var actual = response.RequestMessage?.RequestUri;
        if (expected is null ||
            actual is null ||
            expected.IsAbsoluteUri != actual.IsAbsoluteUri ||
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
            throw Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox endpoint redirected or changed origin.");
        }
    }

    private static void ValidateSuccessHeaders(
        HttpResponseMessage response,
        MailboxHttpEndpointContract contract)
    {
        var contentType = response.Content.Headers.ContentType;
        if (contentType is null ||
            contentType.Parameters.Count != 0 ||
            !string.Equals(
                contentType.MediaType,
                contract.ResponseContentType,
                StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentEncoding.Count != 0)
        {
            throw Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox response media headers violate the exact contract.");
        }

        if (response.Content.Headers.ContentLength is { } length &&
            (length < contract.MinimumResponseBytes ||
             length > contract.MaximumResponseBytes))
        {
            throw Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox response length is outside the exact contract.");
        }
    }

    private static async Task EnsureEmptyErrorBodyAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > 0)
        {
            throw Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Mailbox error response body must be empty.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(
            cancellationToken).ConfigureAwait(false);
        var probe = new byte[1];
        try
        {
            if (await stream.ReadAsync(probe, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw Failure(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "Mailbox error response body must be empty.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        using var output = new MemoryStream(
            content.Headers.ContentLength is > 0 and <= int.MaxValue
                ? checked((int)content.Headers.ContentLength.Value)
                : Math.Min(maximumBytes, 8192));
        var rented = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(
                    rented.AsMemory(0, Math.Min(rented.Length, maximumBytes + 1 - checked((int)output.Length))),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    return output.ToArray();
                }

                output.Write(rented, 0, read);
                if (output.Length > maximumBytes)
                {
                    throw Failure(
                        ClientMailboxTransportFailure.ProtocolViolation,
                        retryable: false,
                        "Mailbox response exceeds its exact size bound.");
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented);
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static ClientMailboxTransportException MapStatus(
        HttpStatusCode status) =>
        status switch
        {
            HttpStatusCode.BadRequest => Failure(
                ClientMailboxTransportFailure.MalformedRequest,
                false,
                "Mailbox server rejected the canonical request."),
            HttpStatusCode.Unauthorized => Failure(
                ClientMailboxTransportFailure.AuthenticationRejected,
                false,
                "Mailbox authentication was rejected."),
            HttpStatusCode.Forbidden => Failure(
                ClientMailboxTransportFailure.AuthorizationRejected,
                false,
                "Mailbox authorization was rejected."),
            HttpStatusCode.Conflict => Failure(
                ClientMailboxTransportFailure.ConflictOrExpired,
                false,
                "Mailbox replay, idempotency, or expiry check rejected the request."),
            HttpStatusCode.RequestEntityTooLarge => Failure(
                ClientMailboxTransportFailure.PayloadTooLarge,
                false,
                "Mailbox request exceeds the server bound."),
            HttpStatusCode.UnsupportedMediaType => Failure(
                ClientMailboxTransportFailure.UnsupportedMediaType,
                false,
                "Mailbox media type was rejected."),
            HttpStatusCode.TooManyRequests => Failure(
                ClientMailboxTransportFailure.Throttled,
                true,
                "Mailbox request was rate limited."),
            HttpStatusCode.ServiceUnavailable => Failure(
                ClientMailboxTransportFailure.DependencyUnavailable,
                true,
                "Mailbox dependency is unavailable."),
            HttpStatusCode.GatewayTimeout => Failure(
                ClientMailboxTransportFailure.DeadlineExceeded,
                true,
                "Mailbox server deadline elapsed."),
            HttpStatusCode.MethodNotAllowed => Failure(
                ClientMailboxTransportFailure.MethodRejected,
                false,
                "Mailbox method was rejected."),
            HttpStatusCode.LengthRequired => Failure(
                ClientMailboxTransportFailure.LengthRequired,
                false,
                "Mailbox request length was rejected."),
            _ => Failure(
                ClientMailboxTransportFailure.ProtocolViolation,
                false,
                "Mailbox server returned an unsupported status.")
        };

    private static ClientMailboxTransportException Failure(
        ClientMailboxTransportFailure failure,
        bool retryable,
        string message,
        Exception? innerException = null) =>
        new(failure, retryable, message, innerException);
}
