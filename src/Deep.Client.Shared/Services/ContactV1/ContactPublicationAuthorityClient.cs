using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public enum ContactPublicationAuthorityRequestError
{
    Rejected = 1,
    RateLimited = 2,
    Unavailable = 3,
    UnexpectedStatus = 4,
}

public sealed class ContactPublicationAuthorityRequestException(
    ContactPublicationAuthorityRequestError error,
    HttpStatusCode statusCode,
    string message) : IOException(message)
{
    public ContactPublicationAuthorityRequestError Error { get; } = error;
    public HttpStatusCode StatusCode { get; } = statusCode;
}

/// <summary>
/// Bounded production client for one threshold-authorized permanent Contact
/// publication. A successful HTTP response is insufficient: Protocol must
/// independently verify the exact XPA1/XPU1 body and current placement before
/// this client returns a publication capability.
/// </summary>
public sealed class ContactPublicationAuthorityClient : IDisposable
{
    public const string EndpointPath = "/api/v1/contact-publication-authority";
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);
    private readonly HttpServiceRequestTransport transport;
    private int disposed;

    public ContactPublicationAuthorityClient(HttpServiceRequestTransport transport) =>
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public static HttpServiceRequestTransportOptions CreateTransportOptions(
        string registryBaseUrl,
        TimeSpan requestTimeout = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryBaseUrl);
        var timeout = requestTimeout == default ? DefaultRequestTimeout : requestTimeout;
        if (timeout <= TimeSpan.Zero || timeout > DefaultRequestTimeout)
            throw new ArgumentOutOfRangeException(
                nameof(requestTimeout),
                "The publication-authority timeout must be 30 seconds or less.");
        return new HttpServiceRequestTransportOptions(
            registryBaseUrl.Trim(),
            [EndpointPath],
            ContactPublicationAuthorityWireCodec.RequestMediaType,
            ContactPublicationAuthorityWireCodec.ResponseMediaType,
            ContactPublicationAuthorityWireCodec.MaximumRequestBytes,
            ContactPublicationAuthorityWireCodec.MaximumResponseBytes,
            timeout);
    }

    public async ValueTask<AuthoredPermanentAddressPublication> IssueAsync(
        AuthoredContactPublicationAuthorityRequest authoredRequest,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(authoredRequest);
        cancellationToken.ThrowIfCancellationRequested();
        var request = authoredRequest.WireRequest;
        var encoded = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
        try
        {
            using var response = await transport.PostAsync(
                    EndpointPath, encoded, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
                throw Status(response.StatusCode);
            var wire = ContactPublicationAuthorityWireCodec.DecodeResponse(
                request, response.Body.Span);
            return await authoredRequest.VerifyResponseAsync(
                    wire.ExactXpu1, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            transport.Dispose();
    }

    private static ContactPublicationAuthorityRequestException Status(HttpStatusCode status) =>
        status switch
        {
            HttpStatusCode.BadRequest or HttpStatusCode.NotFound => new(
                ContactPublicationAuthorityRequestError.Rejected,
                status,
                "The publication authority rejected the exact current Contact closure."),
            HttpStatusCode.TooManyRequests => new(
                ContactPublicationAuthorityRequestError.RateLimited,
                status,
                "The publication authority rate-limited the request."),
            HttpStatusCode.ServiceUnavailable => new(
                ContactPublicationAuthorityRequestError.Unavailable,
                status,
                "The publication authority is temporarily unavailable."),
            _ => new(
                ContactPublicationAuthorityRequestError.UnexpectedStatus,
                status,
                $"The publication authority returned HTTP {(int)status}.")
        };
}
