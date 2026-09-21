using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public enum ContactRouteAuthorityRequestError
{
    Rejected = 1,
    RateLimited = 2,
    Unavailable = 3,
    UnexpectedStatus = 4,
}

public sealed class ContactRouteAuthorityRequestException(
    ContactRouteAuthorityRequestError error,
    HttpStatusCode statusCode,
    string message) : IOException(message)
{
    public ContactRouteAuthorityRequestError Error { get; } = error;
    public HttpStatusCode StatusCode { get; } = statusCode;
}

/// <summary>
/// Bounded production client for the Registry threshold-authority exchange.
/// It accepts only a verifier-derived request, binds the exact response to its
/// nonce and XRA1, and returns no route capability until all PMS2/XRC1/XSS1
/// thresholds have been verified by Protocol.
/// </summary>
public sealed class ContactRouteAuthorityClient : IDisposable
{
    public const string EndpointPath = "/api/v1/contact-route-authority";
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);
    private readonly HttpServiceRequestTransport transport;
    private int disposed;

    public ContactRouteAuthorityClient(HttpServiceRequestTransport transport) =>
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public static HttpServiceRequestTransportOptions CreateTransportOptions(
        string registryBaseUrl,
        TimeSpan requestTimeout = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryBaseUrl);
        var timeout = requestTimeout == default ? DefaultRequestTimeout : requestTimeout;
        if (timeout <= TimeSpan.Zero || timeout > DefaultRequestTimeout)
            throw new ArgumentOutOfRangeException(
                nameof(requestTimeout), "The route-authority timeout must be 30 seconds or less.");
        return new HttpServiceRequestTransportOptions(
            registryBaseUrl.Trim(),
            [EndpointPath],
            ContactRouteAuthorityWireCodec.RequestMediaType,
            ContactRouteAuthorityWireCodec.ResponseMediaType,
            ContactRouteAuthorityWireCodec.RequestBytes,
            ContactRouteAuthorityWireCodec.MaximumResponseBytes,
            timeout);
    }

    public async ValueTask<AuthoredContactRouteThresholdClosure> IssueAsync(
        VerifiedContactRouteProposalAuthority proposal,
        AuthoredContactRouteAdvertisement advertisement,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(proposal);
        ArgumentNullException.ThrowIfNull(advertisement);
        cancellationToken.ThrowIfCancellationRequested();
        var nonce = new byte[32];
        do RandomNumberGenerator.Fill(nonce);
        while (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        var request = proposal.CreateThresholdRequest(advertisement, nonce);
        var encoded = ContactRouteAuthorityWireCodec.EncodeRequest(request);
        try
        {
            using var response = await transport.PostAsync(
                    EndpointPath, encoded, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
                throw Status(response.StatusCode);
            var wire = ContactRouteAuthorityWireCodec.DecodeResponse(
                request, response.Body.Span);
            return await ContactRouteThresholdVerifier.VerifyExactAsync(
                    proposal,
                    advertisement,
                    wire.ExactPms2,
                    wire.ExactXrc1,
                    wire.ExactXss1,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            transport.Dispose();
    }

    private static ContactRouteAuthorityRequestException Status(HttpStatusCode status) =>
        status switch
        {
            HttpStatusCode.BadRequest or HttpStatusCode.NotFound => new(
                ContactRouteAuthorityRequestError.Rejected, status,
                "The route authority rejected the exact current proposal."),
            HttpStatusCode.TooManyRequests => new(
                ContactRouteAuthorityRequestError.RateLimited, status,
                "The route authority rate-limited the request."),
            HttpStatusCode.ServiceUnavailable => new(
                ContactRouteAuthorityRequestError.Unavailable, status,
                "The route authority is temporarily unavailable."),
            _ => new(
                ContactRouteAuthorityRequestError.UnexpectedStatus, status,
                $"The route authority returned HTTP {(int)status}.")
        };
}
