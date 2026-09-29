using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>
/// Owned, bounded identity-neutral network distribution transport. This client
/// returns untrusted exact records, never freshness, placement or route authority.
/// The caller remains responsible for signed acquisition policy and verification.
/// </summary>
public sealed class HttpDeepIdV2NetworkClosureArtifactSource :
    IDeepIdV2NetworkClosureArtifactSource, IDisposable
{
    public const string EndpointPath = "/api/v2/network/closure";
    private readonly HttpServiceRequestTransport transport;

    internal HttpDeepIdV2NetworkClosureArtifactSource(HttpServiceRequestTransport transport) =>
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public static HttpServiceRequestTransportOptions CreateTransportOptions(
        string registryBaseUrl, TimeSpan requestTimeout = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryBaseUrl);
        var timeout = requestTimeout == default ? TimeSpan.FromSeconds(30) : requestTimeout;
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        return new(registryBaseUrl, [EndpointPath],
            XPointNetworkClosureWireCodec.RequestMediaType,
            XPointNetworkClosureWireCodec.ResponseMediaType,
            XPointNetworkClosureWireCodec.RequestLength,
            XPointNetworkClosureWireCodec.MaximumResponseLength, timeout);
    }

    public async ValueTask<DeepIdV2NetworkClosureArtifacts> FetchCurrentAsync(
        ReadOnlyMemory<byte> networkId, XPointNetworkProtectedLkg? protectedFloor,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // The floor is never uploaded and cannot be changed by this adapter.
        if (protectedFloor is not null && !Fixed(protectedFloor.NetworkId.Span, networkId.Span))
            throw new ArgumentException("Network closure floor belongs to another network.", nameof(protectedFloor));
        var query = XPointNetworkClosureWireCodec.EncodeRequest(networkId.Span);
        using var response = await transport.PostAsync(EndpointPath, query,
            cancellationToken).ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            throw new AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException(response.StatusCode, response.RetryAfter);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new InvalidDataException("Network closure distribution rejected the request.");
        var raw = XPointNetworkClosureWireCodec.DecodeResponse(response.Body.Span);
        if (!Fixed(raw.NetworkId.Span, networkId.Span))
            throw new CryptographicException("Network closure distribution scope differs from the request.");
        return new(raw.ExactAuthorityChain, raw.ExactTimePolicyChain,
            raw.ExactNetworkPolicyChain, raw.ExactViewChain, raw.ExactHeadChain,
            raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain);
    }

    public void Dispose() => transport.Dispose();

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
