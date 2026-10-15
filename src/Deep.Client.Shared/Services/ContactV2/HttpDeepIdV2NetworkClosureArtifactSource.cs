using System.Net;
using System.Diagnostics;
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
        if (networkId.Length != 16)
            throw new ArgumentException("Network closure requires an exact network scope.", nameof(networkId));
        var expectedNetwork = networkId.ToArray();
        // The floor is never uploaded and cannot be changed by this adapter.
        if (protectedFloor is not null && !Fixed(protectedFloor.NetworkId.Span, expectedNetwork))
            throw new ArgumentException("Network closure floor belongs to another network.", nameof(protectedFloor));
        var query = XPointNetworkClosureWireCodec.EncodeRequest(expectedNetwork);
        // Distribution has one bounded in-flight response, not a caller quota.
        // Desynchronize rejected public reads without replaying mutations,
        // caching authority or extending the original configured deadline.
        var started = Stopwatch.GetTimestamp();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(transport.RequestTimeout);
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                using var response = await transport.PostAsync(EndpointPath, query,
                    deadline.Token).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    var unavailable = new AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException(
                        response.StatusCode, response.RetryAfter);
                    if (attempt == 7) throw unavailable;
                    var backoff = Math.Min(attempt, 4);
                    var delay = (response.RetryAfter ?? TimeSpan.Zero) + TimeSpan.FromMilliseconds(
                        RandomNumberGenerator.GetInt32(75 << backoff, 175 << backoff));
                    if (delay >= transport.RequestTimeout - Stopwatch.GetElapsedTime(started)) throw unavailable;
                    response.Dispose();
                    await Task.Delay(delay, deadline.Token).ConfigureAwait(false);
                    continue;
                }
                if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
                    throw new AccountDirectoryV2.DeepIdV2DirectoryProofUnavailableException(response.StatusCode, response.RetryAfter);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new InvalidDataException("Network closure distribution rejected the request.");
                var raw = XPointNetworkClosureWireCodec.DecodeResponse(response.Body.Span);
                if (!Fixed(raw.NetworkId.Span, expectedNetwork))
                    throw new CryptographicException("Network closure distribution scope differs from the request.");
                var result = new DeepIdV2NetworkClosureArtifacts(raw.ExactAuthorityChain, raw.ExactTimePolicyChain,
                    raw.ExactNetworkPolicyChain, raw.ExactViewChain, raw.ExactHeadChain,
                    raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain, raw.ExactMailboxAuthorityChain);
                deadline.Token.ThrowIfCancellationRequested();
                return result;
            }
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("Network closure distribution exceeded its bounded timeout.", error); }
    }

    public void Dispose() => transport.Dispose();

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
