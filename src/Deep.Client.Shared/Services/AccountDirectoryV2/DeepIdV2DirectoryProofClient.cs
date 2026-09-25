using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.AccountDirectoryV2;

/// <summary>
/// Account-scoped, rollback-protected DID2 head custody. Restore must
/// re-authenticate the persisted exact ADH1 against the verified authority.
/// Commit is an atomic compare/exchange against expectedHead and must durably
/// flush the next verified head before returning; conflicts fail closed.
/// </summary>
public interface IDeepIdV2DirectoryProtectedLkgStore
{
    ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);

    ValueTask CommitVerifiedAsync(AccountDirectoryProtectedLkg expectedHead,
        VerifiedDeepIdV2DirectoryFreshness verified,
        CancellationToken cancellationToken);
}

/// <summary>
/// Bounded DID2-only Registry exchange. Neither a successful HTTP response nor
/// DPP2 decoding grants authority: only the independent protocol verifier can
/// return a freshness capability, and this client releases it only after the
/// exact next protected head has been durably committed.
/// </summary>
public sealed class DeepIdV2DirectoryProofClient : IDisposable
{
    public const string EndpointPath = "/api/v2/account-directory/proofs";
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpServiceRequestTransport transport;
    private readonly IOnionMonotonicClock clock;
    private readonly IDeepMlDsa65Verifier mlDsa65;
    private readonly IDeepIdV2DirectoryProtectedLkgStore protectedLkgStore;
    private int disposed;

    public DeepIdV2DirectoryProofClient(HttpServiceRequestTransport transport,
        IOnionMonotonicClock clock, IDeepMlDsa65Verifier mlDsa65,
        IDeepIdV2DirectoryProtectedLkgStore protectedLkgStore)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.mlDsa65 = mlDsa65 ?? throw new ArgumentNullException(nameof(mlDsa65));
        this.protectedLkgStore = protectedLkgStore ??
            throw new ArgumentNullException(nameof(protectedLkgStore));
    }

    public static HttpServiceRequestTransportOptions CreateTransportOptions(
        string registryBaseUrl, TimeSpan requestTimeout = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(registryBaseUrl);
        var timeout = requestTimeout == default ? DefaultRequestTimeout : requestTimeout;
        if (timeout <= TimeSpan.Zero || timeout > DefaultRequestTimeout)
            throw new ArgumentOutOfRangeException(nameof(requestTimeout),
                "The DID2 directory proof timeout must be 30 seconds or less.");
        return new HttpServiceRequestTransportOptions(
            registryBaseUrl.Trim(), [EndpointPath],
            DeepIdV2DirectoryProofWireCodec.RequestMediaType,
            DeepIdV2DirectoryProofWireCodec.ResponseMediaType,
            DeepIdV2DirectoryProofWireCodec.RequestLength,
            DeepIdV2DirectoryProofWireCodec.MaximumResponseLength,
            timeout);
    }

    public async ValueTask<VerifiedDeepIdV2DirectoryFreshness> FetchGenesisAsync(
        ParsedAdl1V2 lookup,
        VerifiedDab2 binding,
        VerifiedXPointNetworkAuthority authority,
        ushort deploymentProfileId,
        ushort supportedReader,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(lookup);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();

        var query = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(lookup, binding);
        if (query.NetworkId.Length != authority.NetworkId.Length ||
            !CryptographicOperations.FixedTimeEquals(
                query.NetworkId.Span, authority.NetworkId.Span))
            throw new CryptographicException(
                "The DID2 lookup and verified network authority differ.");
        var protectedLkg = await protectedLkgStore.RestoreAsync(authority,
                cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The protected DID2 directory floor is absent.");
        return await FetchGenesisWithFloorAsync(lookup, binding.DeepId, authority,
            query, protectedLkg, deploymentProfileId, supportedReader,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves a peer from an exact DID2, without trusting a caller-supplied
    /// DAB2. The authenticated current-value proof must return that same DID2.
    /// A verified non-membership result advances the protected floor but is
    /// never released as a usable contact.
    /// </summary>
    public ValueTask<VerifiedDeepIdV2DirectoryFreshness>
        FetchByContactDescriptorAsync(DeepPermanentIdV2 descriptor,
            ParsedDid2 exactCredential,
            VerifiedXPointNetworkAuthority authority,
            ushort deploymentProfileId, ushort supportedReader,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(exactCredential);
        if (!descriptor.MatchesExactCredential(exactCredential))
            throw new CryptographicException(
                "The compact DID2 contact descriptor does not bind the exact public credential.");
        return FetchByDid2Async(exactCredential, authority,
            deploymentProfileId, supportedReader, cancellationToken);
    }

    /// <summary>
    /// Resolves an already authenticated exact DID2 credential. Callers that
    /// start from a compact contact descriptor must use the descriptor-bound
    /// overload above before treating a result as a contact.
    /// </summary>
    public async ValueTask<VerifiedDeepIdV2DirectoryFreshness>
        FetchByDid2Async(ParsedDid2 requestedDid2,
            VerifiedXPointNetworkAuthority authority,
            ushort deploymentProfileId, ushort supportedReader,
            CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(requestedDid2);
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        var protectedLkg = await protectedLkgStore.RestoreAsync(authority,
                cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The protected DID2 directory floor is absent.");
        RequireV2Floor(protectedLkg, authority);
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(requestedDid2,
            authority.NetworkId.Span, protectedLkg.LogGeneration,
            protectedLkg.CoreHash.Span, serviceProfile: 1,
            new byte[38], new byte[32]);
        var query = VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup,
            requestedDid2);
        var verified = await FetchGenesisWithFloorAsync(lookup, requestedDid2,
            authority, query, protectedLkg, deploymentProfileId,
            supportedReader, cancellationToken).ConfigureAwait(false);
        if (verified.CurrentCheckpoint is null)
            throw new CryptographicException(
                "No current authenticated DID2 contact binding exists.");
        return verified;
    }

    /// <summary>
    /// Authors the XPoint-only ADL1 from the exact verified DID2 and the
    /// protected current head. No caller-supplied lookup key or floor enters
    /// this account-owned path.
    /// </summary>
    public async ValueTask<VerifiedDeepIdV2DirectoryFreshness>
        FetchOwnGenesisAsync(VerifiedDab2 binding,
            VerifiedXPointNetworkAuthority authority,
            ushort deploymentProfileId, ushort supportedReader,
            CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        if (binding.Identity.Account.Certificate.NetworkId.Length !=
                authority.NetworkId.Length ||
            !CryptographicOperations.FixedTimeEquals(
                binding.Identity.Account.Certificate.NetworkId.Span,
                authority.NetworkId.Span))
            throw new CryptographicException(
                "The verified DID2 account and network authority differ.");
        var protectedLkg = await protectedLkgStore.RestoreAsync(authority,
                cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The protected DID2 directory floor is absent.");
        RequireV2Floor(protectedLkg, authority);
        var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(binding.DeepId,
            authority.NetworkId.Span, protectedLkg.LogGeneration,
            protectedLkg.CoreHash.Span, serviceProfile: 1,
            new byte[38], new byte[32]);
        var query = VerifiedDeepIdV2DirectoryQuery.VerifyBinding(lookup,
            binding);
        return await FetchGenesisWithFloorAsync(lookup, binding.DeepId, authority,
            query, protectedLkg, deploymentProfileId, supportedReader,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rechecks the same nonce-bound proof after a caller's asynchronous local
    /// account/state validation. The proof may expire while that work runs;
    /// durable LKG commit alone never extends its authority.
    /// </summary>
    internal async ValueTask RequireStillFreshAsync(
        VerifiedDeepIdV2DirectoryFreshness verified,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(verified);
        var current = await clock.ReadAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "The DID2 monotonic clock returned no handoff sample.");
        if (!verified.IsCurrentAtMonotonic(current.BootId.Span,
                current.SampleSeconds))
            throw new CryptographicException(
                "The DID2 directory proof expired before account handoff.");
    }

    private async ValueTask<VerifiedDeepIdV2DirectoryFreshness>
        FetchGenesisWithFloorAsync(ParsedAdl1V2 lookup, ParsedDid2 requestedDid2,
            VerifiedXPointNetworkAuthority authority,
            VerifiedDeepIdV2DirectoryQuery query,
            AccountDirectoryProtectedLkg protectedLkg,
            ushort deploymentProfileId, ushort supportedReader,
            CancellationToken cancellationToken)
    {
        RequireV2Floor(protectedLkg, authority);
        if (deploymentProfileId == 0 || supportedReader < 2)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));

        var requestCreated = await clock.ReadAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "The DID2 monotonic clock returned no request sample.");
        var nonce = RandomNumberGenerator.GetBytes(32);
        byte[]? encoded = null;
        try
        {
            encoded = DeepIdV2DirectoryProofWireCodec.EncodeRequest(
                lookup, requestedDid2, nonce, requestCreated.BootId.Span,
                requestCreated.SampleSeconds);
            var exactRequest = DeepIdV2DirectoryProofWireCodec.DecodeRequest(encoded);
            using var response = await transport.PostAsync(
                    EndpointPath, encoded, cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode is HttpStatusCode.TooManyRequests or
                HttpStatusCode.ServiceUnavailable)
                throw new IOException("The DID2 directory proof authority is unavailable.");
            if (response.StatusCode != HttpStatusCode.OK)
                throw new InvalidDataException(
                    "The DID2 directory proof authority rejected the request.");
            var responseReceived = await clock.ReadAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The DID2 monotonic clock returned no response sample.");
            var current = await clock.ReadAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The DID2 monotonic clock returned no current sample.");
            if (!SameBoot(requestCreated, responseReceived) ||
                !SameBoot(requestCreated, current))
                throw new CryptographicException(
                    "The monotonic boot changed during the DID2 directory proof request.");
            var window = new AccountDirectoryMonotonicRequestWindow(
                requestCreated.BootId.Span, requestCreated.SampleSeconds,
                responseReceived.SampleSeconds, current.SampleSeconds);
            var wire = DeepIdV2DirectoryProofWireCodec.DecodeResponse(
                response.Body.Span, exactRequest);
            var verified = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(
                authority, wire.ExactAdh1, wire.ExactDtt1, wire.ExactAdp1V2,
                nonce, query, window, protectedLkg, deploymentProfileId,
                supportedReader, mlDsa65);
            await protectedLkgStore.CommitVerifiedAsync(protectedLkg,
                verified, cancellationToken).ConfigureAwait(false);
            // Durable storage can outlive the nonce-bound proof's short
            // freshness window. Advancing the rollback floor is safe, but a
            // stale capability must never escape to Contact consumers.
            var afterCommit = await clock.ReadAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw new CryptographicException(
                    "The DID2 monotonic clock returned no post-commit sample.");
            if (!SameBoot(requestCreated, afterCommit) ||
                !verified.IsCurrentAtMonotonic(afterCommit.BootId.Span,
                    afterCommit.SampleSeconds))
                throw new CryptographicException(
                    "The DID2 directory proof expired before durable handoff.");
            return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            if (encoded is not null) CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void RequireV2Floor(AccountDirectoryProtectedLkg protectedLkg,
        VerifiedXPointNetworkAuthority authority)
    {
        if (protectedLkg.Head.MinimumReader < 2 ||
            protectedLkg.Head.NetworkId.Length != authority.NetworkId.Length ||
            !CryptographicOperations.FixedTimeEquals(
                protectedLkg.Head.NetworkId.Span, authority.NetworkId.Span))
            throw new CryptographicException(
                "The DID2 protected directory floor is absent or cross-network.");
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
            transport.Dispose();
    }

    private static bool SameBoot(OnionMonotonicReading left,
        OnionMonotonicReading right) =>
        CryptographicOperations.FixedTimeEquals(
            left.BootId.Span, right.BootId.Span);
}
