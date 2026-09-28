using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>Untrusted, bounded identity-neutral network closure. It carries
/// neither ADP1 V1 nor any caller-supplied freshness/placement capability.</summary>
public sealed class DeepIdV2NetworkClosureArtifacts
{
    private readonly ReadOnlyMemory<byte>[][] chains;

    public DeepIdV2NetworkClosureArtifacts(
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain)
    {
        IReadOnlyList<ReadOnlyMemory<byte>>[] values = [exactXna1AuthorityChain,
            exactDts1PolicyChain, exactOrderedXvp1Chain, exactOrderedXnv1Chain,
            exactOrderedXnh1Chain, exactActiveXnd1, exactOrderedPmt2Chain];
        // Preflight every chain and the total before making owned copies.
        var total = 0L;
        foreach (var value in values)
            total = checked(total + ContactResolveDirectoryArtifacts.ValidateChain(
                value, nameof(values), ContactResolveDirectoryArtifacts.MaximumChainArtifacts));
        if (total > ContactResolveDirectoryArtifacts.MaximumPackageBytes ||
            exactOrderedXnv1Chain.Count != exactOrderedXnh1Chain.Count)
            throw new ArgumentException("The DID2 network closure is oversized or incomplete.");
        chains = values.Select(value => value.Select(artifact =>
            (ReadOnlyMemory<byte>)artifact.ToArray()).ToArray()).ToArray();
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXna1AuthorityChain => Copy(0);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDts1PolicyChain => Copy(1);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXvp1Chain => Copy(2);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1Chain => Copy(3);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnh1Chain => Copy(4);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveXnd1 => Copy(5);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPmt2Chain => Copy(6);
    private IReadOnlyList<ReadOnlyMemory<byte>> Copy(int index) => chains[index]
        .Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

/// <summary>Fetches public signed network records, never account authority.
/// The protected floor is supplied only as an untrusted retrieval hint.</summary>
public interface IDeepIdV2NetworkClosureArtifactSource
{
    ValueTask<DeepIdV2NetworkClosureArtifacts> FetchCurrentAsync(
        ReadOnlyMemory<byte> networkId, XPointNetworkProtectedLkg? protectedFloor,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// DID2-only pre-key publication authority. Each mint obtains an independent
/// nonce-bound proof for the protected local account, verifies NETCODEC from
/// the pinned root, and durably advances/rechecks network custody before
/// releasing placement. It cannot resolve DID1 or accept ADP1 V1. Input
/// providers, proof-client lifetime and durable stores remain caller-owned.
/// </summary>
public sealed class DeepIdV2ContactPathAuthoritySource :
    IContactResolvePathAuthoritySource, IContactResolvePublicationPathAuthoritySource
{
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly DeepIdV2AccountService accounts;
    private readonly DeepIdV2DirectoryProofClient proofs;
    private readonly IDeepIdV2NetworkClosureArtifactSource artifacts;
    private readonly IXPointNetworkStateStore networkStore;
    private readonly XPointNetworkStateClient networkState;
    private readonly OnionTrustedTimeAuthority trustedTime;
    private readonly SemaphoreSlim gate = new(1, 1);
    private VerifiedOnionNetworkContext? liveContext;

    public DeepIdV2ContactPathAuthoritySource(XPointNetworkGenesisPin genesisPin,
        DeepIdV2AccountService accounts, DeepIdV2DirectoryProofClient proofs,
        IDeepIdV2NetworkClosureArtifactSource artifacts,
        IXPointNetworkStateStore networkStore, IOnionMonotonicClock clock)
    {
        this.genesisPin = genesisPin ?? throw new ArgumentNullException(nameof(genesisPin));
        this.accounts = accounts ?? throw new ArgumentNullException(nameof(accounts));
        this.proofs = proofs ?? throw new ArgumentNullException(nameof(proofs));
        this.artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        this.networkStore = networkStore ?? throw new ArgumentNullException(nameof(networkStore));
        networkState = new(networkStore);
        trustedTime = new(clock ?? throw new ArgumentNullException(nameof(clock)));
    }

    public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(Xiq1Request request,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<ContactResolvePathAuthority>(new NotSupportedException(
            "DID2 publication authority does not authorize invite or legacy contact requests."));

    public async ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        ContactResolveCanonicalPathRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory ||
            !request.HasExplicitPlacementBinding)
            throw new NotSupportedException("Only bounded DID2 XPP1 publication is enabled.");
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(request.ExactRequest.Span);
        if (!Fixed(fragment.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(fragment.ViewHash.Span, request.ViewHash.Span) ||
            !Fixed(fragment.PlacementHash.Span, request.PlacementHash.Span))
            throw new CryptographicException("The DID2 request and fragment placement differ.");
        var current = await GetCurrentForPublicationAsync(request.NetworkId,
            request.ShardKey, cancellationToken).ConfigureAwait(false);
        if (!Fixed(request.ViewHash.Span, current.Placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, current.Placement.PlacementHash.Span) ||
            request.ExpiresAtUnixSeconds > current.Placement.ValidUntilUnixSeconds)
            throw new CryptographicException("The DID2 request does not bind current placement.");
        return current;
    }

    public async ValueTask<ContactResolvePathAuthority> GetCurrentForPublicationAsync(
        ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> serviceCapability,
        CancellationToken cancellationToken = default)
    {
        if (!Fixed(networkId.Span, genesisPin.NetworkId.Span) ||
            serviceCapability.Length != 32 ||
            serviceCapability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 publication requires the pinned network and exact service capability.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var before = await networkStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (before?.ForkLatched == true)
                throw new CryptographicException("Protected network fork latch blocks DID2 publication.");
            if (liveContext is not null && (before is null ||
                !Same(before.ProtectedLkg, liveContext.ProtectedLkg)))
                throw new CryptographicException("Live DID2 network capability differs from protected custody.");
            var exact = await artifacts.FetchCurrentAsync(networkId,
                before?.ProtectedLkg, cancellationToken).ConfigureAwait(false) ??
                throw new CryptographicException("The DID2 signed network closure is absent.");
            var authority = XPointNetworkAuthorityVerifier.Verify(genesisPin,
                exact.ExactXna1AuthorityChain, exact.ExactDts1PolicyChain);
            var fresh = await accounts.FetchOwnCurrentDirectoryProofAsync(proofs,
                authority, cancellationToken).ConfigureAwait(false);
            VerifiedOnionNetworkContext verified;
            try
            {
                verified = before is not null && liveContext is null
                    ? await OnionNetworkContextVerifier.VerifyRehydratedCurrentAsync(authority,
                        fresh, exact.ExactOrderedXvp1Chain, exact.ExactOrderedXnv1Chain,
                        exact.ExactOrderedXnh1Chain, exact.ExactActiveXnd1,
                        exact.ExactOrderedPmt2Chain, before.ProtectedLkg, trustedTime,
                        cancellationToken).ConfigureAwait(false)
                    : await OnionNetworkContextVerifier.VerifyAsync(authority, fresh,
                        exact.ExactOrderedXvp1Chain, exact.ExactOrderedXnv1Chain,
                        exact.ExactOrderedXnh1Chain, exact.ExactActiveXnd1,
                        exact.ExactOrderedPmt2Chain, liveContext, trustedTime,
                        cancellationToken).ConfigureAwait(false);
            }
            catch (OnionBoundaryException exception) when (
                before is not null && exception.Code == "network-fork")
            {
                var write = await networkStore.CompareExchangeAsync(before.Revision,
                    new(checked(before.Revision + 1), before.ProtectedLkg, true),
                    cancellationToken).ConfigureAwait(false);
                if (write.Disposition != XPointNetworkStoreWriteDisposition.Applied &&
                    write.Snapshot?.ForkLatched != true)
                    throw new IOException("Network custody changed while recording the verified fork.", exception);
                throw new CryptographicException("A verified network fork blocks DID2 publication.", exception);
            }
            verified.EnsureCurrent();
            var committed = await networkState.ApplyVerifiedNetworkContextAsync(verified,
                cancellationToken).ConfigureAwait(false);
            if (committed.Disposition is not (XPointNetworkAdvanceDisposition.Applied or
                XPointNetworkAdvanceDisposition.Idempotent) ||
                !Same(committed.Snapshot.ProtectedLkg, verified.ProtectedLkg))
                throw new CryptographicException("DID2 network custody did not commit the exact verified context.");
            var after = await networkStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (after is null || after.ForkLatched ||
                !Same(after.ProtectedLkg, verified.ProtectedLkg))
                throw new CryptographicException("Committed DID2 network custody could not be reauthenticated.");
            await proofs.RequireStillFreshAsync(fresh, authority, cancellationToken).ConfigureAwait(false);
            verified.EnsureCurrent();
            var placement = ContactServicePlacementFactory.Create(verified,
                ContactServiceRequestKind.PublishPreKeyInventory, serviceCapability);
            liveContext = verified;
            return new(verified, placement);
        }
        finally { gate.Release(); }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool Same(XPointNetworkProtectedLkg left, XPointNetworkProtectedLkg? right) =>
        right is not null && Fixed(XPointNetworkProtectedLkgCodec.Encode(left),
            XPointNetworkProtectedLkgCodec.Encode(right));
}
