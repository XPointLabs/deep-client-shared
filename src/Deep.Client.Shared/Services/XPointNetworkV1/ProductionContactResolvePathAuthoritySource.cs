using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.XPointNetworkV1;

public interface IContactResolvePlacementContextSource
{
    ValueTask<VerifiedContactResolverPlacementContext> MintPlacementContextAsync(
        ContactStoreScope accountScope,
        PendingContactAddress pendingAddress,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Verifies a bounded canonical directory package and emits the exact current
/// ContactResolve network/placement capability.  It never enables a host
/// adapter or accepts caller-authored view/placement authority.
/// </summary>
public sealed class ProductionContactResolvePathAuthoritySource :
    IContactResolvePathAuthoritySource,
    IContactResolvePublicationPathAuthoritySource,
    IContactResolvePlacementContextSource,
    IContactResolveClaimPathAuthoritySource,
    IContactResolvePermanentPathAuthoritySource
{
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly IContactResolveDirectoryArtifactSource artifacts;
    private readonly IAccountDirectoryStateStore directoryStore;
    private readonly IXPointNetworkStateStore networkStore;
    private readonly XPointNetworkStateClient networkStateClient;
    private readonly ICanonicalContactResolveAuthorityVerifier verifier;
    private readonly SemaphoreSlim gate = new(1, 1);
    private VerifiedOnionNetworkContext? liveContext;

    public ProductionContactResolvePathAuthoritySource(
        XPointNetworkGenesisPin genesisPin,
        IContactResolveDirectoryArtifactSource artifacts,
        IAccountDirectoryStateStore directoryStore,
        IXPointNetworkStateStore networkStore,
        IOnionMonotonicClock monotonicClock,
        ushort supportedDirectoryReader)
        : this(
            genesisPin,
            artifacts,
            directoryStore,
            networkStore,
            new ProtocolCanonicalContactResolveAuthorityVerifier(
                new AccountDirectoryClient(directoryStore),
                new OnionTrustedTimeAuthority(monotonicClock),
                supportedDirectoryReader))
    {
    }

    internal ProductionContactResolvePathAuthoritySource(
        XPointNetworkGenesisPin genesisPin,
        IContactResolveDirectoryArtifactSource artifacts,
        IAccountDirectoryStateStore directoryStore,
        IXPointNetworkStateStore networkStore,
        ICanonicalContactResolveAuthorityVerifier verifier)
    {
        this.genesisPin = genesisPin ?? throw new ArgumentNullException(nameof(genesisPin));
        this.artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        this.directoryStore = directoryStore ?? throw new ArgumentNullException(nameof(directoryStore));
        this.networkStore = networkStore ?? throw new ArgumentNullException(nameof(networkStore));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        networkStateClient = new XPointNetworkStateClient(networkStore);
    }

    public async ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        Xiq1Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var authority = await MintCurrentAuthorityAsync(
            request.NetworkId, request.LocatorHash, ReadOnlyMemory<byte>.Empty,
            AccountDirectoryAdp1ResultKind.NonMembership,
            ContactServiceRequestKind.ResolveInvite,
            cancellationToken).ConfigureAwait(false);
        var network = authority.Network;
        var placement = authority.Placement;
        if (!Fixed(request.NetworkId.Span, network.NetworkId.Span)
            || !Fixed(request.ViewHash.Span, placement.ViewHash.Span)
            || !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span)
            || !placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash)
            || request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw Fail("request-placement-mismatch",
                "XIQ1 does not bind the exact current verified view and InviteResolver placement.");
        return authority;
    }

    async ValueTask<ContactResolvePathAuthority>
        IContactResolvePublicationPathAuthoritySource.GetCurrentForPublicationAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> serviceCapability,
            CancellationToken cancellationToken)
    {
        if (networkId.Length != 16 || networkId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Fail("request-network-invalid",
                "The bounded publication requires one exact non-zero network ID.");
        if (serviceCapability.Length != 32 ||
            serviceCapability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Fail("publication-shard-key-invalid",
                "The bounded publication requires one exact non-zero service capability.");
        return await MintCurrentAuthorityAsync(
                networkId,
                serviceCapability,
                ReadOnlyMemory<byte>.Empty,
                AccountDirectoryAdp1ResultKind.NonMembership,
                ContactServiceRequestKind.PublishPreKeyInventory,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        ContactResolveCanonicalPathRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var authority = await MintCurrentAuthorityAsync(
                request.NetworkId,
                request.ShardKey,
                ReadOnlyMemory<byte>.Empty,
                AccountDirectoryAdp1ResultKind.NonMembership,
                request.RequestKind,
                cancellationToken)
            .ConfigureAwait(false);
        var placement = authority.Placement;
        if (!Fixed(request.NetworkId.Span, authority.Network.NetworkId.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span) ||
            !placement.Binds(request.RequestKind, request.ShardKey) ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw Fail("request-placement-mismatch",
                "The canonical ContactResolve request does not bind its current NETCODEC placement.");
        return authority;
    }

    /// <summary>
    /// Mints pre-authoring placement authority for a locally stored pending
    /// address.  No XIQ1, raw view hash or raw placement hash is required.
    /// </summary>
    public async ValueTask<VerifiedContactResolverPlacementContext> MintPlacementContextAsync(
        ContactStoreScope accountScope,
        PendingContactAddress pendingAddress,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(pendingAddress);
        var locator = ContactCodecHash.OneTimeOrPermanentLocator(pendingAddress.Address);
        try
        {
            var authority = await MintCurrentAuthorityAsync(
                pendingAddress.Address.NetworkId, locator, ReadOnlyMemory<byte>.Empty,
                AccountDirectoryAdp1ResultKind.NonMembership,
                ContactServiceRequestKind.ResolveInvite,
                cancellationToken).ConfigureAwait(false);
            return VerifiedContactResolverPlacementContext.Create(
                accountScope, pendingAddress, authority.Placement);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locator);
        }
    }

    async ValueTask<ContactResolveCurrentValuePathAuthority>
        IContactResolveClaimPathAuthoritySource.GetCurrentForOneTimeClaimAsync(
            Xiq1Request request,
            ReadOnlyMemory<byte> directoryLookupKey,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (directoryLookupKey.Length != 32 || directoryLookupKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Fail("directory-lookup-key-invalid",
                "The one-time claim requires one exact non-zero 32-byte ADL1 lookup key.");

        var resolved = await MintCurrentAuthorityAsync(
            request.NetworkId, request.LocatorHash, directoryLookupKey,
            AccountDirectoryAdp1ResultKind.CurrentValue,
            ContactServiceRequestKind.ResolveInvite,
            cancellationToken).ConfigureAwait(false);
        if (!Fixed(request.NetworkId.Span, resolved.Network.NetworkId.Span)
            || !Fixed(request.ViewHash.Span, resolved.Placement.ViewHash.Span)
            || !Fixed(request.PlacementHash.Span, resolved.Placement.PlacementHash.Span)
            || !resolved.Placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash)
            || request.ExpiresAtUnixSeconds > resolved.Placement.ValidUntilUnixSeconds)
            throw Fail("request-placement-mismatch",
                "XIQ1 does not bind the exact current one-time claim view and placement.");
        var canonical = resolved.Canonical ?? throw Fail(
            "claim-authority-incomplete", "The canonical one-time claim authority projection is missing.");
        return new ContactResolveCurrentValuePathAuthority(
            canonical.Authority,
            canonical.DirectoryFreshness,
            resolved.Network,
            resolved.Placement,
            canonical.ExactXnv1,
            canonical.ExactXnh1,
            canonical.ExactPmt2,
            canonical.CurrentBootId,
            canonical.CurrentMonotonicSample,
            canonical.TrustedTimeAuthority);
    }

    async ValueTask<ContactResolveCurrentValuePathAuthority>
        IContactResolvePermanentPathAuthoritySource.GetCurrentForPermanentResolveAsync(
            Xiq1Request request,
            Deep.Protocol.ApplicationCore.ParsedDid1 permanentDeepId,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(permanentDeepId);
        var directoryLeafKey = PermanentDirectoryLeafKey(
            request.NetworkId.Span, permanentDeepId.CanonicalBytes.Span);
        try
        {
            var resolved = await MintCurrentAuthorityAsync(
                request.NetworkId, request.LocatorHash, directoryLeafKey,
                AccountDirectoryAdp1ResultKind.CurrentValue,
                ContactServiceRequestKind.ResolveInvite,
                cancellationToken).ConfigureAwait(false);
            if (!Fixed(request.NetworkId.Span, resolved.Network.NetworkId.Span)
                || !Fixed(request.ViewHash.Span, resolved.Placement.ViewHash.Span)
                || !Fixed(request.PlacementHash.Span, resolved.Placement.PlacementHash.Span)
                || !resolved.Placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash)
                || request.ExpiresAtUnixSeconds > resolved.Placement.ValidUntilUnixSeconds)
                throw Fail("request-placement-mismatch",
                    "XIQ1 does not bind the exact current permanent resolve view and placement.");
            var canonical = resolved.Canonical ?? throw Fail(
                "permanent-authority-incomplete",
                "The canonical permanent resolve authority projection is missing.");
            return new ContactResolveCurrentValuePathAuthority(
                canonical.Authority,
                canonical.DirectoryFreshness,
                resolved.Network,
                resolved.Placement,
                canonical.ExactXnv1,
                canonical.ExactXnh1,
                canonical.ExactPmt2,
                canonical.CurrentBootId,
                canonical.CurrentMonotonicSample,
                canonical.TrustedTimeAuthority);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(directoryLeafKey);
        }
    }

    private async ValueTask<ContactResolvePathAuthority> MintCurrentAuthorityAsync(
        ReadOnlyMemory<byte> expectedNetworkId,
        ReadOnlyMemory<byte> resolverShardKey,
        ReadOnlyMemory<byte> requiredDirectoryLookupKey,
        AccountDirectoryAdp1ResultKind requiredDirectoryResultKind,
        ContactServiceRequestKind requestKind,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fixed(expectedNetworkId.Span, genesisPin.NetworkId.Span))
            throw Fail("request-network-mismatch", "The pending address or XIQ1 does not name the pinned XPoint network.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directoryState = await directoryStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (directoryState?.ForkLatched == true)
                throw Fail("directory-fork-latched", "The protected account-directory fork latch blocks ContactResolve.");

            var networkState = await networkStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (networkState?.ForkLatched == true)
                throw Fail("network-fork-latched", "The protected XPoint network fork latch blocks ContactResolve.");
            EnsureLiveContextMatchesProtectedState(networkState);

            var fetchContext = new ContactResolveDirectoryFetchContext(
                genesisPin.NetworkId.Span, directoryState, networkState,
                requiredDirectoryLookupKey.Span);
            var package = await artifacts.FetchCurrentAsync(fetchContext, cancellationToken)
                .ConfigureAwait(false)
                ?? throw Fail("directory-package-unavailable", "The directory adapter returned no canonical package.");
            CanonicalContactResolveAuthority? canonical = null;
            VerifiedOnionNetworkContext network;
            try
            {
                if (requiredDirectoryResultKind == AccountDirectoryAdp1ResultKind.CurrentValue)
                {
                    canonical = await verifier.VerifyCurrentValueAsync(
                        genesisPin, package, networkState, liveContext, cancellationToken)
                        .ConfigureAwait(false);
                    network = canonical.Network;
                }
                else
                {
                    network = await verifier.VerifyAsync(
                        genesisPin, package, networkState, liveContext, cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch (OnionBoundaryException exception) when (
                networkState is not null && exception.Code == "network-fork")
            {
                await LatchExactNetworkForkAsync(networkState, cancellationToken).ConfigureAwait(false);
                throw Fail("network-fork-latched",
                    "A signed successor conflicts with protected XPoint network LKG; the fork latch is now set.",
                    exception);
            }
            network.EnsureCurrent();

            var placement = ContactServicePlacementFactory.Create(
                network,
                requestKind,
                resolverShardKey);
            if (!Fixed(expectedNetworkId.Span, network.NetworkId.Span)
                || !placement.Binds(requestKind, resolverShardKey))
                throw Fail("verified-placement-mismatch",
                    "The derived Contact placement does not bind the requested network, kind and shard key.");

            var advance = await networkStateClient.ApplyVerifiedNetworkContextAsync(network, cancellationToken)
                .ConfigureAwait(false);
            if (advance.Disposition is XPointNetworkAdvanceDisposition.StaleCapability)
                throw Fail("network-rollback", "The verified network package is stale against protected LKG.");
            if (advance.Disposition is XPointNetworkAdvanceDisposition.ForkLatched)
                throw Fail("network-fork-latched", "The protected XPoint network fork latch blocks ContactResolve.");
            if (!Same(advance.Snapshot.ProtectedLkg, network.ProtectedLkg))
                throw Fail("network-state-mismatch", "The committed protected LKG differs from the verified network capability.");

            var appliedDirectory = await directoryStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (appliedDirectory is null || appliedDirectory.ForkLatched)
                throw Fail("directory-state-rejected", "The verified directory freshness did not produce usable protected state.");

            liveContext = network;
            return new ContactResolvePathAuthority(network, placement, canonical);
        }
        catch (ContactResolvePathException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            AccountDirectoryFreshnessVerificationException or
            XPointNetworkAuthorityVerificationException or
            XPointNetworkForwardCheckpointVerificationException or
            OnionBoundaryException or CryptographicException or
            FormatException or ArgumentException or InvalidOperationException)
        {
            throw Fail("canonical-authority-invalid",
                "The canonical directory package could not mint current ContactResolve authority.", exception);
        }
        finally
        {
            gate.Release();
        }
    }

    private void EnsureLiveContextMatchesProtectedState(XPointNetworkStateSnapshot? state)
    {
        if (liveContext is null) return;
        if (state is null || !Same(state.ProtectedLkg, liveContext.ProtectedLkg))
            throw Fail("live-context-state-mismatch",
                "The process-local verified network capability does not equal protected LKG.");
    }

    private async ValueTask LatchExactNetworkForkAsync(
        XPointNetworkStateSnapshot observed,
        CancellationToken cancellationToken)
    {
        var replacement = new XPointNetworkStateSnapshot(
            checked(observed.Revision + 1),
            observed.ProtectedLkg,
            forkLatched: true);
        var write = await networkStore.CompareExchangeAsync(
            observed.Revision, replacement, cancellationToken).ConfigureAwait(false);
        if (write.Disposition != XPointNetworkStoreWriteDisposition.Applied
            && write.Snapshot?.ForkLatched != true)
            throw Fail("network-state-contended",
                "Protected network state changed while recording verified fork evidence.");
    }

    private static bool Same(XPointNetworkProtectedLkg left, XPointNetworkProtectedLkg? right)
    {
        if (right is null) return false;
        var leftBytes = XPointNetworkProtectedLkgCodec.Encode(left);
        var rightBytes = XPointNetworkProtectedLkgCodec.Encode(right);
        try { return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes); }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] PermanentDirectoryLeafKey(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> exactDid1)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw Fail("directory-network-invalid",
                "Permanent directory lookup requires one exact non-zero network ID.");
        if (exactDid1.IsEmpty)
            throw Fail("directory-did-invalid",
                "Permanent directory lookup requires exact DID1 canonical bytes.");

        var preimage = new byte[checked(networkId.Length + exactDid1.Length)];
        byte[]? lookup = null;
        try
        {
            networkId.CopyTo(preimage);
            exactDid1.CopyTo(preimage.AsSpan(networkId.Length));
            lookup = Sha256Domain("Deep/AccountDirectory/V1/lookup", preimage);
            return Sha256Domain("Deep/AccountDirectory/V1/leaf", lookup);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
            if (lookup is not null) CryptographicOperations.ZeroMemory(lookup);
        }
    }

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = System.Text.Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
                preimage.AsSpan(label.Length + 1), checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }

    private static ContactResolvePathException Fail(string code, string message, Exception? inner = null) =>
        new(code, message, inner);
}

internal sealed class CanonicalContactResolveAuthority
{
    internal CanonicalContactResolveAuthority(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness directoryFreshness,
        VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactPmt2,
        ReadOnlyMemory<byte> currentBootId,
        ulong currentMonotonicSample,
        OnionTrustedTimeAuthority trustedTimeAuthority)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        DirectoryFreshness = directoryFreshness ?? throw new ArgumentNullException(nameof(directoryFreshness));
        Network = network ?? throw new ArgumentNullException(nameof(network));
        ExactXnv1 = exactXnv1.ToArray();
        ExactXnh1 = exactXnh1.ToArray();
        ExactPmt2 = exactPmt2.ToArray();
        CurrentBootId = currentBootId.ToArray();
        CurrentMonotonicSample = currentMonotonicSample;
        TrustedTimeAuthority = trustedTimeAuthority ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
    }

    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal VerifiedAccountDirectoryFreshness DirectoryFreshness { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal ReadOnlyMemory<byte> ExactXnv1 { get; }
    internal ReadOnlyMemory<byte> ExactXnh1 { get; }
    internal ReadOnlyMemory<byte> ExactPmt2 { get; }
    internal ReadOnlyMemory<byte> CurrentBootId { get; }
    internal ulong CurrentMonotonicSample { get; }
    internal OnionTrustedTimeAuthority TrustedTimeAuthority { get; }
}

internal interface ICanonicalContactResolveAuthorityVerifier
{
    ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        CancellationToken cancellationToken);

    ValueTask<CanonicalContactResolveAuthority> VerifyCurrentValueAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        CancellationToken cancellationToken) =>
        ValueTask.FromException<CanonicalContactResolveAuthority>(
            new ContactResolvePathException(
                "claim-authority-producer-unavailable",
                "The configured canonical verifier cannot mint current-value claim authority."));
}

internal sealed class ProtocolCanonicalContactResolveAuthorityVerifier : ICanonicalContactResolveAuthorityVerifier
{
    private readonly AccountDirectoryClient directoryClient;
    private readonly OnionTrustedTimeAuthority trustedTimeAuthority;
    private readonly ushort supportedDirectoryReader;

    internal ProtocolCanonicalContactResolveAuthorityVerifier(
        AccountDirectoryClient directoryClient,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        ushort supportedDirectoryReader)
    {
        this.directoryClient = directoryClient ?? throw new ArgumentNullException(nameof(directoryClient));
        this.trustedTimeAuthority = trustedTimeAuthority ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
        if (supportedDirectoryReader == 0)
            throw new ArgumentOutOfRangeException(nameof(supportedDirectoryReader));
        this.supportedDirectoryReader = supportedDirectoryReader;
    }

    public async ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        CancellationToken cancellationToken) =>
        (await VerifyCoreAsync(
            genesisPin, artifacts, protectedNetworkState, livePrevious,
            AccountDirectoryAdp1ResultKind.NonMembership, cancellationToken)
            .ConfigureAwait(false)).Network;

    public ValueTask<CanonicalContactResolveAuthority> VerifyCurrentValueAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        CancellationToken cancellationToken) =>
        VerifyCoreAsync(
            genesisPin, artifacts, protectedNetworkState, livePrevious,
            AccountDirectoryAdp1ResultKind.CurrentValue, cancellationToken);

    private async ValueTask<CanonicalContactResolveAuthority> VerifyCoreAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        AccountDirectoryAdp1ResultKind requiredDirectoryResultKind,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        ArgumentNullException.ThrowIfNull(artifacts);
        cancellationToken.ThrowIfCancellationRequested();

        var forward = artifacts.ForwardCheckpoint;
        if (protectedNetworkState is not null && livePrevious is null && forward is null)
            throw new ContactResolvePathException(
                "network-predecessor-capability-unavailable",
                "Protected XLK1 exists, but Protocol cannot restore its non-serializable predecessor capability without XNF1/NFP1.");
        if (protectedNetworkState is null && (livePrevious is not null || forward is not null))
            throw new ContactResolvePathException(
                "network-bootstrap-state-mismatch",
                "A predecessor or forward checkpoint cannot initialize an empty protected network store.");
        if (livePrevious is not null && forward is not null)
            throw new ContactResolvePathException(
                "network-advance-ambiguous",
                "Normal successor and forward-checkpoint paths cannot be combined.");

        var authority = XPointNetworkAuthorityVerifier.Verify(
            genesisPin,
            artifacts.ExactXna1AuthorityChain,
            artifacts.ExactDts1PolicyChain);
        if (!CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, genesisPin.NetworkId.Span))
            throw new ContactResolvePathException("authority-network-mismatch", "Verified XNA1 is outside the pinned network.");

        AccountDirectoryProtectedLkg? directoryLkg = null;
        var directoryState = await directoryClient.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (directoryState?.ForkLatched == true)
            throw new ContactResolvePathException("directory-fork-latched", "The protected account-directory fork latch is set.");
        if (directoryState is not null)
            directoryLkg = await directoryClient.RestoreProtectedLkgAsync(authority, cancellationToken).ConfigureAwait(false);

        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            artifacts.ExactAdh1,
            artifacts.ExactDtt1,
            artifacts.ExactAdp1,
            artifacts.CallerNonce.Span,
            artifacts.QueriedDirectoryLeafKey.Span,
            artifacts.MonotonicRequestWindow,
            directoryLkg,
            currentCheckpoint: null,
            supportedDirectoryReader);
        if (freshness.ResultKind != requiredDirectoryResultKind)
            throw new ContactResolvePathException(
                "directory-proof-purpose-invalid",
                $"Directory proof kind {freshness.ResultKind} does not match required {requiredDirectoryResultKind}.");

        var appliedDirectory = await directoryClient.ApplyVerifiedAsync(
            freshness, null, null, cancellationToken).ConfigureAwait(false);
        if (appliedDirectory.ForkLatched || appliedDirectory.ProtectedLkg is null
            || !Fixed(appliedDirectory.ProtectedLkg.CoreHash.Span, freshness.NextProtectedLkg.CoreHash.Span)
            || !Fixed(appliedDirectory.ProtectedLkg.ExactAdh1.Span, freshness.NextProtectedLkg.ExactAdh1.Span))
            throw new ContactResolvePathException(
                "directory-lkg-rejected",
                "The verified ADH1 could not advance the protected directory LKG exactly.");

        if (forward is null)
        {
            var network = await OnionNetworkContextVerifier.VerifyAsync(
                authority,
                freshness,
                artifacts.ExactOrderedXvp1Chain,
                artifacts.ExactOrderedXnv1Chain,
                artifacts.ExactOrderedXnh1Chain,
                artifacts.ExactActiveXnd1,
                artifacts.ExactOrderedPmt2Chain,
                livePrevious,
                trustedTimeAuthority,
                cancellationToken).ConfigureAwait(false);
            return Complete(authority, freshness, network, artifacts);
        }

        if (artifacts.ExactOrderedXvp1Chain.Count != 1
            || artifacts.ExactOrderedXnv1Chain.Count != 1
            || artifacts.ExactOrderedXnh1Chain.Count != 1
            || artifacts.ExactOrderedPmt2Chain.Count != 1)
            throw new ContactResolvePathException(
                "forward-package-shape-invalid",
                "Forward recovery requires one exact target XVP1/XNV1/XNH1/PMT2 snapshot.");

        var checkpoint = await XPointNetworkForwardCheckpointVerifier.VerifyAsync(
            authority,
            freshness,
            protectedNetworkState!.ProtectedLkg,
            artifacts.ExactXna1AuthorityChain,
            forward.ExactOrderedXnf1Chain,
            forward.ExactNfp1,
            forward.ExactTargetXnv1,
            forward.ExactTargetXnh1,
            trustedTimeAuthority,
            cancellationToken).ConfigureAwait(false);
        var recovered = await OnionNetworkContextVerifier.VerifyFromForwardCheckpointAsync(
            authority,
            freshness,
            checkpoint,
            artifacts.ExactOrderedXvp1Chain[0],
            artifacts.ExactActiveXnd1,
            artifacts.ExactOrderedPmt2Chain[0],
            trustedTimeAuthority,
            cancellationToken).ConfigureAwait(false);
        return Complete(authority, freshness, recovered, artifacts);
    }

    private CanonicalContactResolveAuthority Complete(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedOnionNetworkContext network,
        ContactResolveDirectoryArtifacts artifacts) =>
        new(
            authority,
            freshness,
            network,
            artifacts.ExactOrderedXnv1Chain[^1],
            artifacts.ExactOrderedXnh1Chain[^1],
            artifacts.ExactOrderedPmt2Chain[^1],
            artifacts.MonotonicRequestWindow.BootId,
            artifacts.MonotonicRequestWindow.CurrentSample,
            trustedTimeAuthority);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
