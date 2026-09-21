using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
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
    IContactResolvePermanentPathAuthoritySource,
    IMailboxPrivacyNetworkAuthoritySource,
    IDisposable
{
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly IContactResolveDirectoryArtifactSource artifacts;
    private readonly IAccountDirectoryStateStore directoryStore;
    private readonly IXPointNetworkStateStore networkStore;
    private readonly XPointNetworkStateClient networkStateClient;
    private readonly ICanonicalContactResolveAuthorityVerifier verifier;
    private readonly IDisposable? ownedArtifacts;
    private readonly SemaphoreSlim gate = new(1, 1);
    private VerifiedOnionNetworkContext? liveContext;

    private sealed record LocalRouteProposalContext(
        VerifiedContactRouteProposalAuthority Proposal,
        CanonicalContactResolveAuthority Canonical,
        VerifiedOnionNetworkContext Network,
        VerifiedAccountDirectoryCurrentValueClosure CurrentIdentity,
        VerifiedDevice RecipientDevice,
        CurrentlyAuthoritativeDca1 RecipientAuthorization);

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
                supportedDirectoryReader),
            ownedArtifacts: null)
    {
    }

    internal ProductionContactResolvePathAuthoritySource(
        XPointNetworkGenesisPin genesisPin,
        IContactResolveDirectoryArtifactSource artifacts,
        IAccountDirectoryStateStore directoryStore,
        IXPointNetworkStateStore networkStore,
        IOnionMonotonicClock monotonicClock,
        ushort supportedDirectoryReader,
        bool ownsArtifacts)
        : this(
            genesisPin,
            artifacts,
            directoryStore,
            networkStore,
            new ProtocolCanonicalContactResolveAuthorityVerifier(
                new AccountDirectoryClient(directoryStore),
                new OnionTrustedTimeAuthority(monotonicClock),
                supportedDirectoryReader),
            ownsArtifacts ? artifacts as IDisposable : null)
    {
        if (ownsArtifacts && artifacts is not IDisposable)
        {
            throw new ArgumentException(
                "An owned ContactResolve artifact source must be disposable.",
                nameof(artifacts));
        }
    }

    internal ProductionContactResolvePathAuthoritySource(
        XPointNetworkGenesisPin genesisPin,
        IContactResolveDirectoryArtifactSource artifacts,
        IAccountDirectoryStateStore directoryStore,
        IXPointNetworkStateStore networkStore,
        ICanonicalContactResolveAuthorityVerifier verifier)
        : this(
            genesisPin,
            artifacts,
            directoryStore,
            networkStore,
            verifier,
            ownedArtifacts: null)
    {
    }

    private ProductionContactResolvePathAuthoritySource(
        XPointNetworkGenesisPin genesisPin,
        IContactResolveDirectoryArtifactSource artifacts,
        IAccountDirectoryStateStore directoryStore,
        IXPointNetworkStateStore networkStore,
        ICanonicalContactResolveAuthorityVerifier verifier,
        IDisposable? ownedArtifacts)
    {
        this.genesisPin = genesisPin ?? throw new ArgumentNullException(nameof(genesisPin));
        this.artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        this.directoryStore = directoryStore ?? throw new ArgumentNullException(nameof(directoryStore));
        this.networkStore = networkStore ?? throw new ArgumentNullException(nameof(networkStore));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.ownedArtifacts = ownedArtifacts;
        networkStateClient = new XPointNetworkStateClient(networkStore);
    }

    public void Dispose() => ownedArtifacts?.Dispose();

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

    async ValueTask<VerifiedOnionNetworkContext>
        IMailboxPrivacyNetworkAuthoritySource.GetCurrentForMailboxAsync(
            ReadOnlyMemory<byte> placementCommitment,
            CancellationToken cancellationToken)
    {
        if (placementCommitment.Length != 32 ||
            placementCommitment.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw Fail(
                "mailbox-placement-commitment-invalid",
                "Mailbox authority refresh requires one exact non-zero placement commitment.");
        }

        var authority = await MintCurrentAuthorityAsync(
                genesisPin.NetworkId,
                placementCommitment,
                ReadOnlyMemory<byte>.Empty,
                AccountDirectoryAdp1ResultKind.NonMembership,
                ContactServiceRequestKind.ResolveInvite,
                cancellationToken)
            .ConfigureAwait(false);
        return authority.Network;
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
            request.HasExplicitPlacementBinding &&
                (!Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
                 !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span)) ||
            !request.HasExplicitPlacementBinding &&
                !authority.Network.BindsProjection(request.ProjectionReference) ||
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
                cancellationToken,
                permanentDeepId.CanonicalBytes).ConfigureAwait(false);
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

    /// <summary>
    /// Mints the local route-publication proposal from the exact admitted
    /// account-directory leaf and current verified XPoint closure. The caller
    /// cannot substitute raw DCA1, device, ADH1 or network-view bytes.
    /// </summary>
    public async ValueTask<VerifiedContactRouteProposalAuthority>
        MintLocalRouteProposalAsync(
            DeepGenesisDeviceActivation activation,
            CancellationToken cancellationToken = default)
        => (await MintLocalRouteProposalContextAsync(
                activation, cancellationToken).ConfigureAwait(false)).Proposal;

    private async ValueTask<LocalRouteProposalContext>
        MintLocalRouteProposalContextAsync(
            DeepGenesisDeviceActivation activation,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(activation);
        var leafKey = activation.DirectoryCheckpoint.Checkpoint.DirectoryLeafKey;
        var resolved = await MintCurrentAuthorityAsync(
                activation.VerifiedDevice.Certificate.NetworkId,
                leafKey,
                leafKey,
                AccountDirectoryAdp1ResultKind.CurrentValue,
                ContactServiceRequestKind.PublishInvite,
                cancellationToken,
                activation.AddressBinding.Head.DeepId.CanonicalBytes)
            .ConfigureAwait(false);
        var canonical = resolved.Canonical ?? throw Fail(
            "route-proposal-authority-incomplete",
            "The local current-value package produced no canonical route authority.");
        var current = canonical.CurrentValueClosure ?? throw Fail(
            "route-proposal-current-identity-missing",
            "The local current-value package did not verify the exact DID1 closure.");
        var recipient = current.Directory.Head.Identity.ActiveDevices.SingleOrDefault(
            device => Fixed(
                device.Certificate.DeviceId.Span,
                activation.VerifiedDevice.Certificate.DeviceId.Span)) ??
            throw Fail(
                "route-proposal-device-missing",
                "The current directory no longer contains the local publication device.");
        var authorization = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
            ApplicationCoreVerifier.VerifyDca1(
                ApplicationCoreCodec.DecodeDca1(
                    activation.ContactPublicationAuthorization.Verified.Record.CanonicalBytes.Span),
                current.AddressBinding.Head,
                current.Directory.Head),
            canonical.DirectoryFreshness.TrustedUpperUnixSeconds);
        var proposal = await ContactNetworkAuthorityVerifier.VerifyProposalAsync(
                canonical.Authority,
                resolved.Network,
                canonical.DirectoryFreshness,
                recipient,
                authorization,
                canonical.ExactXnv1,
                canonical.ExactXnh1,
                canonical.DirectoryFreshness.ExactAdh1,
                canonical.ExactPmt2,
                canonical.TrustedTimeAuthority,
                cancellationToken)
            .ConfigureAwait(false);
        return new LocalRouteProposalContext(
            proposal, canonical, resolved.Network, current,
            recipient, authorization);
    }

    /// <summary>
    /// Re-verifies the exact confirmed local XPU1 route after restart against
    /// the current XPoint/directory authority. The encrypted DCR1 is opened by
    /// the account's permanent resolver capability solely to recover the exact
    /// device-signed XIR1 omitted from the six-record route closure.
    /// </summary>
    public async ValueTask<VerifiedContactRouteClosure> RecoverLocalRouteAsync(
        DeepGenesisDeviceActivation activation,
        Xpu1Request confirmedPublication,
        CancellationToken cancellationToken = default)
        => (await RecoverLocalMessagingRecipientAsync(
                activation, confirmedPublication, cancellationToken)
            .ConfigureAwait(false)).Route;

    public async ValueTask<VerifiedLocalMessagingRecipient>
        RecoverLocalMessagingRecipientAsync(
            DeepGenesisDeviceActivation activation,
            Xpu1Request confirmedPublication,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activation);
        ArgumentNullException.ThrowIfNull(confirmedPublication);
        var context = await MintLocalRouteProposalContextAsync(
                activation, cancellationToken)
            .ConfigureAwait(false);
        var parsed = ContactRouteClosureCodec.Decode(
            confirmedPublication.ExactRouteClosure.Span);
        var authority = await ContactNetworkAuthorityVerifier.BindSelectionAsync(
                context.Proposal,
                parsed.Selection.CanonicalBytes,
                cancellationToken)
            .ConfigureAwait(false);
        var protectedDcr = confirmedPublication.ObjectCiphertext.ToArray();
        try
        {
            using var resolution = PermanentContactResolutionDerivation.Derive(
                activation.VerifiedDevice.Certificate.NetworkId.Span,
                activation.AddressBinding.Head.DeepId);
            var dcr = Dcr1ObjectProtectionCodec.OpenPermanent(
                protectedDcr,
                activation.VerifiedDevice.Certificate.NetworkId.Span,
                activation.AddressBinding.Head.DeepId,
                resolution);
            var bundleRecord = ContactCodec.Decode("DCB1", dcr.Field(2).Span);
            var descriptor = bundleRecord.Field(14).Span;
            if (descriptor.Length != 651 ||
                BinaryPrimitives.ReadUInt32BigEndian(descriptor.Slice(36, 4)) != 611)
                throw new CryptographicException(
                    "The confirmed local DCB1 does not contain exact XIR1 framing.");
            var invite = ContactCodec.Decode("XIR1", descriptor[40..]);
            var route = ContactCodec.VerifyRouteUpdateClosure(
                invite,
                parsed.Reachability,
                parsed.Authorization,
                parsed.Route,
                parsed.Successor,
                parsed.Projection,
                parsed.Selection,
                authority);
            var bundle = ContactCodec.VerifyDcr1Closure(
                dcr,
                context.RecipientAuthorization,
                context.Canonical.DirectoryFreshness,
                context.Canonical.CurrentBootId.Span,
                context.Canonical.CurrentMonotonicSample);
            return new VerifiedLocalMessagingRecipient(
                route,
                bundle,
                context.Network,
                context.Canonical.TrustedTimeAuthority);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedDcr);
        }
    }

    /// <summary>
    /// Resolves the current, non-forked sender directory required to verify an
    /// unsolicited DPH2. The exact DID1 is authenticated by the DPH2 header;
    /// it supplies both the targeted directory lookup preimage and the bytes
    /// deliberately omitted by the ADP1 public projection.
    /// </summary>
    public async ValueTask<VerifiedInboundInitiatorDirectory>
        ResolveInboundInitiatorDirectoryAsync(
            Dph2Record initiation,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiation);
        var did = Deep.Protocol.ApplicationCore.ApplicationCoreCodec.DecodeDid1(
            initiation.InitiatorDid1.Span);
        var lookup = DirectoryLookupKey(
            initiation.NetworkId.Span, did.CanonicalBytes.Span);
        try
        {
            var resolved = await MintCurrentAuthorityAsync(
                    initiation.NetworkId,
                    initiation.InitiatorAccountId,
                    lookup,
                    AccountDirectoryAdp1ResultKind.CurrentValue,
                    ContactServiceRequestKind.ResolveInvite,
                    cancellationToken,
                    did.CanonicalBytes)
                .ConfigureAwait(false);
            var canonical = resolved.Canonical ?? throw Fail(
                "inbound-directory-authority-incomplete",
                "The inbound DPH2 directory lookup produced no current-value authority.");
            var closure = canonical.CurrentValueClosure ?? throw Fail(
                "inbound-directory-closure-missing",
                "The inbound DPH2 directory lookup did not verify its exact DID1 closure.");
            var head = closure.Directory.Head;
            var active = head.Record.ActiveDevices.SingleOrDefault(entry =>
                Fixed(entry.DeviceId.Span, initiation.InitiatorDeviceId.Span));
            if (!Fixed(head.Record.NetworkId.Span, initiation.NetworkId.Span) ||
                !Fixed(head.Record.DeepAccountId.Span,
                    initiation.InitiatorAccountId.Span) ||
                active is null ||
                !Fixed(active.Dpd1Reference.CanonicalBytes.Span,
                    initiation.InitiatorDpd1Ref.Span))
            {
                throw Fail(
                    "inbound-directory-scope-mismatch",
                    "The current directory does not contain the exact DPH2 initiator device.");
            }
            return new VerifiedInboundInitiatorDirectory(
                closure, canonical.DirectoryFreshness);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lookup);
        }
    }

    private async ValueTask<ContactResolvePathAuthority> MintCurrentAuthorityAsync(
        ReadOnlyMemory<byte> expectedNetworkId,
        ReadOnlyMemory<byte> resolverShardKey,
        ReadOnlyMemory<byte> requiredDirectoryLookupKey,
        AccountDirectoryAdp1ResultKind requiredDirectoryResultKind,
        ContactServiceRequestKind requestKind,
        CancellationToken cancellationToken,
        ReadOnlyMemory<byte> exactDid1 = default)
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
                    canonical = exactDid1.IsEmpty
                        ? await verifier.VerifyCurrentValueAsync(
                            genesisPin, package, networkState, liveContext,
                            cancellationToken).ConfigureAwait(false)
                        : await verifier.VerifyCurrentValueWithDidAsync(
                            genesisPin, package, networkState, liveContext,
                            exactDid1, cancellationToken).ConfigureAwait(false);
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

    private static byte[] DirectoryLookupKey(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> exactDid1)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            exactDid1.IsEmpty)
            throw Fail("directory-lookup-invalid",
                "A directory lookup requires exact network and DID1 bytes.");
        var preimage = new byte[checked(networkId.Length + exactDid1.Length)];
        try
        {
            networkId.CopyTo(preimage);
            exactDid1.CopyTo(preimage.AsSpan(networkId.Length));
            return Sha256Domain("Deep/AccountDirectory/V1/lookup", preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
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

public sealed class VerifiedLocalMessagingRecipient
{
    private readonly VerifiedOnionNetworkContext network;

    internal VerifiedLocalMessagingRecipient(
        VerifiedContactRouteClosure route,
        VerifiedContactBundleClosure bundle,
        VerifiedOnionNetworkContext network,
        OnionTrustedTimeAuthority trustedTimeAuthority)
    {
        Route = route;
        Bundle = bundle;
        this.network = network;
        TrustedTimeAuthority = trustedTimeAuthority;
    }

    public VerifiedContactRouteClosure Route { get; }
    public VerifiedContactBundleClosure Bundle { get; }
    public VerifiedContactNetworkAuthority Authority => Route.Authority;
    public OnionTrustedTimeAuthority TrustedTimeAuthority { get; }

    public VerifiedContactServicePlacement RequireClaimPlacement(
        Xpk1Request request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var service = Bundle.GetAuthorizedPreKeyService(Authority);
        var placement = ContactServicePlacementFactory.Create(
            network,
            ContactServiceRequestKind.ClaimPreKey,
            service.ServiceCapability);
        if (!CryptographicOperations.FixedTimeEquals(
                request.NetworkId.Span, service.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.ServiceCapability.Span, service.ServiceCapability.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.Dcb1Hash.Span, service.Dcb1Hash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.Xps1Hash.Span, service.Xps1Hash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.ResponderDeviceId.Span, service.DeviceId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.ViewHash.Span, placement.ViewHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                request.PlacementHash.Span, placement.PlacementHash.Span) ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
        {
            throw new CryptographicException(
                "The encrypted XPK1 does not bind the current local recipient publication.");
        }
        return placement;
    }
}

public sealed class VerifiedInboundInitiatorDirectory
{
    internal VerifiedInboundInitiatorDirectory(
        VerifiedAccountDirectoryCurrentValueClosure closure,
        VerifiedAccountDirectoryFreshness freshness)
    {
        Closure = closure;
        Freshness = freshness;
    }

    public VerifiedAccountDirectoryCurrentValueClosure Closure { get; }
    public VerifiedAccountDirectoryFreshness Freshness { get; }
}

internal sealed class CanonicalContactResolveAuthority
{
    internal CanonicalContactResolveAuthority(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness directoryFreshness,
        VerifiedOnionNetworkContext network,
        VerifiedMailboxAuthorityV2 mailboxAuthority,
        ReadOnlyMemory<byte> exactXnv1,
        ReadOnlyMemory<byte> exactXnh1,
        ReadOnlyMemory<byte> exactPmt2,
        ReadOnlyMemory<byte> currentBootId,
        ulong currentMonotonicSample,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedAccountDirectoryCurrentValueClosure? currentValueClosure = null)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        DirectoryFreshness = directoryFreshness ?? throw new ArgumentNullException(nameof(directoryFreshness));
        Network = network ?? throw new ArgumentNullException(nameof(network));
        MailboxAuthority = mailboxAuthority ?? throw new ArgumentNullException(nameof(mailboxAuthority));
        ExactXnv1 = exactXnv1.ToArray();
        ExactXnh1 = exactXnh1.ToArray();
        ExactPmt2 = exactPmt2.ToArray();
        CurrentBootId = currentBootId.ToArray();
        CurrentMonotonicSample = currentMonotonicSample;
        TrustedTimeAuthority = trustedTimeAuthority ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
        CurrentValueClosure = currentValueClosure;
    }

    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal VerifiedAccountDirectoryFreshness DirectoryFreshness { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal VerifiedMailboxAuthorityV2 MailboxAuthority { get; }
    internal ReadOnlyMemory<byte> ExactXnv1 { get; }
    internal ReadOnlyMemory<byte> ExactXnh1 { get; }
    internal ReadOnlyMemory<byte> ExactPmt2 { get; }
    internal ReadOnlyMemory<byte> CurrentBootId { get; }
    internal ulong CurrentMonotonicSample { get; }
    internal OnionTrustedTimeAuthority TrustedTimeAuthority { get; }
    internal VerifiedAccountDirectoryCurrentValueClosure? CurrentValueClosure { get; }
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

    ValueTask<CanonicalContactResolveAuthority> VerifyCurrentValueWithDidAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        ReadOnlyMemory<byte> exactDid1,
        CancellationToken cancellationToken) =>
        VerifyCurrentValueAsync(
            genesisPin, artifacts, protectedNetworkState, livePrevious,
            cancellationToken);
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

    public ValueTask<CanonicalContactResolveAuthority> VerifyCurrentValueWithDidAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        ReadOnlyMemory<byte> exactDid1,
        CancellationToken cancellationToken) =>
        VerifyCoreAsync(
            genesisPin, artifacts, protectedNetworkState, livePrevious,
            AccountDirectoryAdp1ResultKind.CurrentValue, cancellationToken,
            exactDid1);

    private async ValueTask<CanonicalContactResolveAuthority> VerifyCoreAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactResolveDirectoryArtifacts artifacts,
        XPointNetworkStateSnapshot? protectedNetworkState,
        VerifiedOnionNetworkContext? livePrevious,
        AccountDirectoryAdp1ResultKind requiredDirectoryResultKind,
        CancellationToken cancellationToken,
        ReadOnlyMemory<byte> exactDid1 = default)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        ArgumentNullException.ThrowIfNull(artifacts);
        cancellationToken.ThrowIfCancellationRequested();

        var forward = artifacts.ForwardCheckpoint;
        var rehydratingCurrent = protectedNetworkState is not null && livePrevious is null && forward is null;
        if (protectedNetworkState is null && (livePrevious is not null || forward is not null))
            throw new ContactResolvePathException(
                "network-bootstrap-state-mismatch",
                "A predecessor or forward checkpoint cannot initialize an empty protected network store.");
        if (livePrevious is not null && forward is not null)
            throw new ContactResolvePathException(
                "network-advance-ambiguous",
                "Normal successor and forward-checkpoint paths cannot be combined.");

        VerifiedXPointNetworkAuthority authority;
        try
        {
            authority = XPointNetworkAuthorityVerifier.Verify(
                genesisPin,
                artifacts.ExactXna1AuthorityChain,
                artifacts.ExactDts1PolicyChain);
        }
        catch (Exception exception) when (rehydratingCurrent && exception is not OperationCanceledException)
        {
            throw PredecessorUnavailable(exception);
        }
        if (!CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, genesisPin.NetworkId.Span))
            throw new ContactResolvePathException("authority-network-mismatch", "Verified XNA1 is outside the pinned network.");

        AccountDirectoryProtectedLkg? directoryLkg = null;
        var directoryState = await directoryClient.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (directoryState?.ForkLatched == true)
            throw new ContactResolvePathException("directory-fork-latched", "The protected account-directory fork latch is set.");
        if (directoryState is not null)
            directoryLkg = await directoryClient.RestoreProtectedLkgAsync(authority, cancellationToken).ConfigureAwait(false);

        VerifiedAccountDirectoryCheckpoint? currentCheckpoint = null;
        VerifiedAccountDirectoryCurrentValueClosure? currentValueClosure = null;
        if (requiredDirectoryResultKind == AccountDirectoryAdp1ResultKind.CurrentValue &&
            !exactDid1.IsEmpty)
        {
            var proof = AccountDirectoryAdp1Codec.Decode(artifacts.ExactAdp1.Span);
            var current = proof.CurrentValue ?? throw new ContactResolvePathException(
                "directory-current-value-missing",
                "The targeted account-directory proof omitted its current value.");
            currentValueClosure = AccountDirectoryCurrentValueClosureVerifier.Verify(
                proof,
                exactDid1.Span,
                current.Adc1.IssuedAt,
                deploymentProfileId: 1,
                supportedDirectoryReader);
            currentCheckpoint = currentValueClosure.Checkpoint;
        }

        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            artifacts.ExactAdh1,
            artifacts.ExactDtt1,
            artifacts.ExactAdp1,
            artifacts.CallerNonce.Span,
            artifacts.QueriedDirectoryLeafKey.Span,
            artifacts.MonotonicRequestWindow,
            directoryLkg,
            currentCheckpoint,
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
            VerifiedOnionNetworkContext network;
            if (protectedNetworkState is not null && livePrevious is null)
            {
                try
                {
                    network = await OnionNetworkContextVerifier.VerifyRehydratedCurrentAsync(
                        authority,
                        freshness,
                        artifacts.ExactOrderedXvp1Chain,
                        artifacts.ExactOrderedXnv1Chain,
                        artifacts.ExactOrderedXnh1Chain,
                        artifacts.ExactActiveXnd1,
                        artifacts.ExactOrderedPmt2Chain,
                        protectedNetworkState.ProtectedLkg,
                        trustedTimeAuthority,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    throw PredecessorUnavailable(exception);
                }
            }
            else
            {
                network = await OnionNetworkContextVerifier.VerifyAsync(
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
            }
            return Complete(
                authority, freshness, network, artifacts, currentValueClosure);
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
        return Complete(
            authority, freshness, recovered, artifacts, currentValueClosure);
    }

    private CanonicalContactResolveAuthority Complete(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedOnionNetworkContext network,
        ContactResolveDirectoryArtifacts artifacts,
        VerifiedAccountDirectoryCurrentValueClosure? currentValueClosure)
    {
        VerifiedMailboxAuthorityV2 mailboxAuthority;
        try
        {
            mailboxAuthority = MailboxAuthorityV2Verifier.Verify(
                authority,
                artifacts.ExactPma2.Span,
                freshness.TrustedLowerUnixSeconds,
                freshness.TrustedUpperUnixSeconds);
            if (!mailboxAuthority.BindsProjection(
                    artifacts.ExactOrderedPmt2Chain[^1].Span))
                throw new CryptographicException(
                    "The terminal PMT2 does not bind the current PMA2 authority.");
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new ContactResolvePathException(
                "mailbox-authority-invalid",
                "The current ContactResolve package has no valid root-authorized PMA2/PMT2 binding.",
                exception);
        }

        return new CanonicalContactResolveAuthority(
            authority,
            freshness,
            network,
            mailboxAuthority,
            artifacts.ExactOrderedXnv1Chain[^1],
            artifacts.ExactOrderedXnh1Chain[^1],
            artifacts.ExactOrderedPmt2Chain[^1],
            artifacts.MonotonicRequestWindow.BootId,
            artifacts.MonotonicRequestWindow.CurrentSample,
            trustedTimeAuthority,
            currentValueClosure);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static ContactResolvePathException PredecessorUnavailable(Exception inner) =>
        new(
            "network-predecessor-capability-unavailable",
            "Protected XLK1 exists, but the current package cannot restore its exact non-serializable predecessor capability.",
            inner);
}
