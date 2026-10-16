using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Persistence.DeviceV2;
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
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPma2Chain)
    {
        IReadOnlyList<ReadOnlyMemory<byte>>[] values = [exactXna1AuthorityChain,
            exactDts1PolicyChain, exactOrderedXvp1Chain, exactOrderedXnv1Chain,
            exactOrderedXnh1Chain, exactActiveXnd1, exactOrderedPmt2Chain, exactOrderedPma2Chain];
        // Preflight every chain and the total before making owned copies.
        var total = 0L;
        foreach (var value in values)
            total = checked(total + DeepIdV2NetworkClosureBounds.ValidateChain(
                value, nameof(values), DeepIdV2NetworkClosureBounds.MaximumChainArtifacts));
        if (total > DeepIdV2NetworkClosureBounds.MaximumPackageBytes ||
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
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPma2Chain => Copy(7);
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
/// DID2-only network verification and pre-key publication/claim/mailbox path authority.
/// Each mint obtains an independent
/// nonce-bound proof for the protected local account, verifies NETCODEC from
/// the pinned root, and durably advances/rechecks network custody before
/// releasing placement. It cannot resolve DID1 or accept ADP1 V1. Input
/// providers, proof-client lifetime and durable stores remain caller-owned.
/// </summary>
public sealed partial class DeepIdV2ContactPathAuthoritySource :
    IContactResolvePathAuthoritySource, IContactResolvePublicationPathAuthoritySource,
    IMailboxPrivacyNetworkAuthoritySource
{
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly DeepIdV2AccountService accounts;
    private readonly DeepIdV2DirectoryProofClient proofs;
    private readonly IDeepIdV2NetworkClosureArtifactSource artifacts;
    private readonly IXPointNetworkStateStore networkStore;
    private readonly IDeepIdV2NetworkHistoryStore networkHistory;
    private readonly OnionTrustedTimeAuthority trustedTime;
    private readonly IOnionMonotonicClock clock;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal OnionTrustedTimeAuthority RendezvousTrustedTime => trustedTime;
    internal DeepIdV2AccountService AccountOwner => accounts;

    internal MailboxPrivacyPathProvider CreateOwnMailboxPaths(
        DeepIdV2OnionClientCustody custody, PrivacyMailboxRouteSelection selection)
    {
        ArgumentNullException.ThrowIfNull(custody);
        RequireAccountOwner(custody.Owner);
        return new(this, custody.Guards, selection, CreateMailboxGuardSalt);
    }

    internal MailboxPrivacyPathProvider CreateOwnHeldMailboxPaths(
        Did2OwnedMailboxTransportContext dispatch, PrivacyMailboxRouteSelection selection)
    {
        ArgumentNullException.ThrowIfNull(dispatch);
        RequireAccountOwner(dispatch.Custody.Owner);
        if (!ReferenceEquals(dispatch.Source, this))
            throw new ArgumentException("Held mailbox path belongs to another actual source.", nameof(dispatch));
        return new(dispatch, dispatch.Custody.Guards, selection, CreateMailboxGuardSalt);
    }

    async ValueTask<VerifiedOnionNetworkContext>
        IMailboxPrivacyNetworkAuthoritySource.GetCurrentForMailboxAsync(
            ReadOnlyMemory<byte> placementCommitment, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (placementCommitment.Length != 32 ||
            placementCommitment.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Mailbox network refresh requires an exact non-zero placement commitment.",
                nameof(placementCommitment));
        // A commitment is not a directory leaf or a holder/account identifier.
        // Always obtain the independent proof for this source's actual owner.
        return await VerifyCurrentNetworkAsync(genesisPin.NetworkId, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] CreateMailboxGuardSalt()
    {
        var salt = new byte[32];
        do RandomNumberGenerator.Fill(salt);
        while (salt.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return salt;
    }

    internal async ValueTask RecheckInitialClaimInitiatorAsync(
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness initiator,
        OwnPreKeyAuthoringAuthority own, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RequirePinnedNetwork(initiator.NetworkId);
            await proofs.RequireStillFreshAsync(initiator, own.Authority, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    // No source/fetch gate here: their normal holders can wait for this same
    // account lease. These calls only read immutable source-owned custody.
    internal async ValueTask<OnionMonotonicReading> RecheckEndpointPairUnderLeaseAsync(
        OwnPreKeyAuthoringAuthority authoring, Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness peer,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive(); RequirePinnedNetwork(peer.NetworkId);
        await proofs.RequirePairStillFreshUnderLeaseAsync(authoring.Proof, peer, authoring.Authority, held, ct).ConfigureAwait(false);
        if (networkHistory is not IDeepIdV2NetworkHistoryLeaseRead reader)
            throw new NotSupportedException("Held-account freshness requires the owned readonly network backend.");
        var floor = await reader.ReadHistoryUnderLeaseAsync(held, ct).ConfigureAwait(false);
        if (floor is null || floor.Snapshot.ForkLatched || !Same(floor.Snapshot.ProtectedLkg, authoring.Network.ProtectedLkg) ||
            !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(authoring.Network)))
            throw new CryptographicException("Held pre-key authoring no longer binds protected network custody.");
        authoring.Network.EnsureCurrent();
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ?? throw new CryptographicException("Held freshness has no monotonic sample.");
        if (!authoring.Proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !peer.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("Held authoring directory freshness expired.");
        held.RequireActive(); return reading;
    }

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
        networkHistory = networkStore as IDeepIdV2NetworkHistoryStore ??
            throw new ArgumentException("DID2 network authority requires account-owned complete history custody.", nameof(networkStore));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        trustedTime = new(this.clock);
    }

    public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(Xiq1Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return GetCurrentAsync(ContactResolveCanonicalPathRequest.Decode(request.CanonicalBytes.Span), cancellationToken);
    }

    public async ValueTask<ContactResolvePathAuthority> GetCurrentAsync(
        ContactResolveCanonicalPathRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestKind is not (ContactServiceRequestKind.PublishPreKeyInventory or
                ContactServiceRequestKind.ClaimPreKey or ContactServiceRequestKind.ResolveInvite) ||
            !request.HasExplicitPlacementBinding)
            throw new NotSupportedException("Only DID2 pre-key and neutral permanent read paths are enabled.");
        if (request.RequestKind == ContactServiceRequestKind.ClaimPreKey)
        {
            var claim = DeepIdV2PreKeyClaimRequestCodec.Decode(request.ExactRequest.Span);
            if (!Fixed(claim.Field(1).Span, request.NetworkId.Span) ||
                !Fixed(claim.Field(3).Span, request.ViewHash.Span) ||
                !Fixed(claim.Field(4).Span, request.PlacementHash.Span) ||
                !Fixed(claim.Field(16).Span, request.ShardKey.Span) ||
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(claim.Field(6).Span) !=
                    request.ExpiresAtUnixSeconds)
                throw new CryptographicException("The DID2 claim and canonical placement facts differ.");
        }
        else if (request.RequestKind == ContactServiceRequestKind.PublishPreKeyInventory)
        {
            var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(request.ExactRequest.Span);
            if (!Fixed(fragment.NetworkId.Span, request.NetworkId.Span) ||
                !Fixed(fragment.ViewHash.Span, request.ViewHash.Span) ||
                !Fixed(fragment.PlacementHash.Span, request.PlacementHash.Span))
                throw new CryptographicException("The DID2 request and fragment placement differ.");
        }
        else
        {
            var query = Xiq1Codec.Decode(request.ExactRequest.Span);
            if (query.RequestedGeneration != 0 || query.AntiSpamTokenType != Xiq1AntiSpamTokenType.None)
                throw new NotSupportedException("Only non-consuming DID2 genesis permanent reads are enabled.");
        }
        var current = await GetCurrentForPlacementAsync(request.NetworkId,
            request.ShardKey, request.RequestKind, cancellationToken).ConfigureAwait(false);
        if (!Fixed(request.ViewHash.Span, current.Placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, current.Placement.PlacementHash.Span) ||
            request.ExpiresAtUnixSeconds > current.Placement.ValidUntilUnixSeconds)
            throw new CryptographicException("The DID2 request does not bind current placement.");
        return current;
    }

    public ValueTask<ContactResolvePathAuthority> GetCurrentForPublicationAsync(
        ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> serviceCapability,
        CancellationToken cancellationToken = default) =>
        GetCurrentForPlacementAsync(networkId, serviceCapability,
            ContactServiceRequestKind.PublishPreKeyInventory, cancellationToken);

    /// <summary>Obtains a fresh account-owned network proof and derives claim
    /// placement. This does not verify recipient credentials, consume a key or
    /// grant messaging/session authority.</summary>
    public ValueTask<ContactResolvePathAuthority> GetCurrentForPreKeyClaimAsync(
        ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> serviceCapability,
        CancellationToken cancellationToken = default) =>
        GetCurrentForPlacementAsync(networkId, serviceCapability,
            ContactServiceRequestKind.ClaimPreKey, cancellationToken);

    private async ValueTask<ContactResolvePathAuthority> GetCurrentForPlacementAsync(
        ReadOnlyMemory<byte> networkId, ReadOnlyMemory<byte> serviceCapability,
        ContactServiceRequestKind kind, CancellationToken cancellationToken)
    {
        RequirePinnedNetwork(networkId);
        if (serviceCapability.Length != 32 ||
            serviceCapability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 placement requires the pinned network and exact service capability.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var verified = (await VerifyCurrentNetworkCoreAsync(
                cancellationToken).ConfigureAwait(false)).Network;
            var placement = ContactServicePlacementFactory.Create(verified,
                kind, serviceCapability);
            return new(verified, placement);
        }
        finally { gate.Release(); }
    }

    /// <summary>Verifies fresh account-bound network authority and commits/rechecks
    /// its account-owned protected floor, without inventing a service capability
    /// or selecting publication placement. It grants no message delivery authority.</summary>
    public async ValueTask<VerifiedOnionNetworkContext> VerifyCurrentNetworkAsync(
        ReadOnlyMemory<byte> networkId, CancellationToken cancellationToken = default)
    {
        RequirePinnedNetwork(networkId);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return (await VerifyCurrentNetworkCoreAsync(
                cancellationToken).ConfigureAwait(false)).Network;
        }
        finally { gate.Release(); }
    }

    private void RequirePinnedNetwork(ReadOnlyMemory<byte> networkId)
    {
        if (!Fixed(networkId.Span, genesisPin.NetworkId.Span))
            throw new ArgumentException("DID2 verification requires the pinned network.", nameof(networkId));
    }

    // Only account-owned orchestration receives the proof used to verify the
    // network. This is not a public caller-mintable authoring capability.
    internal sealed record OwnPreKeyAuthoringAuthority(
        VerifiedOnionNetworkContext Network,
        VerifiedXPointNetworkAuthority Authority,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness Proof,
        VerifiedMailboxAuthorityV2 MailboxAuthority,
        DeepIdV2NetworkClosureArtifacts NamespaceRecords)
    {
        // Bounded owned public records are lookup inputs, never historical
        // authority. Every selected exact pair must pass the current host's
        // strict retained-history/ancestor verifier before an owned effect.
        internal async ValueTask RequireOriginalMailboxNamespacesAsync(
            VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactIssuancePma2,
            ContactRecord originalProjection, Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain domain,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (domain is not (Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Deposit or
                Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve))
                throw new CryptographicException("Original namespace custody has no supported mailbox role.");
            // DR-0122: both roles use then-current issuance PMA2 while keeping
            // the exact logical assignment. Authenticate both historical joins;
            // these facts do not authorize current Store or Retrieve by themselves.
            var issuance = ContactCodec.Decode("PMA2", exactIssuancePma2.Span);
            if (Fixed(issuance.CoreHash.Span, originalProjection.Field(4).Span[6..]))
            {
                // The actual two namespaces coincide. The captured exact
                // policy already supplies the strict join; unrelated public
                // distribution metadata is neither needed nor authority.
                await host.RequireOriginalNamespaceAsync(issuance.CanonicalBytes, originalProjection.CanonicalBytes, ct).ConfigureAwait(false);
                return;
            }
            // PMT2's canonical decoder checks the complete typed PMA2 CoreRef
            // header, as in VerifyMailboxAuthorityAsync below.
            var issuanceProjection = NamespaceRecords.ExactOrderedPmt2Chain
                .Select(bytes => ContactCodec.Decode("PMT2", bytes.Span))
                .FirstOrDefault(candidate => Fixed(candidate.Field(4).Span[6..], issuance.CoreHash.Span)) ??
                throw new CryptographicException("Original mailbox issuance policy has no exact retained projection metadata.");
            var routePolicy = NamespaceRecords.ExactOrderedPma2Chain
                .Select(bytes => ContactCodec.Decode("PMA2", bytes.Span))
                .FirstOrDefault(candidate => Fixed(candidate.CoreHash.Span, originalProjection.Field(4).Span[6..])) ??
                throw new CryptographicException("Original mailbox route projection has no exact retained policy metadata.");
            await host.RequireOriginalNamespaceAsync(issuance.CanonicalBytes, issuanceProjection.CanonicalBytes, ct).ConfigureAwait(false);
            await host.RequireOriginalNamespaceAsync(routePolicy.CanonicalBytes, originalProjection.CanonicalBytes, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
        }
    }

    internal sealed record MessagingEndpointAuthority(OwnPreKeyAuthoringAuthority Own,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness Peer);

    internal async ValueTask<MessagingEndpointAuthority> VerifyForOwnMessagingAsync(
        DeepIdV2AccountService account, Did2MessagingSessionScope scope, CancellationToken ct,
        OwnPreKeyAuthoringAuthority? verifiedOwn = null)
    {
        RequireAccountOwner(account); ArgumentNullException.ThrowIfNull(scope);
        // This local read may finish an already committed bounded compaction
        // plan. It uses caller cancellation, not a network-authority deadline;
        // no fetch/signing/dispatch occurs during recovery under the lease.
        var did = await account.ReadOwnMessagingPeerCredentialAsync(scope, ct).ConfigureAwait(false);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        var token = budget.Token;
        await gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var own = verifiedOwn ?? await VerifyCurrentNetworkCoreAsync(token).ConfigureAwait(false);
            var peer = await proofs.FetchByDid2Async(did, own.Authority, account.DeploymentProfileId,
                supportedReader: 2, token).ConfigureAwait(false);
            ProtectedDid2MessagingPeerBootstrap.RequireProof(did, peer);
            await proofs.RequireStillFreshAsync(peer, own.Authority, token).ConfigureAwait(false);
            await proofs.RequireStillFreshAsync(own.Proof, own.Authority, token).ConfigureAwait(false);
            var floor = await networkHistory.ReadHistoryAsync(token).ConfigureAwait(false);
            if (floor is null || floor.Snapshot.ForkLatched || !Same(floor.Snapshot.ProtectedLkg, own.Network.ProtectedLkg) ||
                !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(own.Network)))
                throw new CryptographicException("Refreshed messaging endpoints no longer bind owned network custody.");
            own.Network.EnsureCurrent();
            var reading = await clock.ReadAsync(token).ConfigureAwait(false) ??
                throw new CryptographicException("Refreshed messaging endpoints have no protected clock sample.");
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, reading);
            token.ThrowIfCancellationRequested(); return new(own, peer);
        }
        finally { gate.Release(); }
    }

    internal void RequireAccountOwner(DeepIdV2AccountService account)
    {
        if (!ReferenceEquals(accounts, account))
            throw new ArgumentException("Pre-key authoring requires this source's account owner.", nameof(account));
    }

    internal async ValueTask<MessagingEndpointAuthority> VerifyForIncomingInitialAsync(
        DeepIdV2AccountService account, Deep.Protocol.MessagingWire.Dph2Record incoming, CancellationToken ct)
    {
        RequireAccountOwner(account); RequirePinnedNetwork(incoming.NetworkId);
        // Parsed identity is a query candidate, never incoming authentication.
        var did = Deep.Protocol.ApplicationCore.DeepIdV2Codec.DecodeDid2(incoming.InitiatorDid2.Span);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        await gate.WaitAsync(budget.Token).ConfigureAwait(false);
        try
        {
            var own = await VerifyCurrentNetworkCoreAsync(budget.Token).ConfigureAwait(false);
            var peer = await proofs.FetchByDid2Async(did, own.Authority, account.DeploymentProfileId,
                supportedReader: 2, budget.Token).ConfigureAwait(false);
            ProtectedDid2MessagingPeerBootstrap.RequireProof(did, peer);
            await proofs.RequireStillFreshAsync(peer, own.Authority, budget.Token).ConfigureAwait(false);
            await proofs.RequireStillFreshAsync(own.Proof, own.Authority, budget.Token).ConfigureAwait(false);
            own.Network.EnsureCurrent(); budget.Token.ThrowIfCancellationRequested();
            return new(own, peer);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<OwnPreKeyAuthoringAuthority> VerifyForOwnPreKeyAuthoringAsync(
        DeepIdV2AccountService account, CancellationToken cancellationToken)
    {
        RequireAccountOwner(account);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await VerifyCurrentNetworkCoreAsync(cancellationToken).ConfigureAwait(false); }
        finally { gate.Release(); }
    }

    internal async ValueTask<OnionMonotonicReading> RecheckOwnPreKeyAuthoringAsync(
        OwnPreKeyAuthoringAuthority authoring, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await proofs.RequireStillFreshAsync(authoring.Proof, authoring.Authority,
                cancellationToken).ConfigureAwait(false);
            var floor = await networkHistory.ReadHistoryAsync(cancellationToken).ConfigureAwait(false);
            if (floor is null || floor.Snapshot.ForkLatched ||
                !Same(floor.Snapshot.ProtectedLkg, authoring.Network.ProtectedLkg) ||
                !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(authoring.Network)))
                throw new CryptographicException("Pre-key authoring no longer binds protected network custody.");
            authoring.Network.EnsureCurrent();
            var reading = await clock.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!authoring.Proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
                throw new CryptographicException("Pre-key authoring directory freshness expired.");
            return reading;
        }
        finally { gate.Release(); }
    }

    internal sealed record PermanentContactAuthority(
        OwnPreKeyAuthoringAuthority Own, VerifiedDeepIdV2PermanentContactResolveClosure Contact);

    internal async ValueTask<PermanentContactAuthority> VerifyPermanentContactAsync(
        ParsedDeepIdV2PermanentContactCandidate candidate, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        RequirePinnedNetwork(candidate.Request.NetworkId);
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var own = await VerifyCurrentNetworkCoreAsync(ct).ConfigureAwait(false);
            var peer = await accounts.FetchContactPeerProofAsync(candidate, proofs, own.Authority, ct).ConfigureAwait(false);
            var contact = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate,
                peer, own.Network, own.Authority, trustedTime, ct).ConfigureAwait(false);
            await proofs.RequireStillFreshAsync(peer, own.Authority, ct).ConfigureAwait(false);
            await proofs.RequireStillFreshAsync(own.Proof, own.Authority, ct).ConfigureAwait(false);
            var floor = await networkHistory.ReadHistoryAsync(ct).ConfigureAwait(false);
            if (floor is null || floor.Snapshot.ForkLatched ||
                !Same(floor.Snapshot.ProtectedLkg, own.Network.ProtectedLkg) ||
                !Fixed(floor.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(own.Network)))
                throw new CryptographicException("Permanent resolve no longer binds owned network custody.");
            await contact.Route.EnsureCurrentAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return new(own, contact);
        }
        finally { gate.Release(); }
    }

    // The caller holds gate through verification and any placement derivation.
    private async ValueTask<OwnPreKeyAuthoringAuthority> VerifyCurrentNetworkCoreAsync(
        CancellationToken cancellationToken)
    {
        var retained = await networkHistory.ReadHistoryAsync(cancellationToken).ConfigureAwait(false);
        var before = retained?.Snapshot;
        if (before?.ForkLatched == true)
            throw new CryptographicException("Protected network fork latch blocks DID2 publication.");
        for (var acquisition = 0; acquisition < 2; acquisition++)
        {
            var exact = await artifacts.FetchCurrentAsync(genesisPin.NetworkId,
                before?.ProtectedLkg, cancellationToken).AsTask().WaitAsync(cancellationToken).ConfigureAwait(false) ??
                throw new CryptographicException("The DID2 signed network closure is absent.");
            var authority = XPointNetworkAuthorityVerifier.Verify(genesisPin,
                exact.ExactXna1AuthorityChain, exact.ExactDts1PolicyChain);
            var fresh = await accounts.FetchOwnCurrentDirectoryProofAsync(proofs,
                authority, cancellationToken).ConfigureAwait(false);
            networkHistory.RequireAccountScope(fresh.CurrentCheckpoint?.Binding.Record.DeepAccountId ??
                throw new CryptographicException("DID2 network verification requires this account's current checkpoint."));
            VerifiedOnionNetworkContext verified;
            try
            {
                verified = retained is not null
                    ? await OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(authority, fresh,
                        exact.ExactOrderedXvp1Chain, exact.ExactOrderedXnv1Chain,
                        exact.ExactOrderedXnh1Chain, exact.ExactActiveXnd1,
                        exact.ExactOrderedPmt2Chain, retained.ExactHistory, trustedTime,
                        cancellationToken).ConfigureAwait(false)
                    : await OnionNetworkContextVerifier.VerifyAsync(authority, fresh,
                        exact.ExactOrderedXvp1Chain, exact.ExactOrderedXnv1Chain,
                        exact.ExactOrderedXnh1Chain, exact.ExactActiveXnd1,
                        exact.ExactOrderedPmt2Chain, null, trustedTime,
                        cancellationToken).ConfigureAwait(false);
            }
            catch (OnionBoundaryException exception) when (
                acquisition == 0 && exception.Code == "dtt-binding-invalid" &&
                OnionNetworkContextVerifier.ProofNamesStrictlyNewerView(authority, fresh,
                    exact.ExactOrderedXnv1Chain[^1]))
            {
                // Read-only reacquisition under the same owned gate and caller
                // budget; never redispatch a command or reuse mismatched authority.
                await proofs.RequireStillFreshAsync(fresh, authority, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                continue;
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
            var mailboxAuthority = await VerifyMailboxAuthorityAsync(exact, verified, authority, fresh,
                cancellationToken).ConfigureAwait(false);
            if (retained is not null &&
                (!OnionNetworkProtectedHistoryCodec.BindsPredecessor(verified, retained.ExactHistory) ||
                 !Same(before!.ProtectedLkg, verified.PriorProtectedLkg)))
                throw new CryptographicException("Verified network did not bind the complete protected predecessor.");
            var committed = await networkHistory.ApplyVerifiedHistoryAsync(retained, verified,
                cancellationToken).ConfigureAwait(false);
            if (committed.Disposition is not (XPointNetworkAdvanceDisposition.Applied or
                XPointNetworkAdvanceDisposition.Idempotent) ||
                !Same(committed.Snapshot.ProtectedLkg, verified.ProtectedLkg))
                throw new CryptographicException("DID2 network custody did not commit the exact verified context.");
            var after = await networkHistory.ReadHistoryAsync(cancellationToken).ConfigureAwait(false);
            if (after is null || after.Snapshot.ForkLatched ||
                !Same(after.Snapshot.ProtectedLkg, verified.ProtectedLkg) ||
                !Fixed(after.ExactHistory.Span, OnionNetworkProtectedHistoryCodec.Encode(verified)))
                throw new CryptographicException("Committed DID2 network custody could not be reauthenticated.");
            await proofs.RequireStillFreshAsync(fresh, authority, cancellationToken).ConfigureAwait(false);
            verified.EnsureCurrent();
            mailboxAuthority = await VerifyMailboxAuthorityAsync(exact, verified, authority, fresh,
                cancellationToken).ConfigureAwait(false);
            return new(verified, authority, fresh, mailboxAuthority, exact);
        }
        throw new InvalidOperationException("Bounded coherent network acquisition did not produce a verified context.");
    }

    private async ValueTask<VerifiedMailboxAuthorityV2> VerifyMailboxAuthorityAsync(
        DeepIdV2NetworkClosureArtifacts exact, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness proof, CancellationToken ct)
    {
        var projection = ContactCodec.Decode("PMT2", exact.ExactOrderedPmt2Chain[^1].Span);
        if (!network.BindsProjection(ContactCodec.ArtifactReference("PMT2", projection).CanonicalBytes))
            throw new CryptographicException("Mailbox policy requires the exact current verified projection.");
        ContactRecord? selected = null;
        foreach (var value in exact.ExactOrderedPma2Chain)
        {
            var candidate = ContactCodec.Decode("PMA2", value.Span);
            // The PMT2 canonical decoder has already checked the complete
            // typed PMA2 CoreRef header. Compare its core, never invent a ref.
            if (!Fixed(candidate.CoreHash.Span, projection.Field(4).Span[6..])) continue;
            if (selected is not null)
                throw new CryptographicException("Mailbox policy distribution contains ambiguous current authority.");
            selected = candidate;
        }
        if (selected is null)
            throw new CryptographicException("The current signed mailbox issuer policy is absent.");
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("Mailbox issuer verification has no actual monotonic clock sample.");
        if (!proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("Mailbox issuer verification requires this account's current authenticated time.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - proof.MonotonicSample);
            lower = checked(proof.TrustedLowerUnixSeconds + elapsed);
            upper = checked(proof.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException error) { throw new CryptographicException("Mailbox policy time projection overflowed.", error); }
        var result = MailboxAuthorityV2Verifier.Verify(authority, selected.CanonicalBytes.Span, lower, upper);
        if (!result.BindsProjection(projection.CanonicalBytes.Span))
            throw new CryptographicException("Mailbox issuer policy differs from the current verified projection.");
        network.EnsureCurrent(); ct.ThrowIfCancellationRequested(); return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool Same(XPointNetworkProtectedLkg left, XPointNetworkProtectedLkg? right) =>
        right is not null && Fixed(XPointNetworkProtectedLkgCodec.Encode(left),
            XPointNetworkProtectedLkgCodec.Encode(right));
}
