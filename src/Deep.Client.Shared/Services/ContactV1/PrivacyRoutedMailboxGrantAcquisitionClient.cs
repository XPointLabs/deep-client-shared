using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Services.ContactV1;

public sealed class MailboxGrantAcquisitionException : Exception
{
    internal MailboxGrantAcquisitionException(
        MailboxGrantAcquisitionResultCode resultCode,
        bool retryable)
        : base($"Mailbox grant acquisition failed with {resultCode}.")
    {
        ResultCode = resultCode;
        Retryable = retryable;
    }

    public MailboxGrantAcquisitionResultCode ResultCode { get; }
    public bool Retryable { get; }
}

public sealed class VerifiedCurrentMailboxReplica
{
    private readonly byte[] nodeId;
    private readonly byte[] identityPublicKey;

    internal VerifiedCurrentMailboxReplica(
        ReadOnlySpan<byte> nodeId,
        ReadOnlySpan<byte> identityPublicKey)
    {
        if (nodeId.Length != 32 || nodeId.IndexOfAnyExcept((byte)0) < 0 ||
            identityPublicKey.Length != 32 ||
            identityPublicKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A verified mailbox replica binding is invalid.");
        this.nodeId = nodeId.ToArray();
        this.identityPublicKey = identityPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> NodeId => nodeId.ToArray();
    public ReadOnlyMemory<byte> IdentityPublicKey => identityPublicKey.ToArray();
}

/// <summary>
/// A single current-epoch MCG2 returned by exact XMG1/XMC1. This is deliberately
/// not the legacy current/next JSON bundle and carries no Session-derived ID.
/// </summary>
public sealed class VerifiedCurrentMailboxGrant
{
    private static ReadOnlySpan<byte> AccountScopeDomain =>
        "deep.mailbox.account-scope.v1"u8;
    private readonly byte[] exactXmg1;
    private readonly byte[] exactXmc1;
    private readonly byte[] exactGrant;
    private readonly byte[] exactRouteClosure;
    private readonly byte[] mailboxId;
    private readonly byte[] placementId;
    private readonly byte[] placementCommitment;
    private readonly byte[] membershipCommitment;
    private readonly byte[] holderPublicKey;
    private readonly VerifiedCurrentMailboxReplica[] replicas;
    private readonly VerifiedOfficialMailboxAuthority runtimeAuthority;

    internal VerifiedCurrentMailboxGrant(
        ContactRecord request,
        ContactRecord result,
        MailboxAuthenticatedGrant grant,
        ParsedContactRouteClosure route,
        IReadOnlyList<VerifiedCurrentMailboxReplica> replicas,
        VerifiedOfficialMailboxAuthority runtimeAuthority)
    {
        exactXmg1 = request.CanonicalBytes.ToArray();
        exactXmc1 = result.CanonicalBytes.ToArray();
        exactGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        exactRouteClosure = route.ExactBytes.ToArray();
        mailboxId = route.Reachability.Field(2).ToArray();
        placementId = route.Reachability.Field(10).ToArray();
        placementCommitment = grant.PlacementCommitment.ToArray();
        membershipCommitment = grant.MembershipCommitment.ToArray();
        holderPublicKey = grant.HolderPublicKey.ToArray();
        this.replicas = replicas.ToArray();
        this.runtimeAuthority = runtimeAuthority ??
            throw new ArgumentNullException(nameof(runtimeAuthority));
        if (mailboxId.Length != 32 || mailboxId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            placementId.Length != 32 || placementId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            !CryptographicOperations.FixedTimeEquals(
                placementCommitment,
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(placementId))) ||
            this.replicas.Length is < 2 or > 5)
            throw new CryptographicException(
                "The verified current mailbox grant route is malformed.");
        Domain = grant.Domain;
        Epoch = grant.Epoch;
        Generation = grant.Generation;
        NotBeforeUnixSeconds = grant.NotBeforeUnixSeconds;
        ExpiresAtUnixSeconds = grant.ExpiresAtUnixSeconds;
    }

    public MailboxCapabilityDomain Domain { get; }
    public ulong Epoch { get; }
    public ulong Generation { get; }
    public ulong NotBeforeUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> ExactXmg1 => exactXmg1.ToArray();
    public ReadOnlyMemory<byte> ExactXmc1 => exactXmc1.ToArray();
    public ReadOnlyMemory<byte> ExactGrant => exactGrant.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => exactRouteClosure.ToArray();
    public BlindedMailboxId MailboxId => new(mailboxId);
    public BlindedPlacementId PlacementId => new(placementId);
    public ReadOnlyMemory<byte> PlacementCommitment => placementCommitment.ToArray();
    public ReadOnlyMemory<byte> MembershipCommitment => membershipCommitment.ToArray();
    public ReadOnlyMemory<byte> HolderPublicKey => holderPublicKey.ToArray();
    public IReadOnlyList<VerifiedCurrentMailboxReplica> Replicas =>
        Array.AsReadOnly(replicas.ToArray());

    /// <summary>
    /// Atomically installs this exact verified XMC1 result into the clean
    /// mailbox store. Its authenticated PMA2 policy cannot be substituted by
    /// the caller.
    /// </summary>
    public Task InstallAsync(
        IScopedMailboxCredentialRepository repository,
        MailboxCredentialSelector selector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(selector);
        if (Domain == MailboxCapabilityDomain.Retrieve &&
                selector.Kind != MailboxCredentialScopeKind.Self ||
            Domain == MailboxCapabilityDomain.Deposit &&
                selector.Kind == MailboxCredentialScopeKind.Self)
            throw new InvalidOperationException(
                "The verified current grant role does not match its mailbox scope.");
        var epoch = new MailboxCredentialEpoch(
            Epoch,
            NotBeforeUnixSeconds,
            ExpiresAtUnixSeconds,
            MembershipCommitment.Span,
            PlacementId.Bytes.Span,
            PlacementCommitment.Span);
        var grants = Domain == MailboxCapabilityDomain.Retrieve
            ? new CurrentMailboxCredentialGrants(retrieveGrant: ExactGrant.Span)
            : new CurrentMailboxCredentialGrants(depositGrant: ExactGrant.Span);
        return repository.InstallCurrentScopedCredentialAsync(
            new ScopedCurrentMailboxCredential(
                selector,
                SHA256.HashData(ExactGrant.Span),
                HolderPublicKey,
                MailboxId.Bytes,
                epoch,
                grants,
                new MailboxCredentialReplicaPair(
                    replicas[0].NodeId.Span,
                    replicas[0].IdentityPublicKey.Span,
                    replicas[1].NodeId.Span,
                    replicas[1].IdentityPublicKey.Span)),
            runtimeAuthority,
            cancellationToken);
    }

    /// <summary>
    /// Derives the opaque local outbox scope and exact route context from this
    /// verified grant and its holder, then installs the credential atomically.
    /// The application layer never authors either binding.
    /// </summary>
    public async Task<MailboxCredentialSelector> InstallForHolderAsync(
        IScopedMailboxCredentialRepository repository,
        MailboxCredentialScopeKind kind,
        IMailboxOperationSigner holder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(holder);
        var holderKey = holder.GetEd25519PublicKey();
        var account = DomainHash(AccountScopeDomain, holderKey);
        var routeContext = SHA256.HashData(ExactRouteClosure.Span);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    holderKey, HolderPublicKey.Span))
                throw new CryptographicException(
                    "The mailbox grant holder differs from the installing signer.");
            var selector = new MailboxCredentialSelector(
                OutboxAccountScope.FromBytes(account),
                kind,
                holderKey,
                routeContext);
            await InstallAsync(repository, selector, cancellationToken)
                .ConfigureAwait(false);
            return selector;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(holderKey);
            CryptographicOperations.ZeroMemory(account);
            CryptographicOperations.ZeroMemory(routeContext);
        }
    }

    private static byte[] DomainHash(
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    internal VerifiedOfficialMailboxAuthority RuntimeAuthority => runtimeAuthority;
}

/// <summary>
/// Clean-break mailbox grant client. It sends exact holder-authenticated XMG1
/// only through ContactResolve ONION routing and accepts one current MCG2 only
/// after issuer, route, topology-membership and current-node verification.
/// </summary>
public sealed class PrivacyRoutedMailboxGrantAcquisitionClient
{
    private const ulong RequestLifetimeSeconds = 120;
    private const ulong MaximumClockSkewSeconds = 60;
    private readonly IExactContactResolveOnionTransport transport;
    private readonly TimeProvider timeProvider;

    public PrivacyRoutedMailboxGrantAcquisitionClient(
        PrivacyRoutedContactResolverTransport transport,
        TimeProvider? timeProvider = null)
        : this(
            (IExactContactResolveOnionTransport)(transport ??
                throw new ArgumentNullException(nameof(transport))),
            timeProvider)
    {
    }

    internal PrivacyRoutedMailboxGrantAcquisitionClient(
        IExactContactResolveOnionTransport transport,
        TimeProvider? timeProvider = null)
    {
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ValueTask<VerifiedCurrentMailboxGrant> AcquireDepositAsync(
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        IReachabilityMailboxHolderSigner holder,
        CancellationToken cancellationToken = default) =>
        AcquireAsync(
            route,
            locatorHash,
            holder,
            static (verifiedRoute, locator, signer, issuedAt, expiresAt, token) =>
                MailboxGrantRequestAuthor.AuthorDepositAsync(
                    verifiedRoute, locator, signer, issuedAt, expiresAt, token),
            cancellationToken);

    public ValueTask<VerifiedCurrentMailboxGrant> AcquireRetrieveAsync(
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        ReadOnlyMemory<byte> ownerRetrieveCapability,
        IReachabilityMailboxHolderSigner holder,
        CancellationToken cancellationToken = default) =>
        AcquireAsync(
            route,
            locatorHash,
            holder,
            (verifiedRoute, locator, signer, issuedAt, expiresAt, token) =>
                MailboxGrantRequestAuthor.AuthorRetrieveAsync(
                    verifiedRoute,
                    locator,
                    ownerRetrieveCapability,
                    signer,
                    issuedAt,
                    expiresAt,
                    token),
            cancellationToken);

    private async ValueTask<VerifiedCurrentMailboxGrant> AcquireAsync(
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> locatorHash,
        IReachabilityMailboxHolderSigner holder,
        Func<VerifiedContactRouteClosure, ReadOnlyMemory<byte>,
            IReachabilityMailboxHolderSigner, ulong, ulong, CancellationToken,
            ValueTask<AuthoredMailboxGrantRequest>> author,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(holder);
        cancellationToken.ThrowIfCancellationRequested();
        var now = Now();
        var expiresAt = checked(now + RequestLifetimeSeconds);
        var authored = await author(
                route,
                locatorHash,
                holder,
                now,
                expiresAt,
                cancellationToken)
            .ConfigureAwait(false);
        var pathRequest = ContactResolveCanonicalPathRequest.Decode(
            authored.ExactXmg1.Span);
        var exact = await transport
            .SendExactAsync(
                pathRequest,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);
        var result = ContactCodec.Decode("XMC1", exact.ExactBody.Span);
        var authority = exact.PathAuthority?.MailboxAuthority
            ?? throw new CryptographicException(
                "Mailbox grant response has no verified current PMA2 authority.");
        if (authority.NotBeforeUnixSeconds > now ||
            now >= authority.ExpiresAtUnixSeconds)
            throw new CryptographicException(
                "The clean-break PMA2 mailbox authority is not current.");
        ContactCodec.ValidateMailboxGrantResultBinding(authored.Record, result);
        var code = (MailboxGrantAcquisitionResultCode)
            BinaryPrimitives.ReadUInt16BigEndian(result.Field(3).Span);
        if (!Enum.IsDefined(code))
            throw new CryptographicException("XMC1 returned an unknown result code.");
        if (code != MailboxGrantAcquisitionResultCode.Success)
            throw new MailboxGrantAcquisitionException(
                code,
                code is MailboxGrantAcquisitionResultCode.RateLimited or
                    MailboxGrantAcquisitionResultCode.Unavailable);

        var parsedRoute = ContactRouteClosureCodec.Decode(
            ContactRouteClosureCodec.Encode(route));
        ContactCodec.ValidateMailboxGrantResultRouteBinding(result, parsedRoute);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(result.Field(8).Span);
        VerifyCurrentGrant(
            authored,
            result,
            grant,
            parsedRoute,
            now,
            authority);

        var network = exact.PathAuthority?.Network
            ?? throw new CryptographicException(
                "Mailbox grant response has no verified current ContactResolve path authority.");
        var replicaIds = parsedRoute.Selection.Field(6).Span;
        var count = parsedRoute.Selection.Field(5).Span[0];
        if (count is < 2 or > 5 || replicaIds.Length != count * 32)
            throw new CryptographicException("The verified PMS2 replica selection is malformed.");
        var replicas = new VerifiedCurrentMailboxReplica[count];
        for (var index = 0; index < count; index++)
        {
            var nodeId = replicaIds.Slice(index * 32, 32);
            replicas[index] = new VerifiedCurrentMailboxReplica(
                nodeId,
                network.ResolveNodeIdentityPublicKey(nodeId.ToArray()).Span);
        }
        var runtimeAuthority = new VerifiedOfficialMailboxAuthority(
            authority.NetworkId,
            authority.MinimumGrantGeneration,
            [
                authority.ResolveIssuer(MailboxCapabilityDomain.Deposit),
                authority.ResolveIssuer(MailboxCapabilityDomain.Retrieve)
            ],
            requiresManagedEntitlement: false,
            static () => true,
            new Pma2FreshRevocationSource(
                authority.ExpiresAtUnixSeconds,
                timeProvider),
            timeProvider);
        return new VerifiedCurrentMailboxGrant(
            authored.Record,
            result,
            grant,
            parsedRoute,
            replicas,
            runtimeAuthority);
    }

    private void VerifyCurrentGrant(
        AuthoredMailboxGrantRequest request,
        ContactRecord result,
        MailboxAuthenticatedGrant grant,
        ParsedContactRouteClosure route,
        ulong now,
        VerifiedMailboxAuthorityV2 authority)
    {
        var serverTime = BinaryPrimitives.ReadUInt64BigEndian(result.Field(4).Span);
        var responseExpires = BinaryPrimitives.ReadUInt64BigEndian(result.Field(6).Span);
        var requestExpires = BinaryPrimitives.ReadUInt64BigEndian(
            request.Record.Field(10).Span);
        var issuer = authority.ResolveIssuer(grant.Domain);
        var canonical = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        try
        {
            if (serverTime > checked(now + MaximumClockSkewSeconds) ||
                responseExpires <= now ||
                responseExpires > requestExpires ||
                grant.Lifecycle != MailboxCapabilityLifecycle.Active ||
                grant.OverlapUntilUnixSeconds != 0 ||
                grant.Generation < authority.MinimumGrantGeneration ||
                grant.Generation < issuer.MinimumGeneration ||
                grant.Generation > issuer.MaximumGeneration ||
                grant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
                grant.ExpiresAtUnixSeconds > issuer.ValidUntilUnixSeconds ||
                grant.NotBeforeUnixSeconds > now ||
                grant.ExpiresAtUnixSeconds <= now ||
                grant.ExpiresAtUnixSeconds > responseExpires ||
                grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds >
                    authority.MaximumGrantLifetimeSeconds ||
                grant.Epoch != BinaryPrimitives.ReadUInt64BigEndian(
                    route.Selection.Field(4).Span) ||
                grant.MembershipCommitment.Length != 32 ||
                grant.MembershipCommitment.Span.IndexOfAnyExcept((byte)0) < 0 ||
                !Fixed(grant.NetworkId.Span, authority.NetworkId.Span) ||
                !Fixed(grant.HolderPublicKey.Span, request.HolderPublicKey.Span) ||
                !Fixed(
                    grant.PlacementCommitment.Span,
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(
                            route.Reachability.Field(10).Span))) ||
                !new SodiumMailboxCapabilityCrypto().VerifyIssuer(
                    issuer.PublicKey.Span,
                    MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant),
                    grant.IssuerSignature.Span))
                throw new CryptographicException(
                    "XMC1 current grant is stale, revoked, cross-scope, or not authenticated by the current mailbox authority.");
            if (!Fixed(canonical, result.Field(8).Span))
                throw new CryptographicException("XMC1 grant bytes are not canonical.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    private ulong Now()
    {
        var seconds = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        return seconds <= 0
            ? throw new InvalidOperationException("Mailbox grant acquisition requires positive trusted UTC.")
            : checked((ulong)seconds);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class Pma2FreshRevocationSource :
        IFreshMailboxCapabilityRevocationSource
    {
        private readonly ulong expiresAtUnixSeconds;
        private readonly TimeProvider timeProvider;

        internal Pma2FreshRevocationSource(
            ulong expiresAtUnixSeconds,
            TimeProvider timeProvider)
        {
            this.expiresAtUnixSeconds = expiresAtUnixSeconds;
            this.timeProvider = timeProvider;
            ValidateFreshness();
        }

        public void ValidateFreshness()
        {
            var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            if (now <= 0 || checked((ulong)now) >= expiresAtUnixSeconds)
                throw new InvalidOperationException(
                    "The clean PMA2 mailbox authority is no longer current.");
        }

        public bool IsRevoked(MailboxCapabilityRevocationQuery query)
        {
            ArgumentNullException.ThrowIfNull(query);
            ValidateFreshness();
            // PMA2 revokes by minimum-generation advance or authority
            // replacement; it defines no independent serial deny-list.
            return false;
        }
    }
}
