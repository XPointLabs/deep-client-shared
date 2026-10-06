using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

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
/// A single current-epoch MCG3 returned by exact XMG1/XMC2. This is deliberately
/// not the legacy current/next JSON bundle and carries no Session-derived ID.
/// </summary>
public sealed class VerifiedCurrentMailboxGrant
{
    private static ReadOnlySpan<byte> AccountScopeDomain =>
        "deep.mailbox.account-scope.v1"u8;
    private readonly byte[] exactXmg1;
    private readonly byte[] exactXmc2;
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
        exactXmc2 = result.CanonicalBytes.ToArray();
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
            this.replicas.Length != 2)
            throw new CryptographicException(
                "The verified current mailbox grant route is malformed.");
        ContactCodec.ValidateMailboxGrantResultBinding(request, result);
        ContactCodec.ValidateMailboxGrantResultRouteBinding(result, route);
        if (!CryptographicOperations.FixedTimeEquals(result.Field(8).Span, exactGrant))
            throw new CryptographicException("The installed grant differs from its exact verified result.");
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
    public ReadOnlyMemory<byte> ExactXmc2 => exactXmc2.ToArray();
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
    /// Atomically installs this exact verified XMC2 result into the clean
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
        var account = AccountScopeForHolder(holderKey).Value.ToArray();
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

    internal static OutboxAccountScope AccountScopeForHolder(ReadOnlySpan<byte> holderKey)
    {
        if (holderKey.Length != 32 || holderKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact nonzero holder key is required.", nameof(holderKey));
        var bytes = DomainHash(AccountScopeDomain, holderKey);
        try { return OutboxAccountScope.FromBytes(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
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
