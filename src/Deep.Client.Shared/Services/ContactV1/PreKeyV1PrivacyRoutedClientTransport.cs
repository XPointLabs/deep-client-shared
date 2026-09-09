using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// Stable machine-readable reasons reported by the deliberately uncomposed
/// fallback adapter. Current Protocol exposes no missing route capability.
/// </summary>
internal static class PreKeyV1PrivacyRouteCapabilityBlockers
{
    internal static IReadOnlyList<string> Publication { get; } = Array.Empty<string>();

    internal static IReadOnlyList<string> Claim { get; } = Array.Empty<string>();
}

internal enum PreKeyV1PrivacyRouteOperation
{
    PublishInventory = 1,
    ClaimPreKey = 2,
}

internal sealed class PreKeyV1PrivacyRouteCapabilityUnavailableException : InvalidOperationException
{
    internal PreKeyV1PrivacyRouteCapabilityUnavailableException(
        PreKeyV1PrivacyRouteOperation operation)
        : base(BuildMessage(operation))
    {
        Operation = operation;
        Blockers = operation switch
        {
            PreKeyV1PrivacyRouteOperation.PublishInventory =>
                PreKeyV1PrivacyRouteCapabilityBlockers.Publication,
            PreKeyV1PrivacyRouteOperation.ClaimPreKey =>
                PreKeyV1PrivacyRouteCapabilityBlockers.Claim,
            _ => throw new ArgumentOutOfRangeException(nameof(operation)),
        };
    }

    internal PreKeyV1PrivacyRouteOperation Operation { get; }
    internal IReadOnlyList<string> Blockers { get; }

    private static string BuildMessage(PreKeyV1PrivacyRouteOperation operation) => operation switch
    {
        PreKeyV1PrivacyRouteOperation.PublishInventory =>
            "Production bounded XPP1 publication composition was not supplied.",
        PreKeyV1PrivacyRouteOperation.ClaimPreKey =>
            "Production XPK1/XPC1 claim composition was not supplied.",
        _ => throw new ArgumentOutOfRangeException(nameof(operation)),
    };
}

/// <summary>
/// A publication operation that was already atomically staged with its DPK2
/// private inventory. The exact XPP1 bytes and durable operation ID are kept
/// behind the assembly boundary and are available only to the future Protocol-
/// minted privacy-route implementation.
/// </summary>
internal sealed class PreKeyV1DurablePublicationOperation
{
    private readonly PreKeyV1PublicationRequest publication;

    internal PreKeyV1DurablePublicationOperation(PreKeyV1PublicationRequest publication)
    {
        this.publication = publication ?? throw new ArgumentNullException(nameof(publication));

        var decoded = Xpp1Codec.Decode(publication.ExactXpp1Span);
        if (!Fixed(decoded.PublicationOperationId.Span, publication.OperationIdSpan) ||
            !Fixed(decoded.Manifest.CanonicalBytes.Span, publication.ExactXpi1Span) ||
            !Fixed(decoded.Manifest.Xpi1Hash.Span, publication.Xpi1HashSpan))
        {
            throw new CryptographicException(
                "The durable publication operation does not bind one exact XPS1/XPI1/XPP1 lineage.");
        }
    }

    internal ReadOnlySpan<byte> OperationIdSpan => publication.OperationIdSpan;
    internal ReadOnlySpan<byte> ExactXpp1Span => publication.ExactXpp1Span;
    internal PreKeyV1PublicationRequest Publication => publication;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// A canonical XPK1 operation leased from the durable claim journal.
/// </summary>
internal sealed class PreKeyV1DurableClaimOperation
{
    private readonly byte[] exactXpk1;
    private readonly byte[] operationId;

    internal PreKeyV1DurableClaimOperation(
        ReadOnlySpan<byte> exactXpk1,
        ReadOnlySpan<byte> durableOperationId,
        ulong journalRevision)
    {
        if (journalRevision == 0)
            throw new ArgumentOutOfRangeException(nameof(journalRevision));

        var decoded = Xpk1Codec.Decode(exactXpk1);
        if (durableOperationId.Length != 32 ||
            durableOperationId.IndexOfAnyExcept((byte)0) < 0 ||
            !Fixed(decoded.OperationId.Span, durableOperationId) ||
            !Fixed(decoded.ClaimOperationId.Span, durableOperationId) ||
            !Fixed(decoded.CanonicalBytes.Span, exactXpk1))
        {
            throw new CryptographicException(
                "The durable claim operation does not bind one exact canonical XPK1 operation ID.");
        }

        this.exactXpk1 = exactXpk1.ToArray();
        operationId = durableOperationId.ToArray();
        JournalRevision = journalRevision;
    }

    internal ulong JournalRevision { get; }
    internal ReadOnlySpan<byte> OperationIdSpan => operationId;
    internal ReadOnlySpan<byte> ExactXpk1Span => exactXpk1;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Narrow client boundary for the production pre-key privacy transport.
/// It accepts only durable exact operations and returns only capabilities minted
/// by Protocol verification; raw XIC1/XPC1 or DCB1 bytes never cross this API.
/// </summary>
internal interface IPreKeyV1PrivacyRoutedClientTransport
{
    ValueTask<VerifiedPreKeyInventoryPublication> PublishInventoryAsync(
        PreKeyV1DurablePublicationOperation operation,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedXpc1PreKeyClaimReceipt> ClaimPreKeyAsync(
        PreKeyV1DurableClaimOperation operation,
        CancellationToken cancellationToken = default);
}

internal interface IPreKeyV1ClaimReceiptVerifier
{
    ValueTask<VerifiedXpc1PreKeyClaimReceipt> VerifyAsync(
        PreKeyV1DurableClaimOperation operation,
        Xpc1Result result,
        ContactResolvePathAuthority pathAuthority,
        CancellationToken cancellationToken);
}

internal interface IPreKeyV1PublicationVerifier
{
    ValueTask<VerifiedPreKeyInventoryPublication> VerifyAsync(
        BoundedPreKeyInventoryPublication publication,
        IReadOnlyList<Xic1BoundedReceipt> commitReceipts,
        ContactResolvePathAuthority pathAuthority,
        CancellationToken cancellationToken);
}

internal sealed class ProtocolPreKeyV1PublicationVerifier :
    IPreKeyV1PublicationVerifier
{
    private readonly VerifiedContactNetworkAuthority recipientAuthority;
    private readonly VerifiedContactBundleClosure recipientBundle;
    private readonly OnionTrustedTimeAuthority trustedTimeAuthority;
    private readonly VerifiedPreKeyInventoryPublication? predecessor;

    internal ProtocolPreKeyV1PublicationVerifier(
        VerifiedContactNetworkAuthority recipientAuthority,
        VerifiedContactBundleClosure recipientBundle,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        VerifiedPreKeyInventoryPublication? predecessor)
    {
        this.recipientAuthority = recipientAuthority
            ?? throw new ArgumentNullException(nameof(recipientAuthority));
        this.recipientBundle = recipientBundle
            ?? throw new ArgumentNullException(nameof(recipientBundle));
        this.trustedTimeAuthority = trustedTimeAuthority
            ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
        this.predecessor = predecessor;
    }

    public ValueTask<VerifiedPreKeyInventoryPublication> VerifyAsync(
        BoundedPreKeyInventoryPublication publication,
        IReadOnlyList<Xic1BoundedReceipt> commitReceipts,
        ContactResolvePathAuthority pathAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(commitReceipts);
        ArgumentNullException.ThrowIfNull(pathAuthority);
        return PreKeyInventoryPublicationVerifier.VerifyBoundedAsync(
            publication,
            commitReceipts,
            pathAuthority.Placement,
            recipientAuthority,
            recipientBundle,
            trustedTimeAuthority,
            predecessor,
            cancellationToken);
    }
}

internal sealed class ContactResolverPreKeyV1ClaimReceiptVerifier :
    IPreKeyV1ClaimReceiptVerifier
{
    private readonly ContactResolverReverifiedPeerAuthority peer;
    private readonly OnionTrustedTimeAuthority trustedTimeAuthority;

    internal ContactResolverPreKeyV1ClaimReceiptVerifier(
        ContactResolverReverifiedPeerAuthority peer,
        OnionTrustedTimeAuthority trustedTimeAuthority)
    {
        this.peer = peer ?? throw new ArgumentNullException(nameof(peer));
        this.trustedTimeAuthority = trustedTimeAuthority
            ?? throw new ArgumentNullException(nameof(trustedTimeAuthority));
    }

    public ValueTask<VerifiedXpc1PreKeyClaimReceipt> VerifyAsync(
        PreKeyV1DurableClaimOperation operation,
        Xpc1Result result,
        ContactResolvePathAuthority pathAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(pathAuthority);
        var request = Xpk1Codec.Decode(operation.ExactXpk1Span);
        if (!ReferenceEquals(pathAuthority.Network, pathAuthority.Placement.Network) ||
            !pathAuthority.Placement.Binds(
                Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.ClaimPreKey,
                request.ServiceCapability))
            throw new CryptographicException(
                "The exact XPK1 dispatch did not use its current ClaimPreKey placement.");
        return Xpc1PreKeyClaimReceiptVerifier.VerifyAsync(
            request,
            result,
            pathAuthority.Placement,
            peer.Route.Authority,
            peer.Bundle,
            trustedTimeAuthority,
            cancellationToken);
    }
}

internal sealed class PreKeyV1ClaimRejectedException : CryptographicException
{
    internal PreKeyV1ClaimRejectedException(Xpc1Status status)
        : base($"The verified ContactResolve exit returned XPC1 status {status}.") =>
        Status = status;

    internal Xpc1Status Status { get; }
}

internal sealed class PreKeyV1PublicationReplicaRejectedException : CryptographicException
{
    internal PreKeyV1PublicationReplicaRejectedException(
        Xpp1BoundedPhase phase,
        Xic1BoundedStatus status,
        ReadOnlySpan<byte> replicaId)
        : base($"Replica {Convert.ToHexString(replicaId)} rejected bounded XPP1 phase {phase} with XIC1 status {status}.")
    {
        Phase = phase;
        Status = status;
    }

    internal Xpp1BoundedPhase Phase { get; }
    internal Xic1BoundedStatus Status { get; }
}

/// <summary>
/// Production XPK1 adapter. It dispatches only a revision-bound durable request,
/// verifies successful XPC1 before persistence, and commits every exact result
/// through the Protocol-owned immutable journal transition.
/// </summary>
internal sealed class PrivacyRoutedPreKeyV1ClientTransport :
    IPreKeyV1PrivacyRoutedClientTransport
{
    private readonly SqliteXpk1ClaimJournal journal;
    private readonly IExactContactResolveOnionTransport onion;
    private readonly IPreKeyV1ClaimReceiptVerifier receiptVerifier;
    private readonly IContactResolvePublicationPathAuthoritySource publicationAuthoritySource;
    private readonly IPreKeyV1PublicationVerifier publicationVerifier;

    internal PrivacyRoutedPreKeyV1ClientTransport(
        SqliteXpk1ClaimJournal journal,
        IExactContactResolveOnionTransport onion,
        IPreKeyV1ClaimReceiptVerifier receiptVerifier,
        IContactResolvePublicationPathAuthoritySource publicationAuthoritySource,
        IPreKeyV1PublicationVerifier publicationVerifier)
    {
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        this.onion = onion ?? throw new ArgumentNullException(nameof(onion));
        this.receiptVerifier = receiptVerifier
            ?? throw new ArgumentNullException(nameof(receiptVerifier));
        this.publicationAuthoritySource = publicationAuthoritySource
            ?? throw new ArgumentNullException(nameof(publicationAuthoritySource));
        this.publicationVerifier = publicationVerifier
            ?? throw new ArgumentNullException(nameof(publicationVerifier));
    }

    public async ValueTask<VerifiedPreKeyInventoryPublication> PublishInventoryAsync(
        PreKeyV1DurablePublicationOperation operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        var logical = Xpp1Codec.Decode(operation.ExactXpp1Span);
        var serviceCapability = logical.Manifest.ServiceCapability;
        var authority = await publicationAuthoritySource.GetCurrentForPublicationAsync(
                logical.NetworkId,
                serviceCapability,
                cancellationToken)
            .ConfigureAwait(false);
        ValidatePublicationAuthority(logical, authority);
        var bounded = BoundedPreKeyInventoryPublication.Create(
            logical,
            authority.Placement.ViewHash.Span,
            logical.Manifest.IssuedAtUnixSeconds,
            logical.Manifest.ExpiresAtUnixSeconds);
        var replicas = authority.Placement.RankedReplicaNodeIds.ToArray();
        if (replicas.Length != 2)
            throw new CryptographicException(
                "Bounded XPP1 requires exactly two independently addressed placement replicas.");

        var commitReceipts = new Xic1BoundedReceipt[2];
        for (var replicaIndex = 0; replicaIndex < replicas.Length; replicaIndex++)
        {
            var replicaId = replicas[replicaIndex];
            foreach (var request in bounded.OrderedRequests)
            {
                var pathRequest = ContactResolveCanonicalPathRequest.FromBoundedPublication(
                    request,
                    serviceCapability.Span);
                var response = await onion.SendExactAsync(
                        pathRequest,
                        replicaId,
                        cancellationToken)
                    .ConfigureAwait(false);
                var receipt = Xic1BoundedCodec.Decode(response.ExactBody.Span);
                EnsureAccepted(request, receipt, replicaId);
                if (request.Phase == Xpp1BoundedPhase.Commit)
                    commitReceipts[replicaIndex] = receipt;
            }
        }

        return await publicationVerifier.VerifyAsync(
                bounded,
                commitReceipts,
                authority,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<VerifiedXpc1PreKeyClaimReceipt> ClaimPreKeyAsync(
        PreKeyV1DurableClaimOperation operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        var pathRequest = ContactResolveCanonicalPathRequest.Decode(
            operation.ExactXpk1Span);
        var response = await onion.SendExactAsync(
                pathRequest,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);
        var authority = response.PathAuthority ?? throw new CryptographicException(
            "The XPK1 ONION dispatch returned no verified NETCODEC path authority.");
        var result = Xpc1Codec.Decode(response.ExactBody.Span, operation.ExactXpk1Span);
        if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay))
        {
            _ = await journal.RecordFailureAsync(
                    operation,
                    response.ExactBody,
                    cancellationToken)
                .ConfigureAwait(false);
            throw new PreKeyV1ClaimRejectedException(result.Status);
        }

        var verified = await receiptVerifier.VerifyAsync(
                operation,
                result,
                authority,
                cancellationToken)
            .ConfigureAwait(false);
        _ = await journal.RecordVerifiedClaimAsync(
                operation,
                response.ExactBody,
                verified,
                cancellationToken)
            .ConfigureAwait(false);
        return verified;
    }

    private static void ValidatePublicationAuthority(
        Xpp1Record logical,
        ContactResolvePathAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var placement = authority.Placement;
        if (!ReferenceEquals(authority.Network, placement.Network) ||
            !CryptographicOperations.FixedTimeEquals(
                logical.NetworkId.Span,
                authority.Network.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                logical.PlacementHash.Span,
                placement.PlacementHash.Span) ||
            !placement.Binds(
                Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishPreKeyInventory,
                logical.Manifest.ServiceCapability))
        {
            throw new CryptographicException(
                "The durable XPP1 does not bind its exact current PublishPreKeyInventory placement.");
        }
    }

    private static void EnsureAccepted(
        Xpp1BoundedRequest request,
        Xic1BoundedReceipt receipt,
        ReadOnlyMemory<byte> expectedReplicaId)
    {
        var accepted = request.Phase switch
        {
            Xpp1BoundedPhase.Manifest =>
                receipt.Status is Xic1BoundedStatus.ManifestStaged or Xic1BoundedStatus.ExactReplay &&
                receipt.MutationOutcome == Xic1BoundedMutationOutcome.DurablyStaged,
            Xpp1BoundedPhase.Chunk =>
                receipt.Status is Xic1BoundedStatus.ChunkStaged or Xic1BoundedStatus.ExactReplay &&
                receipt.MutationOutcome == Xic1BoundedMutationOutcome.DurablyStaged,
            Xpp1BoundedPhase.Commit =>
                receipt.Status is Xic1BoundedStatus.Committed or Xic1BoundedStatus.ExactReplay &&
                receipt.MutationOutcome == Xic1BoundedMutationOutcome.DurablyActivated,
            _ => false,
        };
        if (!accepted || !CryptographicOperations.FixedTimeEquals(
                receipt.ReplicaId.Span,
                expectedReplicaId.Span))
        {
            throw new PreKeyV1PublicationReplicaRejectedException(
                request.Phase,
                receipt.Status,
                expectedReplicaId.Span);
        }
    }
}

/// <summary>
/// Explicit fail-closed composition retained only for callers that have not
/// supplied the production path, journal and receipt-verification authorities.
/// </summary>
internal sealed class UnavailablePreKeyV1PrivacyRoutedClientTransport :
    IPreKeyV1PrivacyRoutedClientTransport
{
    internal static UnavailablePreKeyV1PrivacyRoutedClientTransport Instance { get; } = new();

    private UnavailablePreKeyV1PrivacyRoutedClientTransport()
    {
    }

    public ValueTask<VerifiedPreKeyInventoryPublication> PublishInventoryAsync(
        PreKeyV1DurablePublicationOperation operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        throw new PreKeyV1PrivacyRouteCapabilityUnavailableException(
            PreKeyV1PrivacyRouteOperation.PublishInventory);
    }

    public ValueTask<VerifiedXpc1PreKeyClaimReceipt> ClaimPreKeyAsync(
        PreKeyV1DurableClaimOperation operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        throw new PreKeyV1PrivacyRouteCapabilityUnavailableException(
            PreKeyV1PrivacyRouteOperation.ClaimPreKey);
    }
}
