using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>
/// Sends one public DID2 XPP1 to both independently selected ONION exits.
/// Its eventual account-owned caller must supply the protected-tip-verified
/// exact aggregate and locally verified public DID2/DCA1/XPS1 support. A
/// successful return proves the exact two-replica XIC1 pair; it does not
/// itself activate a claim or persist that decision.
/// </summary>
internal sealed class DeepIdV2PreKeyPublicationTransport(
    IContactResolvePublicationPathAuthoritySource authoritySource,
    IExactContactResolveOnionTransport onion)
{
    internal async ValueTask<(ParsedXic1V2 First, ParsedXic1V2 Second)>
        PublishAsync(StagedDeepIdV2PreKeyPublication staged,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(staged);
        var exactAggregate = staged.ExactXpp1;
        var exactPublisherDid2 = staged.ExactDid2;
        var exactPublisherDca1 = staged.ExactDca1;
        var exactPublisherXps1 = staged.ExactXps1;
        ArgumentNullException.ThrowIfNull(authoritySource);
        ArgumentNullException.ThrowIfNull(onion);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(
            exactAggregate.Span);
        var serviceCapability = publication.Manifest.Field(2);
        var authority = await authoritySource.GetCurrentForPublicationAsync(
            publication.NetworkId, serviceCapability, cancellationToken)
            .ConfigureAwait(false) ?? throw new CryptographicException(
                "Current DID2 publication authority is unavailable.");
        authority.Network.EnsureCurrent();
        var placement = authority.Placement;
        if (!ReferenceEquals(authority.Network, placement.Network) ||
            placement.RequestKind !=
                ContactServiceRequestKind.PublishPreKeyInventory ||
            !placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory,
                serviceCapability) ||
            !Fixed(authority.Network.NetworkId.Span,
                publication.NetworkId.Span) ||
            !Fixed(placement.PlacementHash.Span,
                publication.PlacementHash.Span))
            throw new CryptographicException(
                "The protected DID2 publication differs from current placement.");
        var replicas = placement.RankedReplicaNodeIds;
        if (replicas.Count != 2 || Fixed(replicas[0].Span,
                replicas[1].Span))
            throw new CryptographicException(
                "DID2 publication requires two distinct selected replicas.");

        var sequence = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
            exactAggregate.Span, placement.ViewHash.Span,
            exactPublisherDid2.Span, exactPublisherDca1.Span,
            exactPublisherXps1.Span);
        var expiresAt = Math.Min(BinaryPrimitives.ReadUInt64BigEndian(
            publication.Manifest.Field(15).Span),
            placement.ValidUntilUnixSeconds);
        var receipts = new ParsedXic1V2[2];
        for (var replicaIndex = 0; replicaIndex < replicas.Count;
             replicaIndex++)
        {
            foreach (var exactFragment in sequence)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
                    exactFragment);
                var request = ContactResolveCanonicalPathRequest
                    .FromDid2BoundedPublication(fragment,
                        serviceCapability.Span, expiresAt);
                var response = await onion.SendExactAsync(request,
                    replicas[replicaIndex], cancellationToken)
                    .ConfigureAwait(false);
                EnsureSameCurrentPlacement(response.PathAuthority,
                    placement, serviceCapability.Span);
                if (fragment.Phase == Xpp1V2FragmentPhase.Commit)
                {
                    var receipt = DeepIdV2PreKeyCommitReceiptCodec.Decode(
                        response.ExactBody.Span);
                    if (!Fixed(receipt.Field(5).Span,
                            replicas[replicaIndex].Span) ||
                        !Fixed(receipt.Field(1).Span,
                            publication.NetworkId.Span) ||
                        !Fixed(receipt.Field(2).Span,
                            publication.PublicationOperationId.Span) ||
                        !Fixed(receipt.Field(4).Span,
                            publication.PlacementHash.Span))
                        throw new CryptographicException(
                            "The DID2 final receipt is not from the selected exit or publication.");
                    receipts[replicaIndex] = receipt;
                }
                else
                    EnsureStaged(response.ExactBody.Span);
            }
        }
        DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication,
            placement, receipts[0], receipts[1]);
        return (receipts[0], receipts[1]);
    }

    internal static void EnsureStaged(ReadOnlySpan<byte> response)
    {
        if (response.Length != 1 || response[0] is not (1 or 3))
            throw new CryptographicException(
                "The DID2 ONION exit did not durably stage the exact fragment.");
    }

    private static void EnsureSameCurrentPlacement(
        ContactResolvePathAuthority? responseAuthority,
        VerifiedContactServicePlacement expected,
        ReadOnlySpan<byte> serviceCapability)
    {
        if (responseAuthority is null)
            throw new CryptographicException(
                "The DID2 ONION response has no verified path authority.");
        responseAuthority.Network.EnsureCurrent();
        var actual = responseAuthority.Placement;
        if (!ReferenceEquals(responseAuthority.Network, actual.Network) ||
            !Fixed(actual.Network.NetworkId.Span,
                expected.Network.NetworkId.Span) ||
            !Fixed(actual.ViewHash.Span, expected.ViewHash.Span) ||
            !Fixed(actual.PlacementHash.Span,
                expected.PlacementHash.Span) ||
            !actual.Binds(ContactServiceRequestKind.PublishPreKeyInventory,
                serviceCapability.ToArray()))
            throw new CryptographicException(
                "The DID2 ONION response used a different publication placement.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
