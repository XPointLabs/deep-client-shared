using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>One exact DID2 claim attempt through the selected ONION exit.
/// A result proves both replica signatures and inventory inclusion, not peer
/// freshness, contact acceptance, session persistence or message delivery.
/// The caller must durably retain its exact request before dispatch/retry.</summary>
internal sealed class DeepIdV2PreKeyClaimTransport(
    IContactResolvePathAuthoritySource authoritySource,
    IExactContactResolveOnionTransport onion)
{
    internal async ValueTask<VerifiedXpc1V2ReplicaSignatures> ClaimExactAsync(
        ReadOnlyMemory<byte> exactRequest, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoritySource);
        ArgumentNullException.ThrowIfNull(onion);
        cancellationToken.ThrowIfCancellationRequested();
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exactRequest.Span);
        var canonical = ContactResolveCanonicalPathRequest.Decode(request.CanonicalBytes.Span);
        var authority = await authoritySource.GetCurrentAsync(canonical, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        RequirePlacement(authority, request);
        var placement = authority.Placement;
        // The fixed coordinator completes both durable replica operations.
        // There is no second independent claim or generated retry operation.
        var response = await onion.SendExactAsync(canonical,
            placement.RankedReplicaNodeIds[0], cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        RequirePlacement(response.PathAuthority, request);
        authority.Network.EnsureCurrent();
        var result = DeepIdV2PreKeyClaimResultCodec.Decode(response.ExactBody.Span,
            request.CanonicalBytes.Span);
        if (result.Status is not (Xpc1V2Status.Claimed or Xpc1V2Status.Replay))
            throw new DeepIdV2PreKeyClaimUnavailableException(result.Status,
                BinaryPrimitives.ReadUInt32BigEndian(result.Field(7).Span));
        return DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, result, placement);
    }

    private static void RequirePlacement(ContactResolvePathAuthority? authority,
        ParsedXpk1V2 request)
    {
        if (authority is null)
            throw new CryptographicException("The DID2 claim has no verified path authority.");
        authority.Network.EnsureCurrent();
        var placement = authority.Placement;
        var replicas = placement.RankedReplicaNodeIds;
        if (!ReferenceEquals(authority.Network, placement.Network) ||
            placement.RequestKind != ContactServiceRequestKind.ClaimPreKey ||
            placement.ServiceClass != ContactServiceClass.PreKeyClaim ||
            !placement.Binds(ContactServiceRequestKind.ClaimPreKey, request.Field(16)) ||
            !Fixed(authority.Network.NetworkId.Span, request.Field(1).Span) ||
            !Fixed(placement.ViewHash.Span, request.Field(3).Span) ||
            !Fixed(placement.PlacementHash.Span, request.Field(4).Span) ||
            BinaryPrimitives.ReadUInt64BigEndian(request.Field(6).Span) >
                placement.ValidUntilUnixSeconds ||
            replicas.Count != 2 || Fixed(replicas[0].Span, replicas[1].Span))
            throw new CryptographicException("The exact DID2 claim differs from current placement.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>Authenticated terminal refusal. It never grants a session or ACK;
/// OutcomeUnknown requires reconciliation with the retained exact request.</summary>
internal sealed class DeepIdV2PreKeyClaimUnavailableException : Exception
{
    internal DeepIdV2PreKeyClaimUnavailableException(Xpc1V2Status status, uint retryAfter)
        : base($"DID2 pre-key claim is unavailable ({status}).")
    {
        Status = status;
        RetryAfterSeconds = retryAfter;
    }

    internal Xpc1V2Status Status { get; }
    internal uint RetryAfterSeconds { get; }
}
