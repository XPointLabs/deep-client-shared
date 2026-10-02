using System.Security.Cryptography;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// No client Registry URL, direct fallback, caller node list or reusable proof.
// Only the owning operation can provide a live, actual custody loan.
internal sealed class Did2ContactCoordinationOnionSource(DeepIdV2ContactPathAuthoritySource source) :
    IDid2ContactRouteThresholdSource, IDid2ContactPublicationSource
{
    public async ValueTask<ParsedDeepIdV2RouteThreshold> FetchAsync(
        ReadOnlyMemory<byte> durableNonce32, DeepIdV2CurrentContactAuthorization authorization,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactXra1, OnionTrustedTimeAuthority trustedTime,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken)
    {
        operation.RequireActive();
        if (!ReferenceEquals(network, operation.Network) || !ReferenceEquals(trustedTime, source.RendezvousTrustedTime) ||
            !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, network.NetworkId.Span))
            throw new CryptographicException("Coordination differs from the owned current network.");
        var floor = authorization.Freshness.NextProtectedLkg;
        var request = new ContactRouteAuthorityWireRequest(network.NetworkId.Span,
            durableNonce32.Span, authorization.Freshness.QueriedDirectoryLeafKey.Span,
            floor.LogGeneration, floor.CoreHash.Span,
            authorization.Authorization.Record.CanonicalBytes.Span, exactXra1.Span);
        var body = await SendAsync(ContactCoordinationTarget.Route,
            ContactRouteAuthorityWireCodec.EncodeRequest(request), operation, cancellationToken).ConfigureAwait(false);
        var parsed = ContactRouteAuthorityWireCodec.DecodeResponse(request, body.Span);
        return new(parsed.ExactPms2.Span, parsed.ExactXrc1.Span, parsed.ExactXss1.Span);
    }

    public ValueTask<ReadOnlyMemory<byte>> FetchAsync(
        ContactPublicationAuthorityWireRequest exactPendingRequest,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken) =>
        SendAsync(ContactCoordinationTarget.Publication,
            ContactPublicationAuthorityWireCodec.EncodeRequest(exactPendingRequest), operation, cancellationToken);

    private async ValueTask<ReadOnlyMemory<byte>> SendAsync(ContactCoordinationTarget target,
        ReadOnlyMemory<byte> exactBody, Did2OwnedContactTransportContext operation,
        CancellationToken cancellationToken)
    {
        operation.RequireActive();
        source.RequireAccountOwner(operation.Custody.Owner);
        var exact = ContactCoordinationOnionCodec.EncodeRequest(target, exactBody.Span);
        var parsed = ContactCoordinationOnionCodec.DecodeRequest(exact);
        var transport = new DeepIdV2PublicationOnionTransport(source, operation.Custody);
        var response = await transport.SendOwnedExactAsync(
            ContactResolveCanonicalPathRequest.Decode(exact), ReadOnlyMemory<byte>.Empty,
            operation, cancellationToken).ConfigureAwait(false);
        var body = ContactCoordinationOnionCodec.DecodeResponse(parsed, response.ExactBody.Span);
        operation.RequireActive();
        cancellationToken.ThrowIfCancellationRequested();
        // Parsing and authenticated transport are not threshold/witness authority.
        // The parent independently verifies and commits the exact response.
        return body;
    }
}
