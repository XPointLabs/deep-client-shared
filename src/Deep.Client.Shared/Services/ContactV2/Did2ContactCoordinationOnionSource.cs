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
    public async ValueTask<ContactRouteAuthorityWireResponse> FetchAsync(
        ContactRouteAuthorityWireRequest exactPendingRequest, DeepIdV2CurrentContactAuthorization authorization,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OnionTrustedTimeAuthority trustedTime,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken)
    {
        operation.RequireActive();
        ArgumentNullException.ThrowIfNull(exactPendingRequest);
        if (!ReferenceEquals(network, operation.Network) || !ReferenceEquals(trustedTime, source.RendezvousTrustedTime) ||
            !CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, network.NetworkId.Span))
            throw new CryptographicException("Coordination differs from the owned current network.");
        Did2ContactRouteRequestCustody.RequireCurrent(exactPendingRequest, authorization, network);
        // A saved replay minimum is not current authority. Never rewrite the
        // exact nonce-bound request with the fresh proof's newer directory floor.
        var body = await SendAsync(ContactCoordinationTarget.Route,
            ContactRouteAuthorityWireCodec.EncodeRequest(exactPendingRequest), operation, cancellationToken).ConfigureAwait(false);
        return ContactRouteAuthorityWireCodec.DecodeResponse(exactPendingRequest, body.Span);
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
