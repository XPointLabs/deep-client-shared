using System.Security.Cryptography;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// One selected exit coordinates the existing two-store commit. Success here
// is only authenticated bytes; the owned parent independently requires both
// selected replica signatures and durable journal read-back before adoption.
internal sealed class Did2ContactReplicaPublicationOnionTransport(DeepIdV2ContactPathAuthoritySource source)
    : IDid2ContactReplicaPublicationTransport
{
    public async Task<ReadOnlyMemory<byte>> PublishAsync(ReadOnlyMemory<byte> exactXpu1,
        Did2OwnedContactTransportContext operation, CancellationToken ct)
    {
        operation.RequireActive(); source.RequireAccountOwner(operation.Custody.Owner);
        var request = ContactResolveCanonicalPathRequest.Decode(exactXpu1.Span);
        if (request.RequestKind != ContactServiceRequestKind.PublishInvite)
            throw new CryptographicException("Owned contact publication requires exact XPU1 V2.");
        var response = await new DeepIdV2PublicationOnionTransport(source, operation.Custody)
            .SendOwnedExactAsync(request, ReadOnlyMemory<byte>.Empty, operation, ct).ConfigureAwait(false);
        _ = Xpo1Codec.Decode(response.ExactBody.Span, request.ExactRequest.Span);
        operation.RequireActive(); ct.ThrowIfCancellationRequested();
        return response.ExactBody;
    }
}
