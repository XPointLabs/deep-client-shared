using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services.ContactV2;

// Private coordination composition remains a shipping gate. TestServer sources
// exercise exact custody, not authorization for a direct Registry fallback.
internal interface IDid2ContactPublicationSource
{
    ValueTask<ReadOnlyMemory<byte>> FetchLeaseAsync(PublicationLeaseWireRequest request,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken);

    ValueTask<ReadOnlyMemory<byte>> FetchAsync(ContactPublicationAuthorityWireRequest exactPendingRequest,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken);
}
