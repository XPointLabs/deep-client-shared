using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services.ContactV2;

// The implementation must use the selected ContactResolve onion terminal.
// This internal seam is not public authority or a direct Registry fallback.
internal interface IDid2MailboxGrantTransport
{
    ValueTask<ReadOnlyMemory<byte>> AcquireAsync(AuthoredMailboxGrantRequest request,
        VerifiedDeepIdV2ContactRouteClosure route, Did2OwnedContactTransportContext dispatch,
        CancellationToken cancellationToken);
}
