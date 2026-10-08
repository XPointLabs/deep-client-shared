using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV2;

// Bounded untrusted result courier only. Original publication/holder custody
// and the current issuer verification remain inside the held account owner.
internal interface IDid2RetainedMailboxReadGrantTransport
{
    ValueTask<ReadOnlyMemory<byte>> AcquireRetainedReadAsync(AuthoredMailboxGrantRequest request,
        Did2OwnedContactTransportContext dispatch, CancellationToken cancellationToken);
}
