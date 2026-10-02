using System.Security.Cryptography;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// No fixed gateway, public issuer endpoint or fallback. The owner has already
// persisted/read back the exact pending operation and loans its actual lease.
internal sealed class Did2MailboxGrantOnionTransport(DeepIdV2ContactPathAuthoritySource source)
    : IDid2MailboxGrantTransport
{
    public async ValueTask<ReadOnlyMemory<byte>> AcquireAsync(AuthoredMailboxGrantRequest request,
        VerifiedDeepIdV2ContactRouteClosure route, Did2OwnedContactTransportContext dispatch, CancellationToken ct)
    {
        dispatch.RequireActive(); source.RequireAccountOwner(dispatch.Custody.Owner);
        if (!ReferenceEquals(route.Network, dispatch.Network))
            throw new CryptographicException("Mailbox acquisition differs from the actual owned network.");
        var exact = ContactResolveCanonicalPathRequest.Decode(request.ExactXmg1.Span);
        if (exact.RequestKind != ContactServiceRequestKind.AcquireMailboxGrant)
            throw new CryptographicException("Mailbox acquisition requires exact XMG1 placement.");
        await route.EnsureCurrentAsync(ct).ConfigureAwait(false);
        var response = await new DeepIdV2PublicationOnionTransport(source, dispatch.Custody)
            .SendOwnedExactAsync(exact, ReadOnlyMemory<byte>.Empty, dispatch, ct).ConfigureAwait(false);
        if (response.ExactBody.Length != 478)
            throw new CryptographicException("Mailbox acquisition did not return an exact success envelope.");
        var result = ContactCodec.Decode("XMC1", response.ExactBody.Span);
        ContactCodec.ValidateMailboxGrantResultBinding(request.Record, result);
        // Authentication of an ONION reply is not PMA2/root/issuer authority.
        // The owning parent independently verifies and persists the winner.
        dispatch.RequireActive(); ct.ThrowIfCancellationRequested(); return response.ExactBody;
    }
}
