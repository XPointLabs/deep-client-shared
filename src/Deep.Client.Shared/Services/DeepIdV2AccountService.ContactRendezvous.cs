using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Authors or restores exact inbound rendezvous custody for one
    /// stable logical intent. Independent metadata secrets remain protected in
    /// the account owner. This is neither a route, accepted contact nor ACK.</summary>
    public async Task<VerifiedDeepIdV2ContactUpdateRendezvous> EnsureOwnContactRendezvousAsync(
        ReadOnlyMemory<byte> logicalIntentId, DeepIdV2ContactPathAuthoritySource authoritySource,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authoritySource);
        Persistence.DeviceV2.ProtectedDph2PreClaimJournal.RequireIntent(logicalIntentId.Span);
        var intent = logicalIntentId.ToArray();
        authoritySource.RequireAccountOwner(this);
        var fresh = await authoritySource.VerifyForOwnPreKeyAuthoringAsync(this,
            cancellationToken).ConfigureAwait(false);
        var reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh,
            cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var result = await owner.EnsureContactRendezvousAsync(TrustedUnixSeconds(), verifier,
            intent, fresh, reading, authoritySource.RendezvousTrustedTime, cancellationToken).ConfigureAwait(false);
        await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        // Recheck issuer/time after durable commit and the independent floor
        // check. A failed return still leaves exact recoverable custody.
        return await DeepIdV2ContactUpdateRendezvousVerifier.VerifyAsync(result.ExactXur1,
            fresh.Proof, authoritySource.RendezvousTrustedTime, cancellationToken).ConfigureAwait(false);
    }
}
