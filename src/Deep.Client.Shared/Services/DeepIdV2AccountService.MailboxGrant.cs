using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal Task<VerifiedDeepIdV2MailboxGrant> AcquireOwnPermanentContactRetrieveGrantAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        AcquireOwnPermanentContactRetrieveGrantAsync(source, new Did2MailboxGrantOnionTransport(source), ct);

    internal async Task<VerifiedDeepIdV2MailboxGrant> AcquireOwnPermanentContactRetrieveGrantAsync(
        DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.AcquireOwnPermanentContactRetrieveGrantAsync(TrustedUnixSeconds(), verifier,
            source, fresh, transport, ct).ConfigureAwait(false);
    }

    internal Task<VerifiedDeepIdV2MailboxGrant> AcquirePermanentContactDepositGrantAsync(
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct = default) =>
        AcquirePermanentContactDepositGrantAsync(contact, source, new Did2MailboxGrantOnionTransport(source), ct);

    // Internal connected custody entry; no public callback/trust/key injection.
    // The protected winner is installed/read back under the actual owner lease;
    // no signer or SQL/runtime authority escapes. Shipping dispatch remains gated.
    internal async Task<VerifiedDeepIdV2MailboxGrant> AcquirePermanentContactDepositGrantAsync(
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        IDid2MailboxGrantTransport transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(transport); source.RequireAccountOwner(this);
        var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.AcquirePermanentContactDepositGrantAsync(TrustedUnixSeconds(), verifier,
            source, fresh, transport, ct).ConfigureAwait(false);
    }
}
