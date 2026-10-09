using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task RetireSupersededRetrieveAcquisitionAsync(ReadOnlyMemory<byte> originalAcquisitionHash,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (originalAcquisitionHash.Length != 32 || originalAcquisitionHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact original acquisition hash is required.", nameof(originalAcquisitionHash));
        var selector = originalAcquisitionHash.ToArray();
        try
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            using var exclusion = await ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.OpenAsync(owner,
                TrustedUnixSeconds(), verifier, source, fresh, selector, ct).ConfigureAwait(false);
            await exclusion.RetireSupersededRetrieveAcquisitionAsync(verifier, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(selector); }
    }

    internal async Task RetireUsedDepositAcquisitionAsync(ReadOnlyMemory<byte> originalAcquisitionHash,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (originalAcquisitionHash.Length != 32 || originalAcquisitionHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact original acquisition hash is required.", nameof(originalAcquisitionHash));
        var selector = originalAcquisitionHash.ToArray();
        try
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            using var exclusion = await ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.OpenAsync(owner,
                TrustedUnixSeconds(), verifier, source, fresh, selector, ct).ConfigureAwait(false);
            await exclusion.RetireUsedDepositAcquisitionAsync(verifier, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(selector); }
    }

    // Cold local readback facts only: no source/callback, new fence, current
    // policy, signing or deletion capability can be obtained through this API.
    internal async Task<Did2CompactionPlan.RootReadback> ReadOwnMailboxReplayFenceAsync(CancellationToken ct = default)
    {
        using var verifier = OpenVerifier();
        return await owner.ReadNativeReplayFenceAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false);
    }

    // Selector only, not a trusted grant, clock, floor or cleanup permission.
    // The caller must dispose the returned account lease and recheck it before
    // consuming its prerequisite in a dependency-closed owner plan.
    internal async Task<ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion> OpenMailboxEpochExclusionAsync(
        ReadOnlyMemory<byte> originalAcquisitionHash, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (originalAcquisitionHash.Length != 32 || originalAcquisitionHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact original acquisition hash is required.", nameof(originalAcquisitionHash));
        var selector = originalAcquisitionHash.ToArray();
        try
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await ProtectedDeepIdV2AccountOwner.MailboxEpochExclusion.OpenAsync(owner, TrustedUnixSeconds(), verifier,
                source, fresh, selector, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(selector); }
    }

    internal async Task<VerifiedMailboxRetainedReadGrantV2> ResumeOwnPermanentContactRetrieveGrantResultAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.AcceptOwnPermanentContactRetrieveGrantResultAsync(TrustedUnixSeconds(), verifier,
            source, fresh, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
    }

    internal async Task<VerifiedDeepIdV2MailboxGrant> ResumePermanentContactDepositGrantResultAsync(
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.AcceptPermanentContactDepositGrantResultAsync(TrustedUnixSeconds(), verifier,
            source, fresh, ReadOnlyMemory<byte>.Empty, ct).ConfigureAwait(false);
    }

    // Incoming bytes are untrusted evidence, not an outcome/clock/route supplied
    // by the caller. Snapshot before any asynchronous current-authority read.
    internal async Task<VerifiedMailboxRetainedReadGrantV2> AcceptOwnPermanentContactRetrieveGrantResultAsync(
        DeepIdV2ContactPathAuthoritySource source, ReadOnlyMemory<byte> exactXmc2, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactXmc2.Length != 510) throw new InvalidDataException("Mailbox result must have its exact bound.");
        var packet = exactXmc2.ToArray();
        try
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.AcceptOwnPermanentContactRetrieveGrantResultAsync(TrustedUnixSeconds(), verifier,
                source, fresh, packet, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(packet); }
    }

    internal async Task<VerifiedDeepIdV2MailboxGrant> AcceptPermanentContactDepositGrantResultAsync(
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactPathAuthoritySource source,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        if (exactXmc2.Length != 510) throw new InvalidDataException("Mailbox result must have its exact bound.");
        var packet = exactXmc2.ToArray();
        try
        {
            var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.AcceptPermanentContactDepositGrantResultAsync(TrustedUnixSeconds(), verifier,
                source, fresh, packet, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(packet); }
    }

    // Closed internal maintenance contract. No caller clock, outcome, policy,
    // route, deletion permission or transport callback is accepted.
    internal async Task<int> CloseExpiredMailboxAcquisitionsAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.CloseExpiredMailboxAcquisitionsAsync(TrustedUnixSeconds(), verifier,
            source, fresh, ct).ConfigureAwait(false);
    }

    internal Task<VerifiedMailboxRetainedReadGrantV2> AcquireOwnPermanentContactRetrieveGrantAsync(
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default) =>
        AcquireOwnPermanentContactRetrieveGrantAsync(source, new Did2MailboxGrantOnionTransport(source), ct);

    internal async Task<VerifiedMailboxRetainedReadGrantV2> AcquireOwnPermanentContactRetrieveGrantAsync(
        DeepIdV2ContactPathAuthoritySource source, IDid2RetainedMailboxReadGrantTransport transport, CancellationToken ct = default)
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

    // Explicit same-original-path transition. Automatic scheduling belongs to
    // the later runtime stage; this selector cannot supply authority or custody.
    internal async Task<VerifiedMailboxRetainedReadGrantV2> RenewOwnPermanentContactRetrieveGrantAsync(
        ReadOnlyMemory<byte> originalAcquisition, DeepIdV2ContactPathAuthoritySource source,
        IDid2RetainedMailboxReadGrantTransport transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this);
        if (originalAcquisition.Length != 32 || originalAcquisition.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact original acquisition selector is required.", nameof(originalAcquisition));
        var selector = originalAcquisition.ToArray();
        try
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.RenewOwnPermanentContactRetrieveGrantAsync(TrustedUnixSeconds(), verifier,
                source, fresh, selector, transport, ct).ConfigureAwait(false);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(selector); }
    }

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
