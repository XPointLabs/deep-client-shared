using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Opens only unverified XPK1/XPC1 prefix evidence from the exact
    /// protected local inventory. Does not reserve a key, open application
    /// plaintext, commit a session, materialize a contact or authorize ACK.</summary>
    public async Task<Dph2InitialClaimPreview> PreviewOwnDph2InitialClaimAsync(ReadOnlyMemory<byte> exactDph2,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness, DeepIdV2ContactPathAuthoritySource authoritySource,
        int maximumMessagesWithoutPqInjection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(initiatorFreshness); ArgumentNullException.ThrowIfNull(authoritySource);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        if (exactDph2.IsEmpty || exactDph2.Length > Persistence.DeviceV2.DeepIdV2InitialSessionCommit.MaximumDphBytes)
            throw new ArgumentException("The initial claim exceeds its closed local byte bound.", nameof(exactDph2));
        // Decoder owns every input before awaiting network or custody work.
        var dph2 = Dph2Codec.Decode(exactDph2.Span);
        authoritySource.RequireAccountOwner(this);
        var fresh = await authoritySource.VerifyForOwnPreKeyAuthoringAsync(this, cancellationToken).ConfigureAwait(false);
        await authoritySource.RecheckInitialClaimInitiatorAsync(initiatorFreshness, fresh, cancellationToken).ConfigureAwait(false);
        var reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh, cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var preview = await owner.PreviewInitialClaimAsync(TrustedUnixSeconds(), verifier, dph2, fresh,
            initiatorFreshness, reading, authoritySource.RendezvousTrustedTime, maximumMessagesWithoutPqInjection, cancellationToken).ConfigureAwait(false);
        await authoritySource.RecheckInitialClaimInitiatorAsync(initiatorFreshness, fresh, cancellationToken).ConfigureAwait(false);
        var final = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh, cancellationToken).ConfigureAwait(false);
        if (final.SampleSeconds < reading.SampleSeconds || !final.BootId.Span.SequenceEqual(reading.BootId.Span) ||
            !initiatorFreshness.IsCurrentAtMonotonic(final.BootId.Span, final.SampleSeconds))
            throw new System.Security.Cryptography.CryptographicException("Initial preview proofs crossed a protected clock discontinuity or expiry.");
        cancellationToken.ThrowIfCancellationRequested();
        return preview;
    }
}
