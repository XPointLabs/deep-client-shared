using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Reads exact historical local receiver custody before claim
    /// preview, including after its one-time prekey has been deleted. Not
    /// current network/contact authority or permission to ACK.</summary>
    public async Task<DeepIdV2InitialContactSessionCommit?> FindOwnInitialContactSessionAsync(
        ReadOnlyMemory<byte> exactDph2, CancellationToken cancellationToken = default)
    {
        if (exactDph2.IsEmpty || exactDph2.Length > DeepIdV2InitialContactSessionCommit.MaximumDphBytes)
            throw new ArgumentException("Initial receiver bytes exceed their closed bound.", nameof(exactDph2));
        var incoming = Dph2Codec.Decode(exactDph2.Span);
        using var verifier = OpenVerifier();
        return await owner.FindReceiverSessionAsync(TrustedUnixSeconds(), verifier, incoming, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Atomically retains authenticated initial ContactHello, ratchet
    /// and prekey consumption under the account lease. No session preparation
    /// or private state escapes before stable local custody. Not acceptance/ACK.</summary>
    public async Task<DeepIdV2InitialContactSessionCommit> CommitOwnInitialContactSessionAsync(VerifiedDph2InitialClaim claim,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness, DeepIdV2ContactPathAuthoritySource authoritySource,
        int maximumMessagesWithoutPqInjection, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claim); ArgumentNullException.ThrowIfNull(initiatorFreshness);
        ArgumentNullException.ThrowIfNull(authoritySource);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048) throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        authoritySource.RequireAccountOwner(this);
        var fresh = await authoritySource.VerifyForOwnPreKeyAuthoringAsync(this, cancellationToken).ConfigureAwait(false);
        await authoritySource.RecheckInitialClaimInitiatorAsync(initiatorFreshness, fresh, cancellationToken).ConfigureAwait(false);
        var reading = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh, cancellationToken).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var completed = await owner.CommitReceiverSessionAsync(TrustedUnixSeconds(), verifier, claim, fresh, initiatorFreshness,
            reading, authoritySource.RendezvousTrustedTime, maximumMessagesWithoutPqInjection, cancellationToken).ConfigureAwait(false);
        try
        {
            await authoritySource.RecheckInitialClaimInitiatorAsync(initiatorFreshness, fresh, cancellationToken).ConfigureAwait(false);
            var final = await authoritySource.RecheckOwnPreKeyAuthoringAsync(fresh, cancellationToken).ConfigureAwait(false);
            if (final.SampleSeconds < reading.SampleSeconds || !final.BootId.Span.SequenceEqual(reading.BootId.Span) ||
                !initiatorFreshness.IsCurrentAtMonotonic(final.BootId.Span, final.SampleSeconds))
                throw new CryptographicException("Receiver completion proofs crossed a protected clock discontinuity or expiry.");
            cancellationToken.ThrowIfCancellationRequested();
            return completed;
        }
        catch { completed.Dispose(); throw; }
    }
}
