using System.Security.Cryptography;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    // Prepares custody only: no network send, claim acceptance, session or ACK.
    // No caller chooses service/device hashes, operation, keys or trusted time.
    internal async Task<ParsedXpk1V2> PrepareOwnPermanentContactClaimAsync(
        ReadOnlyMemory<byte> logicalIntent, VerifiedDeepIdV2PermanentContactResolveClosure contact,
        DeepIdV2ContactPathAuthoritySource source, int maximumMessagesWithoutPqInjection,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        Persistence.DeviceV2.ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        var intent = logicalIntent.ToArray();
        try
        {
            var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            return await owner.PreparePermanentContactClaimAsync(TrustedUnixSeconds(), verifier,
                intent, source, fresh, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(intent); }
    }

    public async Task<VerifiedDeepIdV2PermanentContactResolveClosure> ResolvePermanentContactAsync(
        DeepPermanentIdV2 address, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(address); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        var custody = await OpenOwnOnionClientCustodyAsync(ct).ConfigureAwait(false);
        return await ResolvePermanentContactAsync(address, source,
            new DeepIdV2PublicationOnionTransport(source, custody), ct).ConfigureAwait(false);
    }

    // Read-only bootstrap: no contact acceptance, claim, durable trust flag,
    // message or automatic retry is produced by this operation.
    internal async Task<VerifiedDeepIdV2PermanentContactResolveClosure> ResolvePermanentContactAsync(
        DeepPermanentIdV2 address, DeepIdV2ContactPathAuthoritySource source,
        IExactContactResolveOnionTransport transport, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(address); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(transport); source.RequireAccountOwner(this);
        var own = await source.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var query = await owner.AuthorPermanentContactQueryAsync(TrustedUnixSeconds(), verifier, address,
            source, own, ct).ConfigureAwait(false);
        var canonical = ContactResolveCanonicalPathRequest.Decode(query.CanonicalBytes.Span);
        var placement = ContactServicePlacementFactory.Create(own.Network,
            ContactServiceRequestKind.ResolveInvite, query.LocatorHash);
        // Bounded single read through the selected coordinator. A caller may
        // explicitly retry a read; no second hidden dispatch follows failure.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        var response = await transport.SendExactAsync(canonical, placement.RankedReplicaNodeIds[0], budget.Token)
            .AsTask().WaitAsync(budget.Token).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var candidate = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(address,
            query.CanonicalBytes, response.ExactBody);
        var resolved = await source.VerifyPermanentContactAsync(candidate, ct).ConfigureAwait(false);
        using var releaseVerifier = OpenVerifier();
        return await owner.RecheckPermanentContactAsync(TrustedUnixSeconds(), releaseVerifier,
            source, resolved, ct).ConfigureAwait(false);
    }

    // Only the account-bound source uses this profile-bound peer lookup.
    // Candidate decryption is not peer authority; the independent proof
    // commits/rechecks this account's protected directory floor.
    internal async ValueTask<VerifiedDeepIdV2DirectoryFreshness> FetchContactPeerProofAsync(
        ParsedDeepIdV2PermanentContactCandidate candidate, DeepIdV2DirectoryProofClient proofs,
        VerifiedXPointNetworkAuthority authority, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(proofs);
        ArgumentNullException.ThrowIfNull(authority); ct.ThrowIfCancellationRequested();
        using var verifier = OpenVerifier();
        using var current = await owner.ReadCurrentAsync(TrustedUnixSeconds(), verifier, ct).ConfigureAwait(false) ??
            throw new InvalidOperationException("A protected DID2 account is required for contact resolution.");
        var local = current.Verified.PublicEvidence;
        if (!Fixed(local.Binding.Identity.Account.Certificate.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(candidate.Request.NetworkId.Span, authority.NetworkId.Span))
            throw new CryptographicException("Peer resolution requires this account's pinned network.");
        var fresh = await proofs.FetchByContactDescriptorAsync(candidate.Address, candidate.ExactDid2,
            authority, deploymentProfileId, supportedReader: 2, ct).ConfigureAwait(false);
        using var finalVerifier = OpenVerifier();
        using var final = await owner.ReadCurrentAsync(TrustedUnixSeconds(), finalVerifier, ct).ConfigureAwait(false) ??
            throw new CryptographicException("The protected DID2 account disappeared during contact resolution.");
        if (!Fixed(final.Verified.PublicEvidence.Binding.Record.CanonicalBytes.Span, local.Binding.Record.CanonicalBytes.Span) ||
            !Fixed(final.Verified.PublicEvidence.Directory.Record.CanonicalBytes.Span, local.Directory.Record.CanonicalBytes.Span))
            throw new CryptographicException("The protected DID2 account changed during contact resolution.");
        ct.ThrowIfCancellationRequested(); return fresh;
    }
}
