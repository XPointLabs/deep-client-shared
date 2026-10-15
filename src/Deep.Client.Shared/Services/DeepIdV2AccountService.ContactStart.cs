using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    internal async Task<OwnedDid2InitialContactDraft> PrepareOwnInitialContactDraftAsync(
        ReadOnlyMemory<byte> logicalIntent, VerifiedDeepIdV2PermanentContactResolveClosure contact,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        var intent = logicalIntent.ToArray();
        try
        {
            var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
            return await PrepareOwnedInitialContactDraftAsync(intent, fresh, source, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(intent); }
    }

    internal async Task<OwnedDid2InitialContactDraft> PrepareOwnedInitialContactDraftAsync(
        ReadOnlyMemory<byte> logicalIntent, DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority contact,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        var intent = logicalIntent.ToArray();
        try
        {
            using var verifier = OpenVerifier();
            return await owner.PrepareInitialContactDraftAsync(TrustedUnixSeconds(), verifier, intent, source, contact, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(intent); }
    }

    internal Task<DeepIdV2InitialSessionCommit> CompleteOwnInitialContactAsync(
        ReadOnlyMemory<byte> logicalIntent, VerifiedDeepIdV2PermanentContactResolveClosure contact,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
        => CompleteOwnInitialContactAsync(logicalIntent, contact, source, null, ct);

    // Connected local completion. Shipping callers cannot author protocol
    // events or inject a trust flag; the alternate transport is test-internal.
    internal async Task<DeepIdV2InitialSessionCommit> CompleteOwnInitialContactAsync(
        ReadOnlyMemory<byte> logicalIntent, VerifiedDeepIdV2PermanentContactResolveClosure contact,
        DeepIdV2ContactPathAuthoritySource source, IExactContactResolveOnionTransport? claimOnion, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(contact); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(logicalIntent.Span);
        var intent = logicalIntent.ToArray();
        try
        {
            var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
            using var draft = await PrepareOwnedInitialContactDraftAsync(intent, fresh, source, ct).ConfigureAwait(false);
            return await CompletePreparedOwnInitialContactAsync(intent, fresh, source, claimOnion, draft, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(intent); }
    }

    // StartContact already prepared this exact owned draft in the same command.
    // Same-command proof inputs are not a verification cache: protected draft,
    // endpoint, clock and claim checks still run under their current leases.
    private async Task<DeepIdV2InitialSessionCommit> CompletePreparedOwnInitialContactAsync(
        ReadOnlyMemory<byte> logicalIntent, DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority contact,
        DeepIdV2ContactPathAuthoritySource source, IExactContactResolveOnionTransport? claimOnion,
        OwnedDid2InitialContactDraft draft, CancellationToken ct)
    {
        var intent = logicalIntent.ToArray(); byte[] initial = [], hello = [];
        try
        {
            initial = draft.ExactInit.ToArray(); hello = draft.ExactHello.ToArray();
            using var verifier = OpenVerifier();
            var completed = await owner.FindCompletedContactDraftAsync(TrustedUnixSeconds(), verifier, intent,
                initial, hello, source, contact, ct).ConfigureAwait(false);
            if (completed is not null) return completed;
            var claim = await owner.ClaimPermanentContactAsync(TrustedUnixSeconds(), verifier, intent, source, contact,
                OwnedMailboxMaximumMessagesWithoutPqInjection, claimOnion, ct).ConfigureAwait(false);
            var result = DeepIdV2PreKeyClaimResultCodec.Decode(claim.Result.ExactResult.Span, claim.Request.CanonicalBytes.Span);
            return await source.CompleteOwnContactDraftClaimAsync(intent, contact, claim.Request, result, initial, hello, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { intent, initial, hello }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
