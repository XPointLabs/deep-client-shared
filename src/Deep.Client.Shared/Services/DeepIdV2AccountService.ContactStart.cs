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
            using var verifier = OpenVerifier();
            return await owner.PrepareInitialContactDraftAsync(TrustedUnixSeconds(), verifier, intent, source, fresh, ct).ConfigureAwait(false);
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
        var intent = logicalIntent.ToArray(); byte[] initial = [], hello = [];
        try
        {
            using var draft = await PrepareOwnInitialContactDraftAsync(intent, contact, source, ct).ConfigureAwait(false);
            initial = draft.ExactInit.ToArray(); hello = draft.ExactHello.ToArray();
            var fresh = await source.VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
            using var verifier = OpenVerifier();
            var completed = await owner.FindCompletedContactDraftAsync(TrustedUnixSeconds(), verifier, intent,
                initial, hello, source, fresh, ct).ConfigureAwait(false);
            if (completed is not null) return completed;
            var request = await PrepareOwnPermanentContactClaimAsync(intent, contact, source, OwnedMailboxMaximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
            var custody = await OpenOwnClaimRequestCustodyAsync(ct).ConfigureAwait(false);
            claimOnion ??= new DeepIdV2PublicationOnionTransport(source, await OpenOwnOnionClientCustodyAsync(ct).ConfigureAwait(false));
            var verified = await new DeepIdV2PreKeyClaimTransport(source, claimOnion, custody).ClaimExactAsync(request.CanonicalBytes, ct).ConfigureAwait(false);
            var result = DeepIdV2PreKeyClaimResultCodec.Decode(verified.ExactResult.Span, request.CanonicalBytes.Span);
            return await source.CompleteOwnContactDraftClaimAsync(intent, contact, request, result, initial, hello, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { intent, initial, hello }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
