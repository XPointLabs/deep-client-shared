using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

public sealed partial class DeepIdV2ContactPathAuthoritySource
{
    // Source-owned proof client/clock feed completion; never supplied by UI.
    internal async Task<DeepIdV2InitialSessionCommit> CompleteOwnContactDraftClaimAsync(
        ReadOnlyMemory<byte> intent, VerifiedDeepIdV2PermanentContactResolveClosure contact,
        ParsedXpk1V2 request, ParsedXpc1V2 result, ReadOnlyMemory<byte> initial, ReadOnlyMemory<byte> hello, CancellationToken ct)
    {
        var fresh = await VerifyPermanentContactAsync(contact.Candidate, ct).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(fresh.Own.Network, ContactServiceRequestKind.ClaimPreKey, request.Field(16));
        var claim = await DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(request, result, placement,
            fresh.Contact.Authorization, fresh.Contact.Contact, trustedTime, ct).ConfigureAwait(false);
        using var draft = await accounts.PrepareOwnInitialContactDraftAsync(intent, fresh.Contact, this, ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(draft.ExactInit, initial.Span) || !Did2MessagingSessionScope.Fixed(draft.ExactHello, hello.Span))
            throw new CryptographicException("Contact completion differs from the exact protected initial draft.");
        var reading = await RecheckOwnPreKeyAuthoringAsync(fresh.Own, ct).ConfigureAwait(false);
        return await accounts.CommitOwnDph2InitialSessionAsync(intent, result.Field(16), proofs,
            fresh.Own.Authority, fresh.Own.Proof, fresh.Contact.Authorization.Freshness, reading.BootId, reading.SampleSeconds,
            claim, trustedTime, initial, hello, DeepIdV2AccountService.OwnedMailboxMaximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
    }
}
