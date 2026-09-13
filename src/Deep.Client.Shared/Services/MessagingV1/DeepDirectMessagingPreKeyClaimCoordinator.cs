using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Authors, journals, dispatches, and verifies the exact XPK1 which advances a
/// pre-XPK1 initiator capability. A successful result restored after restart is
/// reverified against current path authority before it is returned.
/// </summary>
public sealed class DeepDirectMessagingPreKeyClaimCoordinator
{
    private readonly SqliteXpk1ClaimJournal journal;
    private readonly IExactContactResolveOnionTransport onion;
    private readonly IContactResolvePathAuthoritySource pathAuthorities;
    private readonly ContactResolverPreKeyV1ClaimReceiptVerifier verifier;
    private readonly ContactResolverReverifiedPeerAuthority peer;

    public DeepDirectMessagingPreKeyClaimCoordinator(
        SqliteXpk1ClaimJournal journal,
        PrivacyRoutedContactResolverTransport onionTransport,
        IContactResolvePathAuthoritySource pathAuthoritySource,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        ContactResolverReverifiedPeerAuthority reverifiedPeer)
    {
        this.journal = journal ?? throw new ArgumentNullException(nameof(journal));
        onion = onionTransport ?? throw new ArgumentNullException(nameof(onionTransport));
        pathAuthorities = pathAuthoritySource
            ?? throw new ArgumentNullException(nameof(pathAuthoritySource));
        peer = reverifiedPeer ?? throw new ArgumentNullException(nameof(reverifiedPeer));
        verifier = new ContactResolverPreKeyV1ClaimReceiptVerifier(
            peer,
            trustedTimeAuthority ?? throw new ArgumentNullException(
                nameof(trustedTimeAuthority)));
    }

    public async ValueTask<VerifiedXpc1PreKeyClaimReceipt> ClaimAsync(
        DeepDirectMessagingInitiatorClaimStart startedClaim,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(startedClaim);
        cancellationToken.ThrowIfCancellationRequested();
        if (!journal.Scope.Equals(peer.Evidence.Scope))
        {
            throw new CryptographicException(
                "The XPK1 journal and reverified peer do not belong to the same account scope.");
        }
        var service = peer.Bundle.GetAuthorizedPreKeyService(peer.Route.Authority);
        var placement = ContactServicePlacementFactory.Create(
            peer.Placement.Network,
            ContactServiceRequestKind.ClaimPreKey,
            service.ServiceCapability);
        var issuedAt = peer.Route.Authority.TrustedLowerUnixSeconds;
        var expiresAt = Math.Min(
            Math.Min(peer.Route.Authority.ExpiresAtUnixSeconds,
                placement.ValidUntilUnixSeconds),
            service.ExpiresAtUnixSeconds);
        if (issuedAt == 0 || expiresAt <= peer.Route.Authority.TrustedUpperUnixSeconds ||
            service.SupportedSuite != 0x0201)
        {
            throw new CryptographicException(
                "The reverified peer pre-key service has no live supported XPK1 window.");
        }

        var exactXpk1 = Xpk1Codec.Encode(
            service.NetworkId.Span,
            startedClaim.ClaimOperationId.Span,
            placement.ViewHash.Span,
            placement.PlacementHash.Span,
            issuedAt,
            expiresAt,
            service.ServiceCapability.Span,
            service.Dcb1Hash.Span,
            service.Xps1Hash.Span,
            service.DeviceId.Span,
            startedClaim.SenderEphemeralCommitment.Span);
        try
        {
            var staged = await journal.StageAsync(exactXpk1, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (staged.Disposition is Xpk1ClaimJournalDisposition.ScopeRejected or
                Xpk1ClaimJournalDisposition.ForkLatched || staged.State.IsForkLatched)
            {
                throw new CryptographicException(
                    "The durable XPK1 journal rejected or fork-latched the exact claim.");
            }

            var operation = staged.TryCreateDispatchOperation();
            if (operation is null)
            {
                if (!staged.State.IsTerminal || staged.StoredResultWire.IsEmpty)
                {
                    throw new CryptographicException(
                        "The durable XPK1 journal has no dispatchable or terminal verified result.");
                }
                return await ReverifyStoredAsync(
                        staged,
                        exactXpk1,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var request = ContactResolveCanonicalPathRequest.Decode(exactXpk1);
            var response = await onion.SendExactAsync(
                    request,
                    ReadOnlyMemory<byte>.Empty,
                    cancellationToken)
                .ConfigureAwait(false);
            var pathAuthority = response.PathAuthority ??
                throw new CryptographicException(
                    "The XPK1 ONION dispatch returned no verified path authority.");
            var result = Xpc1Codec.Decode(response.ExactBody.Span, exactXpk1);
            if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay))
            {
                _ = await journal.RecordFailureAsync(
                        operation,
                        response.ExactBody,
                        cancellationToken)
                    .ConfigureAwait(false);
                throw new CryptographicException(
                    $"The verified Contact Resolver returned XPC1 status {result.Status}.");
            }
            var verified = await verifier.VerifyAsync(
                    operation,
                    result,
                    pathAuthority,
                    cancellationToken)
                .ConfigureAwait(false);
            _ = await journal.RecordVerifiedClaimAsync(
                    operation,
                    response.ExactBody,
                    verified,
                    cancellationToken)
                .ConfigureAwait(false);
            return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactXpk1);
        }
    }

    private async ValueTask<VerifiedXpc1PreKeyClaimReceipt> ReverifyStoredAsync(
        Xpk1ClaimJournalEntry entry,
        ReadOnlyMemory<byte> exactXpk1,
        CancellationToken cancellationToken)
    {
        var request = ContactResolveCanonicalPathRequest.Decode(exactXpk1.Span);
        var pathAuthority = await pathAuthorities.GetCurrentAsync(
                request,
                cancellationToken)
            .ConfigureAwait(false);
        var result = Xpc1Codec.Decode(entry.StoredResultWire.Span, exactXpk1.Span);
        if (result.Status is not (Xpc1Status.Claimed or Xpc1Status.Replay))
        {
            throw new CryptographicException(
                "The terminal XPK1 journal result is not a successful claim.");
        }
        var retained = new PreKeyV1DurableClaimOperation(
            exactXpk1.Span,
            entry.State.OperationId.Span,
            entry.Revision);
        return await verifier.VerifyAsync(
                retained,
                result,
                pathAuthority,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
