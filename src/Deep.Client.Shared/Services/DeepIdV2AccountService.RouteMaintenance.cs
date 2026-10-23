using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.Identity;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Services;

public sealed partial class DeepIdV2AccountService
{
    /// <summary>Re-introduces the same established peer through a current permanent
    /// publication solely to carry its existing relationship's route update.
    /// Does not create a contact, replace a ratchet or admit an expired route.</summary>
    public async Task<int> ReintroduceContactRouteAsync(DeepIdV2Conversation conversation,
        DeepPermanentIdV2 peerAddress, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(peerAddress);
        ArgumentNullException.ThrowIfNull(source); source.RequireAccountOwner(this);
        _ = await EnsureOwnPermanentContactPublishedAsync(source, ct).ConfigureAwait(false);
        return await ReintroducePublishedContactRouteAsync(conversation, peerAddress, source, ct).ConfigureAwait(false);
    }

    private async Task<int> ReintroducePublishedContactRouteAsync(DeepIdV2Conversation conversation,
        DeepPermanentIdV2 peerAddress, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var reads = source.OpenIndependentCommandReadScope(); source = reads.Source;
        var resolved = await ResolveOwnedPermanentContactAsync(peerAddress, source, null, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        // This check is BEFORE authoring: an unrelated current publication
        // cannot leave a new native command in the selected relationship.
        await owner.RequireRouteReintroductionAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            resolved, source, ct).ConfigureAwait(false);
        var selection = await owner.SelectOwnRouteMaintenanceAsync(TrustedUnixSeconds(), verifier,
            conversation.Scope, resolved.Own, resolved.Contact.Authorization.Freshness, source, ct).ConfigureAwait(false);
        if (selection is null) return 0;
        try
        {
            using var command = selection.Length == 0
                ? await CreateOwnDirectRouteUpdateAsync(conversation.Scope, source, ct).ConfigureAwait(false)
                : await PrepareOwnDirectRouteUpdateAsync(conversation.Scope, selection, source, ct).ConfigureAwait(false);
            using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
                command.ExactDmc2, source, ct, routeControl: true).ConfigureAwait(false);
            var retained = await owner.ReadRetainedMessagingStoreAsync(TrustedUnixSeconds(), verifier,
                conversation.Scope, command.OperationId, resolved.Own, source, ct).ConfigureAwait(false);
            if (retained is null)
                _ = await owner.DeliverRouteReintroductionAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
                    command.OperationId, resolved, source, new Did2MailboxGrantOnionTransport(source),
                    new Did2OwnedMailboxOnionTransportFactory(), ct).ConfigureAwait(false);
            return 1;
        }
        finally { CryptographicOperations.ZeroMemory(selection); }
    }

    // Synchronous historical proof verification only. No capability, current
    // time, owner lease, cache or raw verifier lease escapes to a caller.
    internal ParsedContactRouteClosure VerifyOriginalRoutePublication(DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        ParsedDid2 peer, ReadOnlySpan<byte> adp, ReadOnlySpan<byte> dcr, ReadOnlySpan<byte> route, ulong originalSeconds)
    {
        using var verifier = OpenVerifier();
        return DeepIdV2OriginalContactStoreVerifier.Verify(own.Authority, peer, adp, dcr, route,
            originalSeconds, deploymentProfileId, 2, verifier);
    }

    /// <summary>Renews the own adopted publication and advertises its exact successor to one established contact through the existing ratcheted mailbox. Does not use an expired route or XUR.</summary>
    /// <param name="conversation">An existing mutually consented owned conversation.</param>
    /// <param name="source">Independently current network and directory source.</param>
    /// <param name="ct">Cancellation for this owned maintenance operation.</param>
    /// <returns>One for an original or resumed update with verified Store; zero when the actual native advertisement already matches.</returns>
    public async Task<int> RefreshContactRouteAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation); ArgumentNullException.ThrowIfNull(source);
        source.RequireAccountOwner(this);
        // Publication renewal remains its existing exact pending/committed saga.
        // Discard any earlier read memo before acquiring the messaging endpoint.
        _ = await EnsureOwnPermanentContactPublishedAsync(source, ct).ConfigureAwait(false);
        return await RefreshPublishedContactRouteAsync(conversation, source, ct).ConfigureAwait(false);
    }

    private async Task<int> RefreshPublishedContactRouteAsync(DeepIdV2Conversation conversation,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        var selection = await owner.SelectOwnRouteMaintenanceAsync(TrustedUnixSeconds(), verifier,
            conversation.Scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        if (selection is null) return 0;
        try
        {
            using var command = selection.Length == 0
                ? await CreateOwnDirectRouteUpdateAsync(conversation.Scope, source, ct).ConfigureAwait(false)
                : await PrepareOwnDirectRouteUpdateAsync(conversation.Scope, selection, source, ct).ConfigureAwait(false);
            using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
                command.ExactDmc2, source, ct, routeControl: true).ConfigureAwait(false);
            _ = await DeliverOwnMessagingAsync(conversation.Scope, command.OperationId, source, ct).ConfigureAwait(false);
            return 1;
        }
        finally { CryptographicOperations.ZeroMemory(selection); }
    }
}
