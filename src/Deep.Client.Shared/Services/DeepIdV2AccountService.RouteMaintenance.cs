using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
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
        _ = await owner.ContinueRouteHistoryAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            resolved.Own, resolved.Contact.Authorization.Freshness, source, ct).ConfigureAwait(false);
        var selection = await owner.SelectOwnRouteMaintenanceAsync(TrustedUnixSeconds(), verifier,
            conversation.Scope, resolved.Own, resolved.Contact.Authorization.Freshness, source, ct).ConfigureAwait(false);
        if (selection is null) return 0;
        try
        {
            using var command = selection.Length == 0
                ? await CreateOwnElectiveRouteAnnouncementAsync(conversation.Scope, source, ct).ConfigureAwait(false)
                : await PrepareOwnDirectRouteUpdateAsync(conversation.Scope, selection, source, ct).ConfigureAwait(false);
            if (command is null) return 0;
            using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
                command.ExactDmc2, source, ct, routeControl: true).ConfigureAwait(false);
            _ = await DeliverOwnRouteReintroductionWithRecoveryAsync(conversation.Scope, command.OperationId,
                peerAddress, resolved, source, new Did2MailboxGrantOnionTransport(source),
                new Did2OwnedMailboxOnionTransportFactory(), ct).ConfigureAwait(false);
            return 1;
        }
        finally { CryptographicOperations.ZeroMemory(selection); }
    }

    // Selection, authoring and native encryption precede this boundary exactly
    // once. Recovery reopens only this owned operation's original Store custody.
    internal async Task<ClientMailboxStoreResult> DeliverOwnRouteReintroductionWithRecoveryAsync(
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, DeepPermanentIdV2 peerAddress,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority firstContact,
        DeepIdV2ContactPathAuthoritySource source, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct,
        IExactContactResolveOnionTransport? contactRead = null)
    {
        ArgumentNullException.ThrowIfNull(scope); ArgumentNullException.ThrowIfNull(peerAddress);
        ArgumentNullException.ThrowIfNull(firstContact); ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(grants); ArgumentNullException.ThrowIfNull(transport);
        source.RequireAccountOwner(this); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var exact = operation.ToArray(); var first = true;
        try
        {
            async Task<ClientMailboxStoreResult> Attempt()
            {
                var initial = first; first = false;
                using var reads = initial ? null : source.OpenIndependentCommandReadScope();
                var currentSource = reads?.Source ?? source;
                using var verifier = OpenVerifier();
                var own = initial ? firstContact.Own :
                    await currentSource.VerifyForOwnPreKeyAuthoringAsync(this, ct).ConfigureAwait(false);
                var retained = await owner.ReadRetainedMessagingStoreAsync(TrustedUnixSeconds(), verifier,
                    scope, exact, own, currentSource, ct).ConfigureAwait(false);
                if (retained is not null) return retained;
                // Original expiry/closure is checked before any new peer lookup.
                await owner.RequireMessagingWorkNotStoppedAsync(TrustedUnixSeconds(), verifier,
                    scope, exact, own, currentSource, ct).ConfigureAwait(false);
                var currentContact = initial ? firstContact :
                    await ResolveOwnedPermanentContactAsync(peerAddress, currentSource, contactRead, ct).ConfigureAwait(false);
                return await owner.DeliverRouteReintroductionAsync(TrustedUnixSeconds(), verifier, scope,
                    exact, currentContact, currentSource, grants, transport, ct).ConfigureAwait(false);
            }
            return await OwnedMailboxRecovery.RunAsync(Attempt,
                () => source.DiscardUncapturedAuthorityAsync(ct),
                () => Interlocked.Increment(ref storeResumes), () => Interlocked.Increment(ref recoveryLeaseWaits), ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
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
    /// <returns>One for an original or resumed update with verified Store; zero when no runnable update remains, including a confirmed expiry stop. Zero grants no Store or current-route admission.</returns>
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
        => (await DispatchPublishedContactMaintenanceAsync(conversation, source, RouteMaintenanceDispatch.Ordinary,
            null, ct).ConfigureAwait(false)).Completed;

    private enum RouteMaintenanceDispatch { Ordinary, Connected }
    internal readonly record struct ConnectedContactRouteMaintenanceOutcome(int Completed, bool Reintroduced, bool Deferred);

    internal Task<ConnectedContactRouteMaintenanceOutcome> MaintainPublishedContactRouteAsync(
        DeepIdV2Conversation conversation, DeepPermanentIdV2? knownPeer, DeepIdV2ContactPathAuthoritySource source,
        CancellationToken ct, IExactContactResolveOnionTransport? contactRead = null,
        IDid2MailboxGrantTransport? grants = null, IDid2OwnedMailboxTransportFactory? transport = null)
        => DispatchPublishedContactMaintenanceAsync(conversation, source, RouteMaintenanceDispatch.Connected,
            knownPeer, ct, contactRead, grants, transport);

    private async Task<ConnectedContactRouteMaintenanceOutcome> DispatchPublishedContactMaintenanceAsync(
        DeepIdV2Conversation conversation, DeepIdV2ContactPathAuthoritySource source, RouteMaintenanceDispatch purpose,
        DeepPermanentIdV2? knownPeer, CancellationToken ct, IExactContactResolveOnionTransport? contactRead = null,
        IDid2MailboxGrantTransport? grants = null, IDid2OwnedMailboxTransportFactory? transport = null)
    {
        using var reads = source.OpenCommandReadScope(); source = reads.Source;
        var pair = await source.VerifyForOwnMessagingAsync(this, conversation.Scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        _ = await owner.ContinueRouteHistoryAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        var selection = await owner.SelectOwnRouteMaintenanceAsync(TrustedUnixSeconds(), verifier,
            conversation.Scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
        if (selection is null) return new(0, false, false);
        try
        {
            var expired = purpose == RouteMaintenanceDispatch.Connected &&
                await owner.ReadExpiredPeerAnnouncementForMaintenanceAsync(TrustedUnixSeconds(), verifier,
                    conversation.Scope, pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
            if (expired && knownPeer is null) return new(0, false, true);
            using var alternateReads = expired ? source.OpenIndependentCommandReadScope() : null;
            var dispatchSource = alternateReads?.Source ?? source;
            DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority? resolved = null;
            if (expired)
            {
                resolved = await ResolveOwnedPermanentContactAsync(knownPeer!, dispatchSource, contactRead, ct).ConfigureAwait(false);
                // Expiry selects only this attempted path. The unchanged owner
                // independently admits the actual known peer/scope/effect.
                await owner.RequireRouteReintroductionAsync(TrustedUnixSeconds(), verifier, conversation.Scope,
                    resolved, dispatchSource, ct).ConfigureAwait(false);
            }
            using var command = selection.Length == 0
                ? await CreateOwnElectiveRouteAnnouncementAsync(conversation.Scope, dispatchSource, ct).ConfigureAwait(false)
                : await PrepareOwnDirectRouteUpdateAsync(conversation.Scope, selection, dispatchSource, ct).ConfigureAwait(false);
            if (command is null) return new(0, false, expired);
            using var native = await SendOwnedMessagingCoreAsync(conversation.Scope, command.OperationId,
                command.ExactDmc2, dispatchSource, ct, routeControl: true).ConfigureAwait(false);
            if (resolved is null)
                _ = await DeliverOwnMessagingAsync(conversation.Scope, command.OperationId, dispatchSource, ct).ConfigureAwait(false);
            else
                _ = await DeliverOwnRouteReintroductionWithRecoveryAsync(conversation.Scope, command.OperationId, knownPeer!,
                    resolved, dispatchSource, grants ?? new Did2MailboxGrantOnionTransport(dispatchSource),
                    transport ?? new Did2OwnedMailboxOnionTransportFactory(), ct, contactRead).ConfigureAwait(false);
            return new(1, expired, expired);
        }
        finally { CryptographicOperations.ZeroMemory(selection); }
    }

    internal async Task<DirectTextOutboxEntry?> CreateOwnElectiveRouteAnnouncementAsync(Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        source.RequireAccountOwner(this);
        var pair = await source.VerifyForOwnMessagingAsync(this, scope, ct).ConfigureAwait(false);
        using var verifier = OpenVerifier();
        return await owner.PrepareElectiveRouteAnnouncementAsync(TrustedUnixSeconds(), verifier, scope,
            pair.Own, pair.Peer, source, ct).ConfigureAwait(false);
    }
}
