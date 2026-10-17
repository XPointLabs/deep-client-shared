using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<bool> CommitIncomingMailboxInitialAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Dph2Record incoming, DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority pair,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, pair.Own, pair.Peer, source, held, ct).ConfigureAwait(false);
        var device = current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate;
        if (!FixedRoute(incoming.NetworkId.Span, networkId) || !FixedRoute(incoming.ResponderAccountId.Span, current.AccountId.Span) ||
            !FixedRoute(incoming.ResponderDeviceId.Span, device.DeviceId.Span) || incoming.ResponderDeviceGeneration != device.DeviceGeneration)
            throw new CryptographicException("Initial mailbox input belongs to another recipient.");
        // Closed historical source replay precedes lookup of consumed secrets.
        using var previous = await SqliteDeepIdV2AccountGeneration.FindReceiverUnderLeaseAsync(storage, sqlStatePath, current, incoming, ct).ConfigureAwait(false);
        var expired = previous?.IsExpiredDisposal ?? false;
        if (previous is null)
        {
            using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, pair.Own, ct).ConfigureAwait(false);
            var preview = await SqliteDeepIdV2AccountGeneration.PreviewInitialClaimUnderLeaseAsync(storage, sqlStatePath,
                current, incoming, pair.Own, pair.Peer, first, source.RendezvousTrustedTime,
                DeepIdV2AccountService.OwnedMailboxMaximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
            var placement = ContactServicePlacementFactory.Create(pair.Own.Network, ContactServiceRequestKind.ClaimPreKey, preview.Request.Field(16));
            var claim = await preview.VerifyCurrentAsync(placement, publication.Route.Recipient, publication.Contact,
                pair.Peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var reading = await RequireMessagingFreshnessAsync(current, pair.Own, pair.Peer, source, held, ct).ConfigureAwait(false);
            await publication.RecheckCustodyAsync(ct).ConfigureAwait(false);
            using var committed = await SqliteDeepIdV2AccountGeneration.CommitMailboxReceiverUnderLeaseAsync(storage, sqlStatePath,
                current, claim, pair.Own, pair.Peer, reading, source.RendezvousTrustedTime,
                DeepIdV2AccountService.OwnedMailboxMaximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
            expired = committed.IsExpiredDisposal;
            await publication.RecheckCustodyAsync(ct).ConfigureAwait(false);
        }
        var final = await RequireMessagingFreshnessAsync(current, pair.Own, pair.Peer, source, held, ct).ConfigureAwait(false);
        if (final.SampleSeconds < first.SampleSeconds || !FixedRoute(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Initial mailbox receive crossed protected clock continuity.");
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        return expired; // Selection only. ACK independently rereads native custody.
    }

    internal async Task<bool> HasCommittedExpiredMailboxInitialAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Dph2Record incoming, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var retained = await SqliteDeepIdV2AccountGeneration.FindReceiverUnderLeaseAsync(storage, sqlStatePath, current, incoming, ct).ConfigureAwait(false);
        if (retained is null || !retained.IsExpiredDisposal) return false;
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            await RequireExpiredInitialUnderLeaseAsync(current, held, retained, catalog, source, own, ct).ConfigureAwait(false);
            return true;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private static async Task RequireExpiredInitialUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, DeepIdV2InitialContactSessionCommit retained,
        ProtectedDid2MessagingSessionCatalog.Snapshot catalog, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var device = current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate;
        if (!FixedRoute(retained.Record.NetworkId.Span, own.Proof.CurrentCheckpoint!.Directory.Record.NetworkId.Span) ||
            !FixedRoute(retained.Record.ResponderAccountId.Span, current.AccountId.Span) ||
            !FixedRoute(retained.Record.ResponderDeviceId.Span, device.DeviceId.Span) ||
            retained.Record.ResponderDeviceGeneration != device.DeviceGeneration ||
            !FixedRoute(retained.Directory.RecordHash.Span, own.Proof.CurrentCheckpoint.Directory.Record.RecordHash.Span) ||
            catalog.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan)) is not null)
            throw new CryptographicException("Expired Initial lacks exclusive terminal custody for the current own device.");
        retained.RequireExpiredAt(checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample));
        _ = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
    }

    private async Task MaterializeMailboxInitialUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Dph2Record incoming, IReadOnlyList<Did2MailboxSemanticEndpoints> endpoints,
        ProtectedDid2MessagingSessionCatalog.Snapshot catalog, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        using var retained = await SqliteDeepIdV2AccountGeneration.FindReceiverUnderLeaseAsync(storage, sqlStatePath, current, incoming, ct).ConfigureAwait(false) ??
            throw new CryptographicException("Initial ACK has no actual committed receiver source.");
        if (retained.IsExpiredDisposal)
        {
            await RequireExpiredInitialUnderLeaseAsync(current, held, retained, catalog, source, own, ct).ConfigureAwait(false);
            return; // No live scope, peer loan, consent, session import or contact row.
        }
        var scope = catalog.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan)) ??
            throw new CryptographicException("Initial ACK has no owned mutable catalog registration.");
        if (catalog.Phase(catalog.FindExact(scope)) != 2) throw new CryptographicException("Initial ACK cannot initialize mutable SQL.");
        Did2MessagingSourceScope.RequireReceiver(scope, retained);
        var selected = endpoints.SingleOrDefault(value => FixedRoute(value.Scope.Hash, scope.Hash)) ??
            throw new CryptographicException("Initial ACK has no independently refreshed owned endpoint pair.");
        var first = await RequireMessagingFreshnessAsync(current, selected.Pair.Own, selected.Pair.Peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, selected.Pair.Own.Proof, selected.Pair.Peer, first);
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status != 1) throw new CryptographicException("Initial ACK requires completed source retirement and active mutable custody.");
        await MaterializeInitialMessagingUnderLeaseAsync(current, opened, selected.Pair.Own, selected.Pair.Peer, source, held, ct).ConfigureAwait(false);
        await RequireFinalMessagingFreshnessAsync(current, scope, selected.Pair.Own, selected.Pair.Peer, source, held, first, ct).ConfigureAwait(false);
    }
}
