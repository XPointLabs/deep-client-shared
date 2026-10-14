using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Did2MessagingSessionScope?> FindIncomingBraidMessagingScopeAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, UnverifiedDbr2Record incoming, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(incoming);
        if (!Did2MessagingSessionScope.Fixed(incoming.NetworkId.Span, networkId))
            throw new CryptographicException("Incoming Braid control belongs to another network.");
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var device = current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.DeviceId;
        if (!Did2MessagingSessionScope.Fixed(incoming.RecipientDeviceId.Span, device.Span))
            throw new CryptographicException("Incoming Braid control belongs to another owned device.");
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var scope = catalog.FindIncoming(incoming.NetworkId.Span, incoming.SessionId.Span,
                incoming.SenderDeviceId.Span, incoming.RecipientDeviceId.Span);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return scope;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    // A local precheck only: the ACK owner rederives this classification from
    // current exact custody and the captured object before signing anything.
    internal async Task<bool> TryResolveBraidMailboxCustodyAsync(ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> exactControl,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var frame = Dbr2Codec.Decode(exactControl.Span);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var disposition = ClassifyBraidMailboxCustodyUnderLease(opened, scope, floor, frame, held, ct);
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        return disposition != BraidMailboxCustody.NotCommitted;
    }

    private enum BraidMailboxCustody { NotCommitted, AuthenticatedReceive, ObsoletePurpose }

    private BraidMailboxCustody ClassifyBraidMailboxCustodyUnderLease(OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, Did2MessagingFloor floor, UnverifiedDbr2Record frame,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        if (!FixedRoute(frame.NetworkId.Span, scope.Network) || !FixedRoute(frame.SessionId.Span, scope.Session) ||
            !FixedRoute(frame.SenderDeviceId.Span, scope.RemoteDevice) || !FixedRoute(frame.RecipientDeviceId.Span, scope.LocalDevice))
            throw new CryptographicException("Mailbox control lost its owned session/direction.");
        var direction = opened.Sql.ReadVerifiedNativeEventDirection(floor, frame.OperationId.Span);
        if (direction is not null)
        {
            if (direction != 4) throw new CryptographicException("Mailbox control collides with another native event kind/direction.");
            using var received = opened.Sql.ReadVerifiedBraidControl(floor, frame.OperationId.Span) ??
                throw new CryptographicException("Mailbox control lost its retained receive.");
            if (!FixedRoute(received.ExactControl, frame.CanonicalBytes.Span))
                throw new CryptographicException("Mailbox control differs from its exact authenticated receive.");
            return BraidMailboxCustody.AuthenticatedReceive;
        }
        if (opened.Sql.HasVerifiedPeerBraidPurposeProgress(floor, frame.BraidEpoch, ct))
            return BraidMailboxCustody.ObsoletePurpose;
        var context = opened.Sql.CreateVerifiedBraidTransitionContext(floor, frame.OperationId.Span, frame.CanonicalBytes.Span);
        using var native = opened.Sql.ReadVerifiedLatest(floor);
        var proof = native.Use(bytes => ExactBraidRecoveryDurableTransactionProducer.TryVerifyObsoleteControl(
            bytes, context, scope.Network, frame.CanonicalBytes.Span));
        if (proof is null) return BraidMailboxCustody.NotCommitted;
        if (proof.StateGeneration != floor.RatchetGeneration || !FixedRoute(proof.StateCommitment.Span, floor.RatchetCommitment) ||
            proof.BraidEpoch != frame.BraidEpoch || !FixedRoute(proof.ExactControlHash.Span, SHA256.HashData(frame.CanonicalBytes.Span)))
            throw new CryptographicException("Obsolete control proof lost its actual predecessor/object binding.");
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        return BraidMailboxCustody.ObsoletePurpose;
    }
}
