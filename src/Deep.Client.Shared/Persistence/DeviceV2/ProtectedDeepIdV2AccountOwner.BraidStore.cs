using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<ClientMailboxStoreResult?> ReadRetainedBraidStoreAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope requestedScope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
        return await TryReadRetainedBraidStoreUnderLeaseAsync(current, held, opened, scope, operation,
            own, source, ct).ConfigureAwait(false);
    }

    private static OwnedDid2BraidControlPersistedEvent RequireOwnedBraidSend(OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, Did2MessagingFloor floor, ReadOnlySpan<byte> operation)
    {
        if (opened.Sql.ReadVerifiedNativeEventDirection(floor, operation) != 3)
            throw new CryptographicException("Control Store requires an actual authenticated native send.");
        var retained = opened.Sql.ReadVerifiedBraidControl(floor, operation) ??
            throw new CryptographicException("Control Store lost its committed exact frame.");
        try
        {
            var frame = Dbr2Codec.Decode(retained.ExactControl);
            if (!FixedRoute(frame.OperationId.Span, operation) || !FixedRoute(frame.NetworkId.Span, scope.Network) ||
                !FixedRoute(frame.SessionId.Span, scope.Session) || !FixedRoute(frame.SenderDeviceId.Span, scope.LocalDevice) ||
                !FixedRoute(frame.RecipientDeviceId.Span, scope.RemoteDevice))
                throw new CryptographicException("Control Store differs from its native session/direction.");
            return retained;
        }
        catch { retained.Dispose(); throw; }
    }

    private async Task RequireBraidStorePurposeUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> exact,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = RequireOwnedBraidSend(opened, scope, floor, operation.Span);
        if (!FixedRoute(native.ExactControl, exact.Span))
            throw new CryptographicException("Control dispatch cannot remint its original native frame.");
        var frame = Dbr2Codec.Decode(native.ExactControl);
        // Only received, authenticated same-peer data proves that peer installed
        // this output. Local output completion and Store are not peer progress.
        if (opened.Sql.HasVerifiedPeerBraidPurposeProgress(floor, frame.BraidEpoch, ct))
            throw new IOException("The peer has completed this control purpose; retain original transport outcomes without new dispatch.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task RetainBraidStoreEvidenceBeforeDispatchUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        if (evidence.IsInitial) throw new CryptographicException("Control Store cannot acquire initial/application evidence.");
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = RequireOwnedBraidSend(opened, scope, floor, operation.Span);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var attempt = await RequireCurrentStoreEvidenceAttemptUnderLeaseAsync(current, held, opened, scope, operation,
            ReadOnlyMemory<byte>.Empty, evidence, ct).ConfigureAwait(false);
        try
        {
            await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation, attempt, evidence, ct).ConfigureAwait(false);
            await application.RecordStorePublicEvidenceAsync(scope, operation, attempt, evidence, ct).ConfigureAwait(false);
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(final.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Control evidence lost its actual stable native predecessor.");
            using var rechecked = RequireOwnedBraidSend(opened, scope, final, operation.Span);
            if (!FixedRoute(native.ExactControl, rechecked.ExactControl))
                throw new CryptographicException("Control evidence changed its retained frame.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { CryptographicOperations.ZeroMemory(attempt); }
    }

    // Historical Store only. No DMC2/command marker, signer, fresh peer lookup,
    // replacement request or native control acceptance is manufactured here.
    private async Task<ClientMailboxStoreResult?> TryReadRetainedBraidStoreUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        RequireRetainedStoreOwnScope(scope, own);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = RequireOwnedBraidSend(opened, scope, floor, operation.Span);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Control Store lost mandatory original send custody.");
        var sendRoot = raw.Use(bytes => bytes.ToArray());
        var exact = native.ExactControl.ToArray();
        try
        {
            using var sends = ProtectedDid2MailboxSendJournal.Decode(sendRoot, scope.Network, scope.LocalAccount, scope.Instance);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
                storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            using var selected = await ReadRetainedStoreAttemptCandidateUnderLeaseAsync(held, scope, operation,
                exact, application, sends, ct).ConfigureAwait(false);
            if (selected is null) return null;
            var metadata = selected.Evidence;
            if (metadata.IsInitial) throw new CryptographicException("Historical control Store has initial evidence.");
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            var route = await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, metadata.OriginalRoute, ct).ConfigureAwait(false);
            var replicas = MailboxStoreReplicaEvidenceVerifier.Verify(own.Network, own.Authority, route, metadata.Replicas);
            var upper = checked(own.Proof.TrustedUpperUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
            var receipt = await VerifyOriginalStoreOutcomeAsync(scope, selected.Attempt, exact, application, route,
                metadata, replicas, own, source, upper, ct).ConfigureAwait(false);
            var finalMetadata = await application.RequireStorePublicEvidenceAsync(scope, operation, selected.Attempt, ct).ConfigureAwait(false);
            RequireSameInitialStoreEvidence(metadata, finalMetadata);
            await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, operation, selected.Attempt, finalMetadata, ct).ConfigureAwait(false);
            var finalRoute = await ReadOriginalPeerStoreRouteAsync(current, held, opened, application, finalMetadata.OriginalRoute, ct).ConfigureAwait(false);
            if (!FixedRoute(route.ExactBytes.Span, finalRoute.ExactBytes.Span))
                throw new CryptographicException("Historical control Store changed its authenticated original route.");
            var finalReceipt = await VerifyOriginalStoreOutcomeAsync(scope, selected.Attempt, exact, application, finalRoute,
                finalMetadata, replicas, own, source, upper, ct).ConfigureAwait(false);
            if (receipt.Cursor != finalReceipt.Cursor || receipt.Disposition != finalReceipt.Disposition ||
                !FixedRoute(MailboxReceiptV3Codec.EncodeDurableQuorum(receipt.CoordinatorReceipt),
                    MailboxReceiptV3Codec.EncodeDurableQuorum(finalReceipt.CoordinatorReceipt)))
                throw new CryptographicException("Historical control Store changed its original terminal evidence.");
            var finalFloor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, finalFloor.Exact.Span))
                throw new CryptographicException("Historical control Store changed its protected native floor.");
            using var rechecked = RequireOwnedBraidSend(opened, scope, finalFloor, operation.Span);
            if (!FixedRoute(exact, rechecked.ExactControl))
                throw new CryptographicException("Historical control Store changed its committed frame.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, sendRoot, ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(receipt.Cursor, receipt.Disposition, false, receipt.CoordinatorReceipt.CoordinatorId.Span);
        }
        finally { CryptographicOperations.ZeroMemory(sendRoot); CryptographicOperations.ZeroMemory(exact); }
    }
}
