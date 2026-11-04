using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal Task<OwnedDid2BraidControlPersistedEvent> SendBraidControlAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct) =>
        RunBraidControlAsync(trustedUnixSeconds, verifier, scope, operation, ReadOnlyMemory<byte>.Empty, true, own, peer, source, ct);

    internal Task<OwnedDid2BraidControlPersistedEvent> ReceiveBraidControlAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> exactControl,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct) =>
        RunBraidControlAsync(trustedUnixSeconds, verifier, scope, ReadOnlyMemory<byte>.Empty, exactControl, false, own, peer, source, ct);

    private async Task<OwnedDid2BraidControlPersistedEvent> RunBraidControlAsync(ulong trustedUnixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> receivedControl, bool send, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (send) ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        else if (receivedControl.Length != Dbr2Codec.TotalBytes) throw new InvalidDataException("Braid control exceeds its fixed frame bound.");
        var exact = receivedControl.ToArray();
        var op = send ? operation.ToArray() : Dbr2Codec.Decode(exact).OperationId.ToArray();
        OwnedDid2BraidControlPersistedEvent? result = null;
        OwnedDid2MessagingStorage? maintainedStorage = null;
        try
        {
            if (!send)
            {
                var frame = Dbr2Codec.Decode(exact);
                if (!Did2MessagingSessionScope.Fixed(frame.NetworkId.Span, scope.Network) ||
                    !Did2MessagingSessionScope.Fixed(frame.SessionId.Span, scope.Session) ||
                    !Did2MessagingSessionScope.Fixed(frame.SenderDeviceId.Span, scope.RemoteDevice) ||
                    !Did2MessagingSessionScope.Fixed(frame.RecipientDeviceId.Span, scope.LocalDevice))
                    throw new CryptographicException("Braid control has a different owned session/direction.");
            }
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var account = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            var first = await RequireMessagingFreshnessAsync(account, own, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
            using var firstOpened = await OpenNativeMessagingUnderLeaseAsync(account, scope, held, ct).ConfigureAwait(false);
            var opened = firstOpened;
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var freshNative = true;
            if (send)
            {
                result = await opened.WithSqlAsync(sql => sql.ReadVerifiedBraidControl(floor, op), ct).ConfigureAwait(false);
                freshNative = result is null;
                if (result is not null && result.Direction != 3)
                    throw new CryptographicException("Braid send operation belongs to another direction.");
            }
            else
            {
                using var retained = await opened.WithSqlAsync(sql => sql.ReadVerifiedBraidControl(floor, op), ct).ConfigureAwait(false);
                freshNative = retained is null;
                if (retained is not null && (retained.Direction != 4 || !FixedRoute(retained.ExactControl, exact)))
                    throw new CryptographicException("Braid receive differs from its exact original direction/frame.");
            }
            if (result is null)
            {
                if (send)
                {
                    // Recovery bypasses the data32 fence, not bounded transport
                    // custody. Reject capacity/original-operation conflicts
                    // before native entropy or occupation of a Braid slot.
                    await RequireNewMailboxWorkCapacityUnderLeaseAsync(account, held, opened, scope, op,
                        own, peer, source, verifier, ct).ConfigureAwait(false);
                    floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                }
                if (freshNative)
                {
                    maintainedStorage = await PrepareNativeMaintenanceForBraidAsync(account, scope, opened, floor,
                        held, op, exact, send, own, peer, source, first, ct).ConfigureAwait(false);
                    if (maintainedStorage is not null)
                    {
                        opened = maintainedStorage;
                        floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                    }
                }
                var context = await opened.WithSqlAsync(sql => sql.CreateVerifiedBraidTransitionContext(floor, op, exact), ct).ConfigureAwait(false);
                using var prior = await opened.WithSqlAsync(sql => sql.ReadVerifiedLatest(floor), ct).ConfigureAwait(false);
                using var prepared = prior.Use(bytes => send
                    ? ExactBraidRecoveryDurableTransactionProducer.PrepareSend(bytes, context, scope.Network, op)
                    : ExactBraidRecoveryDurableTransactionProducer.PrepareReceive(bytes, context, scope.Network, exact));
                prior.Dispose();
                var authority = new AccountBraidControlAuthority(async (plan, completion, token) =>
                {
                    held.RequireActive(); token.ThrowIfCancellationRequested();
                    var ownedPrior = plan.PriorTrs1.ToArray();
                    try
                    {
                        if (plan.Direction != (send ? ExactBraidRecoveryDurableDirection.Send : ExactBraidRecoveryDurableDirection.Receive) ||
                            !Did2MessagingSessionScope.Fixed(plan.OperationId.Span, op) ||
                            plan.PriorStateGeneration != floor.RatchetGeneration || plan.CheckpointPriorGeneration != floor.RatchetGeneration ||
                            plan.ExpectedJournalGeneration != floor.Ordinal || !Did2MessagingSessionScope.Fixed(plan.JournalPredecessor.Span, floor.Head) ||
                            !Did2MessagingSessionScope.Fixed(plan.PriorStateCommitment.Span, floor.RatchetCommitment) ||
                            !Did2MessagingSessionScope.Fixed(plan.CheckpointPriorCommitment.Span, floor.RatchetCommitment) ||
                            !Did2MessagingSessionScope.Fixed(SHA256.HashData(ownedPrior), floor.RatchetHash) ||
                            !Did2MessagingSessionScope.Fixed(plan.RetentionCommitment.Span, context.RetentionCommitment.Span) ||
                            !send && !Did2MessagingSessionScope.Fixed(plan.ExactControl.Span, exact) ||
                            plan.HasStateMutation != (context.ReceiveReplayDisposition == ExactDpe2ReceiveReplayDisposition.Fresh))
                            throw new CryptographicException("Braid sealed plan differs from its owned durable preparation.");
                    }
                    finally { CryptographicOperations.ZeroMemory(ownedPrior); }
                    var stable = await opened.Custody.ReconcileAsync(token).ConfigureAwait(false);
                    if (!Did2MessagingSessionScope.Fixed(stable.Exact.Span, floor.Exact.Span))
                        throw new CryptographicException("Braid predecessor changed under the held account lease.");
                    await RequireFinalMessagingFreshnessAsync(account, scope, own, peer, source, held, first, token).ConfigureAwait(false);
                    if (plan.HasStateMutation)
                    {
                        using var mutation = OwnedDid2MessagingMutation.BraidControl(scope, stable, plan);
                        stable = await opened.Custody.CommitOwnedAsync(mutation, token).ConfigureAwait(false);
                    }
                    using var retained = await opened.WithSqlAsync(sql => sql.ReadVerifiedBraidControl(stable, op), ct).ConfigureAwait(false) ??
                        throw new CryptographicException("Braid commit lost its exact retained row.");
                    if (retained.Direction != (send ? 3 : 4) || !Did2MessagingSessionScope.Fixed(retained.ExactControl, plan.ExactControl.Span))
                        throw new CryptographicException("Braid commit read-back differs from the sealed control.");
                    held.RequireActive();
                    return completion.Complete(plan.HasStateMutation
                        ? ExactDpe2DurableCommitDisposition.Committed : ExactDpe2DurableCommitDisposition.ExactReplay);
                });
                using var success = await prepared.CommitAsync(authority, ct).ConfigureAwait(false);
                var committed = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                result = await opened.WithSqlAsync(sql => sql.ReadVerifiedBraidControl(committed, op), ct).ConfigureAwait(false) ?? throw new CryptographicException("Braid stable read-back is absent.");
            }
            await RequireFinalMessagingFreshnessAsync(account, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var value = result; result = null; return value;
        }
        finally { maintainedStorage?.Dispose(); result?.Dispose(); CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(op); }
    }

    private async Task<OwnedDid2MessagingStorage?> PrepareNativeMaintenanceForBraidAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, OwnedDid2MessagingStorage opened,
        Did2MessagingFloor floor, HeldDeepIdV2AccountLease held, byte[] operation, byte[] exact, bool send,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, Deep.Protocol.DeepExtension.PrivacyRouting.OnionMonotonicReading first,
        CancellationToken ct)
    {
        if (opened.RecoveredLocalCompaction || string.Equals(recoveredNativePrefixScope, Convert.ToHexString(scope.Hash), StringComparison.Ordinal))
        {
            recoveredNativePrefixScope = null;
            return null;
        }
        var archive = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        if (floor.Ordinal < archive.Basis.Ordinal) throw new CryptographicException("Braid maintenance hint rolled back its native floor.");
        if (floor.Phase != 1 || floor.Status != 1 || floor.Ordinal - archive.Basis.Ordinal < NativeWorkingSoftLimit) return null;
        // Authenticate the fresh control before maintenance. This preparation
        // never commits and all preview state/outputs die before a provider.
        var preview = await opened.WithSqlAsync(sql =>
        {
            var state = sql.ReadFreshMaintenancePreviewState(floor, operation, out var context);
            return (State: state, Context: context);
        }, ct).ConfigureAwait(false);
        using (var state = preview.State)
        using (var prepared = state.Use(bytes => send
            ? ExactBraidRecoveryDurableTransactionProducer.PrepareSend(bytes, preview.Context, scope.Network, operation)
            : ExactBraidRecoveryDurableTransactionProducer.PrepareReceive(bytes, preview.Context, scope.Network, exact))) { }
        opened.Dispose();
        await MaintainNativePrefixUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        recoveredNativePrefixScope = null;
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        return await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
    }

    private sealed class AccountBraidControlAuthority(
        Func<ExactBraidRecoveryPersistencePlan, ExactBraidRecoveryCommitCompletion, CancellationToken,
            Task<ExactBraidRecoveryCommitReceipt>> commit) : IExactBraidRecoveryDurableTransactionAuthority
    {
        private int consumed;
        public ValueTask<ExactBraidRecoveryCommitReceipt> CommitAsync(ExactBraidRecoveryPersistencePlan plan,
            ExactBraidRecoveryCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidOperationException("Owned Braid authority is single-use.");
            return new(commit(plan, completion, cancellationToken));
        }
    }
}
