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
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(
                storage, sqlStatePath, account, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (send)
            {
                result = opened.Sql.ReadVerifiedBraidControl(floor, op);
                if (result is not null && result.Direction != 3)
                    throw new CryptographicException("Braid send operation belongs to another direction.");
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
                var context = opened.Sql.CreateVerifiedBraidTransitionContext(floor, op, exact);
                using var prior = opened.Sql.ReadVerifiedLatest(floor);
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
                    using var retained = opened.Sql.ReadVerifiedBraidControl(stable, op) ??
                        throw new CryptographicException("Braid commit lost its exact retained row.");
                    if (retained.Direction != (send ? 3 : 4) || !Did2MessagingSessionScope.Fixed(retained.ExactControl, plan.ExactControl.Span))
                        throw new CryptographicException("Braid commit read-back differs from the sealed control.");
                    held.RequireActive();
                    return completion.Complete(plan.HasStateMutation
                        ? ExactDpe2DurableCommitDisposition.Committed : ExactDpe2DurableCommitDisposition.ExactReplay);
                });
                using var success = await prepared.CommitAsync(authority, ct).ConfigureAwait(false);
                var committed = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                result = opened.Sql.ReadVerifiedBraidControl(committed, op) ?? throw new CryptographicException("Braid stable read-back is absent.");
            }
            await RequireFinalMessagingFreshnessAsync(account, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            var value = result; result = null; return value;
        }
        finally { result?.Dispose(); CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(op); }
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
