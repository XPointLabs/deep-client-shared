using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class AtomicGroupQueueSessions : IDisposable
    {
        internal Dictionary<string, OwnedDid2MessagingStorage> Items { get; } = new(StringComparer.Ordinal);
        public void Dispose() { foreach (var opened in Items.Values) opened.Dispose(); }
    }
    private sealed record AtomicGroupPrepared(ProtectedDid2GroupJournal.Outgoing Item, GroupTarget Target,
        OwnedDid2MessagingStorage Opened, Did2MessagingFloor Floor, int Index, ExactDpe2PreparedSend Prepared);

    private async Task CommitAtomicGroupQueueUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, GroupRoot root, GroupTarget[] targets, AtomicGroupQueueSessions sessions,
        ProtectedDid2GroupJournal.Outgoing[] outgoing, byte[] ordinaryBefore, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource source, IReadOnlyList<OnionMonotonicReading> readings, CancellationToken ct)
    {
        if (outgoing.Length != targets.Length || outgoing.Select(item => Convert.ToHexString(item.Scope)).Distinct(StringComparer.Ordinal).Count() != targets.Length)
            throw new CryptographicException("Atomic text fanout requires exactly one original per target session.");
        root.State.Revision = checked(root.State.Revision + 1);
        var groupAfter = ProtectedDid2GroupJournal.Encode(root.State, networkId, current.AccountId.Span, root.Instance);
        AtomicGroupQueueBarrier? barrier = null;
        byte[] sendBefore = [];
        var preparations = new List<AtomicGroupPrepared>();
        try
        {
            // Accountwide maintenance and target admission are ordered under
            // the one held account lease. Only sealed commit barriers overlap.
            foreach (var item in outgoing)
            {
                var index = Array.FindIndex(targets, target => FixedRoute(target.Scope.Exact, item.Scope));
                if (index < 0) throw new CryptographicException("Atomic fanout changed its exact target.");
                var target = targets[index]; var opened = sessions.Items[Convert.ToHexString(item.Scope)];
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                await RequireGroupAdmissionUnderLeaseAsync(current, held, opened, target.Scope,
                    ApplicationCoreCodec.DecodeDmc2(item.Event), true, target.Own, target.Peer, source, ct, root).ConfigureAwait(false);
                await RequireNewMailboxWorkCapacityUnderLeaseAsync(current, held, opened, target.Scope, item.Operation,
                    target.Own, target.Peer, source, verifier, ct).ConfigureAwait(false);
                await opened.WithSqlAsync(sql => sql.RequireAppendCapacity(floor), ct).ConfigureAwait(false);
                await opened.Checkpoint.EraseStableOrphansAsync(floor, ct).ConfigureAwait(false);
                var transition = await opened.WithSqlAsync(sql =>
                {
                    var state = sql.ReadVerifiedTransitionState(floor, item.Operation, [], out var context);
                    return (State: state, Context: context);
                }, ct).ConfigureAwait(false);
                using var state = transition.State;
                var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareSend(bytes,
                    transition.Context, item.Event, target.Scope.Network, item.Operation));
                state.Dispose();
                preparations.Add(new(item, target, opened, floor, index, prepared));
            }
            sendBefore = await CaptureAtomicSendReservationAsync(targets[0].Scope, ordinaryBefore, outgoing.Length, ct).ConfigureAwait(false);
            barrier = new AtomicGroupQueueBarrier(this, held, root.Exact, groupAfter, ordinaryBefore, sendBefore, targets.Length, async token =>
            {
                for (var index = 0; index < targets.Length; index++)
                    await RequireFinalMessagingFreshnessAsync(current, targets[index].Scope, targets[index].Own,
                        targets[index].Peer, source, held, readings[index], token).ConfigureAwait(false);
            });
            await Task.WhenAll(preparations.Select(CommitTargetAsync)).ConfigureAwait(false);
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2GroupJournal.Slot, groupAfter, ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(root.Exact); root.Exact = groupAfter; groupAfter = [];
        }
        finally { foreach (var preparation in preparations) preparation.Prepared.Dispose(); CryptographicOperations.ZeroMemory(groupAfter); CryptographicOperations.ZeroMemory(sendBefore); }

        async Task CommitTargetAsync(AtomicGroupPrepared prepared)
        {
            try
            {
                var authority = new AtomicGroupQueueAuthority(current, held, prepared.Opened, prepared.Floor, prepared.Item,
                    prepared.Target, source, readings[prepared.Index], barrier!);
                using var success = await prepared.Prepared.CommitAsync(authority, ct).ConfigureAwait(false);
            }
            catch (Exception error) { barrier!.Fail(error); throw; }
        }
    }

    // Each Protocol authority waits until the complete bounded target set has
    // supplied a sealed transition. No completion receipt precedes publication.
    private sealed class AtomicGroupQueueBarrier(ProtectedDeepIdV2AccountOwner owner, HeldDeepIdV2AccountLease held,
        byte[] before, byte[] after, byte[] ordinary, byte[] sends, int count, Func<CancellationToken, Task> recheck)
    {
        private readonly object gate = new();
        private readonly List<OwnedDid2MessagingMutation> mutations = [];
        private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Fail(Exception error) => completion.TrySetException(error);
        internal async Task JoinAsync(OwnedDid2MessagingMutation mutation, CancellationToken ct)
        {
            bool publish;
            lock (gate) { mutations.Add(mutation); publish = mutations.Count == count && !completion.Task.IsCompleted; }
            if (publish)
            {
                var guards = new Dictionary<string, byte[]>(StringComparer.Ordinal)
                { [ProtectedDid2GroupJournal.Slot] = before, [ProtectedDid2DirectTextJournal.Slot] = ordinary,
                    [ProtectedDid2MailboxSendJournal.Slot] = sends };
                var writes = new List<DeepSecureStorageWrite> { new(ProtectedDid2GroupJournal.Slot, after) };
                try
                {
                    foreach (var item in mutations) CaptureAtomicNativeStage(item, guards, writes);
                    await recheck(ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested(); held.RequireActive();
                    if (!await owner.storage.CompareExchangeBatchAsync(guards, writes, ct).ConfigureAwait(false))
                        throw new CryptographicException("Atomic fanout lost an original or session predecessor.");
#if DEEP_TEST_INTERNALS
                    Did2AtomicQueueTestHooks.Hit(Did2AtomicQueueFailpoint.AfterProtectedCommit);
#endif
                    completion.TrySetResult();
                }
                catch (Exception error) { Fail(error); }
                finally
                {
                    foreach (var write in writes.Skip(1))
                        if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(write.Value, out var bytes)) CryptographicOperations.ZeroMemory(bytes.AsSpan());
                    foreach (var guard in guards.Where(pair => pair.Key != ProtectedDid2GroupJournal.Slot && pair.Key != ProtectedDid2DirectTextJournal.Slot &&
                        pair.Key != ProtectedDid2MailboxSendJournal.Slot)) CryptographicOperations.ZeroMemory(guard.Value);
                }
            }
            await completion.Task.WaitAsync(ct).ConfigureAwait(false);
        }
    }

    private sealed class AtomicGroupQueueAuthority(VerifiedDeepIdV2CurrentAccount account,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened,
        Did2MessagingFloor floor, ProtectedDid2GroupJournal.Outgoing item, GroupTarget target,
        DeepIdV2ContactPathAuthoritySource source, OnionMonotonicReading first, AtomicGroupQueueBarrier barrier)
        : IExactDpe2DurableTransactionAuthority
    {
        private int consumed;
        public async ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidOperationException("Atomic fanout authority is single-use.");
            using var mutation = OwnedDid2MessagingMutation.Ratchet(target.Scope, floor, plan, SHA256.HashData(item.Event));
            if (mutation.Direction != 1 || !FixedRoute(mutation.Operation, item.Operation))
                throw new CryptographicException("Atomic fanout sealed another operation.");
            await RequireFinalMessagingFreshnessAsync(account, target.Scope, target.Own, target.Peer, source, held, first, cancellationToken).ConfigureAwait(false);
            await barrier.JoinAsync(mutation, cancellationToken).ConfigureAwait(false);
            var stable = await opened.Custody.ReconcileAsync(cancellationToken).ConfigureAwait(false);
            using var retained = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(stable, item.Operation), cancellationToken).ConfigureAwait(false) ??
                throw new CryptographicException("Atomic fanout has no exact native readback.");
            if (retained.Direction != 1 || !FixedRoute(retained.EventHash, SHA256.HashData(item.Event)) || !FixedRoute(retained.ExactEnvelope, mutation.Envelope))
                throw new CryptographicException("Atomic fanout changed its exact original envelope.");
            await RequireFinalMessagingFreshnessAsync(account, target.Scope, target.Own, target.Peer, source, held, first, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested(); held.RequireActive();
            return completion.Complete(ExactDpe2DurableCommitDisposition.Committed);
        }
    }
}
