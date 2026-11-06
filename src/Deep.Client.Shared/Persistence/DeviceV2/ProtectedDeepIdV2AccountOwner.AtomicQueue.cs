using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<byte[]> CaptureAtomicSendReservationAsync(Did2MessagingSessionScope scope,
        byte[] ordinaryAfter, int additionalGroupTargets, CancellationToken ct)
    {
        using var owned = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Atomic queue reservation lost protected send custody.");
        var exact = owned.Use(bytes => bytes.ToArray());
        try
        {
            using var sends = ProtectedDid2MailboxSendJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
            using var ordinary = ProtectedDid2DirectTextJournal.Decode(ordinaryAfter, scope.Network, scope.LocalAccount, scope.Instance);
            var reserved = ordinary.Entries.Values.Count(entry => !entry.Stored && !entry.WorkStopped &&
                sends.Current(entry.Scope.Hash, entry.Operation) is null);
            RequireAtomicSendReservationCapacity(sends.Entries.Count, reserved, additionalGroupTargets);
            return exact;
        }
        catch { CryptographicOperations.ZeroMemory(exact); throw; }
    }

    internal static void RequireAtomicSendReservationCapacity(int attempts, int reserved, int additional)
    {
        if (attempts is < 0 or > ProtectedDid2MailboxSendJournal.MaximumEntries || reserved is < 0 or > ProtectedDid2DirectTextJournal.MaximumEntries ||
            additional is < 0 or > 99 || (long)attempts + reserved + additional > ProtectedDid2MailboxSendJournal.MaximumEntries)
            throw new IOException("The complete atomic queue exceeds available mailbox attempt custody.");
    }

    private static async Task RequireEarlierAtomicOrdinaryCommittedAsync(OwnedDid2MessagingStorage opened,
        ProtectedDid2DirectTextJournal.State journal, ulong sequence, CancellationToken ct)
    {
        var earlier = journal.Entries.Values.Where(entry => entry.Sequence < sequence && !entry.Stored && !entry.WorkStopped &&
            FixedRoute(entry.Scope.Exact, opened.Scope.Exact)).OrderBy(entry => entry.Sequence).ToArray();
        if (earlier.Length == 0) return;
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        foreach (var chunk in earlier.Chunk(Did2MessagingSqlJournal.MaximumOperationReadBatch))
        {
            var operations = chunk.Select(entry => (ReadOnlyMemory<byte>)entry.Operation.ToArray()).ToArray();
            try
            {
                var rows = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperations(floor, operations), ct).ConfigureAwait(false);
                try
                {
                    for (var index = 0; index < chunk.Length; index++)
                    {
                        var native = rows[index] ?? throw new InvalidOperationException("Resume the earlier original command before queueing a later native send.");
                        if (native.Direction != 1 || !FixedRoute(native.EventHash, chunk[index].EventHash))
                            throw new CryptographicException("Earlier queued original differs from its committed native send.");
                    }
                }
                finally { foreach (var row in rows) row?.Dispose(); }
            }
            finally { foreach (var operation in operations) CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsMemory(operation).Span); }
        }
    }

    // The linearization point is the protected inventory publication containing
    // BOTH the original command and the sealed native pending floor/parts. SQL
    // and stable cleanup are replayable projections of that one exact decision.
    private async Task CommitAtomicTextQueueUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        byte[] operation, ReadOnlyMemory<byte> exact, byte[] ordinaryBefore, byte[] ordinaryAfter, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        OnionMonotonicReading first, CancellationToken ct)
    {
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        var eventHash = SHA256.HashData(exact.Span); byte[] sendBefore = [];
        try
        {
            using var retained = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), ct).ConfigureAwait(false);
            if (retained is not null)
            {
                if (retained.Direction != 1 || !FixedRoute(retained.EventHash, eventHash))
                    throw new CryptographicException("Atomic queue retry changed its original native event.");
                return;
            }
            await RequireNewMailboxWorkCapacityUnderLeaseAsync(current, held, opened, scope, operation,
                own, peer, source, verifier, ct).ConfigureAwait(false);
            sendBefore = await CaptureAtomicSendReservationAsync(scope, ordinaryAfter, 0, ct).ConfigureAwait(false);
            await opened.WithSqlAsync(sql => sql.RequireAppendCapacity(floor), ct).ConfigureAwait(false);
            var transition = await opened.WithSqlAsync(sql =>
            {
                var state = sql.ReadVerifiedTransitionState(floor, operation, [], out var context);
                return (State: state, Context: context);
            }, ct).ConfigureAwait(false);
            using var state = transition.State;
            using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareSend(bytes,
                transition.Context, exact.Span, scope.Network, operation));
            state.Dispose();
            var authority = new AtomicTextQueueAuthority(this, current, held, opened, floor, operation,
                eventHash, ordinaryBefore, ordinaryAfter, sendBefore, own, peer, source, first);
            using var success = await prepared.CommitAsync(authority, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(eventHash); CryptographicOperations.ZeroMemory(sendBefore); }
    }

    private sealed class AtomicTextQueueAuthority(ProtectedDeepIdV2AccountOwner owner,
        VerifiedDeepIdV2CurrentAccount account, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, Did2MessagingFloor floor, byte[] operation, byte[] eventHash,
        byte[] ordinaryBefore, byte[] ordinaryAfter, byte[] sendBefore,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        OnionMonotonicReading first) : IExactDpe2DurableTransactionAuthority
    {
        private int consumed;
        public async ValueTask<ExactDpe2DurableCommitReceipt> CommitAsync(ExactDpe2DurablePersistencePlan plan,
            ExactDpe2DurableCommitCompletion completion, CancellationToken cancellationToken = default)
        {
            held.RequireActive(); cancellationToken.ThrowIfCancellationRequested();
            if (Interlocked.Exchange(ref consumed, 1) != 0) throw new InvalidOperationException("Atomic queue authority is single-use.");
            using var mutation = OwnedDid2MessagingMutation.Ratchet(opened.Scope, floor, plan, eventHash);
            if (mutation.Direction != 1 || !FixedRoute(mutation.Operation, operation))
                throw new CryptographicException("Atomic queue sealed another operation or direction.");
            await RequireFinalMessagingFreshnessAsync(account, opened.Scope, own, peer, source, held, first, cancellationToken).ConfigureAwait(false);
            await opened.Checkpoint.EraseStableOrphansAsync(floor, cancellationToken).ConfigureAwait(false);
            var writes = new List<DeepSecureStorageWrite> { new(ProtectedDid2DirectTextJournal.Slot, ordinaryAfter) };
            var guards = new Dictionary<string, byte[]>(StringComparer.Ordinal)
            { [ProtectedDid2DirectTextJournal.Slot] = ordinaryBefore, [ProtectedDid2MailboxSendJournal.Slot] = sendBefore };
            try
            {
                CaptureAtomicNativeStage(mutation, guards, writes);
                if (!await owner.storage.CompareExchangeBatchAsync(guards, writes, cancellationToken).ConfigureAwait(false))
                    throw new CryptographicException("Atomic local queue lost its exact original/session predecessor.");
#if DEEP_TEST_INTERNALS
                Did2AtomicQueueTestHooks.Hit(Did2AtomicQueueFailpoint.AfterProtectedCommit);
#endif
                var stable = await opened.Custody.ReconcileAsync(cancellationToken).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2AtomicQueueTestHooks.Hit(Did2AtomicQueueFailpoint.AfterNativeCommit);
#endif
                using var actual = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(stable, operation), cancellationToken).ConfigureAwait(false) ??
                    throw new CryptographicException("Atomic queue has no exact native readback.");
                if (actual.Direction != 1 || !FixedRoute(actual.ExactEnvelope, mutation.Envelope) || !FixedRoute(actual.EventHash, eventHash))
                    throw new CryptographicException("Atomic queue readback changed its exact envelope or command.");
                await owner.RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, ordinaryAfter, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested(); held.RequireActive();
                return completion.Complete(ExactDpe2DurableCommitDisposition.Committed);
            }
            finally
            {
                foreach (var write in writes.Skip(1))
                    if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(write.Value, out var bytes)) CryptographicOperations.ZeroMemory(bytes.AsSpan());
                foreach (var guard in guards.Where(pair => pair.Key != ProtectedDid2DirectTextJournal.Slot && pair.Key != ProtectedDid2MailboxSendJournal.Slot)) CryptographicOperations.ZeroMemory(guard.Value);
            }
        }
    }

    private static void CaptureAtomicNativeStage(OwnedDid2MessagingMutation mutation,
        Dictionary<string, byte[]> guards, List<DeepSecureStorageWrite> writes)
    {
        var scope = mutation.Scope;
        guards.Add(scope.FloorSlot, mutation.Predecessor.Exact.ToArray());
        writes.Add(new(scope.FloorSlot, mutation.Successor.Exact.ToArray()));
        for (var index = 0; index < mutation.Successor.PartCount; index++)
        {
            var offset = index * Did2MessagingFloor.PartBytes;
            writes.Add(new(scope.FloorSlot + ".pending." + index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                mutation.Exact.Slice(offset, Math.Min(Did2MessagingFloor.PartBytes, mutation.Exact.Length - offset)).ToArray()));
        }
    }

    // Local historical recovery requires no fresh route capability. It may
    // only project an already committed native send joined to its protected
    // original; it never prepares crypto, dispatches, or advances the counter.
    private async Task RecoverAtomicTextProjectionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingFloor floor, CancellationToken ct)
    {
        using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Atomic queue recovery lost its original command root.");
        using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, opened.Scope.Network, opened.Scope.LocalAccount, opened.Scope.Instance));
        var pending = journal.Pending;
        if (pending is null || pending.Kind != Dmc2ContentKind.MessageCreate || !FixedRoute(pending.Scope.Exact, opened.Scope.Exact)) return;
        var operation = pending.Operation.ToArray(); var exact = pending.PendingDmc2.ToArray();
        try
        {
            using var native = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), ct).ConfigureAwait(false);
            if (native is null) return; // A preexisting authored-only pending original remains retryable.
            if (native.Direction != 1 || !FixedRoute(native.EventHash, pending.EventHash))
                throw new CryptographicException("Atomic queue recovery changed its original command.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            using var row = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(opened.Scope.Exact[84..]), opened.Scope, operation, ct).ConfigureAwait(false);
            using var handoff = await AuthenticatedDirectDmc2.FromOwnedDid2CommitAsync(opened, floor, operation, exact, ct).ConfigureAwait(false);
            RequireApplicationDisposition(await application.MaterializeDirectDmc2Async(handoff, ct).ConfigureAwait(false));
        }
        finally { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(exact); }
    }
}
