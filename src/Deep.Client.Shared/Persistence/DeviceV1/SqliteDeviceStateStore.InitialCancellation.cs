using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Persistence.DeviceV1;

public sealed partial class SqliteDeviceStateStore
{
    internal async Task<ProtectedInitialKeyRetirementJournal.Entry> RetireCancelledInitialUnderLeaseAsync(string accountPath,
        ReadOnlyMemory<byte> intent, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease accountLease, CancellationToken ct)
    {
        var op = intent.ToArray();
        using var borrowed = held.BorrowFor(accountLease); using var operation = EnterOperation();
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
            var storage = RequireInitialSessionStorage(); var network = initialSessionNetwork!;
            var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, network, accountId.ToArray(), ct).ConfigureAwait(false);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, network, accountId.Span, instance));
            if (!drafts.Entries.TryGetValue(Convert.ToHexString(op), out var draft) || !draft.WorkStopped || draft.NativeStopMode != 2)
                throw new CryptographicException("Source cancellation requires the actual stopped pre-session intent.");
            var draftBinding = draft.CancellationBinding; byte[] hash = new byte[32], preclaimHash = [], rawEntry = new byte[ProtectedInitialKeyRetirementJournal.EntryBytes];
            try
            {
                using var tx = GetConnection().BeginTransaction(deferred: false);
                using var source = ReadInitialSessionByIntent(GetConnection(), tx, op);
                ulong ordinal = 0; var live = false;
                if (source is not null)
                {
                    if (!draft.PayloadRetired)
                    {
                        var conversation = source.RequireInitialConversation(draft.Init, draft.Hello);
                        try { if (!DeviceInitialSessionCheckpoint.Fixed(conversation, draft.Conversation)) throw new CryptographicException("Cancelled source changed its original events."); }
                        finally { CryptographicOperations.ZeroMemory(conversation); }
                    }
                    using var read = GetConnection().CreateCommand(); read.Transaction = tx;
                    read.CommandText = "SELECT sequence,record_hash FROM device_initial_sessions WHERE logical_intent_id=$intent;";
                    read.Parameters.AddWithValue("$intent", op); using var row = read.ExecuteReader();
                    if (!row.Read()) throw new CryptographicException("Cancelled initial source disappeared.");
                    ordinal = checked((ulong)row.GetInt64(0)); hash = row.GetFieldValue<byte[]>(1);
                    if (row.Read()) throw new CryptographicException("Cancelled source is not unique.");
                    SHA256.HashData(source.CanonicalSpan).CopyTo(rawEntry.AsSpan(108)); source.InitialStateHashSpan.CopyTo(rawEntry.AsSpan(140));
                    live = source.HasInitialState;
                }
                preclaimHash = await SqliteDeepIdV2AccountGeneration.ReadPreclaimCancellationHashUnderLeaseAsync(storage,
                    network, accountId.ToArray(), instance, op, draftBinding, source is not null, ct).ConfigureAwait(false);
                rawEntry[0] = 3; rawEntry[1] = 1; storeInstanceId.Span.CopyTo(rawEntry.AsSpan(4));
                BinaryPrimitives.WriteUInt64BigEndian(rawEntry.AsSpan(36), ordinal); hash.CopyTo(rawEntry, 44);
                draftBinding.CopyTo(rawEntry, 76); op.CopyTo(rawEntry, 172); preclaimHash.CopyTo(rawEntry, 204);
                var candidate = new ProtectedInitialKeyRetirementJournal.Entry(rawEntry);
                tx.Commit();
                await SqliteDeepIdV2AccountGeneration.RequireCancellationNativeAbsenceUnderLeaseAsync(storage, accountPath,
                    network, accountId.ToArray(), instance, candidate, held, accountLease, ct).ConfigureAwait(false);
                var pending = await ProtectedInitialKeyRetirementJournal.StageCancellationUnderLeaseAsync(storage,
                    network, accountId.ToArray(), instance, candidate, ct).ConfigureAwait(false);
                if (pending.Phase == 2)
                {
                    if (live) throw new CryptographicException("Stable cancellation retained resurrected source keys.");
                    await SqliteDeepIdV2AccountGeneration.CancelPreclaimUnderLeaseAsync(storage, network, accountId.ToArray(), instance, pending, ct).ConfigureAwait(false);
                    return pending;
                }
#if DEEP_TEST_INTERNALS
                InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPending);
#endif
                await SqliteDeepIdV2AccountGeneration.CancelPreclaimUnderLeaseAsync(storage, network, accountId.ToArray(), instance, pending, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPreclaim);
#endif
                if (pending.Phase != 2 && ordinal != 0)
                {
                    await SqliteDeepIdV2AccountGeneration.RequireCancellationNativeAbsenceUnderLeaseAsync(storage, accountPath,
                        network, accountId.ToArray(), instance, pending, held, accountLease, ct).ConfigureAwait(false);
                    using var deletionTx = GetConnection().BeginTransaction(deferred: false);
                    using var delete = GetConnection().CreateCommand(); delete.Transaction = deletionTx;
                    delete.CommandText = "DELETE FROM device_initial_state WHERE sequence=$sequence;"; delete.Parameters.AddWithValue("$sequence", checked((long)ordinal));
                    if (delete.ExecuteNonQuery() != (live ? 1 : 0)) throw new CryptographicException("Initial cancellation deleted another key source.");
                    ct.ThrowIfCancellationRequested(); held.RequireOwner(accountLease); deletionTx.Commit();
                }
#if DEEP_TEST_INTERNALS
                InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterSourceDelete);
#endif
                await ReconcileInitialSessionsUnderGateAsync(ct).ConfigureAwait(false);
                using (var readBackTx = GetConnection().BeginTransaction(deferred: false))
                using (var retired = ReadInitialSessionByIntent(GetConnection(), readBackTx, op))
                    if (retired?.HasInitialState == true) throw new CryptographicException("Cancelled source keys survived deletion.");
                await SqliteDeepIdV2AccountGeneration.RequireCancellationNativeAbsenceUnderLeaseAsync(storage, accountPath,
                    network, accountId.ToArray(), instance, pending, held, accountLease, ct).ConfigureAwait(false);
                await ProtectedInitialKeyRetirementJournal.CompleteCancellationUnderLeaseAsync(storage, network,
                    accountId.ToArray(), instance, pending, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterStable);
#endif
                return pending.Stable();
            }
            finally { foreach (var bytes in new[] { draftBinding, hash, preclaimHash, rawEntry }) CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { gate.Release(); CryptographicOperations.ZeroMemory(op); }
    }
}
