using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.PreKeyV2;

internal sealed partial class SqlitePreKeyV2InventoryStore
{
    private const string CreateReceiverSessions = "CREATE TABLE receiver_sessions(ordinal INTEGER PRIMARY KEY CHECK(ordinal BETWEEN 1 AND 128),previous_hash BLOB NOT NULL CHECK(length(previous_hash)=32),record_hash BLOB NOT NULL CHECK(length(record_hash)=32),exact_record BLOB NOT NULL CHECK(length(exact_record) BETWEEN 168 AND 132716))";
    private const string CreateReceiverState = "CREATE TABLE receiver_initial_state(ordinal INTEGER PRIMARY KEY REFERENCES receiver_sessions(ordinal),exact_state BLOB NOT NULL CHECK(length(exact_state) BETWEEN 1 AND 131072))";
    private IDeepSecureStorage? receiverStorage;
    private byte[]? receiverInstance;
    private ProtectedInitialKeyRetirementJournal.State? receiverRetirements;
    private sealed record Entry(ulong Sequence, byte[] Previous, byte[] Hash, DeepIdV2InitialContactSessionCommit Commit);
    private sealed class Ledger : IDisposable
    {
        internal List<Entry> Entries { get; } = [];
        internal ulong Sequence => checked((ulong)Entries.Count);
        internal byte[] Hash => Entries.Count == 0 ? new byte[32] : Entries[^1].Hash;
        public void Dispose() { foreach (var entry in Entries) entry.Commit.Dispose(); }
    }

    // The process-independent account lease is held by every caller.
    internal async ValueTask ReconcileReceiverSessionsAsync(IDeepSecureStorage storage, ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        if (instance.Length != 32 || instance.Span.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact receiver instance is required.");
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (receiverStorage is not null && (!ReferenceEquals(receiverStorage, storage) || !Fixed(receiverInstance!, instance.Span)))
                throw new CryptographicException("Receiver custody cannot change owner.");
            receiverStorage = storage; receiverInstance = instance.ToArray();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            ValidateStagedRows(restoreSecrets: true);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<DeepIdV2InitialContactSessionCommit?> FindExactReceiverSessionAsync(Dph2Record incoming, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); RequireReceiverStorage();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            using var ledger = ReadReceiverLedger();
            return RequireExactReplayOrAvailable(ledger, incoming, null);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask CommitReceiverSessionAsync(DeepIdV2InitialContactSessionCommit completed, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var storage = RequireReceiverStorage();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            using var ledger = ReadReceiverLedger();
            using var prior = RequireExactReplayOrAvailable(ledger, completed.Record, completed.ExactClaimReplayHashSpan.ToArray());
            if (prior is not null) return;
            RequireReceiverScope(completed);
            using var owned = await storage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("The protected receiver checkpoint disappeared.");
            var previous = owned.Use(static value => value.ToArray());
            byte[]? pending = null;
            try
            {
                using var stable = ResponderInitialSessionCheckpoint.Decode(previous, receiverInstance!, account, network);
                if (stable.Phase != 1 || stable.Sequence != ledger.Sequence || !Fixed(stable.Hash, ledger.Hash))
                    throw new CryptographicException("Receiver custody is not at its exact stable predecessor.");
                var body = completed.SerializePending();
                try { pending = ResponderInitialSessionCheckpoint.Pending(receiverInstance!, account, network, stable, body); }
                finally { CryptographicOperations.ZeroMemory(body); }
                ct.ThrowIfCancellationRequested();
                if (!await storage.CompareExchangeAsync(ResponderInitialSessionCheckpoint.Slot, previous, pending, ct).ConfigureAwait(false))
                    throw new CryptographicException("Receiver pending checkpoint lost its exact predecessor.");
                ResponderInitialSessionTestHooks.Hit(ResponderInitialSessionFailpoint.AfterPending);
                using var retained = ResponderInitialSessionCheckpoint.Decode(pending, receiverInstance!, account, network);
                AppendReceiverTransaction(retained, completed);
                ResponderInitialSessionTestHooks.Hit(ResponderInitialSessionFailpoint.AfterSqlCommit);
                await StabilizeReceiverAsync(pending, retained, CancellationToken.None).ConfigureAwait(false);
                ResponderInitialSessionTestHooks.Hit(ResponderInitialSessionFailpoint.AfterStable);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previous);
                if (pending is not null) CryptographicOperations.ZeroMemory(pending);
            }
        }
        finally { gate.Release(); }
    }

    internal async Task VerifyMessagingSourceUnderLeaseAsync(Did2MessagingSessionScope scope, bool requireRetired, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); RequireReceiverStorage();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            using var ledger = ReadReceiverLedger();
            var session = scope.Session.ToArray();
            var source = ledger.Entries.SingleOrDefault(value => Fixed(value.Commit.SessionId.Span, session)) ??
                throw new CryptographicException("Mutable receiver source history is absent.");
            Did2MessagingSourceScope.RequireReceiver(scope, source.Commit);
            var entry = receiverRetirements!.Find(2, receiverInstance!, source.Sequence);
            Did2MessagingSourceScope.RequireRetirement(entry, scope, requireRetired, source.Commit.HasInitialState);
        }
        finally { gate.Release(); }
    }

    internal async Task<Did2InitialKeyRetirementReceipt> RetireInitialKeysUnderLeaseAsync(Did2InitialStateTransfer transfer, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); var storage = RequireReceiverStorage();
            await ReconcileReceiverUnderGateAsync(ct).ConfigureAwait(false);
            using var ledger = ReadReceiverLedger();
            var operation = transfer.Operation.ToArray();
            var source = ledger.Entries.SingleOrDefault(value => Fixed(value.Commit.Record.ClaimOperationId.Span, operation)) ??
                throw new CryptographicException("Mutable transfer has no authenticated receiver source.");
            transfer.RequireReceiver(source.Commit);
            var entry = await ProtectedInitialKeyRetirementJournal.StageUnderLeaseAsync(storage, transfer, receiverInstance!,
                source.Sequence, source.Hash, operation, new byte[32], ct).ConfigureAwait(false);
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterPending);
            if (entry.Phase != 2)
            {
                using var tx = connection.BeginTransaction(deferred: false);
                using var deletion = connection.CreateCommand(); deletion.Transaction = tx;
                deletion.CommandText = "DELETE FROM receiver_initial_state WHERE ordinal=$ordinal;";
                deletion.Parameters.AddWithValue("$ordinal", checked((long)source.Sequence));
                if (deletion.ExecuteNonQuery() != (source.Commit.HasInitialState ? 1 : 0))
                    throw new CryptographicException("Receiver deletion affected a different initial state.");
                tx.Commit();
            }
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterSourceDelete);
            await ReconcileReceiverUnderGateAsync(CancellationToken.None).ConfigureAwait(false);
            using var verified = ReadReceiverLedger();
            if (verified.Entries[checked((int)source.Sequence - 1)].Commit.HasInitialState)
                throw new CryptographicException("Receiver initial keys survived retirement.");
            await ProtectedInitialKeyRetirementJournal.CompleteUnderLeaseAsync(storage, transfer, entry, CancellationToken.None).ConfigureAwait(false);
            InitialKeyRetirementTestHooks.Hit(InitialKeyRetirementFailpoint.AfterStable);
            return await Did2InitialKeyRetirementReceipt.VerifyStableAsync(transfer, storage, entry, CancellationToken.None).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    private async ValueTask ReconcileReceiverUnderGateAsync(CancellationToken ct)
    {
        var storage = RequireReceiverStorage();
        receiverRetirements = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, network, account, ct).ConfigureAwait(false);
        var actualInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, network, account, ct).ConfigureAwait(false);
        if (!Fixed(receiverInstance!, actualInstance)) throw new CryptographicException("Receiver instance differs from its account key owner.");
        using var owned = await storage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("The protected receiver checkpoint is missing.");
        var exact = owned.Use(static value => value.ToArray());
        try
        {
            using var checkpoint = ResponderInitialSessionCheckpoint.Decode(exact, receiverInstance!, account, network);
            using var ledger = ReadReceiverLedger();
            if (checkpoint.Phase == 1)
            {
                if (checkpoint.Sequence != ledger.Sequence || !Fixed(checkpoint.Hash, ledger.Hash))
                    throw new CryptographicException("Stable receiver history is missing, rolled back or substituted.");
                return;
            }
            using var completed = DeepIdV2InitialContactSessionCommit.RestorePending(checkpoint.Payload);
            RequireReceiverScope(completed);
            if (ledger.Sequence + 1 == checkpoint.Sequence && Fixed(ledger.Hash, checkpoint.Previous))
                AppendReceiverTransaction(checkpoint, completed);
            else if (ledger.Sequence != checkpoint.Sequence || !Fixed(ledger.Hash, checkpoint.Hash) ||
                !Fixed(ledger.Entries[^1].Commit.CanonicalSpan, completed.CanonicalSpan))
                throw new CryptographicException("Pending receiver record has no exact recoverable predecessor or committed successor.");
            // A durable pending record is authoritative; finish regardless of advisory cancellation.
            await StabilizeReceiverAsync(exact, checkpoint, CancellationToken.None).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private void AppendReceiverTransaction(ResponderInitialSessionCheckpoint.State checkpoint, DeepIdV2InitialContactSessionCommit completed)
    {
        using var transaction = connection.BeginTransaction(deferred: false);
        using var ledger = ReadReceiverLedger(transaction);
        if (ledger.Sequence + 1 != checkpoint.Sequence || !Fixed(ledger.Hash, checkpoint.Previous))
            throw new CryptographicException("Receiver SQL transaction has a different predecessor.");
        using var replay = RequireExactReplayOrAvailable(ledger, completed.Record, completed.ExactClaimReplayHashSpan.ToArray());
        if (replay is not null) throw new CryptographicException("Receiver append cannot replace an existing exact replay.");
        RequireReceiverScope(completed);
        ushort selectedReuseLimit;
        using (var selected = connection.CreateCommand())
        {
            selected.Transaction = transaction;
            selected.CommandText = "SELECT exact_dpk2 FROM secrets WHERE exact_dpk2_hash=$hash;";
            Add(selected, "$hash", completed.Record.ExactDpk2Hash.ToArray());
            if (selected.ExecuteScalar() is not byte[] retained)
                throw new CryptographicException("Receiver completion has no retained selected private prekey.");
            var selectedMember = DeepIdV2Dpk2Codec.Decode(retained);
            if (!Fixed(selectedMember.ExactHash.Span, completed.Record.ExactDpk2Hash.Span) || selectedMember.Kind != completed.Kind ||
                completed.Counter > selectedMember.ReuseLimit)
                throw new CryptographicException("Receiver completion differs from the selected signed prekey limit.");
            selectedReuseLimit = selectedMember.ReuseLimit;
            // Store open has already validated the exact signed public inventory.
        }
        var sameKeyUses = ledger.Entries.Count(entry => Fixed(entry.Commit.Record.ExactDpk2Hash.Span, completed.Record.ExactDpk2Hash.Span));
        var deleteSecret = IsReceiverPreKeyExhausted(completed.Kind, selectedReuseLimit, sameKeyUses + 1);
        var exactRecord = completed.CanonicalSpan.ToArray();
        var exactState = completed.ExactTrsSpan.ToArray();
        try
        {
            using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO receiver_sessions VALUES($ordinal,$previous,$hash,$record);";
            insert.Parameters.AddWithValue("$ordinal", checked((long)checkpoint.Sequence));
            Add(insert, "$previous", checkpoint.Previous); Add(insert, "$hash", checkpoint.Hash);
            Add(insert, "$record", exactRecord); insert.ExecuteNonQuery();
            insert.Parameters.Clear();
            insert.CommandText = "INSERT INTO receiver_initial_state VALUES($ordinal,$state);";
            insert.Parameters.AddWithValue("$ordinal", checked((long)checkpoint.Sequence));
            Add(insert, "$state", exactState); insert.ExecuteNonQuery();
        }
        finally { CryptographicOperations.ZeroMemory(exactRecord); CryptographicOperations.ZeroMemory(exactState); }
        if (deleteSecret)
        {
            using var deletion = connection.CreateCommand(); deletion.Transaction = transaction;
            deletion.CommandText = "DELETE FROM secrets WHERE exact_dpk2_hash=$hash;";
            Add(deletion, "$hash", completed.Record.ExactDpk2Hash.ToArray());
            if (deletion.ExecuteNonQuery() != 1) throw new CryptographicException("Receiver prekey deletion did not consume exactly one secret.");
        }
        transaction.Commit();
    }

    private async ValueTask StabilizeReceiverAsync(byte[] pending, ResponderInitialSessionCheckpoint.State checkpoint, CancellationToken ct)
    {
        using var ledger = ReadReceiverLedger();
        if (ledger.Sequence != checkpoint.Sequence || !Fixed(ledger.Hash, checkpoint.Hash))
            throw new CryptographicException("Receiver cannot stabilize a different SQL history.");
        var stable = ResponderInitialSessionCheckpoint.Stable(receiverInstance!, account, network, checkpoint.Sequence, checkpoint.Hash);
        try
        {
            if (!await RequireReceiverStorage().CompareExchangeAsync(ResponderInitialSessionCheckpoint.Slot, pending, stable, ct).ConfigureAwait(false))
                throw new CryptographicException("Receiver stable checkpoint lost its exact pending predecessor.");
        }
        finally { CryptographicOperations.ZeroMemory(stable); }
    }

    private Ledger ReadReceiverLedger(SqliteTransaction? transaction = null)
    {
        var result = new Ledger();
        try
        {
            using (var integrity = connection.CreateCommand())
            {
                integrity.Transaction = transaction; integrity.CommandText = "PRAGMA foreign_key_check;";
                using var rows = integrity.ExecuteReader();
                if (rows.Read()) throw new CryptographicException("Receiver history contains orphaned source state.");
            }
            using var read = connection.CreateCommand(); read.Transaction = transaction;
            read.CommandText = "SELECT s.ordinal,s.previous_hash,s.record_hash,length(s.exact_record),s.exact_record,length(k.exact_state),k.exact_state FROM receiver_sessions s LEFT JOIN receiver_initial_state k ON k.ordinal=s.ordinal ORDER BY s.ordinal;";
            using var reader = read.ExecuteReader();
            while (reader.Read())
            {
                var sequence = reader.GetInt64(0); var length = reader.GetInt64(3);
                if (result.Entries.Count >= ResponderInitialSessionCheckpoint.MaximumSessions || sequence != result.Entries.Count + 1 ||
                    length < DeepIdV2InitialContactSessionCommit.HeaderBytes || length > DeepIdV2InitialContactSessionCommit.MaximumPayloadBytes)
                    throw new InvalidDataException("Receiver session ledger is not contiguous or bounded.");
                var previous = reader.GetFieldValue<byte[]>(1); var hash = reader.GetFieldValue<byte[]>(2);
                var payload = reader.GetFieldValue<byte[]>(4);
                byte[] state = [];
                DeepIdV2InitialContactSessionCommit? commit = null;
                try
                {
                    if (previous.Length != 32 || hash.Length != 32 || hash.AsSpan().IndexOfAnyExcept((byte)0) < 0 || !Fixed(previous, result.Hash))
                        throw new CryptographicException("Receiver session ledger has a different predecessor.");
                    if (receiverInstance is not null && !Fixed(hash, ResponderInitialSessionCheckpoint.RecordHash(receiverInstance,
                        account, network, checked((ulong)sequence), previous, payload)))
                        throw new CryptographicException("Receiver session ledger hash differs.");
                    // Preliminary schema/inventory validation never opens TRS.
                    // Attached account custody independently verifies protected history first.
                    if (receiverInstance is not null && !reader.IsDBNull(5))
                    {
                        if (reader.GetInt64(5) is < 1 or > DeepIdV2InitialContactSessionCommit.MaximumTrsBytes)
                            throw new InvalidDataException("Receiver initial state exceeds its closed bound.");
                        state = reader.GetFieldValue<byte[]>(6);
                    }
                    commit = DeepIdV2InitialContactSessionCommit.RestoreCustody(payload, state); RequireReceiverScope(commit);
                    if (receiverInstance is not null)
                        (receiverRetirements ?? throw new InvalidOperationException("Receiver retirement journal was not verified.")).RequireSource(
                            2, receiverInstance, checked((ulong)sequence), hash, payload, commit.InitialStateHashSpan,
                            commit.Record.ClaimOperationId.Span, commit.HasInitialState);
                    using var replay = RequireExactReplayOrAvailable(result, commit.Record, commit.ExactClaimReplayHashSpan.ToArray());
                    if (replay is not null) throw new CryptographicException("Receiver ledger contains a duplicate session.");
                    result.Entries.Add(new(checked((ulong)sequence), previous, hash, commit)); commit = null;
                }
                finally { commit?.Dispose(); CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(state); }
            }
            if (receiverInstance is not null) receiverRetirements!.RequireSourceTip(2, receiverInstance, result.Sequence);
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    private DeepIdV2InitialContactSessionCommit? RequireExactReplayOrAvailable(Ledger ledger, Dph2Record incoming, byte[]? claimReplay)
    {
        var incomingExact = Dph2Codec.Encode(incoming);
        foreach (var entry in ledger.Entries)
        {
            var prior = entry.Commit; var record = prior.Record;
            if (Fixed(record.ClaimOperationId.Span, incoming.ClaimOperationId.Span) || Fixed(record.SessionId.Span, incoming.SessionId.Span))
            {
                if (!Fixed(Dph2Codec.Encode(record), incomingExact) || claimReplay is not null && !Fixed(prior.ExactClaimReplayHashSpan, claimReplay))
                    throw new CryptographicException("Receiver operation/session conflicts with its exact retained replay.");
                return DeepIdV2InitialContactSessionCommit.RestoreCustody(prior.CanonicalSpan,
                    prior.HasInitialState ? prior.ExactTrsSpan : default);
            }
            if (incoming.SelectedPrekey.Kind == Dpk2PrekeyKind.OneTime &&
                (Fixed(prior.OneTimeKeyIdSpan, incoming.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.Span) ||
                 Fixed(prior.MlKemKeyIdSpan, incoming.SelectedPrekey.MlKemPrekeyId.Span)) ||
                incoming.SelectedPrekey.Kind == Dpk2PrekeyKind.LastResort &&
                Fixed(prior.MlKemKeyIdSpan, incoming.SelectedPrekey.MlKemPrekeyId.Span) &&
                (prior.Kind != Dpk2PrekeyKind.LastResort || prior.Counter == incoming.LastResortUseCounter))
                throw new CryptographicException("Receiver prekey or last-resort counter was already consumed by a different session.");
        }
        if (ledger.Entries.Count >= ResponderInitialSessionCheckpoint.MaximumSessions) throw new IOException("Initial receiver session capacity is exhausted.");
        return null;
    }

    private void RequireReceiverScope(DeepIdV2InitialContactSessionCommit commit)
    {
        if (!Fixed(commit.Record.NetworkId.Span, network) || !Fixed(commit.Record.ResponderAccountId.Span, account) ||
            !Fixed(commit.Record.ResponderDeviceId.Span, device) || commit.Record.ResponderDeviceGeneration != deviceGeneration ||
            commit.Directory.AccountGeneration != accountGeneration)
            throw new CryptographicException("Receiver custody differs from its local inventory owner.");
    }

    private void RequireInventorySessionBinding(Ledger ledger, ParsedXpp1V2 publication)
    {
        foreach (var entry in ledger.Entries)
        {
            var commit = entry.Commit;
            var member = publication.OneTimeMembers.Append(publication.LastResortMember).SingleOrDefault(candidate =>
                Fixed(candidate.ExactHash.Span, commit.Record.ExactDpk2Hash.Span));
            if (member is null || member.Kind != commit.Kind || !Fixed(member.MlKemPrekeyId.Span, commit.MlKemKeyIdSpan) ||
                commit.Kind == Dpk2PrekeyKind.LastResort && commit.Counter > member.ReuseLimit ||
                member.Kind == Dpk2PrekeyKind.OneTime && !Fixed(member.OneTimePrekeyId.Span, commit.OneTimeKeyIdSpan) ||
                !Fixed(member.SignedX25519PrekeyId.Span, commit.Record.SelectedPrekey.SignedX25519PrekeyId.Span) ||
                !Fixed(member.DeviceDirectoryHeadHash.Span, commit.Directory.RecordHash.Span) ||
                !Fixed(member.ResponderDpd1Reference.Span, dpd1))
                throw new CryptographicException("Receiver ledger is outside its exact signed inventory selection.");
        }
    }
    internal static bool IsReceiverPreKeyExhausted(Dpk2PrekeyKind kind, ushort signedReuseLimit, int completedUses)
    {
        var maximum = kind switch
        {
            Dpk2PrekeyKind.OneTime when signedReuseLimit == 0 => 1,
            Dpk2PrekeyKind.LastResort when signedReuseLimit is >= 1 and <= 64 => signedReuseLimit,
            _ => throw new CryptographicException("Unknown receiver prekey kind or signed reuse limit.")
        };
        if (completedUses < 0 || completedUses > maximum)
            throw new CryptographicException("Receiver prekey consumption exceeds its signed limit.");
        return completedUses == maximum;
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => DeepIdV2InitialContactSessionCommit.Fixed(left, right);
    private IDeepSecureStorage RequireReceiverStorage() => receiverStorage ?? throw new InvalidOperationException("Protected receiver custody has not been reconciled.");
}

internal enum ResponderInitialSessionFailpoint { AfterPending, AfterSqlCommit, AfterStable }
internal static class ResponderInitialSessionTestHooks
{
    private static readonly AsyncLocal<Action<ResponderInitialSessionFailpoint>?> Current = new();
    internal static IDisposable Push(Action<ResponderInitialSessionFailpoint> action)
    {
        var previous = Current.Value; Current.Value = action; return new Reset(previous);
    }
    internal static void Hit(ResponderInitialSessionFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<ResponderInitialSessionFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
