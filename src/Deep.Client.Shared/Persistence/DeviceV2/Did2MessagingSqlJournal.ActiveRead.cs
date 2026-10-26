using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    // Threshold-only cryptographic validation before maintenance. The returned
    // state/preparation is disposed before any await and is NEVER committed.
    // Capacity is still enforced by the normal post-maintenance context and
    // every durable append; checking it here would deadlock a full old suffix.
    internal OwnedDeepSecret ReadFreshMaintenancePreviewState(Did2MessagingFloor stable,
        ReadOnlySpan<byte> operation, out Deep.Protocol.MessagingCrypto.ExactDpe2DurableTransitionContext context)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation);
        if (stable.Phase != 1 || stable.Status != 1) throw new InvalidDataException("Maintenance preview requires active stable custody.");
        using var tx = connection.BeginTransaction(deferred: true);
        using var selection = new ActiveSelection([operation.ToArray()]);
        RequireSame(stable, VerifyActiveTip(tx, selection, out var headers));
        if (selection[0] is not null) throw new CryptographicException("An original operation cannot trigger fresh maintenance.");
        context = CreateVerifiedContextFromSnapshot(stable, Deep.Protocol.MessagingCrypto.ExactDpe2ReceiveReplayDisposition.Fresh,
            headers, maintenancePreview: true);
        return ReadLatestStateInSnapshot(tx, stable);
    }

    // Algorithm selection belongs to the constructing runtime owner, after its
    // cold audit. It is not proof/currentness: every invocation performs all
    // actual page, complete-map, working-state and independently rooted checks.
    private Did2MessagingFloor VerifyOrdinaryTip(SqliteTransaction? tx = null)
    {
        if (!activeHistory) return VerifyTipInTransaction(tx);
        if (tx is not null) return VerifyActiveTip(tx, null, out _);
        using var snapshot = connection.BeginTransaction(deferred: true);
        return VerifyActiveTip(snapshot, null, out _);
    }

    private Did2MessagingFloor VerifyActiveTip(SqliteTransaction tx, ActiveSelection? selection,
        out List<byte[]> headers)
    {
        using var timing = ClientPersistenceTiming.Measure(ClientPersistencePhase.NativeVerify);
        RequireCipherPolicy(tx); ValidateSchema(tx); RequireAllCipherPages(tx);
        VerifyActiveHistory(tx, selection);
        headers = ReadJournal(out var tip, tx);
        VerifyRows(headers, tip, tx);
        // In addition to actual table-column scans, reject hidden extra events
        // outside the independently rooted prefix and current journal suffix.
        using (var actual = Command("SELECT count(*) FROM events NOT INDEXED;", tx))
            if (Convert.ToInt64(actual.ExecuteScalar()) != checked((long)historyRoot.HistoryCount + headers.Count(static metadata => metadata[5] is 2 or 5)))
                throw new CryptographicException("Native event table differs from its complete authenticated map and suffix.");
        NativeWork.Inventory((ulong)headers.Count, historyRoot.HistoryCount);
        var ordinal = historyRoot.Basis.Ordinal;
        foreach (var metadata in headers)
        {
            ordinal = checked(ordinal + 1);
            if (metadata[5] is 2 or 5)
                selection?.Observe(ordinal, metadata[6], metadata.AsSpan(268, 32), metadata);
        }
        return tip;
    }

    private void RequireAllCipherPages(SqliteTransaction tx)
    {
        NativeWork.CipherScan();
        using var command = Command("PRAGMA cipher_integrity_check;", tx);
        using var rows = command.ExecuteReader();
        if (rows.Read()) throw new CryptographicException("Native messaging page authentication failed.");
    }

    private void VerifyActiveHistory(SqliteTransaction tx, ActiveSelection? selection)
    {
        _ = Did2MessagingHistoryCheckpoint.Decode(historyRoot.Exact.Span, scope);
        if (historyRoot.Basis.Ordinal == 0)
        {
            using var empty = Command("SELECT count(*) FROM events WHERE ordinal<=0;", tx);
            if (Convert.ToInt64(empty.ExecuteScalar()) != 0)
                throw new InvalidDataException("Empty messaging history has invalid prefix rows.");
            return;
        }
        var initial = ReadInitialMetadata(tx);
        if (!Fixed(SHA256.HashData(initial), historyRoot.InitialHeaderHash))
            throw new CryptographicException("Protected messaging history lost its initial evidence.");
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-history-prefix"u8); digest.AppendData([0]);
        digest.AppendData(scope.Hash); digest.AppendData(historyRoot.Basis.Exact.Span); digest.AppendData(initial);
        using var command = Command("SELECT ordinal,direction,operation,metadata,length(envelope),length(plaintext),typeof(ordinal),typeof(direction),typeof(operation),typeof(metadata),typeof(envelope),typeof(plaintext),length(operation),length(metadata) FROM events NOT INDEXED WHERE ordinal<=$basis ORDER BY ordinal;", tx);
        command.Parameters.AddWithValue("$basis", checked((long)historyRoot.Basis.Ordinal));
        using var row = command.ExecuteReader();
        ulong count = 0, previous = 0; Span<byte> number = stackalloc byte[8];
        while (row.Read())
        {
            NativeWork.MetadataRow();
            if (row.GetString(6) != "integer" || row.GetString(7) != "integer" ||
                row.GetString(8) != "blob" || row.GetString(9) != "blob" || row.GetString(10) != "blob" ||
                row.GetInt64(12) != 32 || row.GetInt64(13) != Did2MessagingFloor.MetadataBytes)
                throw new InvalidDataException("Retained messaging metadata has a noncanonical storage type.");
            var ordinal = row.GetInt64(0); var direction = row.GetInt32(1);
            if (ordinal < 1 || (ulong)ordinal <= previous || (ulong)ordinal > historyRoot.Basis.Ordinal ||
                direction is not (1 or 2 or 3 or 4) || row.GetString(11) != (direction == 2 ? "blob" : "null"))
                throw new InvalidDataException("Retained messaging metadata has a noncanonical reference.");
            var operation = row.GetFieldValue<byte[]>(2); var metadata = row.GetFieldValue<byte[]>(3);
            var predecessor = Did2MessagingFloor.Decode(metadata.AsSpan(8, Did2MessagingFloor.Bytes), scope);
            OwnedDid2MessagingMutation.ValidateMetadataTransition(metadata, scope, predecessor);
            if (predecessor.Ordinal == ulong.MaxValue || (ulong)ordinal != predecessor.Ordinal + 1 ||
                metadata[5] != (direction is 3 or 4 ? 5 : 2) || metadata[6] != direction ||
                !Fixed(operation, metadata.AsSpan(268, 32)) ||
                row.GetInt64(4) != BinaryPrimitives.ReadUInt32BigEndian(metadata.AsSpan(592)) ||
                (direction == 2 ? row.IsDBNull(5) || row.GetInt64(5) != BinaryPrimitives.ReadUInt32BigEndian(metadata.AsSpan(596)) : !row.IsDBNull(5)))
                throw new CryptographicException("Retained messaging metadata differs from its bound columns.");
            BinaryPrimitives.WriteUInt64BigEndian(number, (ulong)ordinal); digest.AppendData(number); digest.AppendData(metadata);
            selection?.Observe((ulong)ordinal, direction, operation, metadata);
            count = checked(count + 1); previous = (ulong)ordinal;
        }
        BinaryPrimitives.WriteUInt64BigEndian(number, count); digest.AppendData(number);
        if (count != historyRoot.HistoryCount || !Fixed(digest.GetHashAndReset(), historyRoot.HistoryDigest))
            throw new CryptographicException("Messaging retained metadata differs from its protected checkpoint.");
    }

    // Closed bounded selector set. Tuples are copied WHILE hashing the complete
    // independently rooted map, or from the authenticated working journal. No
    // later self-consistent row/negative index lookup can replace this proof.
    private sealed class ActiveSelection : IDisposable
    {
        private readonly byte[][] selectors;
        private readonly bool eventHash;
        private readonly SelectedTuple?[] tuples;
        internal ActiveSelection(IReadOnlyList<byte[]> selectors, bool eventHash = false)
        {
            if (selectors.Count is < 1 or > MaximumOperationReadBatch) throw new ArgumentException("Unbounded native selectors.");
            this.selectors = selectors.Select(static value => value.ToArray()).ToArray();
            this.eventHash = eventHash; tuples = new SelectedTuple?[selectors.Count];
        }
        internal void Observe(ulong ordinal, int direction, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> metadata)
        {
            for (var index = 0; index < selectors.Length; index++)
            {
                if (eventHash ? direction != 2 || !Fixed(selectors[index], metadata.Slice(300, 32)) : !Fixed(selectors[index], operation)) continue;
                var prior = tuples[index];
                if (prior is not null)
                {
                    if (!eventHash) throw new CryptographicException("Native operation is not unique across complete custody.");
                    if (prior.Ordinal <= ordinal) continue; // Existing earliest exact event selector.
                    prior.Dispose();
                }
                tuples[index] = new(ordinal, direction, operation.ToArray(), metadata.ToArray());
            }
        }
        internal SelectedTuple? this[int index] => tuples[index];
        public void Dispose()
        { foreach (var selector in selectors) CryptographicOperations.ZeroMemory(selector); foreach (var tuple in tuples) tuple?.Dispose(); }
    }

    private sealed record SelectedTuple(ulong Ordinal, int Direction, byte[] Operation, byte[] Metadata) : IDisposable
    {
        public void Dispose() { CryptographicOperations.ZeroMemory(Operation); CryptographicOperations.ZeroMemory(Metadata); }
    }

    private OwnedDid2MessagingPersistedEvent? ReadCapturedOrdinaryEvent(SelectedTuple? tuple, SqliteTransaction tx)
    {
        if (tuple is null) return null; // Complete authenticated map AND suffix proved absence.
#if DEEP_TEST_INTERNALS
        Did2ActiveReadTestHooks.AfterProof(connection, tx);
#endif
        using var command = Command("SELECT operation,ordinal,direction,metadata,envelope,plaintext,typeof(operation),typeof(ordinal),typeof(direction),typeof(metadata),typeof(envelope),typeof(plaintext),length(operation),length(metadata),length(envelope),length(plaintext) FROM events NOT INDEXED WHERE ordinal=$ordinal;", tx);
        command.Parameters.AddWithValue("$ordinal", checked((long)tuple.Ordinal));
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetString(6) != "blob" || row.GetString(7) != "integer" || row.GetString(8) != "integer" ||
            row.GetString(9) != "blob" || row.GetString(10) != "blob" || row.GetString(11) != (tuple.Direction == 2 ? "blob" : "null") ||
            row.GetInt64(12) != 32 || row.GetInt64(13) != Did2MessagingFloor.MetadataBytes ||
            row.GetInt64(14) != BinaryPrimitives.ReadUInt32BigEndian(tuple.Metadata.AsSpan(592)) ||
            (tuple.Direction == 2 ? row.IsDBNull(15) || row.GetInt64(15) != BinaryPrimitives.ReadUInt32BigEndian(tuple.Metadata.AsSpan(596)) : !row.IsDBNull(15)) ||
            row.GetInt64(1) != checked((long)tuple.Ordinal) || row.GetInt32(2) != tuple.Direction ||
            !Fixed(row.GetFieldValue<byte[]>(0), tuple.Operation) || !Fixed(row.GetFieldValue<byte[]>(3), tuple.Metadata))
            throw new CryptographicException("Selected native payload lost its authenticated captured tuple.");
        if (tuple.Direction is not (1 or 2)) throw new CryptographicException("Native data operation collides with Braid control custody.");
        byte[] envelope = [], plaintext = [];
        try
        {
            envelope = row.GetFieldValue<byte[]>(4);
            if (tuple.Direction == 2) plaintext = row.GetFieldValue<byte[]>(5);
            if (envelope.Length != BinaryPrimitives.ReadUInt32BigEndian(tuple.Metadata.AsSpan(592)) ||
                plaintext.Length != BinaryPrimitives.ReadUInt32BigEndian(tuple.Metadata.AsSpan(596)))
                throw new CryptographicException("Selected native payload lost its captured lengths.");
            VerifyHistoricalEvent(tuple.Ordinal, tuple.Direction, tuple.Operation, tuple.Metadata, envelope, plaintext);
            if (row.Read()) throw new InvalidDataException("Selected native ordinal is not unique.");
            var result = new OwnedDid2MessagingPersistedEvent(tuple.Direction, tuple.Ordinal, envelope, plaintext,
                tuple.Metadata.AsSpan(300, 32), tuple.Metadata.AsSpan(Did2RouteProcessingMetadata.Offset, Did2RouteProcessingMetadata.Bytes));
            envelope = []; plaintext = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext); }
    }
}
