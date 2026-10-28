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
        RequireCipherPolicy(tx); ValidateSchema(tx);
        VerifyActiveHistory(tx, selection);
        headers = ReadJournal(out var tip, tx);
        VerifyRows(headers, tip, tx);
        NativeWork.Inventory((ulong)headers.Count, archiveRoot!.ArchiveCount);
        var ordinal = WorkingBasis.Ordinal;
        foreach (var metadata in headers)
        {
            ordinal = checked(ordinal + 1);
            if (metadata[5] is 2 or 5)
                selection?.Observe(ordinal, metadata[6], metadata.AsSpan(268, 32), metadata);
        }
        return tip;
    }

    private void RequireAllCipherPages(SqliteTransaction? tx)
    {
        NativeWork.CipherScan();
        using var command = Command("PRAGMA cipher_integrity_check;", tx);
        using var rows = command.ExecuteReader();
        if (rows.Read()) throw new CryptographicException("Native messaging page authentication failed.");
    }

    private void VerifyActiveHistory(SqliteTransaction tx, ActiveSelection? selection)
    {
        RequireArchiveMirror(tx);
        if (selection is null) return;
        for (var i = 0; i < selection.Selectors.Count; i++)
        {
            var selector = selection.Selectors[i];
            var value = ReadArchiveFact(selection.ByEventHash ? Did2MessagingArchiveFamily.FirstIncomingEvent :
                Did2MessagingArchiveFamily.Operation, selector, tx);
            if (value is null) continue;
            var reference = Did2MessagingArchiveReference.Decode(value, false); reference.RequireAtBasis(WorkingBasis.Ordinal);
            var tuple = ReadArchivedTuple(reference, tx);
            if (selection.ByEventHash ? tuple.Direction != 2 || !Fixed(tuple.Metadata.AsSpan(300, 32), selector) :
                !Fixed(tuple.Operation, selector)) throw new CryptographicException("Selected archive fact differs from its actual native original.");
            selection.Observe(tuple.Ordinal, tuple.Direction, tuple.Operation, tuple.Metadata, reference.RowId);
            tuple.Dispose();
        }
    }

    private SelectedTuple ReadArchivedTuple(Did2MessagingArchiveReference reference, SqliteTransaction tx)
    {
        if (reference.Kind != 2) throw new InvalidDataException("An events selector cannot name the initial singleton.");
        using var command = Command("SELECT rowid,ordinal,direction,operation,metadata,typeof(rowid),typeof(ordinal),typeof(direction),typeof(operation),length(operation),typeof(metadata),length(metadata) FROM events WHERE rowid=$rowid;", tx);
        command.Parameters.AddWithValue("$rowid", checked((long)reference.RowId)); using var row = command.ExecuteReader();
        if (!row.Read() || row.GetString(5) != "integer" || row.GetString(6) != "integer" || row.GetString(7) != "integer" ||
            row.GetString(8) != "blob" || row.GetInt64(9) != 32 || row.GetString(10) != "blob" || row.GetInt64(11) != 672 ||
            row.GetInt64(0) != checked((long)reference.RowId) || row.GetInt64(1) != checked((long)reference.Ordinal) ||
            row.GetInt32(2) != reference.Direction || !Fixed(row.GetFieldValue<byte[]>(3), reference.Operation))
            throw new CryptographicException("Authenticated archive reference lost its exact rowid/native columns.");
        var metadata = row.GetFieldValue<byte[]>(4);
        if (!Fixed(SHA256.HashData(metadata), reference.MetadataHash) || row.Read())
            throw new CryptographicException("Authenticated archive metadata hash/uniqueness differs.");
        var prior = Did2MessagingFloor.Decode(metadata.AsSpan(8, 188), scope);
        OwnedDid2MessagingMutation.ValidateMetadataTransition(metadata, scope, prior);
        return new(reference.Ordinal, reference.Direction, reference.Operation.ToArray(), metadata, reference.RowId);
    }

    private Did2MessagingArchiveReference CaptureTupleReference(SelectedTuple tuple, SqliteTransaction tx)
    {
        if (tuple.RowId != 0) return Did2MessagingArchiveReference.Event((byte)tuple.Direction, tuple.Ordinal,
            tuple.RowId, tuple.Operation, SHA256.HashData(tuple.Metadata));
        // A working row has an authenticated ordinal/header in the bounded
        // native suffix. Resolve its actual rowid once and compare every bound
        // native column; the resulting locator is never an absence authority.
        using var query = Command("SELECT rowid,ordinal,direction,operation,metadata,typeof(rowid),typeof(ordinal),typeof(direction),typeof(operation),length(operation),typeof(metadata),length(metadata) FROM events WHERE ordinal=$ordinal;", tx);
        query.Parameters.AddWithValue("$ordinal", checked((long)tuple.Ordinal)); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(5) != "integer" || row.GetString(6) != "integer" || row.GetString(7) != "integer" ||
            row.GetString(8) != "blob" || row.GetInt64(9) != 32 || row.GetString(10) != "blob" || row.GetInt64(11) != 672 ||
            row.GetInt64(0) <= 0 || row.GetInt64(1) != checked((long)tuple.Ordinal) || row.GetInt32(2) != tuple.Direction ||
            !Fixed(row.GetFieldValue<byte[]>(3), tuple.Operation) || !Fixed(row.GetFieldValue<byte[]>(4), tuple.Metadata))
            throw new CryptographicException("Authenticated working tuple lost its actual source rowid/columns.");
        var rowId = checked((ulong)row.GetInt64(0)); if (row.Read()) throw new CryptographicException("Working tuple ordinal is not unique.");
        return Did2MessagingArchiveReference.Event((byte)tuple.Direction, tuple.Ordinal, rowId, tuple.Operation, SHA256.HashData(tuple.Metadata));
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
        internal IReadOnlyList<byte[]> Selectors => selectors;
        internal bool ByEventHash => eventHash;
        internal void Observe(ulong ordinal, int direction, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> metadata, ulong rowId = 0)
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
                tuples[index] = new(ordinal, direction, operation.ToArray(), metadata.ToArray(), rowId);
            }
        }
        internal SelectedTuple? this[int index] => tuples[index];
        public void Dispose()
        { foreach (var selector in selectors) CryptographicOperations.ZeroMemory(selector); foreach (var tuple in tuples) tuple?.Dispose(); }
    }

    private sealed record SelectedTuple(ulong Ordinal, int Direction, byte[] Operation, byte[] Metadata, ulong RowId = 0) : IDisposable
    {
        public void Dispose() { CryptographicOperations.ZeroMemory(Operation); CryptographicOperations.ZeroMemory(Metadata); }
    }

    private OwnedDid2MessagingPersistedEvent? ReadCapturedOrdinaryEvent(SelectedTuple? tuple, SqliteTransaction tx)
    {
        if (tuple is null) return null; // Complete authenticated map AND suffix proved absence.
#if DEEP_TEST_INTERNALS
        Did2ActiveReadTestHooks.BeforeSelectedPayload();
#endif
        using var command = Command("SELECT operation,ordinal,direction,metadata,envelope,plaintext,typeof(operation),typeof(ordinal),typeof(direction),typeof(metadata),typeof(envelope),typeof(plaintext),length(operation),length(metadata),length(envelope),length(plaintext) FROM events WHERE " + (tuple.RowId == 0 ? "ordinal=$ordinal" : "rowid=$rowid") + ";", tx);
        if (tuple.RowId == 0) command.Parameters.AddWithValue("$ordinal", checked((long)tuple.Ordinal));
        else command.Parameters.AddWithValue("$rowid", checked((long)tuple.RowId));
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
