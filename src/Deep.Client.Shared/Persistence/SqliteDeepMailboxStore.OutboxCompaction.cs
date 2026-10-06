#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    internal async Task<byte[]?> ReadRetainedAuthoredEventAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> eventHash, CancellationToken ct)
    {
        if (eventHash.Length != 32) throw new ArgumentException("An exact event hash is required.", nameof(eventHash));
        var logical = await WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
            using var command = connection.CreateCommand(); command.Transaction = tx;
            command.CommandText = "SELECT logical_message_id,length(logical_message_id),typeof(logical_message_id) FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_device_id=$device AND author_account_id=$account AND exact_dmc2_hash=$hash LIMIT 2;";
            command.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray()); command.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
            command.Parameters.AddWithValue("$account", scope.LocalAccount.ToArray()); command.Parameters.AddWithValue("$hash", eventHash.ToArray());
            using var reader = command.ExecuteReader();
            if (!reader.Read()) return Task.FromResult<byte[]?>(null);
            if (reader.GetInt64(1) != 32 || reader.GetString(2) != "blob") throw new InvalidDataException("Retained authored history has a hostile identifier.");
            var bytes = reader.GetFieldValue<byte[]>(0);
            if (reader.Read()) { CryptographicOperations.ZeroMemory(bytes); throw new CryptographicException("Retained authored event is ambiguous."); }
            return Task.FromResult<byte[]?>(bytes);
        }, ct).ConfigureAwait(false);
        if (logical is null) return null;
        try
        {
            var exact = await ReadDirectDmc2Async(scope.LocalAccount.ToArray(), BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]),
                scope.Conversation.ToArray(), logical, scope.LocalDevice.ToArray(), ct).ConfigureAwait(false);
            if (exact is null) throw new CryptographicException("Retained authored history changed during lookup.");
            if (!DirectFixed(SHA256.HashData(exact), eventHash.Span))
            { CryptographicOperations.ZeroMemory(exact); throw new CryptographicException("Retained authored history differs from the committed native event."); }
            return exact;
        }
        finally { CryptographicOperations.ZeroMemory(logical); }
    }

    // Complete SQL facts only. No deletion, staging, authority callback or
    // row-count-derived permission is provided by this reader.
    internal Task<(byte[] Before, byte[] After)> CaptureOrdinaryOutboxEffectsAsync(
        Did2MessagingSessionScope scope, IReadOnlyList<ProtectedDid2DirectTextJournal.Entry> selected,
        CancellationToken ct)
    {
        return WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction();
            return Task.FromResult(CaptureOrdinaryOutboxEffects(connection, tx, scope, selected, ct));
        }, ct);
    }

    private static (byte[] Before, byte[] After) CaptureOrdinaryOutboxEffects(SqliteConnection connection,
        SqliteTransaction tx, Did2MessagingSessionScope scope,
        IReadOnlyList<ProtectedDid2DirectTextJournal.Entry> selected, CancellationToken ct)
    {
        if (selected.Count is < 1 or > Did2CompactionPlan.MaximumRows || selected.Any(entry =>
            !entry.Stored || !DirectFixed(entry.Scope.Exact, scope.Exact)))
            throw new InvalidDataException("Outbox capture requires a bounded exact stable selection.");
        ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
        var operations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in selected)
        {
            ct.ThrowIfCancellationRequested();
            if (!operations.Add(Convert.ToHexString(entry.Operation)))
                throw new InvalidDataException("Duplicate selected ordinary operation.");
            RequireSelectedOrdinaryRow(connection, tx, entry);
        }
        var before = CompleteApplicationCompactionProjection(connection, tx, scope, null, ct);
        var after = CompleteApplicationCompactionProjection(connection, tx, scope, operations, ct);
        ct.ThrowIfCancellationRequested(); return (before, after);
    }

    internal Task<byte[]> ReadCompleteOrdinaryCompactionProjectionAsync(Did2MessagingSessionScope scope, CancellationToken ct) =>
        WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction();
            ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
            return Task.FromResult(CompleteApplicationCompactionProjection(connection, tx, scope, null, ct));
        }, ct);

    internal Task ApplyStoredOrdinaryOutboxAsync(IDeepSecureStorage storage, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, IReadOnlyList<ProtectedDid2DirectTextJournal.Entry> selected,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct) =>
        WithReplayConnectionAsync(async connection =>
        {
            using var borrowed = held.BorrowFor(lease);
            if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Application ||
                !DirectFixed(plan.SqlSelector, scope.Hash) || selected.Count != plan.RowCount)
                throw new InvalidDataException("Only an exact stored ordinary selection can enter SQL.");
            using var tx = connection.BeginTransaction();
            var effects = CaptureOrdinaryOutboxEffects(connection, tx, scope, selected, ct);
            if (!DirectFixed(effects.Before, plan.SqlBefore) || !DirectFixed(effects.After, plan.SqlAfter))
                throw new CryptographicException("Stored ordinary selection differs from complete SQL effects.");
            var ordered = selected.OrderBy(entry => Convert.ToHexString(entry.Operation), StringComparer.Ordinal).ToArray();
            for (var index = 0; index < ordered.Length; index++)
            {
                var row = plan.ReadRow(index);
                if (row.Action != Did2CompactionPlan.Disposition.OutboxPayload ||
                    !DirectFixed(row.Selector.Span, ordered[index].Operation) ||
                    !DirectFixed(row.Commitment.Span, SHA256.HashData(ordered[index].Exact)))
                    throw new CryptographicException("Stored ordinary selection changed a disposition or row.");
            }
            var roots = await ProtectedDeepIdV2AccountOwner.ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(effects.Before, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new InvalidDataException("Ordinary predecessor changed before SQL.");
            foreach (var entry in selected)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var delete = connection.CreateCommand(); delete.Transaction = tx;
                delete.CommandText = "DELETE FROM direct_text_outbox WHERE operation_id=$operation;";
                delete.Parameters.AddWithValue("$operation", entry.Operation.ToArray());
                if (delete.ExecuteNonQuery() != 1) throw new CryptographicException("Ordinary cleanup lost an exact selected row.");
            }
            if (!DirectFixed(CompleteApplicationCompactionProjection(connection, tx, scope, null, ct), plan.SqlAfter))
                throw new CryptographicException("Ordinary SQL effects differ before commit.");
            roots = await ProtectedDeepIdV2AccountOwner.ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(plan.SqlAfter, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                throw new InvalidDataException("Ordinary dependencies changed before SQL commit.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit();
            return true;
        }, ct);

    private static void RequireSelectedOrdinaryRow(SqliteConnection connection, SqliteTransaction tx,
        ProtectedDid2DirectTextJournal.Entry entry)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT conversation_id,logical_message_id,author_device_id,recipient_account_id,recipient_device_id,sender_sequence,exact_dmc2_hash,created_at,length(exact_dmc2),typeof(exact_dmc2),exact_dmc2 FROM direct_text_outbox WHERE operation_id=$operation;";
        command.CommandText = command.CommandText.TrimEnd(';') + " AND " + string.Join(" AND ",
            new[] { "conversation_id", "logical_message_id", "author_device_id", "recipient_account_id", "recipient_device_id", "exact_dmc2_hash" }
                .Select(name => "typeof(" + name + ")='blob' AND length(" + name + ")=32")) +
            " AND typeof(sender_sequence)='integer' AND typeof(created_at)='integer';";
        command.Parameters.AddWithValue("$operation", entry.Operation.ToArray());
        using var reader = command.ExecuteReader();
        if (!reader.Read() || reader.GetString(9) != "blob" || reader.GetInt64(8) is < 285 or > ProtectedDid2DirectTextJournal.MaximumEventBytes)
            throw new CryptographicException("Selected outbox row is missing or outside its exact bound.");
        var scope = entry.Scope;
        var expected = new[] { scope.Conversation.ToArray(), entry.Logical.ToArray(), scope.LocalDevice.ToArray(),
            scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), entry.EventHash.ToArray() };
        try
        {
            for (var index = 0; index < expected.Length; index++)
            {
                var actual = reader.GetFieldValue<byte[]>(index == 5 ? 6 : index);
                try { if (!DirectFixed(actual, expected[index])) throw new CryptographicException("Selected outbox metadata changed."); }
                finally { CryptographicOperations.ZeroMemory(actual); }
            }
            if (reader.GetInt64(5) != checked((long)entry.Sequence) || reader.GetInt64(7) != checked((long)entry.Created))
                throw new CryptographicException("Selected outbox authored position changed.");
            var payload = reader.GetFieldValue<byte[]>(10);
            try { entry.RequireEvent(payload); }
            finally { CryptographicOperations.ZeroMemory(payload); }
            if (reader.Read()) throw new InvalidDataException("Selected ordinary row is not unique.");
        }
        finally { foreach (var bytes in expected) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] CompleteApplicationCompactionProjection(SqliteConnection connection, SqliteTransaction tx,
        Did2MessagingSessionScope scope, HashSet<string>? omitted, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/application-compaction-sql"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        Span<byte> number = stackalloc byte[8];
        foreach (var schema in ReadSchemaObjects(connection, tx))
        {
            var definition = Encoding.UTF8.GetBytes(schema);
            BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)definition.Length)); hash.AppendData(number); hash.AppendData(definition);
        }
        using var tables = connection.CreateCommand(); tables.Transaction = tx;
        tables.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,7)<>'sqlite_' ORDER BY name;";
        var names = new List<string>(); using (var reader = tables.ExecuteReader()) while (reader.Read()) names.Add(reader.GetString(0));
        var omittedCount = 0;
        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();
            var table = "\"" + name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
            using var columns = connection.CreateCommand(); columns.Transaction = tx; columns.CommandText = "PRAGMA table_info(" + table + ");";
            var fields = new List<string>(); using (var reader = columns.ExecuteReader()) while (reader.Read()) fields.Add(reader.GetString(1));
            var quoted = fields.Select(field => "\"" + field.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"").ToArray();
            var bounds = string.Join(",", quoted.Select(field => "typeof(" + field + "),length(CAST(" + field + " AS BLOB))"));
            using var command = connection.CreateCommand(); command.Transaction = tx;
            var values = string.Join(",", quoted.Select(field => "CASE WHEN typeof(" + field + ")='text' THEN CAST(" + field + " AS BLOB) ELSE " + field + " END"));
            command.CommandText = "SELECT " + values + "," + bounds + " FROM " + table + " ORDER BY " + string.Join(",", quoted) + ";";
            using var rows = command.ExecuteReader(); ulong count = 0;
            while (rows.Read())
            {
                ct.ThrowIfCancellationRequested();
                for (var index = 0; index < fields.Count; index++)
                {
                    var type = rows.GetString(fields.Count + index * 2);
                    if (type is not ("null" or "integer" or "blob" or "text") ||
                        type is "blob" or "text" && rows.GetInt64(fields.Count + index * 2 + 1) > TransportOutboxLimits.MaxCiphertextBundleBytes)
                        throw new InvalidDataException("Application compaction cell exceeds its closed type/size bound.");
                }
                if (name == "direct_text_outbox" && omitted is not null)
                {
                    var operation = rows.GetFieldValue<byte[]>(fields.IndexOf("operation_id"));
                    try { if (omitted.Contains(Convert.ToHexString(operation))) { omittedCount++; continue; } }
                    finally { CryptographicOperations.ZeroMemory(operation); }
                }
                hash.AppendData([1]); count = checked(count + 1);
                for (var index = 0; index < fields.Count; index++)
                {
                    var value = rows.GetValue(index);
                    if (value is DBNull) hash.AppendData([0]);
                    else if (value is long integer) { hash.AppendData([1]); BinaryPrimitives.WriteInt64BigEndian(number, integer); hash.AppendData(number); }
                    else
                    {
                        var bytes = (byte[])value;
                        try
                        {
                            hash.AppendData([rows.GetString(fields.Count + index * 2) == "text" ? (byte)3 : (byte)2]);
                            BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length)); hash.AppendData(number); hash.AppendData(bytes);
                        }
                        finally { CryptographicOperations.ZeroMemory(bytes); }
                    }
                }
            }
            hash.AppendData([0]); BinaryPrimitives.WriteUInt64BigEndian(number, count); hash.AppendData(number);
        }
        if (omitted is not null && omittedCount != omitted.Count)
            throw new CryptographicException("Virtual outbox successor lost a selected row.");
        return hash.GetHashAndReset();
    }
}
#endif
