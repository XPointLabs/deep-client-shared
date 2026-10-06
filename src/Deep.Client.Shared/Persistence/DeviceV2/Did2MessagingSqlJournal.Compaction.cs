using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    // Read-only complete-effect facts, not a SQL deletion capability. The
    // account owner still has to stage/revalidate/resume the exact plan.
    internal sealed class HistoryPrefixEffects
    {
        internal HistoryPrefixEffects(Did2MessagingHistoryCheckpoint successor, byte[] before,
            byte[] after, IReadOnlyList<Did2CompactionPlan.Row> rows)
        { Successor = successor; Before = before; After = after; Rows = rows; }
        internal Did2MessagingHistoryCheckpoint Successor { get; }
        internal ReadOnlyMemory<byte> Before { get; }
        internal ReadOnlyMemory<byte> After { get; }
        internal IReadOnlyList<Did2CompactionPlan.Row> Rows { get; }
    }

    internal HistoryPrefixEffects CaptureHistoryPrefixEffects(Did2MessagingFloor stable, int prefixRows)
    {
        if (stable.Phase != 1 || stable.Status != 1 || prefixRows is < 1 or > Did2CompactionPlan.MaximumRows)
            throw new InvalidDataException("Compaction capture needs a bounded active exact prefix.");
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        return CaptureHistoryPrefixEffects(stable, prefixRows, tx);
    }
    private HistoryPrefixEffects CaptureHistoryPrefixEffects(Did2MessagingFloor stable, int prefixRows, SqliteTransaction tx)
    {
        VerifyHistoryPrefix(tx);
        var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx); RequireSame(stable, tip);
        if (prefixRows > headers.Count) throw new InvalidDataException("Compaction prefix exceeds its verified working rows.");
        var basis = historyRoot.Basis; var rows = new List<Did2CompactionPlan.Row>(prefixRows);
        for (var index = 0; index < prefixRows; index++)
        {
            basis = Did2MessagingFloor.FromJournalMetadata(scope, basis, headers[index]);
            rows.Add(new(Did2CompactionPlan.Disposition.JournalPrefix, PrefixRowSelector(scope, basis.Ordinal), SHA256.HashData(headers[index])));
        }
        if (basis.Status != 1) throw new InvalidDataException("An unactivated/latched prefix cannot become a history basis.");
        var initial = ReadInitialMetadata(tx); var retained = ComputeHistoryProjection(basis, initial, tx);
        var successor = historyRoot.NextProjection(scope, basis, initial, retained.Digest, retained.Count);
        // Same SQL snapshot: the virtual successor omits only the selected
        // journal prefix. Every other cell/table is preserved, including full
        // event metadata, ciphertext/plaintext, initial evidence and live TRS.
        var before = CompleteSqlProjection(0, tx);
        var after = CompleteSqlProjection(basis.Ordinal, tx);
        rows.Sort((left, right) => left.Selector.Span.SequenceCompareTo(right.Selector.Span));
        return new(successor, before, after, rows.AsReadOnly());
    }

    internal void VerifyCompletePrefixSuccessor(Did2MessagingFloor stable, Did2CompactionPlan plan)
    {
        RequireCipherPolicy(); ValidateSchema(); using var tx = connection.BeginTransaction();
        VerifyHistoryPrefix(tx); var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx); RequireSame(stable, tip);
        if (!Fixed(CompleteSqlProjection(0, tx), plan.SqlAfter))
            throw new CryptographicException("Compaction SQL is not the exact complete successor.");
    }

    internal async Task ApplyStoredPrefixAsync(IDeepSecureStorage storage, Did2CompactionPlan plan,
        Did2MessagingFloor stable, Did2MessagingHistoryCheckpoint successor,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Messaging || !Fixed(plan.SqlSelector, scope.Hash))
            throw new InvalidDataException("Only an exact prepared messaging prefix can enter SQL.");
        RequireCipherPolicy(); ValidateSchema(); using var tx = connection.BeginTransaction();
        var effects = CaptureHistoryPrefixEffects(stable, plan.RowCount, tx);
        if (!Fixed(effects.Before.Span, plan.SqlBefore) || !Fixed(effects.After.Span, plan.SqlAfter) ||
            !Fixed(effects.Successor.Exact.Span, successor.Exact.Span))
            throw new CryptographicException("Stored prefix differs from independently recaptured complete SQL effects.");
        for (var index = 0; index < effects.Rows.Count; index++)
        {
            var expected = plan.ReadRow(index); var actual = effects.Rows[index];
            if (expected.Action != actual.Action || !Fixed(expected.Selector.Span, actual.Selector.Span) || !Fixed(expected.Commitment.Span, actual.Commitment.Span))
                throw new CryptographicException("Stored prefix changed a selected row/disposition.");
        }
        var roots = await ProtectedDeepIdV2AccountOwner.ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(effects.Before.Span, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
            throw new InvalidDataException("Compaction predecessor changed before SQL.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        using (var delete = Command("DELETE FROM journal WHERE ordinal<=$prefix;", tx))
        {
            delete.Parameters.AddWithValue("$prefix", checked((long)successor.Basis.Ordinal));
            if (delete.ExecuteNonQuery() != plan.RowCount) throw new CryptographicException("Compaction changed another journal prefix.");
        }
        var after = new Did2MessagingSqlJournal(connection, scope, successor);
        after.VerifyHistoryPrefix(tx); var headers = after.ReadJournal(out var tip, tx); after.VerifyRows(headers, tip, tx); RequireSame(stable, tip);
        if (!Fixed(after.CompleteSqlProjection(0, tx), plan.SqlAfter)) throw new CryptographicException("Compaction SQL effects differ before commit.");
        roots = await ProtectedDeepIdV2AccountOwner.ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(plan.SqlAfter, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
            throw new InvalidDataException("Compaction dependencies changed before SQL commit.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit();
    }

    internal byte[] ReadCompleteCompactionProjection()
    {
        RequireCipherPolicy(); ValidateSchema();
        using var tx = connection.BeginTransaction();
        return CompleteSqlProjection(0, tx);
    }

    private byte[] CompleteSqlProjection(ulong skipJournalThrough, SqliteTransaction tx)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/messaging-compaction-sql"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        Span<byte> number = stackalloc byte[8];
        foreach (var (name, schema) in Schema.OrderBy(static entry => entry.Name, StringComparer.Ordinal))
        {
            var definition = Encoding.UTF8.GetBytes(schema);
            BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)definition.Length)); hash.AppendData(number); hash.AppendData(definition);
            var order = name switch { "journal" or "events" => "ordinal", _ => "singleton" };
            var cells = name switch
            {
                "scope" => new[] { ("singleton", 0, 0), ("exact_scope", 404, 404) },
                "journal" => [("ordinal", 0, 0), ("predecessor", 32, 32), ("head", 32, 32), ("metadata", 608, 608)],
                "ratchet" => [("singleton", 0, 0), ("exact_state", 1, 2097152)],
                "initial_events" => [("singleton", 0, 0), ("envelope", 1, 65536), ("session_init", 1, 32768), ("hello", 1, 32768), ("metadata", 608, 608)],
                "events" => [("operation", 32, 32), ("ordinal", 0, 0), ("direction", 0, 0), ("envelope", 1, 65536), ("plaintext", 1, 33082), ("metadata", 608, 608)],
                _ => throw new InvalidDataException("Unsupported compaction SQL table.")
            };
            var boundColumns = string.Join(",", cells.Select(cell => "typeof(" + cell.Item1 + "),length(" + cell.Item1 + ")"));
            var virtualSkip = name == "journal" && skipJournalThrough != 0;
            using var query = Command("SELECT *," + boundColumns + " FROM " + name + (virtualSkip ? " WHERE ordinal>$skip" : "") + " ORDER BY " + order + ";", tx);
            if (virtualSkip) query.Parameters.AddWithValue("$skip", checked((long)skipJournalThrough));
            using var reader = query.ExecuteReader(); ulong count = 0;
            while (reader.Read())
            {
                hash.AppendData([1]); count = checked(count + 1);
                BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)cells.Length)); hash.AppendData(number);
                for (var column = 0; column < cells.Length; column++)
                {
                    var type = reader.GetString(cells.Length + column * 2);
                    if (type == "null")
                    {
                        if (name != "events" || cells[column].Item1 != "plaintext")
                            throw new InvalidDataException("Compaction SQL has an unexpected null cell.");
                        hash.AppendData([0]); continue;
                    }
                    if (cells[column].Item2 == 0 ? type != "integer" : type != "blob" ||
                        reader.GetInt64(cells.Length + column * 2 + 1) < cells[column].Item2 ||
                        reader.GetInt64(cells.Length + column * 2 + 1) > cells[column].Item3)
                        throw new InvalidDataException("Compaction SQL cell exceeds its closed type/size bounds.");
                    var value = reader.GetValue(column);
                    if (value is long integer)
                    { hash.AppendData([1]); BinaryPrimitives.WriteInt64BigEndian(number, integer); hash.AppendData(number); }
                    else if (value is byte[] bytes)
                    {
                        try
                        { hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length)); hash.AppendData(number); hash.AppendData(bytes); }
                        finally { CryptographicOperations.ZeroMemory(bytes); }
                    }
                    else throw new InvalidDataException("Compaction SQL cell has an unsupported canonical type.");
                }
            }
            hash.AppendData([0]); BinaryPrimitives.WriteUInt64BigEndian(number, count); hash.AppendData(number);
        }
        return hash.GetHashAndReset();
    }

    private static byte[] PrefixRowSelector(Did2MessagingSessionScope scope, ulong ordinal)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/messaging-compaction-row"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        Span<byte> number = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(number, ordinal); hash.AppendData(number);
        return hash.GetHashAndReset();
    }
}
