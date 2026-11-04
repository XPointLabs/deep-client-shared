using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed class Did2MessagingArchiveOriginal : IDisposable
{
    internal Did2MessagingArchiveOriginal(Did2MessagingArchiveReference reference, byte[] metadata, byte[] envelope, byte[] plaintext)
    { Reference = reference; Metadata = metadata; Envelope = envelope; Plaintext = plaintext; }
    internal Did2MessagingArchiveReference Reference { get; }
    internal byte[] Metadata { get; }
    internal byte[] Envelope { get; }
    internal byte[] Plaintext { get; }
    public void Dispose()
    { CryptographicOperations.ZeroMemory(Metadata); CryptographicOperations.ZeroMemory(Envelope); CryptographicOperations.ZeroMemory(Plaintext); }
}

internal sealed partial class Did2MessagingSqlJournal
{
    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadArchiveEnrollmentBatch(ProtectedDid2MessagingArchiveEnrollment progress)
    {
        if (!archiveEnrollment || !Fixed(progress.ScopeHash, scope.Hash) || !Fixed(progress.SourceHistory.Exact.Span, historyRoot.Exact.Span))
            throw new InvalidOperationException("Archive enrollment batch requires the exact frozen source history.");
        return ReadArchiveOriginalBatch(progress.Cursor, progress.TargetBasis.Ordinal);
    }

    private IReadOnlyList<Did2MessagingArchiveOriginal> ReadArchiveOriginalBatch(ulong cursor, ulong through, SqliteTransaction? tx = null)
    {
        if (cursor > through || through > long.MaxValue) throw new InvalidDataException("Archive source cursor exceeds its exact basis.");
        var source = "SELECT rowid,ordinal,direction,operation,metadata,envelope,plaintext,2 AS kind FROM events" +
            (HasDecisionTable ? " UNION ALL SELECT rowid,ordinal,0,operation,metadata,X'',decision,3 FROM route_decisions" : "");
        using var query = Command("SELECT rowid,ordinal,direction,operation,metadata,envelope,plaintext," +
            "typeof(rowid),typeof(ordinal),typeof(direction),typeof(operation),length(operation),typeof(metadata),length(metadata)," +
            "typeof(envelope),length(envelope),typeof(plaintext),length(plaintext),kind FROM (" + source + ") WHERE ordinal>$cursor AND ordinal<=$through ORDER BY ordinal LIMIT 32;", tx);
        query.Parameters.AddWithValue("$cursor", checked((long)cursor)); query.Parameters.AddWithValue("$through", checked((long)through));
        using var row = query.ExecuteReader(); var result = new List<Did2MessagingArchiveOriginal>();
        try
        {
            var previous = cursor;
            while (row.Read())
            {
                var rowId = row.GetInt64(0); var ordinal = row.GetInt64(1); var direction = row.GetInt32(2); var kind = row.GetInt32(18);
                if (row.GetString(7) != "integer" || row.GetString(8) != "integer" || row.GetString(9) != "integer" ||
                    rowId <= 0 || ordinal < 3 || (ulong)ordinal <= previous || (ulong)ordinal > through ||
                    (kind == 3 ? direction != 0 : kind != 2 || direction is < 1 or > 4) ||
                    row.GetString(10) != "blob" || row.GetInt64(11) != 32 || row.GetString(12) != "blob" || row.GetInt64(13) != 672 ||
                    row.GetString(14) != "blob" || (kind == 3 ? row.GetInt64(15) != 0 : row.GetInt64(15) is < 1 or > 65536) ||
                    row.GetString(16) != (kind == 3 || direction == 2 ? "blob" : "null") ||
                    (kind == 3 ? row.GetInt64(17) != 1024 : direction == 2 ? row.IsDBNull(17) || row.GetInt64(17) is < 1 or > 33082 : !row.IsDBNull(17)))
                    throw new InvalidDataException("Archive original has a noncanonical exact SQL shape.");
                var operation = row.GetFieldValue<byte[]>(3); var metadata = row.GetFieldValue<byte[]>(4);
                var envelope = row.GetFieldValue<byte[]>(5); var plaintext = kind == 3 || direction == 2 ? row.GetFieldValue<byte[]>(6) : [];
                try
                {
                    RequireUniqueOriginal(operation, (ulong)ordinal, tx);
                    if (kind == 3) _ = VerifyRouteDecisionRow((ulong)ordinal, operation, metadata, plaintext);
                    else VerifyHistoricalEvent((ulong)ordinal, direction, operation, metadata, envelope, plaintext);
                    var reference = kind == 3 ? Did2MessagingArchiveReference.Decision((ulong)ordinal, (ulong)rowId, operation, SHA256.HashData(metadata)) :
                        Did2MessagingArchiveReference.Event((byte)direction, (ulong)ordinal, (ulong)rowId, operation, SHA256.HashData(metadata));
                    result.Add(new(reference, metadata, envelope, plaintext)); metadata = []; envelope = []; plaintext = [];
                    previous = (ulong)ordinal;
                }
                finally
                { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(metadata); CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plaintext); }
            }
            return result;
        }
        catch { foreach (var item in result) item.Dispose(); throw; }
    }

    internal (byte[] Metadata, byte[] Hello) ReadArchiveInitialSource(SqliteTransaction? tx = null)
    {
        var metadata = ReadInitialMetadata(tx);
        using var query = Command("SELECT hello,typeof(hello),length(hello),metadata,typeof(metadata),length(metadata) FROM initial_events WHERE singleton=1;", tx);
        using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) is < 1 or > 32768 ||
            row.GetString(4) != "blob" || row.GetInt64(5) != 672 || !Fixed(row.GetFieldValue<byte[]>(3), metadata))
            throw new CryptographicException("Archive initial singleton differs from its fully verified source.");
        var hello = row.GetFieldValue<byte[]>(0);
        if (row.Read()) { CryptographicOperations.ZeroMemory(hello); throw new CryptographicException("Archive initial singleton is not unique."); }
        return (metadata, hello);
    }
}
