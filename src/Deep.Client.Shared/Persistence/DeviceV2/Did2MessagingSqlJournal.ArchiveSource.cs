using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal byte[] CaptureArchiveEnrollmentSource()
    {
        if (!archiveEnrollment) throw new InvalidOperationException("A lifetime source fingerprint belongs only to explicit enrollment.");
        RequireCipherPolicy(); var version = checked((int)PragmaInteger("user_version"));
        if (version is not (5 or 6)) throw new InvalidDataException("Enrollment SQL has an unsupported exact schema.");
        ValidateSchemaVersion(version);
        using var tx = connection.BeginTransaction(deferred: true);
        RequireAllCipherPages(tx);
        // Original rows are authenticated independently of the three staged
        // tables. Exact source verification precedes fingerprint production.
        VerifyHistoryPrefix(tx); var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx);
        using (var actual = Command("SELECT count(*) FROM events NOT INDEXED;", tx))
            if (Convert.ToInt64(actual.ExecuteScalar()) != checked((long)historyRoot.HistoryCount + headers.Count(static row => row[5] is 2 or 5)))
                throw new CryptographicException("Enrollment source has extra or omitted native originals.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-enrollment-source"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        hash.AppendData(ArchiveSchemaHash(5)); hash.AppendData(ArchiveSchemaHash(6));
        Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(number, ApplicationId); hash.AppendData(number);
        foreach (var (name, ddl) in OriginalSchema.OrderBy(static value => value.Name, StringComparer.Ordinal))
        {
            AppendSchemaFrame(hash, name, ddl);
            AppendOriginalTable(hash, name, tx, includeRowId: true);
        }
        return hash.GetHashAndReset();
    }

    private static (string Name, int Minimum, int Maximum)[] OriginalCells(string name) => name switch
    {
        "scope" => [("singleton", 0, 0), ("exact_scope", 404, 404)],
        "journal" => [("ordinal", 0, 0), ("predecessor", 32, 32), ("head", 32, 32), ("metadata", 672, 672)],
        "ratchet" => [("singleton", 0, 0), ("exact_state", 1, 2097152)],
        "initial_events" => [("singleton", 0, 0), ("envelope", 1, 65536), ("session_init", 1, 32768), ("hello", 1, 32768), ("metadata", 672, 672)],
        "events" => [("operation", 32, 32), ("ordinal", 0, 0), ("direction", 0, 0), ("envelope", 1, 65536), ("plaintext", 1, 33082), ("metadata", 672, 672)],
        _ => throw new InvalidDataException("Unknown original messaging table.")
    };

    private ulong AppendOriginalTable(IncrementalHash hash, string name, SqliteTransaction tx,
        bool includeRowId = false, ulong skipJournalThrough = 0)
    {
        var cells = OriginalCells(name);
        if (includeRowId && name == "events") cells = [("rowid", 0, 0), .. cells];
        var columns = string.Join(',', cells.Select(static cell => cell.Name));
        var shapes = string.Join(',', cells.Select(static cell => $"typeof({cell.Name}),length({cell.Name})"));
        var skip = name == "journal" && skipJournalThrough != 0;
        using var query = Command($"SELECT {columns},{shapes} FROM {name} NOT INDEXED" + (skip ? " WHERE ordinal>$skip" : "") +
            " ORDER BY " + (name is "journal" or "events" ? "ordinal" : "singleton") + ";", tx);
        if (skip) query.Parameters.AddWithValue("$skip", checked((long)skipJournalThrough));
        using var reader = query.ExecuteReader(); ulong count = 0; Span<byte> number = stackalloc byte[8];
        while (reader.Read())
        {
            hash.AppendData([1]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)cells.Length)); hash.AppendData(number);
            for (var i = 0; i < cells.Length; i++)
            {
                var type = reader.GetString(cells.Length + i * 2);
                if (type == "null")
                {
                    if (name != "events" || cells[i].Name != "plaintext") throw new InvalidDataException("Unexpected null original SQL cell.");
                    hash.AppendData([0]); continue;
                }
                if (cells[i].Minimum == 0)
                {
                    if (type != "integer") throw new InvalidDataException("Original SQL integer has a noncanonical type.");
                    var value = reader.GetInt64(i);
                    if (cells[i].Name == "rowid" && value <= 0) throw new InvalidDataException("Original event rowid is not positive.");
                    hash.AppendData([1]); BinaryPrimitives.WriteInt64BigEndian(number, value); hash.AppendData(number);
                }
                else
                {
                    if (type != "blob" || reader.GetInt64(cells.Length + i * 2 + 1) < cells[i].Minimum ||
                        reader.GetInt64(cells.Length + i * 2 + 1) > cells[i].Maximum) throw new InvalidDataException("Original SQL blob exceeds its exact bounds.");
                    var bytes = reader.GetFieldValue<byte[]>(i);
                    try { hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)bytes.Length)); hash.AppendData(number); hash.AppendData(bytes); }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
            }
            count = checked(count + 1);
        }
        hash.AppendData([0]); BinaryPrimitives.WriteUInt64BigEndian(number, count); hash.AppendData(number); return count;
    }
}
