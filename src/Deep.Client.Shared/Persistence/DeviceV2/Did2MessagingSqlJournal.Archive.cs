using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private ReadOnlySpan<byte> ReadArchiveInitialHeaderHash(SqliteTransaction? tx)
        => archiveRoot is null ? historyRoot.InitialHeaderHash : ReadArchiveReducer(tx).InitialMetadataHash;

    internal static byte[] ArchiveSchemaHash(int version)
    {
        if (version is not (5 or 6)) throw new ArgumentOutOfRangeException(nameof(version));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/archive-schema"u8); hash.AppendData([0]);
        Span<byte> header = stackalloc byte[10];
        BinaryPrimitives.WriteUInt32BigEndian(header, ApplicationId);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], (uint)version);
        var tables = version == 5 ? OriginalSchema : Schema;
        BinaryPrimitives.WriteUInt16BigEndian(header[8..], checked((ushort)tables.Length)); hash.AppendData(header);
        foreach (var (name, ddl) in tables.OrderBy(static value => value.Name, StringComparer.Ordinal))
            AppendSchemaFrame(hash, name, ddl);
        return hash.GetHashAndReset();
    }

    private static void AppendSchemaFrame(IncrementalHash hash, string name, string ddl)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name); var ddlBytes = Encoding.UTF8.GetBytes(ddl.TrimEnd(';'));
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)nameBytes.Length)); hash.AppendData(length[..2]); hash.AppendData(nameBytes);
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)ddlBytes.Length)); hash.AppendData(length); hash.AppendData(ddlBytes);
    }

    internal void StageArchiveSchema(ProtectedDid2MessagingArchiveEnrollment progress,
        Did2MessagingArchiveBuilder.Result initial, Did2MessagingArchiveReducer reducer)
    {
        RequireOpenedEnrollmentProgress(progress);
        if (!archiveEnrollment || progress.Phase != ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SourceFrozen ||
            !Fixed(progress.ScopeHash, scope.Hash) || !Fixed(progress.PatriciaHash, initial.PatriciaHash.Span) ||
            !Fixed(progress.ReducerHash, reducer.Digest.Span)) throw new InvalidOperationException("Only exact stored enrollment may stage archive schema.");
        RequireCipherPolicy();
        if (PragmaInteger("user_version") == SchemaVersion)
        {
            ValidateSchemaVersion(SchemaVersion);
            using var mirror = Command("SELECT count(*) FROM archive_state;");
            if (Convert.ToInt64(mirror.ExecuteScalar()) != 0) throw new CryptographicException("SourceFrozen schema stage has an unexpected archive mirror.");
            RequireStagedArchive(initial, reducer);
            return;
        }
        ValidateSchemaVersion(5);
        using var tx = connection.BeginTransaction();
        foreach (var (_, ddl) in DecisionSchema.Concat(ArchiveSchema)) Execute(ddl, tx);
        InsertArchiveNodes(initial.Nodes, tx); InsertArchiveReducer(reducer, tx);
        Execute($"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion};", tx);
        tx.Commit(); ValidateSchemaVersion(SchemaVersion);
    }

    internal void RequireStagedArchive(Did2MessagingArchiveBuilder.Result staged, Did2MessagingArchiveReducer reducer)
    {
        foreach (var node in staged.Nodes)
        {
            var actual = ReadArchiveNode(node.Digest) ?? throw new CryptographicException("A named staging archive node is absent.");
            if (!Fixed(actual.Span, node.Exact.Span)) throw new CryptographicException("A staging archive node differs byte for byte.");
        }
        using var query = Command("SELECT hash,exact,typeof(hash),length(hash),typeof(exact),length(exact) FROM archive_reducers WHERE hash=$hash;");
        query.Parameters.AddWithValue("$hash", reducer.Digest.ToArray()); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(2) != "blob" || row.GetInt64(3) != 32 || row.GetString(4) != "blob" || row.GetInt64(5) != Did2MessagingArchiveReducer.Bytes ||
            !Fixed(row.GetFieldValue<byte[]>(0), reducer.Digest.Span) || !Fixed(row.GetFieldValue<byte[]>(1), reducer.Exact.Span) || row.Read())
            throw new CryptographicException("A named staging archive reducer is absent or changed.");
    }

    internal void RequireArchiveMirror(SqliteTransaction? tx = null)
    {
        var root = archiveRoot ?? throw new InvalidDataException("Independent messaging archive root is absent.");
        root.RequireSource(historyRoot);
        using var command = Command("SELECT singleton,exact,typeof(exact),length(exact) FROM archive_state;", tx);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetInt64(0) != 1 || row.GetString(2) != "blob" || row.GetInt64(3) != Did2MessagingArchiveRoot.Bytes ||
            !Fixed(row.GetFieldValue<byte[]>(1), root.Exact.Span) || row.Read())
            throw new CryptographicException("Messaging archive SQL mirror differs from its actual independent root.");
        _ = ReadArchiveReducer(tx);
    }

    private Did2MessagingArchiveReducer ReadArchiveReducer(SqliteTransaction? tx = null)
    {
        var root = archiveRoot ?? throw new InvalidDataException("Independent messaging archive root is absent.");
        using var command = Command("SELECT exact,typeof(hash),length(hash),typeof(exact),length(exact),hash FROM archive_reducers WHERE hash=$hash;", tx);
        command.Parameters.AddWithValue("$hash", root.SummaryHash.ToArray()); using var row = command.ExecuteReader();
        if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) != 32 || row.GetString(3) != "blob" || row.GetInt64(4) != Did2MessagingArchiveReducer.Bytes ||
            !Fixed(row.GetFieldValue<byte[]>(5), root.SummaryHash))
            throw new CryptographicException("Messaging archive reducer is missing or noncanonical.");
        var reducer = Did2MessagingArchiveReducer.Decode(row.GetFieldValue<byte[]>(0), scope); reducer.RequireRoot(root);
        if (row.Read()) throw new CryptographicException("Messaging archive reducer is not unique.");
        return reducer;
    }

    private ReadOnlyMemory<byte>? ReadArchiveNode(ReadOnlyMemory<byte> digest, SqliteTransaction? tx = null)
    {
        if (digest.Length != 32) throw new InvalidDataException("Archive node selector has the wrong width.");
        using var command = Command("SELECT exact,typeof(hash),length(hash),typeof(exact),length(exact),hash FROM archive_nodes WHERE hash=$hash;", tx);
        command.Parameters.AddWithValue("$hash", digest.ToArray()); using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        if (row.GetString(1) != "blob" || row.GetInt64(2) != 32 || row.GetString(3) != "blob" || row.GetInt64(4) is < 104 or > 320 ||
            !Fixed(row.GetFieldValue<byte[]>(5), digest.Span))
            throw new CryptographicException("Messaging archive node has a noncanonical storage shape.");
        var node = Did2MessagingArchivePatricia.Decode(scope, row.GetFieldValue<byte[]>(0));
        if (!Fixed(node.Digest.Span, digest.Span) || row.Read()) throw new CryptographicException("Messaging archive node hash/uniqueness differs.");
        return node.Exact;
    }

    private byte[]? ReadArchiveFact(Did2MessagingArchiveFamily family, ReadOnlySpan<byte> selector,
        SqliteTransaction tx, List<Did2MessagingArchivePatricia.Node>? visited = null)
    {
        var root = archiveRoot ?? throw new InvalidDataException("Independent messaging archive root is absent.");
        var expected = root.PatriciaHash.ToArray(); var key = Did2MessagingArchivePatricia.Key(scope, family, selector);
        var path = new List<ReadOnlyMemory<byte>>();
        while (!Fixed(expected, Did2MessagingArchiveEncoding.EmptyHash(scope)))
        {
            if (path.Count == Did2MessagingArchivePatricia.MaximumProofNodes) throw new CryptographicException("Archive proof exceeds its closed depth.");
            var raw = ReadArchiveNode(expected, tx) ?? throw new CryptographicException("Archive proof is missing a named immutable node.");
            var node = Did2MessagingArchivePatricia.Decode(scope, raw.Span); path.Add(raw); visited?.Add(node);
            if (node.IsLeaf || !ArchivePrefixMatches(key, node.KeyOrPrefix, node.Bit)) break;
            expected = ((key[node.Bit / 8] & (1 << (7 - node.Bit % 8))) != 0 ? node.RightHash : node.LeftHash).ToArray();
        }
        return Did2MessagingArchivePatricia.VerifyProof(scope, root.PatriciaHash, family, selector, path);
    }

    private static bool ArchivePrefixMatches(ReadOnlySpan<byte> key, ReadOnlySpan<byte> prefix, int bits)
    {
        var bytes = bits / 8; if (!key[..bytes].SequenceEqual(prefix[..bytes])) return false;
        return bits % 8 == 0 || (key[bytes] & (0xff << (8 - bits % 8))) == prefix[bytes];
    }

    private void InsertArchiveNodes(IEnumerable<Did2MessagingArchivePatricia.Node> nodes, SqliteTransaction tx)
    {
        var unique = new Dictionary<string, Did2MessagingArchivePatricia.Node>(StringComparer.Ordinal);
        foreach (var node in nodes)
        {
            var decoded = Did2MessagingArchivePatricia.Decode(scope, node.Exact.Span);
            if (!Fixed(decoded.Digest.Span, node.Digest.Span)) throw new CryptographicException("Archive insertion digest differs.");
            var id = Convert.ToHexString(node.Digest.Span);
            if (unique.TryGetValue(id, out var prior) && !Fixed(prior.Exact.Span, node.Exact.Span))
                throw new CryptographicException("Archive insertion repeats a digest with different exact bytes.");
            unique[id] = node;
        }
        foreach (var node in unique.OrderBy(static value => value.Key, StringComparer.Ordinal).Select(static value => value.Value))
        {
            using var insert = Command("INSERT OR IGNORE INTO archive_nodes(hash,exact) VALUES($hash,$exact);", tx);
            insert.Parameters.AddWithValue("$hash", node.Digest.ToArray()); insert.Parameters.AddWithValue("$exact", node.Exact.ToArray()); insert.ExecuteNonQuery();
            var actual = ReadArchiveNode(node.Digest, tx) ?? throw new IOException("Archive node insertion readback is absent.");
            if (!Fixed(actual.Span, node.Exact.Span)) throw new CryptographicException("Immutable archive node collision differs byte for byte.");
        }
    }

    private void InsertArchiveReducer(Did2MessagingArchiveReducer reducer, SqliteTransaction tx)
    {
        var decoded = Did2MessagingArchiveReducer.Decode(reducer.Exact.Span, scope);
        using var insert = Command("INSERT OR IGNORE INTO archive_reducers(hash,exact) VALUES($hash,$exact);", tx);
        insert.Parameters.AddWithValue("$hash", decoded.Digest.ToArray()); insert.Parameters.AddWithValue("$exact", decoded.Exact.ToArray()); insert.ExecuteNonQuery();
        using var readback = Command("SELECT exact,typeof(exact),length(exact),hash,typeof(hash),length(hash) FROM archive_reducers WHERE hash=$hash;", tx);
        readback.Parameters.AddWithValue("$hash", decoded.Digest.ToArray()); using var row = readback.ExecuteReader();
        if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) != Did2MessagingArchiveReducer.Bytes || row.GetString(4) != "blob" || row.GetInt64(5) != 32 ||
            !Fixed(row.GetFieldValue<byte[]>(3), decoded.Digest.Span) || !Fixed(row.GetFieldValue<byte[]>(0), decoded.Exact.Span) || row.Read())
            throw new CryptographicException("Immutable archive reducer collision differs byte for byte.");
    }

    private void ReplaceArchiveMirror(Did2MessagingArchiveRoot root, SqliteTransaction tx, Did2MessagingArchiveRoot? expected)
    {
        using (var check = Command("SELECT singleton,exact,typeof(exact),length(exact) FROM archive_state;", tx))
        using (var row = check.ExecuteReader())
        {
            if (!row.Read())
            {
                if (expected is not null) throw new CryptographicException("An indexed archive mirror is absent; no repair is allowed.");
            }
            else if (row.GetInt64(0) != 1 || row.GetString(2) != "blob" || row.GetInt64(3) != 608 ||
                !(Fixed(row.GetFieldValue<byte[]>(1), root.Exact.Span) ||
                  expected is not null && Fixed(row.GetFieldValue<byte[]>(1), expected.Exact.Span)) || row.Read())
                throw new CryptographicException("Archive mirror differs from the exact phase-owned predecessor/successor.");
        }
        using var update = Command("INSERT INTO archive_state(singleton,exact) VALUES(1,$exact) ON CONFLICT(singleton) DO UPDATE SET exact=excluded.exact;", tx);
        update.Parameters.AddWithValue("$exact", root.Exact.ToArray()); if (update.ExecuteNonQuery() != 1) throw new IOException("Archive mirror replacement was not singular.");
    }
}
