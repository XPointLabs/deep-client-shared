using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal sealed record ArchiveBatch(Did2MessagingArchiveBuilder.Result Tree,
        Did2MessagingArchiveReducer Reducer, ulong Cursor, ulong Count);

    internal ArchiveBatch CaptureArchiveEnrollmentBootstrap()
    {
        if (!archiveEnrollment) throw new InvalidOperationException("Only explicit enrollment derives a staging bootstrap.");
        var builder = new Did2MessagingArchiveBuilder(scope, Did2MessagingArchiveEncoding.EmptyHash(scope), static _ => null);
        var empty = Did2MessagingArchiveReducer.Empty(scope);
        if (historyRoot.Basis.Ordinal == 0) return new(builder.Complete(), empty, 0, 0);
        var initial = ReadArchiveInitialSource();
        try
        {
            var replay = new Did2MessagingArchiveSemanticReplay(scope, historyRoot.Basis, empty, builder,
                initial.Metadata, initial.Hello, static _ => throw new InvalidOperationException("A staging bootstrap has no event source."));
            return new(builder.Complete(), replay.Complete(), 0, 0);
        }
        finally { CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello); }
    }

    internal Did2MessagingArchiveReducer ReadEnrollmentReducer(ProtectedDid2MessagingArchiveEnrollment progress)
    {
        using var query = Command("SELECT hash,exact,typeof(hash),length(hash),typeof(exact),length(exact) FROM archive_reducers WHERE hash=$hash;");
        query.Parameters.AddWithValue("$hash", progress.ReducerHash.ToArray()); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(2) != "blob" || row.GetInt64(3) != 32 || row.GetString(4) != "blob" || row.GetInt64(5) != 960 ||
            !Fixed(row.GetFieldValue<byte[]>(0), progress.ReducerHash)) throw new CryptographicException("Actual enrollment staging reducer is absent or noncanonical.");
        var reducer = Did2MessagingArchiveReducer.Decode(row.GetFieldValue<byte[]>(1), scope);
        if (!Fixed(reducer.Digest.Span, progress.ReducerHash) || !Fixed(reducer.Basis.Exact.Span, progress.TargetBasis.Exact.Span) || row.Read())
            throw new CryptographicException("Actual enrollment staging reducer differs from protected progress.");
        return reducer;
    }

    internal Did2MessagingArchiveOriginal ReadArchiveOriginal(Did2MessagingArchiveReference reference)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        return ReadArchiveOriginal(reference, tx);
    }

    private Did2MessagingArchiveOriginal ReadArchiveOriginal(Did2MessagingArchiveReference reference, SqliteTransaction tx)
    {
        using var tuple = ReadArchivedTuple(reference, tx);
        using var query = Command("SELECT rowid,ordinal,direction,operation,metadata,envelope,plaintext,typeof(envelope),length(envelope),typeof(plaintext),length(plaintext) FROM events WHERE rowid=$rowid;", tx);
        query.Parameters.AddWithValue("$rowid", checked((long)reference.RowId)); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetInt64(0) != checked((long)reference.RowId) || row.GetInt64(1) != checked((long)reference.Ordinal) ||
            row.GetInt32(2) != reference.Direction || !Fixed(row.GetFieldValue<byte[]>(3), reference.Operation) ||
            !Fixed(row.GetFieldValue<byte[]>(4), tuple.Metadata) || row.GetString(7) != "blob" || row.GetInt64(8) is < 1 or > 65536 ||
            row.GetString(9) != (reference.Direction == 2 ? "blob" : "null") ||
            (reference.Direction == 2 ? row.IsDBNull(10) || row.GetInt64(10) is < 1 or > 33082 : !row.IsDBNull(10)))
            throw new CryptographicException("Archive selected original lost its exact authenticated source row.");
        var envelope = row.GetFieldValue<byte[]>(5); var plain = reference.Direction == 2 ? row.GetFieldValue<byte[]>(6) : [];
        try
        {
            VerifyHistoricalEvent(reference.Ordinal, reference.Direction, reference.Operation, tuple.Metadata, envelope, plain);
            if (row.Read()) throw new CryptographicException("Archive selected original rowid is not unique.");
            var result = new Did2MessagingArchiveOriginal(reference, tuple.Metadata.ToArray(), envelope, plain);
            envelope = []; plain = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(plain); }
    }

    // The account owner supplies only exact outgoing originals independently
    // joined to its actual authored root/archive/counter. This function freshly
    // rejoins their native event hashes and every input row in one SQL segment.
    internal ArchiveBatch InsertArchiveEnrollmentBatch(ProtectedDid2MessagingArchiveEnrollment progress,
        IReadOnlyList<Did2MessagingArchiveReference> references,
        IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>> authored)
    {
        if (!archiveEnrollment || progress.Phase is not (ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged or
            ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building) || references.Count is < 1 or > 32)
            throw new InvalidOperationException("Enrollment insertion needs exact protected staging and a bounded source batch.");
        ValidateSchemaVersion(6); RequireCipherPolicy();
        var before = ReadEnrollmentReducer(progress);
        var initial = progress.TargetBasis.Ordinal == 0 ? (Metadata: Array.Empty<byte>(), Hello: Array.Empty<byte>()) : ReadArchiveInitialSource();
        var selected = new List<Did2MessagingArchiveOriginal>();
        try
        {
            using var tx = connection.BeginTransaction();
            var builder = new Did2MessagingArchiveBuilder(scope, progress.PatriciaHash, hash => ReadArchiveNode(hash, tx));
            var replay = new Did2MessagingArchiveSemanticReplay(scope, progress.TargetBasis, before, builder,
                initial.Metadata, initial.Hello, Resolve);
            var cursor = progress.Cursor; var count = progress.Count;
            foreach (var reference in references)
            {
                if (reference.Ordinal <= cursor || reference.Ordinal > progress.TargetBasis.Ordinal) throw new CryptographicException("Archive batch changes its frozen cursor/order.");
                var native = ReadArchiveOriginal(reference, tx); selected.Add(native);
                ReadOnlyMemory<byte> own = default;
                if (reference.Direction == 1 && (!authored.TryGetValue(reference.Ordinal, out own) ||
                    !Fixed(SHA256.HashData(own.Span), native.Metadata.AsSpan(300, 32))))
                    throw new CryptographicException("Outgoing archive original lacks its independently authored exact event.");
                replay.Observe(native, own); cursor = reference.Ordinal; count = checked(count + 1);
            }
            if (count > progress.SourceHistory.HistoryCount) throw new CryptographicException("Archive batch exceeds the frozen source count.");
            var tree = builder.Complete(); var reducer = replay.Complete();
            InsertArchiveNodes(tree.Nodes, tx); InsertArchiveReducer(reducer, tx); tx.Commit();
            return new(tree, reducer, cursor, count);

            ReadOnlyMemory<byte> Resolve(Did2MessagingArchiveReference reference)
            {
                if (reference.Kind == 1) return initial.Hello;
                var native = ReadArchiveOriginal(reference, tx); selected.Add(native);
                if (reference.Direction == 2) return native.Plaintext;
                if (reference.Direction != 1 || !authored.TryGetValue(reference.Ordinal, out var own) ||
                    !Fixed(SHA256.HashData(own.Span), native.Metadata.AsSpan(300, 32)))
                    throw new CryptographicException("Archive reducer head lost its independently authored original.");
                return own;
            }
        }
        finally
        {
            foreach (var row in selected) row.Dispose();
            CryptographicOperations.ZeroMemory(initial.Metadata); CryptographicOperations.ZeroMemory(initial.Hello);
        }
    }
}
