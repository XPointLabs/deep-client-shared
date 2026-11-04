using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    private bool HasDecisionTable => !archiveEnrollment || archiveEnrollmentVersion == 6;

    private void RequireRouteDecisionAppend(OwnedDid2MessagingMutation mutation, SqliteTransaction tx)
    {
        var body = Did2RouteHistoryDecision.Decode(mutation.RouteDecisionBody, scope); body.RequireBefore(mutation.Predecessor);
        var headers = ReadJournal(out var stable, tx); RequireSame(mutation.Predecessor, stable);
        using var previous = ReadSubjectDecision(body.Subject, ReadArchiveReducer(tx), headers, tx);
        RequireDecisionTransition(previous, body);
        RequireRouteDecisionReferences(body, tx);
    }

    private void RequireRouteDecisionReferences(Did2RouteHistoryDecision body, SqliteTransaction tx)
    {
        foreach (var reference in new[] { body.PreviousDecision, body.Selected, body.C.Reference, body.P.Reference, body.L,
            body.FirstFault, body.Consent, body.Conflicting.Reference })
        {
            if (reference.IsAbsent) continue;
            RequireNativeReference(reference, tx);
            using var actual = ReadArchiveOriginal(reference, tx);
            if (reference.Kind == 2 && reference.Direction is not (1 or 2)) throw new CryptographicException("A route decision names Braid control as public route evidence.");
        }
    }

    internal void RequireRouteDecisionSources(OwnedDid2MessagingMutation mutation)
    {
        if (mutation.Kind != 6 || !Fixed(scope.Exact, mutation.Scope.Exact)) throw new InvalidDataException("Paired decision source read has another native purpose.");
        using var tx = connection.BeginTransaction(deferred: true);
        var actual = VerifyActiveTip(tx, null, out _);
        var after = mutation.Successor.Cleanup(scope).Stable(scope);
        if (!Fixed(actual.Exact.Span, mutation.Predecessor.Exact.Span) && !Fixed(actual.Exact.Span, after.Exact.Span))
            throw new CryptographicException("Recovered route decision has another actual native floor.");
        RequireRouteDecisionReferences(Did2RouteHistoryDecision.Decode(mutation.RouteDecisionBody, scope), tx);
    }

    internal IReadOnlyList<Did2MessagingArchiveOriginal> ReadRouteHistoryDecisionAuthoredSources(OwnedDid2MessagingMutation mutation)
    {
        if (mutation.Kind != 6 || !Fixed(scope.Exact, mutation.Scope.Exact)) throw new InvalidDataException("Recovery source selection has another native decision purpose.");
        using var tx = connection.BeginTransaction(deferred: true);
        var actual = VerifyActiveTip(tx, null, out _); var after = mutation.Successor.Cleanup(scope).Stable(scope);
        if (!Fixed(actual.Exact.Span, mutation.Predecessor.Exact.Span) && !Fixed(actual.Exact.Span, after.Exact.Span))
            throw new CryptographicException("Recovery source selection lost its exact decision floor.");
        var body = Did2RouteHistoryDecision.Decode(mutation.RouteDecisionBody, scope); RequireRouteDecisionReferences(body, tx);
        var originals = new List<Did2MessagingArchiveOriginal>(); var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var reference in new[] { body.Selected, body.C.Reference, body.P.Reference, body.L, body.FirstFault, body.Consent, body.Conflicting.Reference })
                if (reference.Kind == 2 && reference.Direction == 1 && seen.Add(Id(reference))) originals.Add(ReadArchiveOriginal(reference, tx));
            return originals;
        }
        catch { foreach (var original in originals) original.Dispose(); throw; }
    }

    internal OwnedDid2MessagingMutation ReadStoredRouteDecisionMutation(Did2MessagingFloor pending)
    {
        if (pending.Phase is not (2 or 3)) throw new InvalidDataException("Stored decision recovery requires actual pending or cleanup custody.");
        using var tx = connection.BeginTransaction(deferred: true);
        var headers = ReadJournal(out var actual, tx); VerifyRows(headers, actual, tx);
        var expected = pending.Phase == 2 ? pending.Cleanup(scope).Stable(scope) : pending.Stable(scope);
        RequireSame(expected, actual);
        if (headers.Count == 0 || headers[^1][5] != 6) throw new InvalidDataException("Cleanup is not a local route-history decision.");
        var reference = CaptureDecisionReference(pending.Ordinal, headers[^1], tx);
        using var decision = ReadRouteHistoryDecision(reference, tx);
        var exact = new byte[Did2MessagingFloor.MetadataBytes + Did2RouteHistoryDecision.Bytes];
        var phase2 = pending.Exact.ToArray(); phase2[1] = 2;
        try
        {
            decision.Metadata.Span.CopyTo(exact); decision.Body.Exact.Span.CopyTo(exact.AsSpan(Did2MessagingFloor.MetadataBytes));
            return OwnedDid2MessagingMutation.RecoverProtectedPending(scope, Did2MessagingFloor.Decode(phase2, scope), exact);
        }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(phase2); }
    }

    internal bool HasCurrentRouteDecision(Did2MessagingFloor pending)
    {
        using var tx = connection.BeginTransaction(deferred: true); var headers = ReadJournal(out var tip, tx); VerifyRows(headers, tip, tx);
        return headers.Count != 0 && headers[^1][5] == 6 && tip.Ordinal == pending.Ordinal;
    }

    internal Did2RouteHistoryStoredDecision ReadRouteHistoryDecision(Did2MessagingArchiveReference reference)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        _ = VerifyActiveTip(tx, null, out _);
        RequireNativeReference(reference, tx);
        return ReadRouteHistoryDecision(reference, tx);
    }

    private Did2RouteHistoryStoredDecision ReadRouteHistoryDecision(Did2MessagingArchiveReference reference, SqliteTransaction tx)
    {
        if (!HasDecisionTable || reference.Kind != 3) throw new InvalidDataException("A selected local decision requires its exact immutable source kind.");
        using var query = Command("SELECT rowid,operation,ordinal,decision,metadata,typeof(rowid),typeof(operation),length(operation)," +
            "typeof(ordinal),typeof(decision),length(decision),typeof(metadata),length(metadata) FROM route_decisions WHERE rowid=$rowid;", tx);
        query.Parameters.AddWithValue("$rowid", checked((long)reference.RowId)); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(5) != "integer" || row.GetString(6) != "blob" || row.GetInt64(7) != 32 ||
            row.GetString(8) != "integer" || row.GetString(9) != "blob" || row.GetInt64(10) != Did2RouteHistoryDecision.Bytes ||
            row.GetString(11) != "blob" || row.GetInt64(12) != Did2MessagingFloor.MetadataBytes ||
            row.GetInt64(0) != checked((long)reference.RowId) || row.GetInt64(2) != checked((long)reference.Ordinal))
            throw new CryptographicException("Selected route decision has a different actual rowid/type/length.");
        var operation = row.GetFieldValue<byte[]>(1); var body = row.GetFieldValue<byte[]>(3); var metadata = row.GetFieldValue<byte[]>(4);
        try
        {
            if (!Fixed(operation, reference.Operation) || !Fixed(SHA256.HashData(metadata), reference.MetadataHash))
                throw new CryptographicException("Selected route decision changed its immutable operation or metadata.");
            RequireUniqueOriginal(operation, reference.Ordinal, tx);
            var decision = VerifyRouteDecisionRow(reference.Ordinal, operation, metadata, body);
            if (row.Read()) throw new CryptographicException("Selected route decision rowid is not unique.");
            var result = new Did2RouteHistoryStoredDecision(reference, metadata, decision); metadata = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(metadata); }
    }

    private Did2RouteHistoryDecision VerifyRouteDecisionRow(ulong ordinal, ReadOnlySpan<byte> operation,
        ReadOnlySpan<byte> metadata, ReadOnlySpan<byte> body)
    {
        OwnedDid2MessagingMutation.ValidateMetadata(metadata);
        var before = Did2MessagingFloor.Decode(metadata.Slice(8, Did2MessagingFloor.Bytes), scope);
        OwnedDid2MessagingMutation.ValidateMetadataTransition(metadata, scope, before);
        var decision = Did2RouteHistoryDecision.Decode(body, scope); decision.RequireBefore(before);
        if (metadata[5] != 6 || before.Ordinal == ulong.MaxValue || ordinal != before.Ordinal + 1 ||
            !Fixed(metadata.Slice(268, 32), operation) || !Fixed(metadata.Slice(300, 32), SHA256.HashData(body)) ||
            !Fixed(decision.Operation(scope, before), operation))
            throw new CryptographicException("Native route decision lost its exact body/operation/predecessor.");
        return decision;
    }

    private Did2MessagingArchiveReference CaptureDecisionReference(ulong ordinal, ReadOnlySpan<byte> metadata, SqliteTransaction tx)
    {
        using var query = Command("SELECT rowid,operation,typeof(rowid),typeof(operation),length(operation) FROM route_decisions WHERE ordinal=$ordinal;", tx);
        query.Parameters.AddWithValue("$ordinal", checked((long)ordinal)); using var row = query.ExecuteReader();
        if (!row.Read() || row.GetString(2) != "integer" || row.GetString(3) != "blob" || row.GetInt64(4) != 32 || row.GetInt64(0) <= 0 ||
            !Fixed(row.GetFieldValue<byte[]>(1), metadata.Slice(268, 32))) throw new CryptographicException("Native route decision lost its actual indexed row.");
        var result = Did2MessagingArchiveReference.Decision(ordinal, checked((ulong)row.GetInt64(0)), metadata.Slice(268, 32), SHA256.HashData(metadata));
        if (row.Read()) throw new CryptographicException("Native route decision ordinal is not unique.");
        return result;
    }

    private void RequireNativeReference(Did2MessagingArchiveReference reference, SqliteTransaction tx)
    {
        if (reference.IsAbsent) return;
        if (reference.Kind == 1)
        {
            var initial = ReadInitialMetadata(tx);
            if (!Fixed(SHA256.HashData(initial), reference.MetadataHash)) throw new CryptographicException("Original relationship anchor changed.");
            return;
        }
        if (reference.Ordinal <= WorkingBasis.Ordinal)
        {
            var selector = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(selector, reference.Ordinal);
            var ordinal = ReadArchiveFact(Did2MessagingArchiveFamily.Ordinal, selector, tx);
            var operation = ReadArchiveFact(Did2MessagingArchiveFamily.Operation, reference.Operation, tx);
            if (ordinal is null || operation is null || !Fixed(ordinal, reference.Exact.Span) || !Fixed(operation, reference.Exact.Span))
                throw new CryptographicException("Selected original is not named by both actual archive facts.");
        }
        else
        {
            using var query = Command("SELECT metadata,typeof(metadata),length(metadata) FROM journal WHERE ordinal=$ordinal;", tx);
            query.Parameters.AddWithValue("$ordinal", checked((long)reference.Ordinal)); using var row = query.ExecuteReader();
            if (!row.Read() || row.GetString(1) != "blob" || row.GetInt64(2) != 672) throw new CryptographicException("Selected source is absent from the complete working suffix.");
            var metadata = row.GetFieldValue<byte[]>(0);
            if (!Fixed(SHA256.HashData(metadata), reference.MetadataHash) || !Fixed(metadata.AsSpan(268, 32), reference.Operation) ||
                (reference.Kind == 3 ? metadata[5] != 6 : metadata[5] is not (2 or 5) || metadata[6] != reference.Direction) || row.Read())
                throw new CryptographicException("Selected source differs from its authenticated working metadata.");
        }
    }

    private void RequireNoCrossTableCollision(ReadOnlySpan<byte> operation, ulong ordinal, SqliteTransaction tx)
    {
        using var query = Command("SELECT count(*) FROM (SELECT operation,ordinal FROM events WHERE operation=$op OR ordinal=$ordinal" +
            (HasDecisionTable ? " UNION ALL SELECT operation,ordinal FROM route_decisions WHERE operation=$op OR ordinal=$ordinal" : "") + ");", tx);
        query.Parameters.AddWithValue("$op", operation.ToArray()); query.Parameters.AddWithValue("$ordinal", checked((long)ordinal));
        if (Convert.ToInt64(query.ExecuteScalar()) != 0) throw new CryptographicException("Native operation/ordinal collides across immutable source tables.");
    }

    private void RequireUniqueOriginal(ReadOnlySpan<byte> operation, ulong ordinal, SqliteTransaction? tx)
    {
        using var query = Command("SELECT count(*) FROM (SELECT operation,ordinal FROM events WHERE operation=$op OR ordinal=$ordinal" +
            (HasDecisionTable ? " UNION ALL SELECT operation,ordinal FROM route_decisions WHERE operation=$op OR ordinal=$ordinal" : "") + ");", tx);
        query.Parameters.AddWithValue("$op", operation.ToArray()); query.Parameters.AddWithValue("$ordinal", checked((long)ordinal));
        if (Convert.ToInt64(query.ExecuteScalar()) != 1) throw new CryptographicException("Native original is not unique across operation/ordinal source domains.");
    }

    private void VerifyWorkingRouteDecisions(IReadOnlyList<byte[]> headers, SqliteTransaction? tx)
    {
        if (!HasDecisionTable) return;
        using var query = Command("SELECT rowid,ordinal,operation,decision,metadata,typeof(rowid),typeof(ordinal),typeof(operation)," +
            "length(operation),typeof(decision),length(decision),typeof(metadata),length(metadata) FROM route_decisions WHERE ordinal>$basis ORDER BY ordinal;", tx);
        query.Parameters.AddWithValue("$basis", checked((long)WorkingBasis.Ordinal)); using var row = query.ExecuteReader(); var count = 0;
        while (row.Read())
        {
            var ordinal = row.GetInt64(1);
            if (row.GetString(5) != "integer" || row.GetInt64(0) <= 0 || row.GetString(6) != "integer" || ordinal <= 0 ||
                (ulong)ordinal <= WorkingBasis.Ordinal || (ulong)ordinal - WorkingBasis.Ordinal > (ulong)headers.Count ||
                row.GetString(7) != "blob" || row.GetInt64(8) != 32 || row.GetString(9) != "blob" || row.GetInt64(10) != 1024 ||
                row.GetString(11) != "blob" || row.GetInt64(12) != 672) throw new InvalidDataException("Working route decision has a hostile SQL shape.");
            var operation = row.GetFieldValue<byte[]>(2); var body = row.GetFieldValue<byte[]>(3); var metadata = row.GetFieldValue<byte[]>(4);
            try
            {
                var expected = headers[checked((int)((ulong)ordinal - WorkingBasis.Ordinal - 1))];
                if (!Fixed(metadata, expected)) throw new CryptographicException("Working route decision differs from its complete native journal.");
                _ = VerifyRouteDecisionRow((ulong)ordinal, operation, metadata, body);
                using var collision = Command("SELECT count(*) FROM events WHERE operation=$op OR ordinal=$ordinal;", tx);
                collision.Parameters.AddWithValue("$op", operation); collision.Parameters.AddWithValue("$ordinal", ordinal);
                if (Convert.ToInt64(collision.ExecuteScalar()) != 0) throw new CryptographicException("Working native sources collide across tables.");
            }
            finally { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(metadata); }
            count = checked(count + 1);
        }
        if (count != headers.Count(static header => header[5] == 6)) throw new CryptographicException("Working native journal lost a route decision.");
    }
}
