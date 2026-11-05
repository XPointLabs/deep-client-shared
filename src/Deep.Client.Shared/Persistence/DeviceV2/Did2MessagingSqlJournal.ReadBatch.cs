using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    internal const int MaximumOperationReadBatch = 32;

    // Only whole-group history uses this composition. It is consumed inside a
    // single WithSql callback, never across an await/provider or another call.
    // Each returned page still owns at most32 envelopes and must be disposed
    // before the next page. No transaction can be supplied by the caller.
    internal GroupHistorySnapshot OpenGroupHistorySnapshot(Did2MessagingFloor protectedStable)
        => GroupHistorySnapshot.Open(this, protectedStable);

    internal ref struct GroupHistorySnapshot
    {
        private readonly Did2MessagingSqlJournal owner;
        private readonly SqliteTransaction transaction;
        private readonly List<byte[]> headers;
        private bool disposed;

        private GroupHistorySnapshot(Did2MessagingSqlJournal owner, SqliteTransaction transaction, List<byte[]> headers)
        { this.owner = owner; this.transaction = transaction; this.headers = headers; }

        internal static GroupHistorySnapshot Open(Did2MessagingSqlJournal owner, Did2MessagingFloor floor)
        {
            _ = Did2MessagingFloor.Decode(floor.Exact.Span, owner.scope);
            if (floor.Phase != 1 || floor.Status != 1)
                throw new InvalidDataException("Group history requires active stable native custody.");
            if (owner.archiveRoot is null) throw new InvalidOperationException("Whole-group history requires indexed native custody.");
            var transaction = owner.connection.BeginTransaction(deferred: true);
            List<byte[]> headers = [];
            try
            {
                var actual = owner.activeHistory
                    ? owner.VerifyActiveTip(transaction, null, out headers)
                    : owner.VerifyTipInTransaction(transaction, out headers);
                owner.RequireSame(floor, actual);
                return new(owner, transaction, headers);
            }
            catch
            {
                try { transaction.Dispose(); }
                finally { foreach (var header in headers) CryptographicOperations.ZeroMemory(header); }
                throw;
            }
        }

        internal IReadOnlyList<OwnedDid2MessagingPersistedEvent?> ReadOperations(byte[][] operations)
        {
            if (disposed) throw new ObjectDisposedException(nameof(GroupHistorySnapshot));
            ArgumentNullException.ThrowIfNull(operations);
            var count = operations.Length;
            if (count is < 1 or > MaximumOperationReadBatch) throw new ArgumentException("Unbounded group history page.", nameof(operations));
            var selectors = new List<byte[]>(count);
            var result = new List<OwnedDid2MessagingPersistedEvent?>(count);
            try
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                for (var index = 0; index < count; index++)
                {
                    var input = operations[index];
                    if (input is null || input.Length != 32) throw new ArgumentException("Group history selector has another size.", nameof(operations));
                    var selector = input.AsSpan().ToArray(); selectors.Add(selector);
                    if (Did2MessagingSessionScope.Zero(selector) || !seen.Add(Convert.ToHexString(selector)))
                        throw new ArgumentException("Group history page requires distinct nonzero selectors.", nameof(operations));
                }
                using var selection = new ActiveSelection(selectors);
                // Reuse ONLY verified headers from this physical transaction;
                // both algorithms still prove actual selected archive payloads.
                owner.CaptureIndexedSelection(transaction, selection, headers);
                for (var index = 0; index < count; index++) result.Add(owner.ReadCapturedOrdinaryEvent(selection[index], transaction));
                return result;
            }
            catch { foreach (var item in result) item?.Dispose(); throw; }
            finally { foreach (var selector in selectors) CryptographicOperations.ZeroMemory(selector); }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            try { transaction.Dispose(); }
            finally { foreach (var header in headers) CryptographicOperations.ZeroMemory(header); }
        }
    }

    // Local materialization only. Every invocation verifies the COMPLETE actual
    // SQL state against the independent floor in one read transaction. No await,
    // callback, mutation or previous verification result crosses this snapshot.
    // Bound memory to at most32 selected envelopes/plaintexts; caller owns them.
    internal IReadOnlyList<OwnedDid2MessagingPersistedEvent?> ReadVerifiedOperations(
        Did2MessagingFloor protectedStable, IReadOnlyList<ReadOnlyMemory<byte>> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        var count = operations.Count;
        if (count is < 1 or > MaximumOperationReadBatch)
            throw new ArgumentException("Native operation read batch exceeds its closed bound.", nameof(operations));
        var selectors = new List<byte[]>(count);
        var result = new List<OwnedDid2MessagingPersistedEvent?>(count);
        try
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < count; index++)
            {
                var input = operations[index];
                if (input.Length != 32) throw new ArgumentException("Native operation selector has another size.", nameof(operations));
                var selector = input.ToArray(); selectors.Add(selector);
                if (Did2MessagingSessionScope.Zero(selector) ||
                    !seen.Add(Convert.ToHexString(selector)))
                    throw new ArgumentException("Native operation read batch requires distinct nonzero selectors.", nameof(operations));
            }
            _ = Did2MessagingFloor.Decode(protectedStable.Exact.Span, scope);
            if (protectedStable.Phase != 1 || protectedStable.Status != 1)
                throw new InvalidDataException("Native operation read batch requires active stable custody.");
            using var tx = connection.BeginTransaction(deferred: true);
            if (activeHistory || archiveRoot is not null)
            {
                using var selection = new ActiveSelection(selectors);
                RequireSame(protectedStable, VerifyIndexedSelectedTip(tx, selection, out _));
                for (var index = 0; index < count; index++) result.Add(ReadCapturedOrdinaryEvent(selection[index], tx));
                return result;
            }
            RequireSame(protectedStable, VerifyTipInTransaction(tx));
            using var command = Command("SELECT direction,length(envelope),envelope,length(plaintext),plaintext,metadata,ordinal FROM events WHERE operation=$op;", tx);
            var parameter = command.Parameters.Add("$op", Microsoft.Data.Sqlite.SqliteType.Blob);
            foreach (var selector in selectors)
            {
                parameter.Value = selector;
                using var row = command.ExecuteReader();
                result.Add(ReadSelectedOrdinaryEvent(protectedStable, row));
            }
            return result;
        }
        catch { foreach (var item in result) item?.Dispose(); throw; }
        finally { foreach (var selector in selectors) CryptographicOperations.ZeroMemory(selector); }
    }

    // FULL indexed readers retain their complete cipher/legacy-prefix/working
    // verification, then use the SAME authenticated archive selection as active
    // readers. Legacy unindexed enrollment never enters this seam.
    private Did2MessagingFloor VerifyIndexedSelectedTip(SqliteTransaction transaction, ActiveSelection selection,
        out List<byte[]> headers)
    {
        if (activeHistory) return VerifyActiveTip(transaction, selection, out headers);
        if (archiveRoot is null) throw new InvalidOperationException("Indexed selection requires an independent archive root.");
        var tip = VerifyTipInTransaction(transaction, out headers);
        CaptureIndexedSelection(transaction, selection, headers);
        return tip;
    }

    private void CaptureIndexedSelection(SqliteTransaction transaction, ActiveSelection selection, List<byte[]> headers)
    {
        VerifyActiveHistory(transaction, selection);
        var ordinal = WorkingBasis.Ordinal;
        foreach (var metadata in headers)
        {
            ordinal = checked(ordinal + 1);
            if (metadata[5] is 2 or 5 or 6)
                selection.Observe(ordinal, metadata[6], metadata.AsSpan(268, 32), metadata);
        }
    }
}
