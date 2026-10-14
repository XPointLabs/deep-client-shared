using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

// One SQL expiry owner for cancel, retry-expired and successful ordinary audits.
public sealed partial class SqliteDeepMailboxStore
{
    internal Task<(byte[] Before, byte[] After)> CaptureTerminalAuditExpiryAsync(Did2MessagingSessionScope scope,
        ProtectedDid2DirectTextJournal.State state, IReadOnlyList<ProtectedDid2DirectTextJournal.TerminalAudit> selected,
        CancellationToken ct) => WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction();
            return Task.FromResult(CaptureTerminalAuditExpiry(connection, tx, scope, state, selected, ct));
        }, ct);

    private (byte[] Before, byte[] After) CaptureTerminalAuditExpiry(SqliteConnection connection, SqliteTransaction tx,
        Did2MessagingSessionScope scope, ProtectedDid2DirectTextJournal.State state,
        IReadOnlyList<ProtectedDid2DirectTextJournal.TerminalAudit> selected, CancellationToken ct)
    {
        if (selected.Count is < 1 or > Did2CompactionPlan.MaximumRows)
            throw new InvalidDataException("Terminal audit expiry needs a bounded exact selection.");
        ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
        ValidateOwnedStoppedAudits(connection, tx, state);
        var operations = new HashSet<string>(StringComparer.Ordinal);
        var rows = ReadStoppedAuditFacts(connection, tx);
        foreach (var audit in selected)
        {
            var name = Convert.ToHexString(audit.Operation);
            if (!operations.Add(name) || !state.TerminalAudits.TryGetValue(name, out var actual) ||
                !DirectFixed(actual.Exact, audit.Exact) || !rows.TryGetValue(name, out var row))
                throw new CryptographicException("Terminal audit expiry substituted protected membership.");
            RequireTerminalAuditRow(row, audit);
        }
        return (CompleteApplicationCompactionProjection(connection, tx, scope.Hash, null, ct),
            CompleteApplicationCompactionProjection(connection, tx, scope.Hash, null, ct, omitAudits: operations));
    }

    internal Task ApplyTerminalAuditExpiryAsync(IDeepSecureStorage storage, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, ProtectedDid2DirectTextJournal.State state,
        IReadOnlyList<ProtectedDid2DirectTextJournal.TerminalAudit> selected, HeldDeepIdV2AccountLease held,
        DeepIdV2AccountFileLease lease, CancellationToken ct) => WithReplayConnectionAsync(async connection =>
        {
            using var borrowed = held.BorrowFor(lease);
            if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Application ||
                !DirectFixed(plan.SqlSelector, scope.Hash) || plan.RowCount != selected.Count)
                throw new InvalidDataException("Terminal audit SQL requires its actual staged owner.");
            using var tx = connection.BeginTransaction();
            var effects = CaptureTerminalAuditExpiry(connection, tx, scope, state, selected, ct);
            try
            {
                if (!DirectFixed(effects.Before, plan.SqlBefore) || !DirectFixed(effects.After, plan.SqlAfter))
                    throw new CryptographicException("Terminal audit expiry changed complete SQL effects.");
                var ordered = selected.OrderBy(item => Convert.ToHexString(item.Operation), StringComparer.Ordinal).ToArray();
                for (var index = 0; index < ordered.Length; index++)
                {
                    var row = plan.ReadRow(index);
                    if (row.Action != Did2CompactionPlan.Disposition.ExpiredTerminalAudit ||
                        !DirectFixed(row.Selector.Span, ordered[index].Operation) ||
                        !DirectFixed(row.Commitment.Span, SHA256.HashData(ordered[index].Exact)))
                        throw new CryptographicException("Terminal audit expiry changed its selected row.");
                }
                var roots = await ProtectedDeepIdV2AccountOwner.ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(effects.Before, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                    throw new CryptographicException("Terminal audit predecessors changed before SQL.");
                foreach (var audit in selected)
                {
                    using var delete = connection.CreateCommand(); delete.Transaction = tx;
                    delete.CommandText = "DELETE FROM stopped_work_audit WHERE operation_id=$operation AND reason=$reason;";
                    delete.Parameters.AddWithValue("$operation", audit.Operation.ToArray());
                    delete.Parameters.AddWithValue("$reason", (int)audit.Reason);
                    if (delete.ExecuteNonQuery() != 1) throw new CryptographicException("Terminal audit SQL lost its exact row.");
                }
                if (!DirectFixed(CompleteApplicationCompactionProjection(connection, tx, scope.Hash, null, ct), plan.SqlAfter))
                    throw new CryptographicException("Terminal audit expiry changed unrelated SQL.");
                roots = await ProtectedDeepIdV2AccountOwner.ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(plan.SqlAfter, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                    throw new CryptographicException("Terminal audit guards changed before commit.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit(); return true;
            }
            finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
        }, ct);
}
