using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    internal const ulong StoppedAuditSeconds = 2_592_000;
    private const int MaximumStoppedAudits = ProtectedDid2DirectTextJournal.MaximumTerminalAudits +
        ProtectedDid2ContactStartJournal.MaximumEntries + ProtectedDid2ContactAcceptJournal.MaximumEntries;
    private byte[] stoppedAuditKey = [];
    internal sealed record ControlAuditCustody(byte Kind, byte[] Operation, byte Reason, ulong StoppedAt,
        bool PayloadRetired, byte AuditDisposition);
    private readonly Dictionary<string, ControlAuditCustody> controlAuditCustody = new(StringComparer.Ordinal);
    private bool controlAuditBound;
    internal sealed record StoppedAuditRow(byte[] Operation, byte Reason, ulong StoppedAt, ulong ExpiresAt, byte[] Authenticator);

    // Only the registered account factory binds this independently derived
    // key. SQLCipher knowledge, a supplied row and decoding are not authority.
    internal void BindStoppedAuditKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        if (key.Length != 32 || key.IndexOfAnyExcept((byte)0) < 0 || stoppedAuditKey.Length != 0)
            throw new CryptographicException("Stopped audit requires one registered nonzero key binding.");
        stoppedAuditKey = key.ToArray();
    }

    // The registered held account factory supplies actual protected roots, not
    // a caller assertion. This readback binding grants no network authority.
    internal void BindControlAuditCustody(IReadOnlyList<ControlAuditCustody> rows)
    {
        if (controlAuditBound || stoppedAuditKey.Length != 32 || rows.Count >
            ProtectedDid2ContactStartJournal.MaximumEntries + ProtectedDid2ContactAcceptJournal.MaximumEntries)
            throw new CryptographicException("Control audit custody requires one bounded registered binding.");
        foreach (var row in rows)
        {
            if (row.Kind is not (1 or 2) || row.Reason is not (1 or 2 or 3)) throw new InvalidDataException("Unknown control audit owner.");
            if (row.Reason == 3 && row.StoppedAt == 0 && row.AuditDisposition != 2)
                throw new InvalidDataException("Successful control audit has no protected first time.");
            ProtectedDph2PreClaimJournal.RequireIntent(row.Operation);
            Did2ControlWorkStop.RequireCanonical(row.Reason == 3 ? (byte)0 : row.Reason, row.AuditDisposition,
                row.Reason == 3 ? 0 : row.StoppedAt, row.PayloadRetired, row.Reason == 3 ? row.StoppedAt : 0);
            var id = ControlAuditId(row.Kind, row.Operation);
            try
            {
                if (!controlAuditCustody.TryAdd(Convert.ToHexString(id), row with { Operation = row.Operation.ToArray() }))
                    throw new CryptographicException("Duplicate control audit custody.");
            }
            finally { CryptographicOperations.ZeroMemory(id); }
        }
        controlAuditBound = true;
    }

    private byte[] ControlAuditId(byte kind, ReadOnlySpan<byte> operation)
    {
        if (stoppedAuditKey.Length != 32 || kind is not (1 or 2)) throw new CryptographicException("Control audit ID lost its registered key/owner.");
        ProtectedDph2PreClaimJournal.RequireIntent(operation);
        var domain = "Deep/STORE-V2/control-work-audit-id"u8;
        var input = new byte[domain.Length + 2 + 32];
        try
        {
            domain.CopyTo(input); input[domain.Length + 1] = kind; operation.CopyTo(input.AsSpan(domain.Length + 2));
            return HMACSHA256.HashData(stoppedAuditKey, input);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private StoppedAuditRow NewControlAudit(ControlAuditCustody entry)
    {
        if (!controlAuditBound || entry.Reason is not (1 or 2 or 3) || entry.AuditDisposition == 2 || entry.StoppedAt == 0)
            throw new CryptographicException("Control audit requires actual retained stop custody.");
        var operation = ControlAuditId(entry.Kind, entry.Operation);
        var expiry = checked(entry.StoppedAt + StoppedAuditSeconds);
        return new(operation, entry.Reason, entry.StoppedAt, expiry,
            AuthenticateStoppedAudit(operation, entry.Reason, entry.StoppedAt, expiry));
    }

    private void RequireControlAuditRow(StoppedAuditRow row, ControlAuditCustody entry)
    {
        var expected = NewControlAudit(entry);
        try
        {
            if (row.Reason != expected.Reason || row.StoppedAt != expected.StoppedAt || row.ExpiresAt != expected.ExpiresAt ||
                !DirectFixed(row.Operation, expected.Operation) || !DirectFixed(row.Authenticator, expected.Authenticator))
                throw new CryptographicException("Control audit differs from independent protected stop custody.");
        }
        finally { CryptographicOperations.ZeroMemory(expected.Operation); CryptographicOperations.ZeroMemory(expected.Authenticator); }
    }

    private byte[] AuthenticateStoppedAudit(ReadOnlySpan<byte> operation, byte reason, ulong stoppedAt, ulong expiresAt)
    {
        if (stoppedAuditKey.Length != 32) throw new CryptographicException("Stopped audit lost its registered authentication key.");
        var domain = "Deep/STORE-V2/stopped-work-audit-row"u8;
        var input = new byte[domain.Length + 1 + 32 + 1 + 16];
        try
        {
            domain.CopyTo(input); operation.CopyTo(input.AsSpan(domain.Length + 1)); input[domain.Length + 33] = reason;
            BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(domain.Length + 34), stoppedAt);
            BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(domain.Length + 42), expiresAt);
            return HMACSHA256.HashData(stoppedAuditKey, input);
        }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private StoppedAuditRow NewStoppedAudit(ProtectedDid2DirectTextJournal.Entry entry)
    {
        if (!entry.WorkStopped || entry.StoppedAtUpper == 0)
            throw new CryptographicException("Audit construction requires retained actual stop metadata.");
        var expiry = checked(entry.StoppedAtUpper + StoppedAuditSeconds);
        return new(entry.Operation.ToArray(), (byte)entry.StopReason, entry.StoppedAtUpper, expiry,
            AuthenticateStoppedAudit(entry.Operation, (byte)entry.StopReason, entry.StoppedAtUpper, expiry));
    }

    private StoppedAuditRow NewTerminalAudit(ProtectedDid2DirectTextJournal.Entry entry)
    {
        using var metadata = ProtectedDid2DirectTextJournal.TerminalAudit.FromStored(entry);
        return NewTerminalAudit(metadata);
    }

    private StoppedAuditRow NewTerminalAudit(ProtectedDid2DirectTextJournal.TerminalAudit entry)
    {
        var expiry = checked(entry.TerminalAtUpper + StoppedAuditSeconds);
        return new(entry.Operation.ToArray(), entry.Reason, entry.TerminalAtUpper, expiry,
            AuthenticateStoppedAudit(entry.Operation, entry.Reason, entry.TerminalAtUpper, expiry));
    }

    private void RequireTerminalAuditRow(StoppedAuditRow row, ProtectedDid2DirectTextJournal.TerminalAudit entry)
    {
        var expected = NewTerminalAudit(entry);
        try
        {
            if (row.Reason != expected.Reason || row.StoppedAt != expected.StoppedAt || row.ExpiresAt != expected.ExpiresAt ||
                !DirectFixed(row.Operation, expected.Operation) || !DirectFixed(row.Authenticator, expected.Authenticator))
                throw new CryptographicException("Successful audit differs from independent protected terminal custody.");
        }
        finally { CryptographicOperations.ZeroMemory(expected.Operation); CryptographicOperations.ZeroMemory(expected.Authenticator); }
    }

    // Bounded facts only. No key, payload, scope, content hash, manifest,
    // request or ciphertext is stored in this audit class.
    private static SortedDictionary<string, StoppedAuditRow> ReadStoppedAuditFacts(SqliteConnection connection, SqliteTransaction tx)
    {
        using var count = connection.CreateCommand(); count.Transaction = tx;
        count.CommandText = "SELECT count(*) FROM stopped_work_audit;";
        if (Convert.ToInt64(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) is < 0 or > MaximumStoppedAudits)
            throw new InvalidDataException("Stopped audit exceeds its bounded working-owner capacity.");
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT operation_id,reason,stopped_at,expires_at,authenticator,typeof(operation_id),length(operation_id),typeof(reason),typeof(stopped_at),typeof(expires_at),typeof(authenticator),length(authenticator) FROM stopped_work_audit ORDER BY operation_id;";
        using var reader = command.ExecuteReader(); var rows = new SortedDictionary<string, StoppedAuditRow>(StringComparer.Ordinal);
        while (reader.Read())
        {
            if (reader.GetString(5) != "blob" || reader.GetInt64(6) != 32 || reader.GetString(10) != "blob" || reader.GetInt64(11) != 32 ||
                reader.GetString(7) != "integer" || reader.GetString(8) != "integer" || reader.GetString(9) != "integer" ||
                reader.GetInt64(1) is not (1 or 2 or 3) || reader.GetInt64(2) is < 1 or > long.MaxValue - (long)StoppedAuditSeconds ||
                reader.GetInt64(3) != checked(reader.GetInt64(2) + (long)StoppedAuditSeconds))
                throw new CryptographicException("Stopped audit has a hostile type, size or terminal deadline.");
            var operation = reader.GetFieldValue<byte[]>(0);
            ProtectedDph2PreClaimJournal.RequireIntent(operation);
            rows.Add(Convert.ToHexString(operation), new(operation, checked((byte)reader.GetInt64(1)),
                checked((ulong)reader.GetInt64(2)), checked((ulong)reader.GetInt64(3)), reader.GetFieldValue<byte[]>(4)));
        }
        return rows;
    }

    private void ValidateOwnedStoppedAudits(SqliteConnection connection, SqliteTransaction tx, ProtectedDid2DirectTextJournal.State journal)
    {
        var rows = ReadStoppedAuditFacts(connection, tx);
        foreach (var pair in controlAuditCustody)
        {
            var entry = pair.Value;
            if (!entry.PayloadRetired || entry.AuditDisposition != 1)
            {
                if (rows.ContainsKey(pair.Key)) throw new CryptographicException("Absent/working/expired control audit cannot retain a SQL row.");
                continue;
            }
            if (!rows.Remove(pair.Key, out var row)) throw new CryptographicException("Control stop lost its mandatory independent audit row.");
            RequireControlAuditRow(row, entry);
        }
        foreach (var pair in journal.TerminalAudits)
        {
            if (!rows.Remove(pair.Key, out var row)) throw new CryptographicException("Successful work lost its mandatory independent audit row.");
            RequireTerminalAuditRow(row, pair.Value);
        }
        if (rows.Count != 0)
            throw new CryptographicException("An audit row cannot resurrect absent, active or expired work.");
    }

    private static void InsertStoppedAudit(SqliteConnection connection, SqliteTransaction tx, StoppedAuditRow row)
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "INSERT INTO stopped_work_audit VALUES($op,$reason,$at,$until,$mac);";
        command.Parameters.AddWithValue("$op", row.Operation); command.Parameters.AddWithValue("$reason", (int)row.Reason);
        command.Parameters.AddWithValue("$at", checked((long)row.StoppedAt)); command.Parameters.AddWithValue("$until", checked((long)row.ExpiresAt));
        command.Parameters.AddWithValue("$mac", row.Authenticator);
        if (command.ExecuteNonQuery() != 1) throw new CryptographicException("Stopped audit insertion lost its selected operation.");
    }

    internal Task ValidateCompleteStoppedAuditsAsync(ProtectedDid2DirectTextJournal.State ordinary, CancellationToken ct)
        => WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateOwnedStoppedAudits(connection, tx, ordinary);
            return Task.FromResult(true);
        }, ct);

    internal Task<(byte[] Before, byte[] After)> CaptureControlAuditEffectsAsync(Did2MessagingSessionScope scope,
        byte kind, ReadOnlyMemory<byte> operation, bool expire, ProtectedDid2DirectTextJournal.State ordinary, CancellationToken ct)
        => WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction();
            return Task.FromResult(CaptureControlAuditEffects(connection, tx, scope.Hash, kind, operation.Span, expire, ordinary, ct));
        }, ct);

    private (byte[] Before, byte[] After) CaptureControlAuditEffects(SqliteConnection connection, SqliteTransaction tx,
        ReadOnlySpan<byte> selector, byte kind, ReadOnlySpan<byte> operation, bool expire,
        ProtectedDid2DirectTextJournal.State ordinary, CancellationToken ct)
    {
        if (!controlAuditBound) throw new CryptographicException("Control audit capture lost independent registered custody.");
        var id = ControlAuditId(kind, operation);
        try
        {
            if (!controlAuditCustody.TryGetValue(Convert.ToHexString(id), out var entry) || entry.Kind != kind ||
                !DirectFixed(entry.Operation, operation) || (expire ? !entry.PayloadRetired || entry.AuditDisposition != 1 :
                    entry.PayloadRetired || entry.AuditDisposition != 0))
                throw new CryptographicException("Control audit selection is not the exact actual working/retained stop.");
            ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
            ValidateOwnedStoppedAudits(connection, tx, ordinary);
            var rows = ReadStoppedAuditFacts(connection, tx);
            if (expire)
            {
                if (!rows.TryGetValue(Convert.ToHexString(id), out var row)) throw new CryptographicException("Selected control audit is missing.");
                RequireControlAuditRow(row, entry);
            }
            else if (rows.ContainsKey(Convert.ToHexString(id))) throw new CryptographicException("Working control already has an audit row.");
            var before = CompleteApplicationCompactionProjection(connection, tx, selector, null, ct);
            var addition = expire ? null : NewControlAudit(entry);
            try
            {
                var omitted = expire ? new HashSet<string>(StringComparer.Ordinal) { Convert.ToHexString(id) } : null;
                var after = CompleteApplicationCompactionProjection(connection, tx, selector, null, ct,
                    addAudits: addition is null ? null : [addition], omitAudits: omitted);
                ct.ThrowIfCancellationRequested(); return (before, after);
            }
            finally
            {
                if (addition is not null) { CryptographicOperations.ZeroMemory(addition.Operation); CryptographicOperations.ZeroMemory(addition.Authenticator); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(id); }
    }

    internal Task ApplyControlAuditAsync(ProtectedDeepIdV2AccountOwner owner, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, byte kind, ReadOnlyMemory<byte> operation,
        ProtectedDid2DirectTextJournal.State ordinary, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
        => WithReplayConnectionAsync(async connection =>
        {
            using var borrowed = held.BorrowFor(lease);
            var action = plan.ReadRow(0).Action;
            if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Application || plan.RowCount != 1 ||
                action is not (Did2CompactionPlan.Disposition.StoppedControlPayload or Did2CompactionPlan.Disposition.ExpiredControlAudit) ||
                !DirectFixed(plan.SqlSelector, scope.Hash) || !DirectFixed(plan.ReadRow(0).Selector.Span, operation.Span))
                throw new InvalidDataException("Control audit SQL requires its exact active closed plan.");
            var expire = action == Did2CompactionPlan.Disposition.ExpiredControlAudit;
            using var tx = connection.BeginTransaction();
            var effects = CaptureControlAuditEffects(connection, tx, scope.Hash, kind, operation.Span, expire, ordinary, ct);
            var id = ControlAuditId(kind, operation.Span);
            try
            {
                if (!DirectFixed(effects.Before, plan.SqlBefore) || !DirectFixed(effects.After, plan.SqlAfter))
                    throw new CryptographicException("Control audit SQL differs from its complete planned effects.");
                var roots = await owner.ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(effects.Before, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                    throw new CryptographicException("Control audit predecessor changed before SQL.");
                if (expire)
                {
                    using var delete = connection.CreateCommand(); delete.Transaction = tx;
                    delete.CommandText = "DELETE FROM stopped_work_audit WHERE operation_id=$operation;";
                    delete.Parameters.AddWithValue("$operation", id);
                    if (delete.ExecuteNonQuery() != 1) throw new CryptographicException("Control audit expiry lost its exact selected row.");
                }
                else
                {
                    var row = NewControlAudit(controlAuditCustody[Convert.ToHexString(id)]);
                    try { InsertStoppedAudit(connection, tx, row); }
                    finally { CryptographicOperations.ZeroMemory(row.Operation); CryptographicOperations.ZeroMemory(row.Authenticator); }
                }
                if (!DirectFixed(CompleteApplicationCompactionProjection(connection, tx, scope, null, ct), plan.SqlAfter))
                    throw new CryptographicException("Control audit SQL effects differ before commit.");
                roots = await owner.ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(plan.SqlAfter, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                    throw new CryptographicException("Control audit guards changed before commit.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit(); return true;
            }
            finally { CryptographicOperations.ZeroMemory(id); CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
        }, ct);

    internal Task BindPreSessionAuditAccountAsync(VerifiedDeepIdV2CurrentAccount current, CancellationToken ct)
        => WithReplayConnectionAsync(connection =>
        {
            if (!controlAuditBound || stoppedAuditKey.Length != 32) throw new CryptographicException("Pre-session audit requires its registered account factory.");
            using var tx = connection.BeginTransaction();
            var local = current.AccountId.ToArray(); var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, current.Verified.PublicEvidence.Binding.Identity.Account.Certificate.AccountGeneration);
            try
            {
                BindDirectInboxOwner(connection, tx, local, generation);
                ct.ThrowIfCancellationRequested(); tx.Commit(); return Task.FromResult(true);
            }
            finally { CryptographicOperations.ZeroMemory(local); CryptographicOperations.ZeroMemory(generation); }
        }, ct);

    internal byte[] PreSessionControlAuditSelector(ReadOnlySpan<byte> operation)
    {
        if (!controlAuditBound) throw new CryptographicException("Pre-session audit lost registered control custody.");
        return ControlAuditId(1, operation); // Opaque account-derived selection, not a fabricated session hash.
    }

    internal async Task<(byte[] Before, byte[] After)> CapturePreSessionControlAuditEffectsAsync(ReadOnlyMemory<byte> operation,
        bool expire, ProtectedDid2DirectTextJournal.State ordinary, CancellationToken ct)
    {
        var owned = operation.ToArray();
        try
        {
            return await WithReplayConnectionAsync(connection =>
            {
                using var tx = connection.BeginTransaction(); var selector = PreSessionControlAuditSelector(owned);
                try { return Task.FromResult(CaptureControlAuditEffects(connection, tx, selector, 1, owned, expire, ordinary, ct)); }
                finally { CryptographicOperations.ZeroMemory(selector); }
            }, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owned); }
    }

    internal Task ApplyPreSessionControlAuditAsync(ProtectedDeepIdV2AccountOwner owner, Did2CompactionPlan plan,
        ProtectedDid2DirectTextJournal.State ordinary, HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
        => WithReplayConnectionAsync(async connection =>
        {
            using var borrowed = held.BorrowFor(lease);
            var action = plan.ReadRow(0).Action; var operation = plan.ReadRow(0).Selector;
            if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Application || plan.RowCount != 1 ||
                action is not (Did2CompactionPlan.Disposition.PreSessionInitialPayload or Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit))
                throw new InvalidDataException("Pre-session audit requires its exact active closed plan.");
            var id = PreSessionControlAuditSelector(operation.Span);
            try
            {
                if (!DirectFixed(id, plan.SqlSelector)) throw new CryptographicException("Pre-session audit borrowed another SQL selector.");
                await owner.RequireClosedPreSessionControlUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), operation, held, ct).ConfigureAwait(false);
                using var tx = connection.BeginTransaction();
                var expire = action == Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit;
                var effects = CaptureControlAuditEffects(connection, tx, id, 1, operation.Span, expire, ordinary, ct);
                try
                {
                    if (!DirectFixed(effects.Before, plan.SqlBefore) || !DirectFixed(effects.After, plan.SqlAfter))
                        throw new CryptographicException("Pre-session audit changed its complete SQL effects.");
                    var roots = await owner.ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                    if (plan.ObserveReadback(effects.Before, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql) throw new CryptographicException("Pre-session audit predecessor changed.");
                    if (expire)
                    {
                        using var delete = connection.CreateCommand(); delete.Transaction = tx;
                        delete.CommandText = "DELETE FROM stopped_work_audit WHERE operation_id=$op;"; delete.Parameters.AddWithValue("$op", id);
                        if (delete.ExecuteNonQuery() != 1) throw new CryptographicException("Pre-session expiry lost its exact audit row.");
                    }
                    else
                    {
                        var row = NewControlAudit(controlAuditCustody[Convert.ToHexString(id)]);
                        try { InsertStoppedAudit(connection, tx, row); }
                        finally { CryptographicOperations.ZeroMemory(row.Operation); CryptographicOperations.ZeroMemory(row.Authenticator); }
                    }
                    await owner.RequireClosedPreSessionControlUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), operation, held, ct).ConfigureAwait(false);
                    roots = await owner.ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                    if (!DirectFixed(CompleteApplicationCompactionProjection(connection, tx, id, null, ct), plan.SqlAfter) ||
                        plan.ObserveReadback(plan.SqlAfter, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                        throw new CryptographicException("Pre-session audit changed before SQL commit.");
                    ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit(); return true;
                }
                finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
            }
            finally { CryptographicOperations.ZeroMemory(id); }
        }, ct);

    private static void ProjectStoppedAudits(IncrementalHash hash, SqliteConnection connection, SqliteTransaction tx,
        IReadOnlyList<StoppedAuditRow>? additions, HashSet<string>? omitted)
    {
        var rows = ReadStoppedAuditFacts(connection, tx);
        if (omitted is not null) foreach (var name in omitted)
            if (!rows.Remove(name)) throw new CryptographicException("Virtual audit expiry lost a selected row.");
        if (additions is not null) foreach (var row in additions)
            if (!rows.TryAdd(Convert.ToHexString(row.Operation), row)) throw new CryptographicException("A virtual successor cannot replace an existing audit.");
        if (rows.Count > MaximumStoppedAudits) throw new InvalidOperationException("Audit capacity requires authenticated expiry, not eviction.");
        Span<byte> number = stackalloc byte[8];
        foreach (var row in rows.Values)
        {
            hash.AppendData([1]); hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, 32); hash.AppendData(number); hash.AppendData(row.Operation);
            foreach (var value in new[] { (ulong)row.Reason, row.StoppedAt, row.ExpiresAt })
            { hash.AppendData([1]); BinaryPrimitives.WriteUInt64BigEndian(number, value); hash.AppendData(number); }
            hash.AppendData([2]); BinaryPrimitives.WriteUInt64BigEndian(number, 32); hash.AppendData(number); hash.AppendData(row.Authenticator);
        }
        hash.AppendData([0]); BinaryPrimitives.WriteUInt64BigEndian(number, checked((ulong)rows.Count)); hash.AppendData(number);
    }
}
