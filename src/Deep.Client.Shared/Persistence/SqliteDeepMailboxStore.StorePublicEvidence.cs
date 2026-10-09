#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

internal sealed class Did2StorePublicEvidence
{
    private readonly byte[][] records;
    internal Did2StorePublicEvidence(ReadOnlyMemory<byte> accountScope, ReadOnlyMemory<byte> logical,
        ReadOnlyMemory<byte> pma, MailboxStoreReplicaEvidence replicas,
        ReadOnlyMemory<byte> originalDcr = default, ReadOnlyMemory<byte> originalRoute = default,
        ReadOnlyMemory<byte> originalPeerAdp = default)
    {
        ArgumentNullException.ThrowIfNull(replicas);
        if (accountScope.Length != 32 || logical.Length != 16 || pma.Length is < 1 or > 65_535)
            throw new ArgumentException("Store evidence has an invalid bounded transport identity/policy.");
        if (originalDcr.Length > DeepIdV2ResolverClosureCodec.MaximumLength || originalRoute.Length > ContactRouteClosureCodec.MaximumEncodedBytes ||
            originalPeerAdp.Length > DeepIdV2Adp1Codec.MaximumLength ||
            originalDcr.IsEmpty != originalRoute.IsEmpty || originalDcr.IsEmpty != originalPeerAdp.IsEmpty)
            throw new ArgumentException("Original initial Store recipient evidence has a partial or hostile shape.");
        records = [accountScope.ToArray(), logical.ToArray(), pma.ToArray(), replicas.ExactXnv1.ToArray(),
            replicas.ExactFirstXnd1.ToArray(), replicas.ExactSecondXnd1.ToArray(),
            originalDcr.ToArray(), originalRoute.ToArray(), originalPeerAdp.ToArray()];
        _ = ContactCodec.Decode("PMA2", records[2]);
    }
    internal ReadOnlyMemory<byte> AccountScope => records[0].ToArray();
    internal ReadOnlyMemory<byte> Logical => records[1].ToArray();
    internal ReadOnlyMemory<byte> ExactPma => records[2].ToArray();
    internal MailboxStoreReplicaEvidence Replicas => new(records[3], records[4], records[5]);
    internal ReadOnlyMemory<byte> OriginalDcr => records[6].ToArray();
    internal ReadOnlyMemory<byte> OriginalRoute => records[7].ToArray();
    internal ReadOnlyMemory<byte> OriginalPeerAdp => records[8].ToArray();
    internal bool IsInitial => records[6].Length != 0;
    internal byte[][] CopyRecords() => records.Select(bytes => bytes.ToArray()).ToArray();
}

public sealed partial class SqliteDeepMailboxStore
{
    // Producer-only insertion of original public records. It creates no Store
    // result, secret, dispatch, cleanup or deletion permission. Actual signed
    // SQL/native joins are checked by the held owner before and after this call.
    internal async Task RecordStorePublicEvidenceAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, Did2StorePublicEvidence evidence, CancellationToken ct)
    {
        if (operation.Length != 32) throw new ArgumentException("An exact original operation is required.", nameof(operation));
        var selector = operation.ToArray(); var scopeHash = scope.Hash.ToArray(); var records = evidence.CopyRecords();
        try
        {
            await WithReplayConnectionAsync(connection =>
            {
                using var tx = connection.BeginTransaction(deferred: false); ValidateTransportOutboxSchema(connection, tx);
                using var count = connection.CreateCommand(); count.Transaction = tx;
                count.CommandText = "SELECT count(*) FROM mailbox_store_public_evidence WHERE scope_hash=$scope;";
                count.Parameters.AddWithValue("$scope", scopeHash);
                var existing = ReadStorePublicEvidence(connection, tx, scopeHash, selector);
                if (existing is not null)
                {
                    RequireSamePublicEvidence(existing, records);
                    ct.ThrowIfCancellationRequested(); tx.Commit(); return Task.FromResult(true);
                }
                if (Convert.ToInt64(count.ExecuteScalar()) >= Did2MessagingSqlJournal.MaximumEntries)
                    throw new IOException("Retained Store evidence reached the existing native event bound; no evidence may be evicted.");
                using var insert = connection.CreateCommand(); insert.Transaction = tx;
                insert.CommandText = "INSERT INTO mailbox_store_public_evidence(scope_hash,operation_id,account_scope,logical_id,exact_pma,exact_view,first_descriptor,second_descriptor,original_dcr,original_route,original_peer_adp) VALUES($scope,$op,$account,$logical,$pma,$view,$first,$second,$dcr,$route,$adp);";
                insert.Parameters.AddWithValue("$scope", scopeHash); insert.Parameters.AddWithValue("$op", selector);
                var names = new[] { "$account", "$logical", "$pma", "$view", "$first", "$second", "$dcr", "$route", "$adp" };
                for (var index = 0; index < names.Length; index++) insert.Parameters.Add(names[index], SqliteType.Blob).Value = records[index];
                if (insert.ExecuteNonQuery() != 1) throw new CryptographicException("Original Store evidence was not inserted exactly once.");
                var readback = ReadStorePublicEvidence(connection, tx, scopeHash, selector) ?? throw new CryptographicException("Original Store evidence disappeared before commit.");
                RequireSamePublicEvidence(readback, records); ct.ThrowIfCancellationRequested(); tx.Commit(); return Task.FromResult(true);
            }, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(selector); CryptographicOperations.ZeroMemory(scopeHash); foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes); }
    }

    internal async Task<Did2StorePublicEvidence> RequireStorePublicEvidenceAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, CancellationToken ct)
        => await ReadStorePublicEvidenceIfPresentAsync(scope, operation, ct).ConfigureAwait(false) ??
            throw new CryptographicException("Retained Store lost its independent original public evidence; no current reconstruction is allowed.");

    internal async Task<Did2StorePublicEvidence?> ReadStorePublicEvidenceIfPresentAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, CancellationToken ct)
    {
        if (operation.Length != 32) throw new ArgumentException("An exact original operation is required.", nameof(operation));
        var selector = operation.ToArray(); var scopeHash = scope.Hash.ToArray();
        try { return await WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
            var records = ReadStorePublicEvidence(connection, tx, scopeHash, selector);
            if (records is null) { ct.ThrowIfCancellationRequested(); return Task.FromResult<Did2StorePublicEvidence?>(null); }
            try
            {
                var result = RestorePublicEvidence(records);
                ct.ThrowIfCancellationRequested(); return Task.FromResult<Did2StorePublicEvidence?>(result);
            }
            finally { foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes); }
        }, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(selector); CryptographicOperations.ZeroMemory(scopeHash); }
    }

    // Terminal selection only, not authentication. A pending ContactAccept has
    // no protected Stored bit. Use actual SQL to distinguish it from a completed
    // operation, then require the original evidence before the owner verifies
    // the native event, holder signature, quorum and coordinator independently.
    internal async Task RequireAttemptedStoreEvidenceAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> logical, CancellationToken ct)
    {
        if (operation.Length != 32 || logical.Length != 16) throw new ArgumentException("An exact native Store identity is required.");
        var op = operation.ToArray(); var hash = scope.Hash.ToArray(); var id = logical.ToArray();
        try { await WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
            using var attempted = connection.CreateCommand(); attempted.Transaction = tx;
            attempted.CommandText = "SELECT account_scope FROM transport_outbox_items WHERE logical_id=$logical AND state IN (2,3,4,5) LIMIT 2;";
            attempted.Parameters.AddWithValue("$logical", id);
            using var reader = attempted.ExecuteReader();
            if (!reader.Read()) { ct.ThrowIfCancellationRequested(); return Task.FromResult(true); }
            if (reader.GetFieldType(0) != typeof(byte[]) || reader.GetBytes(0, 0, null, 0, 0) != 32)
                throw new CryptographicException("Attempted Store has a malformed owner.");
            var account = reader.GetFieldValue<byte[]>(0);
            try
            {
                if (reader.Read()) throw new CryptographicException("Attempted Store has ambiguous owners.");
                reader.Close();
                var records = ReadStorePublicEvidence(connection, tx, hash, op) ??
                    throw new CryptographicException("Attempted initial Store lost its original public evidence; no reconstruction is allowed.");
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(records[0], account) || !CryptographicOperations.FixedTimeEquals(records[1], id))
                        throw new CryptographicException("Attempted initial Store public identity differs from the actual request.");
                    _ = RestorePublicEvidence(records); ct.ThrowIfCancellationRequested(); return Task.FromResult(true);
                }
                finally { foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes); }
            }
            finally { CryptographicOperations.ZeroMemory(account); }
        }, ct).ConfigureAwait(false); }
        finally { foreach (var bytes in new[] { op, hash, id }) CryptographicOperations.ZeroMemory(bytes); }
    }

    internal async Task<Did2StorePublicEvidence?> ReadDurableStorePublicEvidenceAsync(
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> logical, CancellationToken ct)
    {
        if (operation.Length != 32 || logical.Length != 16)
            throw new ArgumentException("An exact bounded native Store identity is required.");
        var selector = operation.ToArray(); var scopeHash = scope.Hash.ToArray(); var logicalId = logical.ToArray();
        try
        {
            return await WithReplayConnectionAsync(connection =>
            {
                using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
                using var terminal = connection.CreateCommand(); terminal.Transaction = tx;
                terminal.CommandText = "SELECT account_scope FROM transport_outbox_items WHERE logical_id=$logical AND state=$durable LIMIT 2;";
                terminal.Parameters.AddWithValue("$logical", logicalId);
                terminal.Parameters.AddWithValue("$durable", (int)TransportOutboxState.Durable);
                byte[] accountScope;
                using (var reader = terminal.ExecuteReader())
                {
                    if (!reader.Read()) { ct.ThrowIfCancellationRequested(); return Task.FromResult<Did2StorePublicEvidence?>(null); }
                    if (reader.GetFieldType(0) != typeof(byte[]) || reader.GetBytes(0, 0, null, 0, 0) != 32)
                        throw new CryptographicException("Retained Store has a malformed terminal owner.");
                    accountScope = reader.GetFieldValue<byte[]>(0);
                    if (reader.Read()) { CryptographicOperations.ZeroMemory(accountScope); throw new CryptographicException("Retained Store has ambiguous terminal owners."); }
                }
                var records = ReadStorePublicEvidence(connection, tx, scopeHash, selector);
                try
                {
                    if (records is null || !CryptographicOperations.FixedTimeEquals(records[0], accountScope) ||
                        !CryptographicOperations.FixedTimeEquals(records[1], logicalId))
                        throw new CryptographicException("Durable Store lost its exact original public evidence; no current reconstruction is allowed.");
                    var result = RestorePublicEvidence(records);
                    ct.ThrowIfCancellationRequested(); return Task.FromResult<Did2StorePublicEvidence?>(result);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(accountScope);
                    if (records is not null) foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes);
                }
            }, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { selector, scopeHash, logicalId }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[][]? ReadStorePublicEvidence(SqliteConnection connection, SqliteTransaction tx,
        byte[] scope, byte[] operation)
    {
        var columns = new[] { "account_scope", "logical_id", "exact_pma", "exact_view", "first_descriptor", "second_descriptor", "original_dcr", "original_route", "original_peer_adp" };
        using var command = connection.CreateCommand(); command.Transaction = tx;
        // Size/type predicates precede materialization of every retained blob.
        command.CommandText = "SELECT " + string.Join(",", columns) + " FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND operation_id=$op AND " +
            string.Join(" AND ", columns.Select((name, index) => "typeof(" + name + ")='blob' AND length(" + name + ")" +
                (index < 2 ? "=" + (index == 0 ? 32 : 16) : index < 6 ? " BETWEEN 1 AND 65535" :
                    " BETWEEN 0 AND " + (index == 8 ? DeepIdV2Adp1Codec.MaximumLength :
                        index == 7 ? ContactRouteClosureCodec.MaximumEncodedBytes : DeepIdV2ResolverClosureCodec.MaximumLength)))) + " LIMIT 2;";
        command.Parameters.AddWithValue("$scope", scope); command.Parameters.AddWithValue("$op", operation);
        using var reader = command.ExecuteReader(); if (!reader.Read()) return null;
        var records = columns.Select((_, index) => reader.GetFieldValue<byte[]>(index)).ToArray();
        if (reader.Read()) { foreach (var bytes in records) CryptographicOperations.ZeroMemory(bytes); throw new CryptographicException("Original Store evidence is ambiguous."); }
        return records;
    }

    private static void RequireSamePublicEvidence(byte[][] actual, byte[][] expected)
    {
        try
        {
            if (actual.Length != expected.Length || actual.Where((bytes, index) =>
                    !CryptographicOperations.FixedTimeEquals(bytes, expected[index])).Any())
                throw new CryptographicException("Original Store evidence is immutable; replacement is forbidden.");
        }
        finally { foreach (var bytes in actual) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static Did2StorePublicEvidence RestorePublicEvidence(byte[][] records)
    {
        try { return new(records[0], records[1], records[2], new(records[3], records[4], records[5]), records[6], records[7], records[8]); }
        catch (ArgumentException error) { throw new CryptographicException("Retained Store evidence has an invalid bounded shape.", error); }
    }
}
#endif
