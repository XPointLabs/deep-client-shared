#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // Read-only SQL selection facts. Only the held account owner may stage the
    // matching closed plan after independently discharging all dependencies.
    private sealed class RetainedPathSqlSelection
    {
        internal readonly HashSet<string> Scopes = new(StringComparer.Ordinal);
        internal readonly string Traversal;
        internal bool TraversalRowPresent;
        internal RetainedPathSqlSelection(ClientMailboxScope traversal) => Traversal = Convert.ToHexString(traversal.Value);
        internal bool Omit(string table, List<string> fields, SqliteDataReader row)
        {
            var field = table switch
            {
                "mailbox_credential_scopes" or "mailbox_credential_epochs" or
                "mailbox_credential_grants" or "mailbox_replay_counters" => "scope_id",
                "client_mailbox_traversal" or "client_mailbox_poll_clock" => "scope",
                _ => null
            };
            if (field is null) return false;
            var bytes = row.GetFieldValue<byte[]>(fields.IndexOf(field));
            try
            {
                var name = Convert.ToHexString(bytes);
                return field == "scope" ? name == Traversal : Scopes.Contains(name);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    internal Task<(byte[] Before, byte[] After)> CaptureRetainedPathEffectsAsync(
        ParsedContactRouteClosure route, ClientMailboxScope traversal, ClientMailboxTraversal preservedTraversal,
        IReadOnlyList<ReadOnlyMemory<byte>> grants, CancellationToken ct) =>
        WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction();
            var selected = RequireRetainedPathSqlSelection(connection, tx, route, traversal, preservedTraversal, grants, ct);
            var before = CompleteApplicationCompactionProjection(connection, tx, route.ExactHash.Span, null, ct);
            var after = CompleteApplicationCompactionProjection(connection, tx, route.ExactHash.Span, null, ct, selected);
            if (DirectFixed(before, after)) throw new CryptographicException("Retained path has no exact SQL disposition.");
            return Task.FromResult((before, after));
        }, ct);

    internal Task ApplyStoredRetainedPathAsync(ProtectedDeepIdV2AccountOwner owner, Did2CompactionPlan plan,
        ParsedContactRouteClosure route, ClientMailboxScope traversal, ClientMailboxTraversal preservedTraversal,
        IReadOnlyList<ReadOnlyMemory<byte>> grants,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct) =>
        WithReplayConnectionAsync(async connection =>
        {
            using var borrowed = held.BorrowFor(lease);
            if (plan.Phase != 1 || plan.Target != Did2CompactionPlan.SqlTarget.Application ||
                plan.ReadRow(plan.RowCount - 1).Action != Did2CompactionPlan.Disposition.RetainedPath || grants.Count != plan.RowCount - 1 ||
                !DirectFixed(route.ExactHash.Span, plan.SqlSelector))
                throw new InvalidDataException("Only a stored joint retained-path profile can mutate SQL.");
            using var tx = connection.BeginTransaction();
            var selected = RequireRetainedPathSqlSelection(connection, tx, route, traversal, preservedTraversal, grants, ct);
            var before = CompleteApplicationCompactionProjection(connection, tx, plan.SqlSelector, null, ct);
            var after = CompleteApplicationCompactionProjection(connection, tx, plan.SqlSelector, null, ct, selected);
            if (!DirectFixed(before, plan.SqlBefore) || !DirectFixed(after, plan.SqlAfter))
                throw new CryptographicException("Retained-path complete SQL effects changed before mutation.");
            var roots = await owner.ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(before, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Retained-path dependencies changed before SQL.");
            foreach (var scope in selected.Scopes)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                DeleteCurrentCredential(connection, tx, Convert.FromHexString(scope));
            }
            foreach (var table in new[] { "client_mailbox_traversal", "client_mailbox_poll_clock" })
            {
                using var delete = connection.CreateCommand(); delete.Transaction = tx;
                delete.CommandText = "DELETE FROM " + table + " WHERE scope=$scope;";
                delete.Parameters.AddWithValue("$scope", traversal.Value.ToArray());
                var expected = table == "client_mailbox_traversal" && !selected.TraversalRowPresent ? 0 : 1;
                if (delete.ExecuteNonQuery() != expected) throw new CryptographicException("Retained-path traversal changed during SQL.");
            }
            var actual = CompleteApplicationCompactionProjection(connection, tx, plan.SqlSelector, null, ct);
            if (!DirectFixed(actual, plan.SqlAfter)) throw new CryptographicException("Retained-path SQL successor changed unrelated custody.");
            roots = await owner.ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(actual, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                throw new CryptographicException("Retained-path dependencies changed before SQL commit.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); tx.Commit(); return true;
        }, ct);

    private static RetainedPathSqlSelection RequireRetainedPathSqlSelection(SqliteConnection connection, SqliteTransaction tx,
        ParsedContactRouteClosure original, ClientMailboxScope traversal, ClientMailboxTraversal preservedTraversal,
        IReadOnlyList<ReadOnlyMemory<byte>> grants, CancellationToken ct)
    {
        var route = original.ExactHash.Span;
        if (grants.Count is < 1 or >= Did2CompactionPlan.MaximumRows ||
            !DirectFixed(ClientMailboxScope.Derive(route, new BlindedMailboxId(original.Reachability.Field(2).Span),
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(original.Selection.Field(4).Span)).Value, traversal.Value))
            throw new InvalidDataException("Retained-path SQL selection exceeds its closed bounds.");
        ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
        var result = new RetainedPathSqlSelection(traversal);
        foreach (var exact in grants)
        {
            ct.ThrowIfCancellationRequested();
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exact.Span);
            if (grant.Domain != MailboxCapabilityDomain.Retrieve)
                throw new CryptographicException("Retained-path SQL cannot delete a Store namespace.");
            var selector = new MailboxCredentialSelector(VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                MailboxCredentialScopeKind.Self, grant.HolderPublicKey.Span, route);
            if (!result.Scopes.Add(Convert.ToHexString(selector.ScopeId.Span)))
                throw new CryptographicException("Retained-path SQL selected a duplicate holder scope.");
            using var query = connection.CreateCommand(); query.Transaction = tx;
            query.CommandText = """
                SELECT s.account_scope,s.scope_kind,s.subject_id,s.issuer_context,s.network_id,s.holder_key,
                       s.generation,s.active_epoch,s.group_membership_commitment,g.canonical_grant,g.grant_digest,
                       e.mailbox_id,e.placement_id,e.not_before,e.expires_at,
                       CASE WHEN typeof(g.canonical_grant)='blob' AND length(g.canonical_grant)=$grantLength
                            AND typeof(s.active_epoch)='blob' AND length(s.active_epoch)=8
                            AND typeof(e.not_before)='blob' AND length(e.not_before)=8
                            AND typeof(e.expires_at)='blob' AND length(e.expires_at)=8
                            THEN 1 ELSE 0 END
                FROM mailbox_credential_scopes s
                JOIN mailbox_credential_epochs e ON e.scope_id=s.scope_id AND e.epoch=s.active_epoch
                JOIN mailbox_credential_grants g ON g.scope_id=s.scope_id AND g.epoch=s.active_epoch
                WHERE s.scope_id=$scope AND g.role=$role;
                """;
            query.Parameters.AddWithValue("$scope", selector.ScopeId.ToArray());
            query.Parameters.AddWithValue("$role", (int)MailboxCredentialRole.Retrieve);
            query.Parameters.AddWithValue("$grantLength", MailboxAuthenticatedCapabilityLimits.GrantLength);
            using (var row = query.ExecuteReader())
            {
                var digest = SHA256.HashData(exact.Span);
                if (!row.Read() || row.GetInt64(15) != 1 || row.GetInt64(1) != (int)MailboxCredentialScopeKind.Self || !row.IsDBNull(8) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(0), selector.AccountScope.Value) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(2), grant.HolderPublicKey.Span) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(3), route) || !DirectFixed(row.GetFieldValue<byte[]>(4), grant.NetworkId.Span) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(5), grant.HolderPublicKey.Span) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(6), digest) || ReadU64Current(row.GetFieldValue<byte[]>(7)) != grant.Epoch ||
                    !DirectFixed(row.GetFieldValue<byte[]>(9), exact.Span) || !DirectFixed(row.GetFieldValue<byte[]>(10), digest) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(11), original.Reachability.Field(2).Span) ||
                    !DirectFixed(row.GetFieldValue<byte[]>(12), original.Reachability.Field(10).Span) ||
                    ReadU64Current(row.GetFieldValue<byte[]>(13)) != grant.NotBeforeUnixSeconds ||
                    ReadU64Current(row.GetFieldValue<byte[]>(14)) != grant.ExpiresAtUnixSeconds || row.Read())
                    throw new CryptographicException("Retained path lost its exact installed original SQL grant.");
            }
            foreach (var table in new[] { "mailbox_credential_epochs", "mailbox_credential_grants" })
            {
                using var count = connection.CreateCommand(); count.Transaction = tx;
                count.CommandText = "SELECT count(*) FROM " + table + " WHERE scope_id=$scope;";
                count.Parameters.AddWithValue("$scope", selector.ScopeId.ToArray());
                if ((long)count.ExecuteScalar()! != 1) throw new CryptographicException("An additional credential generation pins path retirement.");
            }
            using var counters = connection.CreateCommand(); counters.Transaction = tx;
            counters.CommandText = "SELECT epoch,grant_digest,next_counter,CASE WHEN typeof(epoch)='blob' AND length(epoch)=8 AND typeof(grant_digest)='blob' AND length(grant_digest)=32 AND typeof(next_counter)='blob' AND length(next_counter)=8 THEN 1 ELSE 0 END FROM mailbox_replay_counters WHERE scope_id=$scope LIMIT 2;";
            counters.Parameters.AddWithValue("$scope", selector.ScopeId.ToArray());
            using var counter = counters.ExecuteReader();
            if (!counter.Read() || counter.GetInt64(3) != 1 || ReadU64Current(counter.GetFieldValue<byte[]>(0)) != grant.Epoch ||
                !DirectFixed(counter.GetFieldValue<byte[]>(1), SHA256.HashData(exact.Span)) ||
                ReadU64Current(counter.GetFieldValue<byte[]>(2)) < 2 || counter.Read())
                throw new CryptographicException("Retained path lost its original completed read counter.");
        }
        if (preservedTraversal.PollGeneration == 0)
            throw new CryptographicException("Retained path has no protected completed poll generation.");
        {
            using var query = connection.CreateCommand(); query.Transaction = tx;
            query.CommandText = """
                SELECT p.generation,t.scope,t.after_cursor,t.continuation_token,
                    (SELECT count(*) FROM client_mailbox_inbox WHERE scope=$scope),
                    (SELECT count(*) FROM client_mailbox_expired_quarantine WHERE scope=$scope)
                FROM client_mailbox_poll_clock p
                LEFT JOIN client_mailbox_traversal t ON t.scope=p.scope
                WHERE p.scope=$scope;
                """;
            query.Parameters.AddWithValue("$scope", traversal.Value.ToArray());
            using var row = query.ExecuteReader();
            if (!row.Read() || row.GetValue(0) is not byte[] { Length: 8 } generation ||
                ReadU64Current(generation) != preservedTraversal.PollGeneration)
                throw new CryptographicException("Retained path lost its original protected/SQL poll floor.");
            result.TraversalRowPresent = !row.IsDBNull(1);
            if (result.TraversalRowPresent)
            {
                if (row.GetValue(2) is not byte[] { Length: 8 } cursor ||
                    ReadU64Current(cursor) != preservedTraversal.AfterCursor ||
                    row.GetValue(3) is not byte[] token || !DirectFixed(token, preservedTraversal.ContinuationToken))
                    throw new CryptographicException("Retained path changes its exact protected/SQL cursor.");
            }
            // The existing normalized repository prunes an empty zero cursor,
            // but NEVER its poll-generation floor. Absence is accepted only in
            // that canonical empty case, not as proof of Retrieve/ACK completion.
            else if (preservedTraversal.AfterCursor != 0 || !preservedTraversal.ContinuationToken.IsEmpty ||
                row.GetInt64(4) != 0 || row.GetInt64(5) != 0)
                throw new CryptographicException("Retained path lost a nonempty original traversal.");
            if (row.Read()) throw new CryptographicException("Retained path has ambiguous traversal custody.");
        }
        return result;
    }
}
#endif
