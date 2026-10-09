#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // Actual retained SQL facts, not a terminal/deletion capability. The held
    // owner separately verifies native/public-policy/holder/quorum/coordinator.
    internal async Task<bool> IsOriginalStoreForGrantRetirementAsync(Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> selectedGrant, CancellationToken ct)
    {
        var evidence = await RequireStorePublicEvidenceAsync(scope, operation, ct).ConfigureAwait(false);
        var item = await ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
            OutboxLogicalId.FromBytes(evidence.Logical.Span), ct).ConfigureAwait(false);
        if (item is not { Result: TransportOutboxReadResult.Found, Item.State: TransportOutboxState.Durable })
            throw new IOException("Pending or unknown outgoing history pins grant retirement.");
        var exact = item.Item.GetCiphertextBundleCopy();
        try
        {
            var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
            if (request.Binding.Operation != MailboxAuthenticatedOperation.Store)
                throw new CryptographicException("Outgoing history has no original Store request.");
            var originalGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant);
            return CryptographicOperations.FixedTimeEquals(originalGrant, selectedGrant.Span);
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    // The caller's authenticated native enumeration is the completeness side
    // of this join. SQL absence alone can never grant retirement permission.
    internal async Task RequireCompleteGrantStoreCoverageAsync(ReadOnlyMemory<byte> selectedGrant,
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, CancellationToken, Task> verifyNative, CancellationToken ct)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(selectedGrant.Span);
        var account = VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span).Value.ToArray();
        byte[] cursor = []; var selected = 0;
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                // One bounded row per page. Release the connection before
                // invoking the private native verifier, which rereads this SQL.
                var row = await WithReplayConnectionAsync(connection =>
                {
                    using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
                    using var command = connection.CreateCommand(); command.Transaction = tx;
                    command.CommandText = "SELECT logical_id,ciphertext_bundle,typeof(logical_id),length(logical_id),typeof(ciphertext_bundle),length(ciphertext_bundle) FROM transport_outbox_items WHERE account_scope=$account AND ($first=1 OR logical_id>$cursor) ORDER BY logical_id LIMIT 1;";
                    command.Parameters.AddWithValue("$account", account); command.Parameters.AddWithValue("$first", cursor.Length == 0 ? 1 : 0);
                    command.Parameters.AddWithValue("$cursor", cursor);
                    using var reader = command.ExecuteReader();
                    if (!reader.Read()) return Task.FromResult<byte[][]?>(null);
                    if (reader.GetString(2) != "blob" || reader.GetInt64(3) != 16 || reader.GetString(4) != "blob" ||
                        reader.GetInt64(5) is < 1 or > TransportOutboxLimits.MaxCiphertextBundleBytes)
                        throw new InvalidDataException("Retained grant request has a hostile identity or size.");
                    return Task.FromResult<byte[][]?>([reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1)]);
                }, ct).ConfigureAwait(false);
                if (row is null) break;
                var logical = row[0]; var exact = row[1];
                try
                {
                    CryptographicOperations.ZeroMemory(cursor); cursor = logical.ToArray();
                    var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
                    if (!CryptographicOperations.FixedTimeEquals(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), selectedGrant.Span)) continue;
                    if (request.Binding.Operation != MailboxAuthenticatedOperation.Store)
                        throw new CryptographicException("Original grant request is missing its independently verified native Store outcome.");
                    var selector = await WithReplayConnectionAsync(connection =>
                    {
                        using var command = connection.CreateCommand();
                        command.CommandText = "SELECT scope_hash,operation_id,typeof(scope_hash),length(scope_hash),typeof(operation_id),length(operation_id) FROM mailbox_store_public_evidence WHERE account_scope=$account AND logical_id=$logical LIMIT 2;";
                        command.Parameters.AddWithValue("$account", account); command.Parameters.AddWithValue("$logical", logical);
                        using var reader = command.ExecuteReader();
                        if (!reader.Read() || reader.GetString(2) != "blob" || reader.GetInt64(3) != 32 ||
                            reader.GetString(4) != "blob" || reader.GetInt64(5) != 32)
                            throw new CryptographicException("Original grant Store lost its native evidence selector.");
                        var result = new[] { reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1) };
                        if (reader.Read())
                        {
                            foreach (var bytes in result) CryptographicOperations.ZeroMemory(bytes);
                            throw new CryptographicException("Original grant Store has ambiguous native evidence.");
                        }
                        return Task.FromResult(result);
                    }, ct).ConfigureAwait(false);
                    try { await verifyNative(selector[0], selector[1], ct).ConfigureAwait(false); }
                    finally { foreach (var bytes in selector) CryptographicOperations.ZeroMemory(bytes); }
                    selected = checked(selected + 1);
                }
                finally { CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(exact); }
            }
            if (selected == 0) throw new IOException("Used grant retirement requires positive original Store evidence, not an empty SQL result.");
            ct.ThrowIfCancellationRequested();
        }
        finally { CryptographicOperations.ZeroMemory(cursor); CryptographicOperations.ZeroMemory(account); }
    }
}
#endif
