#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // SQL facts only: the owner also requires an idle protected read journal,
    // matching protected/SQL traversal, excluded old namespace and an actual
    // installed replacement. MRSO/MCO1 are NOT independent quorum authorities.
    internal async Task RequireSettledGrantReadCoverageAsync(ReadOnlyMemory<byte> selectedGrant,
        ClientMailboxScope readScope, ClientMailboxTraversal preservedTraversal, BlindedMailboxId mailbox, BlindedPlacementId placement, CancellationToken ct)
    {
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(selectedGrant.Span);
        var account = VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span);
        byte[] cursor = []; var selected = 0; var expectedAcks = 0; var actualAcks = 0;
        try
        {
            while (true)
            {
                var logical = await WithReplayConnectionAsync(connection =>
                {
                    using var command = connection.CreateCommand();
                    command.CommandText = "SELECT logical_id,typeof(logical_id),length(logical_id),typeof(ciphertext_bundle),length(ciphertext_bundle) FROM transport_outbox_items WHERE account_scope=$account AND ($first=1 OR logical_id>$cursor) ORDER BY logical_id LIMIT 1;";
                    command.Parameters.AddWithValue("$account", account.Value.ToArray());
                    command.Parameters.AddWithValue("$first", cursor.Length == 0 ? 1 : 0); command.Parameters.AddWithValue("$cursor", cursor);
                    using var reader = command.ExecuteReader();
                    if (!reader.Read()) return Task.FromResult<byte[]?>(null);
                    if (reader.GetString(1) != "blob" || reader.GetInt64(2) != 16 || reader.GetString(3) != "blob" ||
                        reader.GetInt64(4) is < 1 or > TransportOutboxLimits.MaxCiphertextBundleBytes)
                        throw new InvalidDataException("Retained read request has a hostile identity or size.");
                    return Task.FromResult<byte[]?>(reader.GetFieldValue<byte[]>(0));
                }, ct).ConfigureAwait(false);
                if (logical is null) break;
                byte[] exact = [], evidence = [];
                try
                {
                    CryptographicOperations.ZeroMemory(cursor); cursor = logical.ToArray();
                    var stored = await ReadTransportOutboxAsync(account, OutboxLogicalId.FromBytes(logical), ct).ConfigureAwait(false);
                    if (stored.Item is not { State: TransportOutboxState.Durable } item)
                        throw new IOException("Pending or unknown original Retrieve/ACK pins holder retirement.");
                    exact = item.GetCiphertextBundleCopy();
                    var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
                    if (!CryptographicOperations.FixedTimeEquals(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), selectedGrant.Span) ||
                        !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(),
                            MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation), grant.HolderPublicKey.ToArray()))
                        throw new CryptographicException("Retained read request lost its original exact grant or holder signature.");
                    var durable = item.Attempts.Where(attempt => attempt.State == TransportOutboxAttemptState.Durable).ToArray();
                    if (durable.Length != 1) throw new CryptographicException("Retained read request lost its unique completed outcome.");
                    evidence = durable[0].GetEvidenceCopy();
                    ReadOnlyMemory<byte> operation;
                    if (request.Binding.Operation == MailboxAuthenticatedOperation.Retrieve)
                    {
                        var body = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(request.Binding.CanonicalRequest.Span);
                        operation = body.OperationId;
                        if (body.Epoch != grant.Epoch || !FixedCurrent(body.MailboxId.Bytes.Span, mailbox.Bytes.Span) ||
                            !FixedCurrent(body.PlacementId.Bytes.Span, placement.Bytes.Span))
                            throw new CryptographicException("Retained Retrieve changed its original mailbox route.");
                        var summary = ClientMailboxRetrieveOutcomeSummary.DecodeAndValidate(evidence, body);
                        if (summary.ItemCount != 0)
                        {
                            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                            hash.AppendData("Deep/Local/DID2/MailboxAckOperation/1"u8); hash.AppendData([0]);
                            hash.AppendData(readScope.Value); hash.AppendData(SHA256.HashData(selectedGrant.Span));
                            hash.AppendData(SHA256.HashData(exact)); hash.AppendData(summary.ResponseDigest.Span);
                            var ackId = hash.GetHashAndReset()[..16];
                            var ack = await ReadTransportOutboxAsync(account, OutboxLogicalId.FromBytes(ackId), ct).ConfigureAwait(false);
                            if (ack.Item is not { State: TransportOutboxState.Durable })
                                throw new IOException("Original nonempty Retrieve lost its completed transport ACK.");
                            var ackExact = ack.Item.GetCiphertextBundleCopy();
                            try
                            {
                                var ackRequest = MailboxAuthenticatedClientRequestCodec.Decode(ackExact);
                                if (ackRequest.Binding.Operation != MailboxAuthenticatedOperation.Ack)
                                    throw new CryptographicException("Original Retrieve ACK has another operation role.");
                                var ackBody = MailboxAuthenticatedRequestTranscript.DecodeAckBody(ackRequest.Binding.CanonicalRequest.Span);
                                if (!FixedCurrent(ackBody.OperationId.Span, ackId) || ackBody.Acknowledgements.Count != summary.ItemCount ||
                                    ackBody.IsFinalPage == summary.HasMore || !FixedCurrent(ackBody.ContinuationToken.Span, summary.ContinuationToken.Span))
                                    throw new CryptographicException("Original Retrieve/ACK binding changed.");
                            }
                            finally { CryptographicOperations.ZeroMemory(ackExact); CryptographicOperations.ZeroMemory(ackId); }
                            expectedAcks = checked(expectedAcks + 1);
                        }
                    }
                    else if (request.Binding.Operation == MailboxAuthenticatedOperation.Ack)
                    {
                        var body = MailboxAuthenticatedRequestTranscript.DecodeAckBody(request.Binding.CanonicalRequest.Span);
                        operation = body.OperationId;
                        if (body.Epoch != grant.Epoch || !FixedCurrent(body.MailboxId.Bytes.Span, mailbox.Bytes.Span) ||
                            !FixedCurrent(body.PlacementId.Bytes.Span, placement.Bytes.Span))
                            throw new CryptographicException("Retained ACK changed its original mailbox route.");
                        actualAcks = checked(actualAcks + 1);
                        if (evidence.Length != 40 || !evidence.AsSpan(0, 4).SequenceEqual("MCO1"u8) ||
                            evidence.AsSpan(4, 4).IndexOfAnyExcept((byte)0) >= 0 || evidence.AsSpan(8).IndexOfAnyExcept((byte)0) < 0)
                            throw new CryptographicException("Retained ACK lost its completed outcome commitment.");
                    }
                    else throw new CryptographicException("Retrieve holder has an unexpected Store operation.");
                    if (!CryptographicOperations.FixedTimeEquals(operation.Span, logical) ||
                        preservedTraversal.PollGeneration == 0)
                        throw new CryptographicException("Original read operation differs from its retained logical/traversal custody.");
                    selected = checked(selected + 1);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(exact);
                    CryptographicOperations.ZeroMemory(evidence);
                }
            }
            if (selected == 0) throw new IOException("Used Retrieve retirement requires positive original read custody, not SQL absence.");
            if (expectedAcks != actualAcks) throw new CryptographicException("Retained read custody has an orphan transport ACK.");
        }
        finally { CryptographicOperations.ZeroMemory(cursor); }
    }

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
