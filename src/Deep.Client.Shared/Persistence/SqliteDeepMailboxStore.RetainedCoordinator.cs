#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // A bounded readback of already recorded evidence. No insertion/pruning,
    // capacity reservation or reconstructed coordinator statement is permitted.
    internal Task RequireRetainedCoordinatorStatementAsync(MailboxAuthenticatedGrant grant,
        VerifiedMailboxDurableQuorumV3 verified, ulong expiry, CancellationToken ct) =>
        WithReplayConnectionAsync(connection =>
        {
            using var tx = connection.BeginTransaction(); ValidateTransportOutboxSchema(connection, tx);
            var receipt = verified.CoordinatorReceipt;
            var key = CoordinatorStatementKey(grant.MembershipCommitment.Span, grant.Epoch,
                receipt.CoordinatorId.Span, receipt.CoordinatorSequence);
            var digest = SHA256.HashData(MailboxReceiptV3Codec.GetQuorumSigningBytes(receipt));
            try
            {
                using var command = connection.CreateCommand(); command.Transaction = tx;
                command.CommandText = "SELECT length(statement_digest),typeof(statement_digest),statement_digest,length(expires_at),typeof(expires_at),expires_at FROM client_mailbox_coordinator_journal WHERE statement_key=$key LIMIT 2;";
                command.Parameters.AddWithValue("$key", key);
                using var reader = command.ExecuteReader();
                if (!reader.Read() || reader.GetInt64(0) != 32 || reader.GetString(1) != "blob" ||
                    reader.GetInt64(3) != 8 || reader.GetString(4) != "blob")
                    throw new CryptographicException("Retained Store has no exact recorded coordinator statement.");
                var actual = reader.GetFieldValue<byte[]>(2); var deadline = reader.GetFieldValue<byte[]>(5);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(actual, digest) || ReadU64(deadline) != expiry || reader.Read())
                        throw new CryptographicException("Retained Store disagrees with its original coordinator statement.");
                }
                finally { CryptographicOperations.ZeroMemory(actual); CryptographicOperations.ZeroMemory(deadline); }
                ct.ThrowIfCancellationRequested(); return Task.FromResult(true);
            }
            finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(digest); }
        }, ct);
}
#endif
