#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // Read-only negative facts. The held account owner separately authenticates
    // the native/control deadline and all protected roots before any stop.
    internal static void RequireNeverAttemptedControl(SqliteConnection connection,
        ProtectedDid2DirectTextJournal.Entry command, ReadOnlyMemory<byte> originalMailboxOperation)
    {
        using var tx = connection.BeginTransaction(deferred: true);
        ValidateTransportOutboxSchema(connection, tx); ValidateDirectInboxState(connection, tx);
        RequireSelectedOrdinaryRow(connection, tx, command, requireRetainedHistory: true);
        using (var evidence = connection.CreateCommand())
        {
            evidence.Transaction = tx;
            evidence.CommandText = "SELECT 1 FROM mailbox_store_public_evidence WHERE scope_hash=$scope AND native_operation_id=$operation LIMIT 1;";
            evidence.Parameters.AddWithValue("$scope", command.Scope.Hash.ToArray());
            evidence.Parameters.AddWithValue("$operation", command.Operation.ToArray());
            if (evidence.ExecuteScalar() is not null)
                throw new CryptographicException("Never-attempted control has retained Store evidence.");
        }
        using var outbox = connection.CreateCommand(); outbox.Transaction = tx;
        // All account scopes and states, including Prepared. A different holder
        // or a transport flag cannot turn an existing original into absence.
        outbox.CommandText = "SELECT 1 FROM transport_outbox_items WHERE logical_id=$logical LIMIT 1;";
        outbox.Parameters.AddWithValue("$logical", originalMailboxOperation.ToArray());
        if (outbox.ExecuteScalar() is not null)
            throw new CryptographicException("Never-attempted control has retained original transport custody.");
    }
}
#endif
