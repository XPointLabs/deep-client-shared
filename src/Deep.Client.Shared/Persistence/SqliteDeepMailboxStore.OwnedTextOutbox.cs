using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    // The actual account owner supplies its protected journal while holding
    // its lease. This SQL mirror is neither a public author nor crypto proof.
    // Optional rows are owner-private, disposable copies; the caller must clear
    // the collection on success or failure. Never publish partial SQL readback.
    internal Task<DirectTextOutboxEntry?> ReconcileOwnedTextOutboxAsync(
        ProtectedDid2DirectTextJournal.State journal, ReadOnlyMemory<byte> account,
        ulong generation, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> selectOperation,
        CancellationToken ct, List<DirectTextOutboxEntry>? retainedEntries = null)
    {
        ArgumentNullException.ThrowIfNull(journal); ArgumentNullException.ThrowIfNull(scope);
        RequireDirectId(account, nameof(account));
        if (generation == 0) throw new ArgumentOutOfRangeException(nameof(generation));
        if (!selectOperation.IsEmpty) RequireDirectId(selectOperation, nameof(selectOperation));
        var local = account.ToArray(); var selection = selectOperation.ToArray();
        var ownerGeneration = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(ownerGeneration, generation);
        return RunAsync();
        async Task<DirectTextOutboxEntry?> RunAsync()
        {
            try
            {
                return await WithReplayConnectionAsync(connection =>
                {
                    using var tx = connection.BeginTransaction(deferred: false);
                    BindDirectInboxOwner(connection, tx, local, ownerGeneration);
                    foreach (var entry in journal.Entries.Values)
                        if (!DirectFixed(entry.Scope.LocalAccount, local) ||
                            BinaryPrimitives.ReadUInt64BigEndian(entry.Scope.Exact[84..]) != generation ||
                            !journal.Floors.TryGetValue(entry.Position, out var floor) ||
                            !DirectFixed(floor.Scope.Exact, entry.Scope.Exact) || entry.Sequence >= floor.NextSequence)
                            throw new CryptographicException("The protected text journal belongs to another account generation.");
                    foreach (var floor in journal.Floors.Values)
                        if (!DirectFixed(floor.Scope.LocalAccount, local) ||
                            BinaryPrimitives.ReadUInt64BigEndian(floor.Scope.Exact[84..]) != generation)
                            throw new CryptographicException("The authored floor belongs to another account generation.");
                    var pending = journal.Pending;
                    var stableCount = journal.Entries.Count - (pending is null ? 0 : 1);
                    using var count = connection.CreateCommand(); count.Transaction = tx;
                    count.CommandText = "SELECT count(*) FROM direct_text_outbox;";
                    var rowCount = Convert.ToInt64(count.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
                    if (rowCount < stableCount || rowCount > journal.Entries.Count)
                        throw new CryptographicException("The SQL text outbox differs from its protected row floor.");
                    var found = new HashSet<string>(StringComparer.Ordinal);
                    DirectTextOutboxEntry? result = null;
                    try
                    {
                        using (var read = connection.CreateCommand())
                        {
                            read.Transaction = tx;
                            read.CommandText = "SELECT conversation_id,logical_message_id,author_device_id,recipient_account_id,recipient_device_id,sender_sequence,operation_id,exact_dmc2_hash,exact_dmc2,created_at,length(exact_dmc2),typeof(exact_dmc2) FROM direct_text_outbox ORDER BY operation_id;";
                            using var row = read.ExecuteReader();
                            while (row.Read())
                            {
                                ct.ThrowIfCancellationRequested();
                                // Reject hostile payload size/type before the
                                // provider materializes a managed BLOB array.
                                if (row.GetString(11) != "blob" || row.GetInt64(10) is < 285 or > ProtectedDid2DirectTextJournal.MaximumEventBytes)
                                    throw new CryptographicException("The SQL text payload exceeds its closed protected bound.");
                                var buffers = new byte[8][];
                                try
                                {
                                    for (var i = 0; i < 5; i++) buffers[i] = (byte[])row[i];
                                    buffers[5] = (byte[])row[6]; buffers[6] = (byte[])row[7]; buffers[7] = (byte[])row[8];
                                    var name = Convert.ToHexString(buffers[5]);
                                    if (!found.Add(name) || !journal.Entries.TryGetValue(name, out var entry))
                                        throw new CryptographicException("The SQL text outbox contains an unprotected command.");
                                    var bound = entry.Scope;
                                    if (!DirectFixed(buffers[0], bound.Conversation) || !DirectFixed(buffers[1], entry.Logical) ||
                                        !DirectFixed(buffers[2], bound.LocalDevice) || !DirectFixed(buffers[3], bound.RemoteAccount) ||
                                        !DirectFixed(buffers[4], bound.RemoteDevice) || row.GetInt64(5) != checked((long)entry.Sequence) ||
                                        !DirectFixed(buffers[6], entry.EventHash) || row.GetInt64(9) != checked((long)entry.Created))
                                        throw new CryptographicException("The SQL text row differs from protected command metadata.");
                                    entry.RequireEvent(buffers[7]);
                                    retainedEntries?.Add(new(buffers[7], entry.Operation, entry.Logical, entry.Sequence));
                                    if (DirectFixed(entry.Operation, selection))
                                        result = new(buffers[7], entry.Operation, entry.Logical, entry.Sequence);
                                }
                                finally { foreach (var bytes in buffers) if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
                            }
                        }
                        if (journal.Entries.Values.Any(entry => !entry.Pending && !found.Contains(Convert.ToHexString(entry.Operation))))
                            throw new CryptographicException("A stable protected text command lost its SQL row.");
                        foreach (var floor in journal.Floors.Values)
                        {
                            var bound = floor.Scope;
                            var pendingAbsent = pending is not null &&
                                pending.Position == ProtectedDid2DirectTextJournal.Position(bound) &&
                                !found.Contains(Convert.ToHexString(pending.Operation));
                            var expected = pendingAbsent ? checked(floor.NextSequence - 1) : floor.NextSequence;
                            RequireCounter(connection, tx, bound, expected,
                                expected == ProtectedDid2DirectTextJournal.Baseline(bound) && bound.IsInitiator);
                        }
                        // The first command adopts only the exact role baseline,
                        // never a larger caller/SQL-supplied next sequence.
                        var position = Convert.ToHexString(scope.Conversation) + Convert.ToHexString(scope.LocalDevice);
                        if (!journal.Floors.ContainsKey(position))
                            RequireCounter(connection, tx, scope, scope.IsInitiator ? 3UL : 4UL, scope.IsInitiator);
                        if (pending is not null && !found.Contains(Convert.ToHexString(pending.Operation)))
                        {
                            InsertPending(connection, tx, pending);
                            retainedEntries?.Add(new(pending.PendingDmc2, pending.Operation, pending.Logical, pending.Sequence));
                            if (DirectFixed(pending.Operation, selection))
                                result = new(pending.PendingDmc2, pending.Operation, pending.Logical, pending.Sequence);
                        }
                        ct.ThrowIfCancellationRequested(); tx.Commit();
                        var released = result; result = null; return Task.FromResult(released);
                    }
                    finally { result?.Dispose(); }
                }, ct).ConfigureAwait(false);
            }
            finally
            { CryptographicOperations.ZeroMemory(local); CryptographicOperations.ZeroMemory(selection); CryptographicOperations.ZeroMemory(ownerGeneration); }
        }
    }

    private static void RequireCounter(SqliteConnection connection, SqliteTransaction tx,
        Did2MessagingSessionScope scope, ulong expected, bool allowAbsent)
    {
        using var read = connection.CreateCommand(); read.Transaction = tx;
        read.CommandText = "SELECT next_sequence FROM direct_sender_sequences WHERE conversation_id=$conversation AND author_device_id=$device;";
        read.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray());
        read.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
        var value = read.ExecuteScalar();
        if (value is null ? !allowAbsent : Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture) != checked((long)expected))
            throw new CryptographicException("The SQL sender counter differs from protected command custody.");
    }

    private static void InsertPending(SqliteConnection connection, SqliteTransaction tx,
        ProtectedDid2DirectTextJournal.Entry pending)
    {
        var scope = pending.Scope;
        using var advance = connection.CreateCommand(); advance.Transaction = tx;
        advance.CommandText = "INSERT INTO direct_sender_sequences VALUES($conversation,$device,$next) ON CONFLICT(conversation_id,author_device_id) DO UPDATE SET next_sequence=$next;";
        advance.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray());
        advance.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
        advance.Parameters.AddWithValue("$next", checked((long)pending.Sequence + 1));
        if (advance.ExecuteNonQuery() != 1) throw new CryptographicException("The pending text counter was not retained.");
        using var insert = connection.CreateCommand(); insert.Transaction = tx;
        insert.CommandText = "INSERT INTO direct_text_outbox VALUES($conversation,$logical,$device,$recipientAccount,$recipientDevice,$sequence,$operation,$hash,$exact,$created);";
        insert.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray());
        insert.Parameters.AddWithValue("$logical", pending.Logical.ToArray()); insert.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray());
        insert.Parameters.AddWithValue("$recipientAccount", scope.RemoteAccount.ToArray()); insert.Parameters.AddWithValue("$recipientDevice", scope.RemoteDevice.ToArray());
        insert.Parameters.AddWithValue("$sequence", checked((long)pending.Sequence)); insert.Parameters.AddWithValue("$operation", pending.Operation.ToArray());
        insert.Parameters.AddWithValue("$hash", pending.EventHash.ToArray()); var exact = pending.PendingDmc2.ToArray();
        try
        {
            insert.Parameters.AddWithValue("$exact", exact); insert.Parameters.AddWithValue("$created", checked((long)pending.Created));
            if (insert.ExecuteNonQuery() != 1) throw new CryptographicException("The exact pending text was not retained.");
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
