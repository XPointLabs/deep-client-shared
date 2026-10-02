#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteDeepMailboxStore
{
    internal async Task<byte[]?> ReadContactAcceptAsync(ReadOnlyMemory<byte> account, ulong accountGeneration,
        ReadOnlyMemory<byte> conversation, ReadOnlyMemory<byte> responderAccount, ReadOnlyMemory<byte> responderDevice, CancellationToken ct)
    {
        RequireDirectId(account, nameof(account)); RequireDirectId(conversation, nameof(conversation));
        RequireDirectId(responderAccount, nameof(responderAccount)); RequireDirectId(responderDevice, nameof(responderDevice));
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        var local = account.ToArray(); var conv = conversation.ToArray(); var responder = responderAccount.ToArray();
        var device = responderDevice.ToArray(); var generation = new byte[8]; byte[]? logical = null;
        BinaryPrimitives.WriteUInt64BigEndian(generation, accountGeneration);
        try
        {
            logical = await WithReplayConnectionAsync(connection =>
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                BindDirectInboxOwner(connection, transaction, local, generation);
                using var read = connection.CreateCommand(); read.Transaction = transaction;
                read.CommandText = "SELECT logical_message_id FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_account_id=$account AND author_device_id=$device AND content_kind=$kind LIMIT 2;";
                read.Parameters.AddWithValue("$conversation", conv); read.Parameters.AddWithValue("$account", responder);
                read.Parameters.AddWithValue("$device", device); read.Parameters.AddWithValue("$kind", (int)Deep.Protocol.ApplicationCore.Dmc2ContentKind.ContactAccept);
                using var reader = read.ExecuteReader();
                if (!reader.Read()) return Task.FromResult<byte[]?>(null);
                var id = (byte[])reader[0];
                if (id.Length != 32 || reader.Read())
                { CryptographicOperations.ZeroMemory(id); throw new CryptographicException("A contact has ambiguous acceptance rows."); }
                return Task.FromResult<byte[]?>(id);
            }, ct).ConfigureAwait(false);
            return logical is null ? null : await ReadDirectDmc2Async(local, accountGeneration, conv, logical, device, ct).ConfigureAwait(false);
        }
        finally
        {
            foreach (var bytes in new[] { local, conv, responder, device, generation }) CryptographicOperations.ZeroMemory(bytes);
            if (logical is not null) CryptographicOperations.ZeroMemory(logical);
        }
    }

    internal Task RequireUnusedContactAcceptPositionAsync(ReadOnlyMemory<byte> account, ulong accountGeneration,
        ReadOnlyMemory<byte> conversation, ReadOnlyMemory<byte> device, CancellationToken ct)
    {
        RequireDirectId(account, nameof(account)); RequireDirectId(conversation, nameof(conversation)); RequireDirectId(device, nameof(device));
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        return WithReplayConnectionAsync(connection =>
        {
            var local = account.ToArray(); var conv = conversation.ToArray(); var sender = device.ToArray(); var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, accountGeneration);
            try
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                BindDirectInboxOwner(connection, transaction, local, generation);
                using var count = connection.CreateCommand(); count.Transaction = transaction;
                count.CommandText = "SELECT count(*) FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_account_id=$account AND author_device_id=$device AND sender_sequence=x'0000000000000003';";
                count.Parameters.AddWithValue("$conversation", conv); count.Parameters.AddWithValue("$account", local); count.Parameters.AddWithValue("$device", sender);
                if (Convert.ToInt64(count.ExecuteScalar()) != 0)
                    throw new CryptographicException("Local acceptance cannot overwrite an occupied authored position.");
                using var highWater = connection.CreateCommand(); highWater.Transaction = transaction;
                highWater.CommandText = "SELECT next_sequence FROM direct_sender_sequences WHERE conversation_id=$conversation AND author_device_id=$device;";
                highWater.Parameters.AddWithValue("$conversation", conv); highWater.Parameters.AddWithValue("$device", sender);
                var value = highWater.ExecuteScalar();
                if (value is not null && Convert.ToInt64(value) != 3)
                    throw new CryptographicException("Local acceptance cannot reuse a queued or exhausted sender position.");
                return Task.FromResult(true); // Read-only: owner binding, if absent, is rolled back.
            }
            finally { foreach (var bytes in new[] { local, conv, sender, generation }) CryptographicOperations.ZeroMemory(bytes); }
        }, ct);
    }
}
#endif
