#if DEEP_CLEAN_PRODUCTION
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

/// <summary>
/// Exact, account-owned plaintext event waiting for its per-device DPE2 send.
/// This is not evidence of network delivery. Disposal clears the entry's owned
/// buffers; callers must also clear any copies obtained from its properties.
/// </summary>
public sealed class DirectTextOutboxEntry : IDisposable
{
    private byte[]? exactDmc2;
    private byte[]? operationId;
    private byte[]? logicalMessageId;

    internal DirectTextOutboxEntry(
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> logicalMessageId,
        ulong senderSequence)
    {
        this.exactDmc2 = exactDmc2.ToArray();
        this.operationId = operationId.ToArray();
        this.logicalMessageId = logicalMessageId.ToArray();
        SenderSequence = senderSequence;
    }

    public ReadOnlyMemory<byte> ExactDmc2 => Copy(exactDmc2);
    public ReadOnlyMemory<byte> OperationId => Copy(operationId);
    public ReadOnlyMemory<byte> LogicalMessageId => Copy(logicalMessageId);
    public ulong SenderSequence { get; }

    public void Dispose()
    {
        Zero(ref exactDmc2);
        Zero(ref operationId);
        Zero(ref logicalMessageId);
    }

    private static ReadOnlyMemory<byte> Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(DirectTextOutboxEntry))).ToArray();

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

public sealed partial class SqliteDeepMailboxStore
{
    private const long MaximumDirectOutboxEvents = 100_000;

    /// <summary>
    /// Atomically reserves the next conversation/device sequence and one exact
    /// canonical MessageCreate. The first two sequence positions belong to the
    /// first-contact control exchange; a retry reads this row, never reauthors.
    /// </summary>
    internal Task<DirectTextOutboxEntry> StageDirectTextAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> localDeviceId,
        ReadOnlyMemory<byte> conversationId,
        ReadOnlyMemory<byte> recipientAccountId,
        ReadOnlyMemory<byte> recipientDeviceId,
        string text,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken = default)
    {
        if (networkId.Length != 16 || networkId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero network ID is required.", nameof(networkId));
        foreach (var (value, name) in new[] {
                     (localAccountId, nameof(localAccountId)),
                     (localDeviceId, nameof(localDeviceId)),
                     (conversationId, nameof(conversationId)),
                     (recipientAccountId, nameof(recipientAccountId)),
                     (recipientDeviceId, nameof(recipientDeviceId)) })
            RequireDirectId(value, name);
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));
        var createdMilliseconds = createdAt.ToUnixTimeMilliseconds();
        if (createdMilliseconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(createdAt));
        var payload = ApplicationCoreCodec.CreateMessageCreatePayload(text);

        return WithReplayConnectionAsync(connection =>
        {
            var network = networkId.ToArray();
            var local = localAccountId.ToArray();
            var localGeneration = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(localGeneration, localAccountGeneration);
            var device = localDeviceId.ToArray();
            var conversation = conversationId.ToArray();
            var recipientAccount = recipientAccountId.ToArray();
            var recipientDevice = recipientDeviceId.ToArray();
            var logical = RandomNonzero32();
            var operation = RandomNonzero32();
            byte[]? exact = null;
            byte[]? exactHash = null;
            try
            {
                using var transaction = connection.BeginTransaction(deferred: false);
                BindDirectInboxOwner(connection, transaction, local, localGeneration);

                using var count = connection.CreateCommand();
                count.Transaction = transaction;
                count.CommandText = "SELECT count(*) FROM direct_text_outbox;";
                if (Convert.ToInt64(count.ExecuteScalar(),
                        System.Globalization.CultureInfo.InvariantCulture) >= MaximumDirectOutboxEvents)
                    throw new InvalidOperationException("The direct text outbox is at capacity.");

                long sequence;
                using (var read = connection.CreateCommand())
                {
                    read.Transaction = transaction;
                    read.CommandText = "SELECT next_sequence FROM direct_sender_sequences WHERE conversation_id=$conversation AND author_device_id=$device;";
                    read.Parameters.AddWithValue("$conversation", conversation);
                    read.Parameters.AddWithValue("$device", device);
                    var next = read.ExecuteScalar();
                    sequence = next is null ? 3 : Convert.ToInt64(next,
                        System.Globalization.CultureInfo.InvariantCulture);
                }
                if (sequence is < 3 or >= long.MaxValue)
                    throw new CryptographicException("The direct sender sequence is invalid or exhausted.");

                var authored = ApplicationCoreCodec.AuthorDmc2(
                    network, logical, conversation, local, device,
                    checked((ulong)sequence), checked((ulong)createdMilliseconds),
                    expiresAtUnixMilliseconds: 0, Dmc2Flags.None,
                    ReadOnlySpan<byte>.Empty, payload);
                exact = authored.CanonicalBytes.ToArray();
                exactHash = SHA256.HashData(exact);

                using (var advance = connection.CreateCommand())
                {
                    advance.Transaction = transaction;
                    advance.CommandText = "INSERT INTO direct_sender_sequences VALUES($conversation,$device,$next) ON CONFLICT(conversation_id,author_device_id) DO UPDATE SET next_sequence=$next;";
                    advance.Parameters.AddWithValue("$conversation", conversation);
                    advance.Parameters.AddWithValue("$device", device);
                    advance.Parameters.AddWithValue("$next", checked(sequence + 1));
                    if (advance.ExecuteNonQuery() != 1)
                        throw new CryptographicException("The direct sender sequence was not reserved.");
                }

                using (var insert = connection.CreateCommand())
                {
                    insert.Transaction = transaction;
                    insert.CommandText = "INSERT INTO direct_text_outbox VALUES($conversation,$logical,$device,$recipientAccount,$recipientDevice,$sequence,$operation,$hash,$exact,$created);";
                    insert.Parameters.AddWithValue("$conversation", conversation);
                    insert.Parameters.AddWithValue("$logical", logical);
                    insert.Parameters.AddWithValue("$device", device);
                    insert.Parameters.AddWithValue("$recipientAccount", recipientAccount);
                    insert.Parameters.AddWithValue("$recipientDevice", recipientDevice);
                    insert.Parameters.AddWithValue("$sequence", sequence);
                    insert.Parameters.AddWithValue("$operation", operation);
                    insert.Parameters.AddWithValue("$hash", exactHash);
                    insert.Parameters.AddWithValue("$exact", exact);
                    insert.Parameters.AddWithValue("$created", createdMilliseconds);
                    if (insert.ExecuteNonQuery() != 1)
                        throw new CryptographicException("The exact direct text event was not staged.");
                }
                cancellationToken.ThrowIfCancellationRequested();
                transaction.Commit();
                return Task.FromResult(new DirectTextOutboxEntry(
                    exact, operation, logical, checked((ulong)sequence)));
            }
            finally
            {
                foreach (var value in new[] { network, local, localGeneration, device,
                             conversation, recipientAccount, recipientDevice, logical, operation,
                             exact, exactHash })
                    if (value is not null) CryptographicOperations.ZeroMemory(value);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Reopens only the exact staged event for the same account generation and
    /// recipient device. A changed row or sender high-water fails closed.
    /// </summary>
    internal Task<DirectTextOutboxEntry?> ReadDirectTextAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> localAccountId,
        ulong localAccountGeneration,
        ReadOnlyMemory<byte> conversationId,
        ReadOnlyMemory<byte> logicalMessageId,
        ReadOnlyMemory<byte> recipientAccountId,
        ReadOnlyMemory<byte> recipientDeviceId,
        CancellationToken cancellationToken = default)
    {
        if (networkId.Length != 16 || networkId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero network ID is required.", nameof(networkId));
        foreach (var (value, name) in new[] {
                     (localAccountId, nameof(localAccountId)),
                     (conversationId, nameof(conversationId)),
                     (logicalMessageId, nameof(logicalMessageId)),
                     (recipientAccountId, nameof(recipientAccountId)),
                     (recipientDeviceId, nameof(recipientDeviceId)) })
            RequireDirectId(value, name);
        if (localAccountGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(localAccountGeneration));

        return WithReplayConnectionAsync(connection =>
        {
            var network = networkId.ToArray();
            var local = localAccountId.ToArray();
            var generation = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(generation, localAccountGeneration);
            var conversation = conversationId.ToArray();
            var logical = logicalMessageId.ToArray();
            var recipientAccount = recipientAccountId.ToArray();
            var recipientDevice = recipientDeviceId.ToArray();
            try
            {
                using (var owner = connection.CreateCommand())
                {
                    owner.CommandText = "SELECT local_account_id,local_account_generation FROM authenticated_dmc2_inbox_owner WHERE singleton=1;";
                    using var reader = owner.ExecuteReader();
                    if (!reader.Read()) return Task.FromResult<DirectTextOutboxEntry?>(null);
                    var storedAccount = (byte[])reader[0];
                    var storedGeneration = (byte[])reader[1];
                    try
                    {
                        if (!DirectFixed(storedAccount, local) ||
                            !DirectFixed(storedGeneration, generation) || reader.Read())
                            throw new CryptographicException("The direct outbox belongs to another account generation.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(storedAccount);
                        CryptographicOperations.ZeroMemory(storedGeneration);
                    }
                }
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT author_device_id,recipient_account_id,recipient_device_id,sender_sequence,operation_id,exact_dmc2_hash,exact_dmc2,created_at FROM direct_text_outbox WHERE conversation_id=$conversation AND logical_message_id=$logical;";
                read.Parameters.AddWithValue("$conversation", conversation);
                read.Parameters.AddWithValue("$logical", logical);
                using var row = read.ExecuteReader();
                if (!row.Read()) return Task.FromResult<DirectTextOutboxEntry?>(null);
                var device = (byte[])row[0];
                var storedRecipientAccount = (byte[])row[1];
                var storedRecipientDevice = (byte[])row[2];
                var sequence = row.GetInt64(3);
                var operation = (byte[])row[4];
                var hash = (byte[])row[5];
                var exact = (byte[])row[6];
                var created = row.GetInt64(7);
                byte[]? actualHash = null;
                byte[]? canonicalBytes = null;
                try
                {
                    var canonical = ApplicationCoreCodec.DecodeDmc2(exact);
                    actualHash = SHA256.HashData(exact);
                    canonicalBytes = canonical.CanonicalBytes.ToArray();
                    if (!DirectFixed(storedRecipientAccount, recipientAccount) ||
                        !DirectFixed(storedRecipientDevice, recipientDevice) ||
                        !DirectFixed(canonical.NetworkId.Span, network) ||
                        !DirectFixed(actualHash, hash) ||
                        !DirectFixed(canonicalBytes, exact) ||
                        !DirectFixed(canonical.SenderAccountId.Span, local) ||
                        !DirectFixed(canonical.SenderDeviceId.Span, device) ||
                        !DirectFixed(canonical.ConversationId.Span, conversation) ||
                        !DirectFixed(canonical.LogicalMessageId.Span, logical) ||
                        canonical.ContentKind != Dmc2ContentKind.MessageCreate ||
                        canonical.SenderClientSequence != checked((ulong)sequence) ||
                        canonical.CreatedAtUnixMilliseconds != checked((ulong)created) ||
                        operation.Length != 32 || operation.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                        row.Read())
                        throw new CryptographicException("The staged direct text differs from its durable scope.");
                    row.Close();
                    using var highWater = connection.CreateCommand();
                    highWater.CommandText = "SELECT next_sequence FROM direct_sender_sequences WHERE conversation_id=$conversation AND author_device_id=$device;";
                    highWater.Parameters.AddWithValue("$conversation", conversation);
                    highWater.Parameters.AddWithValue("$device", device);
                    var next = highWater.ExecuteScalar();
                    if (next is null || Convert.ToInt64(next,
                            System.Globalization.CultureInfo.InvariantCulture) <= sequence)
                        throw new CryptographicException("The direct sender sequence high-water is invalid.");
                    return Task.FromResult<DirectTextOutboxEntry?>(new(
                        exact, operation, logical, checked((ulong)sequence)));
                }
                finally
                {
                    foreach (var value in new[] { device, storedRecipientAccount,
                                 storedRecipientDevice, operation, hash, exact,
                                 actualHash, canonicalBytes })
                        if (value is not null) CryptographicOperations.ZeroMemory(value);
                }
            }
            finally
            {
                foreach (var value in new[] { network, local, generation, conversation,
                             logical, recipientAccount, recipientDevice })
                    CryptographicOperations.ZeroMemory(value);
            }
        }, cancellationToken);
    }

    private static byte[] RandomNonzero32()
    {
        while (true)
        {
            var value = RandomNumberGenerator.GetBytes(32);
            if (value.AsSpan().IndexOfAnyExcept((byte)0) >= 0) return value;
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
#endif
