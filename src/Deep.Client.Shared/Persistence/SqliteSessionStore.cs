using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Globalization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed class SqliteSessionStore :
    ILocalSessionStore,
    IOneToOneConversationOpenRepository,
    IMessageSyncRepository,
    IMembershipTrustRepository,
    IDisposable
{
    private static ReadOnlySpan<byte> SqliteHeader => "SQLite format 3\0"u8;
    private const int PhysicalSchemaVersion = 7;
    private const int ReplayPruneBatchSize = 256;
    private const string ReadCursorSettingPrefix = "sync.read-cursor.";
    private const string MessagePayloadProjection = "json_set(payload_json, '$.deliveryState', delivery_state, '$.readAt', read_at)";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly string? _encryptionKey;
    private readonly SemaphoreSlim _databaseGate = new(1, 1);
    private readonly Action<MembershipTrustCommitFaultPoint>? _membershipTrustFaultInjector;

    private sealed record OneToOneOpenMetadata(
        string? ActiveAccountPayload,
        string? ContactPayload,
        string? ConversationPayload,
        string? ReadCursorPayload);

    private sealed record ConversationSummaryBase(
        DateTimeOffset? ReadCursor,
        Message? LastMessage,
        Contact? Contact);

    static SqliteSessionStore()
    {
        SQLitePCL.Batteries_V2.Init();
    }

    public SqliteSessionStore(string statePath)
        : this(new SqliteSessionStoreOptions(statePath))
    {
    }

    public SqliteSessionStore(SqliteSessionStoreOptions options)
        : this(options, null)
    {
    }

    internal SqliteSessionStore(
        SqliteSessionStoreOptions options,
        Action<MembershipTrustCommitFaultPoint>? faultInjector)
    {
        var statePath = options.StatePath;
        if (string.IsNullOrWhiteSpace(statePath))
        {
            throw new ArgumentException("State path is required.", nameof(statePath));
        }

        var directory = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _encryptionKey = string.IsNullOrWhiteSpace(options.EncryptionKey) ? null : options.EncryptionKey;
        _membershipTrustFaultInjector = faultInjector;
        _connectionString = ConnectionStringFor(
            statePath,
            _encryptionKey,
            pooling: _encryptionKey is not null);

        InitializeSchema();
    }

    public static void EnsureEncryptedDatabase(string statePath, string encryptionKey)
    {
        if (string.IsNullOrWhiteSpace(statePath))
        {
            throw new ArgumentException("State path is required.", nameof(statePath));
        }

        if (string.IsNullOrWhiteSpace(encryptionKey))
        {
            throw new ArgumentException("Encryption key is required.", nameof(encryptionKey));
        }

        var tempPath = statePath + ".encrypted-migration";
        var backupPath = statePath + ".plaintext-migration";
        RecoverInterruptedEncryptionMigration(statePath, tempPath, backupPath, encryptionKey);

        if (!File.Exists(statePath))
        {
            return;
        }

        if (!HasPlaintextSqliteHeader(statePath))
        {
            if (!CanOpenDatabase(statePath, encryptionKey))
            {
                throw new InvalidOperationException("Encrypted local state database cannot be opened with the configured key.");
            }

            SecureDeleteSqliteFileSet(tempPath);
            SecureDeleteSqliteFileSet(backupPath);
            return;
        }

        if (!CanOpenDatabase(statePath, null))
        {
            throw new InvalidOperationException("Local state database cannot be opened with the configured key and is not a plaintext database.");
        }

        SecureDeleteSqliteFileSet(tempPath);
        SecureDeleteSqliteFileSet(backupPath);

        using (var source = OpenConnectionForPath(statePath, null))
        {
            ExecuteNonQuery(source, "PRAGMA wal_checkpoint(TRUNCATE);");
            ExecuteNonQuery(
                source,
                $"""
                ATTACH DATABASE '{EscapePragmaString(tempPath)}' AS encrypted KEY '{EscapePragmaString(encryptionKey)}';
                SELECT sqlcipher_export('encrypted');
                DETACH DATABASE encrypted;
                """);
        }

        if (!CanOpenDatabase(tempPath, encryptionKey))
        {
            DeleteSqliteFileSet(tempPath);
            throw new InvalidOperationException("Encrypted local state migration did not produce a readable SQLCipher database.");
        }

        CompleteEncryptionMigrationSwap(statePath, tempPath, backupPath, encryptionKey);
    }

    private static void RecoverInterruptedEncryptionMigration(
        string statePath,
        string tempPath,
        string backupPath,
        string encryptionKey)
    {
        if (File.Exists(statePath))
        {
            if (CanOpenDatabase(statePath, encryptionKey))
            {
                SecureDeleteSqliteFileSet(tempPath);
                SecureDeleteSqliteFileSet(backupPath);
                return;
            }

            if (!HasPlaintextSqliteHeader(statePath) || !CanOpenDatabase(statePath, null))
            {
                throw new InvalidOperationException("Local state database is neither valid plaintext nor readable with the configured encryption key.");
            }

            if (CanOpenDatabase(tempPath, encryptionKey))
            {
                CompleteEncryptionMigrationSwap(statePath, tempPath, backupPath, encryptionKey);
                return;
            }

            SecureDeleteSqliteFileSet(tempPath);
            SecureDeleteSqliteFileSet(backupPath);
            return;
        }

        if (CanOpenDatabase(tempPath, encryptionKey))
        {
            SecureDeleteSqliteSidecars(statePath);
            File.Move(tempPath, statePath);
            SecureDeleteSqliteSidecars(tempPath);
            if (!CanOpenDatabase(statePath, encryptionKey))
            {
                throw new InvalidOperationException("Interrupted local state migration could not promote the encrypted database.");
            }

            SecureDeleteSqliteFileSet(backupPath);
            return;
        }

        SecureDeleteSqliteFileSet(tempPath);
        if (CanOpenDatabase(backupPath, null))
        {
            SecureDeleteSqliteSidecars(statePath);
            File.Move(backupPath, statePath);
            SecureDeleteSqliteSidecars(backupPath);
            return;
        }

        if (File.Exists(backupPath))
        {
            throw new InvalidOperationException("Interrupted local state migration left an unreadable plaintext backup.");
        }
    }

    private static void CompleteEncryptionMigrationSwap(
        string statePath,
        string tempPath,
        string backupPath,
        string encryptionKey)
    {
        SecureDeleteSqliteFileSet(backupPath);
        try
        {
            File.Move(statePath, backupPath);
            SecureDeleteSqliteSidecars(statePath);
            File.Move(tempPath, statePath);
            SecureDeleteSqliteSidecars(tempPath);
            if (!CanOpenDatabase(statePath, encryptionKey))
            {
                throw new InvalidOperationException("Encrypted local state migration produced an unreadable database after promotion.");
            }

            SecureDeleteSqliteFileSet(backupPath);
        }
        catch
        {
            if (!File.Exists(statePath) && File.Exists(backupPath))
            {
                File.Move(backupPath, statePath);
            }

            throw;
        }
    }

    public async Task UpsertAsync(Conversation conversation, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO conversations (id, updated_at, payload_json)
            VALUES ($id, $updatedAt, $payload)
            ON CONFLICT(id) DO UPDATE SET
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, new (string, object?)[]
        {
            ("$id", conversation.Id.Value),
            ("$updatedAt", conversation.UpdatedAt.ToUnixTimeMilliseconds()),
            ("$payload", JsonSerializer.Serialize(conversation, SerializerOptions))
        }).ConfigureAwait(false);
    }

    public async Task<Conversation?> GetAsync(ConversationId id, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT payload_json FROM conversations WHERE id = $id;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$id", id.Value)).ConfigureAwait(false);
        return payload is null ? null : JsonSerializer.Deserialize<Conversation>(payload, SerializerOptions);
    }

    async IAsyncEnumerable<Conversation> IConversationRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM conversations ORDER BY updated_at DESC;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Conversation>(payload, SerializerOptions)!;
        }
    }

    public async Task UpsertAsync(Contact contact, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO contacts (id, sort_name, payload_json)
            VALUES ($id, $sortName, $payload)
            ON CONFLICT(id) DO UPDATE SET
                sort_name = excluded.sort_name,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, new (string, object?)[]
        {
            ("$id", contact.Id.Value),
            ("$sortName", contact.DisplayName ?? contact.Id.Value),
            ("$payload", JsonSerializer.Serialize(contact, SerializerOptions))
        }).ConfigureAwait(false);
    }

    public Task DeleteAsync(SessionId id, CancellationToken cancellationToken = default) =>
        ExecuteNonQueryAsync(
            "DELETE FROM contacts WHERE id = $id;",
            cancellationToken,
            ("$id", id.Value));

    public async Task<Contact?> GetAsync(SessionId id, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT payload_json FROM contacts WHERE id = $id;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$id", id.Value)).ConfigureAwait(false);
        return payload is null ? null : JsonSerializer.Deserialize<Contact>(payload, SerializerOptions);
    }

    async IAsyncEnumerable<Contact> IContactRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM contacts ORDER BY sort_name;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Contact>(payload, SerializerOptions)!;
        }
    }

    public async Task UpsertAsync(Group group, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO groups (id, sort_name, payload_json)
            VALUES ($id, $sortName, $payload)
            ON CONFLICT(id) DO UPDATE SET
                sort_name = excluded.sort_name,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, new (string, object?)[]
        {
            ("$id", group.Id.Value),
            ("$sortName", group.Name),
            ("$payload", JsonSerializer.Serialize(group, SerializerOptions))
        }).ConfigureAwait(false);
    }

    async Task<Group?> IGroupRepository.GetAsync(ConversationId id, CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM groups WHERE id = $id;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$id", id.Value)).ConfigureAwait(false);
        return payload is null ? null : JsonSerializer.Deserialize<Group>(payload, SerializerOptions);
    }

    async IAsyncEnumerable<Group> IGroupRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM groups ORDER BY sort_name;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Group>(payload, SerializerOptions)!;
        }
    }

    public async Task AppendAsync(Message message, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO messages (
                id,
                conversation_id,
                created_at,
                direction,
                delivery_state,
                read_at,
                expires_at,
                sender_session_id,
                recipient_session_id,
                server_hash,
                self_echo_key,
                payload_json)
            VALUES (
                $id,
                $conversationId,
                $createdAt,
                $direction,
                $deliveryState,
                $readAt,
                $expiresAt,
                $senderSessionId,
                $recipientSessionId,
                $serverHash,
                $selfEchoKey,
                $payload)
            ON CONFLICT(id) DO UPDATE SET
                conversation_id = excluded.conversation_id,
                created_at = excluded.created_at,
                direction = excluded.direction,
                delivery_state = excluded.delivery_state,
                read_at = excluded.read_at,
                expires_at = excluded.expires_at,
                sender_session_id = excluded.sender_session_id,
                recipient_session_id = excluded.recipient_session_id,
                server_hash = excluded.server_hash,
                self_echo_key = excluded.self_echo_key,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, MessageParameters(message)).ConfigureAwait(false);
    }

    public Task UpdateAsync(Message message, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE messages
            SET conversation_id = $conversationId,
                created_at = $createdAt,
                direction = $direction,
                delivery_state = $deliveryState,
                read_at = $readAt,
                expires_at = $expiresAt,
                sender_session_id = $senderSessionId,
                recipient_session_id = $recipientSessionId,
                server_hash = $serverHash,
                self_echo_key = $selfEchoKey,
                payload_json = $payload
            WHERE id = $id;
            """;
        return ExecuteNonQueryAsync(sql, cancellationToken, MessageParameters(message));
    }

    public Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default)
    {
        const string sql = "DELETE FROM messages WHERE id = $id;";
        return ExecuteNonQueryAsync(sql, cancellationToken, ("$id", id.Value));
    }

    public async Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT {MessagePayloadProjection} FROM messages WHERE id = $id;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$id", id.Value)).ConfigureAwait(false);
        return payload is null ? null : JsonSerializer.Deserialize<Message>(payload, SerializerOptions);
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListForConversationAsync(
        ConversationId conversationId,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var sql = $"SELECT {MessagePayloadProjection} FROM messages WHERE conversation_id = $conversationId ORDER BY created_at, id;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken, ("$conversationId", conversationId.Value)).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!;
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListRecentForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var sql = $"""
            SELECT payload_json
            FROM (
                SELECT {MessagePayloadProjection} AS payload_json, created_at, id
                FROM messages
                WHERE conversation_id = $conversationId
                    AND (expires_at IS NULL OR expires_at > $now)
                ORDER BY created_at DESC, id DESC
                LIMIT $limit
            )
            ORDER BY created_at, id;
            """;

        foreach (var payload in await QueryJsonAsync(
                         sql,
                         cancellationToken,
                         ("$conversationId", conversationId.Value),
                         ("$now", now.ToString("O", CultureInfo.InvariantCulture)),
                         ("$limit", limit)).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!;
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListBeforeForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        MessageId beforeMessageId,
        DateTimeOffset now,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var sql = $"""
            SELECT payload_json
            FROM (
                SELECT {MessagePayloadProjection} AS payload_json, created_at, id
                FROM messages
                WHERE conversation_id = $conversationId
                    AND (
                        created_at < $beforeCreatedAt
                        OR (created_at = $beforeCreatedAt AND id < $beforeMessageId)
                    )
                    AND (expires_at IS NULL OR expires_at > $now)
                ORDER BY created_at DESC, id DESC
                LIMIT $limit
            )
            ORDER BY created_at, id;
            """;

        foreach (var payload in await QueryJsonAsync(
                         sql,
                         cancellationToken,
                         ("$conversationId", conversationId.Value),
                         ("$beforeCreatedAt", beforeCreatedAt.ToUnixTimeMilliseconds()),
                         ("$beforeMessageId", beforeMessageId.Value),
                         ("$now", now.ToString("O", CultureInfo.InvariantCulture)),
                         ("$limit", limit)).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!;
        }
    }

    async Task<int> IMessageRepository.CountUnreadForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset? readCursor,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT COUNT(*)
            FROM messages
            WHERE conversation_id = $conversationId
              AND direction = $incomingDirection
              AND delivery_state != $readState
              AND (expires_at IS NULL OR expires_at > $now);
            """;

        var count = await ExecuteScalarAsync<long>(
            sql,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$incomingDirection", (int)MessageDirection.Incoming),
            ("$readState", (int)MessageDeliveryState.Read),
            ("$now", now.ToString("O", CultureInfo.InvariantCulture))).ConfigureAwait(false);

        return (int)count;
    }

    public async Task<bool> ContainsServerHashAsync(
        ConversationId conversationId,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serverHash))
        {
            return false;
        }

        const string sql = """
            SELECT EXISTS (
                SELECT 1
                FROM messages
                WHERE conversation_id = $conversationId
                  AND server_hash = $serverHash);
            """;
        return await ExecuteScalarAsync<long>(
            sql,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$serverHash", serverHash)).ConfigureAwait(false) == 1;
    }

    public async Task<bool> ContainsMatchingSelfOutgoingAsync(
        ConversationId conversationId,
        SessionId account,
        DateTimeOffset createdAt,
        string body,
        IReadOnlyList<AttachmentMetadata> attachments,
        CancellationToken cancellationToken = default)
    {
        var selfEchoKey = MessagePersistenceKeys.SelfEcho(createdAt, body, attachments);
        const string sql = """
            SELECT EXISTS (
                SELECT 1
                FROM messages
                WHERE conversation_id = $conversationId
                  AND sender_session_id = $account
                  AND recipient_session_id = $account
                  AND direction = $outgoingDirection
                  AND self_echo_key = $selfEchoKey);
            """;
        return await ExecuteScalarAsync<long>(
            sql,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$account", account.Value),
            ("$outgoingDirection", (int)MessageDirection.Outgoing),
            ("$selfEchoKey", selfEchoKey)).ConfigureAwait(false) == 1;
    }

    public Task<int> DeleteDuplicateSelfIncomingAsync(
        ConversationId conversationId,
        SessionId account,
        CancellationToken cancellationToken = default) =>
        ExecuteNonQueryCountAsync(
            """
            DELETE FROM messages AS incoming
            WHERE incoming.conversation_id = $conversationId
              AND incoming.sender_session_id = $account
              AND incoming.recipient_session_id = $account
              AND incoming.direction = $incomingDirection
              AND EXISTS (
                  SELECT 1
                  FROM messages AS outgoing
                  WHERE outgoing.conversation_id = incoming.conversation_id
                    AND outgoing.sender_session_id = $account
                    AND outgoing.recipient_session_id = $account
                    AND outgoing.direction = $outgoingDirection
                    AND outgoing.self_echo_key = incoming.self_echo_key);
            """,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$account", account.Value),
            ("$incomingDirection", (int)MessageDirection.Incoming),
            ("$outgoingDirection", (int)MessageDirection.Outgoing));

    public async Task<IReadOnlyList<Message>> ListPendingOutgoingAsync(
        SessionId sender,
        CancellationToken cancellationToken = default)
    {
        var sql = $"""
            SELECT {MessagePayloadProjection}
            FROM messages
            WHERE sender_session_id = $sender
              AND direction = $outgoingDirection
              AND delivery_state IN ($sendingState, $failedState)
            ORDER BY created_at, id;
            """;
        var payloads = await QueryJsonAsync(
            sql,
            cancellationToken,
            ("$sender", sender.Value),
            ("$outgoingDirection", (int)MessageDirection.Outgoing),
            ("$sendingState", (int)MessageDeliveryState.Sending),
            ("$failedState", (int)MessageDeliveryState.Failed)).ConfigureAwait(false);
        return payloads
            .Select(payload => JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!)
            .ToArray();
    }

    public Task<ConversationReadResult> MarkConversationReadIfUnreadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default) =>
        WithConnectionAsync(
            connection => MarkConversationReadOnConnectionAsync(connection, conversationId, readAt, cancellationToken),
            cancellationToken);

    public Task<int> ApplyReadCursorAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default) =>
        WithConnectionAsync(
            connection => ApplyReadCursorOnConnectionAsync(connection, conversationId, readAt, cancellationToken),
            cancellationToken);

    public Task MarkConversationReadAsync(
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken = default) =>
        MarkConversationReadIfUnreadAsync(conversationId, readAt, cancellationToken);

    public Task AppendMessageAndTouchConversationAsync(
        Message message,
        Conversation conversation,
        CancellationToken cancellationToken = default) =>
        WithConnectionAsync(async connection =>
        {
            using var transaction = connection.BeginTransaction();
            bool messageAlreadyExists;
            await using (var existingMessageCommand = connection.CreateCommand())
            {
                existingMessageCommand.Transaction = transaction;
                existingMessageCommand.CommandText =
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE id = $id);";
                existingMessageCommand.Parameters.AddWithValue("$id", message.Id.Value);
                messageAlreadyExists = Convert.ToInt32(
                    await existingMessageCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    CultureInfo.InvariantCulture) != 0;
            }

            await using (var messageCommand = connection.CreateCommand())
            {
                messageCommand.Transaction = transaction;
                messageCommand.CommandText = """
                    INSERT INTO messages (
                        id,
                        conversation_id,
                        created_at,
                        direction,
                        delivery_state,
                        read_at,
                        expires_at,
                        sender_session_id,
                        recipient_session_id,
                        server_hash,
                        self_echo_key,
                        payload_json)
                    VALUES (
                        $id,
                        $conversationId,
                        $createdAt,
                        $direction,
                        $deliveryState,
                        $readAt,
                        $expiresAt,
                        $senderSessionId,
                        $recipientSessionId,
                        $serverHash,
                        $selfEchoKey,
                        $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        conversation_id = excluded.conversation_id,
                        created_at = excluded.created_at,
                        direction = excluded.direction,
                        delivery_state = excluded.delivery_state,
                        read_at = excluded.read_at,
                        expires_at = excluded.expires_at,
                        sender_session_id = excluded.sender_session_id,
                        recipient_session_id = excluded.recipient_session_id,
                        server_hash = excluded.server_hash,
                        self_echo_key = excluded.self_echo_key,
                        payload_json = excluded.payload_json;
                    """;
                AddParameters(messageCommand, MessageParameters(message));
                await messageCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await messageCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            if (!messageAlreadyExists && message.Direction == MessageDirection.Incoming)
            {
                await using var notificationCommand = connection.CreateCommand();
                notificationCommand.Transaction = transaction;
                notificationCommand.CommandText = """
                    INSERT INTO incoming_message_notifications (message_id)
                    VALUES ($messageId)
                    ON CONFLICT(message_id) DO NOTHING;
                    """;
                notificationCommand.Parameters.AddWithValue("$messageId", message.Id.Value);
                await notificationCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await notificationCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using (var conversationCommand = connection.CreateCommand())
            {
                conversationCommand.Transaction = transaction;
                conversationCommand.CommandText = """
                    INSERT INTO conversations (id, updated_at, payload_json)
                    VALUES ($id, $updatedAt, $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        updated_at = excluded.updated_at,
                        payload_json = excluded.payload_json;
                    """;
                conversationCommand.Parameters.AddWithValue("$id", conversation.Id.Value);
                conversationCommand.Parameters.AddWithValue("$updatedAt", conversation.UpdatedAt.ToUnixTimeMilliseconds());
                conversationCommand.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(conversation, SerializerOptions));
                await conversationCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await conversationCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            transaction.Commit();
        }, cancellationToken);

    public async Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        CancellationToken cancellationToken = default) =>
        await ListPendingIncomingMessageNotificationIdsAsync(limit, [], cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<PendingIncomingMessageNotification>> ListPendingIncomingMessageNotificationIdsAsync(
        int limit,
        IReadOnlyCollection<ConversationId> excludedConversationIds,
        CancellationToken cancellationToken = default)
    {
        ValidateIncomingMessageNotificationLimit(limit);
        ArgumentNullException.ThrowIfNull(excludedConversationIds);
        var excluded = excludedConversationIds
            .Select(static id => id.Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var now = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        await ExecuteNonQueryAsync(
            """
            DELETE FROM incoming_message_notifications
            WHERE message_id NOT IN (
                SELECT id
                FROM messages
                WHERE direction = $incomingDirection
                  AND delivery_state != $readState
                  AND read_at IS NULL
                  AND (expires_at IS NULL OR julianday(expires_at) > julianday($now))
            );
            """,
            cancellationToken,
            ("$incomingDirection", (int)MessageDirection.Incoming),
            ("$readState", (int)MessageDeliveryState.Read),
            ("$now", now)).ConfigureAwait(false);

        return await WithConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            var exclusionParameters = Enumerable.Range(0, excluded.Length)
                .Select(static index => $"$excluded{index}")
                .ToArray();
            var exclusionClause = exclusionParameters.Length == 0
                ? string.Empty
                : $"AND message.conversation_id NOT IN ({string.Join(", ", exclusionParameters)})";
            command.CommandText = $$"""
                SELECT notification.message_id, message.conversation_id
                FROM incoming_message_notifications AS notification
                INNER JOIN messages AS message ON message.id = notification.message_id
                WHERE message.direction = $incomingDirection
                  AND message.delivery_state != $readState
                  AND message.read_at IS NULL
                  AND (message.expires_at IS NULL OR julianday(message.expires_at) > julianday($now))
                  {{exclusionClause}}
                ORDER BY notification.sequence
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
            command.Parameters.AddWithValue("$readState", (int)MessageDeliveryState.Read);
            command.Parameters.AddWithValue(
                "$now",
                now);
            command.Parameters.AddWithValue("$limit", limit);
            for (var index = 0; index < excluded.Length; index++)
            {
                command.Parameters.AddWithValue(exclusionParameters[index], excluded[index]);
            }
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            var result = new List<PendingIncomingMessageNotification>();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                result.Add(new PendingIncomingMessageNotification(
                    new MessageId(reader.GetString(0)),
                    new ConversationId(reader.GetString(1))));
            }

            return (IReadOnlyList<PendingIncomingMessageNotification>)result;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task MarkIncomingMessageNotificationsPresentedAsync(
        IReadOnlyCollection<MessageId> ids,
        CancellationToken cancellationToken = default)
    {
        var messageIds = ValidateIncomingMessageNotificationIds(ids);
        if (messageIds.Length == 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        await ExecuteNonQueryAsync(
            """
            DELETE FROM incoming_message_notifications
            WHERE message_id IN (
                SELECT CAST(value AS TEXT)
                FROM json_each($messageIdsJson)
            );
            """,
            cancellationToken,
            ("$messageIdsJson", JsonSerializer.Serialize(messageIds, SerializerOptions))).ConfigureAwait(false);
    }

    public async Task<int> DeleteExpiredMessagesAsync(
        ConversationId conversationId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            DELETE FROM messages
            WHERE conversation_id = $conversationId
              AND expires_at IS NOT NULL
              AND julianday(expires_at) <= julianday($now);
            """;
        return await ExecuteNonQueryCountAsync(
            sql,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$now", now.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture))).ConfigureAwait(false);
    }

    public Task<int> ClearConversationMessagesAsync(
        ConversationId conversationId,
        CancellationToken cancellationToken = default) =>
        ExecuteNonQueryCountAsync(
            "DELETE FROM messages WHERE conversation_id = $conversationId;",
            cancellationToken,
            ("$conversationId", conversationId.Value));

    public async Task<IReadOnlyDictionary<ConversationId, ConversationListSummary>> GetConversationSummariesAsync(
        IReadOnlyCollection<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var ids = conversationIds
            .Distinct()
            .ToArray();
        if (ids.Length == 0)
        {
            return new Dictionary<ConversationId, ConversationListSummary>();
        }

        return await WithConnectionAsync(async connection =>
        {
            var summaryBase = await LoadConversationSummaryBaseAsync(connection, ids, now, cancellationToken).ConfigureAwait(false);
            var unreadCounts = await LoadUnreadCountsAsync(connection, ids, now, cancellationToken).ConfigureAwait(false);

            var summaries = new Dictionary<ConversationId, ConversationListSummary>(ids.Length);
            foreach (var conversationId in ids)
            {
                summaryBase.TryGetValue(conversationId, out var baseItem);
                summaries[conversationId] = new ConversationListSummary(
                    conversationId,
                    baseItem?.ReadCursor,
                    baseItem?.LastMessage,
                    unreadCounts.GetValueOrDefault(conversationId),
                    baseItem?.Contact);
            }

            return summaries;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ConversationListOpenSnapshot> OpenConversationListAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        return await WithConnectionAsync(async connection =>
        {
            var accountPayload = await ExecuteScalarOnConnectionAsync<string?>(
                connection,
                "SELECT payload_json FROM settings WHERE key = $key;",
                cancellationToken,
                ("$key", LocalSettingsKeys.ActiveAccount)).ConfigureAwait(false);
            var account = accountPayload is null
                ? null
                : JsonSerializer.Deserialize<SessionAccount>(accountPayload, SerializerOptions);

            var conversationItems = new List<Conversation>();
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT payload_json FROM conversations ORDER BY updated_at DESC;";
                await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var conversation = JsonSerializer.Deserialize<Conversation>(reader.GetString(0), SerializerOptions);
                    if (conversation is not null)
                    {
                        conversationItems.Add(conversation);
                    }
                }
            }

            var ids = conversationItems.Select(static conversation => conversation.Id).ToArray();
            if (ids.Length == 0)
            {
                return new ConversationListOpenSnapshot(
                    account,
                    conversationItems,
                    new Dictionary<ConversationId, ConversationListSummary>());
            }

            var summaryBase = await LoadConversationSummaryBaseAsync(connection, ids, now, cancellationToken).ConfigureAwait(false);
            var unreadCounts = await LoadUnreadCountsAsync(connection, ids, now, cancellationToken).ConfigureAwait(false);
            var summaries = new Dictionary<ConversationId, ConversationListSummary>(ids.Length);
            foreach (var conversationId in ids)
            {
                summaryBase.TryGetValue(conversationId, out var baseItem);
                summaries[conversationId] = new ConversationListSummary(
                    conversationId,
                    baseItem?.ReadCursor,
                    baseItem?.LastMessage,
                    unreadCounts.GetValueOrDefault(conversationId),
                    baseItem?.Contact);
            }

            return new ConversationListOpenSnapshot(account, conversationItems, summaries);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<OneToOneConversationOpenSnapshot?> OpenOneToOneConversationAsync(
        SessionId recipient,
        string? displayName,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true)
    {
        if (messageLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(messageLimit), "Message limit must be greater than zero.");
        }

        return await WithConnectionAsync<OneToOneConversationOpenSnapshot?>(async connection =>
        {
            var conversationId = ConversationId.ForOneToOne(recipient);
            var metadata = await LoadOneToOneOpenMetadataAsync(connection, recipient, conversationId, cancellationToken)
                .ConfigureAwait(false);
            if (metadata.ActiveAccountPayload is null)
            {
                return null;
            }

            var account = JsonSerializer.Deserialize<SessionAccount>(metadata.ActiveAccountPayload, SerializerOptions);
            if (account is null)
            {
                return null;
            }

            var normalizedDisplayName = ConversationService.NormalizeDisplayName(recipient, displayName);
            var contact = metadata.ContactPayload is null
                ? Contact.Request(recipient, normalizedDisplayName, now)
                : JsonSerializer.Deserialize<Contact>(metadata.ContactPayload, SerializerOptions)
                    ?? Contact.Request(recipient, normalizedDisplayName, now);
            var originalContact = contact;
            var normalizedContactDisplayName = ConversationService.NormalizeDisplayName(recipient, contact.DisplayName);
            var desiredContactDisplayName = normalizedContactDisplayName ?? normalizedDisplayName;
            if (!string.Equals(contact.DisplayName, desiredContactDisplayName, StringComparison.Ordinal))
            {
                contact = contact with
                {
                    DisplayName = desiredContactDisplayName,
                    UpdatedAt = now
                };
            }

            if (metadata.ContactPayload is null || !Equals(contact, originalContact))
            {
                await ExecuteNonQueryOnConnectionAsync(
                    connection,
                    """
                    INSERT INTO contacts (id, sort_name, payload_json)
                    VALUES ($id, $sortName, $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        sort_name = excluded.sort_name,
                        payload_json = excluded.payload_json;
                    """,
                    cancellationToken,
                    ("$id", contact.Id.Value),
                    ("$sortName", contact.DisplayName ?? contact.Id.Value),
                    ("$payload", JsonSerializer.Serialize(contact, SerializerOptions))).ConfigureAwait(false);
            }

            var desiredDisplayName = contact.DisplayName ?? recipient.Value;
            var conversation = metadata.ConversationPayload is null
                ? new Conversation(
                    conversationId,
                    ConversationKind.OneToOne,
                    desiredDisplayName,
                    ConversationSettings.Default(ConversationKind.OneToOne),
                    now,
                    now)
                : JsonSerializer.Deserialize<Conversation>(metadata.ConversationPayload, SerializerOptions)
                    ?? new Conversation(
                        conversationId,
                        ConversationKind.OneToOne,
                        desiredDisplayName,
                        ConversationSettings.Default(ConversationKind.OneToOne),
                        now,
                        now);
            var originalConversation = conversation;
            if (!string.Equals(conversation.DisplayName, desiredDisplayName, StringComparison.Ordinal))
            {
                conversation = conversation with { DisplayName = desiredDisplayName };
            }

            if (conversation.IsHidden)
            {
                conversation = conversation with { IsHidden = false, UpdatedAt = now };
            }

            if (metadata.ConversationPayload is null || !Equals(conversation, originalConversation))
            {
                await ExecuteNonQueryOnConnectionAsync(
                    connection,
                    """
                    INSERT INTO conversations (id, updated_at, payload_json)
                    VALUES ($id, $updatedAt, $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        updated_at = excluded.updated_at,
                        payload_json = excluded.payload_json;
                    """,
                    cancellationToken,
                    ("$id", conversation.Id.Value),
                    ("$updatedAt", conversation.UpdatedAt.ToUnixTimeMilliseconds()),
                    ("$payload", JsonSerializer.Serialize(conversation, SerializerOptions))).ConfigureAwait(false);
            }

            var recentMessages = new List<Message>(messageLimit);
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = $"""
                    SELECT payload_json
                    FROM (
                        SELECT {MessagePayloadProjection} AS payload_json, created_at, id
                        FROM messages
                        WHERE conversation_id = $conversationId
                          AND (expires_at IS NULL OR expires_at > $now)
                        ORDER BY created_at DESC, id DESC
                        LIMIT $limit
                    )
                    ORDER BY created_at, id;
                    """;
                command.Parameters.AddWithValue("$conversationId", conversationId.Value);
                command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
                command.Parameters.AddWithValue("$limit", messageLimit);
                await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var message = JsonSerializer.Deserialize<Message>(reader.GetString(0), SerializerOptions);
                    if (message is not null)
                    {
                        recentMessages.Add(message);
                    }
                }
            }

            var existingReadAt = ParseReadCursorPayload(metadata.ReadCursorPayload);
            DateTimeOffset readAt = markAsRead
                ? Max(existingReadAt, now) ?? now
                : existingReadAt ?? DateTimeOffset.MinValue;
            if (markAsRead)
            {
                var readResult = await MarkConversationReadOnConnectionAsync(
                    connection,
                    conversationId,
                    readAt,
                    cancellationToken).ConfigureAwait(false);
                readAt = readResult.ReadCursor ?? existingReadAt ?? DateTimeOffset.MinValue;
                for (var index = 0; index < recentMessages.Count; index++)
                {
                    var message = recentMessages[index];
                    if (message.Direction == MessageDirection.Incoming
                        && message.DeliveryState != MessageDeliveryState.Read)
                    {
                        recentMessages[index] = message.Mark(MessageDeliveryState.Read, readAt);
                    }
                }
            }

            return new OneToOneConversationOpenSnapshot(account, conversation, contact, recentMessages, readAt);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<GroupConversationOpenSnapshot?> OpenGroupConversationAsync(
        ConversationId groupId,
        int messageLimit,
        DateTimeOffset now,
        CancellationToken cancellationToken = default,
        bool markAsRead = true)
    {
        if (messageLimit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(messageLimit));
        }

        return await WithConnectionAsync<GroupConversationOpenSnapshot?>(async connection =>
        {
            string? accountPayload;
            string? groupPayload;
            string? readCursorPayload;
            await using (var metadataCommand = connection.CreateCommand())
            {
                metadataCommand.CommandText = """
                    SELECT
                        (SELECT payload_json FROM settings WHERE key = $accountKey),
                        (SELECT payload_json FROM groups WHERE id = $groupId),
                        (SELECT payload_json FROM settings WHERE key = $readCursorKey);
                    """;
                metadataCommand.Parameters.AddWithValue("$accountKey", LocalSettingsKeys.ActiveAccount);
                metadataCommand.Parameters.AddWithValue("$groupId", groupId.Value);
                metadataCommand.Parameters.AddWithValue("$readCursorKey", ReadCursorSettingKey(groupId));
                await metadataCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await using var reader = await metadataCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                accountPayload = GetNullableString(reader, 0);
                groupPayload = GetNullableString(reader, 1);
                readCursorPayload = GetNullableString(reader, 2);
            }

            if (accountPayload is null || groupPayload is null
                || JsonSerializer.Deserialize<SessionAccount>(accountPayload, SerializerOptions) is not { } account
                || JsonSerializer.Deserialize<Group>(groupPayload, SerializerOptions) is not { } group)
            {
                return null;
            }

            var recentMessages = new List<Message>(messageLimit);
            await using (var messagesCommand = connection.CreateCommand())
            {
                messagesCommand.CommandText = $"""
                    SELECT payload_json
                    FROM (
                        SELECT {MessagePayloadProjection} AS payload_json, created_at, id
                        FROM messages
                        WHERE conversation_id = $conversationId
                          AND (expires_at IS NULL OR expires_at > $now)
                        ORDER BY created_at DESC, id DESC
                        LIMIT $limit
                    )
                    ORDER BY created_at, id;
                    """;
                messagesCommand.Parameters.AddWithValue("$conversationId", groupId.Value);
                messagesCommand.Parameters.AddWithValue("$now", now.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
                messagesCommand.Parameters.AddWithValue("$limit", messageLimit);
                await messagesCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await using var reader = await messagesCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var message = JsonSerializer.Deserialize<Message>(reader.GetString(0), SerializerOptions);
                    if (message is not null)
                    {
                        recentMessages.Add(message);
                    }
                }
            }

            var senderContacts = new Dictionary<SessionId, Contact>();
            var senders = recentMessages
                .Where(static message => message.Direction == MessageDirection.Incoming)
                .Select(static message => message.Sender)
                .Distinct()
                .ToArray();
            if (senders.Length > 0)
            {
                await using var contactsCommand = connection.CreateCommand();
                var names = new string[senders.Length];
                for (var index = 0; index < senders.Length; index++)
                {
                    names[index] = $"$sender{index}";
                    contactsCommand.Parameters.AddWithValue(names[index], senders[index].Value);
                }

                contactsCommand.CommandText = $"SELECT id, payload_json FROM contacts WHERE id IN ({string.Join(",", names)});";
                await contactsCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await using var reader = await contactsCommand.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var contact = JsonSerializer.Deserialize<Contact>(reader.GetString(1), SerializerOptions);
                    if (contact is not null)
                    {
                        senderContacts[new SessionId(reader.GetString(0))] = contact;
                    }
                }
            }

            var readAt = ParseReadCursorPayload(readCursorPayload) ?? DateTimeOffset.MinValue;
            if (markAsRead)
            {
                var requestedReadAt = Max(readAt, now) ?? now;
                var readResult = await MarkConversationReadOnConnectionAsync(
                    connection,
                    groupId,
                    requestedReadAt,
                    cancellationToken).ConfigureAwait(false);
                readAt = readResult.ReadCursor ?? readAt;
                for (var index = 0; index < recentMessages.Count; index++)
                {
                    var message = recentMessages[index];
                    if (message.Direction == MessageDirection.Incoming
                        && message.DeliveryState != MessageDeliveryState.Read)
                    {
                        recentMessages[index] = message.Mark(MessageDeliveryState.Read, readAt);
                    }
                }
            }

            return new GroupConversationOpenSnapshot(account, group, recentMessages, senderContacts, readAt);
        }, cancellationToken).ConfigureAwait(false);
    }

    public Task SetAsync<T>(string key, T value, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO settings (key, payload_json)
            VALUES ($key, $payload)
            ON CONFLICT(key) DO UPDATE SET
                payload_json = excluded.payload_json;
            """;

        return ExecuteNonQueryAsync(sql, cancellationToken, ("$key", key), ("$payload", JsonSerializer.Serialize(value, SerializerOptions)));
    }

    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT payload_json FROM settings WHERE key = $key;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$key", key)).ConfigureAwait(false);
        return payload is null ? default : JsonSerializer.Deserialize<T>(payload, SerializerOptions);
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken = default)
    {
        const string sql = "DELETE FROM settings WHERE key = $key;";
        return ExecuteNonQueryAsync(sql, cancellationToken, ("$key", key));
    }

    public async Task<int> GetSchemaVersionAsync(CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT version FROM schema_meta WHERE id = 1;";
        var version = await ExecuteScalarAsync<long?>(sql, cancellationToken).ConfigureAwait(false);
        return version is null ? 0 : (int)version.Value;
    }

    public Task SetSchemaVersionAsync(int version, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO schema_meta (id, version)
            VALUES (1, $version)
            ON CONFLICT(id) DO UPDATE SET version = excluded.version;
            """;

        return ExecuteNonQueryAsync(sql, cancellationToken, ("$version", version));
    }

    public Task SetSchemaValueAsync(string key, string value, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO schema_values (key, value)
            VALUES ($key, $value)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
            """;

        return ExecuteNonQueryAsync(sql, cancellationToken, ("$key", key), ("$value", value));
    }

    public async Task<string?> GetSchemaValueAsync(string key, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT value FROM schema_values WHERE key = $key;";
        return await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$key", key)).ConfigureAwait(false);
    }

    public async Task<MembershipTrustCommitResult> CommitMembershipTrustAsync(
        MembershipTrustRecord record,
        ulong? expectedHeadRevision,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRecord.Validate(record);
        if (record.Revision >
            MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords)
        {
            return MembershipTrustCommitResult.Corrupt;
        }
        cancellationToken.ThrowIfCancellationRequested();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();

            ulong? currentHead;
            byte[]? currentHeadDigest;
            long currentHistoryBytes;
            await using (var head = connection.CreateCommand())
            {
                head.Transaction = transaction;
                head.CommandText = """
                    SELECT revision, length(payload_digest), payload_digest, history_bytes
                    FROM membership_trust_heads
                    WHERE profile_key = $profile AND domain = $domain;
                    """;
                head.Parameters.AddWithValue("$profile", record.OpaqueProfileKey);
                head.Parameters.AddWithValue("$domain", (int)record.Domain);
                await using var reader = await head.ExecuteReaderAsync(
                    cancellationToken).ConfigureAwait(false);
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var signedRevision = reader.GetInt64(0);
                    currentHeadDigest = ReadFixedProjectedBlob(
                        reader,
                        lengthOrdinal: 1,
                        blobOrdinal: 2,
                        MembershipLimits.HashLength);
                    currentHistoryBytes = reader.GetInt64(3);
                    if (signedRevision <= 0 ||
                        currentHistoryBytes < 0 ||
                        currentHistoryBytes >
                            MembershipTrustRepositoryValidation
                                .MaximumMembershipTrustHistoryBytes)
                    {
                        transaction.Rollback();
                        return MembershipTrustCommitResult.Corrupt;
                    }
                    currentHead = checked((ulong)signedRevision);
                }
                else
                {
                    currentHead = null;
                    currentHeadDigest = null;
                    currentHistoryBytes = 0;
                }
            }

            if (currentHead.HasValue)
            {
                var currentHeadRecord = await ReadMembershipTrustRecordAsync(
                    connection,
                    transaction,
                    record.OpaqueProfileKey,
                    record.Domain,
                    currentHead.Value,
                    cancellationToken).ConfigureAwait(false);
                if (currentHeadRecord is null ||
                    currentHeadDigest is null ||
                    !currentHeadDigest.AsSpan().SequenceEqual(
                        currentHeadRecord.PayloadDigest) ||
                    currentHistoryBytes <
                        MembershipTrustRepositoryValidation.HistoryBlobBytes(
                            currentHeadRecord))
                {
                    transaction.Rollback();
                    return MembershipTrustCommitResult.Corrupt;
                }
            }

            var existing = await ReadMembershipTrustRecordAsync(
                connection,
                transaction,
                record.OpaqueProfileKey,
                record.Domain,
                record.Revision,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                transaction.Rollback();
                if (currentHead != record.Revision)
                {
                    return MembershipTrustCommitResult.Corrupt;
                }
                return MembershipTrustRepositoryValidation.Same(existing, record)
                    ? MembershipTrustCommitResult.Idempotent
                    : MembershipTrustCommitResult.Conflict;
            }

            if (currentHead != expectedHeadRevision ||
                record.Revision != (currentHead.HasValue ? currentHead.Value + 1 : 1))
            {
                transaction.Rollback();
                return MembershipTrustCommitResult.Conflict;
            }
            var recordBytes =
                MembershipTrustRepositoryValidation.HistoryBlobBytes(record);
            if (currentHistoryBytes >
                MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryBytes -
                recordBytes)
            {
                transaction.Rollback();
                return MembershipTrustCommitResult.Corrupt;
            }
            var nextHistoryBytes = currentHistoryBytes + recordBytes;

            await using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO membership_trust_records
                        (profile_key, domain, revision, version, artifact_kind, sequence, previous_sequence,
                         previous_hash, envelope, payload_digest, canonical_hash, profile_binding_hash,
                         signing_authority, revoked_delegation_hashes,
                         state, observed_at, valid_from, valid_until)
                    VALUES
                        ($profile, $domain, $revision, $version, $artifactKind, $sequence, $previousSequence,
                         $previousHash, $envelope, $digest, $canonicalHash, $profileBindingHash,
                         $signingAuthority, $revokedDelegationHashes,
                         $state, $observedAt, $validFrom, $validUntil);
                    """;
                AddMembershipTrustRecordParameters(insert, record);
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            int updated;
            await using (var update = connection.CreateCommand())
            {
                update.Transaction = transaction;
                if (currentHead.HasValue)
                {
                    update.CommandText = """
                        UPDATE membership_trust_heads
                        SET revision = $revision, payload_digest = $digest,
                            history_bytes = $historyBytes
                        WHERE profile_key = $profile AND domain = $domain AND revision = $expected;
                        """;
                    update.Parameters.AddWithValue("$expected", checked((long)currentHead.Value));
                }
                else
                {
                    update.CommandText = """
                        INSERT INTO membership_trust_heads
                            (profile_key, domain, revision, payload_digest, history_bytes)
                        VALUES ($profile, $domain, $revision, $digest, $historyBytes)
                        ON CONFLICT(profile_key, domain) DO NOTHING;
                        """;
                }
                update.Parameters.AddWithValue("$profile", record.OpaqueProfileKey);
                update.Parameters.AddWithValue("$domain", (int)record.Domain);
                update.Parameters.AddWithValue("$revision", checked((long)record.Revision));
                update.Parameters.AddWithValue("$digest", record.PayloadDigest);
                update.Parameters.AddWithValue("$historyBytes", nextHistoryBytes);
                updated = await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            if (updated != 1)
            {
                transaction.Rollback();
                return MembershipTrustCommitResult.Conflict;
            }

            _membershipTrustFaultInjector?.Invoke(
                MembershipTrustCommitFaultPoint.BeforeDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            _membershipTrustFaultInjector?.Invoke(
                MembershipTrustCommitFaultPoint.AfterDurableCommit);
            cancellationToken.ThrowIfCancellationRequested();
            return MembershipTrustCommitResult.Applied;
        }
        catch (Exception exception) when (
            exception is ArgumentOutOfRangeException or InvalidCastException or InvalidOperationException or
                InvalidDataException or OverflowException)
        {
            return MembershipTrustCommitResult.Corrupt;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<MembershipTrustReadSnapshot> ReadMembershipTrustAsync(
        string opaqueProfileKey,
        MembershipTrustDomain domain,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRepositoryValidation.ValidateKey(opaqueProfileKey, domain);
        cancellationToken.ThrowIfCancellationRequested();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();

            ulong? headRevision;
            byte[]? headDigest;
            long headHistoryBytes;
            await using (var head = connection.CreateCommand())
            {
                head.Transaction = transaction;
                head.CommandText = """
                    SELECT revision, length(payload_digest), payload_digest, history_bytes
                    FROM membership_trust_heads
                    WHERE profile_key = $profile AND domain = $domain;
                    """;
                head.Parameters.AddWithValue("$profile", opaqueProfileKey);
                head.Parameters.AddWithValue("$domain", (int)domain);
                await using var reader = await head.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    await using var records = connection.CreateCommand();
                    records.Transaction = transaction;
                    records.CommandText = """
                        SELECT 1 FROM membership_trust_records
                        WHERE profile_key = $profile AND domain = $domain
                        LIMIT 1;
                        """;
                    records.Parameters.AddWithValue("$profile", opaqueProfileKey);
                    records.Parameters.AddWithValue("$domain", (int)domain);
                    var exists = await records.ExecuteScalarAsync(
                        cancellationToken).ConfigureAwait(false);
                    return exists is null or DBNull
                        ? MembershipTrustRepositoryValidation.Missing()
                        : MembershipTrustRepositoryValidation.Corrupt();
                }
                var signedRevision = reader.GetInt64(0);
                headDigest = ReadFixedProjectedBlob(
                    reader,
                    lengthOrdinal: 1,
                    blobOrdinal: 2,
                    MembershipLimits.HashLength);
                headHistoryBytes = reader.GetInt64(3);
                if (signedRevision <= 0 ||
                    headHistoryBytes < 0 ||
                    headHistoryBytes >
                        MembershipTrustRepositoryValidation
                            .MaximumMembershipTrustHistoryBytes)
                {
                    return MembershipTrustRepositoryValidation.Corrupt();
                }
                headRevision = checked((ulong)signedRevision);
            }

            if (headRevision.Value >
                MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords)
            {
                return MembershipTrustRepositoryValidation.Corrupt();
            }

            await using (var orphan = connection.CreateCommand())
            {
                orphan.Transaction = transaction;
                orphan.CommandText = """
                    SELECT 1
                    FROM membership_trust_records
                    WHERE profile_key = $profile AND domain = $domain
                      AND revision > $head
                    LIMIT 1;
                    """;
                orphan.Parameters.AddWithValue("$profile", opaqueProfileKey);
                orphan.Parameters.AddWithValue("$domain", (int)domain);
                orphan.Parameters.AddWithValue(
                    "$head",
                    checked((long)headRevision.Value));
                var exists = await orphan.ExecuteScalarAsync(
                    cancellationToken).ConfigureAwait(false);
                if (exists is not null and not DBNull)
                {
                    return MembershipTrustRepositoryValidation.Corrupt();
                }
            }

            MembershipTrustRecord? current = null;
            MembershipTrustRecord? predecessor = null;
            MembershipTrustRecord? previous = null;
            var recordsRead = 0UL;
            var historyBytes = 0L;
            await using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    SELECT revision, version, artifact_kind, sequence, previous_sequence,
                           state, observed_at, valid_from, valid_until,
                           length(previous_hash), length(envelope), length(payload_digest),
                           length(canonical_hash), length(profile_binding_hash),
                           length(signing_authority), length(revoked_delegation_hashes),
                           previous_hash, envelope, payload_digest, canonical_hash,
                           profile_binding_hash, signing_authority, revoked_delegation_hashes
                    FROM membership_trust_records
                    WHERE profile_key = $profile AND domain = $domain
                    ORDER BY revision
                    LIMIT $limit;
                    """;
                command.Parameters.AddWithValue("$profile", opaqueProfileKey);
                command.Parameters.AddWithValue("$domain", (int)domain);
                command.Parameters.AddWithValue(
                    "$limit",
                    MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords + 1);
                await using var reader = await command.ExecuteReaderAsync(
                    cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var signedRevision = reader.GetInt64(0);
                    var sequence = reader.GetInt64(3);
                    var previousSequence = reader.GetInt64(4);
                    if (signedRevision <= 0 || sequence <= 0 || previousSequence < 0)
                    {
                        return MembershipTrustRepositoryValidation.Corrupt();
                    }
                    var blobLengths = ReadMembershipTrustBlobLengths(
                        reader,
                        firstLengthOrdinal: 9,
                        ref historyBytes);
                    var record = new MembershipTrustRecord
                    {
                        Version = reader.GetInt32(1),
                        OpaqueProfileKey = opaqueProfileKey,
                        Domain = domain,
                        ArtifactKind = (MembershipTrustArtifactKind)reader.GetInt32(2),
                        Revision = checked((ulong)signedRevision),
                        Sequence = checked((ulong)sequence),
                        PreviousSequence = checked((ulong)previousSequence),
                        PreviousCanonicalHash = ReadProjectedBlob(reader, 16, blobLengths[0]),
                        CanonicalEnvelope = ReadProjectedBlob(reader, 17, blobLengths[1]),
                        PayloadDigest = ReadProjectedBlob(reader, 18, blobLengths[2]),
                        CanonicalHash = ReadProjectedBlob(reader, 19, blobLengths[3]),
                        ProfileBindingHash = ReadProjectedBlob(reader, 20, blobLengths[4]),
                        SigningAuthorityEnvelope = ReadProjectedBlob(reader, 21, blobLengths[5]),
                        RevokedDelegationHashes = ReadProjectedBlob(reader, 22, blobLengths[6]),
                        State = (MembershipTrustState)reader.GetInt32(5),
                        ObservedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(6)),
                        ValidFrom = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(7)),
                        ValidUntil = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(8))
                    };
                    recordsRead++;
                    if (record.Revision != recordsRead ||
                        !MembershipTrustRepositoryValidation.IsValid(record) ||
                        !MembershipTrustRepositoryValidation.HasValidLinkage(
                            record,
                            previous))
                    {
                        return MembershipTrustRepositoryValidation.Corrupt();
                    }
                    if (record.Revision == headRevision.Value - 1)
                    {
                        predecessor = record;
                    }
                    previous = record;
                    current = record;
                }
            }

            if (current is null ||
                recordsRead != headRevision.Value ||
                historyBytes != headHistoryBytes ||
                headDigest is null ||
                !headDigest.AsSpan().SequenceEqual(current.PayloadDigest))
            {
                return MembershipTrustRepositoryValidation.Corrupt();
            }

            return new MembershipTrustReadSnapshot(MembershipTrustReadResult.Found, current, predecessor);
        }
        catch (Exception exception) when (
            exception is ArgumentOutOfRangeException or InvalidCastException or InvalidOperationException or
                InvalidDataException or JsonException or OverflowException)
        {
            return MembershipTrustRepositoryValidation.Corrupt();
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<MembershipTrustClockCommitResult> CommitMembershipTrustClockAsync(
        MembershipTrustClockRecord record,
        ulong? expectedRevision,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustClockRecord.Validate(record);
        cancellationToken.ThrowIfCancellationRequested();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            MembershipTrustClockRecord? current = null;
            await using (var read = connection.CreateCommand())
            {
                read.Transaction = transaction;
                read.CommandText = """
                    SELECT version, revision, observed_at, digest
                    FROM membership_trust_clock
                    WHERE profile_key = $profile;
                    """;
                read.Parameters.AddWithValue("$profile", record.OpaqueProfileKey);
                await using var reader = await read.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var revision = reader.GetInt64(1);
                    if (revision <= 0)
                    {
                        return MembershipTrustClockCommitResult.Corrupt;
                    }
                    current = new MembershipTrustClockRecord
                    {
                        Version = reader.GetInt32(0),
                        OpaqueProfileKey = record.OpaqueProfileKey,
                        Revision = checked((ulong)revision),
                        ObservedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(2)),
                        Digest = reader.GetFieldValue<byte[]>(3)
                    };
                    try
                    {
                        MembershipTrustClockRecord.Validate(current);
                    }
                    catch (InvalidDataException)
                    {
                        return MembershipTrustClockCommitResult.Corrupt;
                    }
                }
            }

            if ((current is not null) != expectedRevision.HasValue ||
                (current is not null && current.Revision != expectedRevision!.Value) ||
                record.Revision != (current is null ? 1UL : current.Revision + 1))
            {
                return current is not null &&
                       current.Revision == record.Revision &&
                       current.Digest.AsSpan().SequenceEqual(record.Digest)
                    ? MembershipTrustClockCommitResult.Idempotent
                    : MembershipTrustClockCommitResult.Conflict;
            }
            if (current is not null && record.ObservedAt < current.ObservedAt)
            {
                return MembershipTrustClockCommitResult.Rollback;
            }

            await using var write = connection.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = """
                INSERT INTO membership_trust_clock
                    (profile_key, version, revision, observed_at, digest)
                VALUES ($profile, $version, $revision, $observedAt, $digest)
                ON CONFLICT(profile_key) DO UPDATE SET
                    version = excluded.version,
                    revision = excluded.revision,
                    observed_at = excluded.observed_at,
                    digest = excluded.digest
                WHERE membership_trust_clock.revision = $expected;
                """;
            write.Parameters.AddWithValue("$profile", record.OpaqueProfileKey);
            write.Parameters.AddWithValue("$version", record.Version);
            write.Parameters.AddWithValue("$revision", checked((long)record.Revision));
            write.Parameters.AddWithValue("$observedAt", record.ObservedAt.ToUnixTimeSeconds());
            write.Parameters.AddWithValue("$digest", record.Digest);
            write.Parameters.AddWithValue("$expected", checked((long)(expectedRevision ?? 0)));
            if (await write.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
            {
                return MembershipTrustClockCommitResult.Conflict;
            }
            transaction.Commit();
            return MembershipTrustClockCommitResult.Applied;
        }
        catch (Exception exception) when (
            exception is ArgumentOutOfRangeException or InvalidCastException or InvalidOperationException or
                InvalidDataException or OverflowException)
        {
            return MembershipTrustClockCommitResult.Corrupt;
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<MembershipTrustClockReadSnapshot> ReadMembershipTrustClockAsync(
        string opaqueProfileKey,
        CancellationToken cancellationToken = default)
    {
        MembershipTrustRepositoryValidation.ValidateProfileKey(opaqueProfileKey);
        cancellationToken.ThrowIfCancellationRequested();
        await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var connection = OpenConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT version, revision, observed_at, digest
                FROM membership_trust_clock
                WHERE profile_key = $profile;
                """;
            command.Parameters.AddWithValue("$profile", opaqueProfileKey);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return new MembershipTrustClockReadSnapshot(MembershipTrustClockReadResult.Missing, null);
            }
            var revision = reader.GetInt64(1);
            if (revision <= 0)
            {
                return new MembershipTrustClockReadSnapshot(MembershipTrustClockReadResult.Corrupt, null);
            }
            var record = new MembershipTrustClockRecord
            {
                Version = reader.GetInt32(0),
                OpaqueProfileKey = opaqueProfileKey,
                Revision = checked((ulong)revision),
                ObservedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(2)),
                Digest = reader.GetFieldValue<byte[]>(3)
            };
            MembershipTrustClockRecord.Validate(record);
            return new MembershipTrustClockReadSnapshot(MembershipTrustClockReadResult.Found, record);
        }
        catch (Exception exception) when (
            exception is ArgumentOutOfRangeException or InvalidCastException or InvalidOperationException or
                InvalidDataException or OverflowException)
        {
            return new MembershipTrustClockReadSnapshot(MembershipTrustClockReadResult.Corrupt, null);
        }
        finally
        {
            _databaseGate.Release();
        }
    }

    public async Task<MessageReplayClaimResult> TryClaimAsync(
        SessionId sender,
        MessageId messageId,
        string envelopeDigest,
        DateTimeOffset protocolExpiresAt,
        CancellationToken cancellationToken = default)
    {
        ValidateReplayClaim(sender, messageId, envelopeDigest, protocolExpiresAt);

        return await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var transaction = connection.BeginTransaction();

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO replay_claims (sender_session_id, message_id, envelope_digest, expires_at)
                VALUES ($senderSessionId, $messageId, $envelopeDigest, $expiresAt)
                ON CONFLICT(sender_session_id, message_id) DO NOTHING;
                """;
            insert.Parameters.AddWithValue("$senderSessionId", sender.Value);
            insert.Parameters.AddWithValue("$messageId", messageId.Value);
            insert.Parameters.AddWithValue("$envelopeDigest", envelopeDigest);
            insert.Parameters.AddWithValue("$expiresAt", protocolExpiresAt.ToUnixTimeMilliseconds());

            await insert.PrepareAsync(cancellationToken).ConfigureAwait(false);
            if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1)
            {
                transaction.Commit();
                return MessageReplayClaimResult.Accepted;
            }

            await using var select = connection.CreateCommand();
            select.Transaction = transaction;
            select.CommandText = """
                SELECT envelope_digest
                FROM replay_claims
                WHERE sender_session_id = $senderSessionId AND message_id = $messageId;
                """;
            select.Parameters.AddWithValue("$senderSessionId", sender.Value);
            select.Parameters.AddWithValue("$messageId", messageId.Value);

            await select.PrepareAsync(cancellationToken).ConfigureAwait(false);
            var existingDigest = await select.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            if (existingDigest is null)
            {
                throw new InvalidOperationException("Replay claim disappeared before its digest could be verified.");
            }

            transaction.Commit();
            return string.Equals(existingDigest, envelopeDigest, StringComparison.Ordinal)
                ? MessageReplayClaimResult.DuplicateSameDigest
                : MessageReplayClaimResult.RejectedDigestMismatch;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> PruneExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        return await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM replay_claims
                WHERE rowid IN (
                    SELECT rowid
                    FROM replay_claims
                    WHERE expires_at <= $now
                    ORDER BY expires_at
                    LIMIT $limit
                );
                """;
            command.Parameters.AddWithValue("$now", now.ToUnixTimeMilliseconds());
            command.Parameters.AddWithValue("$limit", ReplayPruneBatchSize);

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string?> GetInboxCursorAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        return await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT cursor
                FROM inbox_cursors
                WHERE account_session_id = $accountSessionId AND namespace = $namespace;
                """;
            command.Parameters.AddWithValue("$accountSessionId", scope.Account.Value);
            command.Parameters.AddWithValue("$namespace", scope.Namespace);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<DurableInboxStageResult> StageInboxBatchAsync(
        DurableInboxScope scope,
        string? expectedCursor,
        string? nextCursor,
        IReadOnlyList<DurableInboxWireEntry> entries,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxBatch(scope, expectedCursor, nextCursor, entries);

        return await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var transaction = connection.BeginTransaction();
            var currentCursor = await ReadInboxCursorAsync(connection, transaction, scope, cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(currentCursor, expectedCursor, StringComparison.Ordinal))
            {
                if (string.Equals(currentCursor, nextCursor, StringComparison.Ordinal))
                {
                    foreach (var entry in entries)
                    {
                        var existing = await ReadExistingWireIdentityAsync(
                            connection,
                            transaction,
                            scope,
                            entry.ServerHash,
                            cancellationToken).ConfigureAwait(false);
                        if (existing is not null
                            && (existing.Value.StorageTimestamp != entry.StorageTimestamp
                                || !string.Equals(existing.Value.WireDigest, entry.WireDigest, StringComparison.Ordinal)))
                        {
                            throw new DurableInboxDigestMismatchException(
                                $"Inbox server hash '{entry.ServerHash}' was reused with different wire data.");
                        }
                    }

                    transaction.Commit();
                    return new DurableInboxStageResult(0, entries.Count);
                }

                throw new InvalidOperationException("The durable inbox cursor changed before the retrieved batch could be staged.");
            }

            var stagedCount = 0;
            var existingCount = 0;
            var batchEntries = new Dictionary<string, DurableInboxWireEntry>(StringComparer.Ordinal);
            foreach (var entry in entries)
            {
                if (batchEntries.TryGetValue(entry.ServerHash, out var priorBatchEntry))
                {
                    if (priorBatchEntry.StorageTimestamp != entry.StorageTimestamp
                        || !string.Equals(priorBatchEntry.WireDigest, entry.WireDigest, StringComparison.Ordinal))
                    {
                        throw new DurableInboxDigestMismatchException(
                            $"Inbox server hash '{entry.ServerHash}' was repeated with different wire data.");
                    }

                    existingCount++;
                    continue;
                }

                batchEntries.Add(entry.ServerHash, entry);
                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO inbox_items (
                        account_session_id,
                        namespace,
                        server_hash,
                        storage_timestamp,
                        wire_payload,
                        wire_digest)
                    VALUES (
                        $accountSessionId,
                        $namespace,
                        $serverHash,
                        $storageTimestamp,
                        $wirePayload,
                        $wireDigest)
                    ON CONFLICT(account_session_id, namespace, server_hash) DO NOTHING;
                    """;
                AddInboxScopeParameters(insert, scope);
                insert.Parameters.AddWithValue("$serverHash", entry.ServerHash);
                insert.Parameters.AddWithValue("$storageTimestamp", entry.StorageTimestamp);
                insert.Parameters.AddWithValue("$wirePayload", entry.WirePayload);
                insert.Parameters.AddWithValue("$wireDigest", entry.WireDigest);
                await insert.PrepareAsync(cancellationToken).ConfigureAwait(false);
                if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) == 1)
                {
                    stagedCount++;
                    continue;
                }

                var existing = await ReadExistingWireIdentityAsync(
                    connection,
                    transaction,
                    scope,
                    entry.ServerHash,
                    cancellationToken).ConfigureAwait(false);
                if (existing is null
                    || existing.Value.StorageTimestamp != entry.StorageTimestamp
                    || !string.Equals(existing.Value.WireDigest, entry.WireDigest, StringComparison.Ordinal))
                {
                    throw new DurableInboxDigestMismatchException(
                        $"Inbox server hash '{entry.ServerHash}' was reused with different wire data.");
                }

                existingCount++;
            }

            await using (var countCommand = connection.CreateCommand())
            {
                countCommand.Transaction = transaction;
                countCommand.CommandText = """
                    SELECT COUNT(*)
                    FROM inbox_items
                    WHERE account_session_id = $accountSessionId AND namespace = $namespace;
                    """;
                AddInboxScopeParameters(countCommand, scope);
                var pendingCount = Convert.ToInt32(
                    await countCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    CultureInfo.InvariantCulture);
                if (pendingCount > DurableInboxLimits.MaxPendingItemCount)
                {
                    throw new InvalidOperationException("The durable inbox pending-item limit has been reached.");
                }
            }

            if (nextCursor is not null)
            {
                await using var cursor = connection.CreateCommand();
                cursor.Transaction = transaction;
                cursor.CommandText = """
                    INSERT INTO inbox_cursors (account_session_id, namespace, cursor, updated_at)
                    VALUES ($accountSessionId, $namespace, $cursor, $updatedAt)
                    ON CONFLICT(account_session_id, namespace) DO UPDATE SET
                        cursor = excluded.cursor,
                        updated_at = excluded.updated_at;
                    """;
                AddInboxScopeParameters(cursor, scope);
                cursor.Parameters.AddWithValue("$cursor", nextCursor);
                cursor.Parameters.AddWithValue("$updatedAt", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                await cursor.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await cursor.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            transaction.Commit();
            return new DurableInboxStageResult(stagedCount, existingCount);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DurableInboxItem>> ListStagedInboxItemsAsync(
        DurableInboxScope scope,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxList(scope, limit);
        return await QueryInboxItemsAsync(
            scope,
            "item_kind IS NULL",
            null,
            null,
            limit,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DurableInboxPrepareResult> PrepareInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        DurableInboxDecodedMetadata decoded,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);
        ValidateDecodedMetadata(decoded);

        return await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var transaction = connection.BeginTransaction();
            var item = await ReadInboxItemAsync(
                connection,
                transaction,
                scope,
                serverHash,
                cancellationToken).ConfigureAwait(false);
            if (item is null)
            {
                transaction.Commit();
                return DurableInboxPrepareResult.NotFound;
            }

            if (item.Decoded is not null && !Equals(item.Decoded, decoded))
            {
                await DeleteInboxItemAsync(connection, transaction, scope, serverHash, cancellationToken)
                    .ConfigureAwait(false);
                transaction.Commit();
                return DurableInboxPrepareResult.RejectedDigestMismatch;
            }

            var replayDigest = await ReadReplayDigestAsync(
                connection,
                transaction,
                decoded.Sender,
                decoded.MessageId,
                cancellationToken).ConfigureAwait(false);
            if (replayDigest is not null)
            {
                await DeleteInboxItemAsync(connection, transaction, scope, serverHash, cancellationToken)
                    .ConfigureAwait(false);
                transaction.Commit();
                return string.Equals(replayDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                    ? DurableInboxPrepareResult.DuplicateSameDigest
                    : DurableInboxPrepareResult.RejectedDigestMismatch;
            }

            await using (var prior = connection.CreateCommand())
            {
                prior.Transaction = transaction;
                prior.CommandText = """
                    SELECT envelope_digest
                    FROM inbox_items
                    WHERE sequence < $sequence
                      AND account_session_id = $accountSessionId
                      AND namespace = $namespace
                      AND sender_session_id = $senderSessionId
                      AND message_id = $messageId
                    ORDER BY sequence
                    LIMIT 1;
                    """;
                prior.Parameters.AddWithValue("$sequence", item.Sequence);
                AddInboxScopeParameters(prior, scope);
                prior.Parameters.AddWithValue("$senderSessionId", decoded.Sender.Value);
                prior.Parameters.AddWithValue("$messageId", decoded.MessageId.Value);
                await prior.PrepareAsync(cancellationToken).ConfigureAwait(false);
                var priorDigest = await prior.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
                if (priorDigest is not null)
                {
                    await DeleteInboxItemAsync(connection, transaction, scope, serverHash, cancellationToken)
                        .ConfigureAwait(false);
                    transaction.Commit();
                    return string.Equals(priorDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                        ? DurableInboxPrepareResult.DuplicateSameDigest
                        : DurableInboxPrepareResult.RejectedDigestMismatch;
                }
            }

            if (item.Decoded is null)
            {
                await using var update = connection.CreateCommand();
                update.Transaction = transaction;
                update.CommandText = """
                    UPDATE inbox_items
                    SET item_kind = $itemKind,
                        route_key = $routeKey,
                        sender_session_id = $senderSessionId,
                        message_id = $messageId,
                        envelope_digest = $envelopeDigest,
                        protocol_expires_at = $protocolExpiresAt
                    WHERE account_session_id = $accountSessionId
                      AND namespace = $namespace
                      AND server_hash = $serverHash;
                    """;
                AddInboxScopeParameters(update, scope);
                update.Parameters.AddWithValue("$serverHash", serverHash);
                update.Parameters.AddWithValue("$itemKind", (int)decoded.Kind);
                update.Parameters.AddWithValue("$routeKey", decoded.RouteKey);
                update.Parameters.AddWithValue("$senderSessionId", decoded.Sender.Value);
                update.Parameters.AddWithValue("$messageId", decoded.MessageId.Value);
                update.Parameters.AddWithValue("$envelopeDigest", decoded.EnvelopeDigest);
                update.Parameters.AddWithValue("$protocolExpiresAt", decoded.ProtocolExpiresAt.ToUnixTimeMilliseconds());
                await update.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            transaction.Commit();
            return DurableInboxPrepareResult.Ready;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<DurableInboxItem>> ListDecodedInboxItemsAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        string? routeKey,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxList(scope, limit);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        return await QueryInboxItemsAsync(
            scope,
            "item_kind = $itemKind AND ($routeKey IS NULL OR route_key = $routeKey)",
            kind,
            routeKey,
            limit,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<DurableInboxAckResult> AcknowledgeInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);

        return await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var transaction = connection.BeginTransaction();
            var item = await ReadInboxItemAsync(
                connection,
                transaction,
                scope,
                serverHash,
                cancellationToken).ConfigureAwait(false);
            if (item?.Decoded is not { } decoded)
            {
                transaction.Commit();
                return DurableInboxAckResult.NotFound;
            }

            var replayDigest = await ReadReplayDigestAsync(
                connection,
                transaction,
                decoded.Sender,
                decoded.MessageId,
                cancellationToken).ConfigureAwait(false);
            var result = DurableInboxAckResult.Applied;
            if (replayDigest is null)
            {
                await using var insert = connection.CreateCommand();
                insert.Transaction = transaction;
                insert.CommandText = """
                    INSERT INTO replay_claims (sender_session_id, message_id, envelope_digest, expires_at)
                    VALUES ($senderSessionId, $messageId, $envelopeDigest, $expiresAt);
                    """;
                insert.Parameters.AddWithValue("$senderSessionId", decoded.Sender.Value);
                insert.Parameters.AddWithValue("$messageId", decoded.MessageId.Value);
                insert.Parameters.AddWithValue("$envelopeDigest", decoded.EnvelopeDigest);
                insert.Parameters.AddWithValue("$expiresAt", decoded.ProtocolExpiresAt.ToUnixTimeMilliseconds());
                await insert.PrepareAsync(cancellationToken).ConfigureAwait(false);
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                result = string.Equals(replayDigest, decoded.EnvelopeDigest, StringComparison.Ordinal)
                    ? DurableInboxAckResult.DuplicateSameDigest
                    : DurableInboxAckResult.RejectedDigestMismatch;
            }

            await DeleteInboxItemAsync(connection, transaction, scope, serverHash, cancellationToken)
                .ConfigureAwait(false);
            transaction.Commit();
            return result;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task DiscardInboxItemAsync(
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        ValidateServerHash(serverHash);
        await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM inbox_items
                WHERE account_session_id = $accountSessionId
                  AND namespace = $namespace
                  AND server_hash = $serverHash;
                """;
            AddInboxScopeParameters(command, scope);
            command.Parameters.AddWithValue("$serverHash", serverHash);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return 0;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> CountPendingInboxItemsAsync(
        DurableInboxScope scope,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        return await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT COUNT(*)
                FROM inbox_items
                WHERE account_session_id = $accountSessionId AND namespace = $namespace;
                """;
            AddInboxScopeParameters(command, scope);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            return Convert.ToInt32(
                await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                CultureInfo.InvariantCulture);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> DiscardDecodedInboxItemsOutsideRoutesAsync(
        DurableInboxScope scope,
        DurableInboxItemKind kind,
        IReadOnlySet<string> retainedRouteKeys,
        CancellationToken cancellationToken = default)
    {
        ValidateInboxScope(scope);
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        ArgumentNullException.ThrowIfNull(retainedRouteKeys);
        var retainedRoutesJson = JsonSerializer.Serialize(
            retainedRouteKeys.OrderBy(static route => route, StringComparer.Ordinal),
            SerializerOptions);
        return await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM inbox_items
                WHERE account_session_id = $accountSessionId
                  AND namespace = $namespace
                  AND item_kind = $itemKind
                  AND NOT EXISTS (
                      SELECT 1
                      FROM json_each($retainedRoutesJson) AS retained
                      WHERE retained.value = inbox_items.route_key);
                """;
            AddInboxScopeParameters(command, scope);
            command.Parameters.AddWithValue("$itemKind", (int)kind);
            command.Parameters.AddWithValue("$retainedRoutesJson", retainedRoutesJson);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task PersistGroupStateAsync(
        Group group,
        Conversation conversation,
        DateTimeOffset updatedAt,
        GroupStateOutboxItem? outboxItem,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupStatePersistence(group, conversation, updatedAt, outboxItem);
        await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var transaction = connection.BeginTransaction();
            await ValidatePersistedGroupRevisionAsync(connection, transaction, group, cancellationToken)
                .ConfigureAwait(false);

            await using (var groupCommand = connection.CreateCommand())
            {
                groupCommand.Transaction = transaction;
                groupCommand.CommandText = """
                    INSERT INTO groups (id, sort_name, payload_json)
                    VALUES ($id, $sortName, $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        sort_name = excluded.sort_name,
                        payload_json = excluded.payload_json;
                    """;
                groupCommand.Parameters.AddWithValue("$id", group.Id.Value);
                groupCommand.Parameters.AddWithValue("$sortName", group.Name);
                groupCommand.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(group, SerializerOptions));
                await groupCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using (var conversationCommand = connection.CreateCommand())
            {
                conversationCommand.Transaction = transaction;
                conversationCommand.CommandText = """
                    INSERT INTO conversations (id, updated_at, payload_json)
                    VALUES ($id, $updatedAt, $payload)
                    ON CONFLICT(id) DO UPDATE SET
                        updated_at = excluded.updated_at,
                        payload_json = excluded.payload_json;
                    """;
                conversationCommand.Parameters.AddWithValue("$id", conversation.Id.Value);
                conversationCommand.Parameters.AddWithValue("$updatedAt", conversation.UpdatedAt.ToUnixTimeMilliseconds());
                conversationCommand.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(conversation, SerializerOptions));
                await conversationCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using (var settingCommand = connection.CreateCommand())
            {
                settingCommand.Transaction = transaction;
                settingCommand.CommandText = """
                    INSERT INTO settings (key, payload_json)
                    VALUES ($key, $payload)
                    ON CONFLICT(key) DO UPDATE SET payload_json = excluded.payload_json;
                    """;
                settingCommand.Parameters.AddWithValue("$key", GroupStateUpdatedAtSettingKey(group.Id));
                settingCommand.Parameters.AddWithValue(
                    "$payload",
                    JsonSerializer.Serialize(updatedAt.ToString("O", CultureInfo.InvariantCulture), SerializerOptions));
                await settingCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            if (outboxItem is not null)
            {
                var groupPayload = JsonSerializer.Serialize(outboxItem.Group, SerializerOptions);
                var recipientsPayload = JsonSerializer.Serialize(outboxItem.Recipients, SerializerOptions);
                await using var insertOutbox = connection.CreateCommand();
                insertOutbox.Transaction = transaction;
                insertOutbox.CommandText = """
                    INSERT INTO group_state_outbox (
                        operation_id, group_id, revision, updated_at, group_payload, recipients_json)
                    VALUES (
                        $operationId, $groupId, $revision, $updatedAt, $groupPayload, $recipientsJson)
                    ON CONFLICT(operation_id) DO NOTHING;
                    """;
                insertOutbox.Parameters.AddWithValue("$operationId", outboxItem.OperationId);
                insertOutbox.Parameters.AddWithValue("$groupId", outboxItem.Group.Id.Value);
                insertOutbox.Parameters.AddWithValue("$revision", outboxItem.Group.Revision);
                insertOutbox.Parameters.AddWithValue("$updatedAt", outboxItem.UpdatedAt.ToUnixTimeMilliseconds());
                insertOutbox.Parameters.AddWithValue("$groupPayload", groupPayload);
                insertOutbox.Parameters.AddWithValue("$recipientsJson", recipientsPayload);
                var inserted = await insertOutbox.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                if (inserted == 0)
                {
                    await ValidateExistingOutboxAsync(
                        connection,
                        transaction,
                        outboxItem,
                        groupPayload,
                        recipientsPayload,
                        cancellationToken).ConfigureAwait(false);
                }

                await using var count = connection.CreateCommand();
                count.Transaction = transaction;
                count.CommandText = "SELECT COUNT(*) FROM group_state_outbox;";
                var pending = Convert.ToInt32(
                    await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false),
                    CultureInfo.InvariantCulture);
                if (pending > GroupStateOutboxLimits.MaxPendingItems)
                {
                    throw new InvalidOperationException("The group state outbox limit has been reached.");
                }
            }

            transaction.Commit();
            return 0;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<GroupStateOutboxItem>> ListPendingGroupStatePublishesAsync(
        int limit,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupOutboxLimit(limit);
        return await WithReplayConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT operation_id, group_payload, updated_at, recipients_json
                FROM group_state_outbox
                ORDER BY group_id, revision, sequence
                LIMIT $limit;
                """;
            command.Parameters.AddWithValue("$limit", limit);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            var result = new List<GroupStateOutboxItem>();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var group = JsonSerializer.Deserialize<Group>(reader.GetString(1), SerializerOptions)
                    ?? throw new InvalidOperationException("A persisted group outbox item is invalid.");
                var recipients = JsonSerializer.Deserialize<SessionId[]>(reader.GetString(3), SerializerOptions)
                    ?? throw new InvalidOperationException("Persisted group outbox recipients are invalid.");
                result.Add(new GroupStateOutboxItem(
                    reader.GetString(0),
                    group,
                    DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(2)),
                    recipients));
            }

            return (IReadOnlyList<GroupStateOutboxItem>)result;
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task AcknowledgeGroupStatePublishAsync(
        string operationId,
        CancellationToken cancellationToken = default)
    {
        ValidateGroupOutboxOperationId(operationId);
        await ExecuteNonQueryAsync(
            "DELETE FROM group_state_outbox WHERE operation_id = $operationId;",
            cancellationToken,
            ("$operationId", operationId)).ConfigureAwait(false);
    }

    public async Task PurgeAccountDataAsync(CancellationToken cancellationToken = default)
    {
        await WithReplayConnectionAsync(async connection =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using (var secureDelete = connection.CreateCommand())
            {
                secureDelete.CommandText = "PRAGMA secure_delete=ON;";
                await secureDelete.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            using var transaction = connection.BeginTransaction();
            foreach (var table in new[]
                     {
                         "group_state_outbox", "inbox_items", "inbox_cursors", "incoming_message_notifications", "messages", "groups", "conversations", "contacts", "replay_claims", "settings"
                     })
            {
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = $"DELETE FROM {table};";
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            transaction.Commit();
            await RunPostPurgeMaintenanceBestEffortAsync(connection).ConfigureAwait(false);

            return 0;
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunPostPurgeMaintenanceBestEffortAsync(SqliteConnection connection)
    {
        // The account deletion is already committed, so maintenance cannot change the logout result.
        foreach (var sql in new[] { "PRAGMA wal_checkpoint(TRUNCATE);", "VACUUM;" })
        {
            try
            {
                await using var command = connection.CreateCommand();
                command.CommandText = sql;
                await command.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // A later purge or normal SQLite maintenance can retry this work.
            }
        }
    }

    private static void AddMembershipTrustRecordParameters(
        SqliteCommand command,
        MembershipTrustRecord record)
    {
        command.Parameters.AddWithValue("$profile", record.OpaqueProfileKey);
        command.Parameters.AddWithValue("$domain", (int)record.Domain);
        command.Parameters.AddWithValue("$revision", checked((long)record.Revision));
        command.Parameters.AddWithValue("$version", record.Version);
        command.Parameters.AddWithValue("$artifactKind", (int)record.ArtifactKind);
        command.Parameters.AddWithValue("$sequence", checked((long)record.Sequence));
        command.Parameters.AddWithValue("$previousSequence", checked((long)record.PreviousSequence));
        command.Parameters.AddWithValue("$previousHash", record.PreviousCanonicalHash);
        command.Parameters.AddWithValue("$envelope", record.CanonicalEnvelope);
        command.Parameters.AddWithValue("$digest", record.PayloadDigest);
        command.Parameters.AddWithValue("$canonicalHash", record.CanonicalHash);
        command.Parameters.AddWithValue("$profileBindingHash", record.ProfileBindingHash);
        command.Parameters.AddWithValue("$signingAuthority", record.SigningAuthorityEnvelope);
        command.Parameters.AddWithValue("$revokedDelegationHashes", record.RevokedDelegationHashes);
        command.Parameters.AddWithValue("$state", (int)record.State);
        command.Parameters.AddWithValue("$observedAt", record.ObservedAt.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$validFrom", record.ValidFrom.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$validUntil", record.ValidUntil.ToUnixTimeSeconds());
    }

    private static byte[] ReadFixedProjectedBlob(
        SqliteDataReader reader,
        int lengthOrdinal,
        int blobOrdinal,
        int expectedBytes)
    {
        var length = reader.GetInt64(lengthOrdinal);
        if (length != expectedBytes)
        {
            throw new InvalidDataException("Membership trust blob length is invalid.");
        }

        return ReadProjectedBlob(reader, blobOrdinal, checked((int)length));
    }

    private static int[] ReadMembershipTrustBlobLengths(
        SqliteDataReader reader,
        int firstLengthOrdinal,
        ref long historyBytes)
    {
        var minimums = new[] { 32, 1, 32, 32, 32, 0, 0 };
        var maximums = new[]
        {
            MembershipLimits.HashLength,
            MembershipTrustRecord.MaximumEnvelopeLength,
            MembershipLimits.HashLength,
            MembershipLimits.HashLength,
            MembershipLimits.HashLength,
            MembershipTrustRecord.MaximumEnvelopeLength,
            MembershipLimits.MaximumRevokedDelegationHashes *
                MembershipLimits.HashLength
        };
        var lengths = new int[maximums.Length];
        long rowBytes = 0;
        for (var index = 0; index < maximums.Length; index++)
        {
            var length = reader.GetInt64(firstLengthOrdinal + index);
            if (length < minimums[index] || length > maximums[index] ||
                index == 6 && length % MembershipLimits.HashLength != 0)
            {
                throw new InvalidDataException("Membership trust blob length is invalid.");
            }
            rowBytes = checked(rowBytes + length);
            lengths[index] = checked((int)length);
        }

        if (historyBytes >
            MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryBytes -
            rowBytes)
        {
            throw new InvalidDataException("Membership trust history exceeds its budget.");
        }
        historyBytes += rowBytes;
        return lengths;
    }

    private static byte[] ReadProjectedBlob(
        SqliteDataReader reader,
        int blobOrdinal,
        int projectedLength)
    {
        var value = reader.GetFieldValue<byte[]>(blobOrdinal);
        if (value.Length != projectedLength)
        {
            throw new InvalidDataException("Membership trust blob length changed while reading.");
        }
        return value;
    }

    private static async Task<MembershipTrustRecord?> ReadMembershipTrustRecordAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string opaqueProfileKey,
        MembershipTrustDomain domain,
        ulong revision,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT version, artifact_kind, sequence, previous_sequence,
                   state, observed_at, valid_from, valid_until,
                   length(previous_hash), length(envelope), length(payload_digest),
                   length(canonical_hash), length(profile_binding_hash),
                   length(signing_authority), length(revoked_delegation_hashes),
                   previous_hash, envelope, payload_digest, canonical_hash,
                   profile_binding_hash, signing_authority, revoked_delegation_hashes
            FROM membership_trust_records
            WHERE profile_key = $profile AND domain = $domain AND revision = $revision;
            """;
        command.Parameters.AddWithValue("$profile", opaqueProfileKey);
        command.Parameters.AddWithValue("$domain", (int)domain);
        command.Parameters.AddWithValue("$revision", checked((long)revision));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var sequence = reader.GetInt64(2);
        var previousSequence = reader.GetInt64(3);
        if (sequence <= 0 || previousSequence < 0)
        {
            throw new InvalidDataException("Membership trust record counters are invalid.");
        }

        var recordBytes = 0L;
        var blobLengths = ReadMembershipTrustBlobLengths(
            reader,
            firstLengthOrdinal: 8,
            ref recordBytes);
        var record = new MembershipTrustRecord
        {
            Version = reader.GetInt32(0),
            OpaqueProfileKey = opaqueProfileKey,
            Domain = domain,
            ArtifactKind = (MembershipTrustArtifactKind)reader.GetInt32(1),
            Revision = revision,
            Sequence = checked((ulong)sequence),
            PreviousSequence = checked((ulong)previousSequence),
            PreviousCanonicalHash = ReadProjectedBlob(reader, 15, blobLengths[0]),
            CanonicalEnvelope = ReadProjectedBlob(reader, 16, blobLengths[1]),
            PayloadDigest = ReadProjectedBlob(reader, 17, blobLengths[2]),
            CanonicalHash = ReadProjectedBlob(reader, 18, blobLengths[3]),
            ProfileBindingHash = ReadProjectedBlob(reader, 19, blobLengths[4]),
            SigningAuthorityEnvelope = ReadProjectedBlob(reader, 20, blobLengths[5]),
            RevokedDelegationHashes = ReadProjectedBlob(reader, 21, blobLengths[6]),
            State = (MembershipTrustState)reader.GetInt32(4),
            ObservedAt = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(5)),
            ValidFrom = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(6)),
            ValidUntil = DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(7))
        };
        if (!MembershipTrustRepositoryValidation.IsValid(record))
        {
            throw new InvalidDataException("Membership trust record is invalid.");
        }
        return record;
    }

    private void InitializeSchema()
    {
        using var connection = OpenConnection();

        using (var versionCommand = connection.CreateCommand())
        {
            versionCommand.CommandText = "PRAGMA user_version;";
            var currentVersion = Convert.ToInt32(versionCommand.ExecuteScalar(), CultureInfo.InvariantCulture);
            if (currentVersion == PhysicalSchemaVersion)
            {
                EnsureMembershipTrustSchema(connection);
                return;
            }
            if (currentVersion > PhysicalSchemaVersion)
            {
                throw new InvalidOperationException(
                    $"Local database physical schema version {currentVersion} is newer than supported version {PhysicalSchemaVersion}.");
            }
        }

        using (var journalCommand = connection.CreateCommand())
        {
            journalCommand.CommandText = "PRAGMA journal_mode=WAL;";
            journalCommand.ExecuteNonQuery();
        }

        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
                CREATE TABLE IF NOT EXISTS conversations (
                    id TEXT PRIMARY KEY,
                    updated_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS contacts (
                    id TEXT PRIMARY KEY,
                    sort_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS groups (
                    id TEXT PRIMARY KEY,
                    sort_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    direction INTEGER NOT NULL,
                    delivery_state INTEGER NOT NULL,
                    read_at TEXT NULL,
                    expires_at TEXT NULL,
                    sender_session_id TEXT NULL,
                    recipient_session_id TEXT NULL,
                    server_hash TEXT NULL,
                    self_echo_key TEXT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incoming_message_notifications (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS schema_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    version INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS schema_values (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS replay_claims (
                    sender_session_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    envelope_digest TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(sender_session_id, message_id)
                );

                CREATE TABLE IF NOT EXISTS inbox_cursors (
                    account_session_id TEXT NOT NULL,
                    namespace INTEGER NOT NULL,
                    cursor TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(account_session_id, namespace)
                );

                CREATE TABLE IF NOT EXISTS inbox_items (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_session_id TEXT NOT NULL,
                    namespace INTEGER NOT NULL,
                    server_hash TEXT NOT NULL,
                    storage_timestamp INTEGER NOT NULL,
                    wire_payload TEXT NOT NULL,
                    wire_digest TEXT NOT NULL,
                    item_kind INTEGER NULL,
                    route_key TEXT NULL,
                    sender_session_id TEXT NULL,
                    message_id TEXT NULL,
                    envelope_digest TEXT NULL,
                    protocol_expires_at INTEGER NULL,
                    UNIQUE(account_session_id, namespace, server_hash)
                );

                CREATE TABLE IF NOT EXISTS group_state_outbox (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    group_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    group_payload TEXT NOT NULL,
                    recipients_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS membership_trust_records (
                    profile_key TEXT NOT NULL,
                    domain INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    version INTEGER NOT NULL DEFAULT 2,
                    artifact_kind INTEGER NOT NULL DEFAULT 1,
                    sequence INTEGER NOT NULL,
                    previous_sequence INTEGER NOT NULL,
                    previous_hash BLOB NOT NULL,
                    envelope BLOB NOT NULL,
                    payload_digest BLOB NOT NULL,
                    canonical_hash BLOB NOT NULL,
                    profile_binding_hash BLOB NOT NULL,
                    signing_authority BLOB NOT NULL DEFAULT X'',
                    revoked_delegation_hashes BLOB NOT NULL DEFAULT X'',
                    state INTEGER NOT NULL,
                    observed_at INTEGER NOT NULL,
                    valid_from INTEGER NOT NULL DEFAULT 0,
                    valid_until INTEGER NOT NULL,
                    PRIMARY KEY(profile_key, domain, revision)
                );

                CREATE TABLE IF NOT EXISTS membership_trust_heads (
                    profile_key TEXT NOT NULL,
                    domain INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_digest BLOB NOT NULL,
                    history_bytes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(profile_key, domain)
                );

                CREATE TABLE IF NOT EXISTS membership_trust_clock (
                    profile_key TEXT NOT NULL PRIMARY KEY,
                    version INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    observed_at INTEGER NOT NULL,
                    digest BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
                    ON messages(conversation_id, created_at);

                CREATE INDEX IF NOT EXISTS idx_replay_claims_expires_at
                    ON replay_claims(expires_at);

                CREATE INDEX IF NOT EXISTS idx_inbox_items_staged
                    ON inbox_items(account_session_id, namespace, item_kind, sequence);

                CREATE INDEX IF NOT EXISTS idx_inbox_items_decoded_route
                    ON inbox_items(account_session_id, namespace, item_kind, route_key, sequence);

                CREATE INDEX IF NOT EXISTS idx_inbox_items_logical_message
                    ON inbox_items(sender_session_id, message_id, sequence);

                CREATE INDEX IF NOT EXISTS idx_group_state_outbox_order
                    ON group_state_outbox(group_id, revision, sequence);

                CREATE INDEX IF NOT EXISTS idx_membership_trust_records_head
                    ON membership_trust_records(profile_key, domain, revision);
                """;
        command.ExecuteNonQuery();
        EnsureMessageHotColumns(connection, transaction);
        EnsureMessageHotIndexes(connection, transaction);
        EnsureMembershipTrustColumns(connection, transaction);

        using var markVersionCommand = connection.CreateCommand();
        markVersionCommand.Transaction = transaction;
        markVersionCommand.CommandText = $"PRAGMA user_version={PhysicalSchemaVersion};";
        markVersionCommand.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void EnsureMembershipTrustSchema(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS membership_trust_records (
                profile_key TEXT NOT NULL,
                domain INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 2,
                artifact_kind INTEGER NOT NULL DEFAULT 1,
                sequence INTEGER NOT NULL,
                previous_sequence INTEGER NOT NULL,
                previous_hash BLOB NOT NULL,
                envelope BLOB NOT NULL,
                payload_digest BLOB NOT NULL,
                canonical_hash BLOB NOT NULL,
                profile_binding_hash BLOB NOT NULL,
                signing_authority BLOB NOT NULL DEFAULT X'',
                revoked_delegation_hashes BLOB NOT NULL DEFAULT X'',
                state INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                valid_from INTEGER NOT NULL DEFAULT 0,
                valid_until INTEGER NOT NULL,
                PRIMARY KEY(profile_key, domain, revision)
            );

            CREATE TABLE IF NOT EXISTS membership_trust_heads (
                profile_key TEXT NOT NULL,
                domain INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                payload_digest BLOB NOT NULL,
                history_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(profile_key, domain)
            );

            CREATE TABLE IF NOT EXISTS membership_trust_clock (
                profile_key TEXT NOT NULL PRIMARY KEY,
                version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                digest BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_membership_trust_records_head
                ON membership_trust_records(profile_key, domain, revision);
            """;
        command.ExecuteNonQuery();
        EnsureMembershipTrustColumns(connection, transaction);
        transaction.Commit();
    }

    private static void EnsureMembershipTrustColumns(
        SqliteConnection connection,
        SqliteTransaction transaction)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var inspect = connection.CreateCommand())
        {
            inspect.Transaction = transaction;
            inspect.CommandText = "PRAGMA table_info(membership_trust_records);";
            using var reader = inspect.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }
        }
        var additions = new List<string>();
        if (!columns.Contains("artifact_kind"))
        {
            additions.Add(
                "ALTER TABLE membership_trust_records ADD COLUMN artifact_kind INTEGER NOT NULL DEFAULT 1;");
        }
        if (!columns.Contains("signing_authority"))
        {
            additions.Add(
                "ALTER TABLE membership_trust_records ADD COLUMN signing_authority BLOB NOT NULL DEFAULT X'';");
        }
        if (!columns.Contains("revoked_delegation_hashes"))
        {
            additions.Add(
                "ALTER TABLE membership_trust_records ADD COLUMN revoked_delegation_hashes BLOB NOT NULL DEFAULT X'';");
        }
        foreach (var statement in additions)
        {
            using var alter = connection.CreateCommand();
            alter.Transaction = transaction;
            alter.CommandText = statement;
            alter.ExecuteNonQuery();
        }

        var headColumns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var inspect = connection.CreateCommand())
        {
            inspect.Transaction = transaction;
            inspect.CommandText = "PRAGMA table_info(membership_trust_heads);";
            using var reader = inspect.ExecuteReader();
            while (reader.Read())
            {
                headColumns.Add(reader.GetString(1));
            }
        }
        if (!headColumns.Contains("history_bytes"))
        {
            using (var alter = connection.CreateCommand())
            {
                alter.Transaction = transaction;
                alter.CommandText = """
                    ALTER TABLE membership_trust_heads
                    ADD COLUMN history_bytes INTEGER NOT NULL DEFAULT 0;
                    """;
                alter.ExecuteNonQuery();
            }
            using var backfill = connection.CreateCommand();
            backfill.Transaction = transaction;
            backfill.CommandText = """
                UPDATE membership_trust_heads
                SET history_bytes = COALESCE((
                    SELECT SUM(row_bytes)
                    FROM (
                        SELECT length(previous_hash) + length(envelope) +
                               length(payload_digest) + length(canonical_hash) +
                               length(profile_binding_hash) + length(signing_authority) +
                               length(revoked_delegation_hashes) AS row_bytes
                        FROM membership_trust_records
                        WHERE profile_key = membership_trust_heads.profile_key
                          AND domain = membership_trust_heads.domain
                          AND revision <= membership_trust_heads.revision
                        ORDER BY revision
                        LIMIT $historyLimit
                    )
                ), 0);
                """;
            backfill.Parameters.AddWithValue(
                "$historyLimit",
                MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords + 1);
            backfill.ExecuteNonQuery();
        }
    }

    private static void EnsureMessageHotColumns(SqliteConnection connection, SqliteTransaction transaction)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA table_info(messages);";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            var statements = new List<string>();
            if (!columns.Contains("direction"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN direction INTEGER;");
            }

            if (!columns.Contains("delivery_state"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN delivery_state INTEGER;");
            }

            if (!columns.Contains("read_at"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN read_at TEXT;");
            }

            if (!columns.Contains("expires_at"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN expires_at TEXT;");
            }

            if (!columns.Contains("sender_session_id"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN sender_session_id TEXT;");
            }

            if (!columns.Contains("recipient_session_id"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN recipient_session_id TEXT;");
            }

            if (!columns.Contains("server_hash"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN server_hash TEXT;");
            }

            if (!columns.Contains("self_echo_key"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN self_echo_key TEXT;");
            }

            if (statements.Count == 0)
            {
                return;
            }

            command.CommandText = string.Join(Environment.NewLine, statements);
            command.ExecuteNonQuery();
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE messages
                SET
                    direction = COALESCE(direction, CAST(json_extract(payload_json, '$.direction') AS INTEGER)),
                    delivery_state = COALESCE(delivery_state, CAST(json_extract(payload_json, '$.deliveryState') AS INTEGER)),
                    read_at = COALESCE(read_at, json_extract(payload_json, '$.readAt')),
                    expires_at = COALESCE(expires_at, json_extract(payload_json, '$.expiresAt')),
                    sender_session_id = COALESCE(sender_session_id, json_extract(payload_json, '$.sender.value')),
                    recipient_session_id = COALESCE(recipient_session_id, json_extract(payload_json, '$.recipient.value')),
                    server_hash = COALESCE(server_hash, json_extract(payload_json, '$.serverHash'))
                WHERE direction IS NULL
                   OR delivery_state IS NULL
                   OR (read_at IS NULL AND json_extract(payload_json, '$.readAt') IS NOT NULL)
                   OR sender_session_id IS NULL
                   OR (recipient_session_id IS NULL AND json_extract(payload_json, '$.recipient.value') IS NOT NULL)
                   OR (server_hash IS NULL AND json_extract(payload_json, '$.serverHash') IS NOT NULL)
                   OR (expires_at IS NULL AND json_extract(payload_json, '$.expiresAt') IS NOT NULL);
                """;
            command.ExecuteNonQuery();
        }

        BackfillSelfEchoKeys(connection, transaction);
    }

    private static void EnsureMessageHotIndexes(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS idx_messages_conversation_created_id
                ON messages(conversation_id, created_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_messages_unread
                ON messages(conversation_id, direction, delivery_state, created_at);

            CREATE INDEX IF NOT EXISTS idx_messages_server_hash
                ON messages(conversation_id, server_hash)
                WHERE server_hash IS NOT NULL;

            CREATE INDEX IF NOT EXISTS idx_messages_self_echo
                ON messages(conversation_id, sender_session_id, recipient_session_id, direction, self_echo_key);

            CREATE INDEX IF NOT EXISTS idx_messages_pending_outgoing
                ON messages(sender_session_id, direction, delivery_state, created_at, id);
            """;
        command.ExecuteNonQuery();
    }

    private static void BackfillSelfEchoKeys(SqliteConnection connection, SqliteTransaction transaction)
    {
        var rows = new List<(string Id, Message Message)>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT id, payload_json FROM messages WHERE self_echo_key IS NULL;";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var message = JsonSerializer.Deserialize<Message>(reader.GetString(1), SerializerOptions);
                if (message is not null)
                {
                    rows.Add((reader.GetString(0), message));
                }
            }
        }

        using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE messages
            SET sender_session_id = $senderSessionId,
                recipient_session_id = $recipientSessionId,
                server_hash = $serverHash,
                self_echo_key = $selfEchoKey
            WHERE id = $id;
            """;
        var id = update.Parameters.Add("$id", SqliteType.Text);
        var sender = update.Parameters.Add("$senderSessionId", SqliteType.Text);
        var recipient = update.Parameters.Add("$recipientSessionId", SqliteType.Text);
        var serverHash = update.Parameters.Add("$serverHash", SqliteType.Text);
        var selfEchoKey = update.Parameters.Add("$selfEchoKey", SqliteType.Text);
        update.Prepare();
        foreach (var row in rows)
        {
            id.Value = row.Id;
            sender.Value = row.Message.Sender.Value;
            recipient.Value = row.Message.Recipient?.Value ?? (object)DBNull.Value;
            serverHash.Value = row.Message.ServerHash ?? (object)DBNull.Value;
            selfEchoKey.Value = MessagePersistenceKeys.SelfEcho(row.Message);
            update.ExecuteNonQuery();
        }
    }

    private static void ValidateReplayClaim(
        SessionId sender,
        MessageId messageId,
        string envelopeDigest,
        DateTimeOffset protocolExpiresAt)
    {
        if (string.IsNullOrWhiteSpace(sender.Value))
        {
            throw new ArgumentException("Sender session ID is required.", nameof(sender));
        }

        if (string.IsNullOrWhiteSpace(messageId.Value))
        {
            throw new ArgumentException("Message ID is required.", nameof(messageId));
        }

        if (envelopeDigest is null
            || envelopeDigest.Length != 64
            || envelopeDigest.Any(static character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
        {
            throw new ArgumentException("Envelope digest must be 64 lowercase hexadecimal characters.", nameof(envelopeDigest));
        }

        if (protocolExpiresAt <= DateTimeOffset.UnixEpoch)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolExpiresAt), "Protocol expiry must be after the Unix epoch.");
        }
    }


    private async Task ExecuteNonQueryAsync(string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await WithConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var parameter in parameters)
            {
                command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
            }

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static (string Name, object? Value)[] MessageParameters(Message message) =>
    [
        ("$id", message.Id.Value),
        ("$conversationId", message.ConversationId.Value),
        ("$createdAt", message.CreatedAt.ToUnixTimeMilliseconds()),
        ("$direction", (int)message.Direction),
        ("$deliveryState", (int)message.DeliveryState),
        ("$readAt", message.ReadAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)),
        ("$expiresAt", message.ExpiresAt?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)),
        ("$senderSessionId", message.Sender.Value),
        ("$recipientSessionId", message.Recipient?.Value),
        ("$serverHash", message.ServerHash),
        ("$selfEchoKey", MessagePersistenceKeys.SelfEcho(message)),
        ("$payload", JsonSerializer.Serialize(message, SerializerOptions))
    ];

    private static void AddParameters(
        SqliteCommand command,
        IEnumerable<(string Name, object? Value)> parameters)
    {
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        }
    }

    private async Task<int> ExecuteNonQueryCountAsync(
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object? Value)[] parameters)
    {
        return await WithConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var parameter in parameters)
            {
                command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
            }

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecuteNonQueryOnConnectionAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        }

        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ConversationReadResult> MarkConversationReadOnConnectionAsync(
        SqliteConnection connection,
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken)
    {
        using var transaction = connection.BeginTransaction();
        var existingReadAt = await ReadCursorOnConnectionAsync(
            connection,
            transaction,
            conversationId,
            cancellationToken).ConfigureAwait(false);
        int changed;
        await using (var messagesCommand = connection.CreateCommand())
        {
            messagesCommand.Transaction = transaction;
            messagesCommand.CommandText = """
                UPDATE messages
                SET delivery_state = $readState,
                    read_at = $readAt
                WHERE conversation_id = $conversationId
                  AND direction = $incomingDirection
                  AND delivery_state != $readState;
                """;
            messagesCommand.Parameters.AddWithValue("$readState", (int)MessageDeliveryState.Read);
            messagesCommand.Parameters.AddWithValue("$readAt", readAt.ToString("O", CultureInfo.InvariantCulture));
            messagesCommand.Parameters.AddWithValue("$conversationId", conversationId.Value);
            messagesCommand.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
            await messagesCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
            changed = await messagesCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        if (changed == 0)
        {
            transaction.Commit();
            return new ConversationReadResult(0, existingReadAt);
        }

        var effectiveReadAt = Max(existingReadAt, readAt) ?? readAt;
        await UpsertReadCursorOnConnectionAsync(
            connection,
            transaction,
            conversationId,
            effectiveReadAt,
            cancellationToken).ConfigureAwait(false);
        transaction.Commit();
        return new ConversationReadResult(changed, effectiveReadAt);
    }

    private static async Task<int> ApplyReadCursorOnConnectionAsync(
        SqliteConnection connection,
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken)
    {
        using var transaction = connection.BeginTransaction();
        var existingReadAt = await ReadCursorOnConnectionAsync(
            connection,
            transaction,
            conversationId,
            cancellationToken).ConfigureAwait(false);
        int changed;
        await using (var messagesCommand = connection.CreateCommand())
        {
            messagesCommand.Transaction = transaction;
            messagesCommand.CommandText = """
                UPDATE messages
                SET delivery_state = $readState,
                    read_at = $readAt
                WHERE conversation_id = $conversationId
                  AND direction = $incomingDirection
                  AND delivery_state != $readState
                  AND created_at <= $readAtUnixMilliseconds;
                """;
            messagesCommand.Parameters.AddWithValue("$readState", (int)MessageDeliveryState.Read);
            messagesCommand.Parameters.AddWithValue("$readAt", readAt.ToString("O", CultureInfo.InvariantCulture));
            messagesCommand.Parameters.AddWithValue("$readAtUnixMilliseconds", readAt.ToUnixTimeMilliseconds());
            messagesCommand.Parameters.AddWithValue("$conversationId", conversationId.Value);
            messagesCommand.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
            await messagesCommand.PrepareAsync(cancellationToken).ConfigureAwait(false);
            changed = await messagesCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        if (existingReadAt is null || readAt > existingReadAt)
        {
            await UpsertReadCursorOnConnectionAsync(
                connection,
                transaction,
                conversationId,
                readAt,
                cancellationToken).ConfigureAwait(false);
        }

        transaction.Commit();
        return changed;
    }

    private static async Task<DateTimeOffset?> ReadCursorOnConnectionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ConversationId conversationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT payload_json FROM settings WHERE key = $key;";
        command.Parameters.AddWithValue("$key", ReadCursorSettingKey(conversationId));
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        return ParseReadCursorPayload(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string);
    }

    private static async Task UpsertReadCursorOnConnectionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ConversationId conversationId,
        DateTimeOffset readAt,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO settings (key, payload_json)
            VALUES ($key, $payload)
            ON CONFLICT(key) DO UPDATE SET payload_json = excluded.payload_json;
            """;
        command.Parameters.AddWithValue("$key", ReadCursorSettingKey(conversationId));
        command.Parameters.AddWithValue(
            "$payload",
            JsonSerializer.Serialize(readAt.ToString("O", CultureInfo.InvariantCulture), SerializerOptions));
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<T?> ExecuteScalarAsync<T>(string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        return await WithConnectionAsync(async connection =>
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var parameter in parameters)
            {
                command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
            }

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

            var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (result is null || result is DBNull)
            {
                return default;
            }

            if (result is T typed)
            {
                return typed;
            }

            var targetType = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            return (T?)Convert.ChangeType(result, targetType, CultureInfo.InvariantCulture);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T?> ExecuteScalarOnConnectionAsync<T>(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var parameter in parameters)
        {
            command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        }

        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (result is null || result is DBNull)
        {
            return default;
        }

        if (result is T typed)
        {
            return typed;
        }

        var targetType = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
        return (T?)Convert.ChangeType(result, targetType, CultureInfo.InvariantCulture);
    }

    private async Task<IReadOnlyList<string>> QueryJsonAsync(string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        return await WithConnectionAsync(async connection =>
        {
            var result = new List<string>();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var parameter in parameters)
            {
                command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
            }

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                result.Add(reader.GetString(0));
            }

            return result;
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyDictionary<ConversationId, ConversationSummaryBase>> LoadConversationSummaryBaseAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, ConversationSummaryBase>(conversationIds.Count);
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$conversationIdsJson", SerializeConversationIds(conversationIds));
        command.Parameters.AddWithValue("$readCursorPrefix", ReadCursorSettingPrefix);
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        command.CommandText = """
            WITH requested(conversation_id) AS (
                SELECT CAST(value AS TEXT)
                FROM json_each($conversationIdsJson)
            )
            SELECT
                requested.conversation_id,
                settings.payload_json,
                (
                    SELECT json_set(messages.payload_json, '$.deliveryState', messages.delivery_state, '$.readAt', messages.read_at)
                    FROM messages
                    WHERE messages.conversation_id = requested.conversation_id
                      AND (messages.expires_at IS NULL OR messages.expires_at > $now)
                    ORDER BY messages.created_at DESC, messages.id DESC
                    LIMIT 1
                ) AS last_message,
                contacts.payload_json
            FROM requested
            LEFT JOIN settings
                ON settings.key = $readCursorPrefix || requested.conversation_id
            LEFT JOIN contacts
                ON contacts.id = requested.conversation_id;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var conversationId = new ConversationId(reader.GetString(0));
            var readCursor = ParseReadCursorPayload(GetNullableString(reader, 1));
            var lastMessagePayload = GetNullableString(reader, 2);
            var contactPayload = GetNullableString(reader, 3);
            result[conversationId] = new ConversationSummaryBase(
                readCursor,
                lastMessagePayload is null
                    ? null
                    : JsonSerializer.Deserialize<Message>(lastMessagePayload, SerializerOptions),
                contactPayload is null
                    ? null
                    : JsonSerializer.Deserialize<Contact>(contactPayload, SerializerOptions));
        }

        return result;
    }

    private static async Task<OneToOneOpenMetadata> LoadOneToOneOpenMetadataAsync(
        SqliteConnection connection,
        SessionId recipient,
        ConversationId conversationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT payload_json FROM settings WHERE key = $activeAccountKey) AS active_account,
                (SELECT payload_json FROM contacts WHERE id = $recipientId) AS contact,
                (SELECT payload_json FROM conversations WHERE id = $conversationId) AS conversation,
                (SELECT payload_json FROM settings WHERE key = $readCursorKey) AS read_cursor;
            """;
        command.Parameters.AddWithValue("$activeAccountKey", LocalSettingsKeys.ActiveAccount);
        command.Parameters.AddWithValue("$recipientId", recipient.Value);
        command.Parameters.AddWithValue("$conversationId", conversationId.Value);
        command.Parameters.AddWithValue("$readCursorKey", ReadCursorSettingKey(conversationId));
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return new OneToOneOpenMetadata(null, null, null, null);
        }

        return new OneToOneOpenMetadata(
            GetNullableString(reader, 0),
            GetNullableString(reader, 1),
            GetNullableString(reader, 2),
            GetNullableString(reader, 3));
    }

    private static DateTimeOffset? ParseReadCursorPayload(string? payload)
    {
        if (payload is null)
        {
            return null;
        }

        var value = JsonSerializer.Deserialize<string>(payload, SerializerOptions);
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var parsed)
            ? parsed
            : null;
    }

    private static string? GetNullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTimeOffset? Max(DateTimeOffset? left, DateTimeOffset? right)
    {
        if (left is null)
        {
            return right;
        }

        if (right is null)
        {
            return left;
        }

        return left >= right ? left : right;
    }

    private static async Task<IReadOnlyDictionary<ConversationId, int>> LoadUnreadCountsAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, int>();
        await using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$conversationIdsJson", SerializeConversationIds(conversationIds));
        command.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
        command.Parameters.AddWithValue("$readState", (int)MessageDeliveryState.Read);
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        command.CommandText = """
            WITH requested(conversation_id) AS (
                SELECT CAST(value AS TEXT)
                FROM json_each($conversationIdsJson)
            )
            SELECT conversation_id, COUNT(*)
            FROM messages
            WHERE conversation_id IN (SELECT conversation_id FROM requested)
              AND direction = $incomingDirection
              AND delivery_state != $readState
              AND (expires_at IS NULL OR expires_at > $now)
            GROUP BY conversation_id;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result[new ConversationId(reader.GetString(0))] = (int)reader.GetInt64(1);
        }

        return result;
    }

    private static string SerializeConversationIds(IReadOnlyList<ConversationId> conversationIds) =>
        JsonSerializer.Serialize(
            conversationIds.Select(static conversationId => conversationId.Value),
            SerializerOptions);

    private static string ReadCursorSettingKey(ConversationId conversationId) =>
        ReadCursorSettingPrefix + conversationId.Value;

    private async Task<IReadOnlyList<DurableInboxItem>> QueryInboxItemsAsync(
        DurableInboxScope scope,
        string predicate,
        DurableInboxItemKind? kind,
        string? routeKey,
        int limit,
        CancellationToken cancellationToken)
    {
        return await WithReplayConnectionAsync(async connection =>
        {
            var result = new List<DurableInboxItem>(limit);
            await using var command = connection.CreateCommand();
            command.CommandText = $"""
                SELECT sequence,
                       server_hash,
                       storage_timestamp,
                       wire_payload,
                       wire_digest,
                       item_kind,
                       route_key,
                       sender_session_id,
                       message_id,
                       envelope_digest,
                       protocol_expires_at
                FROM inbox_items
                WHERE account_session_id = $accountSessionId
                  AND namespace = $namespace
                  AND {predicate}
                ORDER BY sequence
                LIMIT $limit;
                """;
            AddInboxScopeParameters(command, scope);
            command.Parameters.AddWithValue("$limit", limit);
            if (kind is not null)
            {
                command.Parameters.AddWithValue("$itemKind", (int)kind.Value);
                command.Parameters.AddWithValue("$routeKey", routeKey is null ? DBNull.Value : routeKey);
            }

            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                result.Add(ReadInboxItem(reader, scope));
            }

            return (IReadOnlyList<DurableInboxItem>)result;
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string?> ReadInboxCursorAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DurableInboxScope scope,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT cursor
            FROM inbox_cursors
            WHERE account_session_id = $accountSessionId AND namespace = $namespace;
            """;
        AddInboxScopeParameters(command, scope);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
    }

    private static async Task<(long StorageTimestamp, string WireDigest)?> ReadExistingWireIdentityAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT storage_timestamp, wire_digest
            FROM inbox_items
            WHERE account_session_id = $accountSessionId
              AND namespace = $namespace
              AND server_hash = $serverHash;
            """;
        AddInboxScopeParameters(command, scope);
        command.Parameters.AddWithValue("$serverHash", serverHash);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? (reader.GetInt64(0), reader.GetString(1))
            : null;
    }

    private static async Task<DurableInboxItem?> ReadInboxItemAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT sequence,
                   server_hash,
                   storage_timestamp,
                   wire_payload,
                   wire_digest,
                   item_kind,
                   route_key,
                   sender_session_id,
                   message_id,
                   envelope_digest,
                   protocol_expires_at
            FROM inbox_items
            WHERE account_session_id = $accountSessionId
              AND namespace = $namespace
              AND server_hash = $serverHash;
            """;
        AddInboxScopeParameters(command, scope);
        command.Parameters.AddWithValue("$serverHash", serverHash);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            ? ReadInboxItem(reader, scope)
            : null;
    }

    private static DurableInboxItem ReadInboxItem(SqliteDataReader reader, DurableInboxScope scope)
    {
        DurableInboxDecodedMetadata? decoded = null;
        if (!reader.IsDBNull(5))
        {
            decoded = new DurableInboxDecodedMetadata(
                (DurableInboxItemKind)reader.GetInt32(5),
                reader.GetString(6),
                SessionId.Parse(reader.GetString(7)),
                MessageId.Parse(reader.GetString(8)),
                reader.GetString(9),
                DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(10)));
        }

        return new DurableInboxItem(
            reader.GetInt64(0),
            scope,
            reader.GetString(1),
            reader.GetInt64(2),
            reader.GetString(3),
            reader.GetString(4),
            decoded);
    }

    private static async Task<string?> ReadReplayDigestAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        SessionId sender,
        MessageId messageId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT envelope_digest
            FROM replay_claims
            WHERE sender_session_id = $senderSessionId AND message_id = $messageId;
            """;
        command.Parameters.AddWithValue("$senderSessionId", sender.Value);
        command.Parameters.AddWithValue("$messageId", messageId.Value);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
    }

    private static async Task DeleteInboxItemAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DurableInboxScope scope,
        string serverHash,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            DELETE FROM inbox_items
            WHERE account_session_id = $accountSessionId
              AND namespace = $namespace
              AND server_hash = $serverHash;
            """;
        AddInboxScopeParameters(command, scope);
        command.Parameters.AddWithValue("$serverHash", serverHash);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void AddInboxScopeParameters(SqliteCommand command, DurableInboxScope scope)
    {
        command.Parameters.AddWithValue("$accountSessionId", scope.Account.Value);
        command.Parameters.AddWithValue("$namespace", scope.Namespace);
    }

    private static void ValidateInboxBatch(
        DurableInboxScope scope,
        string? expectedCursor,
        string? nextCursor,
        IReadOnlyList<DurableInboxWireEntry> entries)
    {
        ValidateInboxScope(scope);
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(entries), "Inbox batches must be bounded.");
        }

        ValidateOptionalCursor(expectedCursor, nameof(expectedCursor));
        ValidateOptionalCursor(nextCursor, nameof(nextCursor));
        if (entries.Count == 0)
        {
            if (!string.Equals(expectedCursor, nextCursor, StringComparison.Ordinal))
            {
                throw new ArgumentException("An empty inbox batch cannot advance the cursor.", nameof(nextCursor));
            }

            return;
        }

        if (!string.Equals(entries[^1].ServerHash, nextCursor, StringComparison.Ordinal))
        {
            throw new ArgumentException("The next cursor must be the final staged server hash.", nameof(nextCursor));
        }

        foreach (var entry in entries)
        {
            ArgumentNullException.ThrowIfNull(entry);
            ValidateServerHash(entry.ServerHash);
            if (entry.WirePayload is null || entry.WirePayload.Length > DurableInboxLimits.MaxWirePayloadChars)
            {
                throw new ArgumentOutOfRangeException(nameof(entries), "An inbox wire payload exceeds the durable staging limit.");
            }

            if (!string.Equals(
                    DurableInboxWireEntry.ComputeDigest(entry.WirePayload),
                    entry.WireDigest,
                    StringComparison.Ordinal))
            {
                throw new DurableInboxDigestMismatchException(
                    $"Inbox entry '{entry.ServerHash}' does not match its declared wire digest.");
            }
        }
    }

    private static void ValidateInboxList(DurableInboxScope scope, int limit)
    {
        ValidateInboxScope(scope);
        if (limit is <= 0 or > DurableInboxLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static void ValidateInboxScope(DurableInboxScope scope)
    {
        if (string.IsNullOrWhiteSpace(scope.Account.Value))
        {
            throw new ArgumentException("Inbox account session ID is required.", nameof(scope));
        }
    }

    private static void ValidateOptionalCursor(string? cursor, string parameterName)
    {
        if (cursor is not null && (string.IsNullOrWhiteSpace(cursor) || cursor.Length > DurableInboxLimits.MaxServerHashChars))
        {
            throw new ArgumentException("Inbox cursor is invalid.", parameterName);
        }
    }

    private static void ValidateServerHash(string serverHash)
    {
        if (string.IsNullOrWhiteSpace(serverHash) || serverHash.Length > DurableInboxLimits.MaxServerHashChars)
        {
            throw new ArgumentException("Inbox server hash is invalid.", nameof(serverHash));
        }
    }

    private static void ValidateDecodedMetadata(DurableInboxDecodedMetadata decoded)
    {
        ArgumentNullException.ThrowIfNull(decoded);
        if (!Enum.IsDefined(decoded.Kind))
        {
            throw new ArgumentOutOfRangeException(nameof(decoded));
        }

        if (string.IsNullOrWhiteSpace(decoded.RouteKey))
        {
            throw new ArgumentException("Decoded inbox route is required.", nameof(decoded));
        }

        ValidateReplayClaim(
            decoded.Sender,
            decoded.MessageId,
            decoded.EnvelopeDigest,
            decoded.ProtocolExpiresAt);
    }

    private static async Task ValidatePersistedGroupRevisionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Group candidate,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT payload_json FROM groups WHERE id = $id;";
        command.Parameters.AddWithValue("$id", candidate.Id.Value);
        var payload = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
        if (payload is null)
        {
            return;
        }

        var existing = JsonSerializer.Deserialize<Group>(payload, SerializerOptions)
            ?? throw new InvalidOperationException("Persisted group state is invalid.");
        var candidatePayload = JsonSerializer.Serialize(candidate, SerializerOptions);
        if (candidate.Revision < existing.Revision
            || (candidate.Revision == existing.Revision
                && !string.Equals(payload, candidatePayload, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("A group revision cannot be overwritten by divergent or older state.");
        }
    }

    private static async Task ValidateExistingOutboxAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        GroupStateOutboxItem item,
        string groupPayload,
        string recipientsPayload,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT group_id, revision, updated_at, group_payload, recipients_json
            FROM group_state_outbox
            WHERE operation_id = $operationId;
            """;
        command.Parameters.AddWithValue("$operationId", item.OperationId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || !string.Equals(reader.GetString(0), item.Group.Id.Value, StringComparison.Ordinal)
            || reader.GetInt64(1) != item.Group.Revision
            || reader.GetInt64(2) != item.UpdatedAt.ToUnixTimeMilliseconds()
            || !string.Equals(reader.GetString(3), groupPayload, StringComparison.Ordinal)
            || !string.Equals(reader.GetString(4), recipientsPayload, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("A group outbox operation ID was reused with different state.");
        }
    }

    private static string GroupStateUpdatedAtSettingKey(ConversationId groupId) =>
        $"sync.group-state-updated.{groupId.Value}";

    private static void ValidateGroupStatePersistence(
        Group group,
        Conversation conversation,
        DateTimeOffset updatedAt,
        GroupStateOutboxItem? outboxItem)
    {
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(conversation);
        if (group.Revision < 1 || group.Id != conversation.Id || conversation.Kind != ConversationKind.GroupV2
            || updatedAt <= DateTimeOffset.UnixEpoch)
        {
            throw new ArgumentException("Group persistence state is invalid.");
        }

        if (outboxItem is null)
        {
            return;
        }

        ValidateGroupOutboxOperationId(outboxItem.OperationId);
        if (outboxItem.UpdatedAt != updatedAt
            || outboxItem.Recipients.Count == 0
            || outboxItem.Recipients.Count > 4096
            || outboxItem.Recipients.Any(static recipient => string.IsNullOrWhiteSpace(recipient.Value))
            || !string.Equals(
                JsonSerializer.Serialize(outboxItem.Group, SerializerOptions),
                JsonSerializer.Serialize(group, SerializerOptions),
                StringComparison.Ordinal))
        {
            throw new ArgumentException("Group outbox state is invalid.", nameof(outboxItem));
        }
    }

    private static void ValidateGroupOutboxLimit(int limit)
    {
        if (limit is <= 0 or > GroupStateOutboxLimits.MaxPublishBatch)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static void ValidateIncomingMessageNotificationLimit(int limit)
    {
        if (limit is <= 0 or > IncomingMessageNotificationLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(limit));
        }
    }

    private static string[] ValidateIncomingMessageNotificationIds(IReadOnlyCollection<MessageId> ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        var values = ids
            .Select(static id => id.Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (values.Length > IncomingMessageNotificationLimits.MaxBatchCount)
        {
            throw new ArgumentOutOfRangeException(nameof(ids));
        }

        if (values.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Message IDs must not be empty.", nameof(ids));
        }

        return values;
    }

    private static void ValidateGroupOutboxOperationId(string operationId)
    {
        if (string.IsNullOrWhiteSpace(operationId) || operationId.Length > 256)
        {
            throw new ArgumentException("Group outbox operation ID is invalid.", nameof(operationId));
        }
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        ConfigureConnection(connection);
        return connection;
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        ConfigureConnection(connection);
        return connection;
    }

    private async Task WithConnectionAsync(
        Func<SqliteConnection, Task> action,
        CancellationToken cancellationToken)
    {
        await WithConnectionAsync<object?>(async connection =>
        {
            await action(connection).ConfigureAwait(false);
            return null;
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> WithConnectionAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        return await WithConnectionCoreAsync(action, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> WithConnectionCoreAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        return await ExecuteDatabaseOperationAsync(action, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> WithReplayConnectionAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        return await WithReplayConnectionCoreAsync(action, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> WithReplayConnectionCoreAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        return await ExecuteDatabaseOperationAsync(action, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResult> ExecuteDatabaseOperationAsync<TResult>(
        Func<SqliteConnection, Task<TResult>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();

        return await Task.Run(async () =>
        {
            await _databaseGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
                return await action(connection).ConfigureAwait(false);
            }
            finally
            {
                _databaseGate.Release();
            }
        }, CancellationToken.None).ConfigureAwait(false);
    }

    private static string ConnectionStringFor(string statePath, string? encryptionKey = null, bool pooling = true)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = pooling
        };
        if (!string.IsNullOrWhiteSpace(encryptionKey))
        {
            builder.Password = encryptionKey;
        }

        return builder.ToString();
    }

    private static SqliteConnection OpenConnectionForPath(string statePath, string? encryptionKey)
    {
        var connection = new SqliteConnection(ConnectionStringFor(statePath, pooling: false));
        connection.Open();
        ApplyEncryptionKey(connection, encryptionKey);
        ConfigureConnection(connection);
        return connection;
    }

    private static void ConfigureConnection(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA cache_size = -8192;
            """;
        command.ExecuteNonQuery();
    }

    private static bool HasPlaintextSqliteHeader(string statePath)
    {
        Span<byte> header = stackalloc byte[16];
        try
        {
            using var stream = new FileStream(
                statePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: header.Length,
                FileOptions.SequentialScan);
            stream.ReadExactly(header);
            return header.SequenceEqual(SqliteHeader);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void ApplyEncryptionKey(SqliteConnection connection, string? encryptionKey)
    {
        if (string.IsNullOrWhiteSpace(encryptionKey))
        {
            return;
        }

        using var pragma = connection.CreateCommand();
        pragma.CommandText = $"PRAGMA key = '{EscapePragmaString(encryptionKey)}';";
        pragma.ExecuteNonQuery();

        using var cipherVersion = connection.CreateCommand();
        cipherVersion.CommandText = "PRAGMA cipher_version;";
        var version = cipherVersion.ExecuteScalar()?.ToString();
        if (string.IsNullOrWhiteSpace(version))
        {
            throw new InvalidOperationException("SQLCipher support is not available for the local state database.");
        }
    }

    private static string EscapePragmaString(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static bool CanOpenDatabase(string statePath, string? encryptionKey)
    {
        if (!File.Exists(statePath))
        {
            return false;
        }

        try
        {
            using var connection = OpenConnectionForPath(statePath, encryptionKey);
            ExecuteNonQuery(connection, "SELECT count(*) FROM sqlite_master;");
            return true;
        }
        catch (SqliteException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static void ExecuteNonQuery(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void DeleteSqliteFileSet(string statePath)
    {
        if (File.Exists(statePath))
        {
            File.Delete(statePath);
        }

        DeleteSqliteSidecars(statePath);
    }

    private static void SecureDeleteSqliteFileSet(string statePath)
    {
        SecureDeleteFile(statePath);
        SecureDeleteSqliteSidecars(statePath);
    }

    private static void SecureDeleteSqliteSidecars(string statePath)
    {
        SecureDeleteFile(statePath + "-wal");
        SecureDeleteFile(statePath + "-shm");
    }

    private static void SecureDeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.WriteThrough | FileOptions.SequentialScan);
            var zeroBuffer = new byte[64 * 1024];
            var remaining = stream.Length;
            stream.Position = 0;
            while (remaining > 0)
            {
                var count = (int)Math.Min(zeroBuffer.Length, remaining);
                stream.Write(zeroBuffer, 0, count);
                remaining -= count;
            }

            stream.Flush(flushToDisk: true);
        }
        catch (IOException)
        {
            // Deletion below is still preferable when the platform does not permit in-place overwrite.
        }
        catch (UnauthorizedAccessException)
        {
            // Preserve the original deletion error if the file cannot be removed either.
        }

        File.Delete(path);
    }

    private static void DeleteSqliteSidecars(string statePath)
    {
        foreach (var sidecarPath in new[] { statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(sidecarPath))
            {
                File.Delete(sidecarPath);
            }
        }
    }

    public void Dispose()
    {
        // Connections are short-lived and returned to the provider pool after each operation.
    }

}

public sealed record SqliteSessionStoreOptions(string StatePath, string? EncryptionKey = null);
