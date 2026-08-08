using System.Diagnostics;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Globalization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.Membership;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed partial class SqliteSessionStore :
    ILocalSessionStore,
    ITransportOutboxRepository,
    IOneToOneConversationOpenRepository,
    IMessageSyncRepository,
    IMembershipTrustRepository,
    IDisposable
{
    private const int PhysicalSchemaVersion = 13;
    private const int DeepApplicationId = 0x44454550;
    private const int MaximumSchemaDefinitionLength = 16 * 1024;
    private const int ReplayPruneBatchSize = 256;
    private const string ReadCursorSettingPrefix = "sync.read-cursor.";
    private const string MessagePayloadProjection = "json_set(payload_json, '$.deliveryState', delivery_state, '$.readAt', read_at)";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private static readonly ConcurrentDictionary<string, object> InitializationGates =
        new(StringComparer.OrdinalIgnoreCase);
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private readonly string _connectionString;
    private readonly string _canonicalStateIdentity;
    private readonly SemaphoreSlim _databaseGate = new(1, 1);
    private readonly Action<MembershipTrustCommitFaultPoint>? _membershipTrustFaultInjector;
    private int _disposed;

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
        : this(options, (Action<MembershipTrustCommitFaultPoint>?)null)
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
        statePath = Path.GetFullPath(statePath);

        var directory = Path.GetDirectoryName(statePath);
        var encryptionKey = options.GetEncryptionKeyForStore();
        encryptionKey = string.IsNullOrWhiteSpace(encryptionKey) ? null : encryptionKey;
        _membershipTrustFaultInjector = faultInjector;
        _connectionString = ConnectionStringFor(
            statePath,
            encryptionKey,
            SqliteOpenMode.ReadWrite,
            pooling: true);

        var initializationGate = InitializationGates.GetOrAdd(statePath, static _ => new object());
        lock (initializationGate)
        {
            var mainExists = File.Exists(statePath);
            var walExists = File.Exists(statePath + "-wal");
            var shmExists = File.Exists(statePath + "-shm");
            var isFresh = !mainExists && !walExists && !shmExists;

            if (!isFresh && !mainExists)
            {
                throw ResetRequired(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "Local state is incomplete. Reset local data before retrying.");
            }
            if (mainExists && new FileInfo(statePath).Length == 0)
            {
                throw ResetRequired(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "Local state is empty or damaged. Reset local data before retrying.");
            }

            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            try
            {
                InitializeSchema(
                    statePath,
                    encryptionKey,
                    isFresh,
                    immutableExisting: !isFresh && !walExists && !shmExists);
            }
            catch (LocalStateResetRequiredException)
            {
                throw;
            }
            catch (InvalidDataException exception)
            {
                throw ResetRequired(
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    "Local state does not match the current schema. Reset local data before retrying.",
                    exception);
            }
            catch (SqliteException exception) when (!MustPropagateWithoutReset(exception))
            {
                var reason = PrimarySqliteErrorCode(exception) == 26
                    ? LocalStateResetRequiredReason.UnreadableOrWrongKey
                    : LocalStateResetRequiredReason.InvalidCurrentSchema;
                var message = reason == LocalStateResetRequiredReason.UnreadableOrWrongKey
                    ? "Local state is unreadable or cannot be opened with the configured key. Reset local data before retrying."
                    : "Local state is corrupt or incompatible. Reset local data before retrying.";
                throw ResetRequired(reason, message, exception);
            }

            using var poolIdentity = new SqliteConnection(_connectionString);
            SqliteConnection.ClearPool(poolIdentity);
        }
        _canonicalStateIdentity = SqliteStateFileIdentity.Resolve(statePath);
    }

    internal string CanonicalStateIdentity => _canonicalStateIdentity;

    public async Task UpsertAsync(Conversation conversation, CancellationToken cancellationToken = default)
    {
        EnsureSupportedConversationKind(conversation.Kind);
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
        return payload is null ? null : DeserializeConversation(payload);
    }

    async IAsyncEnumerable<Conversation> IConversationRepository.ListAsync([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM conversations ORDER BY updated_at DESC;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken).ConfigureAwait(false))
        {
            yield return DeserializeConversation(payload);
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
                    conversationItems.Add(DeserializeConversation(reader.GetString(0)));
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
                : DeserializeConversation(metadata.ConversationPayload);
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

            var history = await ValidateMembershipTrustHistoryAsync(
                connection,
                transaction,
                record.OpaqueProfileKey,
                record.Domain,
                record.Revision,
                cancellationToken).ConfigureAwait(false);
            if (history.Snapshot.Result == MembershipTrustReadResult.Corrupt)
            {
                transaction.Rollback();
                return MembershipTrustCommitResult.Corrupt;
            }

            var currentHead = history.Snapshot.Head?.Revision;
            var currentHistoryBytes = history.HistoryBytes;
            var existing = history.SelectedRecord;
            if (existing is not null)
            {
                transaction.Rollback();
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
            if (!MembershipTrustRepositoryValidation.HasValidLinkage(
                    record,
                    history.Snapshot.Head))
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
            var history = await ValidateMembershipTrustHistoryAsync(
                connection,
                transaction,
                opaqueProfileKey,
                domain,
                selectedRevision: null,
                cancellationToken).ConfigureAwait(false);
            return history.Snapshot;
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

    private readonly record struct MembershipTrustHistoryValidation(
        MembershipTrustReadSnapshot Snapshot,
        MembershipTrustRecord? SelectedRecord,
        long HistoryBytes);

    private static async Task<MembershipTrustHistoryValidation>
        ValidateMembershipTrustHistoryAsync(
            SqliteConnection connection,
            SqliteTransaction transaction,
            string opaqueProfileKey,
            MembershipTrustDomain domain,
            ulong? selectedRevision,
            CancellationToken cancellationToken)
    {
        ulong headRevision;
        byte[] headDigest;
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
            await using var reader = await head.ExecuteReaderAsync(
                cancellationToken).ConfigureAwait(false);
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
                var snapshot = exists is null or DBNull
                    ? MembershipTrustRepositoryValidation.Missing()
                    : MembershipTrustRepositoryValidation.Corrupt();
                return new MembershipTrustHistoryValidation(snapshot, null, 0);
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
                    MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryBytes)
            {
                return new MembershipTrustHistoryValidation(
                    MembershipTrustRepositoryValidation.Corrupt(),
                    null,
                    0);
            }
            headRevision = checked((ulong)signedRevision);
        }

        if (headRevision >
            MembershipTrustRepositoryValidation.MaximumMembershipTrustHistoryRecords)
        {
            return new MembershipTrustHistoryValidation(
                MembershipTrustRepositoryValidation.Corrupt(),
                null,
                0);
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
            orphan.Parameters.AddWithValue("$head", checked((long)headRevision));
            var exists = await orphan.ExecuteScalarAsync(
                cancellationToken).ConfigureAwait(false);
            if (exists is not null and not DBNull)
            {
                return new MembershipTrustHistoryValidation(
                    MembershipTrustRepositoryValidation.Corrupt(),
                    null,
                    0);
            }
        }

        MembershipTrustRecord? current = null;
        MembershipTrustRecord? predecessor = null;
        MembershipTrustRecord? previous = null;
        MembershipTrustRecord? selected = null;
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
                    return new MembershipTrustHistoryValidation(
                        MembershipTrustRepositoryValidation.Corrupt(),
                        null,
                        0);
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
                    !MembershipTrustRepositoryValidation.HasValidLinkage(record, previous))
                {
                    return new MembershipTrustHistoryValidation(
                        MembershipTrustRepositoryValidation.Corrupt(),
                        null,
                        0);
                }
                if (record.Revision == headRevision - 1)
                {
                    predecessor = record;
                }
                if (record.Revision == selectedRevision)
                {
                    selected = record;
                }
                previous = record;
                current = record;
            }
        }

        if (current is null ||
            recordsRead != headRevision ||
            historyBytes != headHistoryBytes ||
            !headDigest.AsSpan().SequenceEqual(current.PayloadDigest))
        {
            return new MembershipTrustHistoryValidation(
                MembershipTrustRepositoryValidation.Corrupt(),
                null,
                0);
        }

        return new MembershipTrustHistoryValidation(
            new MembershipTrustReadSnapshot(
                MembershipTrustReadResult.Found,
                current,
                predecessor),
            selected,
            historyBytes);
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
                    SELECT version, revision, observed_at, length(digest), digest
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
                        Digest = ReadFixedProjectedBlob(
                            reader,
                            lengthOrdinal: 3,
                            blobOrdinal: 4,
                            MembershipLimits.HashLength)
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
                SELECT version, revision, observed_at, length(digest), digest
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
                Digest = ReadFixedProjectedBlob(
                    reader,
                    lengthOrdinal: 3,
                    blobOrdinal: 4,
                    MembershipLimits.HashLength)
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
            EnableSqliteSecureDelete(connection);

            using var transaction = connection.BeginTransaction();
            ValidateTransportOutboxSchema(connection, transaction);
            foreach (var table in new[]
                     {
                         "mailbox_prepared_batch_targets", "mailbox_prepared_batches",
                         "logical_dispatch_plans",
                         "mailbox_replay_counters", "mailbox_credential_grants",
                         "mailbox_credential_epochs", "mailbox_credential_scopes",
                         "client_mailbox_coordinator_journal",
                         "client_mailbox_expired_quarantine", "client_mailbox_inbox",
                         "client_mailbox_traversal", "transport_outbox_attempts",
                         "transport_outbox_items", "group_state_outbox", "inbox_items",
                         "inbox_cursors", "incoming_message_notifications", "messages",
                         "groups", "conversations", "contacts", "replay_claims", "settings"
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

    private static void InitializeSchema(
        string statePath,
        string? encryptionKey,
        bool isFresh,
        bool immutableExisting)
    {
        if (!isFresh && !immutableExisting)
        {
            ValidateExistingSchemaReadOnly(statePath, encryptionKey);
            return;
        }

        var preflightConnectionString = ConnectionStringFor(
            statePath,
            encryptionKey,
            isFresh ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadOnly,
            pooling: false,
            immutable: immutableExisting);
        using var connection = new SqliteConnection(preflightConnectionString);
        connection.Open();
        ConfigurePreflightConnection(connection, existing: !isFresh);

        if (!isFresh)
        {
            ValidateCurrentSchema(connection, transaction: null);
            return;
        }

        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
                CREATE TABLE conversations (
                    id TEXT PRIMARY KEY,
                    updated_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE contacts (
                    id TEXT PRIMARY KEY,
                    sort_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE groups (
                    id TEXT PRIMARY KEY,
                    sort_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE messages (
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

                CREATE TABLE logical_dispatch_plans (
                    owner_digest BLOB NOT NULL CHECK(length(owner_digest) = 32),
                    semantic_operation_id BLOB NOT NULL CHECK(length(semantic_operation_id) = 16),
                    plan_digest BLOB NOT NULL CHECK(length(plan_digest) = 32),
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(owner_digest, semantic_operation_id)
                );

                CREATE TABLE incoming_message_notifications (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
                );

                CREATE TABLE settings (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE replay_claims (
                    sender_session_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    envelope_digest TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(sender_session_id, message_id)
                );

                CREATE TABLE inbox_cursors (
                    account_session_id TEXT NOT NULL,
                    namespace INTEGER NOT NULL,
                    cursor TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(account_session_id, namespace)
                );

                CREATE TABLE inbox_items (
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

                CREATE TABLE group_state_outbox (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    operation_id TEXT NOT NULL UNIQUE,
                    group_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    group_payload TEXT NOT NULL,
                    recipients_json TEXT NOT NULL
                );

                CREATE TABLE membership_trust_records (
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

                CREATE TABLE membership_trust_heads (
                    profile_key TEXT NOT NULL,
                    domain INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    payload_digest BLOB NOT NULL,
                    history_bytes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(profile_key, domain)
                );

                CREATE TABLE membership_trust_clock (
                    profile_key TEXT NOT NULL PRIMARY KEY,
                    version INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    observed_at INTEGER NOT NULL,
                    digest BLOB NOT NULL
                );

                CREATE TABLE client_mailbox_traversal (
                    scope BLOB PRIMARY KEY NOT NULL CHECK(length(scope) = 32),
                    after_cursor BLOB NOT NULL CHECK(length(after_cursor) = 8),
                    continuation_token BLOB NOT NULL
                );

                CREATE TABLE client_mailbox_inbox (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0, 1)),
                    PRIMARY KEY(scope, cursor),
                    UNIQUE(scope, digest)
                );

                CREATE TABLE client_mailbox_expired_quarantine (
                    scope BLOB NOT NULL CHECK(length(scope) = 32),
                    cursor BLOB NOT NULL CHECK(length(cursor) = 8),
                    digest BLOB NOT NULL CHECK(length(digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    canonical_envelope BLOB NOT NULL,
                    quarantined_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    PRIMARY KEY(scope, cursor, digest)
                );

                CREATE TABLE client_mailbox_coordinator_journal (
                    installation_scope BLOB NOT NULL CHECK(length(installation_scope) = 32),
                    statement_key BLOB NOT NULL CHECK(length(statement_key) = 32),
                    statement_digest BLOB NOT NULL CHECK(length(statement_digest) = 32),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    PRIMARY KEY(installation_scope, statement_key)
                );

                CREATE TABLE mailbox_credential_scopes (
                    scope_id BLOB NOT NULL PRIMARY KEY CHECK(length(scope_id) = 32),
                    account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                    scope_kind INTEGER NOT NULL CHECK(scope_kind IN (1, 2, 3)),
                    subject_id BLOB NOT NULL CHECK(length(subject_id) = 32),
                    issuer_context BLOB NOT NULL CHECK(length(issuer_context) = 32),
                    network_id BLOB NOT NULL CHECK(length(network_id) = 16),
                    authority_policy_digest BLOB NOT NULL
                        CHECK(length(authority_policy_digest) = 32),
                    holder_key BLOB NOT NULL CHECK(length(holder_key) = 32),
                    generation BLOB NOT NULL CHECK(length(generation) = 32),
                    active_epoch BLOB NOT NULL CHECK(length(active_epoch) = 8),
                    group_membership_commitment BLOB NULL
                        CHECK(group_membership_commitment IS NULL OR length(group_membership_commitment) = 32),
                    UNIQUE(account_scope, scope_kind, subject_id, issuer_context)
                );

                CREATE TABLE mailbox_credential_epochs (
                    scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                    epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                    not_before BLOB NOT NULL CHECK(length(not_before) = 8),
                    expires_at BLOB NOT NULL CHECK(length(expires_at) = 8),
                    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id) = 32),
                    placement_id BLOB NOT NULL CHECK(length(placement_id) = 32),
                    placement_commitment BLOB NOT NULL CHECK(length(placement_commitment) = 32),
                    membership_commitment BLOB NOT NULL CHECK(length(membership_commitment) = 32),
                    first_replica_id BLOB NOT NULL CHECK(length(first_replica_id) = 32),
                    first_replica_key BLOB NOT NULL CHECK(length(first_replica_key) = 32),
                    second_replica_id BLOB NOT NULL CHECK(length(second_replica_id) = 32),
                    second_replica_key BLOB NOT NULL CHECK(length(second_replica_key) = 32),
                    PRIMARY KEY(scope_id, epoch),
                    FOREIGN KEY(scope_id) REFERENCES mailbox_credential_scopes(scope_id) ON DELETE CASCADE
                );

                CREATE TABLE mailbox_credential_grants (
                    scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                    epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                    role INTEGER NOT NULL CHECK(role IN (1, 2)),
                    issuer_context BLOB NOT NULL CHECK(length(issuer_context) = 32),
                    grant_digest BLOB NOT NULL CHECK(length(grant_digest) = 32),
                    issuer_key BLOB NOT NULL CHECK(length(issuer_key) = 32),
                    serial BLOB NOT NULL,
                    canonical_grant BLOB NOT NULL,
                    PRIMARY KEY(scope_id, epoch, role),
                    UNIQUE(issuer_key, serial),
                    FOREIGN KEY(scope_id, epoch)
                        REFERENCES mailbox_credential_epochs(scope_id, epoch) ON DELETE CASCADE
                );

                CREATE TABLE mailbox_replay_counters (
                    scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                    epoch BLOB NOT NULL CHECK(length(epoch) = 8),
                    grant_digest BLOB NOT NULL CHECK(length(grant_digest) = 32),
                    next_counter BLOB NOT NULL CHECK(length(next_counter) = 8),
                    PRIMARY KEY(scope_id, epoch, grant_digest)
                );

                CREATE TABLE mailbox_prepared_batches (
                    account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                    parent_operation_id BLOB NOT NULL CHECK(length(parent_operation_id) = 16),
                    semantic_operation_id BLOB NOT NULL CHECK(length(semantic_operation_id) = 16),
                    plan_digest BLOB NOT NULL CHECK(length(plan_digest) = 32),
                    target_count INTEGER NOT NULL CHECK(target_count BETWEEN 1 AND 2048),
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(account_scope, parent_operation_id),
                    UNIQUE(account_scope, semantic_operation_id)
                );

                CREATE TABLE mailbox_prepared_batch_targets (
                    account_scope BLOB NOT NULL CHECK(length(account_scope) = 32),
                    parent_operation_id BLOB NOT NULL CHECK(length(parent_operation_id) = 16),
                    target_ordinal INTEGER NOT NULL CHECK(target_ordinal BETWEEN 0 AND 2047),
                    target_operation_id BLOB NOT NULL CHECK(length(target_operation_id) = 16),
                    scope_id BLOB NOT NULL CHECK(length(scope_id) = 32),
                    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                    replay_counter BLOB NOT NULL CHECK(length(replay_counter) = 8),
                    PRIMARY KEY(account_scope, parent_operation_id, target_ordinal),
                    UNIQUE(account_scope, target_operation_id),
                    FOREIGN KEY(account_scope, parent_operation_id)
                        REFERENCES mailbox_prepared_batches(account_scope, parent_operation_id)
                        ON DELETE CASCADE
                );

                CREATE TABLE transport_outbox_items (
                    account_scope BLOB NOT NULL,
                    logical_id BLOB NOT NULL,
                    dedup_material BLOB NOT NULL,
                    ciphertext_bundle BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    not_before INTEGER NOT NULL,
                    state INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    transition_source INTEGER NOT NULL,
                    transition_reason INTEGER NOT NULL,
                    transitioned_at INTEGER NOT NULL,
                    last_transition_state INTEGER NOT NULL,
                    last_attempt_id BLOB NULL,
                    last_retry_not_before INTEGER NULL,
                    acknowledgement_evidence BLOB NULL,
                    acknowledged_at INTEGER NULL,
                    PRIMARY KEY(account_scope, logical_id)
                );

                CREATE TABLE transport_outbox_attempts (
                    account_scope BLOB NOT NULL,
                    logical_id BLOB NOT NULL,
                    attempt_id BLOB NOT NULL,
                    state INTEGER NOT NULL,
                    transition_source INTEGER NOT NULL,
                    transition_reason INTEGER NOT NULL,
                    occurred_at INTEGER NOT NULL,
                    evidence BLOB NOT NULL,
                    PRIMARY KEY(account_scope, logical_id, attempt_id),
                    FOREIGN KEY(account_scope, logical_id)
                        REFERENCES transport_outbox_items(account_scope, logical_id) ON DELETE CASCADE
                );

                CREATE INDEX idx_messages_conversation_created
                    ON messages(conversation_id, created_at);

                CREATE INDEX idx_messages_conversation_created_id
                    ON messages(conversation_id, created_at DESC, id DESC);

                CREATE INDEX idx_messages_unread
                    ON messages(conversation_id, direction, delivery_state, created_at);

                CREATE INDEX idx_messages_server_hash
                    ON messages(conversation_id, server_hash)
                    WHERE server_hash IS NOT NULL;

                CREATE INDEX idx_messages_self_echo
                    ON messages(conversation_id, sender_session_id, recipient_session_id, direction, self_echo_key);

                CREATE INDEX idx_messages_pending_outgoing
                    ON messages(sender_session_id, direction, delivery_state, created_at, id);

                CREATE INDEX idx_replay_claims_expires_at
                    ON replay_claims(expires_at);

                CREATE INDEX idx_inbox_items_staged
                    ON inbox_items(account_session_id, namespace, item_kind, sequence);

                CREATE INDEX idx_inbox_items_decoded_route
                    ON inbox_items(account_session_id, namespace, item_kind, route_key, sequence);

                CREATE INDEX idx_inbox_items_logical_message
                    ON inbox_items(sender_session_id, message_id, sequence);

                CREATE INDEX idx_group_state_outbox_order
                    ON group_state_outbox(group_id, revision, sequence);

                CREATE INDEX idx_membership_trust_records_head
                    ON membership_trust_records(profile_key, domain, revision);

                CREATE INDEX idx_client_mailbox_inbox_scope_expiry
                    ON client_mailbox_inbox(scope, expires_at);

                CREATE INDEX idx_client_mailbox_inbox_expiry_scope
                    ON client_mailbox_inbox(expires_at, scope);

                CREATE INDEX idx_client_mailbox_inbox_scope_ack_cursor
                    ON client_mailbox_inbox(scope, acknowledged, cursor);

                CREATE INDEX idx_client_mailbox_quarantine_age
                    ON client_mailbox_expired_quarantine(quarantined_at, expires_at, scope);

                CREATE INDEX idx_client_mailbox_journal_scope_expiry
                    ON client_mailbox_coordinator_journal(installation_scope, expires_at);

                CREATE INDEX idx_mailbox_credential_scope_lookup
                    ON mailbox_credential_scopes(account_scope, scope_kind, subject_id, issuer_context);

                CREATE INDEX idx_mailbox_credential_epoch_expiry
                    ON mailbox_credential_epochs(scope_id, expires_at);

                CREATE INDEX idx_mailbox_prepared_targets_scope
                    ON mailbox_prepared_batch_targets(scope_id, account_scope, parent_operation_id);

                CREATE INDEX idx_transport_outbox_ready
                    ON transport_outbox_items(account_scope, state, not_before, expires_at, created_at);

                CREATE INDEX idx_transport_outbox_expiry
                    ON transport_outbox_items(account_scope, expires_at, state);
                """;
        command.ExecuteNonQuery();

        using var markVersionCommand = connection.CreateCommand();
        markVersionCommand.Transaction = transaction;
        markVersionCommand.CommandText = $"""
            PRAGMA application_id={DeepApplicationId};
            PRAGMA user_version={PhysicalSchemaVersion};
            """;
        markVersionCommand.ExecuteNonQuery();
        ValidateCurrentSchema(connection, transaction);
        transaction.Commit();

        using var journalCommand = connection.CreateCommand();
        journalCommand.CommandText = "PRAGMA journal_mode=WAL;";
        journalCommand.ExecuteNonQuery();
    }

    private static void ValidateExistingSchemaReadOnly(
        string statePath,
        string? encryptionKey)
    {
        var connectionString = ConnectionStringFor(
            statePath,
            encryptionKey,
            SqliteOpenMode.ReadOnly,
            pooling: false);
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        ConfigurePreflightConnection(connection, existing: true);
        using var transaction = connection.BeginTransaction(deferred: true);
        ValidateCurrentSchema(connection, transaction);
        transaction.Commit();
    }

    private sealed record ExpectedSchemaColumn(
        string Name,
        string Type,
        int NotNull,
        string? DefaultValue,
        int PrimaryKey,
        int Hidden = 0);

    private sealed record ExpectedSchemaIndex(
        string Table,
        bool Unique,
        string Origin,
        bool Partial,
        IReadOnlyList<(string Name, bool Descending)> Columns,
        string? NormalizedSql = null);

    private sealed record ExpectedForeignKey(
        int Id,
        int Sequence,
        string TargetTable,
        string From,
        string To,
        string OnUpdate,
        string OnDelete,
        string Match);

    private static void ValidateCurrentSchema(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        var version = ReadPragmaInt(connection, transaction, "user_version");
        if (version != PhysicalSchemaVersion)
        {
            throw ResetRequired(
                LocalStateResetRequiredReason.UnsupportedVersion,
                $"Local state schema version {version} is unsupported; version {PhysicalSchemaVersion} is required. Reset local data before retrying.");
        }
        if (ReadPragmaInt(connection, transaction, "application_id") != DeepApplicationId)
        {
            throw new InvalidDataException("Local state has an invalid application identifier.");
        }

        ValidateDatabaseIntegrity(connection, transaction);
        ValidateExactSchemaObjects(connection, transaction);

        var tables = ExpectedSchemaTables();
        foreach (var table in tables)
        {
            ValidateTableColumns(connection, transaction, table.Key, table.Value);
        }
        ValidateForeignKeys(connection, transaction, tables.Keys);
        ValidateIndexes(connection, transaction, tables.Keys);
        ValidateAutoincrementTables(connection, transaction);
    }

    private static int ReadPragmaInt(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string pragma)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA {pragma};";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    private static void ValidateDatabaseIntegrity(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA integrity_check;";
            using var reader = command.ExecuteReader();
            if (!reader.Read()
                || !string.Equals(reader.GetString(0), "ok", StringComparison.Ordinal)
                || reader.Read())
            {
                throw new InvalidDataException("Local state failed SQLite integrity validation.");
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "PRAGMA foreign_key_check;";
            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                throw new InvalidDataException("Local state contains foreign-key violations.");
            }
        }
    }

    private static void ValidateExactSchemaObjects(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        var expected = new Dictionary<string, (string Type, string Table)>(StringComparer.Ordinal);
        foreach (var table in ExpectedSchemaTables().Keys)
        {
            expected.Add(table, ("table", table));
        }
        foreach (var index in ExpectedSchemaIndexes())
        {
            if (!index.Key.StartsWith("sqlite_autoindex_", StringComparison.Ordinal))
            {
                expected.Add(index.Key, ("index", index.Value.Table));
            }
        }

        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT type, name, tbl_name
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name;
                """;
            using var reader = command.ExecuteReader();
            var actual = new Dictionary<string, (string Type, string Table)>(StringComparer.Ordinal);
            while (reader.Read())
            {
                actual.Add(reader.GetString(1), (reader.GetString(0), reader.GetString(2)));
            }
            if (actual.Count != expected.Count
                || expected.Any(item =>
                    !actual.TryGetValue(item.Key, out var value)
                    || value != item.Value))
            {
                throw new InvalidDataException("Local state has an unexpected or missing schema object.");
            }
        }

        var expectedInternals = ExpectedSchemaIndexes()
            .Where(static item => item.Key.StartsWith("sqlite_autoindex_", StringComparison.Ordinal))
            .ToDictionary(
                static item => item.Key,
                static item => ("index", item.Value.Table),
                StringComparer.Ordinal);
        expectedInternals.Add("sqlite_sequence", ("table", "sqlite_sequence"));

        using var internals = connection.CreateCommand();
        internals.Transaction = transaction;
        internals.CommandText = """
            SELECT type, name, tbl_name
            FROM sqlite_schema
            WHERE name LIKE 'sqlite_%'
            ORDER BY type, name;
            """;
        using var internalReader = internals.ExecuteReader();
        var actualInternals =
            new Dictionary<string, (string Type, string Table)>(StringComparer.Ordinal);
        while (internalReader.Read())
        {
            actualInternals.Add(
                internalReader.GetString(1),
                (internalReader.GetString(0), internalReader.GetString(2)));
        }
        if (actualInternals.Count != expectedInternals.Count
            || expectedInternals.Any(item =>
                !actualInternals.TryGetValue(item.Key, out var value)
                || value != item.Value))
        {
            throw new InvalidDataException("Local state has unexpected SQLite internal objects.");
        }
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<ExpectedSchemaColumn>>
        ExpectedSchemaTables() =>
        new Dictionary<string, IReadOnlyList<ExpectedSchemaColumn>>(StringComparer.Ordinal)
        {
            ["conversations"] =
            [
                new("id", "TEXT", 0, null, 1),
                new("updated_at", "INTEGER", 1, null, 0),
                new("payload_json", "TEXT", 1, null, 0)
            ],
            ["contacts"] =
            [
                new("id", "TEXT", 0, null, 1),
                new("sort_name", "TEXT", 1, null, 0),
                new("payload_json", "TEXT", 1, null, 0)
            ],
            ["groups"] =
            [
                new("id", "TEXT", 0, null, 1),
                new("sort_name", "TEXT", 1, null, 0),
                new("payload_json", "TEXT", 1, null, 0)
            ],
            ["messages"] =
            [
                new("id", "TEXT", 0, null, 1),
                new("conversation_id", "TEXT", 1, null, 0),
                new("created_at", "INTEGER", 1, null, 0),
                new("direction", "INTEGER", 1, null, 0),
                new("delivery_state", "INTEGER", 1, null, 0),
                new("read_at", "TEXT", 0, null, 0),
                new("expires_at", "TEXT", 0, null, 0),
                new("sender_session_id", "TEXT", 0, null, 0),
                new("recipient_session_id", "TEXT", 0, null, 0),
                new("server_hash", "TEXT", 0, null, 0),
                new("self_echo_key", "TEXT", 0, null, 0),
                new("payload_json", "TEXT", 1, null, 0)
            ],
            ["logical_dispatch_plans"] =
            [
                new("owner_digest", "BLOB", 1, null, 1),
                new("semantic_operation_id", "BLOB", 1, null, 2),
                new("plan_digest", "BLOB", 1, null, 0),
                new("created_at", "INTEGER", 1, null, 0)
            ],
            ["incoming_message_notifications"] =
            [
                new("sequence", "INTEGER", 0, null, 1),
                new("message_id", "TEXT", 1, null, 0)
            ],
            ["settings"] =
            [
                new("key", "TEXT", 0, null, 1),
                new("payload_json", "TEXT", 1, null, 0)
            ],
            ["replay_claims"] =
            [
                new("sender_session_id", "TEXT", 1, null, 1),
                new("message_id", "TEXT", 1, null, 2),
                new("envelope_digest", "TEXT", 1, null, 0),
                new("expires_at", "INTEGER", 1, null, 0)
            ],
            ["inbox_cursors"] =
            [
                new("account_session_id", "TEXT", 1, null, 1),
                new("namespace", "INTEGER", 1, null, 2),
                new("cursor", "TEXT", 1, null, 0),
                new("updated_at", "INTEGER", 1, null, 0)
            ],
            ["inbox_items"] =
            [
                new("sequence", "INTEGER", 0, null, 1),
                new("account_session_id", "TEXT", 1, null, 0),
                new("namespace", "INTEGER", 1, null, 0),
                new("server_hash", "TEXT", 1, null, 0),
                new("storage_timestamp", "INTEGER", 1, null, 0),
                new("wire_payload", "TEXT", 1, null, 0),
                new("wire_digest", "TEXT", 1, null, 0),
                new("item_kind", "INTEGER", 0, null, 0),
                new("route_key", "TEXT", 0, null, 0),
                new("sender_session_id", "TEXT", 0, null, 0),
                new("message_id", "TEXT", 0, null, 0),
                new("envelope_digest", "TEXT", 0, null, 0),
                new("protocol_expires_at", "INTEGER", 0, null, 0)
            ],
            ["group_state_outbox"] =
            [
                new("sequence", "INTEGER", 0, null, 1),
                new("operation_id", "TEXT", 1, null, 0),
                new("group_id", "TEXT", 1, null, 0),
                new("revision", "INTEGER", 1, null, 0),
                new("updated_at", "INTEGER", 1, null, 0),
                new("group_payload", "TEXT", 1, null, 0),
                new("recipients_json", "TEXT", 1, null, 0)
            ],
            ["membership_trust_records"] =
            [
                new("profile_key", "TEXT", 1, null, 1),
                new("domain", "INTEGER", 1, null, 2),
                new("revision", "INTEGER", 1, null, 3),
                new("version", "INTEGER", 1, "2", 0),
                new("artifact_kind", "INTEGER", 1, "1", 0),
                new("sequence", "INTEGER", 1, null, 0),
                new("previous_sequence", "INTEGER", 1, null, 0),
                new("previous_hash", "BLOB", 1, null, 0),
                new("envelope", "BLOB", 1, null, 0),
                new("payload_digest", "BLOB", 1, null, 0),
                new("canonical_hash", "BLOB", 1, null, 0),
                new("profile_binding_hash", "BLOB", 1, null, 0),
                new("signing_authority", "BLOB", 1, "X''", 0),
                new("revoked_delegation_hashes", "BLOB", 1, "X''", 0),
                new("state", "INTEGER", 1, null, 0),
                new("observed_at", "INTEGER", 1, null, 0),
                new("valid_from", "INTEGER", 1, "0", 0),
                new("valid_until", "INTEGER", 1, null, 0)
            ],
            ["membership_trust_heads"] =
            [
                new("profile_key", "TEXT", 1, null, 1),
                new("domain", "INTEGER", 1, null, 2),
                new("revision", "INTEGER", 1, null, 0),
                new("payload_digest", "BLOB", 1, null, 0),
                new("history_bytes", "INTEGER", 1, "0", 0)
            ],
            ["membership_trust_clock"] =
            [
                new("profile_key", "TEXT", 1, null, 1),
                new("version", "INTEGER", 1, null, 0),
                new("revision", "INTEGER", 1, null, 0),
                new("observed_at", "INTEGER", 1, null, 0),
                new("digest", "BLOB", 1, null, 0)
            ],
            ["client_mailbox_traversal"] =
            [
                new("scope", "BLOB", 1, null, 1),
                new("after_cursor", "BLOB", 1, null, 0),
                new("continuation_token", "BLOB", 1, null, 0)
            ],
            ["client_mailbox_inbox"] =
            [
                new("scope", "BLOB", 1, null, 1),
                new("cursor", "BLOB", 1, null, 2),
                new("digest", "BLOB", 1, null, 0),
                new("expires_at", "BLOB", 1, null, 0),
                new("canonical_envelope", "BLOB", 1, null, 0),
                new("acknowledged", "INTEGER", 1, null, 0)
            ],
            ["client_mailbox_expired_quarantine"] =
            [
                new("scope", "BLOB", 1, null, 1),
                new("cursor", "BLOB", 1, null, 2),
                new("digest", "BLOB", 1, null, 3),
                new("expires_at", "BLOB", 1, null, 0),
                new("canonical_envelope", "BLOB", 1, null, 0),
                new("quarantined_at", "INTEGER", 1, null, 0),
                new("reason", "TEXT", 1, null, 0)
            ],
            ["client_mailbox_coordinator_journal"] =
            [
                new("installation_scope", "BLOB", 1, null, 1),
                new("statement_key", "BLOB", 1, null, 2),
                new("statement_digest", "BLOB", 1, null, 0),
                new("expires_at", "BLOB", 1, null, 0)
            ],
            ["mailbox_credential_scopes"] =
            [
                new("scope_id", "BLOB", 1, null, 1),
                new("account_scope", "BLOB", 1, null, 0),
                new("scope_kind", "INTEGER", 1, null, 0),
                new("subject_id", "BLOB", 1, null, 0),
                new("issuer_context", "BLOB", 1, null, 0),
                new("network_id", "BLOB", 1, null, 0),
                new("authority_policy_digest", "BLOB", 1, null, 0),
                new("holder_key", "BLOB", 1, null, 0),
                new("generation", "BLOB", 1, null, 0),
                new("active_epoch", "BLOB", 1, null, 0),
                new("group_membership_commitment", "BLOB", 0, null, 0)
            ],
            ["mailbox_credential_epochs"] =
            [
                new("scope_id", "BLOB", 1, null, 1),
                new("epoch", "BLOB", 1, null, 2),
                new("not_before", "BLOB", 1, null, 0),
                new("expires_at", "BLOB", 1, null, 0),
                new("mailbox_id", "BLOB", 1, null, 0),
                new("placement_id", "BLOB", 1, null, 0),
                new("placement_commitment", "BLOB", 1, null, 0),
                new("membership_commitment", "BLOB", 1, null, 0),
                new("first_replica_id", "BLOB", 1, null, 0),
                new("first_replica_key", "BLOB", 1, null, 0),
                new("second_replica_id", "BLOB", 1, null, 0),
                new("second_replica_key", "BLOB", 1, null, 0)
            ],
            ["mailbox_credential_grants"] =
            [
                new("scope_id", "BLOB", 1, null, 1),
                new("epoch", "BLOB", 1, null, 2),
                new("role", "INTEGER", 1, null, 3),
                new("issuer_context", "BLOB", 1, null, 0),
                new("grant_digest", "BLOB", 1, null, 0),
                new("issuer_key", "BLOB", 1, null, 0),
                new("serial", "BLOB", 1, null, 0),
                new("canonical_grant", "BLOB", 1, null, 0)
            ],
            ["mailbox_replay_counters"] =
            [
                new("scope_id", "BLOB", 1, null, 1),
                new("epoch", "BLOB", 1, null, 2),
                new("grant_digest", "BLOB", 1, null, 3),
                new("next_counter", "BLOB", 1, null, 0)
            ],
            ["mailbox_prepared_batches"] =
            [
                new("account_scope", "BLOB", 1, null, 1),
                new("parent_operation_id", "BLOB", 1, null, 2),
                new("semantic_operation_id", "BLOB", 1, null, 0),
                new("plan_digest", "BLOB", 1, null, 0),
                new("target_count", "INTEGER", 1, null, 0),
                new("created_at", "INTEGER", 1, null, 0)
            ],
            ["mailbox_prepared_batch_targets"] =
            [
                new("account_scope", "BLOB", 1, null, 1),
                new("parent_operation_id", "BLOB", 1, null, 2),
                new("target_ordinal", "INTEGER", 1, null, 3),
                new("target_operation_id", "BLOB", 1, null, 0),
                new("scope_id", "BLOB", 1, null, 0),
                new("request_digest", "BLOB", 1, null, 0),
                new("replay_counter", "BLOB", 1, null, 0)
            ],
            ["transport_outbox_items"] =
            [
                new("account_scope", "BLOB", 1, null, 1),
                new("logical_id", "BLOB", 1, null, 2),
                new("dedup_material", "BLOB", 1, null, 0),
                new("ciphertext_bundle", "BLOB", 1, null, 0),
                new("created_at", "INTEGER", 1, null, 0),
                new("expires_at", "INTEGER", 1, null, 0),
                new("not_before", "INTEGER", 1, null, 0),
                new("state", "INTEGER", 1, null, 0),
                new("revision", "INTEGER", 1, null, 0),
                new("transition_source", "INTEGER", 1, null, 0),
                new("transition_reason", "INTEGER", 1, null, 0),
                new("transitioned_at", "INTEGER", 1, null, 0),
                new("last_transition_state", "INTEGER", 1, null, 0),
                new("last_attempt_id", "BLOB", 0, null, 0),
                new("last_retry_not_before", "INTEGER", 0, null, 0),
                new("acknowledgement_evidence", "BLOB", 0, null, 0),
                new("acknowledged_at", "INTEGER", 0, null, 0)
            ],
            ["transport_outbox_attempts"] =
            [
                new("account_scope", "BLOB", 1, null, 1),
                new("logical_id", "BLOB", 1, null, 2),
                new("attempt_id", "BLOB", 1, null, 3),
                new("state", "INTEGER", 1, null, 0),
                new("transition_source", "INTEGER", 1, null, 0),
                new("transition_reason", "INTEGER", 1, null, 0),
                new("occurred_at", "INTEGER", 1, null, 0),
                new("evidence", "BLOB", 1, null, 0)
            ]
        };

    private static void ValidateTableColumns(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        IReadOnlyList<ExpectedSchemaColumn> expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_xinfo(\"{table}\");";
        using var reader = command.ExecuteReader();
        var ordinal = 0;
        while (reader.Read())
        {
            if (ordinal >= expected.Count)
            {
                throw new InvalidDataException($"Local state table {table} has extra columns.");
            }
            var column = expected[ordinal];
            var defaultValue = reader.IsDBNull(4) ? null : reader.GetString(4);
            if (reader.GetInt32(0) != ordinal
                || !string.Equals(reader.GetString(1), column.Name, StringComparison.Ordinal)
                || !string.Equals(reader.GetString(2), column.Type, StringComparison.Ordinal)
                || reader.GetInt32(3) != column.NotNull
                || !string.Equals(defaultValue, column.DefaultValue, StringComparison.Ordinal)
                || reader.GetInt32(5) != column.PrimaryKey
                || reader.GetInt32(6) != column.Hidden)
            {
                throw new InvalidDataException($"Local state table {table} has incompatible columns.");
            }
            ordinal++;
        }
        if (ordinal != expected.Count)
        {
            throw new InvalidDataException($"Local state table {table} is missing columns.");
        }
    }

    private static void ValidateForeignKeys(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        IEnumerable<string> tables)
    {
        var expected = new Dictionary<string, IReadOnlyList<ExpectedForeignKey>>(StringComparer.Ordinal)
        {
            ["incoming_message_notifications"] =
            [
                new(0, 0, "messages", "message_id", "id", "NO ACTION", "CASCADE", "NONE")
            ],
            ["transport_outbox_attempts"] =
            [
                new(0, 0, "transport_outbox_items", "account_scope", "account_scope", "NO ACTION", "CASCADE", "NONE"),
                new(0, 1, "transport_outbox_items", "logical_id", "logical_id", "NO ACTION", "CASCADE", "NONE")
            ],
            ["mailbox_credential_epochs"] =
            [
                new(0, 0, "mailbox_credential_scopes", "scope_id", "scope_id", "NO ACTION", "CASCADE", "NONE")
            ],
            ["mailbox_credential_grants"] =
            [
                new(0, 0, "mailbox_credential_epochs", "scope_id", "scope_id", "NO ACTION", "CASCADE", "NONE"),
                new(0, 1, "mailbox_credential_epochs", "epoch", "epoch", "NO ACTION", "CASCADE", "NONE")
            ],
            ["mailbox_prepared_batch_targets"] =
            [
                new(0, 0, "mailbox_prepared_batches", "account_scope", "account_scope", "NO ACTION", "CASCADE", "NONE"),
                new(0, 1, "mailbox_prepared_batches", "parent_operation_id", "parent_operation_id", "NO ACTION", "CASCADE", "NONE")
            ]
        };

        foreach (var table in tables)
        {
            var rows = expected.GetValueOrDefault(table) ?? [];
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"""
                SELECT id, seq, "table", "from", "to", "on_update", "on_delete", "match"
                FROM pragma_foreign_key_list('{table}')
                ORDER BY id, seq;
                """;
            using var reader = command.ExecuteReader();
            var ordinal = 0;
            while (reader.Read())
            {
                if (ordinal >= rows.Count)
                {
                    throw new InvalidDataException($"Local state table {table} has extra foreign keys.");
                }
                var row = rows[ordinal++];
                if (reader.GetInt32(0) != row.Id
                    || reader.GetInt32(1) != row.Sequence
                    || !string.Equals(reader.GetString(2), row.TargetTable, StringComparison.Ordinal)
                    || !string.Equals(reader.GetString(3), row.From, StringComparison.Ordinal)
                    || !string.Equals(reader.GetString(4), row.To, StringComparison.Ordinal)
                    || !string.Equals(reader.GetString(5), row.OnUpdate, StringComparison.Ordinal)
                    || !string.Equals(reader.GetString(6), row.OnDelete, StringComparison.Ordinal)
                    || !string.Equals(reader.GetString(7), row.Match, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"Local state table {table} has incompatible foreign keys.");
                }
            }
            if (ordinal != rows.Count)
            {
                throw new InvalidDataException($"Local state table {table} is missing foreign keys.");
            }
        }
    }

    private static IReadOnlyDictionary<string, ExpectedSchemaIndex> ExpectedSchemaIndexes()
    {
        static (string Name, bool Descending) Asc(string name) => (name, false);
        static (string Name, bool Descending) Desc(string name) => (name, true);
        return new Dictionary<string, ExpectedSchemaIndex>(StringComparer.Ordinal)
        {
            ["sqlite_autoindex_conversations_1"] = new("conversations", true, "pk", false, [Asc("id")]),
            ["sqlite_autoindex_contacts_1"] = new("contacts", true, "pk", false, [Asc("id")]),
            ["sqlite_autoindex_groups_1"] = new("groups", true, "pk", false, [Asc("id")]),
            ["sqlite_autoindex_messages_1"] = new("messages", true, "pk", false, [Asc("id")]),
            ["sqlite_autoindex_logical_dispatch_plans_1"] = new("logical_dispatch_plans", true, "pk", false, [Asc("owner_digest"), Asc("semantic_operation_id")]),
            ["sqlite_autoindex_incoming_message_notifications_1"] = new("incoming_message_notifications", true, "u", false, [Asc("message_id")]),
            ["sqlite_autoindex_settings_1"] = new("settings", true, "pk", false, [Asc("key")]),
            ["sqlite_autoindex_replay_claims_1"] = new("replay_claims", true, "pk", false, [Asc("sender_session_id"), Asc("message_id")]),
            ["sqlite_autoindex_inbox_cursors_1"] = new("inbox_cursors", true, "pk", false, [Asc("account_session_id"), Asc("namespace")]),
            ["sqlite_autoindex_inbox_items_1"] = new("inbox_items", true, "u", false, [Asc("account_session_id"), Asc("namespace"), Asc("server_hash")]),
            ["sqlite_autoindex_group_state_outbox_1"] = new("group_state_outbox", true, "u", false, [Asc("operation_id")]),
            ["sqlite_autoindex_membership_trust_records_1"] = new("membership_trust_records", true, "pk", false, [Asc("profile_key"), Asc("domain"), Asc("revision")]),
            ["sqlite_autoindex_membership_trust_heads_1"] = new("membership_trust_heads", true, "pk", false, [Asc("profile_key"), Asc("domain")]),
            ["sqlite_autoindex_membership_trust_clock_1"] = new("membership_trust_clock", true, "pk", false, [Asc("profile_key")]),
            ["sqlite_autoindex_client_mailbox_traversal_1"] = new("client_mailbox_traversal", true, "pk", false, [Asc("scope")]),
            ["sqlite_autoindex_client_mailbox_inbox_1"] = new("client_mailbox_inbox", true, "pk", false, [Asc("scope"), Asc("cursor")]),
            ["sqlite_autoindex_client_mailbox_inbox_2"] = new("client_mailbox_inbox", true, "u", false, [Asc("scope"), Asc("digest")]),
            ["sqlite_autoindex_client_mailbox_expired_quarantine_1"] = new("client_mailbox_expired_quarantine", true, "pk", false, [Asc("scope"), Asc("cursor"), Asc("digest")]),
            ["sqlite_autoindex_client_mailbox_coordinator_journal_1"] = new("client_mailbox_coordinator_journal", true, "pk", false, [Asc("installation_scope"), Asc("statement_key")]),
            ["sqlite_autoindex_mailbox_credential_scopes_1"] = new("mailbox_credential_scopes", true, "pk", false, [Asc("scope_id")]),
            ["sqlite_autoindex_mailbox_credential_scopes_2"] = new("mailbox_credential_scopes", true, "u", false, [Asc("account_scope"), Asc("scope_kind"), Asc("subject_id"), Asc("issuer_context")]),
            ["sqlite_autoindex_mailbox_credential_epochs_1"] = new("mailbox_credential_epochs", true, "pk", false, [Asc("scope_id"), Asc("epoch")]),
            ["sqlite_autoindex_mailbox_credential_grants_1"] = new("mailbox_credential_grants", true, "pk", false, [Asc("scope_id"), Asc("epoch"), Asc("role")]),
            ["sqlite_autoindex_mailbox_credential_grants_2"] = new("mailbox_credential_grants", true, "u", false, [Asc("issuer_key"), Asc("serial")]),
            ["sqlite_autoindex_mailbox_replay_counters_1"] = new("mailbox_replay_counters", true, "pk", false, [Asc("scope_id"), Asc("epoch"), Asc("grant_digest")]),
            ["sqlite_autoindex_mailbox_prepared_batches_1"] = new("mailbox_prepared_batches", true, "pk", false, [Asc("account_scope"), Asc("parent_operation_id")]),
            ["sqlite_autoindex_mailbox_prepared_batches_2"] = new("mailbox_prepared_batches", true, "u", false, [Asc("account_scope"), Asc("semantic_operation_id")]),
            ["sqlite_autoindex_mailbox_prepared_batch_targets_1"] = new("mailbox_prepared_batch_targets", true, "pk", false, [Asc("account_scope"), Asc("parent_operation_id"), Asc("target_ordinal")]),
            ["sqlite_autoindex_mailbox_prepared_batch_targets_2"] = new("mailbox_prepared_batch_targets", true, "u", false, [Asc("account_scope"), Asc("target_operation_id")]),
            ["sqlite_autoindex_transport_outbox_items_1"] = new("transport_outbox_items", true, "pk", false, [Asc("account_scope"), Asc("logical_id")]),
            ["sqlite_autoindex_transport_outbox_attempts_1"] = new("transport_outbox_attempts", true, "pk", false, [Asc("account_scope"), Asc("logical_id"), Asc("attempt_id")]),
            ["idx_messages_conversation_created"] = new("messages", false, "c", false, [Asc("conversation_id"), Asc("created_at")]),
            ["idx_messages_conversation_created_id"] = new("messages", false, "c", false, [Asc("conversation_id"), Desc("created_at"), Desc("id")]),
            ["idx_messages_unread"] = new("messages", false, "c", false, [Asc("conversation_id"), Asc("direction"), Asc("delivery_state"), Asc("created_at")]),
            ["idx_messages_server_hash"] = new(
                "messages",
                false,
                "c",
                true,
                [Asc("conversation_id"), Asc("server_hash")],
                "CREATE INDEX idx_messages_server_hash ON messages(conversation_id, server_hash) WHERE server_hash IS NOT NULL"),
            ["idx_messages_self_echo"] = new("messages", false, "c", false, [Asc("conversation_id"), Asc("sender_session_id"), Asc("recipient_session_id"), Asc("direction"), Asc("self_echo_key")]),
            ["idx_messages_pending_outgoing"] = new("messages", false, "c", false, [Asc("sender_session_id"), Asc("direction"), Asc("delivery_state"), Asc("created_at"), Asc("id")]),
            ["idx_replay_claims_expires_at"] = new("replay_claims", false, "c", false, [Asc("expires_at")]),
            ["idx_inbox_items_staged"] = new("inbox_items", false, "c", false, [Asc("account_session_id"), Asc("namespace"), Asc("item_kind"), Asc("sequence")]),
            ["idx_inbox_items_decoded_route"] = new("inbox_items", false, "c", false, [Asc("account_session_id"), Asc("namespace"), Asc("item_kind"), Asc("route_key"), Asc("sequence")]),
            ["idx_inbox_items_logical_message"] = new("inbox_items", false, "c", false, [Asc("sender_session_id"), Asc("message_id"), Asc("sequence")]),
            ["idx_group_state_outbox_order"] = new("group_state_outbox", false, "c", false, [Asc("group_id"), Asc("revision"), Asc("sequence")]),
            ["idx_membership_trust_records_head"] = new("membership_trust_records", false, "c", false, [Asc("profile_key"), Asc("domain"), Asc("revision")]),
            ["idx_client_mailbox_inbox_scope_expiry"] = new("client_mailbox_inbox", false, "c", false, [Asc("scope"), Asc("expires_at")]),
            ["idx_client_mailbox_inbox_expiry_scope"] = new("client_mailbox_inbox", false, "c", false, [Asc("expires_at"), Asc("scope")]),
            ["idx_client_mailbox_inbox_scope_ack_cursor"] = new("client_mailbox_inbox", false, "c", false, [Asc("scope"), Asc("acknowledged"), Asc("cursor")]),
            ["idx_client_mailbox_quarantine_age"] = new("client_mailbox_expired_quarantine", false, "c", false, [Asc("quarantined_at"), Asc("expires_at"), Asc("scope")]),
            ["idx_client_mailbox_journal_scope_expiry"] = new("client_mailbox_coordinator_journal", false, "c", false, [Asc("installation_scope"), Asc("expires_at")]),
            ["idx_mailbox_credential_scope_lookup"] = new("mailbox_credential_scopes", false, "c", false, [Asc("account_scope"), Asc("scope_kind"), Asc("subject_id"), Asc("issuer_context")]),
            ["idx_mailbox_credential_epoch_expiry"] = new("mailbox_credential_epochs", false, "c", false, [Asc("scope_id"), Asc("expires_at")]),
            ["idx_mailbox_prepared_targets_scope"] = new("mailbox_prepared_batch_targets", false, "c", false, [Asc("scope_id"), Asc("account_scope"), Asc("parent_operation_id")]),
            ["idx_transport_outbox_ready"] = new("transport_outbox_items", false, "c", false, [Asc("account_scope"), Asc("state"), Asc("not_before"), Asc("expires_at"), Asc("created_at")]),
            ["idx_transport_outbox_expiry"] = new("transport_outbox_items", false, "c", false, [Asc("account_scope"), Asc("expires_at"), Asc("state")])
        };
    }

    private static void ValidateIndexes(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        IEnumerable<string> tables)
    {
        var expected = ExpectedSchemaIndexes();
        foreach (var table in tables)
        {
            var expectedForTable = expected
                .Where(item => string.Equals(item.Value.Table, table, StringComparison.Ordinal))
                .ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);
            var found = new HashSet<string>(StringComparer.Ordinal);
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = $"PRAGMA index_list(\"{table}\");";
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var name = reader.GetString(1);
                    if (!expectedForTable.TryGetValue(name, out var index)
                        || reader.GetInt32(2) != (index.Unique ? 1 : 0)
                        || !string.Equals(reader.GetString(3), index.Origin, StringComparison.Ordinal)
                        || reader.GetInt32(4) != (index.Partial ? 1 : 0)
                        || !found.Add(name))
                    {
                        throw new InvalidDataException($"Local state table {table} has unexpected indexes.");
                    }
                }
            }
            if (found.Count != expectedForTable.Count)
            {
                throw new InvalidDataException($"Local state table {table} is missing indexes.");
            }

            foreach (var index in expectedForTable)
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = $"""
                    SELECT seqno, name, "desc", coll
                    FROM pragma_index_xinfo('{index.Key}')
                    WHERE "key" = 1
                    ORDER BY seqno;
                    """;
                using var reader = command.ExecuteReader();
                var ordinal = 0;
                while (reader.Read())
                {
                    if (ordinal >= index.Value.Columns.Count)
                    {
                        throw new InvalidDataException($"Local state index {index.Key} has extra columns.");
                    }
                    var column = index.Value.Columns[ordinal];
                    if (reader.GetInt32(0) != ordinal
                        || reader.IsDBNull(1)
                        || !string.Equals(reader.GetString(1), column.Name, StringComparison.Ordinal)
                        || reader.GetInt32(2) != (column.Descending ? 1 : 0)
                        || !string.Equals(reader.GetString(3), "BINARY", StringComparison.Ordinal))
                    {
                        throw new InvalidDataException($"Local state index {index.Key} is incompatible.");
                    }
                    ordinal++;
                }
                if (ordinal != index.Value.Columns.Count)
                {
                    throw new InvalidDataException($"Local state index {index.Key} is missing columns.");
                }
                reader.Close();

                if (index.Value.Partial)
                {
                    if (index.Value.NormalizedSql is null)
                    {
                        throw new InvalidOperationException(
                            $"Expected partial index {index.Key} has no SQL attestation.");
                    }
                    var actualSql = NormalizeSchemaSql(
                        ReadBoundedSchemaSql(
                            connection,
                            transaction,
                            "index",
                            index.Key,
                            index.Value.Table));
                    if (!string.Equals(
                            actualSql,
                            index.Value.NormalizedSql,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException(
                            $"Local state partial index {index.Key} has an incompatible predicate.");
                    }
                }
            }
        }
    }

    private static void ValidateAutoincrementTables(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        foreach (var table in new[]
                 {
                     "incoming_message_notifications",
                     "inbox_items",
                     "group_state_outbox"
                 })
        {
            var normalizedSql = NormalizeSchemaSql(
                ReadBoundedSchemaSql(
                    connection,
                    transaction,
                    "table",
                    table,
                    table));
            var expectedPrefix =
                $"CREATE TABLE {table} ( sequence INTEGER PRIMARY KEY AUTOINCREMENT,";
            if (!normalizedSql.StartsWith(
                    expectedPrefix,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"Local state table {table} does not have the required autoincrementing sequence declaration.");
            }
        }
    }

    private static string ReadBoundedSchemaSql(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string type,
        string name,
        string table)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT length(sql), substr(sql, 1, $maximumLength + 1)
            FROM sqlite_schema
            WHERE type = $type AND name = $name AND tbl_name = $table;
            """;
        command.Parameters.AddWithValue("$maximumLength", MaximumSchemaDefinitionLength);
        command.Parameters.AddWithValue("$type", type);
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$table", table);
        using var reader = command.ExecuteReader();
        if (!reader.Read()
            || reader.IsDBNull(0)
            || reader.IsDBNull(1)
            || reader.GetInt64(0) <= 0
            || reader.GetInt64(0) > MaximumSchemaDefinitionLength)
        {
            throw new InvalidDataException(
                $"Local state schema definition {name} is missing or exceeds its validation bound.");
        }
        var sql = reader.GetString(1);
        if (reader.Read())
        {
            throw new InvalidDataException(
                $"Local state schema definition {name} is ambiguous.");
        }
        return sql;
    }

    private static string NormalizeSchemaSql(string sql)
    {
        var normalized = new StringBuilder(sql.Length);
        var pendingSpace = false;
        foreach (var character in sql)
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = normalized.Length > 0;
                continue;
            }
            if (pendingSpace)
            {
                normalized.Append(' ');
                pendingSpace = false;
            }
            normalized.Append(character);
        }
        return normalized.ToString().TrimEnd(' ', ';');
    }

    private static void ValidateTransportOutboxSchema(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        ValidateTransportOutboxColumns(
            connection,
            transaction,
            "transport_outbox_items",
            [
                ("account_scope", "BLOB", 1, 1),
                ("logical_id", "BLOB", 1, 2),
                ("dedup_material", "BLOB", 1, 0),
                ("ciphertext_bundle", "BLOB", 1, 0),
                ("created_at", "INTEGER", 1, 0),
                ("expires_at", "INTEGER", 1, 0),
                ("not_before", "INTEGER", 1, 0),
                ("state", "INTEGER", 1, 0),
                ("revision", "INTEGER", 1, 0),
                ("transition_source", "INTEGER", 1, 0),
                ("transition_reason", "INTEGER", 1, 0),
                ("transitioned_at", "INTEGER", 1, 0),
                ("last_transition_state", "INTEGER", 1, 0),
                ("last_attempt_id", "BLOB", 0, 0),
                ("last_retry_not_before", "INTEGER", 0, 0),
                ("acknowledgement_evidence", "BLOB", 0, 0),
                ("acknowledged_at", "INTEGER", 0, 0)
            ]);
        ValidateTransportOutboxColumns(
            connection,
            transaction,
            "transport_outbox_attempts",
            [
                ("account_scope", "BLOB", 1, 1),
                ("logical_id", "BLOB", 1, 2),
                ("attempt_id", "BLOB", 1, 3),
                ("state", "INTEGER", 1, 0),
                ("transition_source", "INTEGER", 1, 0),
                ("transition_reason", "INTEGER", 1, 0),
                ("occurred_at", "INTEGER", 1, 0),
                ("evidence", "BLOB", 1, 0)
            ]);
        ValidateTransportOutboxForeignKeys(
            connection,
            transaction,
            "transport_outbox_attempts",
            "transport_outbox_items",
            [
                (0, "account_scope", "account_scope"),
                (1, "logical_id", "logical_id")
            ]);
        ValidateTransportOutboxTriggersAbsent(
            connection,
            transaction,
            ["transport_outbox_items", "transport_outbox_attempts"]);
        ValidateTransportOutboxIndexSet(
            connection,
            transaction,
            "transport_outbox_items",
            ["account_scope", "logical_id"],
            ["idx_transport_outbox_ready", "idx_transport_outbox_expiry"]);
        ValidateTransportOutboxIndexSet(
            connection,
            transaction,
            "transport_outbox_attempts",
            ["account_scope", "logical_id", "attempt_id"],
            []);
        ValidateTransportOutboxIndex(
            connection,
            transaction,
            "idx_transport_outbox_ready",
            "transport_outbox_items",
            ["account_scope", "state", "not_before", "expires_at", "created_at"],
            optional: false);
        ValidateTransportOutboxIndex(
            connection,
            transaction,
            "idx_transport_outbox_expiry",
            "transport_outbox_items",
            ["account_scope", "expires_at", "state"],
            optional: false);
    }

    private static void ValidateTransportOutboxForeignKeys(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string attemptsTable,
        string expectedTable,
        IReadOnlyList<(int Sequence, string From, string To)> expectedMappings)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            SELECT id, seq, "table", "from", "to",
                   "on_update", "on_delete", "match"
            FROM pragma_foreign_key_list('{attemptsTable}')
            ORDER BY id, seq;
            """;
        using var reader = command.ExecuteReader();
        var index = 0;
        int? compositeId = null;
        while (reader.Read())
        {
            if (index >= expectedMappings.Count)
            {
                throw new InvalidDataException(
                    "Transport outbox foreign-key schema has extra rows.");
            }
            compositeId ??= reader.GetInt32(0);
            var expected = expectedMappings[index++];
            if (!string.Equals(
                    reader.GetString(2),
                    expectedTable,
                    StringComparison.Ordinal)
                || reader.GetInt32(0) != compositeId
                || reader.GetInt32(1) != expected.Sequence
                || !string.Equals(reader.GetString(3), expected.From, StringComparison.Ordinal)
                || !string.Equals(reader.GetString(4), expected.To, StringComparison.Ordinal)
                || !string.Equals(reader.GetString(5), "NO ACTION", StringComparison.Ordinal)
                || !string.Equals(reader.GetString(6), "CASCADE", StringComparison.Ordinal)
                || !string.Equals(reader.GetString(7), "NONE", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    "Transport outbox foreign-key schema is incompatible.");
            }
        }
        if (index != expectedMappings.Count)
        {
            throw new InvalidDataException(
                "Transport outbox foreign-key schema is missing rows.");
        }
    }

    private static void ValidateTransportOutboxIndex(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string indexName,
        string expectedTable,
        IReadOnlyList<string> expectedColumns,
        bool optional)
    {
        using (var owner = connection.CreateCommand())
        {
            owner.Transaction = transaction;
            owner.CommandText = """
                SELECT type, tbl_name
                FROM sqlite_master
                WHERE name = $name;
                """;
            owner.Parameters.AddWithValue("$name", indexName);
            using var reader = owner.ExecuteReader();
            if (!reader.Read())
            {
                if (optional)
                {
                    return;
                }
                throw new InvalidDataException(
                    $"Transport outbox index {indexName} is missing.");
            }
            if (!string.Equals(reader.GetString(0), "index", StringComparison.Ordinal)
                || !string.Equals(reader.GetString(1), expectedTable, StringComparison.Ordinal)
                || reader.Read())
            {
                throw new InvalidDataException(
                    $"Transport outbox index {indexName} has an invalid owner.");
            }
        }

        using (var properties = connection.CreateCommand())
        {
            properties.Transaction = transaction;
            properties.CommandText = $"""
                SELECT "unique", origin, partial
                FROM pragma_index_list('{expectedTable}')
                WHERE name = $name;
                """;
            properties.Parameters.AddWithValue("$name", indexName);
            using var reader = properties.ExecuteReader();
            if (!reader.Read()
                || reader.GetInt32(0) != 0
                || !string.Equals(reader.GetString(1), "c", StringComparison.Ordinal)
                || reader.GetInt32(2) != 0
                || reader.Read())
            {
                throw new InvalidDataException(
                    $"Transport outbox index {indexName} properties are incompatible.");
            }
        }

        using var columns = connection.CreateCommand();
        columns.Transaction = transaction;
        columns.CommandText = $"""
            SELECT seqno, name, "desc", coll
            FROM pragma_index_xinfo('{indexName}')
            WHERE "key" = 1
            ORDER BY seqno;
            """;
        using var columnReader = columns.ExecuteReader();
        var columnIndex = 0;
        while (columnReader.Read())
        {
            if (columnIndex >= expectedColumns.Count
                || columnReader.GetInt32(0) != columnIndex
                || columnReader.IsDBNull(1)
                || !string.Equals(
                    columnReader.GetString(1),
                    expectedColumns[columnIndex],
                    StringComparison.Ordinal)
                || columnReader.GetInt32(2) != 0
                || !string.Equals(columnReader.GetString(3), "BINARY", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Transport outbox index {indexName} key columns are incompatible.");
            }
            columnIndex++;
        }
        if (columnIndex != expectedColumns.Count)
        {
            throw new InvalidDataException(
                $"Transport outbox index {indexName} is missing key columns.");
        }
    }

    private static void ValidateTransportOutboxIndexSet(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string tableName,
        IReadOnlyList<string> expectedPrimaryKeyColumns,
        IReadOnlyCollection<string> allowedCustomIndexes)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"""
            SELECT name, "unique", origin, partial
            FROM pragma_index_list('{tableName}');
            """;
        using var reader = command.ExecuteReader();
        var primaryKeyCount = 0;
        string? primaryKeyIndexName = null;
        var customIndexes = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read())
        {
            var name = reader.GetString(0);
            var unique = reader.GetInt32(1);
            var origin = reader.GetString(2);
            var partial = reader.GetInt32(3);
            if (string.Equals(origin, "pk", StringComparison.Ordinal))
            {
                primaryKeyCount++;
                if (unique != 1 || partial != 0)
                {
                    throw new InvalidDataException(
                        $"Transport outbox table {tableName} has an invalid primary-key index.");
                }
                primaryKeyIndexName = name;
                continue;
            }

            if (!string.Equals(origin, "c", StringComparison.Ordinal)
                || unique != 0
                || partial != 0
                || !allowedCustomIndexes.Contains(name)
                || !customIndexes.Add(name))
            {
                throw new InvalidDataException(
                    $"Transport outbox table {tableName} has an unexpected index.");
            }
        }
        if (primaryKeyCount != 1)
        {
            throw new InvalidDataException(
                $"Transport outbox table {tableName} has an incompatible primary-key index.");
        }
        reader.Close();
        ValidateTransportOutboxIndexKeyColumns(
            connection,
            transaction,
            primaryKeyIndexName!,
            expectedPrimaryKeyColumns);
    }

    private static void ValidateTransportOutboxTriggersAbsent(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        IReadOnlyList<string> tableNames)
    {
        foreach (var tableName in tableNames)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT 1 FROM sqlite_master
                WHERE type = 'trigger' AND tbl_name = $table
                LIMIT 1;
                """;
            command.Parameters.AddWithValue("$table", tableName);
            if (command.ExecuteScalar() is not null)
            {
                throw new InvalidDataException(
                    $"Transport outbox table {tableName} must not have triggers.");
            }
        }
    }

    private static void ValidateTransportOutboxIndexKeyColumns(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string indexName,
        IReadOnlyList<string> expectedColumns)
    {
        using var columns = connection.CreateCommand();
        columns.Transaction = transaction;
        columns.CommandText = $"""
            SELECT seqno, name, "desc", coll
            FROM pragma_index_xinfo('{indexName}')
            WHERE "key" = 1
            ORDER BY seqno;
            """;
        using var reader = columns.ExecuteReader();
        var index = 0;
        while (reader.Read())
        {
            if (index >= expectedColumns.Count
                || reader.GetInt32(0) != index
                || reader.IsDBNull(1)
                || !string.Equals(reader.GetString(1), expectedColumns[index], StringComparison.Ordinal)
                || reader.GetInt32(2) != 0
                || !string.Equals(reader.GetString(3), "BINARY", StringComparison.Ordinal))
            {
                throw new InvalidDataException(
                    $"Transport outbox index {indexName} key columns are incompatible.");
            }
            index++;
        }
        if (index != expectedColumns.Count)
        {
            throw new InvalidDataException(
                $"Transport outbox index {indexName} is missing key columns.");
        }
    }

    private static void ValidateTransportOutboxColumns(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string tableName,
        IReadOnlyList<(string Name, string Type, int NotNull, int PrimaryKey)> expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_xinfo(\"{tableName}\");";
        using var reader = command.ExecuteReader();
        var index = 0;
        while (reader.Read())
        {
            if (index >= expected.Count)
            {
                throw new InvalidDataException(
                    $"Transport outbox table {tableName} has unexpected columns.");
            }
            var column = expected[index++];
            if (!string.Equals(reader.GetString(1), column.Name, StringComparison.Ordinal)
                || !string.Equals(reader.GetString(2), column.Type, StringComparison.OrdinalIgnoreCase)
                || reader.GetInt32(3) != column.NotNull
                || !reader.IsDBNull(4)
                || reader.GetInt32(5) != column.PrimaryKey
                || reader.GetInt32(6) != 0)
            {
                throw new InvalidDataException(
                    $"Transport outbox table {tableName} is incompatible.");
            }
        }
        if (index != expected.Count)
        {
            throw new InvalidDataException(
                $"Transport outbox table {tableName} is missing columns.");
        }
    }

    private static void EnableSqliteSecureDelete(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA secure_delete=ON;";
        if (Convert.ToInt32(
                command.ExecuteScalar(),
                CultureInfo.InvariantCulture) != 1)
        {
            throw new InvalidOperationException("SQLite secure_delete could not be enabled.");
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

    private static string ConnectionStringFor(
        string statePath,
        string? encryptionKey,
        SqliteOpenMode mode,
        bool pooling,
        bool immutable = false)
    {
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = immutable
                ? new Uri(statePath).AbsoluteUri + "?immutable=1"
                : statePath,
            Mode = mode,
            Cache = SqliteCacheMode.Private,
            Pooling = pooling
        };
        if (!string.IsNullOrWhiteSpace(encryptionKey))
        {
            builder.Password = encryptionKey;
        }

        return builder.ToString();
    }

    private static void ConfigurePreflightConnection(
        SqliteConnection connection,
        bool existing)
    {
        using var command = connection.CreateCommand();
        command.CommandText = existing
            ? """
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                PRAGMA query_only = ON;
                """
            : """
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                """;
        command.ExecuteNonQuery();
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

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        using var poolIdentity = new SqliteConnection(_connectionString);
        SqliteConnection.ClearPool(poolIdentity);
        _databaseGate.Dispose();
    }

    private static LocalStateResetRequiredException ResetRequired(
        LocalStateResetRequiredReason reason,
        string message,
        Exception? innerException = null) =>
        new(reason, message, innerException);

    private static int PrimarySqliteErrorCode(SqliteException exception) =>
        exception.SqliteExtendedErrorCode & 0xff;

    private static Conversation DeserializeConversation(string payload)
    {
        var conversation = JsonSerializer.Deserialize<Conversation>(payload, SerializerOptions)
            ?? throw new InvalidDataException("Stored conversation payload is null.");
        EnsureSupportedConversationKind(conversation.Kind);
        return conversation;
    }

    private static void EnsureSupportedConversationKind(ConversationKind kind)
    {
        if (kind is not (
                ConversationKind.OneToOne or
                ConversationKind.GroupV2 or
                ConversationKind.Community))
        {
            throw new InvalidDataException("Stored conversation kind is unsupported.");
        }
    }

    private static bool MustPropagateWithoutReset(SqliteException exception) =>
        PrimarySqliteErrorCode(exception) is
            5 or  // SQLITE_BUSY
            6 or  // SQLITE_LOCKED
            7 or  // SQLITE_NOMEM
            8 or  // SQLITE_READONLY
            10 or // SQLITE_IOERR
            13 or // SQLITE_FULL
            14;   // SQLITE_CANTOPEN

}

[DebuggerDisplay("{ToString(),nq}")]
public sealed class SqliteSessionStoreOptions
{
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    private readonly string? encryptionKey;

    public SqliteSessionStoreOptions(string statePath, string? encryptionKey = null)
    {
        StatePath = statePath;
        this.encryptionKey = encryptionKey;
    }

    public string StatePath { get; }

    internal string? GetEncryptionKeyForStore() => encryptionKey;

    public override string ToString() =>
        $"{nameof(SqliteSessionStoreOptions)} {{ " +
        $"StatePath = {(string.IsNullOrWhiteSpace(StatePath) ? "[missing]" : "[configured]")}, " +
        $"EncryptionKey = {(string.IsNullOrWhiteSpace(encryptionKey) ? "[not-configured]" : "[redacted]")} }}";
}
