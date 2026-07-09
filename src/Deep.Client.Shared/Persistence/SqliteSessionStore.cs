using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Globalization;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Services;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed class SqliteSessionStore : ILocalSessionStore, IOneToOneConversationOpenRepository, IDisposable
{
    private const string ReadCursorSettingPrefix = "sync.read-cursor.";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly string? _encryptionKey;
    private readonly SemaphoreSlim _sharedConnectionGate = new(1, 1);
    private SqliteConnection? _sharedConnection;

    private sealed record OneToOneOpenMetadata(
        string? ActiveAccountPayload,
        string? ContactPayload,
        string? ConversationPayload,
        string? ReadCursorPayload,
        long? LatestIncomingCreatedAt);

    static SqliteSessionStore()
    {
        SQLitePCL.Batteries_V2.Init();
    }

    public SqliteSessionStore(string statePath)
        : this(new SqliteSessionStoreOptions(statePath))
    {
    }

    public SqliteSessionStore(SqliteSessionStoreOptions options)
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

        if (!File.Exists(statePath) || CanOpenDatabase(statePath, encryptionKey))
        {
            return;
        }

        if (!CanOpenDatabase(statePath, null))
        {
            throw new InvalidOperationException("Local state database cannot be opened with the configured key and is not a plaintext database.");
        }

        var tempPath = statePath + ".encrypted-migration";
        var backupPath = statePath + ".plaintext-migration";
        DeleteSqliteFileSet(tempPath);
        DeleteSqliteFileSet(backupPath);

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

        try
        {
            File.Move(statePath, backupPath);
            DeleteSqliteSidecars(statePath);
            File.Move(tempPath, statePath);
            DeleteSqliteFileSet(backupPath);
            DeleteSqliteSidecars(tempPath);
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
            INSERT INTO messages (id, conversation_id, created_at, direction, delivery_state, expires_at, payload_json)
            VALUES ($id, $conversationId, $createdAt, $direction, $deliveryState, $expiresAt, $payload)
            ON CONFLICT(id) DO UPDATE SET
                conversation_id = excluded.conversation_id,
                created_at = excluded.created_at,
                direction = excluded.direction,
                delivery_state = excluded.delivery_state,
                expires_at = excluded.expires_at,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, new (string, object?)[]
        {
            ("$id", message.Id.Value),
            ("$conversationId", message.ConversationId.Value),
            ("$createdAt", message.CreatedAt.ToUnixTimeMilliseconds()),
            ("$direction", (int)message.Direction),
            ("$deliveryState", (int)message.DeliveryState),
            ("$expiresAt", message.ExpiresAt?.ToString("O", CultureInfo.InvariantCulture)),
            ("$payload", JsonSerializer.Serialize(message, SerializerOptions))
        }).ConfigureAwait(false);
    }

    public Task UpdateAsync(Message message, CancellationToken cancellationToken = default) =>
        AppendAsync(message, cancellationToken);

    public Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default)
    {
        const string sql = "DELETE FROM messages WHERE id = $id;";
        return ExecuteNonQueryAsync(sql, cancellationToken, ("$id", id.Value));
    }

    public async Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT payload_json FROM messages WHERE id = $id;";
        var payload = await ExecuteScalarAsync<string?>(sql, cancellationToken, ("$id", id.Value)).ConfigureAwait(false);
        return payload is null ? null : JsonSerializer.Deserialize<Message>(payload, SerializerOptions);
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListForConversationAsync(
        ConversationId conversationId,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = "SELECT payload_json FROM messages WHERE conversation_id = $conversationId ORDER BY created_at, id;";
        foreach (var payload in await QueryJsonAsync(sql, cancellationToken, ("$conversationId", conversationId.Value)).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!;
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListRecentForConversationAsync(
        ConversationId conversationId,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT payload_json
            FROM (
                SELECT payload_json, created_at, id
                FROM messages
                WHERE conversation_id = $conversationId
                ORDER BY created_at DESC, id DESC
                LIMIT $limit
            )
            ORDER BY created_at, id;
            """;

        foreach (var payload in await QueryJsonAsync(
                         sql,
                         cancellationToken,
                         ("$conversationId", conversationId.Value),
                         ("$limit", limit)).ConfigureAwait(false))
        {
            yield return JsonSerializer.Deserialize<Message>(payload, SerializerOptions)!;
        }
    }

    async IAsyncEnumerable<Message> IMessageRepository.ListBeforeForConversationAsync(
        ConversationId conversationId,
        DateTimeOffset beforeCreatedAt,
        int limit,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT payload_json
            FROM (
                SELECT payload_json, created_at, id
                FROM messages
                WHERE conversation_id = $conversationId
                    AND created_at < $beforeCreatedAt
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
              AND ($readCursor IS NULL OR created_at > $readCursor)
              AND direction = $incomingDirection
              AND delivery_state != $readState
              AND (expires_at IS NULL OR expires_at > $now);
            """;

        var count = await ExecuteScalarAsync<long>(
            sql,
            cancellationToken,
            ("$conversationId", conversationId.Value),
            ("$readCursor", readCursor?.ToUnixTimeMilliseconds()),
            ("$incomingDirection", (int)MessageDirection.Incoming),
            ("$readState", (int)MessageDeliveryState.Read),
            ("$now", now.ToString("O", CultureInfo.InvariantCulture))).ConfigureAwait(false);

        return (int)count;
    }

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
            var readCursors = await LoadReadCursorsAsync(connection, ids, cancellationToken).ConfigureAwait(false);
            var lastMessages = await LoadLastMessagesAsync(connection, ids, now, cancellationToken).ConfigureAwait(false);
            var unreadCounts = await LoadUnreadCountsAsync(connection, ids, readCursors, now, cancellationToken).ConfigureAwait(false);
            var contacts = await LoadContactsAsync(connection, ids, cancellationToken).ConfigureAwait(false);

            var summaries = new Dictionary<ConversationId, ConversationListSummary>(ids.Length);
            foreach (var conversationId in ids)
            {
                summaries[conversationId] = new ConversationListSummary(
                    conversationId,
                    readCursors.GetValueOrDefault(conversationId),
                    lastMessages.GetValueOrDefault(conversationId),
                    unreadCounts.GetValueOrDefault(conversationId),
                    contacts.GetValueOrDefault(conversationId));
            }

            return summaries;
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
            var metadata = await LoadOneToOneOpenMetadataAsync(connection, recipient, conversationId, now, cancellationToken)
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
            if (!string.Equals(contact.DisplayName, normalizedContactDisplayName, StringComparison.Ordinal)
                || (!string.IsNullOrWhiteSpace(normalizedDisplayName) && contact.DisplayName != normalizedDisplayName))
            {
                contact = contact with
                {
                    DisplayName = string.IsNullOrWhiteSpace(normalizedDisplayName) ? normalizedContactDisplayName : normalizedDisplayName,
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
                command.CommandText = """
                    SELECT payload_json
                    FROM (
                        SELECT payload_json, created_at, id
                        FROM messages
                        WHERE conversation_id = $conversationId
                        ORDER BY created_at DESC, id DESC
                        LIMIT $limit
                    )
                    ORDER BY created_at, id;
                    """;
                command.Parameters.AddWithValue("$conversationId", conversationId.Value);
                command.Parameters.AddWithValue("$limit", messageLimit);
                await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var message = JsonSerializer.Deserialize<Message>(reader.GetString(0), SerializerOptions);
                    if (message is not null && !message.IsExpired(now))
                    {
                        recentMessages.Add(message);
                    }
                }
            }

            var existingReadAt = ParseReadCursorPayload(metadata.ReadCursorPayload);
            DateTimeOffset? latestIncomingAt = metadata.LatestIncomingCreatedAt is null
                ? null
                : DateTimeOffset.FromUnixTimeMilliseconds(metadata.LatestIncomingCreatedAt.Value);
            DateTimeOffset readAt = markAsRead
                ? Max(existingReadAt, latestIncomingAt) ?? now
                : existingReadAt ?? DateTimeOffset.MinValue;
            if (markAsRead && latestIncomingAt is not null && (existingReadAt is null || latestIncomingAt > existingReadAt))
            {
                await ExecuteNonQueryOnConnectionAsync(
                    connection,
                    """
                    INSERT INTO settings (key, payload_json)
                    VALUES ($key, $payload)
                    ON CONFLICT(key) DO UPDATE SET
                        payload_json = excluded.payload_json;
                    """,
                    cancellationToken,
                    ("$key", ReadCursorSettingKey(conversationId)),
                    ("$payload", JsonSerializer.Serialize(latestIncomingAt.Value.ToString("O", CultureInfo.InvariantCulture), SerializerOptions))).ConfigureAwait(false);
            }

            return new OneToOneConversationOpenSnapshot(account, conversation, contact, recentMessages, readAt);
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

    private void InitializeSchema()
    {
        SqliteConnection? transientConnection = null;
        var connection = _encryptionKey is null
            ? transientConnection = OpenConnection()
            : GetSharedEncryptedConnection();

        try
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                PRAGMA journal_mode=WAL;

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
                    expires_at TEXT NULL,
                    payload_json TEXT NOT NULL
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

                CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
                    ON messages(conversation_id, created_at);
                """;
            command.ExecuteNonQuery();
            EnsureMessageHotColumns(connection);
            EnsureMessageHotIndexes(connection);
        }
        finally
        {
            transientConnection?.Dispose();
        }
    }

    private static void EnsureMessageHotColumns(SqliteConnection connection)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA table_info(messages);";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                columns.Add(reader.GetString(1));
            }
        }

        using (var command = connection.CreateCommand())
        {
            var statements = new List<string>();
            if (!columns.Contains("direction"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN direction INTEGER;");
            }

            if (!columns.Contains("delivery_state"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN delivery_state INTEGER;");
            }

            if (!columns.Contains("expires_at"))
            {
                statements.Add("ALTER TABLE messages ADD COLUMN expires_at TEXT;");
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
            command.CommandText = """
                UPDATE messages
                SET
                    direction = COALESCE(direction, CAST(json_extract(payload_json, '$.direction') AS INTEGER)),
                    delivery_state = COALESCE(delivery_state, CAST(json_extract(payload_json, '$.deliveryState') AS INTEGER)),
                    expires_at = COALESCE(expires_at, json_extract(payload_json, '$.expiresAt'))
                WHERE direction IS NULL
                   OR delivery_state IS NULL
                   OR (expires_at IS NULL AND json_extract(payload_json, '$.expiresAt') IS NOT NULL);
                """;
            command.ExecuteNonQuery();
        }
    }

    private static void EnsureMessageHotIndexes(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE INDEX IF NOT EXISTS idx_messages_conversation_created_id
                ON messages(conversation_id, created_at DESC, id DESC);

            CREATE INDEX IF NOT EXISTS idx_messages_unread
                ON messages(conversation_id, direction, delivery_state, created_at);
            """;
        command.ExecuteNonQuery();
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

    private static async Task<IReadOnlyDictionary<ConversationId, DateTimeOffset?>> LoadReadCursorsAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, DateTimeOffset?>();
        await using var command = connection.CreateCommand();
        var keys = conversationIds
            .Select(ReadCursorSettingKey)
            .ToArray();
        var keysClause = AddInParameters(command, "$key", keys);
        command.CommandText = $"SELECT key, payload_json FROM settings WHERE key IN ({keysClause});";

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var key = reader.GetString(0);
            var conversationValue = key[ReadCursorSettingPrefix.Length..];
            var value = JsonSerializer.Deserialize<string>(reader.GetString(1), SerializerOptions);
            if (DateTimeOffset.TryParse(
                    value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind,
                    out var parsed))
            {
                result[new ConversationId(conversationValue)] = parsed;
            }
        }

        return result;
    }

    private static async Task<OneToOneOpenMetadata> LoadOneToOneOpenMetadataAsync(
        SqliteConnection connection,
        SessionId recipient,
        ConversationId conversationId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT payload_json FROM settings WHERE key = $activeAccountKey) AS active_account,
                (SELECT payload_json FROM contacts WHERE id = $recipientId) AS contact,
                (SELECT payload_json FROM conversations WHERE id = $conversationId) AS conversation,
                (SELECT payload_json FROM settings WHERE key = $readCursorKey) AS read_cursor,
                (
                    SELECT MAX(created_at)
                    FROM messages
                    WHERE conversation_id = $conversationId
                      AND direction = $incomingDirection
                      AND (expires_at IS NULL OR expires_at > $now)
                ) AS latest_incoming_created_at;
            """;
        command.Parameters.AddWithValue("$activeAccountKey", LocalSettingsKeys.ActiveAccount);
        command.Parameters.AddWithValue("$recipientId", recipient.Value);
        command.Parameters.AddWithValue("$conversationId", conversationId.Value);
        command.Parameters.AddWithValue("$readCursorKey", ReadCursorSettingKey(conversationId));
        command.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return new OneToOneOpenMetadata(null, null, null, null, null);
        }

        return new OneToOneOpenMetadata(
            GetNullableString(reader, 0),
            GetNullableString(reader, 1),
            GetNullableString(reader, 2),
            GetNullableString(reader, 3),
            reader.IsDBNull(4) ? null : reader.GetInt64(4));
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

    private static async Task<IReadOnlyDictionary<ConversationId, Message>> LoadLastMessagesAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, Message>();
        await using var command = connection.CreateCommand();
        var idsClause = AddInParameters(command, "$id", conversationIds.Select(static id => id.Value));
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        command.CommandText = $"""
            WITH ranked AS (
                SELECT
                    conversation_id,
                    payload_json,
                    ROW_NUMBER() OVER (
                        PARTITION BY conversation_id
                        ORDER BY created_at DESC, id DESC
                    ) AS rank
                FROM messages
                WHERE conversation_id IN ({idsClause})
                  AND (expires_at IS NULL OR expires_at > $now)
            )
            SELECT conversation_id, payload_json
            FROM ranked
            WHERE rank = 1;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var conversationId = new ConversationId(reader.GetString(0));
            var message = JsonSerializer.Deserialize<Message>(reader.GetString(1), SerializerOptions);
            if (message is not null)
            {
                result[conversationId] = message;
            }
        }

        return result;
    }

    private static async Task<IReadOnlyDictionary<ConversationId, int>> LoadUnreadCountsAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        IReadOnlyDictionary<ConversationId, DateTimeOffset?> readCursors,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, int>();
        await using var command = connection.CreateCommand();
        var terms = new List<string>(conversationIds.Count);
        for (var index = 0; index < conversationIds.Count; index++)
        {
            var idName = $"$cid{index}";
            var cursorName = $"$cursor{index}";
            var readCursor = readCursors.GetValueOrDefault(conversationIds[index]);
            command.Parameters.AddWithValue(idName, conversationIds[index].Value);
            command.Parameters.AddWithValue(
                cursorName,
                readCursor is null ? DBNull.Value : readCursor.Value.ToUnixTimeMilliseconds());
            terms.Add($"(conversation_id = {idName} AND ({cursorName} IS NULL OR created_at > {cursorName}))");
        }

        command.Parameters.AddWithValue("$incomingDirection", (int)MessageDirection.Incoming);
        command.Parameters.AddWithValue("$readState", (int)MessageDeliveryState.Read);
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        command.CommandText = $"""
            SELECT conversation_id, COUNT(*)
            FROM messages
            WHERE ({string.Join(" OR ", terms)})
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

    private static async Task<IReadOnlyDictionary<ConversationId, Contact>> LoadContactsAsync(
        SqliteConnection connection,
        IReadOnlyList<ConversationId> conversationIds,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, Contact>();
        await using var command = connection.CreateCommand();
        var idsClause = AddInParameters(command, "$contactId", conversationIds.Select(static id => id.Value));
        command.CommandText = $"SELECT id, payload_json FROM contacts WHERE id IN ({idsClause});";

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var id = new ConversationId(reader.GetString(0));
            var contact = JsonSerializer.Deserialize<Contact>(reader.GetString(1), SerializerOptions);
            if (contact is not null)
            {
                result[id] = contact;
            }
        }

        return result;
    }

    private static string AddInParameters(SqliteCommand command, string prefix, IEnumerable<string> values)
    {
        var names = new List<string>();
        var index = 0;
        foreach (var value in values)
        {
            var name = $"{prefix}{index}";
            command.Parameters.AddWithValue(name, value);
            names.Add(name);
            index++;
        }

        return string.Join(", ", names);
    }

    private static string ReadCursorSettingKey(ConversationId conversationId) =>
        ReadCursorSettingPrefix + conversationId.Value;

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        ConfigureConnection(connection);
        return connection;
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        await LeaveCallingSynchronizationContextAsync(cancellationToken).ConfigureAwait(false);
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
        if (_encryptionKey is null)
        {
            await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            return await action(connection).ConfigureAwait(false);
        }

        await _sharedConnectionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var connection = await GetSharedEncryptedConnectionAsync(cancellationToken).ConfigureAwait(false);
            return await action(connection).ConfigureAwait(false);
        }
        finally
        {
            _sharedConnectionGate.Release();
        }
    }

    private async Task<SqliteConnection> GetSharedEncryptedConnectionAsync(CancellationToken cancellationToken)
    {
        await LeaveCallingSynchronizationContextAsync(cancellationToken).ConfigureAwait(false);
        if (_sharedConnection is not null)
        {
            return _sharedConnection;
        }

        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        ConfigureConnection(connection);
        _sharedConnection = connection;
        return connection;
    }

    private SqliteConnection GetSharedEncryptedConnection()
    {
        if (_sharedConnection is not null)
        {
            return _sharedConnection;
        }

        _sharedConnection = OpenConnection();
        return _sharedConnection;
    }

    private static async Task LeaveCallingSynchronizationContextAsync(CancellationToken cancellationToken)
    {
        if (SynchronizationContext.Current is null)
        {
            return;
        }

        await Task.Run(static () => { }, cancellationToken).ConfigureAwait(false);
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
            """;
        command.ExecuteNonQuery();
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
        _sharedConnectionGate.Wait();
        try
        {
            _sharedConnection?.Dispose();
            _sharedConnection = null;
        }
        finally
        {
            _sharedConnectionGate.Release();
            _sharedConnectionGate.Dispose();
        }
    }

}

public sealed record SqliteSessionStoreOptions(string StatePath, string? EncryptionKey = null);
