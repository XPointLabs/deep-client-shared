using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Globalization;
using Deep.Client.Shared.Domain;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed class SqliteSessionStore : ILocalSessionStore
{
    private const string ReadCursorSettingPrefix = "sync.read-cursor.";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly string? _encryptionKey;

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

        _connectionString = ConnectionStringFor(statePath);

        _encryptionKey = string.IsNullOrWhiteSpace(options.EncryptionKey) ? null : options.EncryptionKey;

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
            INSERT INTO messages (id, conversation_id, created_at, payload_json)
            VALUES ($id, $conversationId, $createdAt, $payload)
            ON CONFLICT(id) DO UPDATE SET
                conversation_id = excluded.conversation_id,
                created_at = excluded.created_at,
                payload_json = excluded.payload_json;
            """;

        await ExecuteNonQueryAsync(sql, cancellationToken, new (string, object?)[]
        {
            ("$id", message.Id.Value),
            ("$conversationId", message.ConversationId.Value),
            ("$createdAt", message.CreatedAt.ToUnixTimeMilliseconds()),
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
              AND json_extract(payload_json, '$.direction') = $incomingDirection
              AND json_extract(payload_json, '$.deliveryState') != $readState
              AND (
                    json_extract(payload_json, '$.expiresAt') IS NULL
                    OR json_extract(payload_json, '$.expiresAt') > $now
                  );
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

        var readCursors = await LoadReadCursorsAsync(ids, cancellationToken).ConfigureAwait(false);
        var lastMessages = await LoadLastMessagesAsync(ids, now, cancellationToken).ConfigureAwait(false);
        var unreadCounts = await LoadUnreadCountsAsync(ids, readCursors, now, cancellationToken).ConfigureAwait(false);
        var contacts = await LoadContactsAsync(ids, cancellationToken).ConfigureAwait(false);

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
        using var connection = OpenConnection();

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
    }


    private async Task ExecuteNonQueryAsync(string sql, CancellationToken cancellationToken, params (string Name, object? Value)[] parameters)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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
        var result = new List<string>();

        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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
    }

    private async Task<IReadOnlyDictionary<ConversationId, DateTimeOffset?>> LoadReadCursorsAsync(
        IReadOnlyList<ConversationId> conversationIds,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, DateTimeOffset?>();
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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

    private async Task<IReadOnlyDictionary<ConversationId, Message>> LoadLastMessagesAsync(
        IReadOnlyList<ConversationId> conversationIds,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, Message>();
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        var idsClause = AddInParameters(command, "$id", conversationIds.Select(static id => id.Value));
        command.Parameters.AddWithValue("$now", now.ToString("O", CultureInfo.InvariantCulture));
        command.CommandText = $"""
            SELECT m.conversation_id, m.payload_json
            FROM messages m
            WHERE m.conversation_id IN ({idsClause})
              AND (
                    json_extract(m.payload_json, '$.expiresAt') IS NULL
                    OR json_extract(m.payload_json, '$.expiresAt') > $now
                  )
              AND NOT EXISTS (
                    SELECT 1
                    FROM messages newer
                    WHERE newer.conversation_id = m.conversation_id
                      AND (
                            newer.created_at > m.created_at
                            OR (newer.created_at = m.created_at AND newer.id > m.id)
                          )
                      AND (
                            json_extract(newer.payload_json, '$.expiresAt') IS NULL
                            OR json_extract(newer.payload_json, '$.expiresAt') > $now
                          )
                  );
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

    private async Task<IReadOnlyDictionary<ConversationId, int>> LoadUnreadCountsAsync(
        IReadOnlyList<ConversationId> conversationIds,
        IReadOnlyDictionary<ConversationId, DateTimeOffset?> readCursors,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, int>();
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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
              AND json_extract(payload_json, '$.direction') = $incomingDirection
              AND json_extract(payload_json, '$.deliveryState') != $readState
              AND (
                    json_extract(payload_json, '$.expiresAt') IS NULL
                    OR json_extract(payload_json, '$.expiresAt') > $now
                  )
            GROUP BY conversation_id;
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result[new ConversationId(reader.GetString(0))] = (int)reader.GetInt64(1);
        }

        return result;
    }

    private async Task<IReadOnlyDictionary<ConversationId, Contact>> LoadContactsAsync(
        IReadOnlyList<ConversationId> conversationIds,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<ConversationId, Contact>();
        await using var connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
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
        ApplyEncryptionKey(connection, _encryptionKey);
        return connection;
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        ApplyEncryptionKey(connection, _encryptionKey);
        return connection;
    }

    private static string ConnectionStringFor(string statePath) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString();

    private static SqliteConnection OpenConnectionForPath(string statePath, string? encryptionKey)
    {
        var connection = new SqliteConnection(ConnectionStringFor(statePath));
        connection.Open();
        ApplyEncryptionKey(connection, encryptionKey);
        return connection;
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

}

public sealed record SqliteSessionStoreOptions(string StatePath, string? EncryptionKey = null);
