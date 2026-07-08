using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Globalization;
using Deep.Client.Shared.Domain;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence;

public sealed class SqliteSessionStore : ILocalSessionStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;
    private readonly string? _encryptionKey;

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

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false
        }.ToString();

        _encryptionKey = string.IsNullOrWhiteSpace(options.EncryptionKey) ? null : options.EncryptionKey;

        InitializeSchema();
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

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        ApplyEncryptionKey(connection);
        return connection;
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        ApplyEncryptionKey(connection);
        return connection;
    }

    private void ApplyEncryptionKey(SqliteConnection connection)
    {
        if (string.IsNullOrWhiteSpace(_encryptionKey))
        {
            return;
        }

        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA key = $key;";
        pragma.Parameters.AddWithValue("$key", _encryptionKey);
        pragma.ExecuteNonQuery();
    }

}

public sealed record SqliteSessionStoreOptions(string StatePath, string? EncryptionKey = null);
