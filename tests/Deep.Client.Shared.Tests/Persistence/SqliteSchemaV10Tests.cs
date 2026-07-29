using System.Diagnostics;
using System.Reflection;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class SqliteSchemaV10Tests
{
    private const int ApplicationId = 0x44454550;
    private const string CorrectKey = "deep-v10-correct-key-4a838277930e";
    private const string WrongKey = "deep-v10-wrong-key-c992865b0267";

    [Fact]
    public void FreshDatabaseHasExactV10AttestationAndNoLogicalSchemaTables()
    {
        var path = TempPath("fresh");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            SqliteConnection.ClearAllPools();

            using var connection = Open(path);
            Assert.Equal(10, Scalar(connection, "PRAGMA user_version;"));
            Assert.Equal(ApplicationId, Scalar(connection, "PRAGMA application_id;"));
            Assert.Equal(
                "ok",
                Convert.ToString(ScalarObject(connection, "PRAGMA integrity_check;")));
            Assert.Equal(
                0,
                Scalar(
                    connection,
                    """
                    SELECT COUNT(*) FROM sqlite_schema
                    WHERE name IN ('schema_meta', 'schema_values');
                    """));
            Assert.Equal(
                15,
                Scalar(
                    connection,
                    """
                    SELECT COUNT(*) FROM sqlite_schema
                    WHERE type = 'table' AND name NOT LIKE 'sqlite_%';
                    """));
            Assert.Equal(
                0,
                Scalar(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check;"));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public async Task ReopenAttestsWithoutChangingCatalogOrData()
    {
        var path = TempPath("reopen");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
                await store.SetAsync("v10.marker", "preserved");
            }
            SqliteConnection.ClearAllPools();
            var before = ReadCatalog(path);

            using (var reopened = new SqliteSessionStore(path))
            {
                Assert.Equal("preserved", await reopened.GetAsync<string>("v10.marker"));
            }
            SqliteConnection.ClearAllPools();

            Assert.Equal(before, ReadCatalog(path));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(9)]
    [InlineData(11)]
    public void ExistingUnsupportedVersionIsRejectedWithoutChangingAnyStateFile(int version)
    {
        var path = TempPath($"version-{version}");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            SqliteConnection.ClearAllPools();

            using var fixture = Open(path);
            Execute(fixture, $"PRAGMA user_version={version};");
            Execute(fixture, "INSERT INTO settings(key, payload_json) VALUES ('fixture', '\"preserved\"');");
            var before = SnapshotDurableFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(path));

            Assert.Equal(LocalStateResetRequiredReason.UnsupportedVersion, exception.Reason);
            AssertDurableFilesEqual(before, path);
            Assert.Equal(
                1,
                Scalar(
                    fixture,
                    "SELECT COUNT(*) FROM settings WHERE key='fixture' AND payload_json='\"preserved\"';"));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public void SidecarsWithoutMainDatabaseAreNeverFreshAndRemainUnchanged()
    {
        var path = TempPath("sidecars-only");
        var wal = path + "-wal";
        var shm = path + "-shm";
        try
        {
            File.WriteAllBytes(wal, [1, 2, 3, 4]);
            File.WriteAllBytes(shm, [5, 6, 7, 8]);
            var before = SnapshotFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(path));

            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            Assert.False(File.Exists(path));
            AssertFilesEqual(before, path);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public void EmptyExistingDatabaseIsNeverFreshAndRemainsUnchanged()
    {
        var path = TempPath("empty");
        try
        {
            File.WriteAllBytes(path, []);
            var before = SnapshotFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(path));

            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            AssertFilesEqual(before, path);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public void ExistingPlaintextDatabaseWithConfiguredKeyIsRejectedWithoutMutation()
    {
        var path = TempPath("plaintext");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            SqliteConnection.ClearAllPools();
            var before = SnapshotFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(new SqliteSessionStoreOptions(path, CorrectKey)));

            Assert.Equal(LocalStateResetRequiredReason.UnreadableOrWrongKey, exception.Reason);
            Assert.IsType<SqliteException>(exception.InnerException);
            AssertFilesEqual(before, path);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public async Task WrongKeyCannotBorrowCorrectKeyPoolAndConcurrentCorrectStoresRemainUsable()
    {
        var path = TempPath("pool-key");
        try
        {
            using var first = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path, CorrectKey));
            await first.SetAsync("pool.marker", "first");

            using var concurrent = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path, CorrectKey));
            Assert.Equal("first", await concurrent.GetAsync<string>("pool.marker"));

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(
                    new SqliteSessionStoreOptions(path, WrongKey)));
            Assert.Equal(LocalStateResetRequiredReason.UnreadableOrWrongKey, exception.Reason);

            await first.SetAsync("pool.after-wrong-key", "still-usable");
            Assert.Equal(
                "still-usable",
                await concurrent.GetAsync<string>("pool.after-wrong-key"));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public async Task ConstructionDuringActiveWalWriterUsesAConsistentReadSnapshot()
    {
        var path = TempPath("active-wal-writer");
        try
        {
            using var first = new SqliteSessionStore(path);
            await first.SetAsync("writer.marker", "committed");

            using var writer = Open(path);
            using var transaction = writer.BeginTransaction();
            using (var command = writer.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    UPDATE settings
                    SET payload_json = '"uncommitted"'
                    WHERE key = 'writer.marker';
                    """;
                Assert.Equal(1, command.ExecuteNonQuery());
            }

            Assert.True(File.Exists(path + "-wal"));
            Assert.True(File.Exists(path + "-shm"));
            var before = SnapshotDurableFiles(path);

            using var concurrent = new SqliteSessionStore(path);
            Assert.Equal(
                "committed",
                await concurrent.GetAsync<string>("writer.marker"));
            AssertDurableFilesEqual(before, path);
            Assert.True(File.Exists(path + "-shm"));

            transaction.Commit();
            Assert.Equal(
                "uncommitted",
                await first.GetAsync<string>("writer.marker"));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public async Task RemovedConversationKindIsRejectedOnWriteAndRead()
    {
        var path = TempPath("removed-conversation-kind");
        var now = DateTimeOffset.Parse("2026-07-29T00:00:00Z");
        var id = ConversationId.ForCommunity("https://community.invalid", "room");
        var valid = new Conversation(
            id,
            ConversationKind.Community,
            "Community",
            ConversationSettings.Default(ConversationKind.Community),
            now,
            now);
        try
        {
            using var store = new SqliteSessionStore(path);
            await store.UpsertAsync(valid);

            var invalid = valid with { Kind = (ConversationKind)2 };
            await Assert.ThrowsAsync<InvalidDataException>(
                () => store.UpsertAsync(invalid));

            using (var fixture = Open(path))
            {
                Execute(
                    fixture,
                    """
                    UPDATE conversations
                    SET payload_json = json_set(payload_json, '$.kind', 2);
                    """);
            }

            await Assert.ThrowsAsync<InvalidDataException>(
                () => store.GetAsync(id));
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public void KeyedRuntimeUsesAHiddenPooledConnectionString()
    {
        var path = TempPath("pooling");
        try
        {
            using var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path, CorrectKey));
            var field = typeof(SqliteSessionStore).GetField(
                "_connectionString",
                BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.NotNull(field);
            Assert.Equal(
                DebuggerBrowsableState.Never,
                field.GetCustomAttribute<DebuggerBrowsableAttribute>()?.State);
            var builder = new SqliteConnectionStringBuilder((string)field.GetValue(store)!);
            Assert.True(builder.Pooling);
            Assert.Equal(SqliteOpenMode.ReadWrite, builder.Mode);
            Assert.DoesNotContain(
                CorrectKey,
                store.ToString() ?? string.Empty,
                StringComparison.Ordinal);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Theory]
    [InlineData("DROP INDEX idx_messages_unread;")]
    [InlineData("CREATE VIEW hostile_view AS SELECT id FROM messages;")]
    [InlineData("CREATE TRIGGER hostile_trigger AFTER INSERT ON settings BEGIN DELETE FROM settings; END;")]
    [InlineData("CREATE TABLE transport_outbox_items_v8_recovery(marker INTEGER);")]
    public void TamperedV10CatalogIsRejectedWithoutFurtherMutation(string tamperSql)
    {
        AssertTamperRejected(tamperSql);
    }

    [Fact]
    public void MissingV10ColumnIsRejectedWithoutFurtherMutation()
    {
        AssertTamperRejected(
            """
            DROP INDEX idx_messages_self_echo;
            ALTER TABLE messages DROP COLUMN self_echo_key;
            """);
    }

    [Fact]
    public void MissingV10ForeignKeyIsRejectedWithoutFurtherMutation()
    {
        AssertTamperRejected(
            """
            PRAGMA foreign_keys=OFF;
            BEGIN;
            ALTER TABLE incoming_message_notifications RENAME TO old_notifications;
            CREATE TABLE incoming_message_notifications (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL UNIQUE
            );
            DROP TABLE old_notifications;
            COMMIT;
            """);
    }

    [Fact]
    public void ChangedPartialIndexPredicateIsRejectedWithoutFurtherMutation()
    {
        AssertTamperRejected(
            """
            DROP INDEX idx_messages_server_hash;
            CREATE INDEX idx_messages_server_hash
                ON messages(conversation_id, server_hash)
                WHERE server_hash IS NULL;
            """);
    }

    [Fact]
    public void AutoincrementCommentCannotSatisfySequenceDeclaration()
    {
        AssertTamperRejected(
            """
            BEGIN;
            DROP INDEX idx_group_state_outbox_order;
            ALTER TABLE group_state_outbox RENAME TO old_group_state_outbox;
            CREATE TABLE group_state_outbox (
                sequence INTEGER PRIMARY KEY /* AUTOINCREMENT */,
                operation_id TEXT NOT NULL UNIQUE,
                group_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                group_payload TEXT NOT NULL,
                recipients_json TEXT NOT NULL
            );
            DROP TABLE old_group_state_outbox;
            CREATE INDEX idx_group_state_outbox_order
                ON group_state_outbox(group_id, revision, sequence);
            COMMIT;
            """);
    }

    [Fact]
    public void CorruptV10DatabaseIsRejectedWithoutChangingBytes()
    {
        var path = TempPath("corrupt");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            SqliteConnection.ClearAllPools();
            var bytes = File.ReadAllBytes(path);
            Array.Fill<byte>(bytes, 0xA5, 0, Math.Min(128, bytes.Length));
            File.WriteAllBytes(path, bytes);
            var before = SnapshotFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(path));

            Assert.Contains(
                exception.Reason,
                new[]
                {
                    LocalStateResetRequiredReason.InvalidCurrentSchema,
                    LocalStateResetRequiredReason.UnreadableOrWrongKey
                });
            AssertFilesEqual(before, path);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    [Fact]
    public void CannotOpenIsNotClassifiedAsResetRequired()
    {
        var path = Path.Combine(Path.GetTempPath(), $"deep-v10-directory-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        try
        {
            var exception = Assert.Throws<SqliteException>(
                () => new SqliteSessionStore(path));
            Assert.Equal(14, exception.SqliteExtendedErrorCode & 0xff);
        }
        finally
        {
            Directory.Delete(path);
        }
    }

    [Fact]
    public void MigrationAndLogicalSchemaApisAreAbsent()
    {
        Assert.DoesNotContain(
            typeof(ILocalSessionStore).GetMethods(),
            method => method.Name.Contains("Schema", StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(SqliteSessionStore).GetMethods(BindingFlags.Instance | BindingFlags.Public),
            method => method.Name.Contains("Schema", StringComparison.Ordinal));

        var root = RepositoryRoot();
        Assert.False(
            File.Exists(
                Path.Combine(
                    root,
                    "src",
                    "Deep.Client.Shared",
                    "Persistence",
                    "SchemaMigration.cs")));
        var source = File.ReadAllText(
            Path.Combine(
                root,
                "src",
                "Deep.Client.Shared",
                "Persistence",
                "SqliteSessionStore.cs"));
        Assert.DoesNotContain("ALTER TABLE", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("MigrateTransportOutbox", source, StringComparison.Ordinal);
        Assert.DoesNotContain("_v8_recovery", source, StringComparison.Ordinal);
        Assert.DoesNotContain("schema_meta", source, StringComparison.Ordinal);
        Assert.DoesNotContain("schema_values", source, StringComparison.Ordinal);
    }

    private static void AssertTamperRejected(string tamperSql)
    {
        var path = TempPath("tamper");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            SqliteConnection.ClearAllPools();
            using (var connection = Open(path))
            {
                Execute(connection, tamperSql);
            }
            var before = SnapshotFiles(path);

            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => new SqliteSessionStore(path));

            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            Assert.IsType<InvalidDataException>(exception.InnerException);
            AssertFilesEqual(before, path);
        }
        finally
        {
            DeleteFiles(path);
        }
    }

    private static string ReadCatalog(string path)
    {
        using var connection = Open(path);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT type, name, tbl_name, COALESCE(sql, ''), rootpage
            FROM sqlite_schema
            ORDER BY type, name;
            """;
        using var reader = command.ExecuteReader();
        var rows = new List<string>();
        while (reader.Read())
        {
            rows.Add(
                string.Join(
                    "\u001f",
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetInt32(4)));
        }
        return string.Join("\n", rows);
    }

    private static IReadOnlyDictionary<string, byte[]> SnapshotFiles(string path)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                using var stream = new FileStream(
                    candidate,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var bytes = new byte[stream.Length];
                stream.ReadExactly(bytes);
                result[candidate] = bytes;
            }
        }
        return result;
    }

    private static IReadOnlyDictionary<string, byte[]> SnapshotDurableFiles(string path)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var candidate in new[] { path, path + "-wal" })
        {
            if (File.Exists(candidate))
            {
                using var stream = new FileStream(
                    candidate,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                var bytes = new byte[stream.Length];
                stream.ReadExactly(bytes);
                result[candidate] = bytes;
            }
        }
        return result;
    }

    private static void AssertFilesEqual(
        IReadOnlyDictionary<string, byte[]> expected,
        string path)
    {
        var actual = SnapshotFiles(path);
        Assert.Equal(expected.Keys.Order(), actual.Keys.Order());
        foreach (var file in expected)
        {
            Assert.Equal(file.Value, actual[file.Key]);
        }
    }

    private static void AssertDurableFilesEqual(
        IReadOnlyDictionary<string, byte[]> expected,
        string path)
    {
        var actual = SnapshotDurableFiles(path);
        Assert.Equal(expected.Keys.Order(), actual.Keys.Order());
        foreach (var file in expected)
        {
            Assert.Equal(file.Value, actual[file.Key]);
        }
    }

    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false
            }.ToString());
        connection.Open();
        return connection;
    }

    private static long Scalar(SqliteConnection connection, string sql) =>
        Convert.ToInt64(ScalarObject(connection, sql), System.Globalization.CultureInfo.InvariantCulture);

    private static object? ScalarObject(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string TempPath(string name) =>
        Path.Combine(
            Path.GetTempPath(),
            $"deep-v10-{name}-{Guid.NewGuid():N}.db");

    private static void DeleteFiles(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
               && !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new DirectoryNotFoundException();
    }
}
