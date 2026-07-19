using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxMigrationPrivacyRedTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Fact]
    public async Task ScopePurgeRemovesOnlyMatchingQuarantinedV8RowsAcrossRestart()
    {
        var path = TempPath("scope-purge");
        try
        {
            CreateExactV8Fixture(path, populatedScopes: 2);
            var firstScope = Scope(0xB1);
            using (var store = new SqliteSessionStore(path))
            {
                await store.PurgeTransportOutboxScopeAsync(firstScope);
            }

            Assert.Equal((0L, 0L, 1L, 1L), ReadRecoveryCounts(path));
            using var restarted = new SqliteSessionStore(path);
            Assert.Equal((0L, 0L, 1L, 1L), ReadRecoveryCounts(path));
            await restarted.PurgeAccountDataAsync();
            Assert.Equal((0L, 0L, 0L, 0L), ReadRecoveryCounts(path));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task AccountPurgeRemovesAllQuarantinedV8Rows()
    {
        var path = TempPath("account-purge");
        try
        {
            CreateExactV8Fixture(path, populatedScopes: 2);
            using (var store = new SqliteSessionStore(path))
            {
                await store.PurgeAccountDataAsync();
            }

            using var restarted = new SqliteSessionStore(path);
            Assert.Equal((0L, 0L, 0L, 0L), ReadRecoveryCounts(path));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData("missing-ready-index")]
    [InlineData("missing-expiry-index")]
    [InlineData("wrong-ready-order")]
    [InlineData("wrong-expiry-order")]
    [InlineData("unique-ready-index")]
    [InlineData("partial-ready-index")]
    [InlineData("ready-index-on-wrong-table")]
    [InlineData("independent-foreign-keys")]
    [InlineData("foreign-key-update-cascade")]
    public void V9SchemaAttestationRejectsHostileIndexAndForeignKeyLayouts(string corruption)
    {
        var path = TempPath(corruption);
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = corruption switch
                {
                    "missing-ready-index" =>
                        "DROP INDEX idx_transport_outbox_ready;",
                    "missing-expiry-index" =>
                        "DROP INDEX idx_transport_outbox_expiry;",
                    "wrong-ready-order" => """
                        DROP INDEX idx_transport_outbox_ready;
                        CREATE INDEX idx_transport_outbox_ready
                            ON transport_outbox_items(
                                account_scope, not_before, state, expires_at, created_at);
                        """,
                    "wrong-expiry-order" => """
                        DROP INDEX idx_transport_outbox_expiry;
                        CREATE INDEX idx_transport_outbox_expiry
                            ON transport_outbox_items(account_scope, state, expires_at);
                        """,
                    "unique-ready-index" => """
                        DROP INDEX idx_transport_outbox_ready;
                        CREATE UNIQUE INDEX idx_transport_outbox_ready
                            ON transport_outbox_items(
                                account_scope, state, not_before, expires_at, created_at);
                        """,
                    "partial-ready-index" => """
                        DROP INDEX idx_transport_outbox_ready;
                        CREATE INDEX idx_transport_outbox_ready
                            ON transport_outbox_items(
                                account_scope, state, not_before, expires_at, created_at)
                            WHERE state > 0;
                        """,
                    "ready-index-on-wrong-table" => """
                        DROP INDEX idx_transport_outbox_ready;
                        CREATE TABLE hostile_index_owner (
                            account_scope BLOB,
                            state INTEGER,
                            not_before INTEGER,
                            expires_at INTEGER,
                            created_at INTEGER);
                        CREATE INDEX idx_transport_outbox_ready
                            ON hostile_index_owner(
                                account_scope, state, not_before, expires_at, created_at);
                        """,
                    "independent-foreign-keys" => """
                        PRAGMA foreign_keys=OFF;
                        DROP TABLE transport_outbox_attempts;
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
                            FOREIGN KEY(account_scope)
                                REFERENCES transport_outbox_items(account_scope)
                                ON DELETE CASCADE,
                            FOREIGN KEY(logical_id)
                                REFERENCES transport_outbox_items(logical_id)
                                ON DELETE CASCADE
                        );
                        PRAGMA foreign_keys=ON;
                        """,
                    "foreign-key-update-cascade" => """
                        PRAGMA foreign_keys=OFF;
                        DROP TABLE transport_outbox_attempts;
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
                                REFERENCES transport_outbox_items(account_scope, logical_id)
                                ON UPDATE CASCADE ON DELETE CASCADE
                        );
                        PRAGMA foreign_keys=ON;
                        """,
                    _ => throw new ArgumentOutOfRangeException(nameof(corruption))
                };
                command.ExecuteNonQuery();
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrivacyPurgeFailsClosedOnHostileRecoveryObjectWithoutDeletingActiveRows(
        bool accountPurge)
    {
        var path = TempPath(accountPurge ? "hostile-account-purge" : "hostile-scope-purge");
        try
        {
            var item = TransportOutboxPreparedItem.Create(
                Scope(0xD1),
                OutboxLogicalId.FromBytes(Bytes(16, 0xD2)),
                OutboxDedupMaterial.FromBytes(Bytes(32, 0xD3)),
                Bytes(64, 0xD4),
                Now,
                Now.AddHours(1),
                Now);
            using var store = new SqliteSessionStore(path);
            await store.PrepareTransportOutboxAsync(item);
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE VIEW transport_outbox_items_v8_recovery
                    AS SELECT 1 AS hostile;
                    """;
                command.ExecuteNonQuery();
            }

            if (accountPurge)
            {
                await Assert.ThrowsAnyAsync<Exception>(
                    () => store.PurgeAccountDataAsync());
            }
            else
            {
                await Assert.ThrowsAnyAsync<Exception>(
                    () => store.PurgeTransportOutboxScopeAsync(item.AccountScope));
            }

            using var verify = Open(path);
            Assert.Equal(
                1L,
                ScalarInt64(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void V8MigrationRejectsWrongOwnedIndexBeforeDropAndRollsBack()
    {
        var path = TempPath("wrong-v8-index");
        try
        {
            CreateExactV8Fixture(path, populatedScopes: 1);
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    DROP INDEX idx_transport_outbox_ready;
                    CREATE INDEX idx_transport_outbox_ready
                        ON transport_outbox_items(
                            logical_id, account_scope, state, not_before, expires_at);
                    """;
                command.ExecuteNonQuery();
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));
            using var verify = Open(path);
            Assert.Equal(8L, ScalarInt64(verify, "PRAGMA user_version;"));
            Assert.Equal(
                1L,
                ScalarInt64(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void V8MigrationAcceptsAbsentOptionalPhysicalIndexes()
    {
        var path = TempPath("absent-v8-indexes");
        try
        {
            CreateExactV8Fixture(path, populatedScopes: 0);
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    DROP INDEX idx_transport_outbox_ready;
                    DROP INDEX idx_transport_outbox_expiry;
                    """;
                command.ExecuteNonQuery();
            }

            using var store = new SqliteSessionStore(path);
            using var verify = Open(path);
            Assert.Equal(9L, ScalarInt64(verify, "PRAGMA user_version;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData("transport_outbox_items_v8_recovery", "table")]
    [InlineData("transport_outbox_items_v8_recovery", "view")]
    [InlineData("transport_outbox_items_v8_recovery", "index")]
    [InlineData("transport_outbox_items_v8_recovery", "trigger")]
    [InlineData("transport_outbox_attempts_v8_recovery", "table")]
    [InlineData("transport_outbox_attempts_v8_recovery", "view")]
    [InlineData("transport_outbox_attempts_v8_recovery", "index")]
    [InlineData("transport_outbox_attempts_v8_recovery", "trigger")]
    public void EmptyV8MigrationFailsClosedOnAnyRecoveryNameConflict(
        string recoveryName,
        string objectType)
    {
        var path = TempPath($"recovery-{objectType}");
        try
        {
            CreateExactV8Fixture(path, populatedScopes: 0);
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = objectType switch
                {
                    "table" => $"CREATE TABLE \"{recoveryName}\"(marker INTEGER);",
                    "view" => $"CREATE VIEW \"{recoveryName}\" AS SELECT 1 AS marker;",
                    "index" => $"CREATE INDEX \"{recoveryName}\" ON settings(key);",
                    "trigger" => $"""
                        CREATE TRIGGER "{recoveryName}"
                        AFTER INSERT ON settings
                        BEGIN SELECT 1; END;
                        """,
                    _ => throw new ArgumentOutOfRangeException(nameof(objectType))
                };
                command.ExecuteNonQuery();
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));
            using var verify = Open(path);
            Assert.Equal(8L, ScalarInt64(verify, "PRAGMA user_version;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void V8PresenceProbeUsesBoundedExistsInsteadOfCount()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Persistence",
            "SqliteSessionStore.cs"));

        Assert.DoesNotContain(
            "SELECT COUNT(*) FROM \\\"{tableName}\\\"",
            source,
            StringComparison.Ordinal);
        Assert.Contains("SELECT EXISTS(", source, StringComparison.Ordinal);
    }

    private static void CreateExactV8Fixture(string path, int populatedScopes)
    {
        using var connection = Open(path);
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
            INSERT INTO settings(key, payload_json)
            VALUES ('legacy.marker', '"preserved"');

            CREATE TABLE transport_outbox_items (
                account_scope BLOB NOT NULL,
                logical_id BLOB NOT NULL PRIMARY KEY,
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
                acknowledgement_evidence BLOB NULL
            );
            CREATE TABLE transport_outbox_attempts (
                logical_id BLOB NOT NULL,
                attempt_id BLOB NOT NULL,
                state INTEGER NOT NULL,
                transition_source INTEGER NOT NULL,
                transition_reason INTEGER NOT NULL,
                occurred_at INTEGER NOT NULL,
                evidence BLOB NOT NULL,
                PRIMARY KEY(logical_id, attempt_id),
                FOREIGN KEY(logical_id)
                    REFERENCES transport_outbox_items(logical_id) ON DELETE CASCADE
            );
            CREATE INDEX idx_transport_outbox_ready
                ON transport_outbox_items(
                    account_scope, state, not_before, expires_at, created_at);
            CREATE INDEX idx_transport_outbox_expiry
                ON transport_outbox_items(account_scope, expires_at, state);
            PRAGMA user_version=8;
            """;
        command.ExecuteNonQuery();

        for (var index = 0; index < populatedScopes; index++)
        {
            using var insertItem = connection.CreateCommand();
            insertItem.CommandText = """
                INSERT INTO transport_outbox_items (
                    account_scope, logical_id, dedup_material, ciphertext_bundle,
                    created_at, expires_at, not_before, state, revision,
                    transition_source, transition_reason, transitioned_at,
                    acknowledgement_evidence)
                VALUES (
                    $scope, $logicalId, $dedup, $ciphertext,
                    $createdAt, $expiresAt, $notBefore, 2, 2, 2, 2, $occurredAt, NULL);
                """;
            var scope = checked((byte)(0xB1 + index * 4));
            var logical = checked((byte)(0xB2 + index * 4));
            insertItem.Parameters.AddWithValue("$scope", Bytes(32, scope));
            insertItem.Parameters.AddWithValue("$logicalId", Bytes(16, logical));
            insertItem.Parameters.AddWithValue("$dedup", Bytes(32, 0xC1));
            insertItem.Parameters.AddWithValue("$ciphertext", Bytes(64, 0xC2));
            insertItem.Parameters.AddWithValue("$createdAt", Now.ToUnixTimeMilliseconds());
            insertItem.Parameters.AddWithValue(
                "$expiresAt",
                Now.AddHours(1).ToUnixTimeMilliseconds());
            insertItem.Parameters.AddWithValue("$notBefore", Now.ToUnixTimeMilliseconds());
            insertItem.Parameters.AddWithValue(
                "$occurredAt",
                Now.AddMinutes(1).ToUnixTimeMilliseconds());
            insertItem.ExecuteNonQuery();

            using var insertAttempt = connection.CreateCommand();
            insertAttempt.CommandText = """
                INSERT INTO transport_outbox_attempts (
                    logical_id, attempt_id, state, transition_source,
                    transition_reason, occurred_at, evidence)
                VALUES ($logicalId, $attemptId, 1, 2, 2, $occurredAt, X'');
                """;
            insertAttempt.Parameters.AddWithValue("$logicalId", Bytes(16, logical));
            insertAttempt.Parameters.AddWithValue(
                "$attemptId",
                Bytes(16, checked((byte)(0xB3 + index * 4))));
            insertAttempt.Parameters.AddWithValue(
                "$occurredAt",
                Now.AddMinutes(1).ToUnixTimeMilliseconds());
            insertAttempt.ExecuteNonQuery();
        }
    }

    private static (long FirstItems, long FirstAttempts, long OtherItems, long OtherAttempts)
        ReadRecoveryCounts(string path)
    {
        using var connection = Open(path);
        return (
            ScalarInt64(
                connection,
                "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery WHERE account_scope = X'" +
                Convert.ToHexString(Bytes(32, 0xB1)) + "';"),
            ScalarInt64(
                connection,
                "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery WHERE logical_id = X'" +
                Convert.ToHexString(Bytes(16, 0xB2)) + "';"),
            ScalarInt64(
                connection,
                "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery WHERE account_scope = X'" +
                Convert.ToHexString(Bytes(32, 0xB5)) + "';"),
            ScalarInt64(
                connection,
                "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery WHERE logical_id = X'" +
                Convert.ToHexString(Bytes(16, 0xB6)) + "';"));
    }

    private static long ScalarInt64(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static OutboxAccountScope Scope(byte value) =>
        OutboxAccountScope.FromBytes(Bytes(32, value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string TempPath(string name) =>
        Path.Combine(
            Path.GetTempPath(),
            $"deep-p11a-iteration3-{name}-{Guid.NewGuid():N}.db");

    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        return connection;
    }

    private static void DeleteSqliteFiles(string path)
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
