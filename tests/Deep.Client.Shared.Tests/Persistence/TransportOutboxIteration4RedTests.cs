using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxIteration4RedTests
{
    private const int ExpectedMaxItemsPerScope = 200;
    private const int ExpectedMaxLogicalBytesPerScope = 8 * 1024 * 1024;
    private static readonly TransportOutboxCommitResult CapacityExceeded =
        (TransportOutboxCommitResult)4;
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Fact]
    public void V8MigrationRejectsTriggerBeforeRenameAndKeepsRowsAndVersion()
    {
        var path = TempPath("v8-trigger");
        try
        {
            CreateExactV8Fixture(path, populated: true);
            using (var connection = Open(path))
            {
                Execute(connection, """
                    CREATE TRIGGER hostile_v8_delete
                    BEFORE DELETE ON transport_outbox_items
                    BEGIN
                        SELECT RAISE(IGNORE);
                    END;
                    """);
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));
            using var verify = Open(path);
            Assert.Equal(8L, Scalar(verify, "PRAGMA user_version;"));
            Assert.Equal(1L, Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
            Assert.Equal(
                0L,
                Scalar(
                    verify,
                    """
                    SELECT COUNT(*) FROM sqlite_master
                    WHERE type='table' AND name='transport_outbox_items_v8_recovery';
                    """));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void V9OpenRejectsUpdateTriggerOnActiveOutboxTable()
    {
        var path = TempPath("v9-update-trigger");
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            using (var connection = Open(path))
            {
                Execute(connection, """
                    CREATE TRIGGER hostile_active_update
                    AFTER UPDATE ON transport_outbox_items
                    BEGIN
                        SELECT 1;
                    END;
                    """);
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void V9OpenRejectsRecoveryTriggerAndPreservesQuarantine()
    {
        var path = TempPath("v9-recovery-trigger");
        try
        {
            CreateExactV8Fixture(path, populated: true);
            using (var migrated = new SqliteSessionStore(path))
            {
            }
            using (var connection = Open(path))
            {
                Execute(connection, """
                    CREATE TRIGGER hostile_recovery_update
                    AFTER UPDATE ON transport_outbox_items_v8_recovery
                    BEGIN
                        DELETE FROM transport_outbox_attempts_v8_recovery;
                    END;
                    """);
            }

            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(path));

            using var verify = Open(path);
            Assert.Equal(9L, Scalar(verify, "PRAGMA user_version;"));
            Assert.Equal(
                1L,
                Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery;"));
            Assert.Equal(
                1L,
                Scalar(
                    verify,
                    "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PurgeRejectsRecoveryDeleteTriggerBeforeAnyMutation(bool afterDeleteCopy)
    {
        var path = TempPath(afterDeleteCopy ? "after-delete-copy" : "before-delete-ignore");
        try
        {
            CreateExactV8Fixture(path, populated: true);
            using var store = new SqliteSessionStore(path);
            var active = Prepared(Scope(0xB1), Logical(0xD1), ciphertextBytes: 64);
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await store.PrepareTransportOutboxAsync(active));

            using (var connection = Open(path))
            {
                Execute(connection, "CREATE TABLE hostile_copy(payload BLOB NOT NULL);");
                Execute(
                    connection,
                    afterDeleteCopy
                        ? """
                            CREATE TRIGGER hostile_recovery_after_delete
                            AFTER DELETE ON transport_outbox_items_v8_recovery
                            BEGIN
                                INSERT INTO hostile_copy(payload) VALUES (OLD.ciphertext_bundle);
                            END;
                            """
                        : """
                            CREATE TRIGGER hostile_recovery_before_delete
                            BEFORE DELETE ON transport_outbox_items_v8_recovery
                            BEGIN
                                SELECT RAISE(IGNORE);
                            END;
                            """);
            }

            await Assert.ThrowsAnyAsync<Exception>(
                () => afterDeleteCopy
                    ? store.PurgeAccountDataAsync()
                    : store.PurgeTransportOutboxScopeAsync(active.AccountScope));

            using var verify = Open(path);
            Assert.Equal(
                1L,
                Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery;"));
            Assert.Equal(
                1L,
                Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery;"));
            Assert.Equal(1L, Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
            Assert.Equal(0L, Scalar(verify, "SELECT COUNT(*) FROM hostile_copy;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData("extra-unique")]
    [InlineData("extra-nonunique")]
    [InlineData("extra-expression")]
    [InlineData("extra-partial")]
    [InlineData("hidden-generated")]
    public void V9OpenRejectsUnexpectedIndexesAndHiddenColumns(string corruption)
    {
        var path = TempPath(corruption);
        try
        {
            using (var store = new SqliteSessionStore(path))
            {
            }
            using (var connection = Open(path))
            {
                Execute(
                    connection,
                    corruption switch
                    {
                        "extra-unique" =>
                            "CREATE UNIQUE INDEX hostile_extra ON transport_outbox_items(logical_id);",
                        "extra-nonunique" =>
                            "CREATE INDEX hostile_extra ON transport_outbox_items(dedup_material);",
                        "extra-expression" =>
                            "CREATE INDEX hostile_extra ON transport_outbox_items(length(ciphertext_bundle));",
                        "extra-partial" => """
                            CREATE INDEX hostile_extra ON transport_outbox_items(logical_id)
                            WHERE state > 0;
                            """,
                        "hidden-generated" => """
                            ALTER TABLE transport_outbox_items
                            ADD COLUMN hostile_hidden INTEGER
                            GENERATED ALWAYS AS (length(ciphertext_bundle)) VIRTUAL;
                            """,
                        _ => throw new ArgumentOutOfRangeException(nameof(corruption))
                    });
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
    public async Task RecoveryOrphanFailsClosedAndPreservesActiveAndRecoveryRows(bool accountPurge)
    {
        var path = TempPath(accountPurge ? "orphan-account" : "orphan-scope");
        try
        {
            CreateExactV8Fixture(path, populated: true);
            using var store = new SqliteSessionStore(path);
            var active = Prepared(Scope(0xB1), Logical(0xD2), ciphertextBytes: 64);
            await store.PrepareTransportOutboxAsync(active);
            using (var connection = Open(path))
            {
                Execute(connection, "PRAGMA foreign_keys=OFF;");
                using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO transport_outbox_attempts_v8_recovery (
                        logical_id, attempt_id, state, transition_source,
                        transition_reason, occurred_at, evidence)
                    VALUES ($logicalId, $attemptId, 1, 2, 2, $occurredAt, X'');
                    """;
                insert.Parameters.AddWithValue("$logicalId", Bytes(16, 0xF1));
                insert.Parameters.AddWithValue("$attemptId", Bytes(16, 0xF2));
                insert.Parameters.AddWithValue(
                    "$occurredAt",
                    Now.AddMinutes(1).ToUnixTimeMilliseconds());
                insert.ExecuteNonQuery();
            }

            await Assert.ThrowsAnyAsync<Exception>(
                () => accountPurge
                    ? store.PurgeAccountDataAsync()
                    : store.PurgeTransportOutboxScopeAsync(active.AccountScope));

            using var verify = Open(path);
            Assert.Equal(
                1L,
                Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery;"));
            Assert.Equal(
                2L,
                Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery;"));
            Assert.Equal(1L, Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void ScopePurgeDeclaresSecureDeleteAndBoundedTruncateCheckpoint()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Persistence",
            "SqliteTransportOutboxRepository.cs"));
        var start = source.IndexOf(
            "public Task PurgeTransportOutboxScopeAsync(",
            StringComparison.Ordinal);
        var end = source.IndexOf(
            "private static TransportOutboxStoredItem? ReadTransportOutboxItem(",
            start,
            StringComparison.Ordinal);
        var implementation = source[start..end];

        Assert.Contains("EnableSqliteSecureDelete", implementation, StringComparison.Ordinal);
        Assert.Contains("RunPostScopePurgeMaintenanceBestEffort", implementation, StringComparison.Ordinal);
        Assert.Contains("busy_timeout=0", implementation, StringComparison.Ordinal);
        Assert.Contains("wal_checkpoint(TRUNCATE)", implementation, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScopePurgeCommitsLogicalDeletionWhenTruncateCheckpointIsBusy()
    {
        var path = TempPath("busy-checkpoint");
        try
        {
            CreateExactV8Fixture(path, populated: true);
            using var store = new SqliteSessionStore(path);
            var item = Prepared(Scope(0xB1), Logical(0xD2), ciphertextBytes: 4096);
            var unrelated = Prepared(Scope(0xD3), Logical(0xD4), ciphertextBytes: 4096);
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await store.PrepareTransportOutboxAsync(item));
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await store.PrepareTransportOutboxAsync(unrelated));

            using var readerConnection = Open(path);
            Execute(readerConnection, "BEGIN;");
            Assert.Equal(
                2L,
                Scalar(
                    readerConnection,
                    "SELECT COUNT(*) FROM transport_outbox_items;"));
            Assert.Equal(
                1L,
                Scalar(
                    readerConnection,
                    "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery;"));

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            await store.PurgeTransportOutboxScopeAsync(item.AccountScope);
            stopwatch.Stop();

            Assert.True(
                stopwatch.Elapsed < TimeSpan.FromSeconds(2),
                $"Busy checkpoint blocked purge for {stopwatch.Elapsed}.");
            Assert.Equal(
                TransportOutboxReadResult.Missing,
                (await store.ReadTransportOutboxAsync(
                    item.AccountScope,
                    item.LogicalId)).Result);
            Assert.Equal(
                TransportOutboxReadResult.Found,
                (await store.ReadTransportOutboxAsync(
                    unrelated.AccountScope,
                    unrelated.LogicalId)).Result);

            Execute(readerConnection, "COMMIT;");
            await store.PurgeTransportOutboxScopeAsync(item.AccountScope);
            using (var verify = Open(path))
            {
                Assert.Equal(
                    0L,
                    Scalar(
                        verify,
                        "SELECT COUNT(*) FROM transport_outbox_items_v8_recovery;"));
                Assert.Equal(
                    0L,
                    Scalar(
                        verify,
                        "SELECT COUNT(*) FROM transport_outbox_attempts_v8_recovery;"));
                Assert.Equal(
                    1L,
                    Scalar(verify, "SELECT COUNT(*) FROM transport_outbox_items;"));
            }
            Assert.False(
                File.Exists(path + "-wal") && new FileInfo(path + "-wal").Length > 0);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task ExpiryBoundaryIsHalfOpenForScheduleRetryAcknowledgementAndDelivery()
    {
        var scope = Scope(0xC1);
        var expiresAt = Now.AddHours(1);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TransportOutboxPreparedItem.Create(
                scope,
                Logical(0xC2),
                Dedup(0xC3),
                Bytes(32, 0xC4),
                Now,
                expiresAt,
                expiresAt));

        var retryItem = Prepared(scope, Logical(0xC5), ciphertextBytes: 32);
        var retryStore = new InMemorySessionStore();
        await retryStore.PrepareTransportOutboxAsync(retryItem);
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await retryStore.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Attempted(
                    retryItem.AccountScope,
                    retryItem.LogicalId,
                    1,
                    Attempt(0xC6),
                    OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.DispatchStarted,
                    Now.AddMinutes(1),
                    retryItem.ExpiresAt)));

        var ackAtExpiry = Prepared(scope, Logical(0xC7), ciphertextBytes: 32);
        var ackStore = new InMemorySessionStore();
        await AdvanceDurableAsync(ackStore, ackAtExpiry, Attempt(0xC8));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await ackStore.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Delivered(
                    ackAtExpiry.AccountScope,
                    ackAtExpiry.LogicalId,
                    4,
                    RecipientDeviceAcknowledgement.Create(
                        ackAtExpiry.LogicalId,
                        ackAtExpiry.DedupMaterial,
                        Bytes(16, 0xC9),
                        ackAtExpiry.ExpiresAt),
                    OutboxTransitionReason.RecipientAcknowledged,
                    ackAtExpiry.ExpiresAt)));

        var deliveryAtExpiry = Prepared(scope, Logical(0xCA), ciphertextBytes: 32);
        var deliveryStore = new InMemorySessionStore();
        await AdvanceDurableAsync(deliveryStore, deliveryAtExpiry, Attempt(0xCB));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await deliveryStore.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Delivered(
                    deliveryAtExpiry.AccountScope,
                    deliveryAtExpiry.LogicalId,
                    4,
                    RecipientDeviceAcknowledgement.Create(
                        deliveryAtExpiry.LogicalId,
                        deliveryAtExpiry.DedupMaterial,
                        Bytes(16, 0xCC),
                        deliveryAtExpiry.ExpiresAt.AddMilliseconds(-1)),
                    OutboxTransitionReason.RecipientAcknowledged,
                    deliveryAtExpiry.ExpiresAt)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueueItemAdmissionIsPerScopeAndExistingRowsRemainReconcilable(bool sqlite)
    {
        using var lease = StoreLease.Create(sqlite);
        var fullScope = Scope(0x31);
        var first = Prepared(fullScope, LogicalFromInt(1), ciphertextBytes: 1);
        await lease.Store.PrepareTransportOutboxAsync(first);
        await FillScopeAsync(
            lease,
            fullScope,
            start: 2,
            count: ExpectedMaxItemsPerScope - 1,
            ciphertextBytes: 1);

        Assert.Equal(
            TransportOutboxCommitResult.Idempotent,
            await lease.Store.PrepareTransportOutboxAsync(first));
        Assert.Equal(
            CapacityExceeded,
            await lease.Store.PrepareTransportOutboxAsync(
                Prepared(fullScope, Logical(0xE1), ciphertextBytes: 1)));

        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await lease.Store.PrepareTransportOutboxAsync(
                Prepared(Scope(0x32), Logical(0xE1), ciphertextBytes: 1)));
        Assert.Equal(
            TransportOutboxReadResult.Found,
            (await lease.Store.ReadTransportOutboxAsync(
                first.AccountScope,
                first.LogicalId)).Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueueLogicalByteAdmissionIsPerScope(bool sqlite)
    {
        using var lease = StoreLease.Create(sqlite);
        var scope = Scope(0x41);
        const int itemBytes = 1024 * 1024;
        await FillScopeAsync(
            lease,
            scope,
            start: 1,
            count: ExpectedMaxLogicalBytesPerScope / itemBytes,
            ciphertextBytes: itemBytes);

        Assert.Equal(
            CapacityExceeded,
            await lease.Store.PrepareTransportOutboxAsync(
                Prepared(scope, Logical(0xE2), ciphertextBytes: 1)));
        await lease.Store.PurgeTransportOutboxScopeAsync(scope);
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await lease.Store.PrepareTransportOutboxAsync(
                Prepared(scope, Logical(0xE2), ciphertextBytes: 1)));
    }

    private static async Task FillScopeAsync(
        StoreLease lease,
        OutboxAccountScope scope,
        int start,
        int count,
        int ciphertextBytes)
    {
        if (lease.Path is not null)
        {
            InsertPreparedRows(lease.Path, scope, start, count, ciphertextBytes);
            return;
        }

        for (var index = start; index < start + count; index++)
        {
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await lease.Store.PrepareTransportOutboxAsync(
                    Prepared(scope, LogicalFromInt(index), ciphertextBytes)));
        }
    }

    private static void InsertPreparedRows(
        string path,
        OutboxAccountScope scope,
        int start,
        int count,
        int ciphertextBytes)
    {
        using var connection = Open(path);
        using var transaction = connection.BeginTransaction();
        for (var index = start; index < start + count; index++)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO transport_outbox_items (
                    account_scope, logical_id, dedup_material, ciphertext_bundle,
                    created_at, expires_at, not_before, state, revision,
                    transition_source, transition_reason, transitioned_at,
                    last_transition_state, last_attempt_id, last_retry_not_before,
                    acknowledgement_evidence, acknowledged_at)
                VALUES (
                    $scope, $logicalId, $dedup, zeroblob($ciphertextBytes),
                    $createdAt, $expiresAt, $notBefore, 1, 1, 1, 1, $createdAt,
                    1, NULL, NULL, NULL, NULL);
                """;
            command.Parameters.AddWithValue("$scope", scope.ToArray());
            command.Parameters.AddWithValue("$logicalId", LogicalFromInt(index).ToArray());
            command.Parameters.AddWithValue("$dedup", DedupFromInt(index).ToArray());
            command.Parameters.AddWithValue("$ciphertextBytes", ciphertextBytes);
            command.Parameters.AddWithValue("$createdAt", Now.ToUnixTimeMilliseconds());
            command.Parameters.AddWithValue("$expiresAt", Now.AddHours(1).ToUnixTimeMilliseconds());
            command.Parameters.AddWithValue("$notBefore", Now.ToUnixTimeMilliseconds());
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    private static async Task AdvanceDurableAsync(
        ITransportOutboxRepository store,
        TransportOutboxPreparedItem item,
        OutboxAttemptId attempt)
    {
        await store.PrepareTransportOutboxAsync(item);
        await store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Attempted(
                item.AccountScope,
                item.LogicalId,
                1,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.DispatchStarted,
                Now.AddMinutes(1),
                Now.AddMinutes(2)));
        await store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Accepted(
                item.AccountScope,
                item.LogicalId,
                2,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterAccepted,
                Now.AddMinutes(2),
                Now.AddMinutes(3),
                Bytes(16, 0xD4)));
        await store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Durable(
                item.AccountScope,
                item.LogicalId,
                3,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterConfirmedDurable,
                Now.AddMinutes(3),
                Bytes(16, 0xD5)));
    }

    private static TransportOutboxPreparedItem Prepared(
        OutboxAccountScope scope,
        OutboxLogicalId logicalId,
        int ciphertextBytes) =>
        TransportOutboxPreparedItem.Create(
            scope,
            logicalId,
            DedupFromInt(logicalId.ToArray()[^1] + 1),
            Bytes(ciphertextBytes, 0xA5),
            Now,
            Now.AddHours(1),
            Now);

    private static void CreateExactV8Fixture(string path, bool populated)
    {
        using var connection = Open(path);
        Execute(connection, """
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
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
            """);
        if (!populated)
        {
            return;
        }

        using var item = connection.CreateCommand();
        item.CommandText = """
            INSERT INTO transport_outbox_items (
                account_scope, logical_id, dedup_material, ciphertext_bundle,
                created_at, expires_at, not_before, state, revision,
                transition_source, transition_reason, transitioned_at,
                acknowledgement_evidence)
            VALUES (
                $scope, $logicalId, $dedup, $ciphertext,
                $createdAt, $expiresAt, $notBefore, 2, 2, 2, 2, $occurredAt, NULL);
            """;
        item.Parameters.AddWithValue("$scope", Scope(0xB1).ToArray());
        item.Parameters.AddWithValue("$logicalId", Logical(0xB2).ToArray());
        item.Parameters.AddWithValue("$dedup", Dedup(0xB3).ToArray());
        item.Parameters.AddWithValue("$ciphertext", Bytes(64, 0xB4));
        item.Parameters.AddWithValue("$createdAt", Now.ToUnixTimeMilliseconds());
        item.Parameters.AddWithValue("$expiresAt", Now.AddHours(1).ToUnixTimeMilliseconds());
        item.Parameters.AddWithValue("$notBefore", Now.ToUnixTimeMilliseconds());
        item.Parameters.AddWithValue("$occurredAt", Now.AddMinutes(1).ToUnixTimeMilliseconds());
        item.ExecuteNonQuery();

        using var attempt = connection.CreateCommand();
        attempt.CommandText = """
            INSERT INTO transport_outbox_attempts (
                logical_id, attempt_id, state, transition_source,
                transition_reason, occurred_at, evidence)
            VALUES ($logicalId, $attemptId, 1, 2, 2, $occurredAt, X'');
            """;
        attempt.Parameters.AddWithValue("$logicalId", Logical(0xB2).ToArray());
        attempt.Parameters.AddWithValue("$attemptId", Attempt(0xB5).ToArray());
        attempt.Parameters.AddWithValue("$occurredAt", Now.AddMinutes(1).ToUnixTimeMilliseconds());
        attempt.ExecuteNonQuery();
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(
            command.ExecuteScalar(),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static OutboxAccountScope Scope(byte value) =>
        OutboxAccountScope.FromBytes(Bytes(32, value));

    private static OutboxLogicalId Logical(byte value) =>
        OutboxLogicalId.FromBytes(Bytes(16, value));

    private static OutboxLogicalId LogicalFromInt(int value)
    {
        var bytes = new byte[16];
        BitConverter.TryWriteBytes(bytes.AsSpan(8), value);
        bytes[0] = 0x7A;
        return OutboxLogicalId.FromBytes(bytes);
    }

    private static OutboxDedupMaterial Dedup(byte value) =>
        OutboxDedupMaterial.FromBytes(Bytes(32, value));

    private static OutboxDedupMaterial DedupFromInt(int value)
    {
        var bytes = new byte[32];
        BitConverter.TryWriteBytes(bytes.AsSpan(24), value);
        bytes[0] = 0x6B;
        return OutboxDedupMaterial.FromBytes(bytes);
    }

    private static OutboxAttemptId Attempt(byte value) =>
        OutboxAttemptId.FromBytes(Bytes(16, value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string TempPath(string name) =>
        Path.Combine(
            Path.GetTempPath(),
            $"deep-p11a-iteration4-{name}-{Guid.NewGuid():N}.db");

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

    private sealed class StoreLease(
        ITransportOutboxRepository store,
        IDisposable? disposable,
        string? path)
        : IDisposable
    {
        public ITransportOutboxRepository Store { get; } = store;
        public string? Path { get; } = path;

        public static StoreLease Create(bool sqlite)
        {
            if (!sqlite)
            {
                return new StoreLease(new InMemorySessionStore(), null, null);
            }
            var path = TempPath("admission");
            var store = new SqliteSessionStore(path);
            return new StoreLease(store, store, path);
        }

        public void Dispose()
        {
            disposable?.Dispose();
            if (Path is not null)
            {
                DeleteSqliteFiles(Path);
            }
        }
    }
}
