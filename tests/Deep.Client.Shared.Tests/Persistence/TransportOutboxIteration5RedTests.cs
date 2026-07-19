using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxIteration5RedTests
{
    private const string EncryptionKeyCanary =
        "p11a-iter5-encryption-key-canary-7f6219ce";
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Fact]
    public async Task ScopePurgeRemovesActiveOrphanAttemptsAndPreservesUnrelatedScope()
    {
        var path = TempPath("active-orphan");
        try
        {
            var target = Prepared(0xB1, 0xD1);
            var unrelated = Prepared(0xB2, 0xD2);
            using (var store = new SqliteSessionStore(path))
            {
                await PrepareAttemptedAsync(store, target, 0xE1);
                await PrepareAttemptedAsync(store, unrelated, 0xE2);
            }
            InsertActiveOrphan(path, target.AccountScope, 0xD3, 0xE3);

            using (var store = new SqliteSessionStore(path))
            {
                await store.PurgeTransportOutboxScopeAsync(target.AccountScope);
            }

            using (var verify = Open(path))
            {
                Assert.Equal(
                    0L,
                    ScopedCount(verify, "transport_outbox_items", target.AccountScope));
                Assert.Equal(
                    0L,
                    ScopedCount(verify, "transport_outbox_attempts", target.AccountScope));
                Assert.Equal(
                    1L,
                    ScopedCount(verify, "transport_outbox_items", unrelated.AccountScope));
                Assert.Equal(
                    1L,
                    ScopedCount(verify, "transport_outbox_attempts", unrelated.AccountScope));
            }

            using var restarted = new SqliteSessionStore(path);
            Assert.Equal(
                TransportOutboxReadResult.Missing,
                (await restarted.ReadTransportOutboxAsync(
                    target.AccountScope,
                    target.LogicalId)).Result);
            Assert.Equal(
                TransportOutboxReadResult.Found,
                (await restarted.ReadTransportOutboxAsync(
                    unrelated.AccountScope,
                    unrelated.LogicalId)).Result);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task ActiveAttemptTriggerFailsScopePurgeBeforeAnyMutation()
    {
        var path = TempPath("active-trigger-rollback");
        try
        {
            var target = Prepared(0xC1, 0xE1);
            var unrelated = Prepared(0xC2, 0xE2);
            using var store = new SqliteSessionStore(path);
            await PrepareAttemptedAsync(store, target, 0xF1);
            await PrepareAttemptedAsync(store, unrelated, 0xF2);
            InsertActiveOrphan(path, target.AccountScope, 0xE3, 0xF3);
            using (var connection = Open(path))
            {
                Execute(connection, """
                    CREATE TRIGGER hostile_active_attempt_delete
                    BEFORE DELETE ON transport_outbox_attempts
                    BEGIN
                        SELECT RAISE(IGNORE);
                    END;
                    """);
            }

            await Assert.ThrowsAnyAsync<Exception>(
                () => store.PurgeTransportOutboxScopeAsync(target.AccountScope));

            using var verify = Open(path);
            Assert.Equal(
                1L,
                ScopedCount(verify, "transport_outbox_items", target.AccountScope));
            Assert.Equal(
                2L,
                ScopedCount(verify, "transport_outbox_attempts", target.AccountScope));
            Assert.Equal(
                1L,
                ScopedCount(verify, "transport_outbox_items", unrelated.AccountScope));
            Assert.Equal(
                1L,
                ScopedCount(verify, "transport_outbox_attempts", unrelated.AccountScope));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void SqliteOptionsDiagnosticsRedactEncryptionKeyAtEveryNestedSurface()
    {
        var options = new SqliteSessionStoreOptions(
            Path.Combine(Path.GetTempPath(), "p11a-options-diagnostics.db"),
            EncryptionKeyCanary);
        var constructionException = Assert.Throws<ArgumentException>(
            () => new SqliteSessionStore(
                new SqliteSessionStoreOptions(string.Empty, EncryptionKeyCanary)));

        var text = options.ToString();
        var nestedText = new
        {
            Options = options,
            StoreException = constructionException
        }.ToString();
        var structured = JsonSerializer.Serialize(new
        {
            Options = options,
            StoreException = constructionException.ToString()
        });
        var debuggerDisplay = typeof(SqliteSessionStoreOptions)
            .GetCustomAttribute<DebuggerDisplayAttribute>();

        Assert.DoesNotContain(EncryptionKeyCanary, text, StringComparison.Ordinal);
        Assert.DoesNotContain(EncryptionKeyCanary, nestedText, StringComparison.Ordinal);
        Assert.DoesNotContain(EncryptionKeyCanary, structured, StringComparison.Ordinal);
        Assert.Contains("[redacted]", text, StringComparison.Ordinal);
        Assert.NotNull(debuggerDisplay);
        Assert.Equal("{ToString(),nq}", debuggerDisplay.Value);
        Assert.DoesNotContain(
            typeof(SqliteSessionStoreOptions).GetMethods(),
            method => method.Name == "Deconstruct");
    }

    private static async Task PrepareAttemptedAsync(
        ITransportOutboxRepository store,
        TransportOutboxPreparedItem item,
        byte attempt)
    {
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await store.PrepareTransportOutboxAsync(item));
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Attempted(
                    item.AccountScope,
                    item.LogicalId,
                    1,
                    OutboxAttemptId.FromBytes(Bytes(16, attempt)),
                    OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.DispatchStarted,
                    Now.AddMinutes(1),
                    Now.AddMinutes(2))));
    }

    private static void InsertActiveOrphan(
        string path,
        OutboxAccountScope scope,
        byte logical,
        byte attempt)
    {
        using var connection = Open(path);
        Execute(connection, "PRAGMA foreign_keys=OFF;");
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO transport_outbox_attempts (
                account_scope, logical_id, attempt_id, state,
                transition_source, transition_reason, occurred_at, evidence)
            VALUES (
                $scope, $logicalId, $attemptId, 2,
                2, 3, $occurredAt, $evidence);
            """;
        command.Parameters.AddWithValue("$scope", scope.ToArray());
        command.Parameters.AddWithValue("$logicalId", Bytes(16, logical));
        command.Parameters.AddWithValue("$attemptId", Bytes(16, attempt));
        command.Parameters.AddWithValue(
            "$occurredAt",
            Now.AddMinutes(1).ToUnixTimeMilliseconds());
        command.Parameters.AddWithValue("$evidence", Bytes(32, 0xFA));
        command.ExecuteNonQuery();
    }

    private static long ScopedCount(
        SqliteConnection connection,
        string table,
        OutboxAccountScope scope)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {table} WHERE account_scope = $scope;";
        command.Parameters.AddWithValue("$scope", scope.ToArray());
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static TransportOutboxPreparedItem Prepared(byte scope, byte logical) =>
        TransportOutboxPreparedItem.Create(
            OutboxAccountScope.FromBytes(Bytes(32, scope)),
            OutboxLogicalId.FromBytes(Bytes(16, logical)),
            OutboxDedupMaterial.FromBytes(Bytes(32, 0xA1)),
            Bytes(64, 0xA2),
            Now,
            Now.AddHours(1),
            Now);

    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection($"Data Source={path}");
        connection.Open();
        return connection;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string TempPath(string name) =>
        Path.Combine(
            Path.GetTempPath(),
            $"deep-p11a-iter5-{name}-{Guid.NewGuid():N}.db");

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
}
