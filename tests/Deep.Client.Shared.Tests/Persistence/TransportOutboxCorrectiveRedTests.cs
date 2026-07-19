using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxCorrectiveRedTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00.1234567Z");

    [Fact]
    public async Task SameLogicalIdIsIndependentAcrossAccountScopes()
    {
        foreach (var sqlite in new[] { false, true })
        {
            using var scope = StoreScope.Create(sqlite);
            var first = Prepared(0x11, 0x41);
            var second = Prepared(0x12, 0x41);

            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await scope.Store.PrepareTransportOutboxAsync(first));
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await scope.Store.PrepareTransportOutboxAsync(second));
        }
    }

    [Fact]
    public void ReadApplyAndTransitionIdentityRequireAccountScope()
    {
        var read = typeof(ITransportOutboxRepository).GetMethods()
            .Single(method => method.Name == "ReadTransportOutboxAsync");
        var apply = typeof(ITransportOutboxRepository).GetMethods()
            .Single(method => method.Name == "ApplyTransportOutboxTransitionAsync");

        Assert.Equal(typeof(OutboxAccountScope), read.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(OutboxAccountScope), apply.GetParameters()[0].ParameterType);
        Assert.NotNull(typeof(TransportOutboxTransition).GetProperty("AccountScope"));
    }

    [Fact]
    public async Task SubMillisecondInputsAreCanonicalAndExactRetryIsIdempotent()
    {
        foreach (var sqlite in new[] { false, true })
        {
            using var scope = StoreScope.Create(sqlite);
            var item = Prepared(0x21, 0x51);
            var canonical = DateTimeOffset.FromUnixTimeMilliseconds(Now.ToUnixTimeMilliseconds());

            Assert.Equal(canonical, item.CreatedAt);
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await scope.Store.PrepareTransportOutboxAsync(item));
            scope.Restart();
            Assert.Equal(
                TransportOutboxCommitResult.Idempotent,
                await scope.Store.PrepareTransportOutboxAsync(item));
        }
    }

    [Fact]
    public async Task RetryNotBeforeAndFullAcknowledgementBindingAreExact()
    {
        using var scope = StoreScope.Create(sqlite: false);
        var item = Prepared(0x31, 0x61);
        await scope.Store.PrepareTransportOutboxAsync(item);
        var attempt = Attempt(0x62);
        var attempted = TransportOutboxTransition.Attempted(
            item.LogicalId,
            1,
            attempt,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted,
            Now.AddMinutes(1),
            Now.AddMinutes(2));
        await scope.Store.ApplyTransportOutboxTransitionAsync(attempted);
        var divergentRetry = TransportOutboxTransition.Attempted(
            item.LogicalId,
            1,
            attempt,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted,
            Now.AddMinutes(1),
            Now.AddMinutes(3));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(divergentRetry));

        await scope.Store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Accepted(
                item.LogicalId, 2, attempt, OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterAccepted, Now.AddMinutes(3),
                Now.AddMinutes(4), Bytes(16, 0x63)));
        await scope.Store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Durable(
                item.LogicalId, 3, attempt, OutboxTransitionSource.Adapter,
                OutboxTransitionReason.AdapterConfirmedDurable, Now.AddMinutes(5),
                Bytes(16, 0x64)));
        var ack = RecipientDeviceAcknowledgement.Create(
            item.LogicalId,
            item.DedupMaterial,
            Bytes(16, 0x65),
            Now.AddMinutes(6));
        await scope.Store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Delivered(
                item.LogicalId, 4, ack,
                OutboxTransitionReason.RecipientAcknowledged, Now.AddMinutes(6)));
        var divergentAck = RecipientDeviceAcknowledgement.Create(
            item.LogicalId,
            OutboxDedupMaterial.FromBytes(Bytes(32, 0x66)),
            Bytes(16, 0x65),
            Now.AddMinutes(6));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Delivered(
                    item.LogicalId, 4, divergentAck,
                    OutboxTransitionReason.RecipientAcknowledged, Now.AddMinutes(6))));
    }

    [Fact]
    public async Task PersistedAllZeroAndWrongProviderTypesReturnCorrupt()
    {
        var path = TempPath("corrupt");
        try
        {
            var item = Prepared(0x41, 0x71);
            using (var store = new SqliteSessionStore(path))
            {
                await store.PrepareTransportOutboxAsync(item);
            }
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE transport_outbox_items
                    SET account_scope = zeroblob(32),
                        ciphertext_bundle = 'wrong-provider-type'
                    WHERE logical_id = $logicalId;
                    """;
                command.Parameters.AddWithValue("$logicalId", item.LogicalId.ToArray());
                command.ExecuteNonQuery();
            }

            using var restarted = new SqliteSessionStore(path);
            Assert.Equal(
                TransportOutboxReadResult.Corrupt,
                (await restarted.ReadTransportOutboxAsync(item.LogicalId)).Result);
            Assert.Equal(
                TransportOutboxCommitResult.Corrupt,
                await restarted.PrepareTransportOutboxAsync(item));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task AttemptsCollectionCannotBeMutatedThroughRuntimeArray()
    {
        using var scope = StoreScope.Create(sqlite: false);
        var item = Prepared(0x51, 0x81);
        await scope.Store.PrepareTransportOutboxAsync(item);
        await scope.Store.ApplyTransportOutboxTransitionAsync(
            TransportOutboxTransition.Attempted(
                item.LogicalId, 1, Attempt(0x82), OutboxTransitionSource.Adapter,
                OutboxTransitionReason.DispatchStarted, Now.AddMinutes(1),
                Now.AddMinutes(2)));
        var snapshot = (await scope.Store.ReadTransportOutboxAsync(item.LogicalId)).Item!;
        var mutable = Assert.IsAssignableFrom<IList<TransportOutboxAttemptSnapshot>>(
            snapshot.Attempts);

        Assert.Throws<NotSupportedException>(() => mutable.Clear());
    }

    [Fact]
    public void CompatibilitySurfacesRemainSourceAndBinaryStable()
    {
        Assert.False(typeof(ITransportOutboxRepository).IsAssignableFrom(typeof(ILocalSessionStore)));
        Assert.NotNull(typeof(ClientFeatureFlags).GetConstructor(
        [
            typeof(bool), typeof(bool), typeof(bool), typeof(bool), typeof(bool),
            typeof(bool), typeof(bool), typeof(bool), typeof(bool), typeof(bool),
            typeof(bool)
        ]));
    }

    [Fact]
    public async Task SQLiteTransitionMutatesOnlyAffectedAttemptAndMetadata()
    {
        var path = TempPath("write-amplification");
        try
        {
            var item = Prepared(0x61, 0x91);
            var first = Attempt(0x92);
            using var store = new SqliteSessionStore(path);
            await store.PrepareTransportOutboxAsync(item);
            await store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Attempted(
                    item.LogicalId, 1, first, OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.DispatchStarted, Now.AddMinutes(1),
                    Now.AddMinutes(2)));
            using (var connection = Open(path))
            {
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE outbox_write_audit(kind TEXT NOT NULL);
                    CREATE TRIGGER audit_item_immutable
                    AFTER UPDATE OF account_scope, dedup_material, ciphertext_bundle,
                        created_at, expires_at ON transport_outbox_items
                    BEGIN INSERT INTO outbox_write_audit VALUES ('immutable'); END;
                    CREATE TRIGGER audit_attempt_delete
                    AFTER DELETE ON transport_outbox_attempts
                    BEGIN INSERT INTO outbox_write_audit VALUES ('attempt-delete'); END;
                    """;
                command.ExecuteNonQuery();
            }

            await store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Accepted(
                    item.LogicalId, 2, first, OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.AdapterAccepted, Now.AddMinutes(3),
                    Now.AddMinutes(4), Bytes(16, 0x93)));

            using var verify = Open(path);
            using var read = verify.CreateCommand();
            read.CommandText = "SELECT kind FROM outbox_write_audit ORDER BY rowid;";
            using var reader = read.ExecuteReader();
            Assert.False(reader.Read());
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void FileBackedInMemoryStoreRejectsOversizedSnapshotBeforeAdmission()
    {
        var path = TempPath("memory-json");
        try
        {
            File.WriteAllText(path, new string(' ', 9 * 1024 * 1024), Encoding.UTF8);

            Assert.Throws<TransportOutboxCorruptException>(
                () => new InMemorySessionStore(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void AttemptsReaderUsesBoundedSentinelInsteadOfCount()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Persistence",
            "SqliteTransportOutboxRepository.cs"));

        Assert.DoesNotContain("SELECT COUNT(*) FROM transport_outbox_attempts", source);
        Assert.Contains("MaxAttemptsPerItem + 1", source);
    }

    [Fact]
    public async Task TwoSqliteInstancesRaceTheSameRevisionWithSingleWinner()
    {
        var path = TempPath("two-instance-cas");
        try
        {
            var item = Prepared(0x71, 0xA1);
            using var first = new SqliteSessionStore(path);
            using var second = new SqliteSessionStore(path);
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await first.PrepareTransportOutboxAsync(item));

            var attempt = Attempt(0xA2);
            var transition = TransportOutboxTransition.Attempted(
                item.LogicalId,
                1,
                attempt,
                OutboxTransitionSource.Adapter,
                OutboxTransitionReason.DispatchStarted,
                Now.AddMinutes(1),
                Now.AddMinutes(2));
            var results = await Task.WhenAll(
                Task.Run(() => first.ApplyTransportOutboxTransitionAsync(transition)),
                Task.Run(() => second.ApplyTransportOutboxTransitionAsync(transition)));

            Assert.Equal(1, results.Count(result => result == TransportOutboxCommitResult.Applied));
            Assert.Equal(1, results.Count(result => result == TransportOutboxCommitResult.Idempotent));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void SqliteGraphReadIsExplicitlyTransactionBound()
    {
        var source = File.ReadAllText(Path.Combine(
            RepositoryRoot(),
            "src",
            "Deep.Client.Shared",
            "Persistence",
            "SqliteTransportOutboxRepository.cs"));
        var readStart = source.IndexOf(
            "public Task<TransportOutboxReadSnapshot> ReadTransportOutboxAsync(",
            StringComparison.Ordinal);
        var applyStart = source.IndexOf(
            "public Task<TransportOutboxCommitResult> ApplyTransportOutboxTransitionAsync(",
            readStart,
            StringComparison.Ordinal);
        var readImplementation = source[readStart..applyStart];

        Assert.Contains("BeginTransaction", readImplementation);
        Assert.Contains("transaction.Commit()", readImplementation);
    }

    private static TransportOutboxPreparedItem Prepared(byte scope, byte logical) =>
        TransportOutboxPreparedItem.Create(
            OutboxAccountScope.FromBytes(Bytes(32, scope)),
            OutboxLogicalId.FromBytes(Bytes(16, logical)),
            OutboxDedupMaterial.FromBytes(Bytes(32, 0x31)),
            Bytes(64, 0x32),
            Now,
            Now.AddHours(1),
            Now);

    private static OutboxAttemptId Attempt(byte value) =>
        OutboxAttemptId.FromBytes(Bytes(16, value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string TempPath(string name) =>
        Path.Combine(Path.GetTempPath(), $"deep-p11a-corrective-{name}-{Guid.NewGuid():N}.db");

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
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Deep.Client.Shared.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new DirectoryNotFoundException();
    }

    private sealed class StoreScope : IDisposable
    {
        private readonly bool sqlite;
        private StoreScope(bool sqlite)
        {
            this.sqlite = sqlite;
            Path = TempPath(sqlite ? "sqlite" : "memory");
            Store = OpenStore();
        }

        public string Path { get; }
        public ITransportOutboxRepository Store { get; private set; }

        public static StoreScope Create(bool sqlite) => new(sqlite);

        public void Restart()
        {
            (Store as IDisposable)?.Dispose();
            Store = OpenStore();
        }

        public void Dispose()
        {
            (Store as IDisposable)?.Dispose();
            if (sqlite)
            {
                DeleteSqliteFiles(Path);
            }
            else if (File.Exists(Path))
            {
                File.Delete(Path);
            }
        }

        private ITransportOutboxRepository OpenStore() =>
            sqlite ? new SqliteSessionStore(Path) : new InMemorySessionStore(Path);
    }
}
