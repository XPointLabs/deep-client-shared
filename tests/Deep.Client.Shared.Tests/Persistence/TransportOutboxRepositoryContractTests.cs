using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class TransportOutboxRepositoryContractTests
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RestartAtEveryTransitionPreservesMonotonicState(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var prepared = Prepared();
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.PrepareTransportOutboxAsync(prepared));
        await AssertRestartedStateAsync(scope, TransportOutboxState.Prepared, 1);

        var attempt = Attempt(0x61);
        var attempted = TransportOutboxTransition.Attempted(
            prepared.AccountScope,
            prepared.LogicalId,
            1,
            attempt,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted,
            Now.AddMinutes(1),
            Now.AddMinutes(2));
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.ApplyTransportOutboxTransitionAsync(attempted));
        await AssertRestartedStateAsync(scope, TransportOutboxState.Attempted, 2);
        Assert.Equal(
            TransportOutboxCommitResult.Idempotent,
            await scope.Store.ApplyTransportOutboxTransitionAsync(attempted));

        var accepted = TransportOutboxTransition.Accepted(
            prepared.AccountScope,
            prepared.LogicalId,
            2,
            attempt,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterAccepted,
            Now.AddMinutes(3),
            Now.AddMinutes(4),
            Bytes(32, 0x62));
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.ApplyTransportOutboxTransitionAsync(accepted));
        await AssertRestartedStateAsync(scope, TransportOutboxState.Accepted, 3);

        var durable = TransportOutboxTransition.Durable(
            prepared.AccountScope,
            prepared.LogicalId,
            3,
            attempt,
            OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterConfirmedDurable,
            Now.AddMinutes(5),
            Bytes(32, 0x63));
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.ApplyTransportOutboxTransitionAsync(durable));
        await AssertRestartedStateAsync(scope, TransportOutboxState.Durable, 4);

        var acknowledgement = RecipientDeviceAcknowledgement.Create(
            prepared.LogicalId,
            prepared.DedupMaterial,
            Bytes(48, 0x64),
            Now.AddMinutes(6));
        var delivered = TransportOutboxTransition.Delivered(
            prepared.AccountScope,
            prepared.LogicalId,
            4,
            acknowledgement,
            OutboxTransitionReason.RecipientAcknowledged,
            Now.AddMinutes(6));
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.ApplyTransportOutboxTransitionAsync(delivered));
        var terminal = await AssertRestartedStateAsync(
            scope,
            TransportOutboxState.Delivered,
            5);
        Assert.Equal(acknowledgement.GetEvidenceCopy(), terminal.GetAcknowledgementEvidenceCopy());

        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Expired(
                    prepared.AccountScope,
                    prepared.LogicalId,
                    5,
                    prepared.ExpiresAt.AddMinutes(1))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SimultaneousAttemptSuccessAdvancesOneLogicalDurableState(bool sqlite)
    {
        using var firstCommitEntered = new ManualResetEventSlim();
        using var releaseFirstCommit = new ManualResetEventSlim();
        var gateEnabled = false;
        var gateCalls = 0;
        using var scope = StoreScope.Create(
            sqlite,
            point =>
            {
                if (gateEnabled
                    && point == TransportOutboxCommitFaultPoint.BeforeDurableCommit
                    && Interlocked.Increment(ref gateCalls) == 1)
                {
                    firstCommitEntered.Set();
                    releaseFirstCommit.Wait(TimeSpan.FromSeconds(5));
                }
            });
        var item = Prepared();
        await scope.Store.PrepareTransportOutboxAsync(item);
        var first = Attempt(0x71);
        var second = Attempt(0x72);
        await scope.Store.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Attempted(
            item.AccountScope,
            item.LogicalId, 1, first, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted, Now.AddMinutes(1), Now.AddMinutes(2)));
        await scope.Store.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Attempted(
            item.AccountScope,
            item.LogicalId, 2, second, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted, Now.AddMinutes(2), Now.AddMinutes(3)));
        await scope.Store.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Accepted(
            item.AccountScope,
            item.LogicalId, 3, first, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterAccepted, Now.AddMinutes(3), Now.AddMinutes(4),
            Bytes(16, 0x73)));
        await scope.Store.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Accepted(
            item.AccountScope,
            item.LogicalId, 4, second, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterAccepted, Now.AddMinutes(4), Now.AddMinutes(5),
            Bytes(16, 0x74)));

        var firstSuccess = TransportOutboxTransition.Durable(
            item.AccountScope,
            item.LogicalId, 5, first, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterConfirmedDurable, Now.AddMinutes(6),
            Bytes(16, 0x75));
        var secondSuccess = TransportOutboxTransition.Durable(
            item.AccountScope,
            item.LogicalId, 5, second, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.AdapterConfirmedDurable, Now.AddMinutes(6),
            Bytes(16, 0x76));
        gateEnabled = true;
        var firstTask = Task.Run(
            () => scope.Store.ApplyTransportOutboxTransitionAsync(firstSuccess));
        Assert.True(firstCommitEntered.Wait(TimeSpan.FromSeconds(5)));
        var secondTask = Task.Run(
            () => scope.Store.ApplyTransportOutboxTransitionAsync(secondSuccess));
        releaseFirstCommit.Set();
        var results = await Task.WhenAll(firstTask, secondTask);

        Assert.Single(results, result => result == TransportOutboxCommitResult.Applied);
        Assert.Single(results, result => result == TransportOutboxCommitResult.Conflict);
        var read = await scope.Store.ReadTransportOutboxAsync(item.AccountScope, item.LogicalId);
        Assert.Equal(TransportOutboxState.Durable, read.Item?.State);
        Assert.Equal((ulong)6, read.Item?.Revision);
        Assert.Equal(2, read.Item?.Attempts.Count);
        Assert.Single(read.Item!.Attempts, attempt =>
            attempt.State == TransportOutboxAttemptState.Durable);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DivergentReuseAndRegressionFailClosed(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var item = Prepared();
        Assert.Equal(
            TransportOutboxCommitResult.Applied,
            await scope.Store.PrepareTransportOutboxAsync(item));
        var divergent = TransportOutboxPreparedItem.Create(
            item.AccountScope,
            item.LogicalId,
            item.DedupMaterial,
            Bytes(64, 0x7f),
            item.CreatedAt,
            item.ExpiresAt,
            item.NotBefore);
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.PrepareTransportOutboxAsync(divergent));

        var attempt = Attempt(0x81);
        await scope.Store.ApplyTransportOutboxTransitionAsync(TransportOutboxTransition.Attempted(
            item.AccountScope,
            item.LogicalId, 1, attempt, OutboxTransitionSource.Adapter,
            OutboxTransitionReason.DispatchStarted, Now.AddMinutes(1), Now.AddMinutes(2)));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Attempted(
                    item.AccountScope,
                    item.LogicalId, 2, attempt, OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.RetryScheduled, Now.AddMinutes(2), Now.AddMinutes(3))));
        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Durable(
                    item.AccountScope,
                    item.LogicalId, 2, attempt, OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.AdapterConfirmedDurable, Now.AddMinutes(3),
                    Bytes(16, 0x82))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiryAndRetryListingAreBoundedAndTerminal(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var ready = Prepared(logical: 0x21, notBefore: Now);
        var delayed = Prepared(logical: 0x22, notBefore: Now.AddMinutes(30));
        var expired = Prepared(
            logical: 0x23,
            created: Now.AddHours(-2),
            expires: Now.AddHours(-1),
            notBefore: Now.AddHours(-2));
        await scope.Store.PrepareTransportOutboxAsync(ready);
        await scope.Store.PrepareTransportOutboxAsync(delayed);
        await scope.Store.PrepareTransportOutboxAsync(expired);

        var listed = await scope.Store.ListReadyTransportOutboxAsync(
            ready.AccountScope,
            Now,
            1);
        Assert.Single(listed);
        Assert.Equal(ready.LogicalId, listed[0].LogicalId);
        Assert.Equal(1, await scope.Store.ExpireDueTransportOutboxAsync(
            ready.AccountScope,
            Now,
            1));
        var expiredRead = await scope.Store.ReadTransportOutboxAsync(
            expired.AccountScope,
            expired.LogicalId);
        Assert.Equal(TransportOutboxState.Expired, expiredRead.Item?.State);
        var remaining = await scope.Store.ListReadyTransportOutboxAsync(
            ready.AccountScope,
            Now,
            TransportOutboxLimits.MaxListCount);
        Assert.Single(remaining);
        Assert.Equal(ready.LogicalId, remaining[0].LogicalId);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => scope.Store.ListReadyTransportOutboxAsync(
                ready.AccountScope,
                Now,
                TransportOutboxLimits.MaxListCount + 1));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ScopePurgeAndAccountPurgeRemoveOutboxWithoutCrossScopeLeak(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var first = Prepared(scope: 0x31, logical: 0x41);
        var second = Prepared(scope: 0x32, logical: 0x42);
        await scope.Store.PrepareTransportOutboxAsync(first);
        await scope.Store.PrepareTransportOutboxAsync(second);

        await scope.Store.PurgeTransportOutboxScopeAsync(first.AccountScope);
        Assert.Equal(
            TransportOutboxReadResult.Missing,
            (await scope.Store.ReadTransportOutboxAsync(
                first.AccountScope,
                first.LogicalId)).Result);
        Assert.Equal(
            TransportOutboxReadResult.Found,
            (await scope.Store.ReadTransportOutboxAsync(
                second.AccountScope,
                second.LogicalId)).Result);

        await ((IAccountDataPurger)scope.Store).PurgeAccountDataAsync();
        Assert.Equal(
            TransportOutboxReadResult.Missing,
            (await scope.Store.ReadTransportOutboxAsync(
                second.AccountScope,
                second.LogicalId)).Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReturnedBuffersAreDefensiveCopies(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var source = Bytes(64, 0x91);
        var item = TransportOutboxPreparedItem.Create(
            Scope(0x90),
            Logical(0x91),
            Dedup(0x92),
            source,
            Now,
            Now.AddHours(1),
            Now);
        source[0] = 0;
        await scope.Store.PrepareTransportOutboxAsync(item);

        var first = (await scope.Store.ReadTransportOutboxAsync(
            item.AccountScope,
            item.LogicalId)).Item!;
        var copy = first.GetCiphertextBundleCopy();
        Assert.Equal(0x91, copy[0]);
        copy[0] = 0;
        var second = (await scope.Store.ReadTransportOutboxAsync(
            item.AccountScope,
            item.LogicalId)).Item!;
        Assert.Equal(0x91, second.GetCiphertextBundleCopy()[0]);
    }

    [Fact]
    public async Task CancellationBeforeAndFailureAfterDurablePointAreExplicit()
    {
        foreach (var sqlite in new[] { false, true })
        {
            using var beforeCancellation = new CancellationTokenSource();
            using var before = StoreScope.Create(
                sqlite,
                point =>
                {
                    if (point == TransportOutboxCommitFaultPoint.BeforeDurableCommit)
                    {
                        beforeCancellation.Cancel();
                    }
                });
            var item = Prepared(logical: sqlite ? (byte)0xa1 : (byte)0xa2);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => before.Store.PrepareTransportOutboxAsync(
                    item,
                    beforeCancellation.Token));
            Assert.Equal(
                TransportOutboxReadResult.Missing,
                (await before.Store.ReadTransportOutboxAsync(
                    item.AccountScope,
                    item.LogicalId)).Result);

            using var after = StoreScope.Create(
                sqlite,
                point =>
                {
                    if (point == TransportOutboxCommitFaultPoint.AfterDurableCommit)
                    {
                        throw new IOException("simulated post-commit loss");
                    }
                });
            var committed = Prepared(logical: sqlite ? (byte)0xa3 : (byte)0xa4);
            await Assert.ThrowsAsync<TransportOutboxCommitOutcomeUnknownException>(
                () => after.Store.PrepareTransportOutboxAsync(committed));
            Assert.Equal(
                TransportOutboxReadResult.Found,
                (await after.Store.ReadTransportOutboxAsync(
                    committed.AccountScope,
                    committed.LogicalId)).Result);
            Assert.Equal(
                TransportOutboxCommitResult.Idempotent,
                await after.Store.PrepareTransportOutboxAsync(committed));
        }
    }

    [Fact]
    public async Task SqliteMigratesPopulatedV7WithoutTouchingExistingRowsAndRejectsNewerSchema()
    {
        var path = TempPath("migration");
        try
        {
            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL
                    );
                    INSERT INTO settings(key, payload_json)
                    VALUES ('legacy.marker', '"preserved"');
                    PRAGMA user_version=7;
                    """;
                command.ExecuteNonQuery();
            }

            using (var store = new SqliteSessionStore(path))
            {
                Assert.Equal("preserved", await store.GetAsync<string>("legacy.marker"));
            }
            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    SELECT
                        (SELECT user_version FROM pragma_user_version),
                        (SELECT payload_json FROM settings WHERE key='legacy.marker'),
                        (SELECT COUNT(*) FROM sqlite_master
                            WHERE type='table' AND name='transport_outbox_items');
                    """;
                using var reader = command.ExecuteReader();
                Assert.True(reader.Read());
                Assert.Equal(9, reader.GetInt32(0));
                Assert.Equal("\"preserved\"", reader.GetString(1));
                Assert.Equal(1, reader.GetInt32(2));
            }

            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA user_version=10;";
                command.ExecuteNonQuery();
            }
            Assert.Throws<InvalidOperationException>(() => new SqliteSessionStore(path));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task SqliteRejectsOversizedPersistedBlobBeforeIdempotencyDecision()
    {
        var path = TempPath("corrupt");
        try
        {
            var item = Prepared();
            using (var store = new SqliteSessionStore(path))
            {
                await store.PrepareTransportOutboxAsync(item);
            }
            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE transport_outbox_items
                    SET ciphertext_bundle = zeroblob($length)
                    WHERE logical_id = $logicalId;
                    """;
                command.Parameters.AddWithValue(
                    "$length",
                    TransportOutboxLimits.MaxCiphertextBundleBytes + 1);
                command.Parameters.AddWithValue("$logicalId", item.LogicalId.ToArray());
                command.ExecuteNonQuery();
            }

            using var restarted = new SqliteSessionStore(path);
            Assert.Equal(
                TransportOutboxReadResult.Corrupt,
                (await restarted.ReadTransportOutboxAsync(
                    item.AccountScope,
                    item.LogicalId)).Result);
            Assert.Equal(
                TransportOutboxCommitResult.Corrupt,
                await restarted.PrepareTransportOutboxAsync(item));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AttemptCountIsStrictlyBounded(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var item = Prepared();
        await scope.Store.PrepareTransportOutboxAsync(item);
        ulong revision = 1;
        for (var index = 0; index < TransportOutboxLimits.MaxAttemptsPerItem; index++)
        {
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await scope.Store.ApplyTransportOutboxTransitionAsync(
                    TransportOutboxTransition.Attempted(
                        item.AccountScope,
                        item.LogicalId,
                        revision,
                        Attempt(checked((byte)(0xb0 + index))),
                        OutboxTransitionSource.Adapter,
                        OutboxTransitionReason.DispatchStarted,
                        Now.AddSeconds(index + 1),
                        Now.AddMinutes(10))));
            revision++;
        }

        Assert.Equal(
            TransportOutboxCommitResult.Conflict,
            await scope.Store.ApplyTransportOutboxTransitionAsync(
                TransportOutboxTransition.Attempted(
                    item.AccountScope,
                    item.LogicalId,
                    revision,
                    Attempt(0xcf),
                    OutboxTransitionSource.Adapter,
                    OutboxTransitionReason.DispatchStarted,
                    Now.AddMinutes(1),
                    Now.AddMinutes(10))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExhaustedItemCannotStarveReadyItemBeforeLimit(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var exhausted = Prepared(
            logical: 0x71,
            created: Now,
            notBefore: Now.AddMinutes(1));
        var ready = Prepared(
            logical: 0x72,
            created: Now.AddSeconds(1),
            notBefore: Now.AddMinutes(1));
        await scope.Store.PrepareTransportOutboxAsync(exhausted);
        await scope.Store.PrepareTransportOutboxAsync(ready);

        ulong revision = 1;
        for (var index = 0; index < TransportOutboxLimits.MaxAttemptsPerItem; index++)
        {
            Assert.Equal(
                TransportOutboxCommitResult.Applied,
                await scope.Store.ApplyTransportOutboxTransitionAsync(
                    TransportOutboxTransition.Attempted(
                        exhausted.AccountScope,
                        exhausted.LogicalId,
                        revision++,
                        Attempt(checked((byte)(0x80 + index))),
                        OutboxTransitionSource.Adapter,
                        index == 0
                            ? OutboxTransitionReason.DispatchStarted
                            : OutboxTransitionReason.RetryScheduled,
                        Now.AddSeconds(index + 1),
                        Now.AddMinutes(1))));
        }

        var listed = await scope.Store.ListReadyTransportOutboxAsync(
            exhausted.AccountScope,
            Now.AddMinutes(2),
            limit: 1);

        Assert.Single(listed);
        Assert.Equal(ready.LogicalId, listed[0].LogicalId);
        Assert.Empty(listed[0].Attempts);
    }

    [Fact]
    public async Task SqliteRejectsOversizedAttemptEvidenceBeforeReadingIt()
    {
        var path = TempPath("attempt-corrupt");
        try
        {
            var item = Prepared();
            var attempt = Attempt(0xd1);
            using (var store = new SqliteSessionStore(path))
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
                        Bytes(16, 0xd2)));
            }
            using (var connection = new SqliteConnection($"Data Source={path}"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE transport_outbox_attempts
                    SET evidence = zeroblob($length)
                    WHERE logical_id = $logicalId AND attempt_id = $attemptId;
                    """;
                command.Parameters.AddWithValue(
                    "$length",
                    TransportOutboxLimits.MaxEvidenceBytes + 1);
                command.Parameters.AddWithValue("$logicalId", item.LogicalId.ToArray());
                command.Parameters.AddWithValue("$attemptId", attempt.ToArray());
                command.ExecuteNonQuery();
            }

            using var restarted = new SqliteSessionStore(path);
            Assert.Equal(
                TransportOutboxReadResult.Corrupt,
                (await restarted.ReadTransportOutboxAsync(
                    item.AccountScope,
                    item.LogicalId)).Result);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    private static async Task<TransportOutboxItemSnapshot> AssertRestartedStateAsync(
        StoreScope scope,
        TransportOutboxState state,
        ulong revision)
    {
        scope.Restart();
        var read = await scope.Store.ReadTransportOutboxAsync(Scope(0x11), Logical());
        Assert.Equal(TransportOutboxReadResult.Found, read.Result);
        Assert.Equal(state, read.Item?.State);
        Assert.Equal(revision, read.Item?.Revision);
        return read.Item!;
    }

    private static TransportOutboxPreparedItem Prepared(
        byte scope = 0x11,
        byte logical = 0x12,
        DateTimeOffset? created = null,
        DateTimeOffset? expires = null,
        DateTimeOffset? notBefore = null) =>
        TransportOutboxPreparedItem.Create(
            Scope(scope),
            Logical(logical),
            Dedup(0x13),
            Bytes(64, 0x14),
            created ?? Now,
            expires ?? Now.AddHours(1),
            notBefore ?? created ?? Now);

    private static OutboxAccountScope Scope(byte value) =>
        OutboxAccountScope.FromBytes(Bytes(TransportOutboxLimits.AccountScopeBytes, value));

    private static OutboxLogicalId Logical(byte value = 0x12) =>
        OutboxLogicalId.FromBytes(Bytes(TransportOutboxLimits.LogicalIdBytes, value));

    private static OutboxAttemptId Attempt(byte value) =>
        OutboxAttemptId.FromBytes(Bytes(TransportOutboxLimits.AttemptIdBytes, value));

    private static OutboxDedupMaterial Dedup(byte value) =>
        OutboxDedupMaterial.FromBytes(Bytes(TransportOutboxLimits.DedupMaterialBytes, value));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string TempPath(string name) =>
        Path.Combine(Path.GetTempPath(), $"deep-p11a-{name}-{Guid.NewGuid():N}.db");

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

    private sealed class StoreScope : IDisposable
    {
        private readonly bool sqlite;
        private readonly Action<TransportOutboxCommitFaultPoint>? faultInjector;

        private StoreScope(
            bool sqlite,
            Action<TransportOutboxCommitFaultPoint>? faultInjector)
        {
            this.sqlite = sqlite;
            this.faultInjector = faultInjector;
            Path = TempPath(sqlite ? "sqlite" : "memory");
            Store = Open();
        }

        public string Path { get; }
        public ITransportOutboxRepository Store { get; private set; }

        public static StoreScope Create(
            bool sqlite,
            Action<TransportOutboxCommitFaultPoint>? faultInjector = null) =>
            new(sqlite, faultInjector);

        public void Restart()
        {
            (Store as IDisposable)?.Dispose();
            Store = Open();
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

        private ITransportOutboxRepository Open()
        {
            if (sqlite)
            {
                var options = new SqliteSessionStoreOptions(Path);
                return faultInjector is null
                    ? new SqliteSessionStore(options)
                    : new SqliteSessionStore(options, faultInjector);
            }
            return faultInjector is null
                ? new InMemorySessionStore(Path)
                : new InMemorySessionStore(Path, faultInjector);
        }
    }
}
