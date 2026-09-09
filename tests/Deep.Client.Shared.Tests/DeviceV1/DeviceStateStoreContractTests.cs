using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.DeviceV1;

public sealed class DeviceStateStoreContractTests
{
    public static IEnumerable<object[]> Stores()
    {
        yield return [new StoreKind(false)];
        yield return [new StoreKind(true)];
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task Bootstrap_DedupAndCurrentGenerationIsolation(StoreKind kind)
    {
        using var fixture = kind.Open();
        var active = DeviceV1Fixture.Active(0x20, 0x50);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [active]);
        var plan = DeviceTransactionPlan.Bootstrap(DeviceV1Fixture.Operation(0x80), genesis);
        var first = await fixture.Store.CommitAsync(plan, CancellationToken.None);
        var replay = await fixture.Store.CommitAsync(plan, CancellationToken.None);
        var conflict = await fixture.Store.CommitAsync(DeviceTransactionPlan.Bootstrap(
            DeviceV1Fixture.Operation(0x80), DeviceV1Fixture.Directory(1, 0x41, 0x60, [active])),
            CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.Applied, first.Disposition);
        Assert.Equal(DeviceCommitDisposition.Idempotent, replay.Disposition);
        Assert.Equal(DeviceCommitDisposition.Conflict, conflict.Disposition);
        Assert.False((await fixture.Store.ReadAsync(DeviceV1Fixture.Account(), 2, CancellationToken.None)).Found);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task OfflineRevokeMidFanout_FloorWinsBeforeExternalEffects(StoreKind kind)
    {
        using var fixture = kind.Open();
        var a = DeviceV1Fixture.Active(0x20, 0x50); var b = DeviceV1Fixture.Active(0x21, 0x51);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, b]);
        var current = await DeviceV1Fixture.BootstrapAsync(fixture.Store, genesis);
        var stale = DeviceTargetSelector.SelectExact(current.Directory, b.DeviceId);
        var successor = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a], genesis.DirectoryHash, 2);
        var intent = DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, successor);
        var sagaId = DeviceV1Fixture.Operation(0x89);
        var prepared = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(current,
            DeviceV1Fixture.Operation(0x81), sagaId, intent), CancellationToken.None);
        var saga = Assert.Single(prepared.Snapshot!.RevocationSagas);
        Assert.Equal(new[] { DeviceV1Fixture.Contact(0xC0), DeviceV1Fixture.Contact(0xC1) }, saga.Intent.ContactWorklist);
        Assert.Equal(DeviceV1Fixture.Operation(0x90), saga.Intent.PlaneOperations!.Prekeys);

        var committed = await fixture.Store.CommitAsync(DeviceTransactionPlan.CommitRevocationFloor(
            prepared.Snapshot, DeviceV1Fixture.Operation(0x82), sagaId), CancellationToken.None);
        Assert.True(committed.Snapshot!.IsLocallyRevoked(b.DeviceId));
        Assert.Equal(DeviceTargetSelectionOutcome.RevokedTarget,
            DeviceTargetSelector.Revalidate(stale, committed.Snapshot.Directory));
        Assert.Equal(DeviceRevocationPhase.LocalFloorCommitted,
            Assert.Single(committed.Snapshot.RevocationSagas).Phase);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task RepairAuthorization_IncrementsBeforeRepairAndStopsAtTwo(StoreKind kind)
    {
        using var fixture = kind.Open();
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60,
            [DeviceV1Fixture.Active(0x20, 0x50)]);
        var current = await DeviceV1Fixture.BootstrapAsync(fixture.Store, genesis);
        var key = new DeviceRepairKey(DeviceV1Fixture.Account(), 1, DeviceV1Fixture.Message(0x70),
            DeviceV1Fixture.Account(0x30), 4, DeviceV1Fixture.Device(0x40));
        var first = await fixture.Store.CommitAsync(DeviceTransactionPlan.AuthorizeRepairAttempt(current,
            DeviceV1Fixture.Operation(0x81), key), CancellationToken.None);
        Assert.Equal(1, Assert.Single(first.Snapshot!.Repairs).AttemptsUsed);
        var second = await fixture.Store.CommitAsync(DeviceTransactionPlan.AuthorizeRepairAttempt(first.Snapshot,
            DeviceV1Fixture.Operation(0x82), key), CancellationToken.None);
        var exhaustedState = Assert.Single(second.Snapshot!.Repairs);
        Assert.Equal(2, exhaustedState.AttemptsUsed);
        Assert.Equal(DeviceRepairStatus.Exhausted, exhaustedState.Status);
        var third = await fixture.Store.CommitAsync(DeviceTransactionPlan.AuthorizeRepairAttempt(second.Snapshot,
            DeviceV1Fixture.Operation(0x83), key), CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.RepairExhausted, third.Disposition);
        Assert.Equal(2, Assert.Single(third.Snapshot!.Repairs).AttemptsUsed);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task CompetingSagas_MustAbortOrCompleteTerminally(StoreKind kind)
    {
        using var fixture = kind.Open();
        var a = DeviceV1Fixture.Active(0x20, 0x50); var b = DeviceV1Fixture.Active(0x21, 0x51);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, b]);
        var current = await DeviceV1Fixture.BootstrapAsync(fixture.Store, genesis);
        var successor = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a], genesis.DirectoryHash, 2);
        var intent = DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, successor);
        var firstSaga = DeviceV1Fixture.Operation(0x89);
        var prepared = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(current,
            DeviceV1Fixture.Operation(0x81), firstSaga, intent), CancellationToken.None);
        var competing = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(prepared.Snapshot!,
            DeviceV1Fixture.Operation(0x82), DeviceV1Fixture.Operation(0x8A), intent), CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.InvalidTransition, competing.Disposition);
        var aborted = await fixture.Store.CommitAsync(DeviceTransactionPlan.AbortPreparedRevocation(
            prepared.Snapshot!, DeviceV1Fixture.Operation(0x83), firstSaga), CancellationToken.None);
        Assert.Equal(DeviceRevocationPhase.Aborted, Assert.Single(aborted.Snapshot!.RevocationSagas).Phase);
        var replacement = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(aborted.Snapshot,
            DeviceV1Fixture.Operation(0x84), DeviceV1Fixture.Operation(0x8A), intent), CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.Applied, replacement.Disposition);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task PreparedSagaFingerprint_BindsEveryPlaneOperation(StoreKind kind)
    {
        using var fixture = kind.Open();
        var a = DeviceV1Fixture.Active(0x20, 0x50); var b = DeviceV1Fixture.Active(0x21, 0x51);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, b]);
        var current = await DeviceV1Fixture.BootstrapAsync(fixture.Store, genesis);
        var successor = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a], genesis.DirectoryHash, 2);
        var operation = DeviceV1Fixture.Operation(0x81); var saga = DeviceV1Fixture.Operation(0x89);
        var first = DeviceTransactionPlan.PrepareRevocation(current, operation, saga,
            DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, successor, 0x90));
        var changedPlane = DeviceTransactionPlan.PrepareRevocation(current, operation, saga,
            DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, successor, 0xA0));
        Assert.Equal(DeviceCommitDisposition.Applied,
            (await fixture.Store.CommitAsync(first, CancellationToken.None)).Disposition);
        Assert.Equal(DeviceCommitDisposition.Conflict,
            (await fixture.Store.CommitAsync(changedPlane, CancellationToken.None)).Disposition);
    }

    [Theory, MemberData(nameof(Stores))]
    public async Task HostilePersistedIntent_CannotRemoveAdditionalDevice(StoreKind kind)
    {
        using var fixture = kind.Open();
        var a = DeviceV1Fixture.Active(0x20, 0x50); var b = DeviceV1Fixture.Active(0x21, 0x51);
        var c = DeviceV1Fixture.Active(0x22, 0x52);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, b, c]);
        var current = await DeviceV1Fixture.BootstrapAsync(fixture.Store, genesis);
        var hostileSuccessor = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a],
            genesis.DirectoryHash, 2);
        var hostile = DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, hostileSuccessor);
        var result = await fixture.Store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(current,
            DeviceV1Fixture.Operation(0x81), DeviceV1Fixture.Operation(0x89), hostile),
            CancellationToken.None);
        Assert.Equal(DeviceCommitDisposition.InvalidTransition, result.Disposition);
        Assert.Empty(result.Snapshot!.RevocationSagas);
    }

    public sealed record StoreKind(bool Sqlite)
    {
        public override string ToString() => Sqlite ? "SQLCipher" : "InMemory";
        internal StoreFixture Open() => Sqlite ? StoreFixture.Sqlite() : StoreFixture.Memory();
    }

    internal sealed class StoreFixture : IDisposable
    {
        private readonly string? directory;
        private StoreFixture(IDeviceStateStore store, string? directory = null)
        { Store = store; this.directory = directory; }
        internal IDeviceStateStore Store { get; }
        internal static StoreFixture Memory() => new(new InMemoryDeviceStateStore());
        internal static StoreFixture Sqlite()
        {
            var directory = Path.Combine(Path.GetTempPath(), "deep-device-v1-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var options = Options(Path.Combine(directory, "device.db"));
            return new(new SqliteDeviceStateStore(options), directory);
        }
        internal static SqliteDeviceStateStoreOptions Options(string path, byte keyMarker = 0xE0,
            ulong databaseGeneration = 1, byte storeMarker = 0xF0) =>
            new(path, DeviceV1Fixture.Bytes(32, keyMarker), DeviceV1Fixture.Account(), 1,
                databaseGeneration, DeviceV1Fixture.Operation(storeMarker));
        public void Dispose()
        {
            (Store as IDisposable)?.Dispose();
            if (directory is not null) SqliteDeviceStateStoreTests.DeleteDirectory(directory);
        }
    }
}

public sealed class SqliteDeviceStateStoreTests
{
    [Fact]
    public async Task Reopen_PreservesFloorSagaForkDedupAndRepair()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-reopen-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        try
        {
            DeviceAccountStateSnapshot state;
            DeviceTransactionPlan repairPlan;
            using (var store = new SqliteDeviceStateStore(options))
            {
                var floor = await DeviceV1Fixture.CommitFloorAsync(store); state = floor.State;
                var key = new DeviceRepairKey(DeviceV1Fixture.Account(), 1, DeviceV1Fixture.Message(0x71),
                    DeviceV1Fixture.Account(0x31), 9, DeviceV1Fixture.Device(0x41));
                repairPlan = DeviceTransactionPlan.AuthorizeRepairAttempt(state,
                    DeviceV1Fixture.Operation(0x83), key);
                state = (await store.CommitAsync(repairPlan, CancellationToken.None)).Snapshot!;
                var wrongPredecessor = DeviceV1Fixture.Directory(3, 0x45, 0x61,
                    state.Directory.Head.ActiveDevices,
                    DeviceDirectoryHash32.FromBytes(DeviceV1Fixture.Bytes(32, 0x79)), 2);
                state = (await store.CommitAsync(DeviceTransactionPlan.InstallDirectory(state,
                    DeviceV1Fixture.Operation(0x84), wrongPredecessor), CancellationToken.None)).Snapshot!;
            }
            using (var reopened = new SqliteDeviceStateStore(options))
            {
                var restored = (await reopened.ReadAsync(DeviceV1Fixture.Account(), 1, CancellationToken.None)).Snapshot!;
                Assert.Single(restored.LocalRevocationFloor);
                Assert.Equal(DeviceRevocationPhase.LocalFloorCommitted, Assert.Single(restored.RevocationSagas).Phase);
                Assert.Equal(1, Assert.Single(restored.Repairs).AttemptsUsed);
                Assert.True(restored.Directory.ForkLatched);
                var duplicate = await reopened.CommitAsync(repairPlan, CancellationToken.None);
                Assert.Equal(DeviceCommitDisposition.Idempotent, duplicate.Disposition);
            }
        }
        finally { DeleteDirectory(directory); }
    }

    [Fact]
    public async Task SQLCipherRejectsWrongKeyScopeAndPooling_AndNeverWritesPlaintextHeaders()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-key-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        try
        {
            var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
            using (var store = new SqliteDeviceStateStore(options))
            {
                var parsed = new SqliteConnectionStringBuilder(store.ConnectionString);
                Assert.False(parsed.Pooling);
                await DeviceV1Fixture.BootstrapAsync(store, DeviceV1Fixture.Directory(1, 0x40, 0x60,
                    [DeviceV1Fixture.Active(0x20, 0x50)]));
                store.ValidateEncryptedFilesForTesting();
            Assert.NotEqual("SQLite format 3\0", ReadHeader(path));
                var wal = path + "-wal";
                Assert.True(File.Exists(wal));
            Assert.NotEqual("SQLite format 3\0", ReadHeader(wal));
            }
            var wrongKey = Assert.Throws<DeviceStateStoreOpenException>(() =>
                new SqliteDeviceStateStore(DeviceStateStoreContractTests.StoreFixture.Options(path, 0xE1)));
            Assert.Equal(DeviceStateStoreOpenFailure.UnreadableOrWrongKey, wrongKey.Reason);
            var wrongGeneration = Assert.Throws<DeviceStateStoreOpenException>(() =>
                new SqliteDeviceStateStore(DeviceStateStoreContractTests.StoreFixture.Options(path,
                    databaseGeneration: 2)));
            Assert.Equal(DeviceStateStoreOpenFailure.ScopeMismatch, wrongGeneration.Reason);
            using var unkeyed = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Pooling = false }.ToString());
            unkeyed.Open();
            Assert.Throws<SqliteException>(() =>
            {
                using var command = unkeyed.CreateCommand();
                command.CommandText = "SELECT * FROM device_store_meta;";
                command.ExecuteScalar();
            });
        }
        finally { DeleteDirectory(directory); }
    }

    [Fact]
    public void SchemaHasAtomicStateTables()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-schema-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        try
        {
            var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
            using var store = new SqliteDeviceStateStore(options);
            SQLitePCL.Batteries_V2.Init();
            using var connection = new SqliteConnection(store.ConnectionString); connection.Open();
            Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                SQLitePCL.raw.sqlite3_key(connection.Handle, options.EncryptionKey.ToArray()));
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='table';";
            using var reader = command.ExecuteReader(); var names = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read()) names.Add(reader.GetString(0));
            Assert.Subset(names, new HashSet<string>
            {
                "device_heads", "device_revocation_floor", "device_sagas", "device_repairs",
                "device_operation_dedup", "device_directory_entries", "protected_current_dmd1",
                "device_agreement_authorizations"
            });
            reader.Close();
            command.CommandText = "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
            using var indexes = command.ExecuteReader(); var indexNames = new List<string>();
            while (indexes.Read()) indexNames.Add(indexes.GetString(0));
            Assert.Equal(new[] { "device_repairs_status", "device_sagas_phase" }, indexNames);
        }
        finally { DeleteDirectory(directory); }
    }

    [Fact]
    public async Task AbandonedSqlTransaction_DoesNotPartiallyLatchFork()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-crash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        try
        {
            using (var store = new SqliteDeviceStateStore(options))
                await DeviceV1Fixture.BootstrapAsync(store, DeviceV1Fixture.Directory(1, 0x40, 0x60,
                    [DeviceV1Fixture.Active(0x20, 0x50)]));
            using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = path, Pooling = false }.ToString()))
            {
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                    SQLitePCL.raw.sqlite3_key(connection.Handle, options.EncryptionKey.ToArray()));
                using var transaction = connection.BeginTransaction(deferred: false);
                using var command = connection.CreateCommand(); command.Transaction = transaction;
                command.CommandText = "UPDATE device_heads SET fork_latched=1 WHERE singleton=1;";
                Assert.Equal(1, command.ExecuteNonQuery());
                // Disposal without Commit models process loss before the atomic commit boundary.
            }
            using var reopened = new SqliteDeviceStateStore(options);
            var state = (await reopened.ReadAsync(DeviceV1Fixture.Account(), 1, CancellationToken.None)).Snapshot!;
            Assert.False(state.Directory.ForkLatched);
        }
        finally { DeleteDirectory(directory); }
    }

    [Theory]
    [InlineData((int)DeviceStateStoreFailpoint.AfterHeadWritten)]
    [InlineData((int)DeviceStateStoreFailpoint.AfterChildReplacement)]
    [InlineData((int)DeviceStateStoreFailpoint.BeforeDedupInsert)]
    [InlineData((int)DeviceStateStoreFailpoint.BeforeCommit)]
    public async Task InjectedCrash_DuringFloorSagaChildReplacementAndDedup_RollsBackAtomically(
        int pointValue)
    {
        var point = (DeviceStateStoreFailpoint)pointValue;
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-failpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        try
        {
            DeviceTransactionPlan floorPlan;
            using (var store = new SqliteDeviceStateStore(options))
            {
                var a = DeviceV1Fixture.Active(0x20, 0x50); var b = DeviceV1Fixture.Active(0x21, 0x51);
                var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, b]);
                var current = await DeviceV1Fixture.BootstrapAsync(store, genesis);
                var successor = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a], genesis.DirectoryHash, 2);
                var saga = DeviceV1Fixture.Operation(0x89);
                var prepared = await store.CommitAsync(DeviceTransactionPlan.PrepareRevocation(current,
                    DeviceV1Fixture.Operation(0x81), saga, DeviceV1Fixture.RevokeIntent(current.Directory, b.DeviceId, successor)),
                    CancellationToken.None);
                floorPlan = DeviceTransactionPlan.CommitRevocationFloor(prepared.Snapshot!, DeviceV1Fixture.Operation(0x82), saga);
                using var hook = DeviceStateStoreTestHooks.Push(hit =>
                {
                    if (hit == point) throw new DeviceStateStoreInjectedCrashException(hit);
                });
                await Assert.ThrowsAsync<DeviceStateStoreInjectedCrashException>(() =>
                    store.CommitAsync(floorPlan, CancellationToken.None).AsTask());
            }
            using var reopened = new SqliteDeviceStateStore(options);
            var restored = (await reopened.ReadAsync(DeviceV1Fixture.Account(), 1, CancellationToken.None)).Snapshot!;
            Assert.Empty(restored.LocalRevocationFloor);
            Assert.Equal(DeviceRevocationPhase.Prepared, Assert.Single(restored.RevocationSagas).Phase);
            var retry = DeviceTransactionPlan.CommitRevocationFloor(restored, floorPlan.OperationId,
                Assert.Single(restored.RevocationSagas).OperationId);
            Assert.Equal(DeviceCommitDisposition.Applied,
                (await reopened.CommitAsync(retry, CancellationToken.None)).Disposition);
        }
        finally { DeleteDirectory(directory); }
    }

    [Fact]
    public async Task InjectedCrash_BeforeRepairCommit_RollsBackRepairAndOperationDedup()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-repair-failpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        try
        {
            DeviceTransactionPlan repair;
            using (var store = new SqliteDeviceStateStore(options))
            {
                var current = await DeviceV1Fixture.BootstrapAsync(store, DeviceV1Fixture.Directory(1, 0x40, 0x60,
                    [DeviceV1Fixture.Active(0x20, 0x50)]));
                var key = new DeviceRepairKey(DeviceV1Fixture.Account(), 1, DeviceV1Fixture.Message(0x70),
                    DeviceV1Fixture.Account(0x30), 2, DeviceV1Fixture.Device(0x40));
                repair = DeviceTransactionPlan.AuthorizeRepairAttempt(current, DeviceV1Fixture.Operation(0x81), key);
                using var hook = DeviceStateStoreTestHooks.Push(hit =>
                {
                    if (hit == DeviceStateStoreFailpoint.BeforeCommit) throw new DeviceStateStoreInjectedCrashException(hit);
                });
                await Assert.ThrowsAsync<DeviceStateStoreInjectedCrashException>(() => store.CommitAsync(repair,
                    CancellationToken.None).AsTask());
            }
            using var reopened = new SqliteDeviceStateStore(options);
            var restored = (await reopened.ReadAsync(DeviceV1Fixture.Account(), 1, CancellationToken.None)).Snapshot!;
            Assert.Empty(restored.Repairs);
            Assert.Equal(DeviceCommitDisposition.Applied,
                (await reopened.CommitAsync(DeviceTransactionPlan.AuthorizeRepairAttempt(restored, repair.OperationId,
                    repair.RepairKey!), CancellationToken.None)).Disposition);
        }
        finally { DeleteDirectory(directory); }
    }

    [Fact]
    public async Task Dispose_WaitsForActiveAndCancelledQueuedOperation_ThenZeroizesKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-dispose-race-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var store = new SqliteDeviceStateStore(DeviceStateStoreContractTests.StoreFixture.Options(path));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim(false);
        try
        {
            using var hook = DeviceStateStoreTestHooks.Push(point =>
            {
                if (point == DeviceStateStoreFailpoint.AfterGateAcquired)
                { entered.TrySetResult(); release.Wait(); }
            });
            var active = Task.Run(async () => await store.ReadAsync(DeviceV1Fixture.Account(), 1, CancellationToken.None));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var cancelled = new CancellationTokenSource();
            var queued = Task.Run(async () => await store.CommitAsync(DeviceTransactionPlan.Bootstrap(
                DeviceV1Fixture.Operation(0x80), DeviceV1Fixture.Directory(1, 0x40, 0x60,
                    [DeviceV1Fixture.Active(0x20, 0x50)])), cancelled.Token));
            await Task.Delay(50); var disposal = Task.Run(store.Dispose);
            await Task.Delay(100); Assert.False(disposal.IsCompleted);
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);
            Assert.False(disposal.IsCompleted);
            release.Set(); await active; await disposal;
            Assert.True(store.IsKeyZeroedForTesting);
            await Assert.ThrowsAsync<ObjectDisposedException>(() => store.ReadAsync(DeviceV1Fixture.Account(), 1,
                CancellationToken.None).AsTask());
        }
        finally
        {
            release.Set(); store.Dispose();
            DeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task OpenRejectsModifiedDdlAndInvalidPersistedEnumSemantics()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-schema-tamper-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "device.db");
        var options = DeviceStateStoreContractTests.StoreFixture.Options(path);
        try
        {
            using (var store = new SqliteDeviceStateStore(options)) { }
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql,'fork_latched IN (0,1)','fork_latched IN (0,2)') WHERE name='device_heads'; PRAGMA writable_schema=OFF;";
                command.ExecuteNonQuery();
            }
            var ddl = Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(options));
            Assert.Equal(DeviceStateStoreOpenFailure.Corrupt, ddl.Reason);
            DeleteSqliteFiles(path);
            using (var store = new SqliteDeviceStateStore(options))
                await DeviceV1Fixture.BootstrapAsync(store, DeviceV1Fixture.Directory(1, 0x40, 0x60,
                    [DeviceV1Fixture.Active(0x20, 0x50)]));
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA ignore_check_constraints=ON; UPDATE device_heads SET fork_latched=2 WHERE singleton=1;";
                command.ExecuteNonQuery();
            }
            var semantic = Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(options));
            Assert.Equal(DeviceStateStoreOpenFailure.Corrupt, semantic.Reason);
        }
        finally { DeleteDirectory(directory); }
    }

    private static SqliteConnection OpenEncrypted(string path, SqliteDeviceStateStoreOptions options)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, options.EncryptionKey.ToArray()));
        return connection;
    }

    private static string ReadHeader(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var bytes = new byte[16]; Assert.Equal(bytes.Length, stream.Read(bytes, 0, bytes.Length));
        return System.Text.Encoding.ASCII.GetString(bytes);
    }

    private static void DeleteSqliteFiles(string path)
    {
        SqliteConnection.ClearAllPools();
        foreach (var file in new[] { path, path + "-wal", path + "-shm" })
        {
            IOException? last = null;
            for (var attempt = 0; File.Exists(file) && attempt != 20; attempt++)
            {
                try { File.Delete(file); last = null; break; }
                catch (IOException ex) { last = ex; Thread.Sleep(25); SqliteConnection.ClearAllPools(); }
            }
            if (last is not null) throw last;
        }
    }

    internal static void DeleteDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return;
        SqliteConnection.ClearAllPools();
        for (var attempt = 0; attempt != 20; attempt++)
        {
            try { Directory.Delete(directory, true); return; }
            catch (IOException) { Thread.Sleep(25); SqliteConnection.ClearAllPools(); }
        }
        // Windows Defender can retain a just-closed encrypted WAL briefly.  This is deliberately
        // best-effort test-artifact cleanup; correctness has already been asserted before it.
    }
}
