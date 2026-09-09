using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

[Collection("SQLite global pool isolation")]
public sealed class SqliteXPointNetworkStateStoreTests
{
    [Fact]
    public async Task RestartPreservesExactProtectedLkgAndScope()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        var options = Options(path);
        try
        {
            var original = Snapshot(1, fork: false, withCheckpoint: true);
            using (var store = new SqliteXPointNetworkStateStore(options))
            {
                var result = await store.CompareExchangeAsync(
                    null,
                    original,
                    CancellationToken.None);
                Assert.Equal(XPointNetworkStoreWriteDisposition.Applied, result.Disposition);
                Assert.Equal(
                    XPointNetworkProtectedLkgCodec.Encode(original.ProtectedLkg),
                    XPointNetworkProtectedLkgCodec.Encode(result.Snapshot!.ProtectedLkg));
                Assert.False(new SqliteConnectionStringBuilder(store.ConnectionString).Pooling);
                Assert.NotEqual("SQLite format 3\0", ReadHeader(path));
            }

            using var reopened = new SqliteXPointNetworkStateStore(options);
            var restored = Assert.IsType<XPointNetworkStateSnapshot>(
                await reopened.ReadAsync(CancellationToken.None));
            Assert.Equal(1UL, restored.Revision);
            Assert.False(restored.ForkLatched);
            Assert.Equal(
                XPointNetworkProtectedLkgCodec.Encode(original.ProtectedLkg),
                XPointNetworkProtectedLkgCodec.Encode(restored.ProtectedLkg));

            using var connection = OpenEncrypted(path, options);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT length(exact_xlk1) FROM xpoint_network_state;";
            Assert.Equal(265L, Convert.ToInt64(command.ExecuteScalar()));
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task CompareExchangeIsAtomicAndReturnsCurrentSnapshotOnConflict()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        try
        {
            using var store = new SqliteXPointNetworkStateStore(
                Options(path));
            var initial = Snapshot(1, fork: false, withCheckpoint: false);
            Assert.Equal(
                XPointNetworkStoreWriteDisposition.Applied,
                (await store.CompareExchangeAsync(null, initial, CancellationToken.None)).Disposition);
            using var competingStore = new SqliteXPointNetworkStateStore(Options(path));
            Assert.Equal(1UL, (await competingStore.ReadAsync(CancellationToken.None))!.Revision);

            var proposed = Snapshot(2, fork: true, withCheckpoint: true);
            var applied = await store.CompareExchangeAsync(1, proposed, CancellationToken.None);
            Assert.Equal(XPointNetworkStoreWriteDisposition.Applied, applied.Disposition);

            var conflict = await competingStore.CompareExchangeAsync(
                1,
                Snapshot(2, fork: false, withCheckpoint: false),
                CancellationToken.None);
            Assert.Equal(XPointNetworkStoreWriteDisposition.Conflict, conflict.Disposition);
            Assert.Equal(2UL, conflict.Snapshot!.Revision);
            Assert.True(conflict.Snapshot.ForkLatched);
            Assert.Equal(2UL, (await store.ReadAsync(CancellationToken.None))!.Revision);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task ReturnedSnapshotsAreDefensiveCopies()
    {
        var directory = TempDirectory();
        try
        {
            using var store = new SqliteXPointNetworkStateStore(
                Options(Path.Combine(directory, "xpoint-network.db")));
            var source = Snapshot(1, fork: false, withCheckpoint: true);
            await store.CompareExchangeAsync(null, source, CancellationToken.None);

            var first = (await store.ReadAsync(CancellationToken.None))!;
            var exposedNetwork = first.ProtectedLkg.NetworkId.ToArray();
            exposedNetwork[0] ^= 0xFF;
            var exposedReference = first.ProtectedLkg.HeadCoreReference.ToArray();
            exposedReference[^1] ^= 0xFF;

            var second = (await store.ReadAsync(CancellationToken.None))!;
            Assert.Equal(Bytes(16, 0x11), second.ProtectedLkg.NetworkId.ToArray());
            Assert.Equal(Reference("XNH1", 0x21), second.ProtectedLkg.HeadCoreReference.ToArray());
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task ForkLatchSurvivesRestart()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        var options = Options(path);
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(options))
                await store.CompareExchangeAsync(
                    null,
                    Snapshot(1, fork: true, withCheckpoint: true),
                    CancellationToken.None);

            using var reopened = new SqliteXPointNetworkStateStore(options);
            Assert.True((await reopened.ReadAsync(CancellationToken.None))!.ForkLatched);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task ForkLatchCannotBeClearedByNextRevision()
    {
        var directory = TempDirectory();
        try
        {
            using var store = new SqliteXPointNetworkStateStore(
                Options(Path.Combine(directory, "xpoint-network.db")));
            await store.CompareExchangeAsync(
                null,
                Snapshot(1, fork: true, withCheckpoint: true),
                CancellationToken.None);

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.CompareExchangeAsync(
                    1,
                    Snapshot(2, fork: false, withCheckpoint: true),
                    CancellationToken.None));
            Assert.True((await store.ReadAsync(CancellationToken.None))!.ForkLatched);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public void WrongKeyFailsClosed()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(Options(path))) { }
            Assert.Equal(
                XPointNetworkStoreOpenFailure.UnreadableOrWrongKey,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(Options(path, keyMarker: 0xE2))).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void EveryScopeDimensionIsExact(int changedDimension)
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(Options(path))) { }
            var changed = changedDimension switch
            {
                1 => Options(path, networkMarker: 0x12),
                2 => Options(path, accountMarker: 0xC2),
                3 => Options(path, accountGeneration: 2),
                4 => Options(path, databaseGeneration: 2),
                5 => Options(path, storeMarker: 0xD2),
                _ => throw new ArgumentOutOfRangeException(nameof(changedDimension)),
            };
            Assert.Equal(
                XPointNetworkStoreOpenFailure.ScopeMismatch,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(changed)).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task WriteRejectsLkgFromAnotherNetwork()
    {
        var directory = TempDirectory();
        try
        {
            using var store = new SqliteXPointNetworkStateStore(
                Options(Path.Combine(directory, "xpoint-network.db")));
            var wrongNetworkLkg = new XPointNetworkProtectedLkg(
                Bytes(16, 0x12),
                Reference("XNH1", 0x21),
                8,
                Bytes(32, 0x31),
                Reference("XNV1", 0x41),
                7,
                Reference("XNA1", 0x51));

            var exception = await Assert.ThrowsAsync<XPointNetworkStoreOpenException>(() =>
                store.CompareExchangeAsync(
                    null,
                    new XPointNetworkStateSnapshot(1, wrongNetworkLkg, forkLatched: false),
                    CancellationToken.None).AsTask());
            Assert.Equal(XPointNetworkStoreOpenFailure.ScopeMismatch, exception.Reason);
            Assert.Null(await store.ReadAsync(CancellationToken.None));
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public void AllowCreateFalseDoesNotCreateAStore()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "missing.db");
        try
        {
            Assert.Equal(
                XPointNetworkStoreOpenFailure.UnreadableOrWrongKey,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(Options(path, allowCreate: false))).Reason);
            Assert.False(File.Exists(path));
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public void PlaintextAndTruncatedDatabasesFailClosed()
    {
        var directory = TempDirectory();
        try
        {
            var plaintextPath = Path.Combine(directory, "plaintext.db");
            using (var plaintext = new SqliteConnection(
                new SqliteConnectionStringBuilder
                {
                    DataSource = plaintextPath,
                    Pooling = false,
                }.ToString()))
            {
                plaintext.Open();
                using var command = plaintext.CreateCommand();
                command.CommandText = "CREATE TABLE forbidden(value INTEGER);";
                command.ExecuteNonQuery();
            }
            Assert.Equal(
                XPointNetworkStoreOpenFailure.Corrupt,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(Options(plaintextPath))).Reason);

            var truncatedPath = Path.Combine(directory, "truncated.db");
            File.WriteAllBytes(truncatedPath, [0x01, 0x02, 0x03]);
            Assert.Equal(
                XPointNetworkStoreOpenFailure.Corrupt,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(Options(truncatedPath))).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task CorruptXlk1FailsClosedOnRestart()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        var options = Options(path);
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(options))
                await store.CompareExchangeAsync(
                    null,
                    Snapshot(1, fork: false, withCheckpoint: true),
                    CancellationToken.None);
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText =
                    "UPDATE xpoint_network_state SET exact_xlk1=zeroblob(265); PRAGMA wal_checkpoint(FULL);";
                command.ExecuteNonQuery();
            }

            Assert.Equal(
                XPointNetworkStoreOpenFailure.Corrupt,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(options)).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public void DdlTamperFailsClosed()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        var options = Options(path);
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(options)) { }
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText =
                    "PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql,'length(exact_xlk1)=265','length(exact_xlk1)>=1') WHERE name='xpoint_network_state'; PRAGMA writable_schema=OFF; PRAGMA wal_checkpoint(FULL);";
                command.ExecuteNonQuery();
            }

            Assert.Equal(
                XPointNetworkStoreOpenFailure.Corrupt,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(options)).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public void UnsupportedSchemaGenerationFailsClosedWithoutMigration()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "xpoint-network.db");
        var options = Options(path);
        try
        {
            using (var store = new SqliteXPointNetworkStateStore(options)) { }
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA user_version=2; PRAGMA wal_checkpoint(FULL);";
                command.ExecuteNonQuery();
            }
            Assert.Equal(
                XPointNetworkStoreOpenFailure.UnsupportedGeneration,
                Assert.Throws<XPointNetworkStoreOpenException>(() =>
                    new SqliteXPointNetworkStateStore(options)).Reason);
        }
        finally
        {
            Delete(directory);
        }
    }

    [Fact]
    public async Task DisposeZeroizesKeyAndRejectsFurtherUse()
    {
        var directory = TempDirectory();
        try
        {
            var store = new SqliteXPointNetworkStateStore(
                Options(Path.Combine(directory, "xpoint-network.db")));
            store.Dispose();
            Assert.True(store.IsKeyZeroedForTesting);
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                store.ReadAsync(CancellationToken.None).AsTask());
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                store.CompareExchangeAsync(
                    null,
                    Snapshot(1, fork: false, withCheckpoint: false),
                    CancellationToken.None).AsTask());
        }
        finally
        {
            Delete(directory);
        }
    }

    private static SqliteXPointNetworkStateStoreOptions Options(
        string path,
        byte keyMarker = 0xE1,
        byte networkMarker = 0x11,
        byte accountMarker = 0xC1,
        ulong accountGeneration = 1,
        ulong databaseGeneration = 1,
        byte storeMarker = 0xD1,
        bool allowCreate = true) => new(
            path,
            Bytes(32, keyMarker),
            Bytes(16, networkMarker),
            Bytes(32, accountMarker),
            accountGeneration,
            databaseGeneration,
            Bytes(32, storeMarker),
            allowCreate);

    private static XPointNetworkStateSnapshot Snapshot(
        ulong revision,
        bool fork,
        bool withCheckpoint) => new(revision, Lkg(withCheckpoint), fork);

    private static XPointNetworkProtectedLkg Lkg(bool withCheckpoint) => new(
        Bytes(16, 0x11),
        Reference("XNH1", 0x21),
        8,
        Bytes(32, 0x31),
        Reference("XNV1", 0x41),
        7,
        Reference("XNA1", 0x51),
        withCheckpoint ? Reference("XNF1", 0x61) : default,
        withCheckpoint ? 5UL : null);

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        Bytes(32, marker).CopyTo(value, 6);
        return value;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Range(0, length).Select(index => (byte)(marker + index)).ToArray();

    private static string TempDirectory()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "deep-xpoint-network-v1-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static string ReadHeader(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        var bytes = new byte[16];
        Assert.Equal(16, stream.Read(bytes));
        return System.Text.Encoding.ASCII.GetString(bytes);
    }

    private static SqliteConnection OpenEncrypted(
        string path,
        SqliteXPointNetworkStateStoreOptions options)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            }.ToString());
        connection.Open();
        Assert.Equal(
            SQLitePCL.raw.SQLITE_OK,
            SQLitePCL.raw.sqlite3_key(connection.Handle, options.EncryptionKey.ToArray()));
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA cipher_compatibility=4;";
        command.ExecuteNonQuery();
        return connection;
    }

    private static void Delete(string path)
    {
        SqliteConnection.ClearAllPools();
        for (var attempt = 0; attempt < 20 && Directory.Exists(path); attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(25);
                SqliteConnection.ClearAllPools();
            }
        }
    }
}
