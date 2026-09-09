using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class EntryGuardStateStoreTests
{
    [Fact]
    public void Codec_RoundTripsCanonicalState_AndRejectsTamper()
    {
        var state = State(1, 7, 0x31, [0x41, 0x42, 0x43], 0x42);
        var exact = EntryGuardStateCodec.Encode(state);
        var decoded = EntryGuardStateCodec.Decode(exact);
        Assert.Equal(exact, EntryGuardStateCodec.Encode(decoded));
        Assert.Equal(B(32, 0x42), decoded.PrimaryNodeId.ToArray());

        exact[70] ^= 0x80;
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            EntryGuardStateCodec.Decode(exact));
    }

    [Fact]
    public async Task InMemoryStore_UsesExactCasAndDefensiveCopies()
    {
        var store = new InMemoryProtectedEntryGuardStore();
        var initial = State(1, 7, 0x31, [0x41], 0x41);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await store.CompareExchangeAsync(null, initial, default)).Disposition);
        Assert.Equal(EntryGuardStoreWriteDisposition.Conflict,
            (await store.CompareExchangeAsync(null, initial, default)).Disposition);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.CompareExchangeAsync(1, State(3, 8, 0x32, [0x42], 0x42), default));
        var restored = Assert.IsType<EntryGuardState>(await store.ReadAsync(default));
        Assert.Equal(1UL, restored.Revision);
    }

    [Fact]
    public async Task SqlCipherStore_PersistsAcrossRestart_AndRejectsWrongKey()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "guards.db");
        try
        {
            var options = Options(path);
            using (var store = new SqliteProtectedEntryGuardStore(options))
            {
                var write = await store.CompareExchangeAsync(
                    null, State(1, 7, 0x31, [0x41, 0x42], 0x41), default);
                Assert.Equal(EntryGuardStoreWriteDisposition.Applied, write.Disposition);
            }

            using (var reopened = new SqliteProtectedEntryGuardStore(options))
            {
                var state = Assert.IsType<EntryGuardState>(await reopened.ReadAsync(default));
                Assert.Equal(7UL, state.ViewGeneration);
                Assert.Equal(B(32, 0x41), state.PrimaryNodeId.ToArray());
            }

            var wrongKey = Options(path, keyMarker: 0xE2, allowCreate: false);
            Assert.Equal(EntryGuardStoreOpenFailure.UnreadableOrWrongKey,
                Assert.Throws<EntryGuardStoreOpenException>(() =>
                    new SqliteProtectedEntryGuardStore(wrongKey)).Reason);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task SqlCipherStore_DetectsTamperAndCasConflict()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "guards.db");
        try
        {
            var options = Options(path);
            using (var store = new SqliteProtectedEntryGuardStore(options))
            {
                await store.CompareExchangeAsync(null, State(1, 7, 0x31, [0x41], 0x41), default);
                var conflict = await store.CompareExchangeAsync(null, State(1, 8, 0x32, [0x42], 0x42), default);
                Assert.Equal(EntryGuardStoreWriteDisposition.Conflict, conflict.Disposition);
            }

            Tamper(path, B(32, 0xA1));
            Assert.Equal(EntryGuardStoreOpenFailure.Corrupt,
                Assert.Throws<EntryGuardStoreOpenException>(() =>
                    new SqliteProtectedEntryGuardStore(Options(path, allowCreate: false))).Reason);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void SqlCipherStore_RejectsSchemaTamperEvenWhenDatabaseRemainsReadable()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "guards.db");
        try
        {
            using (var store = new SqliteProtectedEntryGuardStore(Options(path))) { }
            ExecuteWithKey(path, B(32, 0xA1),
                "CREATE TABLE attacker_controlled(value BLOB);", expectedChanges: 0);

            Assert.Equal(EntryGuardStoreOpenFailure.Corrupt,
                Assert.Throws<EntryGuardStoreOpenException>(() =>
                    new SqliteProtectedEntryGuardStore(Options(path, allowCreate: false))).Reason);
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static EntryGuardState State(
        ulong revision,
        ulong viewGeneration,
        byte viewMarker,
        byte[] guards,
        byte primary) => new(
            revision, B(16, 0x11), viewGeneration, B(32, viewMarker), B(32, 0x51),
            B(32, primary), guards.Select(marker => (ReadOnlyMemory<byte>)B(32, marker)));

    private static SqliteProtectedEntryGuardStoreOptions Options(
        string path,
        byte keyMarker = 0xA1,
        bool allowCreate = true) => new(
            path, B(32, keyMarker), B(16, 0x11), B(32, 0x21), 1, 1, B(32, 0x31), allowCreate);

    private static void Tamper(string path, byte[] key)
    {
        ExecuteWithKey(path, key,
            "UPDATE entry_guard_state SET exact_xgs1=zeroblob(length(exact_xgs1));");
    }

    private static void ExecuteWithKey(
        string path,
        byte[] key,
        string sql,
        int expectedChanges = 1)
    {
        SQLitePCL.Batteries_V2.Init();
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString());
        db.Open();
        Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(db.Handle, key));
        using var command = db.CreateCommand();
        command.CommandText = sql;
        Assert.Equal(expectedChanges, command.ExecuteNonQuery());
    }

    private static string TempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "deep-route01-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    internal static byte[] B(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
}
