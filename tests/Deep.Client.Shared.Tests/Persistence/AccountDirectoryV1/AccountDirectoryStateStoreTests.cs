using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.AccountDirectoryV1;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Client.Shared.Tests.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence.AccountDirectoryV1;

[Collection("SQLite global pool isolation")]
public sealed class AccountDirectoryStateStoreTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InMemoryAndSqlite_HaveAlignedCasAndSnapshotIsolation(bool sqlite)
    {
        using var fixture = StoreFixture.Create(sqlite);
        var initial = AccountDirectoryV1Fixture.Snapshot();
        var applied = await fixture.Store.CompareExchangeAsync(null, initial, CancellationToken.None);
        Assert.Equal(AccountDirectoryStoreWriteDisposition.Applied, applied.Disposition);
        initial.ProtectedLkg!.ExactAdh1.ToArray()[0] ^= 0xFF;
        var read = (await fixture.Store.ReadAsync(CancellationToken.None))!;
        Assert.Equal(1UL, read.Revision); Assert.False(read.ForkLatched);

        var replacement = new AccountDirectoryStateSnapshot(2, read.ProtectedLkg, false,
            [AccountDirectoryV1Fixture.Subject(AccountDirectoryClientState.RevocationRefreshRequired,
                AccountDirectoryRefreshReason.ProofUnavailable)]);
        var conflict = await fixture.Store.CompareExchangeAsync(null, replacement, CancellationToken.None);
        Assert.Equal(AccountDirectoryStoreWriteDisposition.Conflict, conflict.Disposition);
        Assert.Equal(1UL, conflict.Snapshot!.Revision);
        Assert.Equal(AccountDirectoryStoreWriteDisposition.Applied,
            (await fixture.Store.CompareExchangeAsync(1, replacement, CancellationToken.None)).Disposition);
    }

    [Fact]
    public async Task Sqlite_ReopenPreservesProtectedLkgForkAndSubjects()
    {
        var directory = TempDirectory(); var path = Path.Combine(directory, "directory.db"); var options = Options(path);
        try
        {
            var blocked = AccountDirectoryV1Fixture.Subject(AccountDirectoryClientState.DirectoryForkBlocked);
            using (var store = new SqliteAccountDirectoryStateStore(options))
                await store.CompareExchangeAsync(null, AccountDirectoryV1Fixture.Snapshot(fork: true, subjects: blocked), CancellationToken.None);
            using var reopened = new SqliteAccountDirectoryStateStore(options);
            var state = (await reopened.ReadAsync(CancellationToken.None))!;
            Assert.True(state.ForkLatched); Assert.Equal(1UL, state.ProtectedLkg!.LogGeneration);
            Assert.Equal(AccountDirectoryClientState.DirectoryForkBlocked, Assert.Single(state.Subjects).State);
        }
        finally { Delete(directory); }
    }

    [Theory]
    [InlineData((int)AccountDirectoryStoreFailpoint.AfterHeadWrite)]
    [InlineData((int)AccountDirectoryStoreFailpoint.AfterSubjectReplacement)]
    [InlineData((int)AccountDirectoryStoreFailpoint.BeforeCommit)]
    public async Task Sqlite_InjectedCrashRollsBackHeadAndSubjectsAtomically(int failpointValue)
    {
        var directory = TempDirectory(); var path = Path.Combine(directory, "directory.db"); var options = Options(path);
        try
        {
            using (var store = new SqliteAccountDirectoryStateStore(options))
            {
                var initial = AccountDirectoryV1Fixture.Snapshot();
                await store.CompareExchangeAsync(null, initial, CancellationToken.None);
                var replacement = new AccountDirectoryStateSnapshot(2, initial.ProtectedLkg, true,
                    [AccountDirectoryV1Fixture.Subject(AccountDirectoryClientState.DirectoryForkBlocked)]);
                using var hook = AccountDirectoryStateStoreTestHooks.Push(point =>
                {
                    if (point == (AccountDirectoryStoreFailpoint)failpointValue)
                        throw new AccountDirectoryStoreInjectedCrashException(point);
                });
                await Assert.ThrowsAsync<AccountDirectoryStoreInjectedCrashException>(() =>
                    store.CompareExchangeAsync(1, replacement, CancellationToken.None).AsTask());
            }
            using var reopened = new SqliteAccountDirectoryStateStore(options);
            var restored = (await reopened.ReadAsync(CancellationToken.None))!;
            Assert.Equal(1UL, restored.Revision); Assert.False(restored.ForkLatched);
            Assert.Equal(AccountDirectoryClientState.Current, Assert.Single(restored.Subjects).State);
        }
        finally { Delete(directory); }
    }

    [Fact]
    public async Task Sqlite_IsEncryptedScopedAndRejectsWrongKey()
    {
        var directory = TempDirectory(); var path = Path.Combine(directory, "directory.db"); var options = Options(path);
        try
        {
            using (var store = new SqliteAccountDirectoryStateStore(options))
            {
                await store.CompareExchangeAsync(null, AccountDirectoryV1Fixture.Snapshot(), CancellationToken.None);
                Assert.False(new SqliteConnectionStringBuilder(store.ConnectionString).Pooling);
                Assert.NotEqual("SQLite format 3\0", ReadHeader(path));
            }
            Assert.Equal(AccountDirectoryStoreOpenFailure.UnreadableOrWrongKey,
                Assert.Throws<AccountDirectoryStoreOpenException>(() => new SqliteAccountDirectoryStateStore(
                    Options(path, keyMarker: 0xE2))).Reason);
            Assert.Equal(AccountDirectoryStoreOpenFailure.ScopeMismatch,
                Assert.Throws<AccountDirectoryStoreOpenException>(() => new SqliteAccountDirectoryStateStore(
                    Options(path, networkMarker: 0x12))).Reason);
        }
        finally { Delete(directory); }
    }

    [Fact]
    public void DisposeZeroizesOwnedKey()
    {
        var directory = TempDirectory();
        try
        {
            var store = new SqliteAccountDirectoryStateStore(Options(Path.Combine(directory, "directory.db")));
            store.Dispose(); Assert.True(store.IsKeyZeroedForTesting);
        }
        finally { Delete(directory); }
    }

    [Fact]
    public void Sqlite_RejectsDdlConstraintTampering()
    {
        var directory = TempDirectory(); var path = Path.Combine(directory, "directory.db"); var options = Options(path);
        try
        {
            using (var store = new SqliteAccountDirectoryStateStore(options)) { }
            using (var connection = OpenEncrypted(path, options))
            {
                using var command = connection.CreateCommand();
                command.CommandText = "PRAGMA writable_schema=ON; UPDATE sqlite_master SET sql=replace(sql,'state BETWEEN 1 AND 4','state BETWEEN 1 AND 5') WHERE name='account_directory_subjects'; PRAGMA writable_schema=OFF;";
                command.ExecuteNonQuery();
            }
            Assert.Equal(AccountDirectoryStoreOpenFailure.Corrupt,
                Assert.Throws<AccountDirectoryStoreOpenException>(() => new SqliteAccountDirectoryStateStore(options)).Reason);
        }
        finally { Delete(directory); }
    }

    [Fact]
    public async Task SqliteRestart_RestoresAuthenticatedLkg_ThenForwardProofSucceeds()
    {
        var fixture = AccountDirectoryRestartFixture.Load();
        var network = fixture.Bytes(fixture.Network);
        var authority = XPointNetworkAuthorityVerifier.Verify(
            new XPointNetworkGenesisPin(network, fixture.Bytes(fixture.AuthorityHash)),
            [fixture.Bytes(fixture.Xna)], [fixture.Bytes(fixture.Dts)]);
        var exactLkg = fixture.Bytes(fixture.LkgAdh); var parsedLkg = AccountDirectoryAdh1Codec.Decode(exactLkg);
        var protectedLkg = AccountDirectoryProtectedLkgState.RestorePersisted(
            exactLkg, fixture.Bytes(fixture.LkgHash), parsedLkg.LogGeneration, parsedLkg.TreeSize);
        var query = fixture.Bytes(fixture.Query);
        var subject = AccountDirectoryV1Fixture.Subject(leafMarker: query[0]);
        var directory = TempDirectory(); var path = Path.Combine(directory, "directory.db");
        var options = new SqliteAccountDirectoryStateStoreOptions(path,
            AccountDirectoryV1Fixture.Bytes(32, 0xE1), network, AccountDirectoryV1Fixture.Bytes(32, 0xC1),
            1, 1, AccountDirectoryStoreId32.FromBytes(AccountDirectoryV1Fixture.Bytes(32, 0xD1)));
        try
        {
            using (var store = new SqliteAccountDirectoryStateStore(options))
                Assert.Equal(AccountDirectoryStoreWriteDisposition.Applied,
                    (await store.CompareExchangeAsync(null,
                        new AccountDirectoryStateSnapshot(1, protectedLkg, false, [subject]),
                        CancellationToken.None)).Disposition);

            using var reopened = new SqliteAccountDirectoryStateStore(options);
            var client = new AccountDirectoryClient(reopened);
            var result = await client.RestoreVerifyAndApplyAsync(authority,
                fixture.Bytes(fixture.Head), fixture.Bytes(fixture.Dtt), fixture.Bytes(fixture.Adp),
                fixture.Bytes(fixture.Nonce), query,
                new AccountDirectoryMonotonicRequestWindow(AccountDirectoryV1Fixture.Bytes(16, 0x44),
                    1_000, 1_002, 1_003), null, 1, null, null, CancellationToken.None);

            Assert.False(result.ForkLatched);
            Assert.Equal(3UL, result.ProtectedLkg!.LogGeneration);
            Assert.Equal(AccountDirectoryClientState.RevocationRefreshRequired,
                result.Find(AccountDirectoryLeafKey32.FromBytes(query))!.State);
        }
        finally { Delete(directory); }
    }

    private static SqliteAccountDirectoryStateStoreOptions Options(string path, byte keyMarker = 0xE1,
        byte networkMarker = 0x11) => new(path, AccountDirectoryV1Fixture.Bytes(32, keyMarker),
            AccountDirectoryV1Fixture.Bytes(16, networkMarker), AccountDirectoryV1Fixture.Bytes(32, 0xC1),
            1, 1, AccountDirectoryStoreId32.FromBytes(AccountDirectoryV1Fixture.Bytes(32, 0xD1)));
    private static string TempDirectory() { var path = Path.Combine(Path.GetTempPath(), "deep-directory-v1-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(path); return path; }
    private static string ReadHeader(string path) { using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); var bytes = new byte[16]; Assert.Equal(16, stream.Read(bytes)); return System.Text.Encoding.ASCII.GetString(bytes); }
    private static SqliteConnection OpenEncrypted(string path, SqliteAccountDirectoryStateStoreOptions options)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, options.EncryptionKey.ToArray()));
        return connection;
    }
    private static void Delete(string path) { SqliteConnection.ClearAllPools(); for (var i = 0; i < 20 && Directory.Exists(path); i++) { try { Directory.Delete(path, true); return; } catch (IOException) { Thread.Sleep(25); SqliteConnection.ClearAllPools(); } } }

    private sealed class StoreFixture(IAccountDirectoryStateStore store, string? directory) : IDisposable
    {
        internal IAccountDirectoryStateStore Store { get; } = store;
        internal static StoreFixture Create(bool sqlite)
        {
            if (!sqlite) return new(new InMemoryAccountDirectoryStateStore(), null);
            var directory = TempDirectory(); return new(new SqliteAccountDirectoryStateStore(Options(Path.Combine(directory, "directory.db"))), directory);
        }
        public void Dispose() { (Store as IDisposable)?.Dispose(); if (directory is not null) Delete(directory); }
    }
}
