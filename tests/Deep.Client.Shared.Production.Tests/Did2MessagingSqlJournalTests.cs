using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingSqlJournalTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("extra-table")]
    [InlineData("missing-scope")]
    [InlineData("version")]
    [InlineData("wal")]
    [InlineData("weak-sync")]
    [InlineData("weak-delete")]
    public async Task EmptySqlProjectionIsExactAndRejectsSchemaIdentityOrPolicyChanges(string defect)
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-msg-sql-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "session.dms2"); var key = RandomNumberGenerator.GetBytes(32);
        var scope = Scope(); var floor = Did2MessagingFloor.Empty(scope);
        try
        {
            using (var connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, true))
            {
                var sql = new Did2MessagingSqlJournal(connection, scope); sql.CreateRegisteredEmpty(floor);
                Assert.Equal(floor.Exact.ToArray(), sql.VerifyTip().Exact.ToArray());
                Assert.Throws<InvalidDataException>(() => sql.ReadVerifiedLatest(floor));
                Assert.Throws<InvalidDataException>(() => sql.CreateVerifiedTransitionContext(floor, new byte[32].Select(_ => (byte)1).ToArray(), []));
                Assert.Throws<InvalidDataException>(() => sql.CreateRegisteredEmpty(floor));
                using var storage = new InMemoryDeepSecureStorage();
                var checkpoint = new Did2MessagingProtectedCheckpoint(storage, scope);
                await checkpoint.InitializeRegisteredSessionAsync(default);
                await storage.WriteBatchAsync([new(scope.FloorSlot + ".pending.0", new byte[] { 1 })]);
                var owner = new Did2MessagingDurableCustody(scope, checkpoint, sql);
                Assert.Equal(floor.Exact.ToArray(), (await owner.ReconcileAsync(default)).Exact.ToArray());
                using (var erased = await storage.ReadOwnedAsync(scope.FloorSlot + ".pending.0")) Assert.Null(erased);
                await Assert.ThrowsAsync<InvalidOperationException>(() => owner.ReadActiveStateAsync(default));
                using var mutate = connection.CreateCommand();
                mutate.CommandText = defect switch
                {
                    "extra-table" => "CREATE TABLE unexpected(value BLOB);", "missing-scope" => "DELETE FROM scope;",
                    "version" => "PRAGMA user_version=1;", "wal" => "PRAGMA journal_mode=WAL;",
                    "weak-sync" => "PRAGMA synchronous=NORMAL;", "weak-delete" => "PRAGMA secure_delete=OFF;", _ => "SELECT 1;"
                };
                mutate.ExecuteNonQuery();
                if (defect != "none") Assert.ThrowsAny<Exception>(() => sql.VerifyTip());
            }
            if (defect == "none")
            {
                using var connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, false);
                Assert.Equal(floor.Exact.ToArray(), new Did2MessagingSqlJournal(connection, scope).VerifyTip().Exact.ToArray());
            }
            Assert.False(File.ReadAllBytes(path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file); Directory.Delete(directory);
        }
    }
    [Fact]
    public void RandomKeyModeReopensWithZeroBytesAndRejectsPasswordModeOrWrongKey()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-msg-key-mode-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var rawPath = Path.Combine(directory, "raw.dms2"); var passwordPath = Path.Combine(directory, "password.dms2");
        var key = RandomNumberGenerator.GetBytes(32); key[0] = 0; key[31] = 0;
        var wrong = key.ToArray(); wrong[1] ^= 1;
        try
        {
            var scope = Scope(); var floor = Did2MessagingFloor.Empty(scope);
            using (var connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(rawPath, key, true))
                new Did2MessagingSqlJournal(connection, scope).CreateRegisteredEmpty(floor);
            using (var reopened = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(rawPath, key, false))
                Assert.Equal(floor.Exact.ToArray(), new Did2MessagingSqlJournal(reopened, scope).VerifyTip().Exact.ToArray());
            Assert.False(File.ReadAllBytes(rawPath).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            Assert.Equal((2, 1, "delete"), SqliteDeepIdV2AccountGeneration.ReadConnectionPolicyForTests(rawPath, key, false));
            Assert.ThrowsAny<Exception>(() =>
            {
                using var _ = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(rawPath, wrong, false);
            });
            // A disposable wrong-mode file is a negative input, never an
            // account/runtime compatibility reader or a retained old vector.
            using (var wrongMode = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={passwordPath};Pooling=False"))
            {
                wrongMode.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(wrongMode.Handle, key));
                using var create = wrongMode.CreateCommand(); create.CommandText = "CREATE TABLE negative_key_probe(n INTEGER); INSERT INTO negative_key_probe VALUES(1);"; create.ExecuteNonQuery();
            }
            Assert.ThrowsAny<Exception>(() =>
            {
                using var _ = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(passwordPath, key, false);
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(wrong);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(33)]
    public void AbsentOrWrongSizedRandomKeyRejectsBeforeFileCreation(int bytes)
    {
        var path = Path.Combine(Path.GetTempPath(), "did2-msg-wrong-key-" + Guid.NewGuid().ToString("N") + ".dms2");
        Assert.Throws<CryptographicException>(() =>
        {
            using var _ = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, new byte[bytes], true);
        });
        Assert.False(File.Exists(path));
    }
    private static Did2MessagingSessionScope Scope()
    {
        var bytes = new byte[404]; bytes[0] = 1; bytes[1] = 1; bytes.AsSpan(4, 16).Fill(1);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) bytes.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(bytes);
    }
}
