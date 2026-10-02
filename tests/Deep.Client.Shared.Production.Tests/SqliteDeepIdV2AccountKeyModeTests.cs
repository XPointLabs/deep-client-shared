using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SqliteDeepIdV2AccountKeyModeTests
{
    [Fact]
    public void ActualRandomAccountFactoryReopensEncryptedPagesAndRejectsOtherKeyModes()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-account-key-mode-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "raw.dsv2");
        var wrongModePath = Path.Combine(directory, "wrong-mode.dsv2");
        var key = RandomNumberGenerator.GetBytes(32); key[0] = key[31] = 0;
        var wrong = key.ToArray(); wrong[1] ^= 1;
        try
        {
            using (var created = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(path, key, create: true))
            { using var command = created.CreateCommand(); command.CommandText = "CREATE TABLE probe(n INTEGER); INSERT INTO probe VALUES(7);"; command.ExecuteNonQuery(); }
            using (var reopened = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(path, key, create: false))
            { using var read = reopened.CreateCommand(); read.CommandText = "SELECT n FROM probe;"; Assert.Equal(7L, read.ExecuteScalar()); }
            Assert.False(File.ReadAllBytes(path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            Assert.Equal((2, 1, "delete"), SqliteDeepIdV2AccountGeneration.ReadConnectionPolicyForTests(path, key, false));
            Assert.Throws<SqliteException>(() => { using var _ = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(path, wrong, false); });
            Assert.Throws<CryptographicException>(() => { using var _ = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(path, new byte[31], false); });
            Assert.Throws<CryptographicException>(() => { using var _ = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(path, new byte[32], false); });
            using (var oldMode = new SqliteConnection($"Data Source={path};Pooling=False"))
            {
                oldMode.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(oldMode.Handle, key));
                using var read = oldMode.CreateCommand(); read.CommandText = "SELECT n FROM probe;";
                Assert.Throws<SqliteException>(() => read.ExecuteScalar());
            }
            using (var oldMode = new SqliteConnection($"Data Source={wrongModePath};Pooling=False"))
            {
                oldMode.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(oldMode.Handle, key));
                using var write = oldMode.CreateCommand(); write.CommandText = "CREATE TABLE probe(n INTEGER); INSERT INTO probe VALUES(7);"; write.ExecuteNonQuery();
            }
            Assert.Throws<SqliteException>(() => { using var _ = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(wrongModePath, key, false); });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(wrong);
            foreach (var file in new[] { path, wrongModePath })
                foreach (var suffix in new[] { "", "-journal", "-wal", "-shm" }) File.Delete(file + suffix);
            Directory.Delete(directory, recursive: false);
        }
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(4)]
    public async Task RetiredOrUnknownProtectedKeyRecordIsRejectedWithoutMutation(ushort generation)
    {
        var network = Enumerable.Repeat((byte)1, 16).ToArray();
        var account = Enumerable.Repeat((byte)2, 32).ToArray();
        var record = new byte[120]; "DSK2"u8.CopyTo(record); BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(4), generation);
        network.CopyTo(record, 8); account.CopyTo(record, 24); record.AsSpan(56, 64).Fill(3);
        using var storage = new InMemoryDeepSecureStorage();
        await storage.WriteBatchAsync([new("deep.store.v2.sql-generation", record)]);
        await Assert.ThrowsAsync<InvalidDataException>(() => SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, network, account, default));
        using var retained = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
        Assert.Equal(record, retained!.Use(bytes => bytes.ToArray()));
    }
}
