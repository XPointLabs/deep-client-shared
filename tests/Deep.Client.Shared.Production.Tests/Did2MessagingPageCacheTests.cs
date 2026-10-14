using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingPageCacheTests
{
    [Fact]
    public void MessagingNativeCacheIsConnectionLocalAndPreservesCipherPolicyAndOtherConnectionChanges()
    {
        SQLitePCL.Batteries_V2.Init();
        var directory = Path.Combine(Path.GetTempPath(), "did2-native-cache-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "messaging.db");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            // The unconfigured account opener shares the same native provider
            // and raw-key core. Observe its actual default, do not assume one.
            using (var provider = SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(
                Path.Combine(directory, "provider-default.db"), key, true))
                Console.WriteLine("Native provider default cache_size=" + Scalar(provider, "PRAGMA cache_size;"));
            using (var first = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, true))
            {
                AssertPolicy(first);
                using var create = first.CreateCommand();
                create.CommandText = "CREATE TABLE cache_probe(value BLOB NOT NULL); INSERT INTO cache_probe VALUES(X'01');";
                create.ExecuteNonQuery();
                Assert.Equal(new byte[] { 1 }, Value(first));
                using (var second = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, false))
                {
                    AssertPolicy(second);
                    using var update = second.CreateCommand();
                    update.CommandText = "UPDATE cache_probe SET value=X'02';";
                    Assert.Equal(1, update.ExecuteNonQuery());
                }
                // Native caching must not hide another connection's commit.
                Assert.Equal(new byte[] { 2 }, Value(first));
                using var change = first.CreateCommand();
                change.CommandText = "PRAGMA cache_size=-1024;";
                change.ExecuteNonQuery();
                Assert.Equal(-1024L, Scalar(first, "PRAGMA cache_size;"));
            }
            Assert.False(File.ReadAllBytes(path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            using var reopened = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, false);
            AssertPolicy(reopened);
            Assert.Equal(new byte[] { 2 }, Value(reopened));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    private static void AssertPolicy(SqliteConnection connection)
    {
        Assert.Equal(-8192L, Scalar(connection, "PRAGMA cache_size;"));
        Assert.Equal(2L, Scalar(connection, "PRAGMA synchronous;"));
        Assert.Equal(1L, Scalar(connection, "PRAGMA secure_delete;"));
        Assert.Equal(1L, Scalar(connection, "PRAGMA foreign_keys;"));
        using var journal = connection.CreateCommand();
        journal.CommandText = "PRAGMA journal_mode;";
        Assert.Equal("delete", journal.ExecuteScalar());
        using var cipher = connection.CreateCommand();
        cipher.CommandText = "PRAGMA cipher_version;";
        Assert.StartsWith("4.", Convert.ToString(cipher.ExecuteScalar())!);
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand(); command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }
    private static byte[] Value(SqliteConnection connection)
    {
        using var command = connection.CreateCommand(); command.CommandText = "SELECT value FROM cache_probe;";
        return (byte[])command.ExecuteScalar()!;
    }
}
