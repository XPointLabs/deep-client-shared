using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Microsoft.Data.Sqlite;
using Xunit.Abstractions;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeviceSqlCipherConnectionCostTests(ITestOutputHelper output)
{
    // Measurement only: no machine-dependent timing assertion or longer dispatch budget.
    // Provider-mode probes are separate disposable files, never production device state.
    [Fact]
    public void AuthenticatedDeviceReopensAndIsolatedProviderKeyModes()
    {
        SQLitePCL.Batteries_V2.Init();
        var directory = Path.Combine(Path.GetTempPath(), "deep-device-connection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var key = RandomNumberGenerator.GetBytes(32);
        var account = RandomNumberGenerator.GetBytes(32);
        var instance = RandomNumberGenerator.GetBytes(32);
        try
        {
            var devicePath = Path.Combine(directory, "device.db");
            SqliteDeviceStateStoreOptions Options(bool create) => new(devicePath, key,
                DeviceAccountId32.FromBytes(account), 1, 1, DeviceOperationId32.FromBytes(instance), create);
            using (new SqliteDeviceStateStore(Options(true))) { }
            var deviceCost = Stopwatch.StartNew();
            for (var i = 0; i < 3; i++) using (new SqliteDeviceStateStore(Options(false))) { }
            deviceCost.Stop();
            output.WriteLine("authenticated_device_reopens=3 elapsed_ms={0:F1}", deviceCost.Elapsed.TotalMilliseconds);

            foreach (var raw in new[] { false, true })
            {
                var path = Path.Combine(directory, raw ? "raw.db" : "password.db");
                using (var db = Open(path, raw))
                {
                    using var command = db.CreateCommand();
                    command.CommandText = "CREATE TABLE probe(value INTEGER NOT NULL); INSERT INTO probe VALUES(1);";
                    command.ExecuteNonQuery();
                }
                var cost = Stopwatch.StartNew();
                for (var i = 0; i < 3; i++)
                {
                    using var db = Open(path, raw);
                    using var command = db.CreateCommand(); command.CommandText = "SELECT value FROM probe;";
                    Assert.Equal(1L, command.ExecuteScalar());
                }
                cost.Stop();
                output.WriteLine("provider_raw_mode={0} authenticated_reopens=3 elapsed_ms={1:F1}", raw, cost.Elapsed.TotalMilliseconds);
                var digest = SHA256.HashData(File.ReadAllBytes(path));
                using (var opposite = Open(path, !raw))
                {
                    using var command = opposite.CreateCommand(); command.CommandText = "SELECT count(*) FROM sqlite_master;";
                    Assert.Throws<SqliteException>(() => command.ExecuteScalar());
                }
                Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(path)));
                Assert.False(File.ReadAllBytes(path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            }

            SqliteConnection Open(string path, bool raw)
            {
                var db = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = path, Pooling = false, Cache = SqliteCacheMode.Private }.ToString());
                try
                {
                    db.Open();
                    Assert.Equal(SQLitePCL.raw.SQLITE_OK, raw
                        ? MailboxRandomKeyTestEncoding.Apply(db, key) : SQLitePCL.raw.sqlite3_key(db.Handle, key));
                    return db;
                }
                catch { db.Dispose(); throw; }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(account);
            CryptographicOperations.ZeroMemory(instance); Directory.Delete(directory, recursive: true);
        }
    }
}
