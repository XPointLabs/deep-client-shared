using System.Security.Cryptography;
using Deep.Client.Shared.Domain.DeviceV1;
using Deep.Client.Shared.Persistence.DeviceV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeviceSqlCipherRandomKeyTests
{
    [Fact]
    public async Task CurrentEncryptedGenerationReopensAndKeepsConnectionPolicyAndReadOnlySource()
    {
        using var fixture = new Fixture();
        using (var created = new SqliteDeviceStateStore(fixture.Options()))
        {
            Assert.Equal((2L, 1L, "delete", 1L), created.ReadConnectionPolicyForTesting());
            Assert.False((await created.ReadAsync(DeviceAccountId32.FromBytes(fixture.Account), 1, default)).Found);
            created.ValidateEncryptedFilesForTesting();
        }
        Assert.False(File.ReadAllBytes(fixture.Path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        using (var reopened = new SqliteDeviceStateStore(fixture.Options(create: false)))
        {
            Assert.Equal((2L, 1L, "delete", 1L), reopened.ReadConnectionPolicyForTesting());
            reopened.Dispose(); Assert.True(reopened.IsKeyZeroedForTesting);
            Assert.Throws<ObjectDisposedException>(() => reopened.ReadConnectionPolicyForTesting());
        }
        using var readOnly = fixture.Open(raw: true, readOnly: true);
        SqliteDeviceStateStore.RequireReadOnlyMailboxSource(readOnly, fixture.Instance, fixture.Account);
        using var version = readOnly.CreateCommand(); version.CommandText = "PRAGMA user_version;";
        Assert.Equal(6L, version.ExecuteScalar());
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void RetiredPasswordModeOrRawSchemaRejectWithoutMutation(bool raw)
    {
        using var fixture = new Fixture();
        if (raw) using (new SqliteDeviceStateStore(fixture.Options())) { }
        using (var old = fixture.Open(raw))
        {
            using var command = old.CreateCommand();
            command.CommandText = raw ? "PRAGMA user_version=5;" : "CREATE TABLE negative_probe(value INTEGER); PRAGMA user_version=5;";
            command.ExecuteNonQuery();
        }
        var digest = SHA256.HashData(File.ReadAllBytes(fixture.Path));
        var error = Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(fixture.Options(create: false)));
        Assert.Equal(raw ? DeviceStateStoreOpenFailure.UnsupportedGeneration : DeviceStateStoreOpenFailure.UnreadableOrWrongKey, error.Reason);
        Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
    }

    [Theory]
    [InlineData(0)] [InlineData(31)] [InlineData(33)] [InlineData(32)]
    public void InvalidLengthOrZeroKeyRejectsBeforeCreation(int length)
    {
        using var fixture = new Fixture();
        var key = length == 32 ? new byte[32] : RandomNumberGenerator.GetBytes(length);
        try
        {
            Assert.Throws<ArgumentException>(() => fixture.Options(key: key));
            Assert.False(File.Exists(fixture.Path));
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Fact]
    public void WrongKeyScopeOrCorruptPageRefuseWithoutRepair()
    {
        using var fixture = new Fixture();
        using (new SqliteDeviceStateStore(fixture.Options())) { }
        var digest = SHA256.HashData(File.ReadAllBytes(fixture.Path));
        var wrong = RandomNumberGenerator.GetBytes(32);
        try
        {
            Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(fixture.Options(create: false, key: wrong)));
            Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
            var error = Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(new(fixture.Path,
                fixture.Key, DeviceAccountId32.FromBytes(wrong), 1, 1, DeviceOperationId32.FromBytes(fixture.Instance), false)));
            Assert.Equal(DeviceStateStoreOpenFailure.ScopeMismatch, error.Reason);
            Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
            // Deliberate corruption only in this disposable encrypted fixture.
            using (var file = File.Open(fixture.Path, FileMode.Open, FileAccess.ReadWrite))
            { file.Position = 100; var value = file.ReadByte(); file.Position = 100; file.WriteByte((byte)(value ^ 1)); }
            var corrupted = SHA256.HashData(File.ReadAllBytes(fixture.Path));
            Assert.Throws<DeviceStateStoreOpenException>(() => new SqliteDeviceStateStore(fixture.Options(create: false)));
            Assert.Equal(corrupted, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
        }
        finally { CryptographicOperations.ZeroMemory(wrong); }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-device-raw-" + Guid.NewGuid().ToString("N"));
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
        internal byte[] Account { get; } = RandomNumberGenerator.GetBytes(32);
        internal byte[] Instance { get; } = RandomNumberGenerator.GetBytes(32);
        internal string Path => System.IO.Path.Combine(directory, "device.db");
        internal Fixture() { Directory.CreateDirectory(directory); SQLitePCL.Batteries_V2.Init(); }
        internal SqliteDeviceStateStoreOptions Options(bool create = true, byte[]? key = null) => new(Path, key ?? Key,
            DeviceAccountId32.FromBytes(Account), 1, 1, DeviceOperationId32.FromBytes(Instance), create);
        internal SqliteConnection Open(bool raw, bool readOnly = false)
        {
            var db = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path, Pooling = false, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate }.ToString());
            try
            {
                db.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, raw
                    ? MailboxRandomKeyTestEncoding.Apply(db, Key) : SQLitePCL.raw.sqlite3_key(db.Handle, Key));
                return db;
            }
            catch { db.Dispose(); throw; }
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key); CryptographicOperations.ZeroMemory(Account);
            CryptographicOperations.ZeroMemory(Instance); Directory.Delete(directory, recursive: true);
        }
    }
}
