using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

internal static class MailboxRandomKeyTestEncoding
{
    internal static int Apply(SqliteConnection connection, byte[] key)
    {
        Assert.Equal(32, key.Length);
        var bytes = new byte[67]; bytes[0] = (byte)'x'; bytes[1] = bytes[66] = (byte)'\'';
        ReadOnlySpan<byte> alphabet = "0123456789abcdef"u8;
        for (var i = 0; i < key.Length; i++) { bytes[2 + 2 * i] = alphabet[key[i] >> 4]; bytes[3 + 2 * i] = alphabet[key[i] & 15]; }
        try { return SQLitePCL.raw.sqlite3_key(connection.Handle, bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}

public sealed class SqliteDeepMailboxRandomKeyTests
{
    [Fact]
    public async Task CurrentRawKeyReopensEncryptedSchemaEightAndPreservesDurablePolicy()
    {
        using var fixture = new Fixture();
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            var policy = await store.ReadConnectionPolicyForTestsAsync();
            Assert.Equal(2, policy.Synchronous); Assert.Equal(1, policy.SecureDelete); Assert.Equal("wal", policy.JournalMode);
        }
        Assert.False(File.ReadAllBytes(fixture.Path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        using (var db = fixture.Open(raw: true))
        { using var read = db.CreateCommand(); read.CommandText = "PRAGMA user_version;"; Assert.Equal(8L, read.ExecuteScalar()); }
        using (SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key))) { }
        var digest = SHA256.HashData(File.ReadAllBytes(fixture.Path));
        using (var wrongMode = fixture.Open(raw: false))
        { using var read = wrongMode.CreateCommand(); read.CommandText = "SELECT count(*) FROM sqlite_schema;"; Assert.Throws<SqliteException>(() => read.ExecuteScalar()); }
        Assert.Equal(digest, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    public void RetiredPasswordModeAndRetiredRawSchemaRejectWithoutRepairOrMutation(int retiredVersion)
    {
        using var fixture = new Fixture();
        using (var old = fixture.Open(raw: false))
        { using var write = old.CreateCommand(); write.CommandText = $"CREATE TABLE negative_probe(value INTEGER); PRAGMA user_version={retiredVersion};"; write.ExecuteNonQuery(); }
        var oldDigest = SHA256.HashData(File.ReadAllBytes(fixture.Path));
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key)));
        Assert.Equal(oldDigest, SHA256.HashData(File.ReadAllBytes(fixture.Path)));
        using var rawFixture = new Fixture();
        using (new SqliteDeepMailboxStore(new(rawFixture.Path, rawFixture.Key))) { }
        using (var old = rawFixture.Open(raw: true))
        { using var write = old.CreateCommand(); write.CommandText = $"PRAGMA user_version={retiredVersion};"; write.ExecuteNonQuery(); }
        var schemaDigest = SHA256.HashData(File.ReadAllBytes(rawFixture.Path));
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(new(rawFixture.Path, rawFixture.Key)));
        Assert.Equal(schemaDigest, SHA256.HashData(File.ReadAllBytes(rawFixture.Path)));
    }

    [Theory]
    [InlineData(0)] [InlineData(31)] [InlineData(33)]
    public void WrongLengthRejectsBeforeCreation(int length)
    {
        using var fixture = new Fixture();
        Assert.Throws<ArgumentException>(() => new SqliteDeepMailboxStore(new(fixture.Path, RandomNumberGenerator.GetBytes(length))));
        Assert.False(File.Exists(fixture.Path));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-dmb1-raw-key-" + Guid.NewGuid().ToString("N"));
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
        internal string Path => System.IO.Path.Combine(directory, "probe.db");
        internal Fixture() { Directory.CreateDirectory(directory); SQLitePCL.Batteries_V2.Init(); }
        internal SqliteConnection Open(bool raw)
        {
            var db = new SqliteConnection($"Data Source={Path};Pooling=False");
            db.Open();
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, raw ? MailboxRandomKeyTestEncoding.Apply(db, Key) : SQLitePCL.raw.sqlite3_key(db.Handle, Key));
            return db;
        }
        public void Dispose() { CryptographicOperations.ZeroMemory(Key); Directory.Delete(directory, recursive: true); }
    }
}
