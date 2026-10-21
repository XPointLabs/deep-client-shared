using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Deep.Client.Shared.Production.Tests;

public sealed class PreKeySqlCipherConnectionKeyTests
{
    [Fact]
    public void OriginalPasswordFilesRoundTripOptimizedWritesAndColdNativeReads()
    {
        using var fixture = new Database();
        using var key = new PreKeySqlCipherConnectionKey();
        for (var i = 0; i < 3; i++)
        {
            using var connection = fixture.Open();
            key.ApplyExisting(connection, fixture.Path, fixture.Password);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM probe;";
            Assert.Equal(i, Convert.ToInt32(command.ExecuteScalar()));
            command.CommandText = "INSERT INTO probe VALUES(1);"; command.ExecuteNonQuery();
        }
        Assert.Equal(1, key.Derivations);
        using var cold = fixture.OpenNative();
        using var read = cold.CreateCommand(); read.CommandText = "SELECT count(*) FROM probe;";
        Assert.Equal(3, Convert.ToInt32(read.ExecuteScalar()));
    }

    [Fact]
    public void WrongPasswordStillFailsPageAuthentication()
    {
        using var fixture = new Database(); using var key = new PreKeySqlCipherConnectionKey();
        using var connection = fixture.Open();
        var wrong = RandomNumberGenerator.GetBytes(32);
        try
        {
            key.ApplyExisting(connection, fixture.Path, wrong);
            using var command = connection.CreateCommand(); command.CommandText = "SELECT count(*) FROM probe;";
            Assert.Throws<SqliteException>(() => command.ExecuteScalar());
        }
        finally { CryptographicOperations.ZeroMemory(wrong); }
    }

    [Fact]
    public void ChangedKeyOrFileOrSaltCannotReuseDerivedMaterial()
    {
        using var fixture = new Database(); using var other = new Database();
        using var key = new PreKeySqlCipherConnectionKey();
        using (var first = fixture.Open()) key.ApplyExisting(first, fixture.Path, fixture.Password);
        using (var connection = fixture.Open())
            Assert.Throws<CryptographicException>(() => key.ApplyExisting(connection, fixture.Path, other.Password));
        using (var connection = other.Open())
            Assert.Throws<CryptographicException>(() => key.ApplyExisting(connection, other.Path, fixture.Password));
        using (var file = new FileStream(fixture.Path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        { var value = file.ReadByte(); file.Position = 0; file.WriteByte((byte)(value ^ 1)); }
        using (var connection = fixture.Open())
            Assert.Throws<CryptographicException>(() => key.ApplyExisting(connection, fixture.Path, fixture.Password));
        Assert.Equal(1, key.Derivations);
    }

    [Fact]
    public void DisposedScopeAndTruncatedFileRejectBeforeDerivation()
    {
        using var fixture = new Database(); var key = new PreKeySqlCipherConnectionKey(); key.Dispose();
        using var connection = fixture.Open();
        Assert.Throws<ObjectDisposedException>(() => key.ApplyExisting(connection, fixture.Path, fixture.Password));
        using var active = new PreKeySqlCipherConnectionKey();
        var shortPath = System.IO.Path.Combine(fixture.Directory, "short.db");
        using (var file = new FileStream(shortPath, FileMode.CreateNew)) file.WriteByte(1);
        using var truncated = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = shortPath, Pooling = false }.ToString());
        truncated.Open();
        Assert.Throws<EndOfStreamException>(() => active.ApplyExisting(truncated, shortPath, fixture.Password));
        Assert.Equal(0, active.Derivations);
    }

    private sealed class Database : IDisposable
    {
        internal string Directory { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-pkv2-key-" + Guid.NewGuid().ToString("N"));
        internal string Path => System.IO.Path.Combine(Directory, "probe.db");
        internal byte[] Password { get; } = RandomNumberGenerator.GetBytes(32);
        internal Database()
        {
            SQLitePCL.Batteries_V2.Init(); System.IO.Directory.CreateDirectory(Directory);
            using var connection = OpenNative(create: true);
            using var command = connection.CreateCommand(); command.CommandText = "CREATE TABLE probe(value INTEGER NOT NULL);";
            command.ExecuteNonQuery();
        }
        internal SqliteConnection Open() => OpenConnection(false);
        private SqliteConnection OpenConnection(bool create)
        {
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = Path, Mode = create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            connection.Open(); return connection;
        }
        internal SqliteConnection OpenNative(bool create = false)
        {
            var connection = OpenConnection(create);
            Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, Password));
            return connection;
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Password);
            System.IO.Directory.Delete(Directory, recursive: true);
        }
    }
}
