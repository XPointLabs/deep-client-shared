using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Microsoft.Data.Sqlite;
using static Deep.Client.Shared.Production.Tests.Did2RouteHistoryDecisionTests;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MessagingRouteHistorySqlTests
{
    [Fact]
    public void InitialOwnedAuditClassifiesOnlyActualCanonicalEmptySql()
    {
        using var fixture = new SqlFixture();
        Assert.True(fixture.Sql.ClassifyInitialOwnedNativeAudit(fixture.Empty, null));
        Assert.Throws<InvalidDataException>(() => fixture.Sql.ClassifyInitialOwnedNativeAudit(fixture.Empty, new byte[672]));
        Assert.Equal(fixture.Empty.Exact.ToArray(), fixture.Sql.VerifyTip().Exact.ToArray());
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("initial")]
    [InlineData("mirror")]
    public void InitialOwnedAuditRejectsCorruptedEmptySqlWithoutRepair(string defect)
    {
        using var fixture = new SqlFixture();
        using (var corrupt = fixture.Connection.CreateCommand())
        {
            corrupt.CommandText = defect switch
            {
                "scope" => "DELETE FROM scope;",
                "initial" => "INSERT INTO initial_events(singleton,envelope,session_init,hello,metadata) VALUES(1,zeroblob(1),zeroblob(1),zeroblob(1),zeroblob(672));",
                "mirror" => "UPDATE archive_state SET exact=zeroblob(608);",
                _ => throw new ArgumentOutOfRangeException(nameof(defect))
            };
            Assert.Equal(1, corrupt.ExecuteNonQuery());
        }
        var error = Record.Exception(() => fixture.Sql.ClassifyInitialOwnedNativeAudit(fixture.Empty, null));
        Assert.True(error is InvalidDataException or CryptographicException);
        using var unchanged = fixture.Connection.CreateCommand();
        unchanged.CommandText = defect switch
        {
            "scope" => "SELECT count(*) FROM scope;",
            "initial" => "SELECT count(*) FROM initial_events WHERE metadata=zeroblob(672);",
            _ => "SELECT count(*) FROM archive_state WHERE exact=zeroblob(608);"
        };
        Assert.Equal(defect == "scope" ? 0L : 1L, Convert.ToInt64(unchanged.ExecuteScalar()));
    }

    [Fact]
    public void CurrentSchemaRequiresDecisionOriginalsAndOnly1136ByteReducers()
    {
        using var fixture = new SqlFixture();
        using (var query = fixture.Connection.CreateCommand())
        {
            query.CommandText = "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%';";
            Assert.Equal(9L, Convert.ToInt64(query.ExecuteScalar()));
            query.CommandText = "SELECT sql FROM sqlite_schema WHERE name='route_decisions';";
            Assert.Equal("CREATE TABLE route_decisions (operation BLOB PRIMARY KEY NOT NULL CHECK(typeof(operation)='blob' AND length(operation)=32), ordinal INTEGER NOT NULL UNIQUE CHECK(typeof(ordinal)='integer' AND ordinal BETWEEN 1 AND 9223372036854775807), decision BLOB NOT NULL CHECK(typeof(decision)='blob' AND length(decision)=1024), metadata BLOB NOT NULL CHECK(typeof(metadata)='blob' AND length(metadata)=672))",
                Assert.IsType<string>(query.ExecuteScalar()));
            query.CommandText = "SELECT length(exact) FROM archive_reducers;";
            Assert.Equal(1136L, Convert.ToInt64(query.ExecuteScalar()));
            query.CommandText = "UPDATE archive_reducers SET exact=substr(exact,1,960);";
            Assert.Throws<SqliteException>(() => query.ExecuteNonQuery());
            query.CommandText = "SELECT length(exact) FROM archive_reducers;";
            Assert.Equal(1136L, Convert.ToInt64(query.ExecuteScalar()));
        }
        Assert.Equal(fixture.Empty.Exact.ToArray(), fixture.Sql.VerifyTip().Exact.ToArray());
    }

    [Fact]
    public void ActualUnrootedDecisionRowCannotBecomeNativeStateAndRejectionDoesNotRepairIt()
    {
        using var fixture = new SqlFixture();
        using (var insert = fixture.Connection.CreateCommand())
        {
            insert.CommandText = "INSERT INTO route_decisions(operation,ordinal,decision,metadata) VALUES($op,1,$body,$metadata);";
            insert.Parameters.AddWithValue("$op", Hash(1)); insert.Parameters.AddWithValue("$body", new byte[1024]);
            insert.Parameters.AddWithValue("$metadata", new byte[672]); Assert.Equal(1, insert.ExecuteNonQuery());
        }
        Assert.Throws<InvalidDataException>(() => fixture.Sql.VerifyTip());
        using var read = fixture.Connection.CreateCommand();
        read.CommandText = "SELECT rowid,ordinal,operation,decision,metadata FROM route_decisions;";
        using var row = read.ExecuteReader(); Assert.True(row.Read()); Assert.True(row.GetInt64(0) > 0);
        Assert.Equal(1L, row.GetInt64(1)); Assert.Equal(Hash(1), row.GetFieldValue<byte[]>(2));
        Assert.Equal(new byte[1024], row.GetFieldValue<byte[]>(3)); Assert.Equal(new byte[672], row.GetFieldValue<byte[]>(4));
        Assert.False(row.Read());
    }

    private sealed class SqlFixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "did2-route-history-sql-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        internal SqliteConnection Connection { get; }
        internal Did2MessagingSqlJournal Sql { get; }
        internal Did2MessagingFloor Empty { get; }
        internal SqlFixture()
        {
            Directory.CreateDirectory(directory); var scope = Scope(); Empty = Did2MessagingFloor.Empty(scope);
            Connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(Path.Combine(directory, "native.dms2"), key, true);
            Sql = new(Connection, scope, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope)); Sql.CreateRegisteredEmpty(Empty);
        }
        public void Dispose()
        { Connection.Dispose(); CryptographicOperations.ZeroMemory(key); Directory.Delete(directory, recursive: true); }
    }
}
