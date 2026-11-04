using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class AuthenticatedDirectDmc2InboxTests
{
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task SchemaCanonicalNewlines_ReopenRetainsDataAndExactStoredSchema(string newline)
    {
        using var fixture = new Fixture();
        var exact = Event("retained across schema newline validation");
        try
        {
            using (var store = Open(true, fixture))
            using (var handoff = Handoff(exact, 0x71))
                await Materialize(store, handoff);
            // Only this disposable fixture is rewritten to model databases
            // created by the same trusted DDL compiled with either newline.
            WithSchemaFixture(fixture, connection =>
            {
                using var rewrite = connection.CreateCommand();
                rewrite.CommandText = "PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(replace(sql,char(13)||char(10),char(10)),char(10),$newline) WHERE substr(name,1,7)<>'sqlite_'; PRAGMA writable_schema=OFF;";
                rewrite.Parameters.AddWithValue("$newline", newline); rewrite.ExecuteNonQuery();
            });
            var before = ReadSchemaFixtureFrames(fixture);
            Assert.Contains(before, frame => frame.Contains(newline, StringComparison.Ordinal));
            using (var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key))
            using (var reopened = SqliteDeepMailboxStore.OpenExisting(options))
            {
                var message = Assert.Single(await reopened.ListDirectMessageCreatesAsync(Local, 1, Conversation));
                Assert.Equal("retained across schema newline validation", message.Text);
            }
            Assert.Equal(before, ReadSchemaFixtureFrames(fixture));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData("CREATE INDEX extra_event_index ON authenticated_dmc2_inbox(content_kind);")]
    [InlineData("DROP INDEX idx_authenticated_dmc2_authored_position;")]
    [InlineData("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'length(scope) = 32','length(scope) = 31') WHERE name='client_mailbox_traversal'; PRAGMA writable_schema=OFF;")]
    public void SchemaCanonicalNewlines_RejectChangedObjectsAndConstraints(string tamper)
    {
        using var fixture = new Fixture();
        using (var store = Open(true, fixture)) { }
        WithSchemaFixture(fixture, connection =>
        {
            using var change = connection.CreateCommand(); change.CommandText = tamper; change.ExecuteNonQuery();
        });
        var before = ReadSchemaFixtureFrames(fixture);
        using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        var failure = Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(options));
        Assert.Equal(8, failure.Data.Count);
        Assert.Equal(0, Assert.IsType<int>(failure.Data["Deep.ApplicationSchema.ReadBoundReason"]));
        foreach (System.Collections.DictionaryEntry entry in failure.Data)
        {
            Assert.StartsWith("Deep.ApplicationSchema.", Assert.IsType<string>(entry.Key));
            Assert.InRange(Assert.IsType<int>(entry.Value), -1, 64);
        }
        Assert.Equal(before, ReadSchemaFixtureFrames(fixture));
    }

    [Theory]
    [InlineData("'literal\r\nvalue'")]
    [InlineData("'escaped''\r\nvalue'")]
    [InlineData("\"identifier\r\nvalue\"")]
    [InlineData("\"escaped\"\"\r\nvalue\"")]
    [InlineData("`identifier\r\nvalue`")]
    [InlineData("`escaped``\r\nvalue`")]
    [InlineData("[identifier\r\nvalue]")]
    public void SchemaCanonicalNewlines_PreserveQuotedBytesAndEscapes(string quoted)
    {
        // Exercise the actual private comparison boundary without changing the
        // trusted expected schema or manufacturing an accepted authority.
        var normalize = typeof(SqliteDeepMailboxStore).GetMethod("CanonicalSchemaDdl", BindingFlags.NonPublic | BindingFlags.Static)!;
        var crlf = "CREATE TABLE example (\r\nvalue TEXT DEFAULT " + quoted + "\r\n)";
        var expected = "CREATE TABLE example (\nvalue TEXT DEFAULT " + quoted + "\n)";
        var result = Assert.IsType<string>(normalize.Invoke(null, [crlf]));
        Assert.Equal(expected, result);
        Assert.NotEqual(result, Assert.IsType<string>(normalize.Invoke(null, [crlf.Replace("\r\n", "\n", StringComparison.Ordinal)])));
        Assert.Equal("a\rb  c", Assert.IsType<string>(normalize.Invoke(null, ["a\rb  c"])));
    }

    [Theory]
    [InlineData("-- stray ' \" ` [\r\n")]
    [InlineData("/* stray ' \" ` [\r\nend */\r\n")]
    public void SchemaCanonicalNewlines_CommentQuotesCannotChangeLaterLiteral(string comment)
    {
        var normalize = typeof(SqliteDeepMailboxStore).GetMethod("CanonicalSchemaDdl", BindingFlags.NonPublic | BindingFlags.Static)!;
        var sql = comment + "SELECT 'later\r\nliteral'\r\n";
        var result = Assert.IsType<string>(normalize.Invoke(null, [sql]));
        Assert.Equal(comment.Replace("\r\n", "\n", StringComparison.Ordinal) + "SELECT 'later\r\nliteral'\n", result);
        Assert.NotEqual(result, Assert.IsType<string>(normalize.Invoke(null, [sql.Replace("later\r\nliteral", "later\nliteral", StringComparison.Ordinal)])));
    }

    private static void WithSchemaFixture(Fixture fixture, Action<SqliteConnection> action)
    {
        using var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False");
        connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
        action(connection);
    }

    private static string[] ReadSchemaFixtureFrames(Fixture fixture)
    {
        string[] frames = [];
        WithSchemaFixture(fixture, connection =>
        {
            var read = typeof(SqliteDeepMailboxStore).GetMethod("ReadSchemaObjects", BindingFlags.NonPublic | BindingFlags.Static)!;
            frames = Assert.IsType<string[]>(read.Invoke(null, [connection, null]));
        });
        return frames;
    }
}
