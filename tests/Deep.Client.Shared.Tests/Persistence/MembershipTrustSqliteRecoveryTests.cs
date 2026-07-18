using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class MembershipTrustSqliteRecoveryTests
{
    [Fact]
    public async Task RestartWithValidHead_IsFound()
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var first = database.Open())
        {
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await first.CommitMembershipTrustAsync(Record(1, 6, 0x10), null));
        }

        using var restarted = database.Open();
        var read = await restarted.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        Assert.Equal(1UL, read.Head!.Revision);
    }

    [Theory]
    [InlineData("orphan")]
    [InlineData("missing-head")]
    [InlineData("digest")]
    [InlineData("payload")]
    [InlineData("revision")]
    public async Task CorruptPhysicalState_BlocksWithoutPriorFallback(string corruption)
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            _ = await store.CommitMembershipTrustAsync(Record(1, 6, 0x10), null);
            _ = await store.CommitMembershipTrustAsync(Record(2, 7, 0x20), 1);
        }

        await database.MutateAsync(corruption);

        using var restarted = database.Open();
        var read = await restarted.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Corrupt, read.Result);
        Assert.Null(read.Head);
        Assert.Null(read.Predecessor);
    }

    [Fact]
    public async Task LogicalSchemaThreeToFour_PreservesExistingDomainRows()
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            await store.SetSchemaVersionAsync(3);
            await store.SetSchemaValueAsync("existing.account", "preserved");
            await store.SetSchemaValueAsync("existing.message", "preserved");
            await store.SetSchemaValueAsync("existing.group", "preserved");

            var migrator = new LocalSchemaMigrator(LocalSchemaMigrations.Default);
            Assert.Equal(4, await migrator.MigrateAsync(store));
            Assert.Equal("preserved", await store.GetSchemaValueAsync("existing.account"));
            Assert.Equal("preserved", await store.GetSchemaValueAsync("existing.message"));
            Assert.Equal("preserved", await store.GetSchemaValueAsync("existing.group"));
        }

        using var restarted = database.Open();
        Assert.Equal(4, await restarted.GetSchemaVersionAsync());
        Assert.Equal("preserved", await restarted.GetSchemaValueAsync("existing.account"));
        Assert.Equal("preserved", await restarted.GetSchemaValueAsync("existing.message"));
        Assert.Equal("preserved", await restarted.GetSchemaValueAsync("existing.group"));
    }

    private static MembershipTrustRecord Record(ulong revision, ulong sequence, byte fill) =>
        MembershipTrustRecord.Create(
            "install:test",
            MembershipTrustDomain.Membership,
            revision,
            sequence,
            sequence - 1,
            Enumerable.Repeat((byte)(fill - 1), 32).ToArray(),
            Enumerable.Repeat(fill, 96).ToArray(),
            MembershipTrustState.Healthy,
            DateTimeOffset.FromUnixTimeSeconds(1010),
            DateTimeOffset.FromUnixTimeSeconds(1200));

    private sealed class TestDatabase(string path) : IAsyncDisposable
    {
        public static Task<TestDatabase> CreateAsync() =>
            Task.FromResult(new TestDatabase(
                Path.Combine(Path.GetTempPath(), $"deep-p07-recovery-{Guid.NewGuid():N}.db")));

        public SqliteSessionStore Open() => new(path);

        public async Task MutateAsync(string corruption)
        {
            await using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = corruption switch
            {
                "orphan" => """
                    INSERT INTO membership_trust_records
                        (profile_key, domain, revision, sequence, previous_sequence,
                         previous_hash, envelope, payload_digest, canonical_hash, state, observed_at, valid_until)
                    VALUES
                        ('install:orphan', 3, 1, 6, 5, zeroblob(32), zeroblob(96),
                         zeroblob(32), zeroblob(32), 3, 1010, 1200);
                    """,
                "missing-head" => """
                    DELETE FROM membership_trust_heads
                    WHERE profile_key = 'install:test' AND domain = 3;
                    """,
                "digest" => """
                    UPDATE membership_trust_records
                    SET payload_digest = zeroblob(32)
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "payload" => """
                    UPDATE membership_trust_records
                    SET envelope = x'', payload_digest = $emptyDigest
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "revision" => """
                    UPDATE membership_trust_heads
                    SET revision = 0
                    WHERE profile_key = 'install:test' AND domain = 3;
                    """,
                _ => throw new ArgumentOutOfRangeException(nameof(corruption))
            };
            if (corruption == "payload")
            {
                command.Parameters.AddWithValue("$emptyDigest", SHA256.HashData([]));
            }
            await command.ExecuteNonQueryAsync();
        }

        public ValueTask DisposeAsync()
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
            return ValueTask.CompletedTask;
        }
    }
}
