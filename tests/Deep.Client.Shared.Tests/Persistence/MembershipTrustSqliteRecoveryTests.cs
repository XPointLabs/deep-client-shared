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
    [InlineData("state")]
    [InlineData("observed-at")]
    [InlineData("valid-until")]
    [InlineData("canonical-hash")]
    [InlineData("previous-hash")]
    [InlineData("profile-binding")]
    public async Task CorruptPhysicalState_BlocksWithoutPriorFallback(string corruption)
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            var first = Record(1, 6, 0x10);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(first, null));
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(
                    Record(2, 7, 0x20, previousCanonicalHash: first.CanonicalHash),
                    1));
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

    [Theory]
    [InlineData("observed-at-out-of-range")]
    [InlineData("valid-from-null")]
    [InlineData("valid-until-null")]
    public async Task MalformedOrOutOfRangeRecordTimestamps_ReturnCorrupt(string corruption)
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            _ = await store.CommitMembershipTrustAsync(Record(1, 6, 0x10), null);
        }
        await database.MutateAsync(corruption);

        if (corruption.EndsWith("-null", StringComparison.Ordinal))
        {
            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => database.Open());
            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            return;
        }

        using var restarted = database.Open();
        var read = await restarted.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Corrupt, read.Result);
    }

    [Theory]
    [InlineData("clock-observed-out-of-range")]
    [InlineData("clock-observed-null")]
    public async Task MalformedOrOutOfRangeClockTimestamps_ReturnCorrupt(string corruption)
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            _ = await store.CommitMembershipTrustClockAsync(
                MembershipTrustClockRecord.Create(
                    "install:test",
                    1,
                    DateTimeOffset.FromUnixTimeSeconds(1000)),
                null);
        }
        await database.MutateAsync(corruption);

        if (corruption.EndsWith("-null", StringComparison.Ordinal))
        {
            var exception = Assert.Throws<LocalStateResetRequiredException>(
                () => database.Open());
            Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, exception.Reason);
            return;
        }

        using var restarted = database.Open();
        var read = await restarted.ReadMembershipTrustClockAsync("install:test");
        Assert.Equal(MembershipTrustClockReadResult.Corrupt, read.Result);
    }

    [Fact]
    public async Task OrphanInAnotherProfile_DoesNotBlockCurrentProfile()
    {
        await using var database = await TestDatabase.CreateAsync();
        using (var store = database.Open())
        {
            _ = await store.CommitMembershipTrustAsync(Record(1, 6, 0x10), null);
        }
        await database.MutateAsync("other-profile-orphan");

        using var restarted = database.Open();
        var read = await restarted.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        Assert.Equal(1UL, read.Head!.Revision);
    }

    [Fact]
    public async Task InMemoryCorruptionInAnotherProfile_DoesNotBlockCurrentProfile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"deep-p07-profile-scope-{Guid.NewGuid():N}.json");
        try
        {
            var store = new InMemorySessionStore(path);
            _ = await store.CommitMembershipTrustAsync(Record(1, 6, 0x10), null);
            var other = Record(1, 6, 0x20, "install:other");
            _ = await store.CommitMembershipTrustAsync(other, null);

            var root = System.Text.Json.Nodes.JsonNode.Parse(await File.ReadAllTextAsync(path))!;
            var heads = root["membershipTrustHeads"]!.AsArray();
            var otherHead = heads.Single(node =>
                node!["opaqueProfileKey"]!.GetValue<string>() == "install:other");
            heads.Remove(otherHead);
            await File.WriteAllTextAsync(path, root.ToJsonString());

            var restarted = new InMemorySessionStore(path);
            var read = await restarted.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership);
            Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static MembershipTrustRecord Record(
        ulong revision,
        ulong sequence,
        byte fill,
        string profile = "install:test",
        byte[]? previousCanonicalHash = null) =>
        MembershipTrustRecord.Create(
            profile,
            MembershipTrustDomain.Membership,
            revision,
            sequence,
            sequence - 1,
            previousCanonicalHash ??
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
                         previous_hash, envelope, payload_digest, canonical_hash, profile_binding_hash,
                         state, observed_at, valid_until)
                    VALUES
                        ('install:test', 3, 3, 8, 7, zeroblob(32), zeroblob(96),
                         zeroblob(32), zeroblob(32), zeroblob(32), 3, 1010, 1200);
                    """,
                "other-profile-orphan" => """
                    INSERT INTO membership_trust_records
                        (profile_key, domain, revision, sequence, previous_sequence,
                         previous_hash, envelope, payload_digest, canonical_hash, profile_binding_hash,
                         state, observed_at, valid_until)
                    VALUES
                        ('install:other', 3, 1, 6, 5, zeroblob(32), zeroblob(96),
                         zeroblob(32), zeroblob(32), zeroblob(32), 3, 1010, 1200);
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
                "state" => """
                    UPDATE membership_trust_records
                    SET state = 10
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "observed-at" => """
                    UPDATE membership_trust_records
                    SET observed_at = observed_at + 600
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "valid-until" => """
                    UPDATE membership_trust_records
                    SET valid_until = valid_until + 600
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "canonical-hash" => """
                    UPDATE membership_trust_records
                    SET canonical_hash = randomblob(32)
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "previous-hash" => """
                    UPDATE membership_trust_records
                    SET previous_hash = randomblob(32)
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "profile-binding" => """
                    UPDATE membership_trust_records
                    SET profile_binding_hash = randomblob(32)
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                    """,
                "observed-at-out-of-range" => """
                    UPDATE membership_trust_records
                    SET observed_at = 9223372036854775807
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                    """,
                "valid-from-null" => """
                    ALTER TABLE membership_trust_records RENAME TO membership_trust_records_old;
                    CREATE TABLE membership_trust_records AS
                    SELECT profile_key, domain, revision, version, artifact_kind, sequence,
                           previous_sequence, previous_hash, envelope, payload_digest,
                           canonical_hash, profile_binding_hash, signing_authority,
                           revoked_delegation_hashes, state, observed_at,
                           CASE WHEN revision = 1 THEN NULL ELSE valid_from END AS valid_from,
                           valid_until
                    FROM membership_trust_records_old;
                    DROP TABLE membership_trust_records_old;
                    """,
                "valid-until-null" => """
                    ALTER TABLE membership_trust_records RENAME TO membership_trust_records_old;
                    CREATE TABLE membership_trust_records AS
                    SELECT profile_key, domain, revision, version, artifact_kind, sequence,
                           previous_sequence, previous_hash, envelope, payload_digest,
                           canonical_hash, profile_binding_hash, signing_authority,
                           revoked_delegation_hashes, state, observed_at, valid_from,
                           CASE WHEN revision = 1 THEN NULL ELSE valid_until END AS valid_until
                    FROM membership_trust_records_old;
                    DROP TABLE membership_trust_records_old;
                    """,
                "clock-observed-out-of-range" => """
                    UPDATE membership_trust_clock
                    SET observed_at = 9223372036854775807
                    WHERE profile_key = 'install:test';
                    """,
                "clock-observed-null" => """
                    ALTER TABLE membership_trust_clock RENAME TO membership_trust_clock_old;
                    CREATE TABLE membership_trust_clock AS
                    SELECT profile_key, version, revision, NULL AS observed_at, digest
                    FROM membership_trust_clock_old;
                    DROP TABLE membership_trust_clock_old;
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
