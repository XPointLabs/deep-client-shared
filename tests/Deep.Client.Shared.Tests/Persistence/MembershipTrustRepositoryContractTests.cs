using System.Collections;
using System.Reflection;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class MembershipTrustRepositoryContractTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FirstCommitReplaySuccessorAndCasConflict_HaveParity(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var store = scope.Store;
        var first = Record(revision: 1, sequence: 6, fill: 0x11);

        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await store.CommitMembershipTrustAsync(first, expectedHeadRevision: null));
        Assert.Equal(
            MembershipTrustCommitResult.Idempotent,
            await store.CommitMembershipTrustAsync(first, expectedHeadRevision: null));

        var divergent = Record(revision: 1, sequence: 6, fill: 0x22);
        Assert.Equal(
            MembershipTrustCommitResult.Conflict,
            await store.CommitMembershipTrustAsync(divergent, expectedHeadRevision: null));

        var second = Record(
            revision: 2,
            sequence: 7,
            fill: 0x33,
            previousCanonicalHash: first.CanonicalHash);
        Assert.Equal(
            MembershipTrustCommitResult.Conflict,
            await store.CommitMembershipTrustAsync(second, expectedHeadRevision: 0));
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await store.CommitMembershipTrustAsync(second, expectedHeadRevision: 1));

        var read = await store.ReadMembershipTrustAsync("install:test", MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        Assert.Equal(2UL, read.Head!.Revision);
        Assert.Equal(7UL, read.Head.Sequence);
        Assert.Equal(1UL, read.Predecessor!.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalReplayAndDivergence_HaveParity(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var first = Record(revision: 1, sequence: 6, fill: 0x11);
        var second = Record(
            revision: 2,
            sequence: 7,
            fill: 0x22,
            previousCanonicalHash: first.CanonicalHash);
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(first, null));
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(second, 1));

        Assert.Equal(
            MembershipTrustCommitResult.Idempotent,
            await scope.Store.CommitMembershipTrustAsync(first, null));
        Assert.Equal(
            MembershipTrustCommitResult.Conflict,
            await scope.Store.CommitMembershipTrustAsync(
                Record(revision: 1, sequence: 6, fill: 0x33),
                null));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidSuccessorLinkage_IsRejectedAndHeadPreserved(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var first = Record(revision: 1, sequence: 6, fill: 0x11);
        var unlinked = Record(revision: 2, sequence: 7, fill: 0x22);
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(first, null));

        Assert.Equal(
            MembershipTrustCommitResult.Conflict,
            await scope.Store.CommitMembershipTrustAsync(unlinked, 1));
        var read = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        Assert.Equal(1UL, read.Head!.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentDifferentSuccessors_OnlyOneWins(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var store = scope.Store;
        var predecessor = Record(revision: 1, sequence: 6, fill: 0x10);
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await store.CommitMembershipTrustAsync(
                predecessor,
                expectedHeadRevision: null));

        var first = Record(
            revision: 2,
            sequence: 7,
            fill: 0x20,
            previousCanonicalHash: predecessor.CanonicalHash);
        var second = Record(
            revision: 2,
            sequence: 7,
            fill: 0x30,
            previousCanonicalHash: predecessor.CanonicalHash);
        var results = await Task.WhenAll(
            store.CommitMembershipTrustAsync(first, 1),
            store.CommitMembershipTrustAsync(second, 1));

        Assert.Single(results, result => result == MembershipTrustCommitResult.Applied);
        Assert.Single(results, result => result == MembershipTrustCommitResult.Conflict);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainAndInstallationProfileTracks_AreIndependent(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var store = scope.Store;
        var authority = Record(
            revision: 1,
            sequence: 2,
            fill: 0x40,
            domain: MembershipTrustDomain.Authority);
        var bridge = Record(
            revision: 1,
            sequence: 6,
            fill: 0x40,
            domain: MembershipTrustDomain.Bridge);
        var otherProfile = Record(
            revision: 1,
            sequence: 6,
            fill: 0x40,
            profile: "install:other");

        Assert.Equal(MembershipTrustCommitResult.Applied, await store.CommitMembershipTrustAsync(authority, null));
        Assert.Equal(MembershipTrustCommitResult.Applied, await store.CommitMembershipTrustAsync(bridge, null));
        Assert.Equal(MembershipTrustCommitResult.Applied, await store.CommitMembershipTrustAsync(otherProfile, null));

        Assert.Equal(
            2UL,
            (await store.ReadMembershipTrustAsync("install:test", MembershipTrustDomain.Authority)).Head!.Sequence);
        Assert.Equal(
            6UL,
            (await store.ReadMembershipTrustAsync("install:test", MembershipTrustDomain.Bridge)).Head!.Sequence);
        Assert.Equal(
            6UL,
            (await store.ReadMembershipTrustAsync("install:other", MembershipTrustDomain.Membership)).Head!.Sequence);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PreCancelledWrite_DoesNotCreateRecordOrHead(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scope.Store.CommitMembershipTrustAsync(
                Record(revision: 1, sequence: 6, fill: 0x55),
                expectedHeadRevision: null,
                cancellation.Token));

        Assert.Equal(
            MembershipTrustReadResult.Missing,
            (await scope.Store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership)).Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationBeforeDurableCommit_RollsBackRecordAndHead(bool sqlite)
    {
        using var cancellation = new CancellationTokenSource();
        using var scope = StoreScope.Create(
            sqlite,
            point =>
            {
                if (point == MembershipTrustCommitFaultPoint.BeforeDurableCommit)
                {
                    cancellation.Cancel();
                }
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scope.Store.CommitMembershipTrustAsync(
                Record(revision: 1, sequence: 6, fill: 0x56),
                expectedHeadRevision: null,
                cancellation.Token));

        Assert.Equal(
            MembershipTrustReadResult.Missing,
            (await scope.Store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership)).Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationAfterDurableCommit_IsUncertainButRestartRevealsAppliedState(bool sqlite)
    {
        using var cancellation = new CancellationTokenSource();
        using var scope = StoreScope.Create(
            sqlite,
            point =>
            {
                if (point == MembershipTrustCommitFaultPoint.AfterDurableCommit)
                {
                    cancellation.Cancel();
                }
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            scope.Store.CommitMembershipTrustAsync(
                Record(revision: 1, sequence: 6, fill: 0x57),
                expectedHeadRevision: null,
                cancellation.Token));

        var read = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Found, read.Result);
        Assert.Equal(1UL, read.Head!.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StoredRecordsAndClocks_AreDefensiveCopies(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var record = Record(revision: 1, sequence: 6, fill: 0x58);
        var expectedEnvelope = record.CanonicalEnvelope.ToArray();
        var expectedDigest = record.PayloadDigest.ToArray();
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(record, null));

        record.CanonicalEnvelope[0] ^= 0xff;
        record.PayloadDigest[0] ^= 0xff;
        var firstRead = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(expectedEnvelope, firstRead.Head!.CanonicalEnvelope);
        Assert.Equal(expectedDigest, firstRead.Head.PayloadDigest);

        firstRead.Head.CanonicalEnvelope[1] ^= 0xff;
        firstRead.Head.PayloadDigest[1] ^= 0xff;
        var secondRead = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(expectedEnvelope, secondRead.Head!.CanonicalEnvelope);
        Assert.Equal(expectedDigest, secondRead.Head.PayloadDigest);

        var clock = MembershipTrustClockRecord.Create(
            "install:test", 1, DateTimeOffset.FromUnixTimeSeconds(1000));
        var expectedClockDigest = clock.Digest.ToArray();
        Assert.Equal(
            MembershipTrustClockCommitResult.Applied,
            await scope.Store.CommitMembershipTrustClockAsync(clock, null));
        clock.Digest[0] ^= 0xff;
        var firstClockRead = await scope.Store.ReadMembershipTrustClockAsync("install:test");
        Assert.Equal(expectedClockDigest, firstClockRead.Record!.Digest);
        firstClockRead.Record.Digest[1] ^= 0xff;
        var secondClockRead = await scope.Store.ReadMembershipTrustClockAsync("install:test");
        Assert.Equal(expectedClockDigest, secondClockRead.Record!.Digest);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SubsecondAndOffsetTimes_AreCanonicalAndIdempotent(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var precise = new DateTimeOffset(
            2026, 7, 19, 4, 5, 6, 789, TimeSpan.FromHours(5));
        var record = MembershipTrustRecord.Create(
            "install:test",
            MembershipTrustDomain.Membership,
            revision: 1,
            sequence: 6,
            previousSequence: 5,
            previousCanonicalHash: Enumerable.Repeat((byte)0x10, 32).ToArray(),
            canonicalEnvelope: Enumerable.Repeat((byte)0x20, 96).ToArray(),
            state: MembershipTrustState.Healthy,
            observedAt: precise,
            validFrom: precise.AddMinutes(-1),
            validUntil: precise.AddMinutes(1));
        Assert.Equal(TimeSpan.Zero, record.ObservedAt.Offset);
        Assert.Equal(0, record.ObservedAt.Millisecond);
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(record, null));
        Assert.Equal(
            MembershipTrustCommitResult.Idempotent,
            await scope.Store.CommitMembershipTrustAsync(record, null));
        var read = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(record.ObservedAt, read.Head!.ObservedAt);
        Assert.Equal(record.ValidFrom, read.Head.ValidFrom);
        Assert.Equal(record.ValidUntil, read.Head.ValidUntil);

        var clock = MembershipTrustClockRecord.Create("install:test", 1, precise);
        Assert.Equal(TimeSpan.Zero, clock.ObservedAt.Offset);
        Assert.Equal(0, clock.ObservedAt.Millisecond);
        Assert.Equal(
            MembershipTrustClockCommitResult.Applied,
            await scope.Store.CommitMembershipTrustClockAsync(clock, null));
        Assert.Equal(
            MembershipTrustClockCommitResult.Idempotent,
            await scope.Store.CommitMembershipTrustClockAsync(clock, null));
        Assert.Equal(
            clock.ObservedAt,
            (await scope.Store.ReadMembershipTrustClockAsync(
                "install:test")).Record!.ObservedAt);
    }

    [Fact]
    public async Task InMemoryRestart_PreservesHeadAndPredecessor()
    {
        var path = Path.Combine(Path.GetTempPath(), $"deep-p07-memory-{Guid.NewGuid():N}.json");
        try
        {
            var first = new InMemorySessionStore(path);
            var predecessor = Record(1, 6, 0x10);
            _ = await first.CommitMembershipTrustAsync(predecessor, null);
            _ = await first.CommitMembershipTrustAsync(
                Record(2, 7, 0x20, previousCanonicalHash: predecessor.CanonicalHash),
                1);

            var restarted = new InMemorySessionStore(path);
            var read = await restarted.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership);
            Assert.Equal(MembershipTrustReadResult.Found, read.Result);
            Assert.Equal(2UL, read.Head!.Revision);
            Assert.Equal(1UL, read.Predecessor!.Revision);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignedHeadLinkageMismatch_IsRejectedEvenWithValidRecordDigest(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var first = Record(1, 6, 0x10);
        _ = await scope.Store.CommitMembershipTrustAsync(first, null);
        var second = MembershipTrustRecord.Create(
            "install:test",
            MembershipTrustDomain.Membership,
            revision: 2,
            sequence: 7,
            previousSequence: 6,
            previousCanonicalHash: Enumerable.Repeat((byte)0xee, 32).ToArray(),
            canonicalEnvelope: Enumerable.Repeat((byte)0x20, 96).ToArray(),
            state: MembershipTrustState.Healthy,
            observedAt: DateTimeOffset.FromUnixTimeSeconds(1010),
            validUntil: DateTimeOffset.FromUnixTimeSeconds(1200));
        Assert.Equal(
            MembershipTrustCommitResult.Conflict,
            await scope.Store.CommitMembershipTrustAsync(second, 1));

        Assert.Equal(
            MembershipTrustReadResult.Found,
            (await scope.Store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership)).Result);
    }

    [Theory]
    [InlineData(false, "deleted-record")]
    [InlineData(false, "digest")]
    [InlineData(false, "linkage")]
    [InlineData(true, "deleted-record")]
    [InlineData(true, "digest")]
    [InlineData(true, "linkage")]
    public async Task DeepHistoryCorruption_BeyondImmediatePredecessor_IsCorrupt(
        bool sqlite,
        string corruption)
    {
        using var scope = DeepHistoryStoreScope.Create(sqlite);
        var first = Record(1, 6, 0x10);
        var second = Record(
            2,
            7,
            0x20,
            previousCanonicalHash: first.CanonicalHash);
        var third = Record(
            3,
            8,
            0x30,
            previousCanonicalHash: second.CanonicalHash);

        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(first, null));
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(second, 1));
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await scope.Store.CommitMembershipTrustAsync(third, 2));

        await scope.CorruptDeepHistoryAsync(corruption, first, second);

        var read = await scope.Store.ReadMembershipTrustAsync(
            "install:test",
            MembershipTrustDomain.Membership);
        Assert.Equal(MembershipTrustReadResult.Corrupt, read.Result);
        Assert.Null(read.Head);
        Assert.Null(read.Predecessor);
    }

    [Fact]
    public void SqliteHistoryValidation_HasSingleOrderedQueryAndExplicitBudget()
    {
        var root = FindRepositoryRoot();
        var source = File.ReadAllText(Path.Combine(
            root,
            "src",
            "Deep.Client.Shared",
            "Persistence",
            "SqliteSessionStore.cs"));
        var start = source.IndexOf(
            "public async Task<MembershipTrustReadSnapshot> ReadMembershipTrustAsync(",
            StringComparison.Ordinal);
        var end = source.IndexOf(
            "public async Task<MembershipTrustClockCommitResult>",
            start,
            StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        var implementation = source[start..end];

        Assert.Contains("ORDER BY revision", implementation, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ReadMembershipTrustRecordAsync(",
            implementation,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "COUNT(*)",
            implementation,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "new List<MembershipTrustRecord>",
            implementation,
            StringComparison.Ordinal);
        Assert.Contains(
            "MaximumMembershipTrustHistoryRecords",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "MaximumMembershipTrustHistoryBytes",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "length(payload_digest)",
            implementation,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "GetBytes(ordinal, 0, null",
            source,
            StringComparison.Ordinal);

        var clockCommitStart = source.IndexOf(
            "public async Task<MembershipTrustClockCommitResult> CommitMembershipTrustClockAsync(",
            StringComparison.Ordinal);
        var clockReadStart = source.IndexOf(
            "public async Task<MembershipTrustClockReadSnapshot> ReadMembershipTrustClockAsync(",
            clockCommitStart,
            StringComparison.Ordinal);
        var clockReadEnd = source.IndexOf(
            "public async Task<MessageReplayClaimResult>",
            clockReadStart,
            StringComparison.Ordinal);
        Assert.True(
            clockCommitStart >= 0 &&
            clockReadStart > clockCommitStart &&
            clockReadEnd > clockReadStart);
        var clockCommit = source[clockCommitStart..clockReadStart];
        var clockRead = source[clockReadStart..clockReadEnd];
        Assert.Contains("length(digest)", clockCommit, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ReadFixedProjectedBlob(", clockCommit, StringComparison.Ordinal);
        Assert.Contains("length(digest)", clockRead, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ReadFixedProjectedBlob(", clockRead, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedCorruptHistory_FailsClosedWithoutSelectingOlderState(
        bool deleteHead)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-oversized-corrupt-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var first = Record(1, 6, 0x10);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(first, null));

            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var transaction = connection.BeginTransaction();
                await using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = """
                    WITH RECURSIVE sequence(value) AS (
                        SELECT 2
                        UNION ALL
                        SELECT value + 1 FROM sequence WHERE value <= 5002
                    )
                    INSERT INTO membership_trust_records
                        (profile_key, domain, revision, version, artifact_kind, sequence,
                         previous_sequence, previous_hash, envelope, payload_digest,
                         canonical_hash, profile_binding_hash, signing_authority,
                         revoked_delegation_hashes, state, observed_at, valid_from, valid_until)
                    SELECT record.profile_key, record.domain, sequence.value, record.version,
                           record.artifact_kind, sequence.value + 5, sequence.value + 4,
                           record.previous_hash, record.envelope, record.payload_digest,
                           record.canonical_hash, record.profile_binding_hash,
                           record.signing_authority, record.revoked_delegation_hashes,
                           record.state, record.observed_at, record.valid_from, record.valid_until
                    FROM membership_trust_records AS record
                    CROSS JOIN sequence
                    WHERE record.profile_key = 'install:test'
                      AND record.domain = 3
                      AND record.revision = 1;
                    """;
                await command.ExecuteNonQueryAsync();
                if (deleteHead)
                {
                    await using var delete = connection.CreateCommand();
                    delete.Transaction = transaction;
                    delete.CommandText = """
                        DELETE FROM membership_trust_heads
                        WHERE profile_key = 'install:test' AND domain = 3;
                        """;
                    await delete.ExecuteNonQueryAsync();
                }
                transaction.Commit();
            }

            var read = await store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership);

            Assert.Equal(MembershipTrustReadResult.Corrupt, read.Result);
            Assert.Null(read.Head);
            Assert.Null(read.Predecessor);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Fact]
    public async Task SqliteHistory_CumulativeValidBytesBeyondBudgetFailClosed()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-history-byte-budget-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            MembershipTrustRecord? previous = null;
            var rejected = false;
            for (var revision = 1; revision <= 34; revision++)
            {
                var record = MembershipTrustRecord.Create(
                    "install:test",
                    MembershipTrustDomain.Membership,
                    checked((ulong)revision),
                    checked((ulong)(revision + 5)),
                    checked((ulong)(revision + 4)),
                    previous?.CanonicalHash ??
                        Enumerable.Repeat((byte)0x10, 32).ToArray(),
                    Enumerable.Repeat(
                        checked((byte)(revision % 251 + 1)),
                        MembershipTrustRecord.MaximumEnvelopeLength).ToArray(),
                    MembershipTrustState.Healthy,
                    DateTimeOffset.FromUnixTimeSeconds(2_000),
                    DateTimeOffset.FromUnixTimeSeconds(3_000),
                    DateTimeOffset.FromUnixTimeSeconds(1_000),
                    profileBindingHash: Enumerable.Repeat((byte)0x30, 32).ToArray(),
                    artifactKind: MembershipTrustArtifactKind.Membership,
                    signingAuthorityEnvelope: Enumerable.Repeat(
                        checked((byte)(revision % 241 + 1)),
                        MembershipTrustRecord.MaximumEnvelopeLength).ToArray());
                var result = await store.CommitMembershipTrustAsync(
                    record,
                    previous?.Revision);
                if (result == MembershipTrustCommitResult.Corrupt)
                {
                    rejected = true;
                    break;
                }
                Assert.Equal(MembershipTrustCommitResult.Applied, result);
                previous = record;
            }
            Assert.True(rejected, "The cumulative byte budget was not enforced before commit.");

            var read = await store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership);

            Assert.Equal(MembershipTrustReadResult.Found, read.Result);
            Assert.Equal(previous!.Revision, read.Head!.Revision);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Fact]
    public async Task SqliteHistory_OversizedBlobFailsClosed()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-history-blob-budget-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(Record(1, 6, 0x10), null));
            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE membership_trust_records
                    SET envelope = zeroblob(1048576)
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                    """;
                await command.ExecuteNonQueryAsync();
            }

            var read = await store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership);

            Assert.Equal(MembershipTrustReadResult.Corrupt, read.Result);
            Assert.Null(read.Head);
            Assert.Null(read.Predecessor);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Fact]
    public async Task SqliteCommit_OversizedExistingCandidateCannotAdvanceHead()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-oversized-candidate-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var first = Record(1, 6, 0x10);
            var second = Record(
                2,
                7,
                0x20,
                previousCanonicalHash: first.CanonicalHash);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(first, null));
            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    INSERT INTO membership_trust_records
                        (profile_key, domain, revision, version, artifact_kind, sequence,
                         previous_sequence, previous_hash, envelope, payload_digest,
                         canonical_hash, profile_binding_hash, signing_authority,
                         revoked_delegation_hashes, state, observed_at, valid_from, valid_until)
                    SELECT profile_key, domain, 2, version, artifact_kind, 7, 6,
                           canonical_hash, zeroblob(1048576), payload_digest,
                           canonical_hash, profile_binding_hash, signing_authority,
                           revoked_delegation_hashes, state, observed_at, valid_from, valid_until
                    FROM membership_trust_records
                    WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                    """;
                await command.ExecuteNonQueryAsync();
            }

            Assert.Equal(
                MembershipTrustCommitResult.Corrupt,
                await store.CommitMembershipTrustAsync(second, 1));
            await using var verify = new SqliteConnection(
                $"Data Source={path};Pooling=False");
            await verify.OpenAsync();
            await using var query = verify.CreateCommand();
            query.CommandText = """
                SELECT revision FROM membership_trust_heads
                WHERE profile_key = 'install:test' AND domain = 3;
                """;
            Assert.Equal(1L, Convert.ToInt64(await query.ExecuteScalarAsync()));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Fact]
    public async Task SqliteOversizedHeadDigest_BlocksReadIdempotencyAndSuccessor()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-oversized-head-digest-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var first = Record(1, 6, 0x10);
            var second = Record(
                2,
                7,
                0x20,
                previousCanonicalHash: first.CanonicalHash);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(first, null));
            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE membership_trust_heads
                    SET payload_digest = zeroblob(1048576)
                    WHERE profile_key = 'install:test' AND domain = 3;
                    """;
                await command.ExecuteNonQueryAsync();
            }

            Assert.Equal(
                MembershipTrustReadResult.Corrupt,
                (await store.ReadMembershipTrustAsync(
                    "install:test",
                    MembershipTrustDomain.Membership)).Result);
            Assert.Equal(
                MembershipTrustCommitResult.Corrupt,
                await store.CommitMembershipTrustAsync(first, null));
            Assert.Equal(
                MembershipTrustCommitResult.Corrupt,
                await store.CommitMembershipTrustAsync(second, 1));
            await using var verify = new SqliteConnection(
                $"Data Source={path};Pooling=False");
            await verify.OpenAsync();
            await using var query = verify.CreateCommand();
            query.CommandText = """
                SELECT revision, length(payload_digest)
                FROM membership_trust_heads
                WHERE profile_key = 'install:test' AND domain = 3;
                """;
            await using var reader = await query.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1L, reader.GetInt64(0));
            Assert.Equal(1048576L, reader.GetInt64(1));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Fact]
    public async Task SqliteOversizedClockDigest_BlocksReadReplayAndSuccessor()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-oversized-clock-digest-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var first = MembershipTrustClockRecord.Create(
                "install:test",
                1,
                DateTimeOffset.FromUnixTimeSeconds(1000));
            var second = MembershipTrustClockRecord.Create(
                "install:test",
                2,
                DateTimeOffset.FromUnixTimeSeconds(2000));
            Assert.Equal(
                MembershipTrustClockCommitResult.Applied,
                await store.CommitMembershipTrustClockAsync(first, null));
            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    UPDATE membership_trust_clock
                    SET digest = zeroblob(1048576)
                    WHERE profile_key = 'install:test';
                    """;
                await command.ExecuteNonQueryAsync();
            }

            Assert.Equal(
                MembershipTrustClockReadResult.Corrupt,
                (await store.ReadMembershipTrustClockAsync("install:test")).Result);
            Assert.Equal(
                MembershipTrustClockCommitResult.Corrupt,
                await store.CommitMembershipTrustClockAsync(first, null));
            Assert.Equal(
                MembershipTrustClockCommitResult.Corrupt,
                await store.CommitMembershipTrustClockAsync(second, 1));
            await using var verify = new SqliteConnection(
                $"Data Source={path};Pooling=False");
            await verify.OpenAsync();
            await using var query = verify.CreateCommand();
            query.CommandText = """
                SELECT revision, length(digest)
                FROM membership_trust_clock
                WHERE profile_key = 'install:test';
                """;
            await using var reader = await query.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1L, reader.GetInt64(0));
            Assert.Equal(1048576L, reader.GetInt64(1));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Theory]
    [InlineData("version")]
    [InlineData("digest")]
    public async Task InMemoryCorruptClock_BlocksReplayRollbackAndSuccessor(
        string corruption)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-corrupt-clock-{corruption}-{Guid.NewGuid():N}.json");
        try
        {
            var first = MembershipTrustClockRecord.Create(
                "install:test",
                1,
                DateTimeOffset.FromUnixTimeSeconds(1000));
            var store = new InMemorySessionStore(path);
            Assert.Equal(
                MembershipTrustClockCommitResult.Applied,
                await store.CommitMembershipTrustClockAsync(first, null));

            var root = System.Text.Json.Nodes.JsonNode.Parse(
                await File.ReadAllTextAsync(path))!;
            var clock = root["membershipTrustClocks"]!.AsArray().Single()!;
            if (corruption == "version")
            {
                clock["version"] = 999;
            }
            else
            {
                clock["digest"] = Convert.ToBase64String(new byte[32]);
            }
            await File.WriteAllTextAsync(path, root.ToJsonString());

            var restarted = new InMemorySessionStore(path);
            Assert.Equal(
                MembershipTrustClockReadResult.Corrupt,
                (await restarted.ReadMembershipTrustClockAsync("install:test")).Result);
            Assert.Equal(
                MembershipTrustClockCommitResult.Corrupt,
                await restarted.CommitMembershipTrustClockAsync(first, null));
            Assert.Equal(
                MembershipTrustClockCommitResult.Corrupt,
                await restarted.CommitMembershipTrustClockAsync(
                    MembershipTrustClockRecord.Create(
                        "install:test",
                        2,
                        DateTimeOffset.FromUnixTimeSeconds(900)),
                    1));
            Assert.Equal(
                MembershipTrustClockCommitResult.Corrupt,
                await restarted.CommitMembershipTrustClockAsync(
                    MembershipTrustClockRecord.Create(
                        "install:test",
                        2,
                        DateTimeOffset.FromUnixTimeSeconds(2000)),
                    1));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("orphan")]
    [InlineData("missing-middle")]
    [InlineData("history-undercount")]
    public async Task SqliteCommit_ValidatesCanonicalHistoryBeforeSuccess(
        string corruption)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"deep-p07-commit-history-{corruption}-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(path);
            var first = Record(1, 6, 0x10);
            var second = Record(
                2,
                7,
                0x20,
                previousCanonicalHash: first.CanonicalHash);
            var third = Record(
                3,
                8,
                0x30,
                previousCanonicalHash: second.CanonicalHash);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await store.CommitMembershipTrustAsync(first, null));
            if (corruption == "missing-middle")
            {
                Assert.Equal(
                    MembershipTrustCommitResult.Applied,
                    await store.CommitMembershipTrustAsync(second, 1));
                Assert.Equal(
                    MembershipTrustCommitResult.Applied,
                    await store.CommitMembershipTrustAsync(third, 2));
            }

            await using (var connection = new SqliteConnection(
                             $"Data Source={path};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = corruption switch
                {
                    "orphan" => """
                        INSERT INTO membership_trust_records
                            (profile_key, domain, revision, version, artifact_kind, sequence,
                             previous_sequence, previous_hash, envelope, payload_digest,
                             canonical_hash, profile_binding_hash, signing_authority,
                             revoked_delegation_hashes, state, observed_at, valid_from, valid_until)
                        SELECT profile_key, domain, 3, version, artifact_kind, 8, 7,
                               canonical_hash, envelope, payload_digest, canonical_hash,
                               profile_binding_hash, signing_authority,
                               revoked_delegation_hashes, state, observed_at, valid_from, valid_until
                        FROM membership_trust_records
                        WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                        """,
                    "missing-middle" => """
                        DELETE FROM membership_trust_records
                        WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                        """,
                    "history-undercount" => """
                        UPDATE membership_trust_heads
                        SET history_bytes = 1
                        WHERE profile_key = 'install:test' AND domain = 3;
                        """,
                    _ => throw new InvalidOperationException()
                };
                await command.ExecuteNonQueryAsync();
            }

            var candidate = corruption == "missing-middle" ? third : second;
            var expected = corruption == "missing-middle" ? (ulong?)2 : 1;
            Assert.Equal(
                MembershipTrustCommitResult.Corrupt,
                await store.CommitMembershipTrustAsync(candidate, expected));
            await using var verify = new SqliteConnection(
                $"Data Source={path};Pooling=False");
            await verify.OpenAsync();
            await using var query = verify.CreateCommand();
            query.CommandText = """
                SELECT revision
                FROM membership_trust_heads
                WHERE profile_key = 'install:test' AND domain = 3;
                """;
            Assert.Equal(
                corruption == "missing-middle" ? 3L : 1L,
                Convert.ToInt64(await query.ExecuteScalarAsync()));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BoundedHistory_RepeatedReadsRemainCancelableAndEquivalent(
        bool sqlite)
    {
        const int historyLength = 128;
        using var scope = DeepHistoryStoreScope.Create(sqlite);
        MembershipTrustRecord? previous = null;
        for (var revision = 1; revision <= historyLength; revision++)
        {
            var record = Record(
                checked((ulong)revision),
                checked((ulong)(revision + 5)),
                checked((byte)(revision % 251 + 1)),
                previousCanonicalHash: previous?.CanonicalHash);
            Assert.Equal(
                MembershipTrustCommitResult.Applied,
                await scope.Store.CommitMembershipTrustAsync(
                    record,
                    previous?.Revision));
            previous = record;
        }

        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var read = await scope.Store.ReadMembershipTrustAsync(
                "install:test",
                MembershipTrustDomain.Membership,
                budget.Token);
            Assert.Equal(MembershipTrustReadResult.Found, read.Result);
            Assert.Equal(checked((ulong)historyLength), read.Head!.Revision);
            Assert.Equal(checked((ulong)(historyLength - 1)), read.Predecessor!.Revision);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObservedClockHighWater_IsCasPersistedAndRejectsRollback(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var missing = await scope.Store.ReadMembershipTrustClockAsync("install:test");
        Assert.Equal(MembershipTrustClockReadResult.Missing, missing.Result);

        var first = MembershipTrustClockRecord.Create(
            "install:test", 1, DateTimeOffset.FromUnixTimeSeconds(1000));
        Assert.Equal(
            MembershipTrustClockCommitResult.Applied,
            await scope.Store.CommitMembershipTrustClockAsync(first, null));
        var second = MembershipTrustClockRecord.Create(
            "install:test", 2, DateTimeOffset.FromUnixTimeSeconds(2000));
        Assert.Equal(
            MembershipTrustClockCommitResult.Applied,
            await scope.Store.CommitMembershipTrustClockAsync(second, 1));
        var rollback = MembershipTrustClockRecord.Create(
            "install:test", 3, DateTimeOffset.FromUnixTimeSeconds(1500));
        Assert.Equal(
            MembershipTrustClockCommitResult.Rollback,
            await scope.Store.CommitMembershipTrustClockAsync(rollback, 2));

        var read = await scope.Store.ReadMembershipTrustClockAsync("install:test");
        Assert.Equal(2UL, read.Record!.Revision);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(2000), read.Record.ObservedAt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ObservedClockHighWater_ConcurrentCasHasOneWinner(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        _ = await scope.Store.CommitMembershipTrustClockAsync(
            MembershipTrustClockRecord.Create(
                "install:test", 1, DateTimeOffset.FromUnixTimeSeconds(1000)),
            null);
        var results = await Task.WhenAll(
            scope.Store.CommitMembershipTrustClockAsync(
                MembershipTrustClockRecord.Create(
                    "install:test", 2, DateTimeOffset.FromUnixTimeSeconds(2000)),
                1),
            scope.Store.CommitMembershipTrustClockAsync(
                MembershipTrustClockRecord.Create(
                    "install:test", 2, DateTimeOffset.FromUnixTimeSeconds(2100)),
                1));
        Assert.Single(results, result => result == MembershipTrustClockCommitResult.Applied);
        Assert.Single(results, result => result == MembershipTrustClockCommitResult.Conflict);
    }

    private static MembershipTrustRecord Record(
        ulong revision,
        ulong sequence,
        byte fill,
        MembershipTrustDomain domain = MembershipTrustDomain.Membership,
        string profile = "install:test",
        byte[]? previousCanonicalHash = null) =>
        MembershipTrustRecord.Create(
            profile,
            domain,
            revision,
            sequence,
            previousSequence: sequence - 1,
            previousCanonicalHash: previousCanonicalHash ??
                Enumerable.Repeat((byte)(fill - 1), 32).ToArray(),
            canonicalEnvelope: Enumerable.Repeat(fill, 96).ToArray(),
            state: MembershipTrustState.Healthy,
            observedAt: DateTimeOffset.FromUnixTimeSeconds(1010),
            validUntil: DateTimeOffset.FromUnixTimeSeconds(1200));

    private sealed class StoreScope(IMembershipTrustRepository store, IDisposable? disposable) : IDisposable
    {
        public IMembershipTrustRepository Store { get; } = store;

        public static StoreScope Create(
            bool sqlite,
            Action<MembershipTrustCommitFaultPoint>? faultInjector = null)
        {
            if (!sqlite)
            {
                return new StoreScope(new InMemorySessionStore(null, faultInjector), null);
            }

            var path = Path.Combine(Path.GetTempPath(), $"deep-p07-{Guid.NewGuid():N}.db");
            var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path),
                faultInjector);
            return new StoreScope(store, new Cleanup(store, path));
        }

        public void Dispose() => disposable?.Dispose();
    }

    private sealed class Cleanup(SqliteSessionStore store, string path) : IDisposable
    {
        public void Dispose()
        {
            store.Dispose();
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
            {
                File.Delete(candidate);
            }
        }
    }

    private sealed class DeepHistoryStoreScope(
        IMembershipTrustRepository store,
        string? sqlitePath) : IDisposable
    {
        public IMembershipTrustRepository Store { get; } = store;

        public static DeepHistoryStoreScope Create(bool sqlite)
        {
            if (!sqlite)
            {
                return new DeepHistoryStoreScope(new InMemorySessionStore(), null);
            }

            var path = Path.Combine(
                Path.GetTempPath(),
                $"deep-p07-deep-history-{Guid.NewGuid():N}.db");
            return new DeepHistoryStoreScope(new SqliteSessionStore(path), path);
        }

        public async Task CorruptDeepHistoryAsync(
            string corruption,
            MembershipTrustRecord first,
            MembershipTrustRecord second)
        {
            var invalidDigest = first.PayloadDigest.ToArray();
            invalidDigest[0] ^= 0xff;
            var brokenLink = second with
            {
                PreviousCanonicalHash = Enumerable.Repeat((byte)0xee, 32).ToArray(),
                PayloadDigest = []
            };
            brokenLink = brokenLink with
            {
                PayloadDigest = MembershipTrustRecord.ComputePayloadDigest(brokenLink)
            };

            if (sqlitePath is not null)
            {
                await using var connection = new SqliteConnection(
                    $"Data Source={sqlitePath};Pooling=False");
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = corruption switch
                {
                    "deleted-record" => """
                        DELETE FROM membership_trust_records
                        WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                        """,
                    "digest" => """
                        UPDATE membership_trust_records
                        SET payload_digest = $digest
                        WHERE profile_key = 'install:test' AND domain = 3 AND revision = 1;
                        """,
                    "linkage" => """
                        UPDATE membership_trust_records
                        SET previous_hash = $previousHash, payload_digest = $digest
                        WHERE profile_key = 'install:test' AND domain = 3 AND revision = 2;
                        """,
                    _ => throw new ArgumentOutOfRangeException(nameof(corruption))
                };
                if (corruption == "digest")
                {
                    command.Parameters.AddWithValue("$digest", invalidDigest);
                }
                else if (corruption == "linkage")
                {
                    command.Parameters.AddWithValue(
                        "$previousHash",
                        brokenLink.PreviousCanonicalHash);
                    command.Parameters.AddWithValue("$digest", brokenLink.PayloadDigest);
                }
                await command.ExecuteNonQueryAsync();
                return;
            }

            var field = typeof(InMemorySessionStore).GetField(
                "membershipTrustRecords",
                BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(field);
            var dictionary = Assert.IsAssignableFrom<IDictionary>(field.GetValue(Store));
            var entries = dictionary.GetEnumerator();
            Assert.True(entries.MoveNext());
            var entry = entries.Entry;
            Assert.False(entries.MoveNext());
            var records = Assert.IsAssignableFrom<IDictionary>(entry.Value);
            switch (corruption)
            {
                case "deleted-record":
                    records.Remove(1UL);
                    break;
                case "digest":
                    records[1UL] = first with { PayloadDigest = invalidDigest };
                    break;
                case "linkage":
                    records[2UL] = brokenLink;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(corruption));
            }
        }

        public void Dispose()
        {
            if (Store is IDisposable disposable)
            {
                disposable.Dispose();
            }
            if (sqlitePath is null)
            {
                return;
            }
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[]
                     {
                         sqlitePath,
                         sqlitePath + "-wal",
                         sqlitePath + "-shm"
                     })
            {
                File.Delete(candidate);
            }
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Deep.Client.Shared.slnx")))
            {
                return current.FullName;
            }
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root was not found.");
    }

    private sealed class AsyncDisposableSqliteStore(string path) : IAsyncDisposable
    {
        public SqliteSessionStore Value { get; } = new(path);

        public ValueTask DisposeAsync()
        {
            Value.Dispose();
            SqliteConnection.ClearAllPools();
            return ValueTask.CompletedTask;
        }
    }
}
