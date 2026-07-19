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
    public async Task ConcurrentDifferentSuccessors_OnlyOneWins(bool sqlite)
    {
        using var scope = StoreScope.Create(sqlite);
        var store = scope.Store;
        Assert.Equal(
            MembershipTrustCommitResult.Applied,
            await store.CommitMembershipTrustAsync(
                Record(revision: 1, sequence: 6, fill: 0x10),
                expectedHeadRevision: null));

        var first = Record(revision: 2, sequence: 7, fill: 0x20);
        var second = Record(revision: 2, sequence: 7, fill: 0x30);
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
    public async Task SignedHeadLinkageMismatch_IsCorruptEvenWithValidRecordDigest(bool sqlite)
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
        _ = await scope.Store.CommitMembershipTrustAsync(second, 1);

        Assert.Equal(
            MembershipTrustReadResult.Corrupt,
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
        Assert.Contains(
            "MaximumMembershipTrustHistoryRecords",
            source,
            StringComparison.Ordinal);
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
}
