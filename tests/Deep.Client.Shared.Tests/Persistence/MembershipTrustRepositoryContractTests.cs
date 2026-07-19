using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

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
}
