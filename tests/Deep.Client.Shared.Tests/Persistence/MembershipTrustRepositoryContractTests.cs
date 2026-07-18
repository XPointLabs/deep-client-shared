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

        var second = Record(revision: 2, sequence: 7, fill: 0x33);
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

    [Fact]
    public async Task InMemoryRestart_PreservesHeadAndPredecessor()
    {
        var path = Path.Combine(Path.GetTempPath(), $"deep-p07-memory-{Guid.NewGuid():N}.json");
        try
        {
            var first = new InMemorySessionStore(path);
            _ = await first.CommitMembershipTrustAsync(Record(1, 6, 0x10), null);
            _ = await first.CommitMembershipTrustAsync(Record(2, 7, 0x20), 1);

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

    private static MembershipTrustRecord Record(
        ulong revision,
        ulong sequence,
        byte fill,
        MembershipTrustDomain domain = MembershipTrustDomain.Membership,
        string profile = "install:test") =>
        MembershipTrustRecord.Create(
            profile,
            domain,
            revision,
            sequence,
            previousSequence: sequence - 1,
            previousCanonicalHash: Enumerable.Repeat((byte)(fill - 1), 32).ToArray(),
            canonicalEnvelope: Enumerable.Repeat(fill, 96).ToArray(),
            state: MembershipTrustState.Healthy,
            observedAt: DateTimeOffset.FromUnixTimeSeconds(1010),
            validUntil: DateTimeOffset.FromUnixTimeSeconds(1200));

    private sealed class StoreScope(IMembershipTrustRepository store, IDisposable? disposable) : IDisposable
    {
        public IMembershipTrustRepository Store { get; } = store;

        public static StoreScope Create(bool sqlite)
        {
            if (!sqlite)
            {
                return new StoreScope(new InMemorySessionStore(), null);
            }

            var path = Path.Combine(Path.GetTempPath(), $"deep-p07-{Guid.NewGuid():N}.db");
            var store = new SqliteSessionStore(path);
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
