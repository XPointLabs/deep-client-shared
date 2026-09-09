using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class GroupFanoutJournalTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "deep-group-fanout-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] key = GroupFanoutTestFixture.Hash("sqlcipher", 1, 0);

    public GroupFanoutJournalTests() => Directory.CreateDirectory(directory);

    [Fact]
    public async Task ThreeTargetsPartialFailureAndRestartPreserveExactAttempts()
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 3, marker: 11);
        var plan = GroupFanoutTestFixture.Batch(transition, 3, marker: 11);
        var batchId = plan.BatchId;
        var path = DatabasePath(11);
        var now = GroupFanoutTestFixture.Time(11);
        var owner = GroupFanoutTestFixture.Owner(11);

        using (var store = OpenSql(path, transition.Scope, allowCreate: true))
        {
            Assert.Equal(GroupFanoutStageDisposition.Staged, (await store.StageAsync(plan)).Disposition);
            var leases = await store.ClaimReadyAsync(batchId, owner, now, TimeSpan.FromMinutes(1), 3);
            Assert.Equal(3, leases.Count);
            var works = new List<GroupFanoutNetworkWork>();
            foreach (var lease in leases)
            {
                var begun = await store.BeginNetworkWorkAsync(lease, now);
                Assert.Equal(GroupFanoutMutationDisposition.Applied, begun.Disposition);
                works.Add(Assert.IsType<GroupFanoutNetworkWork>(begun.Work));
            }

            var first = Work(works, 0);
            var second = Work(works, 1);
            var third = Work(works, 2);
            Assert.Equal(GroupFanoutMutationDisposition.Applied,
                await store.RecordOutcomeAsync(first, GroupFanoutAttemptOutcome.Accepted));
            Assert.Equal(GroupFanoutMutationDisposition.Applied,
                await store.RecordOutcomeAsync(second, GroupFanoutAttemptOutcome.OutcomeUnknown));
            Assert.Equal(GroupFanoutMutationDisposition.Applied,
                await store.RecordOutcomeAsync(
                    third,
                    GroupFanoutAttemptOutcome.DefiniteRejected,
                    GroupFanoutDefiniteRejectRule.RetryWithNewOperation,
                    GroupFanoutTestFixture.NextOperation(11, 2)));
        }

        using (var reopened = OpenSql(path, transition.Scope, allowCreate: false))
        {
            var leases = await reopened.ClaimReadyAsync(
                batchId, GroupFanoutTestFixture.Owner(12), now.AddMinutes(2), TimeSpan.FromMinutes(1), 3);
            Assert.Equal(2, leases.Count);
            var works = new List<GroupFanoutNetworkWork>();
            foreach (var lease in leases)
                works.Add(Assert.IsType<GroupFanoutNetworkWork>(
                    (await reopened.BeginNetworkWorkAsync(lease, now.AddMinutes(2))).Work));

            var unknownRetry = Work(works, 1);
            Assert.True(unknownRetry.RetriesOutcomeUnknown);
            Assert.Equal(
                GroupFanoutTestFixture.Hash("operation", 11, 1),
                unknownRetry.NetworkOperationId.Bytes.ToArray());
            Assert.Equal("canonical-envelope-1", Encoding.UTF8.GetString(unknownRetry.ExactCanonicalEnvelope.Span));

            var definiteRetry = Work(works, 2);
            Assert.False(definiteRetry.RetriesOutcomeUnknown);
            Assert.Equal(GroupFanoutTestFixture.NextOperation(11, 2).Bytes.ToArray(),
                definiteRetry.NetworkOperationId.Bytes.ToArray());
            Assert.Equal("canonical-envelope-2", Encoding.UTF8.GetString(definiteRetry.ExactCanonicalEnvelope.Span));

            Assert.Equal(GroupFanoutMutationDisposition.Applied,
                await reopened.RecordOutcomeAsync(unknownRetry, GroupFanoutAttemptOutcome.Accepted));
            Assert.Equal(GroupFanoutMutationDisposition.Applied,
                await reopened.RecordOutcomeAsync(definiteRetry, GroupFanoutAttemptOutcome.Accepted));
            var snapshot = Assert.IsType<GroupFanoutBatchSnapshot>(await reopened.ReadAsync(batchId));
            Assert.All(snapshot.Targets, target => Assert.Equal(GroupFanoutTargetState.Accepted, target.State));
            Assert.Equal(2, Target(snapshot, 2).Attempts.Count);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReorderIsIdempotentButChangedBodyOrTargetSetLatchesConflict(bool sqlite)
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 3, marker: 21);
        using var handle = Open(sqlite, transition.Scope, 21);
        var first = GroupFanoutTestFixture.Batch(transition, 3, marker: 21);
        var reordered = GroupFanoutTestFixture.Batch(transition, 3, marker: 21, reverse: true);
        var changed = GroupFanoutTestFixture.Batch(transition, 3, marker: 21, changedEnvelopeTarget: 1);

        Assert.Equal(GroupFanoutStageDisposition.Staged, (await handle.Store.StageAsync(first)).Disposition);
        Assert.Equal(GroupFanoutStageDisposition.Idempotent, (await handle.Store.StageAsync(reordered)).Disposition);
        Assert.Equal(GroupFanoutStageDisposition.ConflictLatched, (await handle.Store.StageAsync(changed)).Disposition);
        var replay = await handle.Store.StageAsync(first);
        Assert.Equal(GroupFanoutStageDisposition.ConflictLatched, replay.Disposition);
        Assert.True(replay.Snapshot.ConflictLatched);
        Assert.Empty(await handle.Store.ClaimReadyAsync(
            first.BatchId, GroupFanoutTestFixture.Owner(21), GroupFanoutTestFixture.Time(21),
            TimeSpan.FromMinutes(1), 3));

        var setBatchId = GroupFanoutTestFixture.BatchId(23);
        var originalSet = GroupFanoutTestFixture.Batch(
            transition,
            setBatchId,
            Enumerable.Range(0, 3).Select(index => GroupFanoutTestFixture.Target(23, index)).ToArray(),
            GroupFanoutTestFixture.Time(23));
        var changedSet = GroupFanoutTestFixture.Batch(
            transition,
            setBatchId,
            [
                GroupFanoutTestFixture.Target(23, 0),
                GroupFanoutTestFixture.Target(23, 1),
                GroupFanoutTestFixture.Target(24, 2),
            ],
            GroupFanoutTestFixture.Time(23));
        Assert.Equal(GroupFanoutStageDisposition.Staged,
            (await handle.Store.StageAsync(originalSet)).Disposition);
        Assert.Equal(GroupFanoutStageDisposition.ConflictLatched,
            (await handle.Store.StageAsync(changedSet)).Disposition);

        var duplicate = new[]
        {
            GroupFanoutTestFixture.Target(22, 0),
            GroupFanoutTestFixture.Target(22, 0),
        };
        Assert.Throws<ArgumentException>(() => GroupFanoutTestFixture.Batch(
            transition, GroupFanoutTestFixture.BatchId(22), duplicate, GroupFanoutTestFixture.Time(22)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RevokeBetweenClaimAndBeginNeverReleasesBytesOrNetworkAuthority(bool sqlite)
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 2, marker: 31);
        using var handle = Open(sqlite, transition.Scope, 31);
        var plan = GroupFanoutTestFixture.Batch(transition, 2, marker: 31);
        await handle.Store.StageAsync(plan);

        var publicLeaseProperties = typeof(GroupFanoutDispatchLease)
            .GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Select(static property => property.Name)
            .ToArray();
        Assert.DoesNotContain(nameof(GroupFanoutNetworkWork.ExactCanonicalEnvelope), publicLeaseProperties);
        Assert.DoesNotContain(nameof(GroupFanoutNetworkWork.NetworkOperationId), publicLeaseProperties);
        Assert.DoesNotContain(nameof(GroupFanoutNetworkWork.ExactCanonicalEnvelope),
            typeof(GroupFanoutTargetSnapshot).GetProperties().Select(static property => property.Name));
        Assert.DoesNotContain(nameof(GroupFanoutNetworkWork.NetworkOperationId),
            typeof(GroupFanoutAttemptSnapshot).GetProperties().Select(static property => property.Name));
        Assert.Empty(typeof(GroupFanoutDispatchLease).GetConstructors());
        Assert.Empty(typeof(GroupFanoutNetworkWork).GetConstructors());
        Assert.Empty(typeof(GroupFanoutTargetEnvelope).GetConstructors());
        Assert.Empty(typeof(GroupFanoutBatchPlan).GetConstructors());
        var prepare = typeof(Deep.Client.Shared.Services.GroupV1.GroupFanoutJournalService)
            .GetMethod(nameof(Deep.Client.Shared.Services.GroupV1.GroupFanoutJournalService.PrepareVerifiedBatch));
        Assert.NotNull(prepare);
        Assert.Equal(typeof(GroupTransitionCommitPlan), prepare.GetParameters()[0].ParameterType);

        var lease = Assert.Single(await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(31), GroupFanoutTestFixture.Time(31),
            TimeSpan.FromMinutes(1), 1));
        Assert.Equal(GroupFanoutMutationDisposition.Applied,
            await handle.Store.RevokeBeforeSendAsync(plan.BatchId, lease.TargetId));
        var blocked = await handle.Store.BeginNetworkWorkAsync(lease, GroupFanoutTestFixture.Time(31));
        Assert.Equal(GroupFanoutMutationDisposition.RevokedBeforeSend, blocked.Disposition);
        Assert.Null(blocked.Work);

        var secondLease = Assert.Single(await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(32), GroupFanoutTestFixture.Time(31),
            TimeSpan.FromMinutes(1), 1));
        var released = await handle.Store.BeginNetworkWorkAsync(secondLease, GroupFanoutTestFixture.Time(31));
        Assert.NotNull(released.Work);
        Assert.Equal(GroupFanoutMutationDisposition.MayHaveForwarded,
            await handle.Store.RevokeBeforeSendAsync(plan.BatchId, secondLease.TargetId));

        for (var iteration = 0; iteration < 8; iteration++)
        {
            var marker = 100 + iteration;
            var racePlan = GroupFanoutTestFixture.Batch(
                transition,
                GroupFanoutTestFixture.BatchId(marker),
                [GroupFanoutTestFixture.Target(marker, 0)],
                GroupFanoutTestFixture.Time(marker));
            await handle.Store.StageAsync(racePlan);
            var raceLease = Assert.Single(await handle.Store.ClaimReadyAsync(
                racePlan.BatchId, GroupFanoutTestFixture.Owner(marker), GroupFanoutTestFixture.Time(1),
                TimeSpan.FromMinutes(1), 1));
            var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var revokeTask = Task.Run(async () =>
            {
                await start.Task;
                return await handle.Store.RevokeBeforeSendAsync(racePlan.BatchId, raceLease.TargetId);
            });
            var beginTask = Task.Run(async () =>
            {
                await start.Task;
                return await handle.Store.BeginNetworkWorkAsync(raceLease, GroupFanoutTestFixture.Time(1));
            });
            start.SetResult();
            await Task.WhenAll(revokeTask, beginTask);
            var revokeResult = await revokeTask;
            var beginResult = await beginTask;
            if (revokeResult == GroupFanoutMutationDisposition.Applied)
            {
                Assert.Null(beginResult.Work);
                Assert.Equal(GroupFanoutMutationDisposition.RevokedBeforeSend, beginResult.Disposition);
            }
            else
            {
                Assert.Equal(GroupFanoutMutationDisposition.MayHaveForwarded, revokeResult);
                Assert.NotNull(beginResult.Work);
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LeaseRecoveryDistinguishesBeforeSendFromOutcomeUnknownAndKeepsConcurrencyBound(bool sqlite)
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 20, marker: 41);
        using var handle = Open(sqlite, transition.Scope, 41);
        var plan = GroupFanoutTestFixture.Batch(transition, 20, marker: 41);
        var now = GroupFanoutTestFixture.Time(41);
        await handle.Store.StageAsync(plan);

        var firstWave = await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(41), now, TimeSpan.FromSeconds(30), 16);
        Assert.Equal(GroupFanoutLimits.MaximumConcurrentLeases, firstWave.Count);
        var replayedClaim = await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(41), now, TimeSpan.FromSeconds(30), 16);
        Assert.Equal(firstWave.Select(static lease => (lease.TargetId, lease.LeaseGeneration)),
            replayedClaim.Select(static lease => (lease.TargetId, lease.LeaseGeneration)));
        Assert.Empty(await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(42), now, TimeSpan.FromSeconds(30), 16));

        var released = Assert.IsType<GroupFanoutNetworkWork>(
            (await handle.Store.BeginNetworkWorkAsync(firstWave[0], now)).Work);
        var recovery = await handle.Store.RecoverStaleLeasesAsync(plan.BatchId, now.AddSeconds(31));
        Assert.Equal(15, recovery.RecoveredBeforeSendCount);
        Assert.Equal(1, recovery.PromotedToOutcomeUnknownCount);

        var recovered = await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(43), now.AddSeconds(31), TimeSpan.FromMinutes(1), 16);
        Assert.Equal(16, recovered.Count);
        var unknownLease = Assert.Single(recovered, item => item.TargetId.Equals(released.TargetId));
        Assert.True(unknownLease.RetriesOutcomeUnknown);
        var unknownWork = Assert.IsType<GroupFanoutNetworkWork>(
            (await handle.Store.BeginNetworkWorkAsync(unknownLease, now.AddSeconds(31))).Work);
        Assert.Equal(released.NetworkOperationId.Bytes.ToArray(), unknownWork.NetworkOperationId.Bytes.ToArray());
        Assert.Equal(released.ExactCanonicalEnvelope.ToArray(), unknownWork.ExactCanonicalEnvelope.ToArray());
        Assert.Equal(GroupFanoutMutationDisposition.Applied,
            await handle.Store.RecordOutcomeAsync(released, GroupFanoutAttemptOutcome.Accepted));
        Assert.Equal(GroupFanoutMutationDisposition.Idempotent,
            await handle.Store.RecordOutcomeAsync(unknownWork, GroupFanoutAttemptOutcome.Accepted));
        Assert.Equal(GroupFanoutMutationDisposition.AlreadyTerminal,
            await handle.Store.RecordOutcomeAsync(unknownWork, GroupFanoutAttemptOutcome.OutcomeUnknown));

        var expiredPlan = GroupFanoutTestFixture.Batch(transition, 1, marker: 44);
        await handle.Store.StageAsync(expiredPlan);
        var expiredLease = Assert.Single(await handle.Store.ClaimReadyAsync(
            expiredPlan.BatchId, GroupFanoutTestFixture.Owner(44), now, TimeSpan.FromSeconds(30), 1));
        var expiredBegin = await handle.Store.BeginNetworkWorkAsync(expiredLease, now.AddSeconds(31));
        Assert.Equal(GroupFanoutMutationDisposition.LeaseLost, expiredBegin.Disposition);
        Assert.Null(expiredBegin.Work);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FiveHundredTargetsStageAtomicallyAndFiveHundredOneRejects(bool sqlite)
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 100, devicesPerMember: 5, marker: 51);
        var maximum = GroupFanoutTestFixture.Batch(transition, 500, marker: 51);
        using var handle = Open(sqlite, transition.Scope, 51);
        var staged = await handle.Store.StageAsync(maximum);
        Assert.Equal(GroupFanoutStageDisposition.Staged, staged.Disposition);
        Assert.Equal(100, staged.Snapshot.MemberCount);
        Assert.Equal(500, staged.Snapshot.VerifiedDeviceCount);
        Assert.Equal(500, staged.Snapshot.Targets.Count);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            GroupFanoutTestFixture.Batch(transition, 501, marker: 52));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefiniteRejectRequiresExplicitNewOperationWhileUnknownReusesSameOperation(bool sqlite)
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 1, marker: 61);
        using var handle = Open(sqlite, transition.Scope, 61);
        var plan = GroupFanoutTestFixture.Batch(transition, 1, marker: 61);
        await handle.Store.StageAsync(plan);
        var lease = Assert.Single(await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(61), GroupFanoutTestFixture.Time(1),
            TimeSpan.FromMinutes(1), 1));
        var work = Assert.IsType<GroupFanoutNetworkWork>(
            (await handle.Store.BeginNetworkWorkAsync(lease, GroupFanoutTestFixture.Time(1))).Work);

        await Assert.ThrowsAsync<ArgumentException>(async () => await handle.Store.RecordOutcomeAsync(
            work,
            GroupFanoutAttemptOutcome.DefiniteRejected,
            GroupFanoutDefiniteRejectRule.RetryWithNewOperation));
        Assert.Equal(GroupFanoutMutationDisposition.Applied,
            await handle.Store.RecordOutcomeAsync(work, GroupFanoutAttemptOutcome.OutcomeUnknown));
        Assert.Equal(GroupFanoutMutationDisposition.Idempotent,
            await handle.Store.RecordOutcomeAsync(work, GroupFanoutAttemptOutcome.OutcomeUnknown));

        var retryLease = Assert.Single(await handle.Store.ClaimReadyAsync(
            plan.BatchId, GroupFanoutTestFixture.Owner(62), GroupFanoutTestFixture.Time(2),
            TimeSpan.FromMinutes(1), 1));
        var retryWork = Assert.IsType<GroupFanoutNetworkWork>(
            (await handle.Store.BeginNetworkWorkAsync(retryLease, GroupFanoutTestFixture.Time(2))).Work);
        Assert.Equal(work.NetworkOperationId.Bytes.ToArray(), retryWork.NetworkOperationId.Bytes.ToArray());
        Assert.Equal(work.ExactCanonicalEnvelope.ToArray(), retryWork.ExactCanonicalEnvelope.ToArray());
    }

    [Fact]
    public async Task AccountAndStoreScopeAreFailClosedInMemoryAndAcrossSqlCipherRestart()
    {
        var first = GroupFanoutTestFixture.Plan(memberCount: 1, marker: 71);
        var other = GroupFanoutTestFixture.Plan(memberCount: 1, marker: 72);
        var plan = GroupFanoutTestFixture.Batch(first, 1, marker: 71);
        using (var memory = new InMemoryGroupFanoutStore(other.Scope))
            await Assert.ThrowsAsync<ArgumentException>(async () => await memory.StageAsync(plan));

        var path = DatabasePath(71);
        using (var store = OpenSql(path, first.Scope, allowCreate: true))
            await store.StageAsync(plan);
        using var wrongScope = new SqliteGroupFanoutStoreOptions(path, key, other.Scope, allowCreate: false);
        var error = Assert.Throws<GroupStateStoreOpenException>(() => new SqliteGroupFanoutStore(wrongScope));
        Assert.Equal(GroupStateStoreOpenFailure.ScopeMismatch, error.Reason);
    }

    [Fact]
    public async Task SqlStoreIsEncryptedCurrentSchemaAndWrongKeyFailsClosed()
    {
        var transition = GroupFanoutTestFixture.Plan(memberCount: 1, marker: 81);
        var plan = GroupFanoutTestFixture.Batch(transition, 1, marker: 81);
        var path = DatabasePath(81);
        using (var store = OpenSql(path, transition.Scope, allowCreate: true))
            await store.StageAsync(plan);

        var header = new byte[16];
        await using (var stream = File.OpenRead(path))
            Assert.Equal(header.Length, await stream.ReadAsync(header));
        Assert.False(header.AsSpan().SequenceEqual("SQLite format 3\0"u8));

        var wrongKey = GroupFanoutTestFixture.Hash("wrong-key", 81, 0);
        using var options = new SqliteGroupFanoutStoreOptions(path, wrongKey, transition.Scope, allowCreate: false);
        var error = Assert.Throws<GroupStateStoreOpenException>(() => new SqliteGroupFanoutStore(options));
        Assert.Equal(GroupStateStoreOpenFailure.UnreadableOrWrongKey, error.Reason);
        CryptographicOperations.ZeroMemory(wrongKey);
    }

    private static GroupFanoutNetworkWork Work(IEnumerable<GroupFanoutNetworkWork> values, int targetIndex) =>
        Assert.Single(values, value => Encoding.UTF8.GetString(value.ExactCanonicalEnvelope.Span)
            .StartsWith($"canonical-envelope-{targetIndex}", StringComparison.Ordinal));

    private static GroupFanoutTargetSnapshot Target(GroupFanoutBatchSnapshot snapshot, int targetIndex) =>
        Assert.Single(snapshot.Targets, value => value.TargetId.Bytes.Span.SequenceEqual(
            GroupFanoutTestFixture.Hash("target", 11, targetIndex)));

    private StoreHandle Open(bool sqlite, GroupStoreScope scope, int marker)
    {
        if (!sqlite)
        {
            var memory = new InMemoryGroupFanoutStore(scope);
            return new(memory, memory);
        }
        var store = OpenSql(DatabasePath(marker), scope, allowCreate: true);
        return new(store, store);
    }

    private SqliteGroupFanoutStore OpenSql(string path, GroupStoreScope scope, bool allowCreate)
    {
        using var options = new SqliteGroupFanoutStoreOptions(path, key, scope, allowCreate);
        return new(options);
    }

    private string DatabasePath(int marker) => Path.Combine(directory, $"fanout-{marker}.db");

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(key);
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed record StoreHandle(IGroupFanoutStore Store, IDisposable Disposable) : IDisposable
    {
        public void Dispose() => Disposable.Dispose();
    }
}
