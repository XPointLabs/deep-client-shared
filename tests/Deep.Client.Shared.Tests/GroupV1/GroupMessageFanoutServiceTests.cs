using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Client.Shared.Tests.MessagingV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class GroupMessageFanoutServiceTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "deep-group-msg01-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] groupKey = Hash("group-sqlcipher", 1, 1);

    public GroupMessageFanoutServiceTests() => Directory.CreateDirectory(directory);

    [Theory]
    [InlineData("memory")]
    [InlineData("sqlite")]
    public async Task ExactDgm1CreatesOneMsg01OutboxForEveryOtherActiveDeviceAndReplays(string kind)
    {
        var fixture = Fixture([2, 1, 1], marker: 11);
        await using var messages = MessageStoreHarness.Create(kind, MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var service = Service(groups, messages.Store);

        var first = await service.StageAsync(fixture.BatchId, fixture.Message);
        Assert.Equal(GroupMessageFanoutDisposition.Staged, first.Disposition);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(first.LogicalOutbox);
        Assert.Equal(MessagePayloadKind.GroupMessage, outbox.PayloadKind);
        Assert.Equal(fixture.Message.Field(5).ToArray(), outbox.SemanticMessageId.ToArray());
        Assert.Equal(fixture.Message.Field(2).ToArray(), outbox.ConversationId.ToArray());
        Assert.Equal(fixture.Message.CanonicalBytes.ToArray(), outbox.CanonicalPayload);
        Assert.Equal(fixture.Head.DeviceCount - 1, outbox.Targets.Count);
        Assert.DoesNotContain(outbox.Targets, target =>
            target.Target.AccountId.Equals(fixture.AuthorAccount)
            && target.Target.DeviceId.Equals(fixture.AuthorDevice));
        Assert.Equal(outbox.Targets.Count,
            outbox.Targets.Select(static target => target.OperationId).Distinct().Count());

        var exactOperations = outbox.Targets.Select(static target => target.OperationId!.ToArray()).ToArray();
        var replay = await service.StageAsync(fixture.BatchId, fixture.Message);
        Assert.Equal(GroupMessageFanoutDisposition.Idempotent, replay.Disposition);
        Assert.Equal(exactOperations,
            replay.LogicalOutbox!.Targets.Select(static target => target.OperationId!.ToArray()).ToArray());
    }

    [Fact]
    public async Task SqlCipherGroupHeadAndMsg01FanoutSurviveIndependentColdRestartAtMaximumProfile()
    {
        var fixture = Fixture(Enumerable.Repeat(5, 100).ToArray(), marker: 21);
        var groupPath = Path.Combine(directory, "groups.db");
        using (var options = new SqliteGroupStateStoreOptions(
                   groupPath, groupKey, fixture.Scope, allowCreate: true))
        using (var groups = new SqliteGroupStateStore(options))
        {
            var transition = TransitionPlan(fixture, GroupOperationId32.FromBytes(Hash("transition", 21, 0)));
            Assert.Equal(GroupCommitDisposition.Applied,
                (await groups.CommitVerifiedTransitionAsync(transition)).Disposition);
        }

        await using var messages = MessageStoreHarness.Create("sqlite", MessageScope(fixture));
        using (var options = new SqliteGroupStateStoreOptions(
                   groupPath, groupKey, fixture.Scope, allowCreate: false))
        using (var groups = new SqliteGroupStateStore(options))
        {
            var first = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
            Assert.Equal(GroupMessageFanoutDisposition.Staged, first.Disposition);
            Assert.Equal(100, fixture.Head.MemberCount);
            Assert.Equal(500, fixture.Head.DeviceCount);
            Assert.Equal(499, first.LogicalOutbox!.Targets.Count);
        }

        await messages.ReopenAsync();
        using (var options = new SqliteGroupStateStoreOptions(
                   groupPath, groupKey, fixture.Scope, allowCreate: false))
        using (var groups = new SqliteGroupStateStore(options))
        {
            var replay = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
            Assert.Equal(GroupMessageFanoutDisposition.Idempotent, replay.Disposition);
            Assert.Equal(499, replay.LogicalOutbox!.Targets.Count);
            Assert.All(replay.LogicalOutbox.Targets, static target =>
                Assert.Equal(LogicalTargetState.Pending, target.State));
        }
    }

    [Fact]
    public async Task StaleOrForkedHeadFailsBeforeMsg01Mutation()
    {
        var old = Fixture([2, 1], marker: 31);
        var successor = Fixture([1, 1], marker: 31, epoch: 1,
            predecessorHash: old.Head.CommitHash.ToArray());
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(old));
        var groups = new FixedGroupStateStore(old.Scope, successor.Head);
        var service = Service(groups, messages.Store);

        var stale = await service.StageAsync(old.BatchId, old.Message);
        Assert.Equal(GroupMessageFanoutDisposition.StaleGroupState, stale.Disposition);
        Assert.Null(await messages.Store.ReadAsync(Claim(old), CancellationToken.None));

        groups.Head = Forked(successor.Head);
        var fork = await service.StageAsync(successor.BatchId, successor.Message);
        Assert.Equal(GroupMessageFanoutDisposition.ForkLatched, fork.Disposition);
        Assert.Null(await messages.Store.ReadAsync(Claim(successor), CancellationToken.None));
    }

    [Fact]
    public async Task RemovedDeviceIsExcludedAndOldEpochCannotReuseItsPendingTargetSet()
    {
        var old = Fixture([2, 1], marker: 41);
        var current = Fixture([1, 1], marker: 41, epoch: 1,
            predecessorHash: old.Head.CommitHash.ToArray());
        var removedDevice = Device(41, 0, 1);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(current));
        var groups = new FixedGroupStateStore(current.Scope, current.Head);
        var service = Service(groups, messages.Store);

        Assert.Equal(GroupMessageFanoutDisposition.StaleGroupState,
            (await service.StageAsync(old.BatchId, old.Message)).Disposition);
        var staged = await service.StageAsync(current.BatchId, current.Message);
        Assert.Equal(GroupMessageFanoutDisposition.Staged, staged.Disposition);
        Assert.DoesNotContain(staged.LogicalOutbox!.Targets,
            target => target.Target.DeviceId.Equals(removedDevice));
        Assert.Single(staged.LogicalOutbox.Targets);
    }

    [Fact]
    public async Task ChangedBytesOrReusedBatchIdFailClosedWithOriginalExactIdsIntact()
    {
        var fixture = Fixture([2, 1], marker: 51);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var service = Service(groups, messages.Store);
        var first = await service.StageAsync(fixture.BatchId, fixture.Message);
        var original = first.LogicalOutbox!.Targets
            .Select(static target => target.OperationId!.ToArray()).ToArray();

        var changed = Message(fixture, semantic: fixture.Message.Field(5).ToArray(), payload: "changed"u8.ToArray());
        var fork = await service.StageAsync(fixture.BatchId, changed);
        Assert.Equal(GroupMessageFanoutDisposition.MessageForkLatched, fork.Disposition);

        var differentSemantic = Message(fixture, semantic: Hash("semantic", 51, 999), payload: "different"u8.ToArray());
        var conflict = await service.StageAsync(fixture.BatchId, differentSemantic);
        Assert.Equal(GroupMessageFanoutDisposition.Conflict, conflict.Disposition);
        var retained = await messages.Store.ReadAsync(Claim(fixture), CancellationToken.None);
        Assert.Equal(original, retained!.Targets.Select(static target => target.OperationId!.ToArray()).ToArray());
        Assert.Equal(fixture.Message.CanonicalBytes.ToArray(), retained.CanonicalPayload);
    }

    [Fact]
    public async Task UnboundDurablePackageIsRejectedBeforeLogicalOutboxCallback()
    {
        var fixture = Fixture([2, 1], marker: 56);
        var unrelated = Fixture([2, 1], marker: 57);
        var hostileHead = new GroupHeadSnapshot(
            fixture.Head.GroupId,
            fixture.Head.NetworkId.Span,
            fixture.Head.Epoch,
            fixture.Head.Revision,
            fixture.Head.CommitHash.Span,
            unrelated.Head.PackageHash.Span,
            fixture.Head.PredecessorHash.Span,
            fixture.Head.ExactCanonicalCommit.Span,
            unrelated.Head.ExactCanonicalPackage.Span,
            unrelated.Head.ExactVerifiedGcp1Sha256.Span,
            fixture.Head.MemberCount,
            fixture.Head.DeviceCount,
            false,
            [],
            []);
        var outbox = new RejectIfCalledLogicalOutbox();
        var service = new GroupMessageFanoutService(
            new FixedGroupStateStore(fixture.Scope, hostileHead), outbox);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.StageAsync(fixture.BatchId, fixture.Message).AsTask());
        Assert.False(outbox.Called);
    }

    [Fact]
    public async Task HeadLeaseRemainsHeldUntilCompleteLogicalFanoutIsDurable()
    {
        var fixture = Fixture([2, 1], marker: 61);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new BlockingGroupStateStore(fixture.Scope, fixture.Head);
        var outbox = new BlockingLogicalOutbox(new Msg01GroupMessageLogicalOutbox(messages.Store));
        var stage = new GroupMessageFanoutService(groups, outbox)
            .StageAsync(fixture.BatchId, fixture.Message).AsTask();
        await outbox.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var advance = groups.AdvanceAsync();
        await Task.Delay(50);
        Assert.False(advance.IsCompleted);
        outbox.Release.SetResult();

        Assert.Equal(GroupMessageFanoutDisposition.Staged, (await stage).Disposition);
        await advance.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("memory")]
    [InlineData("sqlite")]
    public async Task FirstDispatchRevalidatesExactDurableTargetAndDisposesCallbackPayload(string kind)
    {
        var fixture = Fixture([2, 1], marker: 71);
        await using var messages = MessageStoreHarness.Create(kind, MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, outbox, outbox.Targets.Last(), 710);
        var target = active.Target;
        GroupMessageFirstDispatchContext? retained = null;
        var callbacks = 0;

        var result = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            active.Snapshot,
            target,
            (context, cancellationToken) =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                callbacks++;
                retained = context;
                Assert.Equal(active.Snapshot.CanonicalPayload, context.CanonicalDgm1.ToArray());
                Assert.Equal(target.Target, context.Target);
                Assert.Equal(target.DirectoryHeadHash, context.DirectoryHeadHash);
                Assert.Equal(target.OperationId, context.OperationId);
                Assert.Equal(target.BindingHash, context.BindingHash);
                Assert.Equal(active.AttemptId, context.AttemptId);
                Assert.Equal(target.RequestHash, context.RequestHash);
                Assert.Equal(target.RatchetBeforeHash, context.RatchetBeforeHash);
                Assert.Equal(target.RatchetTransitionHash, context.RatchetTransitionHash);
                Assert.Equal(target.Ciphertext, context.Ciphertext.ToArray());
                return ValueTask.CompletedTask;
            });

        Assert.Equal(GroupMessageFirstDispatchDisposition.Dispatched, result.Disposition);
        Assert.Equal(1, callbacks);
        Assert.Throws<ObjectDisposedException>(() => retained!.CanonicalDgm1.ToArray());
        Assert.Throws<ObjectDisposedException>(() => retained!.Ciphertext.ToArray());
    }

    [Fact]
    public async Task FirstDispatchHoldsDatabaseWideHeadLeaseThroughCallback()
    {
        var fixture = Fixture([2, 1], marker: 72);
        var successor = Fixture([1, 1], marker: 72, epoch: 1,
            predecessorHash: fixture.Head.CommitHash.ToArray());
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new BlockingGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, outbox, outbox.Targets[0], 720);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var dispatch = DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            active.Snapshot,
            active.Target,
            async (_, cancellationToken) =>
            {
                entered.SetResult();
                await release.Task.WaitAsync(cancellationToken);
            }).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var advance = groups.AdvanceAsync(successor.Head);
        await Task.Delay(50);
        Assert.False(advance.IsCompleted);
        release.SetResult();

        Assert.Equal(GroupMessageFirstDispatchDisposition.Dispatched, (await dispatch).Disposition);
        await advance.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(successor.Head.Epoch,
            (await groups.ReadHeadAsync(successor.Head.GroupId))!.Epoch);
    }

    [Fact]
    public async Task RemovedTargetIsRejectedBeforeFirstDispatchCallback()
    {
        var old = Fixture([2, 1], marker: 73);
        var current = Fixture([1, 1], marker: 73, epoch: 1,
            predecessorHash: old.Head.CommitHash.ToArray());
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(old));
        var groups = new FixedGroupStateStore(old.Scope, old.Head);
        var staged = await Service(groups, messages.Store).StageAsync(old.BatchId, old.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var removedDevice = Device(73, 0, 1);
        var removed = Assert.Single(outbox.Targets,
            candidate => candidate.Target.DeviceId.Equals(removedDevice));
        var active = await ActivateFirstAttemptAsync(messages.Store, outbox, removed, 730);
        groups.Head = current.Head;
        var called = false;

        var result = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            active.Snapshot, active.Target,
            (_, _) => { called = true; return ValueTask.CompletedTask; });

        Assert.Equal(GroupMessageFirstDispatchDisposition.TargetRemoved, result.Disposition);
        Assert.False(called);
        var durable = await messages.Store.ReadAsync(
            active.Snapshot.ClaimKey, CancellationToken.None);
        Assert.Equal(LogicalOutboxState.FanoutPrepared, durable!.State);
        var revoked = Assert.Single(durable.Targets,
            candidate => candidate.Target.Equals(active.Target.Target));
        Assert.Equal(LogicalTargetState.RevokedTarget, revoked.State);
        Assert.Null(revoked.ActiveAttemptId);
        Assert.Null(revoked.UnresolvedAttemptId);
        Assert.Null(revoked.Ciphertext);
    }

    [Fact]
    public async Task RevokedAndTerminalRejectedTargetsAggregateAsTerminalRejectedNotExpired()
    {
        var old = Fixture([2, 1], marker: 731);
        var current = Fixture([1, 1], marker: 731, epoch: 1,
            predecessorHash: old.Head.CommitHash.ToArray());
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(old));
        var groups = new FixedGroupStateStore(old.Scope, old.Head);
        var staged = await Service(groups, messages.Store).StageAsync(old.BatchId, old.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var removedDevice = Device(731, 0, 1);
        var removed = Assert.Single(outbox.Targets,
            candidate => candidate.Target.DeviceId.Equals(removedDevice));
        var first = await ActivateFirstAttemptAsync(messages.Store, outbox, removed, 7310);
        groups.Head = current.Head;
        var callbacks = 0;

        var revoked = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            first.Snapshot,
            first.Target,
            (_, _) => { callbacks++; return ValueTask.CompletedTask; });
        Assert.Equal(GroupMessageFirstDispatchDisposition.TargetRemoved, revoked.Disposition);
        var afterRevocation = Assert.IsType<LogicalOutboxSnapshot>(
            await messages.Store.ReadAsync(first.Snapshot.ClaimKey, CancellationToken.None));
        Assert.Equal(LogicalOutboxState.FanoutPrepared, afterRevocation.State);

        var remaining = Assert.Single(afterRevocation.Targets,
            candidate => candidate.State == LogicalTargetState.Pending);
        var second = await ActivateFirstAttemptAsync(
            messages.Store, afterRevocation, remaining, 7311);
        var rejected = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            second.Snapshot,
            second.Target,
            (_, _) => { callbacks++; return ValueTask.CompletedTask; });

        Assert.Equal(GroupMessageFirstDispatchDisposition.StaleGroupState, rejected.Disposition);
        Assert.Equal(0, callbacks);
        var terminal = Assert.IsType<LogicalOutboxSnapshot>(
            await messages.Store.ReadAsync(second.Snapshot.ClaimKey, CancellationToken.None));
        Assert.Equal(LogicalOutboxState.TerminalRejected, terminal.State);
        Assert.DoesNotContain(terminal.Targets,
            candidate => candidate.State == LogicalTargetState.Expired);
        Assert.Contains(terminal.Targets,
            candidate => candidate.State == LogicalTargetState.RevokedTarget);
        Assert.Contains(terminal.Targets,
            candidate => candidate.State == LogicalTargetState.TerminalRejected);
        Assert.All(terminal.Targets, static candidate =>
        {
            Assert.Null(candidate.ActiveAttemptId);
            Assert.Null(candidate.UnresolvedAttemptId);
            Assert.Null(candidate.Ciphertext);
        });
    }

    [Fact]
    public async Task ChangedHeadAndForkReturnExplicitDispositionWithoutCallback()
    {
        var old = Fixture([2, 1], marker: 74);
        var current = Fixture([2, 1], marker: 74, epoch: 1,
            predecessorHash: old.Head.CommitHash.ToArray());
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(old));
        var groups = new FixedGroupStateStore(old.Scope, old.Head);
        var staged = await Service(groups, messages.Store).StageAsync(old.BatchId, old.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, outbox, outbox.Targets.Last(), 740);
        var target = active.Target;
        var called = false;
        var service = new GroupMessageDispatchSafetyService(groups);

        groups.Head = current.Head;
        var stale = await DispatchFirstAsync(messages, service,
            active.Snapshot, target, (_, _) => { called = true; return ValueTask.CompletedTask; });
        Assert.Equal(GroupMessageFirstDispatchDisposition.StaleGroupState, stale.Disposition);
        Assert.False(called);

        var forkFixture = Fixture([2, 1], marker: 741);
        await using var forkMessages = MessageStoreHarness.Create("memory", MessageScope(forkFixture));
        var forkGroups = new FixedGroupStateStore(forkFixture.Scope, forkFixture.Head);
        var forkStaged = await Service(forkGroups, forkMessages.Store)
            .StageAsync(forkFixture.BatchId, forkFixture.Message);
        var forkOutbox = Assert.IsType<LogicalOutboxSnapshot>(forkStaged.LogicalOutbox);
        var forkActive = await ActivateFirstAttemptAsync(
            forkMessages.Store, forkOutbox, forkOutbox.Targets.Last(), 7410);
        forkGroups.Head = Forked(forkFixture.Head);
        var fork = await DispatchFirstAsync(
            forkMessages,
            new GroupMessageDispatchSafetyService(forkGroups),
            forkActive.Snapshot,
            forkActive.Target,
            (_, _) => { called = true; return ValueTask.CompletedTask; });
        Assert.Equal(GroupMessageFirstDispatchDisposition.ForkLatched, fork.Disposition);
        Assert.False(called);
    }

    [Fact]
    public async Task TargetFromAnotherOutboxReturnsNoTargetWithoutCallback()
    {
        var fixture = Fixture([2, 1], marker: 75);
        var other = Fixture([2, 1], marker: 76);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        await using var otherMessages = MessageStoreHarness.Create("memory", MessageScope(other));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var otherStaged = await Service(
            new FixedGroupStateStore(other.Scope, other.Head), otherMessages.Store)
            .StageAsync(other.BatchId, other.Message);
        var active = await ActivateFirstAttemptAsync(
            messages.Store, staged.LogicalOutbox!, staged.LogicalOutbox!.Targets[0], 750);
        var otherActive = await ActivateFirstAttemptAsync(
            otherMessages.Store, otherStaged.LogicalOutbox!, otherStaged.LogicalOutbox!.Targets[0], 751);
        var called = false;

        var result = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            active.Snapshot,
            otherActive.Target,
            (_, _) => { called = true; return ValueTask.CompletedTask; });

        Assert.Equal(GroupMessageFirstDispatchDisposition.NoTarget, result.Disposition);
        Assert.False(called);
    }

    [Fact]
    public async Task AlreadyDispatchedAndReconciliationAttemptsAreNotFirstDispatches()
    {
        var fixture = Fixture([2, 1], marker: 761);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var original = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, original, original.Targets[0], 7610);
        var outcome = MessagingV1Fixture.Outcome(
            messages.Capabilities,
            active.Snapshot,
            active.Target.Target,
            active.AttemptId,
            VerifiedTargetOutcomeKind.Accepted);
        var accepted = (await messages.Store.ApplyAsync(
            PreparedMessageMutation.FromVerifiedOutcome(
                active.Snapshot, outcome, active.Snapshot.CreatedAt.AddMilliseconds(2)),
            CancellationToken.None)).Snapshot!;
        var acceptedTarget = accepted.Targets.Single(candidate =>
            candidate.Target.Equals(active.Target.Target));
        var called = false;

        var dispatched = await DispatchFirstAsync(
            messages,
            new GroupMessageDispatchSafetyService(groups),
            accepted,
            acceptedTarget,
            (_, _) => { called = true; return ValueTask.CompletedTask; });

        Assert.Equal(GroupMessageFirstDispatchDisposition.NotFirstDispatch, dispatched.Disposition);
        Assert.False(called);

        var reconcileFixture = Fixture([2, 1], marker: 762);
        await using var reconcileMessages = MessageStoreHarness.Create(
            "memory", MessageScope(reconcileFixture));
        var reconcileGroups = new FixedGroupStateStore(
            reconcileFixture.Scope, reconcileFixture.Head);
        var reconcileStaged = await Service(reconcileGroups, reconcileMessages.Store)
            .StageAsync(reconcileFixture.BatchId, reconcileFixture.Message);
        var reconcileOutbox = reconcileStaged.LogicalOutbox!;
        var reconcileActive = await ActivateFirstAttemptAsync(
            reconcileMessages.Store, reconcileOutbox, reconcileOutbox.Targets[0], 7620);
        var uncertainty = MessagingV1Fixture.Uncertainty(
            reconcileMessages.Capabilities,
            reconcileActive.Snapshot,
            reconcileActive.Target.Target,
            reconcileActive.AttemptId);
        var unknown = (await reconcileMessages.Store.ApplyAsync(
            PreparedMessageMutation.MarkOutcomeUnknown(
                reconcileActive.Snapshot,
                uncertainty,
                reconcileActive.Snapshot.CreatedAt.AddMilliseconds(2)),
            CancellationToken.None)).Snapshot!;
        var unknownTarget = unknown.Targets.Single(candidate =>
            candidate.Target.Equals(reconcileActive.Target.Target));

        var reconcile = await DispatchFirstAsync(
                reconcileMessages,
                new GroupMessageDispatchSafetyService(reconcileGroups),
                unknown,
                unknownTarget,
                (_, _) => { called = true; return ValueTask.CompletedTask; });
        Assert.Equal(GroupMessageFirstDispatchDisposition.NotFirstDispatch, reconcile.Disposition);
        Assert.False(called);

        var reconciliation = MessagingV1Fixture.Reconciliation(
            reconcileMessages.Capabilities,
            unknown,
            reconcileActive.AttemptId,
            VerifiedTargetOutcomeKind.NotAccepted);
        var reconciled = (await reconcileMessages.Store.ApplyAsync(
            PreparedMessageMutation.ReconcileOutcomeUnknown(
                unknown,
                reconciliation,
                unknown.CreatedAt.AddMilliseconds(3)),
            CancellationToken.None)).Snapshot!;
        var reconciledTarget = reconciled.Targets.Single(candidate =>
            candidate.Target.Equals(reconcileActive.Target.Target));

        var afterReconcile = await DispatchFirstAsync(
                reconcileMessages,
                new GroupMessageDispatchSafetyService(reconcileGroups),
                reconciled,
                reconciledTarget,
                (_, _) => { called = true; return ValueTask.CompletedTask; });
        Assert.Equal(GroupMessageFirstDispatchDisposition.NotFirstDispatch,
            afterReconcile.Disposition);
        Assert.False(called);
    }

    [Fact]
    public async Task HostileGroupPayloadRejectsBeforeCallback()
    {
        var fixture = Fixture([2, 1], marker: 77);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var original = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, original, original.Targets[0], 770);
        var hostileBytes = "not-a-dgm1"u8.ToArray();
        var hostile = new LogicalOutboxSnapshot(
            active.Snapshot.StoreScope,
            active.Snapshot.ClaimKey,
            active.Snapshot.AuthorDeviceId,
            MessageEventHash32.FromBytes(SHA256.HashData(hostileBytes)),
            hostileBytes,
            active.Snapshot.CreatedAt,
            active.Snapshot.ExpiresAt,
            active.Snapshot.State,
            active.Snapshot.Revision,
            active.Snapshot.Targets,
            payloadKind: MessagePayloadKind.GroupMessage);
        var called = false;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            DispatchFirstAsync(
                messages,
                new GroupMessageDispatchSafetyService(groups),
                hostile,
                hostile.Targets[0],
                (_, _) => { called = true; return ValueTask.CompletedTask; }).AsTask());
        Assert.False(called);
    }

    [Fact]
    public async Task ActiveAttemptWithChangedCiphertextBindingRejectsBeforeCallback()
    {
        var fixture = Fixture([2, 1], marker: 78);
        await using var messages = MessageStoreHarness.Create("memory", MessageScope(fixture));
        var groups = new FixedGroupStateStore(fixture.Scope, fixture.Head);
        var staged = await Service(groups, messages.Store).StageAsync(fixture.BatchId, fixture.Message);
        var original = staged.LogicalOutbox!;
        var active = await ActivateFirstAttemptAsync(messages.Store, original, original.Targets[0], 780);
        var changedCiphertext = active.Target.Ciphertext!;
        changedCiphertext[0] ^= 0x80;
        var hostileTarget = new LogicalTargetSnapshot(
            active.Target.Target,
            active.Target.DirectoryHeadHash,
            active.Target.State,
            active.Target.ActiveAttemptId,
            active.Target.LastAttemptId,
            active.Target.UnresolvedAttemptId,
            active.Target.RequestHash,
            active.Target.RatchetTransitionHash,
            active.Target.OutcomeUnknown,
            active.Target.OperationId,
            active.Target.BindingHash,
            changedCiphertext,
            active.Target.RatchetBeforeHash);
        var targets = active.Snapshot.Targets
            .Select(candidate => candidate.Target.Equals(hostileTarget.Target)
                ? hostileTarget : candidate)
            .ToArray();
        var hostile = new LogicalOutboxSnapshot(
            active.Snapshot.StoreScope,
            active.Snapshot.ClaimKey,
            active.Snapshot.AuthorDeviceId,
            active.Snapshot.EventHash,
            active.Snapshot.CanonicalPayload,
            active.Snapshot.CreatedAt,
            active.Snapshot.ExpiresAt,
            active.Snapshot.State,
            active.Snapshot.Revision,
            targets,
            payloadKind: MessagePayloadKind.GroupMessage);
        var called = false;
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                DispatchFirstAsync(
                    messages,
                    new GroupMessageDispatchSafetyService(groups),
                    hostile,
                    hostileTarget,
                    (_, _) => { called = true; return ValueTask.CompletedTask; }).AsTask());
            Assert.False(called);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(changedCiphertext);
        }
    }

    private static async Task<ActiveAttempt> ActivateFirstAttemptAsync(
        IMessageTransactionStore store,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        int marker)
    {
        var attemptId = TransportAttemptId16.FromBytes(Hash("attempt", marker, 0)[..16]);
        var ciphertext = Enumerable.Range(0, 256)
            .Select(index => unchecked((byte)(marker + index * 17)))
            .ToArray();
        try
        {
            var attempt = new TargetAttemptPlan(
                target.Target,
                attemptId,
                TransportRequestHash32.FromBytes(SHA256.HashData(ciphertext)),
                RatchetStateHash32.FromBytes(Hash("ratchet-before", marker, 0)),
                RatchetTransitionHash32.FromBytes(Hash("ratchet-after", marker, 0)),
                target.DirectoryHeadHash,
                target.OperationId!,
                target.BindingHash!,
                ciphertext);
            var applied = await store.ApplyAsync(
                PreparedMessageMutation.StartSending(
                    outbox,
                    MessageMutationId32.FromBytes(Hash("start-attempt", marker, 0)),
                    [attempt],
                    outbox.CreatedAt.AddMilliseconds(1)),
                CancellationToken.None);
            Assert.Equal(MessageCommitResult.Applied, applied.CommitResult);
            var snapshot = Assert.IsType<LogicalOutboxSnapshot>(applied.Snapshot);
            var durableTarget = Assert.Single(snapshot.Targets,
                candidate => candidate.Target.Equals(target.Target));
            Assert.Equal(attemptId, durableTarget.ActiveAttemptId);
            Assert.Equal(attemptId, durableTarget.UnresolvedAttemptId);
            Assert.Null(durableTarget.LastAttemptId);
            return new ActiveAttempt(snapshot, durableTarget, attemptId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static ValueTask<GroupMessageFirstDispatchResult> DispatchFirstAsync(
        MessageStoreHarness messages,
        GroupMessageDispatchSafetyService service,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        Func<GroupMessageFirstDispatchContext, CancellationToken, ValueTask> firstDispatch,
        CancellationToken cancellationToken = default) =>
        service.DispatchFirstAsync(
            outbox,
            target,
            messages.Store,
            messages.GroupDispatchSafety,
            outbox.CreatedAt.AddSeconds(1),
            firstDispatch,
            cancellationToken);

    private static GroupMessageFanoutService Service(
        IGroupStateStore groups,
        IMessageTransactionStore messages) =>
        new(groups, new Msg01GroupMessageLogicalOutbox(messages));

    private static MessageStoreScope MessageScope(FixtureData fixture) => new(
        fixture.AuthorAccount,
        fixture.Scope.AccountGeneration,
        MessageStoreInstanceId32.FromBytes(Hash("message-store", fixture.Marker, 0)));

    private static SemanticClaimKey Claim(FixtureData fixture) => new(
        fixture.AuthorAccount,
        ConversationId32.FromBytes(fixture.Message.Field(2).Span),
        SemanticMessageId32.FromBytes(fixture.Message.Field(5).Span));

    private static FixtureData Fixture(
        IReadOnlyList<int> devicesPerMember,
        int marker,
        ulong epoch = 0,
        byte[]? predecessorHash = null)
    {
        if (devicesPerMember.Count is < 1 or > 100
            || devicesPerMember.Any(static count => count is < 1 or > 5))
            throw new ArgumentOutOfRangeException(nameof(devicesPerMember));
        var scope = Scope(marker);
        var network = Hash("network", marker, 0)[..16];
        var group = Hash("group", marker, 0);
        var ownerAccount = scope.AccountId.Bytes.ToArray();
        var ownerDevice = Device(marker, 0, 0).ToArray();
        var rows = new List<(byte[] Account, byte[] Row)>();
        for (var memberIndex = 0; memberIndex < devicesPerMember.Count; memberIndex++)
        {
            var account = memberIndex == 0 ? ownerAccount : Hash("account", marker, memberIndex);
            var devices = Enumerable.Range(0, devicesPerMember[memberIndex])
                .Select(deviceIndex => Device(marker, memberIndex, deviceIndex).ToArray()).ToArray();
            rows.Add((account, Member(
                account,
                memberIndex == 0 ? (byte)1 : (byte)3,
                memberIndex == 0 ? scope.AccountGeneration : 1,
                Hash("directory", marker, memberIndex),
                devices,
                marker,
                memberIndex)));
        }
        var members = rows.OrderBy(static row => row.Account, ByteArrayComparer.Instance)
            .SelectMany(static row => row.Row).ToArray();
        var commit = Assert.IsType<GroupCommitRecord>(Record("DGC1",
        [
            network, group, U16(1), U64(epoch), predecessorHash ?? new byte[32],
            ownerAccount, ownerDevice, Ref("DPD1", Hash("dpd", marker, 0)),
            U16(0), [], U16(checked((ushort)devicesPerMember.Count)), members,
            "group"u8.ToArray(), [0], U32(3600), U64(epoch + 1), Hash("signature", marker, 0).Concat(Hash("signature", marker, 1)).ToArray(),
        ]));
        var package = Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",
        [
            network, group, U64(epoch), Lp(commit.CanonicalBytes.Span),
            U16(0), [], U32(0), [], U16(0), [], [],
        ]));
        var deviceCount = checked((ushort)devicesPerMember.Sum());
        var head = new GroupHeadSnapshot(
            GroupId32.FromBytes(group), network, epoch, 1,
            commit.ArtifactHash.Span, package.ArtifactHash.Span,
            predecessorHash ?? new byte[32], commit.CanonicalBytes.Span,
            package.CanonicalBytes.Span, SHA256.HashData(package.CanonicalBytes.Span),
            checked((ushort)devicesPerMember.Count), deviceCount, false, [], []);
        var batch = GroupFanoutBatchId32.FromBytes(Hash("batch", marker, checked((int)epoch)));
        var fixture = new FixtureData(marker, scope, head, commit, package, batch,
            MessagingAccountId32.FromBytes(ownerAccount), MessagingDeviceId32.FromBytes(ownerDevice), null!);
        fixture = fixture with { Message = Message(fixture, Hash("semantic", marker, checked((int)epoch)), "hello"u8.ToArray()) };
        return fixture;
    }

    private static GroupApplicationMessageRecord Message(
        FixtureData fixture,
        byte[] semantic,
        byte[] payload) =>
        Assert.IsType<GroupApplicationMessageRecord>(Record("DGM1",
        [
            fixture.Head.NetworkId.ToArray(), fixture.Head.GroupId.ToArray(), U64(fixture.Head.Epoch),
            fixture.Head.CommitHash.ToArray(), semantic, fixture.AuthorAccount.ToArray(),
            fixture.AuthorDevice.ToArray(), U64(1), U64(1_900_000_000_000),
            U64(1_900_000_000_000 + 7 * 24 * 60 * 60 * 1000), U16(1), payload,
        ]));

    private static GroupTransitionCommitPlan TransitionPlan(
        FixtureData fixture,
        GroupOperationId32 operationId)
    {
        var verified = Verified(fixture.Commit, null, fixture.Package);
        return new GroupClientStateService().PrepareVerifiedTransition(
            fixture.Scope, operationId, null, verified, fixture.Package);
    }

    private static VerifiedGroupTransition Verified(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        GroupCommitPackageRecord package)
    {
        var implementation = typeof(VerifiedGroupTransition).Assembly.GetType(
            "Deep.Protocol.GroupV1.GroupCodec+VerifiedGroupTransitionImpl", throwOnError: true)!;
        var transition = (VerifiedGroupTransition)System.Runtime.CompilerServices.RuntimeHelpers
            .GetUninitializedObject(implementation);
        typeof(VerifiedGroupTransition).GetField(
            "<Commit>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(transition, commit);
        typeof(VerifiedGroupTransition).GetField(
            "<Predecessor>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(transition, predecessor);
        typeof(VerifiedGroupTransition).GetField(
            "exactVerifiedGcp1Sha256", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(transition, SHA256.HashData(package.CanonicalBytes.Span));
        return transition;
    }

    private static GroupHeadSnapshot Forked(GroupHeadSnapshot head) => new(
        head.GroupId, head.NetworkId.Span, head.Epoch, head.Revision,
        head.CommitHash.Span, head.PackageHash.Span, head.PredecessorHash.Span,
        head.ExactCanonicalCommit.Span, head.ExactCanonicalPackage.Span,
        head.ExactVerifiedGcp1Sha256.Span, head.MemberCount, head.DeviceCount,
        true, head.Artifacts, head.ControlCursors);

    private static GroupStoreScope Scope(int marker)
    {
        var capability = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Hash("identity-network", marker, 0)[..16]),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Hash("identity", marker, 0)));
        return GroupStoreScope.ForCurrentAccount(capability.AccountId, capability.AccountGeneration);
    }

    private static MessagingDeviceId32 Device(int marker, int member, int device) =>
        MessagingDeviceId32.FromBytes(Hash("device", marker * 1000 + member, device));

    private static byte[] Member(
        byte[] account,
        byte role,
        ulong accountGeneration,
        byte[] directoryHash,
        IReadOnlyList<byte[]> devices,
        int marker,
        int memberIndex)
    {
        var ordered = devices.OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
        var body = new byte[220 + ordered.Length * 70];
        account.CopyTo(body, 0);
        body[32] = role;
        Ref("ADC1", Hash("adc", marker, memberIndex)).CopyTo(body, 33);
        Ref("ADH1", Hash("adh", marker, memberIndex)).CopyTo(body, 71);
        Hash("adp", marker, memberIndex).CopyTo(body, 109);
        U64(accountGeneration).CopyTo(body, 141);
        directoryHash.CopyTo(body, 149);
        Ref("DRS1", Hash("drs", marker, memberIndex)).CopyTo(body, 181);
        body[219] = checked((byte)ordered.Length);
        for (var index = 0; index < ordered.Length; index++)
        {
            ordered[index].CopyTo(body, 220 + index * 70);
            Ref("DPD1", Hash("dpd", marker * 1000 + memberIndex, index))
                .CopyTo(body, 252 + index * 70);
        }
        return U16(checked((ushort)body.Length)).Concat(body).ToArray();
    }

    private static GroupRecord Record(string magic, IReadOnlyList<byte[]> fields)
    {
        var length = 12 + fields.Sum(static field => 8 + field.Length);
        var bytes = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var at = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at + 4), checked((uint)fields[index].Length));
            at += 8;
            fields[index].CopyTo(bytes, at);
            at += fields[index].Length;
        }
        return GroupCodec.Decode(magic, bytes);
    }

    private static byte[] Ref(string magic, byte[] hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        hash.CopyTo(value, 6);
        return value;
    }

    private static byte[] Hash(string domain, int marker, int index) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"{domain}\0{marker}\0{index}"));
    private static byte[] Lp(ReadOnlySpan<byte> value) => U32(checked((uint)value.Length)).Concat(value.ToArray()).ToArray();
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(groupKey);
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed record FixtureData(
        int Marker,
        GroupStoreScope Scope,
        GroupHeadSnapshot Head,
        GroupCommitRecord Commit,
        GroupCommitPackageRecord Package,
        GroupFanoutBatchId32 BatchId,
        MessagingAccountId32 AuthorAccount,
        MessagingDeviceId32 AuthorDevice,
        GroupApplicationMessageRecord Message);

    private sealed record ActiveAttempt(
        LogicalOutboxSnapshot Snapshot,
        LogicalTargetSnapshot Target,
        TransportAttemptId16 AttemptId);

    private sealed class FixedGroupStateStore(GroupStoreScope scope, GroupHeadSnapshot head) : IGroupStateStore
    {
        public GroupStoreScope Scope { get; } = scope;
        internal GroupHeadSnapshot Head { get; set; } = head;
        public ValueTask<GroupHeadSnapshot?> ReadHeadAsync(GroupId32 groupId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<GroupHeadSnapshot?>(Head.GroupId.Equals(groupId) ? Head.Copy() : null);
        public ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadHeadsAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IReadOnlyList<GroupHeadSnapshot>>([Head.Copy()]);
        public ValueTask<GroupHeadReadLease> AcquireHeadReadLeaseAsync(GroupId32 groupId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new GroupHeadReadLease(Head.GroupId.Equals(groupId) ? Head : null, static () => { }));
        public ValueTask<GroupCommitResult> CommitVerifiedTransitionAsync(GroupTransitionCommitPlan plan, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class BlockingGroupStateStore(GroupStoreScope scope, GroupHeadSnapshot head) : IGroupStateStore
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private GroupHeadSnapshot current = head.Copy();
        public GroupStoreScope Scope { get; } = scope;
        public ValueTask<GroupHeadSnapshot?> ReadHeadAsync(GroupId32 groupId, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<GroupHeadSnapshot?>(current.Copy());
        public ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadHeadsAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<IReadOnlyList<GroupHeadSnapshot>>([current.Copy()]);
        public async ValueTask<GroupHeadReadLease> AcquireHeadReadLeaseAsync(GroupId32 groupId, CancellationToken cancellationToken = default)
        {
            await gate.WaitAsync(cancellationToken);
            return new GroupHeadReadLease(current, () => { gate.Release(); });
        }
        public ValueTask<GroupCommitResult> CommitVerifiedTransitionAsync(GroupTransitionCommitPlan plan, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
        internal async Task AdvanceAsync(GroupHeadSnapshot? successor = null)
        {
            await gate.WaitAsync();
            if (successor is not null)
                current = successor.Copy();
            gate.Release();
        }
    }

    private sealed class BlockingLogicalOutbox(IGroupMessageLogicalOutbox inner) : IGroupMessageLogicalOutbox
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<GroupMessageLogicalOutboxWriteResult> StageAsync(
            GroupMessageLogicalOutboxPlan plan,
            CancellationToken cancellationToken = default)
        {
            Entered.SetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return await inner.StageAsync(plan, cancellationToken);
        }
    }

    private sealed class RejectIfCalledLogicalOutbox : IGroupMessageLogicalOutbox
    {
        internal bool Called { get; private set; }
        public ValueTask<GroupMessageLogicalOutboxWriteResult> StageAsync(
            GroupMessageLogicalOutboxPlan plan,
            CancellationToken cancellationToken = default)
        {
            Called = true;
            throw new InvalidOperationException("The hostile head reached the logical outbox.");
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) =>
            (x ?? throw new ArgumentNullException(nameof(x))).AsSpan()
            .SequenceCompareTo(y ?? throw new ArgumentNullException(nameof(y)));
    }
}
