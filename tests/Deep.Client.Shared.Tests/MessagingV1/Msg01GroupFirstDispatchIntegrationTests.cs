using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class Msg01GroupFirstDispatchIntegrationTests
{
    [Theory]
    [InlineData(GroupMessageFirstDispatchDisposition.GroupNotFound)]
    [InlineData(GroupMessageFirstDispatchDisposition.StaleGroupState)]
    [InlineData(GroupMessageFirstDispatchDisposition.ForkLatched)]
    [InlineData(GroupMessageFirstDispatchDisposition.TargetRemoved)]
    public async Task HeadChangeAfterRatchetPreparationBlocksFirstNetworkDispatch(
        GroupMessageFirstDispatchDisposition expected)
    {
        var initial = Fixture(marker: 811, includeRemote: true);
        var replacement = expected switch
        {
            GroupMessageFirstDispatchDisposition.GroupNotFound => null,
            GroupMessageFirstDispatchDisposition.StaleGroupState =>
                Fixture(811, includeRemote: true, epoch: 1,
                    predecessorHash: initial.Head.CommitHash.ToArray()).Head,
            GroupMessageFirstDispatchDisposition.ForkLatched => Forked(initial.Head),
            GroupMessageFirstDispatchDisposition.TargetRemoved =>
                Fixture(811, includeRemote: false, epoch: 1,
                    predecessorHash: initial.Head.CommitHash.ToArray()).Head,
            _ => throw new ArgumentOutOfRangeException(nameof(expected)),
        };
        var groups = new MutableGroupStateStore(initial.Scope, initial.Head);
        await using var messages = SharedMessagingV1Composition.CreateInMemory(
            initial.MessageScope, MessagingV1Fixture.CreateEvidenceAuthority());
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var leaseBaseline = groups.LeaseAcquisitions;
        var source = new AuthenticatedEvidenceSource(outbox.Targets)
        {
            AfterPrepare = cancellationToken => groups.ReplaceAsync(replacement, cancellationToken),
        };
        await using var transport = CreateTransport(source, groups);

        var result = await transport.DispatchDurableGroupAsync(
            messages, outbox, CancellationToken.None);

        var block = Assert.Single(result.Blocks);
        Assert.Equal(expected, block.Disposition);
        Assert.Equal(outbox.Targets[0].Target, block.Target);
        Assert.Equal(0, source.DispatchCount);
        Assert.Equal(0, source.ReconcileCount);
        Assert.Equal(leaseBaseline + 1, groups.LeaseAcquisitions);
        var durableTarget = Assert.Single(result.Snapshot.Targets);
        Assert.Equal(LogicalOutboxState.TerminalRejected, result.Snapshot.State);
        Assert.Equal(
            expected == GroupMessageFirstDispatchDisposition.TargetRemoved
                ? LogicalTargetState.RevokedTarget
                : LogicalTargetState.TerminalRejected,
            durableTarget.State);
        Assert.Null(durableTarget.ActiveAttemptId);
        Assert.Null(durableTarget.UnresolvedAttemptId);
        Assert.Null(durableTarget.LastAttemptId);
        Assert.Null(durableTarget.RequestHash);
        Assert.Null(durableTarget.RatchetBeforeHash);
        Assert.Null(durableTarget.RatchetTransitionHash);
        Assert.Null(durableTarget.Ciphertext);
    }

    [Fact]
    public async Task ConcurrentHeadChangeCannotInterleaveWithFirstNetworkCallback()
    {
        var initial = Fixture(marker: 812, includeRemote: true);
        var successor = Fixture(812, includeRemote: true, epoch: 1,
            predecessorHash: initial.Head.CommitHash.ToArray());
        var groups = new MutableGroupStateStore(initial.Scope, initial.Head);
        await using var messages = SharedMessagingV1Composition.CreateInMemory(
            initial.MessageScope, MessagingV1Fixture.CreateEvidenceAuthority());
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var leaseBaseline = groups.LeaseAcquisitions;
        var source = new AuthenticatedEvidenceSource(outbox.Targets)
        {
            HoldDispatch = true,
            BeforeDispatch = async (request, cancellationToken) =>
            {
                var durable = await messages.Store.ReadAsync(
                    request.ClaimKey, cancellationToken);
                var durableTarget = Assert.Single(durable!.Targets);
                Assert.Equal(LogicalOutboxState.Sending, durable.State);
                Assert.Equal(request.AttemptId, durableTarget.ActiveAttemptId);
                Assert.Equal(request.AttemptId, durableTarget.UnresolvedAttemptId);
                Assert.Null(durableTarget.LastAttemptId);
            },
        };
        await using var transport = CreateTransport(source, groups);

        var dispatch = transport.DispatchDurableGroupAsync(
            messages, outbox, CancellationToken.None).AsTask();
        await source.DispatchEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var advance = groups.ReplaceAsync(successor.Head, CancellationToken.None).AsTask();
        await Task.Delay(75);
        Assert.False(advance.IsCompleted);
        source.ReleaseDispatch.TrySetResult();

        var result = await dispatch.WaitAsync(TimeSpan.FromSeconds(5));
        await advance.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Empty(result.Blocks);
        Assert.Equal(LogicalOutboxState.Accepted, result.Snapshot.State);
        Assert.Equal(1, source.DispatchCount);
        Assert.Equal(0, source.ReconcileCount);
        Assert.Equal(leaseBaseline + 1, groups.LeaseAcquisitions);
        Assert.Equal(successor.Head.Epoch,
            (await groups.ReadHeadAsync(successor.Head.GroupId))!.Epoch);
    }

    [Fact]
    public async Task RecoveredFirstAttemptReauthorizesButResolvedRetryDoesNotAcquireAnotherLease()
    {
        var fixture = Fixture(marker: 813, includeRemote: true);
        var groups = new MutableGroupStateStore(fixture.Scope, fixture.Head);
        await using var messages = SharedMessagingV1Composition.CreateInMemory(
            fixture.MessageScope, MessagingV1Fixture.CreateEvidenceAuthority());
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(fixture.BatchId, fixture.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var leaseBaseline = groups.LeaseAcquisitions;
        var target = Assert.Single(outbox.Targets);
        var ciphertext = fixture.Message.CanonicalBytes.ToArray();
        LogicalOutboxSnapshot active;
        try
        {
            var attempt = TransportAttemptId16.FromBytes(Hash("attempt", 813, 1)[..16]);
            active = (await messages.Store.ApplyAsync(
                PreparedMessageMutation.StartSending(
                    outbox,
                    MessageMutationId32.FromBytes(Hash("start", 813, 1)),
                    [new TargetAttemptPlan(
                        target.Target,
                        attempt,
                        TransportRequestHash32.FromBytes(SHA256.HashData(ciphertext)),
                        RatchetStateHash32.FromBytes(Hash("before", 813, 1)),
                        RatchetTransitionHash32.FromBytes(Hash("after", 813, 1)),
                        target.DirectoryHeadHash,
                        target.OperationId!,
                        target.BindingHash!,
                        ciphertext)],
                    outbox.CreatedAt.AddMilliseconds(1)),
                CancellationToken.None)).Snapshot!;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
        var source = new AuthenticatedEvidenceSource(active.Targets);
        await using var transport = CreateTransport(source, groups);

        var reconciled = await transport.DispatchDurableGroupAsync(
            messages, active, CancellationToken.None);
        Assert.Empty(reconciled.Blocks);
        Assert.Equal(LogicalOutboxState.FanoutPrepared, reconciled.Snapshot.State);
        Assert.Equal(0, source.DispatchCount);
        Assert.Equal(1, source.ReconcileCount);
        Assert.Equal(leaseBaseline + 1, groups.LeaseAcquisitions);

        var retried = await transport.DispatchDurableGroupAsync(
            messages, reconciled.Snapshot, CancellationToken.None);
        Assert.Empty(retried.Blocks);
        Assert.Equal(LogicalOutboxState.Accepted, retried.Snapshot.State);
        Assert.Equal(1, source.DispatchCount);
        Assert.Equal(1, source.ReconcileCount);
        Assert.Equal(leaseBaseline + 1, groups.LeaseAcquisitions);
    }

    [Fact]
    public async Task SqliteRestartNeverReconcilesOrDispatchesDurablyBlockedTarget()
    {
        var initial = Fixture(marker: 814, includeRemote: true);
        var removed = Fixture(814, includeRemote: false, epoch: 1,
            predecessorHash: initial.Head.CommitHash.ToArray());
        var groups = new MutableGroupStateStore(initial.Scope, initial.Head);
        await using var messages = MessageStoreHarness.Create("sqlite", initial.MessageScope);
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var outbox = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var source = new AuthenticatedEvidenceSource(outbox.Targets)
        {
            AfterPrepare = cancellationToken => groups.ReplaceAsync(
                removed.Head, cancellationToken),
        };
        await using var transport = CreateTransport(source, groups);

        var blocked = await transport.DispatchDurableGroupAsync(
            messages.Composition, outbox, CancellationToken.None);
        Assert.Equal(LogicalTargetState.RevokedTarget,
            Assert.Single(blocked.Snapshot.Targets).State);
        Assert.Equal(0, source.DispatchCount);
        Assert.Equal(0, source.ReconcileCount);

        await messages.ReopenAsync();
        var reloaded = await messages.Store.ReadAsync(
            blocked.Snapshot.ClaimKey, CancellationToken.None);
        var afterRestart = await transport.DispatchDurableGroupAsync(
            messages.Composition,
            Assert.IsType<LogicalOutboxSnapshot>(reloaded),
            CancellationToken.None);

        Assert.Empty(afterRestart.Blocks);
        Assert.Equal(LogicalOutboxState.TerminalRejected, afterRestart.Snapshot.State);
        Assert.Equal(LogicalTargetState.RevokedTarget,
            Assert.Single(afterRestart.Snapshot.Targets).State);
        Assert.Equal(0, source.DispatchCount);
        Assert.Equal(0, source.ReconcileCount);
    }

    [Theory]
    [InlineData("memory")]
    [InlineData("sqlite")]
    public async Task LocalBlockCapabilityRejectsReplaySubstitutionFakeAndForeignAuthority(
        string kind)
    {
        var initial = Fixture(marker: 815, includeRemote: true);
        var removed = Fixture(815, includeRemote: false, epoch: 1,
            predecessorHash: initial.Head.CommitHash.ToArray());
        var groups = new MutableGroupStateStore(initial.Scope, initial.Head);
        await using var messages = MessageStoreHarness.Create(kind, initial.MessageScope);
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var prepared = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, prepared, 815);
        await groups.ReplaceAsync(removed.Head, CancellationToken.None);
        var capturing = new CapturingMessageStore(messages.Store);
        var networkCalled = false;

        var decision = await new GroupMessageDispatchSafetyService(groups).DispatchFirstAsync(
            active,
            Assert.Single(active.Targets),
            capturing,
            messages.GroupDispatchSafety,
            active.CreatedAt.AddSeconds(1),
            (_, _) =>
            {
                networkCalled = true;
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(GroupMessageFirstDispatchDisposition.TargetRemoved, decision.Disposition);
        Assert.False(networkCalled);
        var mutation = Assert.IsType<PreparedMessageMutation>(capturing.LocalBlock);
        var capability = Assert.IsAssignableFrom<VerifiedLocalGroupDispatchBlock>(
            mutation.GroupDispatchBlock);
        var exactReplay = await messages.Store.ApplyAsync(mutation, CancellationToken.None);
        Assert.Equal(MessageCommitResult.Idempotent, exactReplay.CommitResult);
        Assert.Equal(LogicalOutboxState.TerminalRejected, exactReplay.Snapshot!.State);

        var stale = CopyOutbox(active, active.CanonicalPayload, active.EventHash,
            checked(active.Revision + 1));
        Assert.Throws<InvalidOperationException>(() =>
            PreparedMessageMutation.FromLocalGroupDispatchBlock(stale, capability));

        var changedDgm1 = active.CanonicalPayload;
        changedDgm1[^1] ^= 0x01;
        try
        {
            var substituted = CopyOutbox(
                active,
                changedDgm1,
                MessageEventHash32.FromBytes(SHA256.HashData(changedDgm1)),
                active.Revision);
            Assert.Throws<InvalidOperationException>(() =>
                PreparedMessageMutation.FromLocalGroupDispatchBlock(substituted, capability));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(changedDgm1);
        }

        await using var foreign = MessageStoreHarness.Create("memory", initial.MessageScope);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            foreign.Store.ApplyAsync(mutation, CancellationToken.None).AsTask());

        var fake = Assert.IsAssignableFrom<VerifiedLocalGroupDispatchBlock>(
            RuntimeHelpers.GetUninitializedObject(capability.GetType()));
        Assert.Throws<CryptographicException>(() =>
            PreparedMessageMutation.FromLocalGroupDispatchBlock(active, fake));
    }

    [Fact]
    public async Task CrashAfterLocalBlockCommitRestartsTerminalWithoutNetworkOrReconciliation()
    {
        var initial = Fixture(marker: 816, includeRemote: true);
        var removed = Fixture(816, includeRemote: false, epoch: 1,
            predecessorHash: initial.Head.CommitHash.ToArray());
        var groups = new MutableGroupStateStore(initial.Scope, initial.Head);
        var failpoint = new ArmableMessageStoreFailpoint();
        await using var messages = MessageStoreHarness.Create(
            "sqlite", initial.MessageScope, failpoint);
        var staged = await new GroupMessageFanoutService(
            groups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var prepared = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, prepared, 816);
        await groups.ReplaceAsync(removed.Head, CancellationToken.None);
        var networkCalled = false;
        failpoint.Arm("apply.after-commit-before-return");

        await Assert.ThrowsAsync<InjectedMessageStoreCrashException>(() =>
            new GroupMessageDispatchSafetyService(groups).DispatchFirstAsync(
                active,
                Assert.Single(active.Targets),
                messages.Store,
                messages.GroupDispatchSafety,
                active.CreatedAt.AddSeconds(1),
                (_, _) =>
                {
                    networkCalled = true;
                    return ValueTask.CompletedTask;
                },
                CancellationToken.None).AsTask());
        Assert.False(networkCalled);

        await messages.CrashReopenAsync();
        var durable = await messages.Store.ReadAsync(active.ClaimKey, CancellationToken.None);
        Assert.Equal(LogicalOutboxState.TerminalRejected, durable!.State);
        var target = Assert.Single(durable.Targets);
        Assert.Equal(LogicalTargetState.RevokedTarget, target.State);
        Assert.Null(target.ActiveAttemptId);
        Assert.Null(target.UnresolvedAttemptId);
        Assert.Null(target.Ciphertext);

        var source = new AuthenticatedEvidenceSource(active.Targets);
        await using var transport = CreateTransport(source, groups);
        var afterRestart = await transport.DispatchDurableGroupAsync(
            messages.Composition, durable, CancellationToken.None);
        Assert.Equal(LogicalOutboxState.TerminalRejected, afterRestart.Snapshot.State);
        Assert.Equal(0, source.DispatchCount);
        Assert.Equal(0, source.ReconcileCount);
    }

    [Fact]
    public async Task LocalBlockCommitsWhileExactGroupHeadLeaseRemainsHeld()
    {
        var initial = Fixture(marker: 817, includeRemote: true);
        var removed = Fixture(817, includeRemote: false, epoch: 1,
            predecessorHash: initial.Head.CommitHash.ToArray());
        var groups = new MutableGroupStateStore(initial.Scope, removed.Head);
        await using var messages = MessageStoreHarness.Create("memory", initial.MessageScope);
        var stagingGroups = new MutableGroupStateStore(initial.Scope, initial.Head);
        var staged = await new GroupMessageFanoutService(
            stagingGroups, new Msg01GroupMessageLogicalOutbox(messages.Store))
            .StageAsync(initial.BatchId, initial.Message);
        var prepared = Assert.IsType<LogicalOutboxSnapshot>(staged.LogicalOutbox);
        var active = await ActivateFirstAttemptAsync(messages.Store, prepared, 817);
        var capturing = new CapturingMessageStore(messages.Store) { HoldLocalBlock = true };

        var block = new GroupMessageDispatchSafetyService(groups).DispatchFirstAsync(
            active,
            Assert.Single(active.Targets),
            capturing,
            messages.GroupDispatchSafety,
            active.CreatedAt.AddSeconds(1),
            (_, _) => ValueTask.FromException(
                new InvalidOperationException("Blocked dispatch callback must not run.")),
            CancellationToken.None).AsTask();
        await capturing.LocalBlockEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var changeHead = groups.ReplaceAsync(initial.Head, CancellationToken.None).AsTask();
        await Task.Delay(75);
        Assert.False(changeHead.IsCompleted);
        capturing.ReleaseLocalBlock.TrySetResult();

        var decision = await block.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(GroupMessageFirstDispatchDisposition.TargetRemoved, decision.Disposition);
        await changeHead.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static async Task<LogicalOutboxSnapshot> ActivateFirstAttemptAsync(
        IMessageTransactionStore store,
        LogicalOutboxSnapshot outbox,
        int marker)
    {
        var target = Assert.Single(outbox.Targets);
        var ciphertext = outbox.CanonicalPayload;
        try
        {
            var attempt = TransportAttemptId16.FromBytes(Hash("attempt", marker, 9)[..16]);
            var result = await store.ApplyAsync(
                PreparedMessageMutation.StartSending(
                    outbox,
                    MessageMutationId32.FromBytes(Hash("start", marker, 9)),
                    [new TargetAttemptPlan(
                        target.Target,
                        attempt,
                        TransportRequestHash32.FromBytes(SHA256.HashData(ciphertext)),
                        RatchetStateHash32.FromBytes(Hash("before", marker, 9)),
                        RatchetTransitionHash32.FromBytes(Hash("after", marker, 9)),
                        target.DirectoryHeadHash,
                        target.OperationId!,
                        target.BindingHash!,
                        ciphertext)],
                    outbox.CreatedAt.AddMilliseconds(1)),
                CancellationToken.None);
            Assert.Equal(MessageCommitResult.Applied, result.CommitResult);
            return Assert.IsType<LogicalOutboxSnapshot>(result.Snapshot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private static LogicalOutboxSnapshot CopyOutbox(
        LogicalOutboxSnapshot source,
        ReadOnlySpan<byte> canonical,
        MessageEventHash32 eventHash,
        ulong revision) => new(
            source.StoreScope,
            source.ClaimKey,
            source.AuthorDeviceId,
            eventHash,
            canonical,
            source.CreatedAt,
            source.ExpiresAt,
            source.State,
            revision,
            source.Targets,
            payloadKind: source.PayloadKind);

    private static Msg01AuthoritativeTransport CreateTransport(
        AuthenticatedEvidenceSource source,
        IGroupStateStore groups)
    {
        var owner = MessagingV1RuntimeOwner.CreatePersistent(
            Path.Combine(Path.GetTempPath(), $"deep-msg01-group-owner-{Guid.NewGuid():N}.db"),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            source.EvidenceAuthority);
        return new Msg01AuthoritativeTransport(
            source,
            null,
            source,
            owner,
            new FrozenClock(MessagingV1Fixture.CreatedAt.AddSeconds(1)),
            ownsTransport: false,
            new GroupMessageDispatchSafetyService(groups));
    }

    private static FixtureData Fixture(
        int marker,
        bool includeRemote,
        ulong epoch = 0,
        byte[]? predecessorHash = null)
    {
        var identity = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Hash("identity-network", marker, 0)[..16]),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Hash("identity", marker, 0)));
        var scope = GroupStoreScope.ForCurrentAccount(
            identity.AccountId, identity.AccountGeneration);
        var network = Hash("network", marker, 0)[..16];
        var group = Hash("group", marker, 0);
        var ownerAccount = identity.AccountId.Bytes.ToArray();
        var ownerDevice = Device(marker, 0, 0).ToArray();
        var rows = new List<(byte[] Account, byte[] Row)>
        {
            (ownerAccount, Member(ownerAccount, 1, scope.AccountGeneration,
                Hash("directory", marker, 0), [ownerDevice], marker, 0)),
        };
        if (includeRemote)
        {
            var remoteAccount = Hash("account", marker, 1);
            rows.Add((remoteAccount, Member(remoteAccount, 3, 1,
                Hash("directory", marker, 1), [Device(marker, 1, 0).ToArray()], marker, 1)));
        }
        var members = rows.OrderBy(static row => row.Account, ByteArrayComparer.Instance)
            .SelectMany(static row => row.Row).ToArray();
        var commit = Assert.IsType<GroupCommitRecord>(Record("DGC1",
        [
            network, group, U16(1), U64(epoch), predecessorHash ?? new byte[32],
            ownerAccount, ownerDevice, Ref("DPD1", Hash("owner-dpd", marker, 0)),
            U16(0), [], U16(checked((ushort)rows.Count)), members,
            "group"u8.ToArray(), [0], U32(3600), U64(epoch + 1),
            Hash("signature", marker, 0).Concat(Hash("signature", marker, 1)).ToArray(),
        ]));
        var package = Assert.IsType<GroupCommitPackageRecord>(Record("GCP1",
        [
            network, group, U64(epoch), Lp(commit.CanonicalBytes.Span),
            U16(0), [], U32(0), [], U16(0), [], [],
        ]));
        var head = new GroupHeadSnapshot(
            GroupId32.FromBytes(group), network, epoch, epoch + 1,
            commit.ArtifactHash.Span, package.ArtifactHash.Span,
            predecessorHash ?? new byte[32], commit.CanonicalBytes.Span,
            package.CanonicalBytes.Span, SHA256.HashData(package.CanonicalBytes.Span),
            checked((ushort)rows.Count), checked((ushort)rows.Count), false, [], []);
        var semantic = Hash("semantic", marker, 0);
        var message = Assert.IsType<GroupApplicationMessageRecord>(Record("DGM1",
        [
            network, group, U64(epoch), head.CommitHash.ToArray(), semantic,
            ownerAccount, ownerDevice, U64(1),
            U64((ulong)MessagingV1Fixture.CreatedAt.ToUnixTimeMilliseconds()),
            U64((ulong)MessagingV1Fixture.CreatedAt.AddDays(7).ToUnixTimeMilliseconds()),
            U16(1), "hello"u8.ToArray(),
        ]));
        return new FixtureData(
            scope,
            head,
            GroupFanoutBatchId32.FromBytes(Hash("batch", marker, (int)epoch)),
            message,
            new MessageStoreScope(
                MessagingAccountId32.FromBytes(ownerAccount),
                scope.AccountGeneration,
                MessageStoreInstanceId32.FromBytes(Hash("message-store", marker, 0))));
    }

    private static GroupHeadSnapshot Forked(GroupHeadSnapshot head) => new(
        head.GroupId, head.NetworkId.Span, head.Epoch, head.Revision,
        head.CommitHash.Span, head.PackageHash.Span, head.PredecessorHash.Span,
        head.ExactCanonicalCommit.Span, head.ExactCanonicalPackage.Span,
        head.ExactVerifiedGcp1Sha256.Span, head.MemberCount, head.DeviceCount,
        true, head.Artifacts, head.ControlCursors);

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
        var bytes = new byte[12 + fields.Sum(static field => 8 + field.Length)];
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
    private static byte[] Lp(ReadOnlySpan<byte> value) =>
        U32(checked((uint)value.Length)).Concat(value.ToArray()).ToArray();
    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }
    private static byte[] U32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }
    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private sealed record FixtureData(
        GroupStoreScope Scope,
        GroupHeadSnapshot Head,
        GroupFanoutBatchId32 BatchId,
        GroupApplicationMessageRecord Message,
        MessageStoreScope MessageScope);

    private sealed class CapturingMessageStore(IMessageTransactionStore inner)
        : IMessageTransactionStore
    {
        internal PreparedMessageMutation? LocalBlock { get; private set; }
        internal bool HoldLocalBlock { get; init; }
        internal TaskCompletionSource LocalBlockEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReleaseLocalBlock { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public MessageStoreScope Scope => inner.Scope;
        public IMessageVerifiedTransportHandoff ClaimVerifiedTransportHandoff() =>
            inner.ClaimVerifiedTransportHandoff();
        public IMessageGroupDispatchSafetyHandoff ClaimGroupDispatchSafetyHandoff() =>
            inner.ClaimGroupDispatchSafetyHandoff();
        public ValueTask<SemanticClaimResult> ClaimSemanticAsync(
            SemanticClaimCandidate claim, CancellationToken cancellationToken) =>
            inner.ClaimSemanticAsync(claim, cancellationToken);
        public ValueTask<BeginMessageResult> BeginOutboundAsync(
            MessageMutationId32 operationId, SemanticClaimCandidate claim,
            LogicalOutboxSeed seed, CancellationToken cancellationToken) =>
            inner.BeginOutboundAsync(operationId, claim, seed, cancellationToken);
        public async ValueTask<ApplyMessageResult> ApplyAsync(
            PreparedMessageMutation plan, CancellationToken cancellationToken)
        {
            if (plan.Kind == MessageMutationKind.LocalGroupDispatchBlock)
            {
                LocalBlock = plan;
                LocalBlockEntered.TrySetResult();
                if (HoldLocalBlock)
                    await ReleaseLocalBlock.Task.WaitAsync(cancellationToken);
            }
            return await inner.ApplyAsync(plan, cancellationToken);
        }
        public ValueTask<LogicalOutboxSnapshot?> ReadAsync(
            SemanticClaimKey claimKey, CancellationToken cancellationToken) =>
            inner.ReadAsync(claimKey, cancellationToken);
        public ValueTask<InboxEventSnapshot?> ReadInboxAsync(
            SemanticClaimKey claimKey, CancellationToken cancellationToken) =>
            inner.ReadInboxAsync(claimKey, cancellationToken);
        public ValueTask<MessageRatchetSnapshot?> ReadRatchetAsync(
            RatchetSessionId32 sessionId, CancellationToken cancellationToken) =>
            inner.ReadRatchetAsync(sessionId, cancellationToken);
        public ValueTask<InboxEventSnapshot?> MaterializeInboundAsync(
            InboxMaterializationRequest request, CancellationToken cancellationToken) =>
            inner.MaterializeInboundAsync(request, cancellationToken);
        public ValueTask<IReadOnlyList<MessageStoreRecoveryItem>> ClaimRecoveryAsync(
            MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems,
            CancellationToken cancellationToken) =>
            inner.ClaimRecoveryAsync(owner, now, maxItems, cancellationToken);
        public ValueTask<IReadOnlyList<PendingMessageReceipt>> ClaimPendingReceiptsAsync(
            MessageRecoveryOwnerId16 owner, DateTimeOffset now, int maxItems,
            CancellationToken cancellationToken) =>
            inner.ClaimPendingReceiptsAsync(owner, now, maxItems, cancellationToken);
        public ValueTask<PendingMessageReceipt?> ClaimPendingReceiptAsync(
            MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner,
            DateTimeOffset now, CancellationToken cancellationToken) =>
            inner.ClaimPendingReceiptAsync(receiptId, owner, now, cancellationToken);
        public ValueTask<MessageCommitResult> CompletePendingReceiptAsync(
            MessageReceiptId32 receiptId, MessageRecoveryOwnerId16 owner,
            DateTimeOffset completedAt, CancellationToken cancellationToken) =>
            inner.CompletePendingReceiptAsync(receiptId, owner, completedAt, cancellationToken);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class MutableGroupStateStore(
        GroupStoreScope scope,
        GroupHeadSnapshot initial) : IGroupStateStore
    {
        private readonly SemaphoreSlim gate = new(1, 1);
        private GroupHeadSnapshot? current = initial.Copy();
        private int leaseAcquisitions;

        public GroupStoreScope Scope { get; } = scope;
        internal int LeaseAcquisitions => Volatile.Read(ref leaseAcquisitions);

        public async ValueTask<GroupHeadSnapshot?> ReadHeadAsync(
            GroupId32 groupId,
            CancellationToken cancellationToken = default)
        {
            await gate.WaitAsync(cancellationToken);
            try { return current?.GroupId.Equals(groupId) == true ? current.Copy() : null; }
            finally { gate.Release(); }
        }

        public async ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadHeadsAsync(
            CancellationToken cancellationToken = default)
        {
            await gate.WaitAsync(cancellationToken);
            try { return current is null ? [] : [current.Copy()]; }
            finally { gate.Release(); }
        }

        public async ValueTask<GroupHeadReadLease> AcquireHeadReadLeaseAsync(
            GroupId32 groupId,
            CancellationToken cancellationToken = default)
        {
            await gate.WaitAsync(cancellationToken);
            Interlocked.Increment(ref leaseAcquisitions);
            return new GroupHeadReadLease(
                current?.GroupId.Equals(groupId) == true ? current : null,
                () => gate.Release());
        }

        public ValueTask<GroupCommitResult> CommitVerifiedTransitionAsync(
            GroupTransitionCommitPlan plan,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<GroupCommitResult>(new NotSupportedException());

        internal async ValueTask ReplaceAsync(
            GroupHeadSnapshot? replacement,
            CancellationToken cancellationToken)
        {
            await gate.WaitAsync(cancellationToken);
            try { current = replacement?.Copy(); }
            finally { gate.Release(); }
        }
    }

    private sealed class AuthenticatedEvidenceSource(
        IReadOnlyList<LogicalTargetSnapshot> targets) : ISessionMessageTransport,
        IMsg01AuthenticatedEvidenceSource
    {
        private readonly Dictionary<RecipientDeviceTarget, DirectoryHeadHash32> directories =
            targets.ToDictionary(
                static target => target.Target,
                static target => target.DirectoryHeadHash);
        private long replayCounter;
        private int dispatchCount;
        private int reconcileCount;

        internal Func<CancellationToken, ValueTask>? AfterPrepare { get; init; }
        internal Func<Msg01DispatchEvidenceRequest, CancellationToken, ValueTask>?
            BeforeDispatch { get; init; }
        internal bool HoldDispatch { get; init; }
        internal int DispatchCount => Volatile.Read(ref dispatchCount);
        internal int ReconcileCount => Volatile.Read(ref reconcileCount);
        internal TaskCompletionSource DispatchEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReleaseDispatch { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Msg01VerifiedSessionAuthority EvidenceAuthority { get; } =
            MessagingV1Fixture.CreateEvidenceAuthority();

        public ValueTask<SessionId> GetLocalAccountAsync(CancellationToken cancellationToken) =>
            ValueTask.FromException<SessionId>(new NotSupportedException());

        public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
            Msg01ResolveFanoutTargetRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(directories[request.Target]);

        public async ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
            Msg01PrepareAttemptRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ciphertext = request.CanonicalPayload.ToArray();
            var attemptId = request.AttemptId.ToArray();
            try
            {
                if (AfterPrepare is not null)
                    await AfterPrepare(cancellationToken);
                return new Msg01PreparedTransportAttempt(
                    directories[request.Target],
                    RatchetStateHash32.FromBytes(Hash("ratchet-before", 1, 1)),
                    RatchetTransitionHash32.FromBytes(SHA256.HashData(attemptId)),
                    ciphertext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(attemptId);
            }
        }

        public async ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
            Msg01DispatchEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            if (BeforeDispatch is not null)
                await BeforeDispatch(request, cancellationToken);
            Interlocked.Increment(ref dispatchCount);
            DispatchEntered.TrySetResult();
            if (HoldDispatch)
                await ReleaseDispatch.Task.WaitAsync(cancellationToken);
            return Authenticate(
                request, MessageEvidencePurpose.TargetOutcome,
                VerifiedTargetOutcomeKind.Accepted);
        }

        public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
            Msg01DispatchEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref reconcileCount);
            return ValueTask.FromResult(Authenticate(
                request, MessageEvidencePurpose.AttemptReconciliation,
                VerifiedTargetOutcomeKind.NotAccepted));
        }

        public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
            Msg01InboundEvidenceRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<Msg01AuthenticatedInboundResult>(new NotSupportedException());

        public ValueTask AcknowledgeReceiptAsync(
            ReadOnlyMemory<byte> authenticatedReceipt,
            CancellationToken cancellationToken) =>
            ValueTask.FromException(new NotSupportedException());

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        private Msg01AuthenticatedDispatchResult Authenticate(
            Msg01DispatchEvidenceRequest request,
            MessageEvidencePurpose purpose,
            VerifiedTargetOutcomeKind outcome)
        {
            var replay = checked((ulong)Interlocked.Increment(ref replayCounter));
            var nonce = Hash("replay", checked((int)replay), 1);
            var context = new MessageCapabilityTrustedContext(
                purpose,
                request.Scope,
                request.ClaimKey,
                request.Target,
                request.AttemptId,
                outcome,
                targetOperationId: request.OperationId,
                bindingHash: request.BindingHash,
                requestHash: request.RequestHash.ToArray(),
                envelopeHash: request.EnvelopeHash.ToArray(),
                ratchetBeforeHash: request.RatchetBeforeHash.ToArray(),
                ratchetAfterHash: request.RatchetAfterHash.ToArray(),
                replayCounter: replay,
                replayNonce: nonce);
            var ciphertext = request.Ciphertext.ToArray();
            try
            {
                var canonicalEvidence = SHA256.HashData(ciphertext);
                return new Msg01AuthenticatedDispatchResult(
                    outcome,
                    outcomeUnknown: false,
                    replay,
                    nonce,
                    MessagingV1Fixture.Authenticate(context, canonicalEvidence));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
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
