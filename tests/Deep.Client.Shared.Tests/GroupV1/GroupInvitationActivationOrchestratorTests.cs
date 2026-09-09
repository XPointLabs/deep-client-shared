using System.Buffers.Binary;
using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.GroupV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;
using Sodium;

namespace Deep.Client.Shared.Tests.GroupV1;

public sealed class GroupInvitationActivationOrchestratorTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(), "deep-group-activation-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] key = Fill(0xc1, 32);

    public GroupInvitationActivationOrchestratorTests() => Directory.CreateDirectory(directory);

    [Fact]
    public async Task CrashAfterDurableStage_ReopensBeforeFirstNetworkWrite()
    {
        var fixture = Fixture.Create();
        await fixture.CommitGenesisAsync(StatePath(), key);
        var transport = new SignedTransport(fixture);

        using (var journalOptions = JournalOptions(fixture.Scope))
        using (var journal = new SqliteGroupInvitationActivationStore(journalOptions))
        using (var stateOptions = StateOptions(fixture.Scope, allowCreate: false))
        using (var state = new SqliteGroupStateStore(stateOptions))
        {
            var crash = new OneShotFailpoint(GroupInvitationActivationFailpoint.AfterStage);
            await Assert.ThrowsAsync<InjectedCrashException>(() =>
                new GroupInvitationActivationOrchestrator(journal, state, transport, crash)
                    .RunAsync(fixture.Plan).AsTask());
            var staged = await journal.ReadAsync(fixture.Plan.ActivationId);
            Assert.Equal(GroupInvitationActivationJournalState.Sending, staged!.State);
            Assert.Equal(0, staged.NetworkAttemptCount);
            Assert.Empty(transport.OperationIds);
        }

        using var reopenedJournalOptions = JournalOptions(fixture.Scope, allowCreate: false);
        using var reopenedJournal = new SqliteGroupInvitationActivationStore(reopenedJournalOptions);
        using var reopenedStateOptions = StateOptions(fixture.Scope, allowCreate: false);
        using var reopenedState = new SqliteGroupStateStore(reopenedStateOptions);
        var resumed = await new GroupInvitationActivationOrchestrator(
            reopenedJournal, reopenedState, transport).RunAsync(fixture.Plan);

        Assert.Equal(GroupInvitationActivationDisposition.Activated, resumed.Disposition);
        Assert.Equal(GroupInvitationActivationJournalState.Committed, resumed.Journal.State);
        Assert.Single(transport.OperationIds);
    }

    [Fact]
    public async Task CrashAfterVerifiedGssBeforeAck_ReopensAndRetriesSameExactOperation()
    {
        var fixture = Fixture.Create();
        await fixture.CommitGenesisAsync(StatePath(), key);
        var transport = new SignedTransport(fixture);

        using (var journalOptions = JournalOptions(fixture.Scope))
        using (var journal = new SqliteGroupInvitationActivationStore(journalOptions))
        using (var stateOptions = StateOptions(fixture.Scope, allowCreate: false))
        using (var state = new SqliteGroupStateStore(stateOptions))
        {
            var crash = new OneShotFailpoint(GroupInvitationActivationFailpoint.AfterVerifiedControlBeforeAck);
            var orchestrator = new GroupInvitationActivationOrchestrator(journal, state, transport, crash);
            await Assert.ThrowsAsync<InjectedCrashException>(() =>
                orchestrator.RunAsync(fixture.Plan).AsTask());
            var staged = await journal.ReadAsync(fixture.Plan.ActivationId);
            Assert.Equal(GroupInvitationActivationJournalState.Sending, staged!.State);
            Assert.Equal(1, staged.NetworkAttemptCount);
        }

        using (var journalOptions = JournalOptions(fixture.Scope, allowCreate: false))
        using (var journal = new SqliteGroupInvitationActivationStore(journalOptions))
        using (var stateOptions = StateOptions(fixture.Scope, allowCreate: false))
        using (var state = new SqliteGroupStateStore(stateOptions))
        {
            var result = await new GroupInvitationActivationOrchestrator(journal, state, transport)
                .RunAsync(fixture.Plan);
            Assert.Equal(GroupInvitationActivationDisposition.Activated, result.Disposition);
            Assert.Equal(GroupInvitationActivationJournalState.Committed, result.Journal.State);
            Assert.Equal(2, result.Journal.NetworkAttemptCount);
            Assert.Equal(2, transport.OperationIds.Count);
            Assert.All(transport.OperationIds, operation =>
                Assert.Equal(fixture.Request.OperationId.ToArray(), operation));
            Assert.Contains(result.StateCommit!.Head!.Artifacts, artifact => artifact.Magic == "GIV1");
            Assert.Contains(result.StateCommit.Head.Artifacts, artifact => artifact.Magic == "GIA1");
        }
    }

    [Fact]
    public async Task CrashAfterStateCommit_ResumesAsIdempotentWithoutAnotherNetworkWrite()
    {
        var fixture = Fixture.Create();
        await fixture.CommitGenesisAsync(StatePath(), key);
        var transport = new SignedTransport(fixture);
        using (var journalOptions = JournalOptions(fixture.Scope))
        using (var journal = new SqliteGroupInvitationActivationStore(journalOptions))
        using (var stateOptions = StateOptions(fixture.Scope, allowCreate: false))
        using (var state = new SqliteGroupStateStore(stateOptions))
        {
            var failpoint = new OneShotFailpoint(GroupInvitationActivationFailpoint.AfterStateCommitBeforeJournalCommit);
            await Assert.ThrowsAsync<InjectedCrashException>(() =>
                new GroupInvitationActivationOrchestrator(journal, state, transport, failpoint)
                    .RunAsync(fixture.Plan).AsTask());
            Assert.Equal(GroupInvitationActivationJournalState.ReadyToCommit,
                (await journal.ReadAsync(fixture.Plan.ActivationId))!.State);
            Assert.Equal((ulong)2, (await state.ReadHeadAsync(fixture.Plan.GroupId))!.Revision);
        }

        using (var journalOptions = JournalOptions(fixture.Scope, allowCreate: false))
        using (var journal = new SqliteGroupInvitationActivationStore(journalOptions))
        using (var stateOptions = StateOptions(fixture.Scope, allowCreate: false))
        using (var state = new SqliteGroupStateStore(stateOptions))
        {
            var resumed = await new GroupInvitationActivationOrchestrator(journal, state, transport)
                .RunAsync(fixture.Plan);
            Assert.Equal(GroupInvitationActivationDisposition.Idempotent, resumed.Disposition);
            Assert.Equal(GroupInvitationActivationJournalState.Committed, resumed.Journal.State);
            Assert.Single(transport.OperationIds);
        }
    }

    [Fact]
    public async Task ForeignOperationGss1CannotAdvanceJournalOrGroupState()
    {
        var fixture = Fixture.Create();
        await fixture.CommitGenesisAsync(StatePath(), key);
        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        using var stateOptions = StateOptions(fixture.Scope, allowCreate: false);
        using var state = new SqliteGroupStateStore(stateOptions);

        await Assert.ThrowsAsync<GroupControlClientException>(() =>
            new GroupInvitationActivationOrchestrator(journal, state, new ForeignResultTransport(fixture))
                .RunAsync(fixture.Plan).AsTask());

        var snapshot = await journal.ReadAsync(fixture.Plan.ActivationId);
        Assert.Equal(GroupInvitationActivationJournalState.Sending, snapshot!.State);
        Assert.Equal(0, snapshot.AcceptedControlCount);
        Assert.Equal((ulong)1, (await state.ReadHeadAsync(fixture.Plan.GroupId))!.Revision);
    }

    [Fact]
    public async Task ExactReplayIsTerminalAndChangedPlanPermanentlyConflictLatches()
    {
        var fixture = Fixture.Create();
        await fixture.CommitGenesisAsync(StatePath(), key);
        var transport = new SignedTransport(fixture);
        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        using var stateOptions = StateOptions(fixture.Scope, allowCreate: false);
        using var state = new SqliteGroupStateStore(stateOptions);
        var orchestrator = new GroupInvitationActivationOrchestrator(journal, state, transport);

        Assert.Equal(GroupInvitationActivationDisposition.Activated,
            (await orchestrator.RunAsync(fixture.Plan)).Disposition);
        Assert.Equal(GroupInvitationActivationDisposition.Idempotent,
            (await orchestrator.RunAsync(fixture.Plan)).Disposition);
        Assert.Single(transport.OperationIds);

        var changed = fixture.PlanWithDifferentControlOperation();
        var conflict = await journal.StageAsync(changed);
        Assert.Equal(GroupInvitationActivationStageDisposition.ConflictLatched, conflict.Disposition);
        Assert.Equal(GroupInvitationActivationJournalState.ConflictLatched, conflict.Snapshot.State);
        Assert.Equal(GroupInvitationActivationStageDisposition.ConflictLatched,
            (await journal.StageAsync(fixture.Plan)).Disposition);
    }

    [Fact]
    public async Task OutOfOrderActivationNeverCreatesAGroupHead()
    {
        var fixture = Fixture.Create();
        var transport = new SignedTransport(fixture);
        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        using var stateOptions = StateOptions(fixture.Scope);
        using var state = new SqliteGroupStateStore(stateOptions);

        var result = await new GroupInvitationActivationOrchestrator(journal, state, transport)
            .RunAsync(fixture.Plan);
        Assert.Equal(GroupInvitationActivationDisposition.OutOfOrder, result.Disposition);
        Assert.Null(result.StateCommit);
        Assert.Empty(transport.OperationIds);
        Assert.Null(await state.ReadHeadAsync(fixture.Plan.GroupId));
        Assert.Equal(GroupInvitationActivationJournalState.Sending, result.Journal.State);
    }

    [Fact]
    public async Task MemberRemovedOrSiblingHead_ForkLatchesInsteadOfActivatingAcceptance()
    {
        var fixture = Fixture.Create();
        using var stateOptions = StateOptions(fixture.Scope);
        using var state = new SqliteGroupStateStore(stateOptions);
        await fixture.CommitGenesisAsync(state);
        await state.CommitVerifiedTransitionAsync(fixture.SiblingPlan());

        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        var transport = new SignedTransport(fixture);
        var result = await new GroupInvitationActivationOrchestrator(
            journal, state, transport).RunAsync(fixture.Plan);

        Assert.Equal(GroupInvitationActivationDisposition.ConflictLatched, result.Disposition);
        Assert.Equal(GroupCommitDisposition.ForkLatched, result.StateCommit!.Disposition);
        Assert.Equal(GroupInvitationActivationJournalState.ConflictLatched, result.Journal.State);
        var head = await state.ReadHeadAsync(fixture.Plan.GroupId);
        Assert.True(head!.ForkLatched);
        Assert.DoesNotContain(head.Artifacts, artifact => artifact.Magic is "GIV1" or "GIA1");
        Assert.Empty(transport.OperationIds);
    }

    [Fact]
    public async Task AccountRuntimeActivationUsesDurableOutboxAndConfiguredGroupControlTransport()
    {
        var fixture = Fixture.Create();
        using var stateOptions = StateOptions(fixture.Scope);
        using var state = new SqliteGroupStateStore(stateOptions);
        await fixture.CommitGenesisAsync(state);
        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        var transport = new SignedTransport(fixture);
        var device = LocalDevice();
        IDeepGroupV1Runtime runtime = new DeepGroupV1Runtime(
            fixture.Scope.AccountId, device, new RuntimeSigner(device), state, transport, journal);

        var activated = await runtime.ActivateInvitationAsync(fixture.Plan);

        Assert.Equal(GroupInvitationActivationDisposition.Activated, activated.Disposition);
        Assert.Equal(GroupInvitationActivationJournalState.Committed, activated.Journal.State);
        Assert.Single(transport.OperationIds);
        Assert.Contains(activated.StateCommit!.Head!.Artifacts, artifact => artifact.Magic == "GIV1");
        Assert.Contains(activated.StateCommit.Head.Artifacts, artifact => artifact.Magic == "GIA1");
    }

    [Fact]
    public async Task DurableActivationTraversesConcretePrivacyRoutedGroupControlTransport()
    {
        var fixture = Fixture.Create();
        using var stateOptions = StateOptions(fixture.Scope);
        using var state = new SqliteGroupStateStore(stateOptions);
        await fixture.CommitGenesisAsync(state);
        var journal = new InMemoryGroupInvitationActivationStore(fixture.Scope);
        var primaryId = Fill(0xd1, 32);
        var primary = new CountingPrivacyIngress();
        var codec = new ActivationPrivacyCodec(fixture.SignedResult(fixture.Request));
        using var transport = new PrivacyRoutedGroupControlTransport(
            new GroupControlIngressRoute(new Uri("https://group-primary.example/"), primaryId),
            new GroupControlIngressRoute(new Uri("https://group-fallback.example/"), Fill(0xd2, 32)),
            new FixedGroupControlPathProvider(primaryId),
            codec,
            primary,
            new NeverPrivacyIngress());
        var device = LocalDevice();
        IDeepGroupV1Runtime runtime = new DeepGroupV1Runtime(
            fixture.Scope.AccountId, device, new RuntimeSigner(device), state, transport, journal);

        var activated = await runtime.ActivateInvitationAsync(fixture.Plan);

        Assert.Equal(GroupInvitationActivationDisposition.Activated, activated.Disposition);
        Assert.Equal(GroupControlResultStatus.Committed, activated.LastControlStatus);
        Assert.Equal(1, primary.CallCount);
        Assert.Equal(1, codec.OpenCount);
    }

    [Fact]
    public async Task GenericRuntimeApplyCannotBypassInvitationOutbox()
    {
        var fixture = Fixture.Create();
        using var stateOptions = StateOptions(fixture.Scope);
        using var state = new SqliteGroupStateStore(stateOptions);
        await fixture.CommitGenesisAsync(state);
        var device = LocalDevice();
        IDeepGroupV1Runtime runtime = new DeepGroupV1Runtime(
            fixture.Scope.AccountId, device, new RuntimeSigner(device), state);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            runtime.ApplyVerifiedTransitionAsync(
                fixture.Plan.ActivationId, 1, fixture.Authored).AsTask());

        Assert.Contains("durable activation outbox", error.Message, StringComparison.Ordinal);
        Assert.Equal((ulong)1, (await state.ReadHeadAsync(fixture.Plan.GroupId))!.Revision);
        Assert.DoesNotContain((await state.ReadHeadAsync(fixture.Plan.GroupId))!.Artifacts,
            artifact => artifact.Magic is "GIV1" or "GIA1");
    }

    [Fact]
    public void PublicRuntimeSeparatesActivationAuthoringFromDurableCommit()
    {
        Assert.Null(typeof(IDeepGroupV1Runtime).GetMethod("CommitActivationAsync"));
        Assert.NotNull(typeof(IDeepGroupV1Runtime).GetMethod("AuthorActivationCommitAsync"));
        Assert.NotNull(typeof(IDeepGroupV1Runtime).GetMethod("ActivateInvitationAsync"));
    }

    [Fact]
    public void DeviceDispatchBoundaryIsNarrowAndHasNoProductionFake()
    {
        var method = Assert.Single(typeof(IGroupMessageDeviceDispatcher).GetMethods());
        Assert.Equal(nameof(IGroupMessageDeviceDispatcher.DispatchAsync), method.Name);
        Assert.Equal(typeof(ValueTask), method.ReturnType);
        Assert.Equal(typeof(GroupMessageFirstDispatchContext), method.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(typeof(IGroupMessageDeviceDispatcher).Assembly.GetTypes(), type =>
            type.IsClass && !type.IsAbstract && typeof(IGroupMessageDeviceDispatcher).IsAssignableFrom(type));
    }

    private SqliteGroupInvitationActivationStoreOptions JournalOptions(
        GroupStoreScope scope,
        bool allowCreate = true) =>
        new(Path.Combine(directory, "activation.giaj"), key, scope, allowCreate);

    private SqliteGroupStateStoreOptions StateOptions(GroupStoreScope scope, bool allowCreate = true) =>
        new(StatePath(), key, scope, allowCreate);

    private string StatePath() => Path.Combine(directory, "groups.dgv1");

    public void Dispose()
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed class SignedTransport(Fixture fixture) : IDeepGroupControlTransport
    {
        internal List<byte[]> OperationIds { get; } = [];

        public ValueTask<ReadOnlyMemory<byte>> ExecuteAsync(
            VerifiedGroupControlRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OperationIds.Add(request.OperationId.ToArray());
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                fixture.SignedResult((VerifiedGroupControlWriteRequest)request));
        }
    }

    private sealed class ForeignResultTransport(Fixture fixture) : IDeepGroupControlTransport
    {
        public ValueTask<ReadOnlyMemory<byte>> ExecuteAsync(
            VerifiedGroupControlRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(fixture.ForeignSignedResult());
        }
    }

    private sealed class OneShotFailpoint(GroupInvitationActivationFailpoint target)
        : IGroupInvitationActivationFailpoint
    {
        private int fired;
        public ValueTask HitAsync(GroupInvitationActivationFailpoint point, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (point == target && Interlocked.Exchange(ref fired, 1) == 0)
                throw new InjectedCrashException();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InjectedCrashException : Exception;

    private sealed class Fixture
    {
        private readonly IReadOnlyDictionary<string, KeyPair> replicaKeys;

        private Fixture(
            GroupStoreScope scope,
            GroupTransitionCommitPlan genesisPlan,
            GroupInvitationActivationPlan plan,
            GroupTransitionCommitPlan siblingPlan,
            VerifiedGroupControlWriteRequest request,
            VerifiedGroupInvitation invitation,
            VerifiedGroupInvitationAcceptance acceptance,
            VerifiedAuthoredGroupTransition authored,
            GroupCommitChunkRecord[] chunks,
            VerifiedGroupControlPlacement placement,
            IReadOnlyDictionary<string, KeyPair> replicaKeys)
        {
            Scope = scope; GenesisPlan = genesisPlan; Plan = plan; this.siblingPlan = siblingPlan;
            Request = request; Invitation = invitation; Acceptance = acceptance; Authored = authored;
            Chunks = chunks; Placement = placement; this.replicaKeys = replicaKeys;
        }

        private readonly GroupTransitionCommitPlan siblingPlan;
        internal GroupStoreScope Scope { get; }
        internal GroupTransitionCommitPlan GenesisPlan { get; }
        internal GroupInvitationActivationPlan Plan { get; }
        internal VerifiedGroupControlWriteRequest Request { get; }
        internal VerifiedGroupInvitation Invitation { get; }
        internal VerifiedGroupInvitationAcceptance Acceptance { get; }
        internal VerifiedAuthoredGroupTransition Authored { get; }
        internal GroupCommitChunkRecord[] Chunks { get; }
        internal VerifiedGroupControlPlacement Placement { get; }

        internal static Fixture Create()
        {
            var scope = ScopeForTest();
            var stateService = new GroupClientStateService();
            var genesis = TransitionFixture.Genesis();
            var activation = TransitionFixture.SuccessorWithInvite(genesis.Commit, "activated");
            var sibling = TransitionFixture.SuccessorWithoutInvite(genesis.Commit, "member-removed");
            var genesisPlan = stateService.PrepareVerifiedTransition(
                scope, Operation(1), null, genesis.Transition, genesis.Package, TransitionFixture.Chunks(genesis.Package));
            var siblingPlan = stateService.PrepareVerifiedTransition(
                scope, Operation(3), 1, sibling.Transition, sibling.Package, TransitionFixture.Chunks(sibling.Package));
            var invitation = BuildInvitation(activation.Invitation, genesis.Transition);
            var acceptance = BuildAcceptance(activation.Acceptance, invitation);
            var authored = BuildAuthored(activation.Package, activation.Transition);
            var chunks = TransitionFixture.Chunks(activation.Package);
            var control = ControlCapability.Create(genesis.Transition, chunks[0], Fill(0x91, 32));
            var plan = new GroupInvitationActivationPlanner().Prepare(
                scope, Operation(2), 1, invitation, acceptance, authored, chunks, [control.Request]);
            return new Fixture(scope, genesisPlan, plan, siblingPlan, control.Request,
                invitation, acceptance, authored, chunks, control.Placement, control.ReplicaKeys);
        }

        internal async Task CommitGenesisAsync(string path, byte[] encryptionKey)
        {
            using var options = new SqliteGroupStateStoreOptions(path, encryptionKey, Scope);
            using var store = new SqliteGroupStateStore(options);
            await CommitGenesisAsync(store);
        }

        internal async Task CommitGenesisAsync(IGroupStateStore store)
        {
            var result = await store.CommitVerifiedTransitionAsync(GenesisPlan);
            Assert.Equal(GroupCommitDisposition.Applied, result.Disposition);
        }

        internal GroupTransitionCommitPlan SiblingPlan() => siblingPlan;

        internal GroupInvitationActivationPlan PlanWithDifferentControlOperation()
        {
            var changed = ControlCapability.Create(
                Invitation.BaseState, Chunks[0], Fill(0x92, 32), Placement, replicaKeys);
            return new GroupInvitationActivationPlanner().Prepare(
                Scope, Plan.ActivationId, 1, Invitation, Acceptance, Authored, Chunks, [changed.Request]);
        }

        internal byte[] SignedResult(VerifiedGroupControlWriteRequest request)
        {
            var requestHash = DomainHash(
                "Deep/ContactResolver/V1/request", request.CanonicalBytes.Span);
            var generation = U64(1);
            var tuple = Join(requestHash, request.Record.Field(18).ToArray(),
                request.Record.Field(20).ToArray(), generation);
            var signingInput = SignatureInput("Deep/Group/V1/control-store-commit", tuple);
            var receipts = request.Placement.ReplicaNodeIds
                .OrderBy(static value => value, MemoryComparer.Instance)
                .Select(nodeId => Join(nodeId.ToArray(), PublicKeyAuth.SignDetached(
                    signingInput, replicaKeys[Convert.ToHexString(nodeId.Span)].PrivateKey)))
                .ToArray();
            return TaggedRecord("GSS1", [1,2,3,4,5,6,7,8,16,17,18,19,20],
                [request.Record.Field(1), request.Record.Field(2), requestHash, U16(1), new byte[]{1},
                 U64(30), U32(0), U16(4), new byte[]{1}, request.Record.Field(18),
                 request.Record.Field(20), generation, Join(receipts)]);
        }

        internal byte[] ForeignSignedResult()
        {
            var foreign = ControlCapability.Create(
                Invitation.BaseState, Chunks[0], Fill(0x93, 32), Placement, replicaKeys);
            return SignedResult(foreign.Request);
        }

        private static VerifiedGroupInvitation BuildInvitation(
            GroupInvitationRecord record,
            VerifiedGroupTransition baseState) =>
            (VerifiedGroupInvitation)Activator.CreateInstance(
                typeof(VerifiedGroupInvitation), BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, args: [record, baseState, null!], culture: null)!;

        private static VerifiedGroupInvitationAcceptance BuildAcceptance(
            GroupInvitationAcceptanceRecord record,
            VerifiedGroupInvitation invitation) =>
            (VerifiedGroupInvitationAcceptance)Activator.CreateInstance(
                typeof(VerifiedGroupInvitationAcceptance), BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, args: [record, invitation, null!], culture: null)!;

        private static VerifiedAuthoredGroupTransition BuildAuthored(
            GroupCommitPackageRecord package,
            VerifiedGroupTransition transition) =>
            (VerifiedAuthoredGroupTransition)Activator.CreateInstance(
                typeof(VerifiedAuthoredGroupTransition), BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, args: [package, transition], culture: null)!;
    }

    private sealed class ControlCapability
    {
        private ControlCapability(
            VerifiedGroupControlWriteRequest request,
            VerifiedGroupControlPlacement placement,
            IReadOnlyDictionary<string, KeyPair> replicaKeys)
        { Request = request; Placement = placement; ReplicaKeys = replicaKeys; }

        internal VerifiedGroupControlWriteRequest Request { get; }
        internal VerifiedGroupControlPlacement Placement { get; }
        internal IReadOnlyDictionary<string, KeyPair> ReplicaKeys { get; }

        internal static ControlCapability Create(
            VerifiedGroupTransition group,
            GroupCommitChunkRecord chunk,
            byte[] operationId,
            VerifiedGroupControlPlacement? existingPlacement = null,
            IReadOnlyDictionary<string, KeyPair>? existingKeys = null)
        {
            var networkId = group.Commit.Field(1).ToArray();
            var keys = existingKeys ?? new Dictionary<string, KeyPair>(StringComparer.Ordinal);
            var placement = existingPlacement ?? BuildPlacement(networkId, out keys);
            var sealedChunk = SHA256.HashData(chunk.CanonicalBytes.Span);
            var gsw = (GroupControlWriteRecord)GroupCodec.Decode("GSW1", TaggedRecord(
                "GSW1", [1,2,3,4,5,6,16,17,18,19,20,21,22],
                [networkId, operationId, placement.ViewHash, placement.PlacementHash, U64(20), U64(40),
                 placement.Rendezvous.Record.Field(2), placement.Rendezvous.Record.ArtifactHash,
                 U64(1), new byte[32], SHA256.HashData(sealedChunk), Lp(sealedChunk), U64(80)]));
            var network = NetworkOf(placement);
            var terminal = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network, OnionOperation.GroupControl, gsw.CanonicalBytes);
            var request = (VerifiedGroupControlWriteRequest)Activator.CreateInstance(
                typeof(VerifiedGroupControlWriteRequest), BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, args: [group, placement, gsw, terminal], culture: null)!;
            return new(request, placement, keys);
        }

        private static VerifiedGroupControlPlacement BuildPlacement(
            byte[] networkId,
            out IReadOnlyDictionary<string, KeyPair> keys)
        {
            var nodeType = typeof(VerifiedOnionNetworkContext).Assembly.GetType(
                "Deep.Protocol.DeepExtension.PrivacyRouting.VerifiedNetworkNode", throwOnError: true)!;
            var firstKey = PublicKeyAuth.GenerateKeyPair(Fill(0xa1, 32));
            var secondKey = PublicKeyAuth.GenerateKeyPair(Fill(0xa2, 32));
            var firstId = Fill(0x31, 32); var secondId = Fill(0x41, 32);
            var first = Node(nodeType, firstId, firstKey.PublicKey, 0x51);
            var second = Node(nodeType, secondId, secondKey.PublicKey, 0x61);
            var dictionaryType = typeof(Dictionary<,>).MakeGenericType(typeof(string), nodeType);
            var nodes = (IDictionary)Activator.CreateInstance(dictionaryType)!;
            nodes.Add(Convert.ToHexString(firstId), first);
            nodes.Add(Convert.ToHexString(secondId), second);
            var network = (VerifiedOnionNetworkContext)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedOnionNetworkContext));
            SetField(network, "_networkId", networkId);
            SetField(network, "_nodes", nodes);

            var rendezvousRecord = (GroupControlRendezvousRecord)GroupCodec.Decode("GSR1", Record(
                "GSR1", [networkId, Fill(0x62,32), Fill(0x63,32), U64(0), new byte[32],
                 Ref("PMT2", Fill(0x64,32)), Fill(0x65,32), Fill(0x66,32), Fill(0x67,32),
                 Fill(0x68,32), Ref("DPD1", Fill(0x69,32)), U64(20), U64(90), Fill(0x6a,64)]));
            var rendezvous = (VerifiedGroupControlRendezvous)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedGroupControlRendezvous));
            SetField(rendezvous, "<Record>k__BackingField", rendezvousRecord);
            SetField(rendezvous, "<Owner>k__BackingField", null);

            var placement = (VerifiedGroupControlPlacement)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedGroupControlPlacement));
            SetField(placement, "<Network>k__BackingField", network);
            SetField(placement, "<Rendezvous>k__BackingField", rendezvous);
            SetField(placement, "_viewHash", Fill(0x71, 32));
            SetField(placement, "_placementHash", Fill(0x72, 32));
            SetField(placement, "_replicaNodeIds", new[] { firstId, secondId });
            keys = new Dictionary<string, KeyPair>(StringComparer.Ordinal)
            {
                [Convert.ToHexString(firstId)] = firstKey,
                [Convert.ToHexString(secondId)] = secondKey,
            };
            return placement;
        }

        private static object Node(Type nodeType, byte[] id, byte[] identityKey, byte marker) =>
            Activator.CreateInstance(nodeType, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args: [id, Fill(marker,32), Fill((byte)(marker+1),32), Fill((byte)(marker+2),32),
                    Fill((byte)(marker+3),32), (byte)1, (byte)4, Fill((byte)(marker+4),16),
                    (ushort)443, Fill((byte)(marker+5),32), (ushort)4, (uint)1, (ulong)1,
                    (ulong)1, (ulong)1, Fill((byte)(marker+6),32), Fill((byte)(marker+7),32), identityKey],
                culture: null)!;

        private static VerifiedOnionNetworkContext NetworkOf(VerifiedGroupControlPlacement placement) =>
            (VerifiedOnionNetworkContext)typeof(VerifiedGroupControlPlacement)
                .GetProperty("Network", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(placement)!;
    }

    private static class TransitionFixture
    {
        internal static (GroupCommitRecord Commit, GroupCommitPackageRecord Package, VerifiedGroupTransition Transition) Genesis()
        {
            var commit = Commit(0, new byte[32], "genesis", []);
            var package = Package(commit, [], []);
            return (commit, package, Verified(commit, null, package));
        }

        internal static (GroupCommitRecord Commit, GroupCommitPackageRecord Package,
            VerifiedGroupTransition Transition, GroupInvitationRecord Invitation,
            GroupInvitationAcceptanceRecord Acceptance) SuccessorWithInvite(
                GroupCommitRecord predecessor, string name)
        {
            var network = predecessor.Field(1).ToArray(); var group = predecessor.Field(2).ToArray();
            var inviteId = Fill(0x31, 32);
            var invitation = (GroupInvitationRecord)GroupCodec.Decode("GIV1", Record("GIV1",
                [network, group, inviteId, U64(0), predecessor.ArtifactHash.ToArray(), Fill(2,32), Fill(3,32),
                 Ref("DPD1", Fill(4,32)), Fill(5,32), new byte[]{2}, Ref("ADC1", Fill(6,32)),
                 Ref("ADH1", Fill(7,32)), Fill(8,32), Fill(9,32), Ref("DRS1", Fill(10,32)),
                 U64(1), U64(2), Fill(11,64)]));
            var acceptance = (GroupInvitationAcceptanceRecord)GroupCodec.Decode("GIA1", Record("GIA1",
                [network, group, inviteId, Ref("GIV1", invitation.ArtifactHash.Span), Fill(5,32), Fill(12,32),
                 Ref("DPD1", Fill(13,32)), Ref("ADC1", Fill(6,32)), Ref("ADH1", Fill(7,32)),
                 Fill(8,32), Fill(9,32), Ref("DRS1", Fill(10,32)), U64(1), U64(2), Fill(14,64)]));
            var payload = Join(Ref("GIV1", invitation.ArtifactHash.Span),
                Ref("GIA1", acceptance.ArtifactHash.Span), Fill(5,32), new byte[]{2},
                Ref("ADC1", Fill(6,32)), Ref("ADH1", Fill(7,32)), Fill(8,32), Fill(9,32),
                Ref("DRS1", Fill(10,32)));
            var proposal = (GroupProposalRecord)GroupCodec.Decode("DGP1", Record("DGP1",
                [network, group, U64(0), predecessor.ArtifactHash.ToArray(), Fill(15,32), Fill(2,32),
                 Fill(3,32), Ref("DPD1", Fill(4,32)), U16(1), payload, U64(1), U64(2), Fill(16,64)]));
            var commit = Commit(1, predecessor.ArtifactHash.ToArray(), name, [proposal.ArtifactHash.ToArray()]);
            var package = Package(commit, [proposal], [(invitation, acceptance)]);
            return (commit, package, Verified(commit, predecessor, package), invitation, acceptance);
        }

        internal static (GroupCommitRecord Commit, GroupCommitPackageRecord Package, VerifiedGroupTransition Transition)
            SuccessorWithoutInvite(GroupCommitRecord predecessor, string name)
        {
            var commit = Commit(1, predecessor.ArtifactHash.ToArray(), name, []);
            var package = Package(commit, [], []);
            return (commit, package, Verified(commit, predecessor, package));
        }

        internal static GroupCommitChunkRecord[] Chunks(GroupCommitPackageRecord package)
        {
            var bytes = package.CanonicalBytes.ToArray();
            return [(GroupCommitChunkRecord)GroupCodec.Decode("GCF1", Record("GCF1",
                [package.ArtifactHash.ToArray(), U32((uint)bytes.Length), U32(24576), U32(0),
                 U32(1), SHA256.HashData(bytes), Lp(bytes)]))];
        }

        private static GroupCommitRecord Commit(ulong epoch, byte[] predecessor, string name, byte[][] proposals)
        {
            var body = Join(Fill(2,32), new byte[]{1}, Ref("ADC1", Fill(21,32)),
                Ref("ADH1", Fill(22,32)), Fill(23,32), U64(1), Fill(24,32),
                Ref("DRS1", Fill(25,32)), new byte[]{1}, Fill(3,32), Ref("DPD1", Fill(4,32)));
            var members = Join(U16((ushort)body.Length), body);
            return (GroupCommitRecord)GroupCodec.Decode("DGC1", Record("DGC1",
                [Fill(1,16), Fill(20,32), U16(1), U64(epoch), predecessor, Fill(2,32), Fill(3,32),
                 Ref("DPD1", Fill(4,32)), U16((ushort)proposals.Length), Join(proposals), U16(1),
                 members, Encoding.UTF8.GetBytes(name), new byte[]{0}, U32(60), U64(epoch+1),
                 Fill((byte)(30+epoch),64)]));
        }

        private static GroupCommitPackageRecord Package(
            GroupCommitRecord commit,
            GroupProposalRecord[] proposals,
            (GroupInvitationRecord Invitation, GroupInvitationAcceptanceRecord Acceptance)[] pairs)
        {
            var proposalBytes = Join(proposals.Select(record => Lp(record.CanonicalBytes.Span)).ToArray());
            var pairBytes = Join(pairs.Select(pair => Join(
                Ref("GIV1", pair.Invitation.ArtifactHash.Span), Lp(pair.Invitation.CanonicalBytes.Span),
                Ref("GIA1", pair.Acceptance.ArtifactHash.Span), Lp(pair.Acceptance.CanonicalBytes.Span))).ToArray());
            return (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", Record("GCP1",
                [commit.Field(1).ToArray(), commit.Field(2).ToArray(), commit.Field(4).ToArray(),
                 Lp(commit.CanonicalBytes.Span), U16((ushort)proposals.Length), proposalBytes,
                 U32(0), Array.Empty<byte>(), U16((ushort)pairs.Length), pairBytes, Array.Empty<byte>()]));
        }

        private static VerifiedGroupTransition Verified(
            GroupCommitRecord commit,
            GroupCommitRecord? predecessor,
            GroupCommitPackageRecord package)
        {
            var implementation = typeof(VerifiedGroupTransition).Assembly.GetType(
                "Deep.Protocol.GroupV1.GroupCodec+VerifiedGroupTransitionImpl", throwOnError: true)!;
            var transition = (VerifiedGroupTransition)RuntimeHelpers.GetUninitializedObject(implementation);
            SetField(transition, "<Commit>k__BackingField", commit);
            SetField(transition, "<Predecessor>k__BackingField", predecessor);
            SetField(transition, "exactVerifiedGcp1Sha256", SHA256.HashData(package.CanonicalBytes.Span));
            return transition;
        }
    }

    private sealed class MemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly MemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) =>
            left.Span.SequenceCompareTo(right.Span);
    }

    private static GroupStoreScope ScopeForTest()
    {
        var capability = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Fill(1,16)), 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Fill(0x71,32)));
        return GroupStoreScope.ForCurrentAccount(capability.AccountId, capability.AccountGeneration);
    }

    private static GroupOperationId32 Operation(int value) =>
        GroupOperationId32.FromBytes(SHA256.HashData(BitConverter.GetBytes(value)));

    private static DeviceId32 LocalDevice()
    {
        using var persisted = OwnedPersistedDeviceIdentitySecrets.TakeOwnership(
            Fill(0xb1, 32), Fill(0xb2, 32), Fill(0xb3, 32), Fill(0xb4, 32));
        using var restored = OwnedGenesisDeviceSecrets.RestoreFromPersistedOwnedSecrets(persisted);
        return restored.DeviceId;
    }

    private static void SetField(object target, string name, object? value)
    {
        for (var type = target.GetType(); type is not null; type = type.BaseType)
        {
            var field = type.GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
            if (field is null) continue;
            field.SetValue(target, value);
            return;
        }
        throw new MissingFieldException(target.GetType().FullName, name);
    }

    private static byte[] TaggedRecord(string magic, IReadOnlyList<int> tags, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var bytes = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)tags[index]));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8; fields[index].Span.CopyTo(bytes.AsSpan(offset)); offset += fields[index].Length;
        }
        return GroupCodec.Decode(magic, bytes).CanonicalBytes.ToArray();
    }

    private static byte[] Record(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        TaggedRecord(magic, Enumerable.Range(1, fields.Count).ToArray(), fields);
    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(label.Length + 5 + value.Length)];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)value.Length));
        value.CopyTo(preimage.AsSpan(label.Length + 5));
        return SHA256.HashData(preimage);
    }
    private static byte[] SignatureInput(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var output = new byte[checked(label.Length + 7 + value.Length)];
        label.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(label.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(label.Length + 3), checked((uint)value.Length));
        value.CopyTo(output.AsSpan(label.Length + 7));
        return output;
    }
    private static byte[] Ref(string magic, ReadOnlySpan<byte> hash)
    { var value = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(value,0); value[5]=1; hash.CopyTo(value.AsSpan(6)); return value; }
    private static byte[] Lp(ReadOnlySpan<byte> value) => Join(U32((uint)value.Length), value.ToArray());
    private static byte[] Fill(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var output=new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(output,value); return output; }
    private static byte[] U32(uint value) { var output=new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(output,value); return output; }
    private static byte[] U64(ulong value) { var output=new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output,value); return output; }
    private static byte[] Join(params byte[][] values) => values.SelectMany(static value => value).ToArray();

    private sealed class RuntimeSigner(DeviceId32 deviceId) : IGroupDeviceCustodySigner
    {
        public ReadOnlyMemory<byte> DeviceId => deviceId.Bytes;
        public ReadOnlyMemory<byte> Ed25519PublicKey => Fill(0xc1, 32);
        public ReadOnlyMemory<byte> CustodyDomainHash => Fill(0xc2, 32);

        public ValueTask<int> SignAsync(
            GroupDeviceSigningRequest request,
            Memory<byte> signature64,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<int>(new InvalidOperationException(
                "The activation integration fixture never authors signatures."));
    }

    private sealed class FixedGroupControlPathProvider(byte[] entryRouterId)
        : IGroupControlPrivacyPathProvider
    {
        public ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
            VerifiedGroupControlRequest request,
            GroupControlIngressRoute route,
            PrivacyMailboxRouteSelection selection,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(PrivacyMailboxRouteSelection.Primary, selection);
            Assert.Equal(entryRouterId, route.EntryRouterId.ToArray());
            var path = (VerifiedOnionPathContext)RuntimeHelpers.GetUninitializedObject(
                typeof(VerifiedOnionPathContext));
            SetField(path, "_entryRouterId", entryRouterId.ToArray());
            var network = NetworkOf(request.Placement);
            var terminal = OnionTerminalPayloadVerifierV1.VerifyRequest(
                network, OnionOperation.GroupControl, request.CanonicalBytes);
            return ValueTask.FromResult(new PrivacyMailboxOnionAttempt(path, terminal));
        }
    }

    private sealed class ActivationPrivacyCodec(ReadOnlyMemory<byte> exactGss1)
        : IGroupControlPrivacyCodec
    {
        public int OpenCount { get; private set; }

        public ValueTask<IGroupControlPrivacyBuiltRequest> BuildAsync(
            VerifiedOnionPathContext path,
            VerifiedCanonicalOnionRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(OnionOperation.GroupControl, request.Operation);
            return ValueTask.FromResult<IGroupControlPrivacyBuiltRequest>(new ActivationBuiltRequest());
        }

        public ValueTask<GroupControlPrivacyOpenedResponse> OpenResponseAsync(
            ReadOnlyMemory<byte> frame,
            IGroupControlPrivacyBuiltRequest builtRequest,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OpenCount++;
            return ValueTask.FromResult(new GroupControlPrivacyOpenedResponse(
                OnionOperation.GroupControl,
                OnionTerminalResultKind.Success,
                null,
                exactGss1));
        }
    }

    private sealed class ActivationBuiltRequest : IGroupControlPrivacyBuiltRequest
    {
        public ReadOnlyMemory<byte> Frame => Fill(0xd3, 64);
        public void Dispose() { }
    }

    private sealed class CountingPrivacyIngress : IPrivacyManagedIngressTransport
    {
        public int CallCount { get; private set; }

        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult<ReadOnlyMemory<byte>>(Fill(0xd4, 64));
        }

        public void Dispose() { }
    }

    private sealed class NeverPrivacyIngress : IPrivacyManagedIngressTransport
    {
        public Task<ReadOnlyMemory<byte>> ForwardAsync(
            ReadOnlyMemory<byte> opaqueFrame,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Fallback ingress must not be used.");

        public void Dispose() { }
    }

    private static VerifiedOnionNetworkContext NetworkOf(VerifiedGroupControlPlacement placement) =>
        (VerifiedOnionNetworkContext)typeof(VerifiedGroupControlPlacement)
            .GetProperty("Network", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(placement)!;
}
