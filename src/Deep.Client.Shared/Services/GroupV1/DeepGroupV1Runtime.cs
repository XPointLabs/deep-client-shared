using System.Buffers.Binary;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Services.GroupV1;

/// <summary>
/// Opaque GroupControl network boundary. The transport receives only a request
/// already bound to verified group and placement capabilities. Returned bytes
/// carry no authority until the runtime verifies the exact GSS1 response.
/// </summary>
public interface IDeepGroupControlTransport
{
    ValueTask<ReadOnlyMemory<byte>> ExecuteAsync(
        VerifiedGroupControlRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>One locally authored and durably evaluated GroupV1 transition.</summary>
public sealed class DeepGroupV1TransitionResult
{
    internal DeepGroupV1TransitionResult(
        VerifiedAuthoredGroupTransition authored,
        GroupCommitResult persistence)
    {
        Authored = authored ?? throw new ArgumentNullException(nameof(authored));
        Persistence = persistence ?? throw new ArgumentNullException(nameof(persistence));
    }

    public VerifiedAuthoredGroupTransition Authored { get; }
    public GroupCommitResult Persistence { get; }
}

/// <summary>
/// Account-scoped clean-break GroupV1 facade. Its public boundary contains no
/// legacy Session identity, conversation aliases, raw signing keys, or trust
/// booleans. Protocol capabilities remain the only authoring authority.
/// </summary>
public interface IDeepGroupV1Runtime
{
    DeepAccountId32 AccountId { get; }
    DeviceId32 DeviceId { get; }

    ValueTask<DeepGroupV1TransitionResult> CreateAsync(
        GroupOperationId32 operationId,
        GroupGenesisAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupInvitation> AuthorInvitationAsync(
        GroupInvitationAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupInvitationAcceptance> AuthorInvitationAcceptanceAsync(
        GroupInvitationAcceptanceAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupActivationProposal> AuthorActivationProposalAsync(
        GroupActivationProposalAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupMembershipProposal> AuthorRemoveAccountProposalAsync(
        GroupRemoveAccountProposalAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupMembershipProposal> AuthorLeaveAccountProposalAsync(
        GroupLeaveAccountProposalAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupMembershipProposal> AuthorRoleChangeProposalAsync(
        GroupRoleChangeProposalAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedAuthoredGroupTransition> AuthorActivationCommitAsync(
        GroupMembershipCommitAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<GroupInvitationActivationResult> ActivateInvitationAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default);

    ValueTask<DeepGroupV1TransitionResult> CommitMembershipChangeAsync(
        GroupOperationId32 operationId,
        ulong expectedRevision,
        GroupMembershipChangeCommitAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<GroupCommitResult> ApplyVerifiedTransitionAsync(
        GroupOperationId32 operationId,
        ulong? expectedRevision,
        VerifiedAuthoredGroupTransition transition,
        CancellationToken cancellationToken = default);

    ValueTask<GroupHeadSnapshot?> ReadAsync(
        GroupId32 groupId,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadAllAsync(
        CancellationToken cancellationToken = default);

    VerifiedGroupApplicationMessage AuthorApplicationMessage(
        GroupApplicationMessageAuthoringRequest request);

    ValueTask<VerifiedGroupControlResult> ExecuteControlWriteAsync(
        GroupControlWriteAuthoringRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<VerifiedGroupControlResult> ExecuteControlQueryAsync(
        GroupControlQueryAuthoringRequest request,
        CancellationToken cancellationToken = default);
}

public sealed class DeepGroupV1Runtime : IDeepGroupV1Runtime
{
    private readonly IGroupDeviceCustodySigner signer;
    private readonly IGroupStateStore stateStore;
    private readonly GroupClientStateService stateService;
    private readonly IDeepGroupControlTransport? controlTransport;
    private readonly GroupInvitationActivationOrchestrator? invitationActivation;

    public DeepGroupV1Runtime(
        DeepAccountId32 accountId,
        DeviceId32 deviceId,
        IGroupDeviceCustodySigner signer,
        IGroupStateStore stateStore,
        IDeepGroupControlTransport? controlTransport = null,
        IGroupInvitationActivationStore? invitationActivationStore = null)
    {
        AccountId = accountId ?? throw new ArgumentNullException(nameof(accountId));
        DeviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        this.signer = signer ?? throw new ArgumentNullException(nameof(signer));
        this.stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        this.controlTransport = controlTransport;
        stateService = new GroupClientStateService();

        if (!stateStore.Scope.AccountId.Equals(accountId))
            throw new ArgumentException("The GroupV1 store belongs to another Deep account.", nameof(stateStore));
        if (!deviceId.Matches(signer.DeviceId.Span))
            throw new ArgumentException("The custody capability belongs to another Deep device.", nameof(signer));
        if (invitationActivationStore is not null)
        {
            if (controlTransport is null)
                throw new ArgumentException(
                    "Invitation activation requires a capability-bound GroupControl transport.",
                    nameof(controlTransport));
            invitationActivation = new GroupInvitationActivationOrchestrator(
                invitationActivationStore, stateStore, controlTransport);
        }
    }

    public DeepAccountId32 AccountId { get; }
    public DeviceId32 DeviceId { get; }

    public async ValueTask<DeepGroupV1TransitionResult> CreateAsync(
        GroupOperationId32 operationId,
        GroupGenesisAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Owner.Directory.Record.DeepAccountId.Span, request.SequencerDeviceId.Span);
        var authored = await GroupProductionAuthor.AuthorGenesisAsync(request, signer, cancellationToken)
            .ConfigureAwait(false);
        var persisted = await ApplyVerifiedTransitionAsync(operationId, null, authored, cancellationToken)
            .ConfigureAwait(false);
        return new DeepGroupV1TransitionResult(authored, persisted);
    }

    public ValueTask<VerifiedGroupInvitation> AuthorInvitationAsync(
        GroupInvitationAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Inviter.Directory.Record.DeepAccountId.Span, request.InviterDeviceId.Span);
        return GroupProductionAuthor.AuthorInvitationAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedGroupInvitationAcceptance> AuthorInvitationAcceptanceAsync(
        GroupInvitationAcceptanceAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Invitee.Directory.Record.DeepAccountId.Span, request.AcceptingDeviceId.Span);
        return GroupProductionAuthor.AuthorInvitationAcceptanceAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedGroupActivationProposal> AuthorActivationProposalAsync(
        GroupActivationProposalAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Proposer.Directory.Record.DeepAccountId.Span, request.ProposerDeviceId.Span);
        return GroupProductionAuthor.AuthorActivationProposalAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedGroupMembershipProposal> AuthorRemoveAccountProposalAsync(
        GroupRemoveAccountProposalAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Proposer.Directory.Record.DeepAccountId.Span, request.ProposerDeviceId.Span);
        return GroupProductionAuthor.AuthorRemoveAccountProposalAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedGroupMembershipProposal> AuthorLeaveAccountProposalAsync(
        GroupLeaveAccountProposalAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Member.Directory.Record.DeepAccountId.Span, request.MemberDeviceId.Span);
        return GroupProductionAuthor.AuthorLeaveAccountProposalAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedGroupMembershipProposal> AuthorRoleChangeProposalAsync(
        GroupRoleChangeProposalAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Proposer.Directory.Record.DeepAccountId.Span, request.ProposerDeviceId.Span);
        return GroupProductionAuthor.AuthorRoleChangeProposalAsync(request, signer, cancellationToken);
    }

    public ValueTask<VerifiedAuthoredGroupTransition> AuthorActivationCommitAsync(
        GroupMembershipCommitAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireSequencer(request.Previous);
        return GroupProductionAuthor.AuthorMembershipCommitAsync(request, signer, cancellationToken);
    }

    public ValueTask<GroupInvitationActivationResult> ActivateInvitationAsync(
        GroupInvitationActivationPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var activation = invitationActivation ?? throw new InvalidOperationException(
            "No durable invitation activation journal and GroupControl transport are configured for this runtime.");
        return activation.RunAsync(plan, cancellationToken);
    }

    public async ValueTask<DeepGroupV1TransitionResult> CommitMembershipChangeAsync(
        GroupOperationId32 operationId,
        ulong expectedRevision,
        GroupMembershipChangeCommitAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(request);
        if (expectedRevision == 0) throw new ArgumentOutOfRangeException(nameof(expectedRevision));
        RequireSequencer(request.Previous);
        var authored = await GroupProductionAuthor.AuthorMembershipChangeCommitAsync(request, signer, cancellationToken)
            .ConfigureAwait(false);
        var persisted = await ApplyVerifiedTransitionAsync(operationId, expectedRevision, authored, cancellationToken)
            .ConfigureAwait(false);
        return new DeepGroupV1TransitionResult(authored, persisted);
    }

    public ValueTask<GroupCommitResult> ApplyVerifiedTransitionAsync(
        GroupOperationId32 operationId,
        ulong? expectedRevision,
        VerifiedAuthoredGroupTransition transition,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operationId);
        ArgumentNullException.ThrowIfNull(transition);
        cancellationToken.ThrowIfCancellationRequested();
        if (ContainsInvitationActivation(transition.Package))
            throw new InvalidOperationException(
                "Invitation-bearing GroupV1 transitions must commit through the durable activation outbox.");
        var plan = stateService.PrepareVerifiedTransition(
            stateStore.Scope,
            operationId,
            expectedRevision,
            transition.Transition,
            transition.Package);
        return stateStore.CommitVerifiedTransitionAsync(plan, cancellationToken);
    }

    private static bool ContainsInvitationActivation(GroupCommitPackageRecord package)
    {
        var count = package.Field(9).Span;
        return count.Length != 2 || BinaryPrimitives.ReadUInt16BigEndian(count) != 0;
    }

    public ValueTask<GroupHeadSnapshot?> ReadAsync(
        GroupId32 groupId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(groupId);
        return stateStore.ReadHeadAsync(groupId, cancellationToken);
    }

    public ValueTask<IReadOnlyList<GroupHeadSnapshot>> ReadAllAsync(
        CancellationToken cancellationToken = default) =>
        stateStore.ReadHeadsAsync(cancellationToken);

    public VerifiedGroupApplicationMessage AuthorApplicationMessage(
        GroupApplicationMessageAuthoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLocalActor(request.Sender.Directory.Record.DeepAccountId.Span, request.SenderDeviceId.Span);
        return GroupProductionAuthor.AuthorApplicationMessage(request);
    }

    public async ValueTask<VerifiedGroupControlResult> ExecuteControlWriteAsync(
        GroupControlWriteAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var verifiedRequest = GroupControlProductionClient.AuthorWrite(request);
        return await ExecuteControlAsync(verifiedRequest, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<VerifiedGroupControlResult> ExecuteControlQueryAsync(
        GroupControlQueryAuthoringRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var verifiedRequest = GroupControlProductionClient.AuthorQuery(request);
        return await ExecuteControlAsync(verifiedRequest, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<VerifiedGroupControlResult> ExecuteControlAsync(
        VerifiedGroupControlRequest request,
        CancellationToken cancellationToken)
    {
        var transport = controlTransport ?? throw new InvalidOperationException(
            "No capability-bound GroupControl transport is configured for this runtime.");
        var exactGss1 = await transport.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return GroupControlProductionClient.VerifyResult(request, exactGss1);
    }

    private void RequireSequencer(VerifiedGroupTransition previous) =>
        RequireLocalActor(previous.Commit.Field(6).Span, previous.Commit.Field(7).Span);

    private void RequireLocalActor(ReadOnlySpan<byte> accountId, ReadOnlySpan<byte> deviceId)
    {
        if (!AccountId.Matches(accountId) || !DeviceId.Matches(deviceId))
            throw new InvalidOperationException(
                "The GroupV1 authoring capability is not bound to this account-scoped runtime actor.");
    }
}
