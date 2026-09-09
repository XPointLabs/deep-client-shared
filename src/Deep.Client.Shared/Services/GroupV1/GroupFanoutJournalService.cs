using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

/// <summary>
/// Converts an already protocol-verified group transition into one bounded,
/// immutable per-device fanout plan. It does not author envelopes or transport work.
/// </summary>
public sealed class GroupFanoutJournalService
{
    public GroupFanoutBatchPlan PrepareVerifiedBatch(
        GroupTransitionCommitPlan transition,
        GroupFanoutBatchId32 batchId,
        IReadOnlyList<GroupFanoutTargetEnvelope> targets,
        DateTimeOffset stagedAt)
    {
        ArgumentNullException.ThrowIfNull(transition);
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(targets);

        if (!transition.VerifiedTransition.BindsExactGcp1(transition.CanonicalPackage)
            || !CryptographicOperations.FixedTimeEquals(
                transition.VerifiedTransition.ExactVerifiedGcp1Sha256.Span,
                transition.ExactVerifiedGcp1Sha256))
            throw new ArgumentException("The fanout source is not bound to the exact verified GCP1.", nameof(transition));
        if (transition.MemberCount is < 1 or > GroupFanoutLimits.MaximumMembers
            || transition.DeviceCount is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new ArgumentException("The verified transition exceeds the GroupV1 profile.", nameof(transition));
        if (targets.Count is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new ArgumentOutOfRangeException(nameof(targets));
        if (targets.Count > transition.DeviceCount)
            throw new ArgumentException("Fanout targets exceed the verified active-device count.", nameof(targets));

        var targetIds = new HashSet<string>(StringComparer.Ordinal);
        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var target in targets)
        {
            if (target is null) throw new ArgumentException("A fanout target cannot be null.", nameof(targets));
            if (!targetIds.Add(Convert.ToHexString(target.TargetId.Bytes.Span)))
                throw new ArgumentException("A target device occurs more than once.", nameof(targets));
            if (!operationIds.Add(Convert.ToHexString(target.InitialNetworkOperationId.Bytes.Span)))
                throw new ArgumentException("A network operation identity cannot be shared by two targets.", nameof(targets));
        }

        return new GroupFanoutBatchPlan(transition, batchId, targets, stagedAt);
    }
}
