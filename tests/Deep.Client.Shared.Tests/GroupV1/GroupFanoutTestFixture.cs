using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.GroupV1;

internal static class GroupFanoutTestFixture
{
    internal static VerifiedTransitionFacts Plan(
        int memberCount = 3,
        int devicesPerMember = 1,
        int marker = 1)
    {
        if (memberCount is < 1 or > GroupFanoutLimits.MaximumMembers
            || devicesPerMember is < 1 or > 5)
            throw new ArgumentOutOfRangeException();

        return new(
            Scope((byte)(0x60 + marker)),
            GroupOperationId32.FromBytes(Hash("transition-operation", marker, 0)),
            GroupId32.FromBytes(Hash("group", marker, 0)),
            Hash("package", marker, 0),
            Hash("verified-package", marker, 0),
            checked((ushort)memberCount),
            checked((ushort)(memberCount * devicesPerMember)));
    }

    internal static GroupFanoutBatchPlan Batch(
        VerifiedTransitionFacts transition,
        int targetCount,
        int marker = 1,
        bool reverse = false,
        int changedEnvelopeTarget = -1)
    {
        var targets = Enumerable.Range(0, targetCount)
            .Select(index => Target(marker, index, changedEnvelopeTarget == index))
            .ToArray();
        if (reverse) Array.Reverse(targets);
        return Batch(transition, BatchId(marker), targets, Time(marker));
    }

    internal static GroupFanoutBatchPlan Batch(
        VerifiedTransitionFacts transition,
        GroupFanoutBatchId32 batchId,
        IReadOnlyList<GroupFanoutTargetEnvelope> targets,
        DateTimeOffset stagedAt) =>
        GroupFanoutBatchPlan.FromVerifiedTransitionFactsForTests(
            transition.Scope,
            transition.OperationId,
            transition.GroupId,
            transition.PackageHash,
            transition.VerifiedPackageHash,
            transition.MemberCount,
            transition.VerifiedDeviceCount,
            batchId,
            targets,
            stagedAt);

    internal static GroupFanoutTargetEnvelope Target(int marker, int index, bool changed = false) =>
        GroupFanoutTargetEnvelope.FromExactCanonicalEnvelope(
        GroupFanoutTargetId32.FromOpaqueBytes(Hash("target", marker, index)),
        GroupFanoutNetworkOperationId32.FromBytes(Hash("operation", marker, index)),
        Encoding.UTF8.GetBytes(changed ? $"canonical-envelope-{index}-changed" : $"canonical-envelope-{index}"));

    internal static GroupFanoutBatchId32 BatchId(int marker) =>
        GroupFanoutBatchId32.FromBytes(Hash("batch", marker, 0));

    internal static GroupFanoutLeaseOwnerId16 Owner(int marker) =>
        GroupFanoutLeaseOwnerId16.FromBytes(Hash("owner", marker, 0).AsSpan(0, 16));

    internal static GroupFanoutNetworkOperationId32 NextOperation(int marker, int index) =>
        GroupFanoutNetworkOperationId32.FromBytes(Hash("next-operation", marker, index));

    internal static DateTimeOffset Time(int marker) =>
        new(2026, 9, 1, 12, marker % 60, 0, TimeSpan.Zero);

    internal static byte[] Hash(string domain, int first, int second) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"{domain}:{first}:{second}"));

    private static GroupStoreScope Scope(byte marker)
    {
        var capability = DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Enumerable.Repeat((byte)1, 16).ToArray()),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Enumerable.Repeat(marker, 32).ToArray()));
        return GroupStoreScope.ForCurrentAccount(capability.AccountId, capability.AccountGeneration);
    }

    internal sealed record VerifiedTransitionFacts(
        GroupStoreScope Scope,
        GroupOperationId32 OperationId,
        GroupId32 GroupId,
        byte[] PackageHash,
        byte[] VerifiedPackageHash,
        ushort MemberCount,
        ushort VerifiedDeviceCount);
}
