using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

/// <summary>
/// Materializes one exact DGM1 as one MSG-01 logical outbox over every active
/// device in the current durable DGC1 head. It owns no crypto or transport trust.
/// </summary>
public sealed class GroupMessageFanoutService
{
    private readonly IGroupStateStore groupState;
    private readonly IGroupMessageLogicalOutbox logicalOutbox;

    public GroupMessageFanoutService(
        IGroupStateStore groupState,
        IGroupMessageLogicalOutbox logicalOutbox)
    {
        this.groupState = groupState ?? throw new ArgumentNullException(nameof(groupState));
        this.logicalOutbox = logicalOutbox ?? throw new ArgumentNullException(nameof(logicalOutbox));
    }

    public async ValueTask<GroupMessageFanoutResult> StageAsync(
        GroupFanoutBatchId32 batchId,
        GroupApplicationMessageRecord message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batchId);
        ArgumentNullException.ThrowIfNull(message);
        cancellationToken.ThrowIfCancellationRequested();

        var groupId = GroupId32.FromBytes(message.Field(2).Span);
        var epoch = U64(message.Field(3).Span);
        var semanticId = SemanticMessageId32.FromBytes(message.Field(5).Span);
        await using var headLease = await groupState.AcquireHeadReadLeaseAsync(
            groupId, cancellationToken).ConfigureAwait(false);
        var head = headLease.Head;
        if (head is null)
            return Result(GroupMessageFanoutDisposition.GroupNotFound, null);
        if (head.ForkLatched)
            return Result(GroupMessageFanoutDisposition.ForkLatched, null);
        if (!CurrentHeadBinds(message, head))
            return Result(GroupMessageFanoutDisposition.StaleGroupState, null);

        var commit = (GroupCommitRecord)GroupCodec.Decode(
            "DGC1", head.ExactCanonicalCommit.Span);
        var package = (GroupCommitPackageRecord)GroupCodec.Decode(
            "GCP1", head.ExactCanonicalPackage.Span);
        var verifiedPackageHash = SHA256.HashData(head.ExactCanonicalPackage.Span);
        if (!commit.ArtifactHash.Span.SequenceEqual(head.CommitHash.Span)
            || !package.ArtifactHash.Span.SequenceEqual(head.PackageHash.Span)
            || !CryptographicOperations.FixedTimeEquals(
                verifiedPackageHash, head.ExactVerifiedGcp1Sha256.Span)
            || !commit.Field(1).Span.SequenceEqual(head.NetworkId.Span)
            || !commit.Field(2).Span.SequenceEqual(head.GroupId.Span)
            || U64(commit.Field(4).Span) != head.Epoch)
            throw new InvalidDataException("The durable GroupV1 head is not self-consistent.");
        var packagedCommit = ReadLp32(package.Field(4).Span);
        if (!package.Field(1).Span.SequenceEqual(head.NetworkId.Span)
            || !package.Field(2).Span.SequenceEqual(head.GroupId.Span)
            || U64(package.Field(3).Span) != head.Epoch
            || !packagedCommit.SequenceEqual(head.ExactCanonicalCommit.Span))
            throw new InvalidDataException("The durable GCP1 does not bind the current DGC1 head.");

        var authorAccount = MessagingAccountId32.FromBytes(message.Field(6).Span);
        var authorDevice = MessagingDeviceId32.FromBytes(message.Field(7).Span);
        if (!groupState.Scope.AccountId.Bytes.Span.SequenceEqual(authorAccount.Span))
            return Result(GroupMessageFanoutDisposition.StaleGroupState, null);

        var targets = ReadTargets(
            message,
            commit.Field(12).Span,
            head.MemberCount,
            head.DeviceCount,
            authorAccount,
            authorDevice,
            groupState.Scope.AccountGeneration,
            batchId);
        if (targets.Count == 0)
            return Result(GroupMessageFanoutDisposition.NoRemoteTargets, null);

        var createdAt = UnixMilliseconds(message.Field(9).Span);
        var expiresAt = UnixMilliseconds(message.Field(10).Span);
        if (expiresAt <= createdAt || expiresAt - createdAt > MessagingV1Limits.MaxEventLifetime)
            throw new InvalidDataException("DGM1 lifetime is outside the MSG-01 bound.");
        var plan = new GroupMessageLogicalOutboxPlan(
            batchId,
            groupId,
            epoch,
            head.CommitHash.Span,
            authorAccount,
            authorDevice,
            semanticId,
            message.CanonicalBytes.Span,
            createdAt,
            expiresAt,
            targets);
        var write = await logicalOutbox.StageAsync(plan, cancellationToken).ConfigureAwait(false);
        if (write.Disposition is not (GroupMessageFanoutDisposition.Staged
            or GroupMessageFanoutDisposition.Idempotent
            or GroupMessageFanoutDisposition.MessageForkLatched
            or GroupMessageFanoutDisposition.Conflict))
            throw new InvalidOperationException("The logical outbox returned an invalid GroupV1 disposition.");
        if ((write.Disposition is GroupMessageFanoutDisposition.Staged
                or GroupMessageFanoutDisposition.Idempotent)
            && write.Snapshot is null)
            throw new InvalidOperationException("The logical outbox omitted its durable MSG-01 snapshot.");
        if (write.Snapshot is not null && !SnapshotMatches(write.Snapshot, plan))
            return Result(GroupMessageFanoutDisposition.Conflict, write.Snapshot);
        return Result(write.Disposition, write.Snapshot);

        GroupMessageFanoutResult Result(
            GroupMessageFanoutDisposition disposition,
            LogicalOutboxSnapshot? snapshot) =>
            new(disposition, batchId, groupId, epoch, semanticId, snapshot);
    }

    private static bool CurrentHeadBinds(
        GroupApplicationMessageRecord message,
        GroupHeadSnapshot head) =>
        message.Field(1).Span.SequenceEqual(head.NetworkId.Span)
        && message.Field(2).Span.SequenceEqual(head.GroupId.Span)
        && U64(message.Field(3).Span) == head.Epoch
        && CryptographicOperations.FixedTimeEquals(
            message.Field(4).Span, head.CommitHash.Span);

    private static List<GroupMessageFanoutTarget> ReadTargets(
        GroupApplicationMessageRecord message,
        ReadOnlySpan<byte> members,
        ushort expectedMemberCount,
        ushort expectedDeviceCount,
        MessagingAccountId32 authorAccount,
        MessagingDeviceId32 authorDevice,
        ulong localAccountGeneration,
        GroupFanoutBatchId32 batchId)
    {
        var result = new List<GroupMessageFanoutTarget>(expectedDeviceCount);
        var at = 0;
        var memberCount = 0;
        var deviceCount = 0;
        var authorMemberFound = false;
        var authorDeviceFound = false;
        while (at < members.Length)
        {
            Require(members, at, 2);
            var memberLength = BinaryPrimitives.ReadUInt16BigEndian(members[at..]);
            at += 2;
            Require(members, at, memberLength);
            var member = members.Slice(at, memberLength);
            at += memberLength;
            if (memberLength < 220)
                throw new InvalidDataException("The durable DGC1 member table is truncated.");
            var count = member[219];
            if (count is < 1 or > 5 || memberLength != 220 + count * 70)
                throw new InvalidDataException("The durable DGC1 member table is malformed.");

            var accountId = MessagingAccountId32.FromBytes(member[..32]);
            var accountGeneration = U64(member.Slice(141, 8));
            var directoryHead = DirectoryHeadHash32.FromBytes(member.Slice(149, 32));
            var isAuthorAccount = accountId.Equals(authorAccount);
            if (isAuthorAccount)
            {
                if (authorMemberFound || accountGeneration != localAccountGeneration)
                    throw new InvalidDataException("DGM1 author account generation is not current.");
                authorMemberFound = true;
            }

            for (var deviceIndex = 0; deviceIndex < count; deviceIndex++)
            {
                var device = member.Slice(220 + deviceIndex * 70, 70);
                var deviceId = MessagingDeviceId32.FromBytes(device[..32]);
                var isAuthorDevice = isAuthorAccount && deviceId.Equals(authorDevice);
                if (isAuthorDevice)
                {
                    if (authorDeviceFound)
                        throw new InvalidDataException("DGM1 author device occurs more than once.");
                    authorDeviceFound = true;
                }
                else
                {
                    var target = new RecipientDeviceTarget(accountId, deviceId);
                    var memberProjection = new GroupMessageMemberProjection(
                        accountId, accountGeneration, directoryHead,
                        [new GroupMessageDeviceProjection(deviceId, device.Slice(38, 32).ToArray())]);
                    result.Add(new GroupMessageFanoutTarget(
                        target,
                        accountGeneration,
                        directoryHead,
                        TargetOperationId(batchId, target),
                        GroupMessageHeadInspection.TargetBinding(
                            message, memberProjection, memberProjection.Devices[0])));
                }
                deviceCount++;
            }
            memberCount++;
        }

        if (memberCount != expectedMemberCount
            || deviceCount != expectedDeviceCount
            || memberCount is < 1 or > GroupFanoutLimits.MaximumMembers
            || deviceCount is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new InvalidDataException("The durable DGC1 counts are inconsistent.");
        if (!authorMemberFound || !authorDeviceFound)
            throw new InvalidDataException("DGM1 author is not an active device of the current group head.");
        if (result.Count != deviceCount - 1)
            throw new InvalidDataException("The GroupV1 target projection is incomplete.");
        return result.OrderBy(static target => target.Target).ToList();
    }

    private static MessageTargetOperationId32 TargetOperationId(
        GroupFanoutBatchId32 batchId,
        RecipientDeviceTarget target)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Group/V1/msg01-target-operation/v1\0"u8);
        hash.AppendData(batchId.Span);
        hash.AppendData(target.AccountId.Span);
        hash.AppendData(target.DeviceId.Span);
        return MessageTargetOperationId32.FromBytes(hash.GetHashAndReset());
    }

    private static bool SnapshotMatches(
        LogicalOutboxSnapshot snapshot,
        GroupMessageLogicalOutboxPlan plan) =>
        snapshot.AuthorAccountId.Equals(plan.AuthorAccountId)
        && snapshot.AuthorDeviceId.Equals(plan.AuthorDeviceId)
        && snapshot.ConversationId.Span.SequenceEqual(plan.GroupId.Span)
        && snapshot.SemanticMessageId.Equals(plan.SemanticMessageId)
        && snapshot.EventHash.Span.SequenceEqual(SHA256.HashData(plan.CanonicalEvent.Span))
        && snapshot.CanonicalPayload.AsSpan().SequenceEqual(plan.CanonicalEvent.Span)
        && snapshot.PayloadKind == MessagePayloadKind.GroupMessage
        && snapshot.Targets.Count == plan.TargetRows.Count
        && snapshot.Targets.Zip(plan.TargetRows).All(static pair =>
            pair.First.Target.Equals(pair.Second.Target)
            && pair.First.DirectoryHeadHash.Equals(pair.Second.DirectoryHeadHash)
            && pair.First.OperationId?.Equals(pair.Second.OperationId) == true
            && pair.First.BindingHash?.Equals(pair.Second.BindingHash) == true);

    private static DateTimeOffset UnixMilliseconds(ReadOnlySpan<byte> value)
    {
        var milliseconds = U64(value);
        if (milliseconds > long.MaxValue)
            throw new InvalidDataException("DGM1 timestamp exceeds the signed clock domain.");
        try { return DateTimeOffset.FromUnixTimeMilliseconds((long)milliseconds); }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException("DGM1 timestamp is outside the supported clock domain.", exception);
        }
    }

    private static ReadOnlySpan<byte> ReadLp32(ReadOnlySpan<byte> value)
    {
        if (value.Length < 4)
            throw new InvalidDataException("The durable GCP1 commit field is truncated.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(value);
        if (length > int.MaxValue || length != value.Length - 4)
            throw new InvalidDataException("The durable GCP1 commit field is not exact LP32.");
        return value[4..];
    }

    private static ulong U64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8) throw new InvalidDataException("DGM1 u64 field has an invalid width.");
        return BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static void Require(ReadOnlySpan<byte> value, int at, int length)
    {
        if (at < 0 || length < 0 || length > value.Length - at)
            throw new InvalidDataException("The durable DGC1 member table is truncated.");
    }
}
