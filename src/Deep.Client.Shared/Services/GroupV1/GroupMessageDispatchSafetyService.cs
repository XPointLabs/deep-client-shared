using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

internal static class GroupMessageDispatchSafetyCompositionStatus
{
    internal const string Blocker =
        "ClientRuntime has no production-owned account-scoped IGroupStateStore; exact DGM1 dispatch remains fail-closed until that real store is supplied by account runtime composition.";
}

/// <summary>
/// Reauthorizes exactly one first durable active GroupMessage attempt against
/// the current DGC1/GCP1 head immediately before its first network action,
/// including recovery reconciliation. The callback runs while the
/// database-wide group-head lease remains held.
/// </summary>
public sealed class GroupMessageDispatchSafetyService
{
    private readonly IGroupStateStore groupState;

    public GroupMessageDispatchSafetyService(IGroupStateStore groupState) =>
        this.groupState = groupState ?? throw new ArgumentNullException(nameof(groupState));

    internal ValueTask<GroupMessageFirstDispatchResult> DispatchFirstAsync(
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        IMessageTransactionStore messageStore,
        IMessageGroupDispatchSafetyHandoff capabilityIssuer,
        DateTimeOffset occurredAt,
        IGroupMessageDeviceDispatcher dispatcher,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        return DispatchFirstAsync(
            outbox, target, messageStore, capabilityIssuer, occurredAt,
            dispatcher.DispatchAsync, cancellationToken);
    }

    internal async ValueTask<GroupMessageFirstDispatchResult> DispatchFirstAsync(
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        IMessageTransactionStore messageStore,
        IMessageGroupDispatchSafetyHandoff capabilityIssuer,
        DateTimeOffset occurredAt,
        Func<GroupMessageFirstDispatchContext, CancellationToken, ValueTask> firstDispatch,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outbox);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(messageStore);
        ArgumentNullException.ThrowIfNull(capabilityIssuer);
        ArgumentNullException.ThrowIfNull(firstDispatch);
        cancellationToken.ThrowIfCancellationRequested();
        if (!messageStore.Scope.Equals(outbox.StoreScope))
            throw new InvalidDataException(
                "The GroupV1 safety boundary received a foreign MSG-01 store scope.");

        var exactTarget = FindExactTarget(outbox, target);
        if (exactTarget is null)
            return Result(GroupMessageFirstDispatchDisposition.NoTarget);
        if (!IsFirstDurableActiveAttempt(outbox, exactTarget))
            return Result(GroupMessageFirstDispatchDisposition.NotFirstDispatch);

        var canonicalDgm1 = outbox.CanonicalPayload;
        try
        {
            if (canonicalDgm1.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes)
                throw new InvalidDataException("The durable DGM1 payload exceeds the MSG-01 bound.");
            var preflight = GroupCodec.Decode("DGM1", canonicalDgm1)
                as GroupApplicationMessageRecord
                ?? throw new InvalidDataException("The durable GroupMessage payload is not DGM1.");
            ValidateOutboxBinding(outbox, preflight, canonicalDgm1);
            if (!outbox.StoreScope.LocalAccountId.Span.SequenceEqual(
                    groupState.Scope.AccountId.Bytes.Span)
                || outbox.StoreScope.DatabaseGeneration != groupState.Scope.AccountGeneration)
                throw new InvalidDataException(
                    "The MSG-01 and GroupV1 stores do not share the exact account generation.");

            var groupId = GroupId32.FromBytes(preflight.Field(2).Span);
            await using var headLease = await groupState.AcquireHeadReadLeaseAsync(
                groupId, cancellationToken).ConfigureAwait(false);
            var head = headLease.Head;
            if (head is null)
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.GroupNotFound,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);
            if (head.ForkLatched)
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.ForkLatched,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);

            var message = GroupCodec.Decode("DGM1", canonicalDgm1)
                as GroupApplicationMessageRecord
                ?? throw new InvalidDataException("The durable GroupMessage payload is not DGM1.");
            ValidateOutboxBinding(outbox, message, canonicalDgm1);
            var members = GroupMessageHeadInspection.ReadCurrentMembers(head);
            if (!message.Field(1).Span.SequenceEqual(head.NetworkId.Span))
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.StaleGroupState,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);

            if (!GroupMessageHeadInspection.AuthorIsCurrent(
                    members, outbox.AuthorAccountId, outbox.AuthorDeviceId,
                    groupState.Scope.AccountId.Bytes.Span, groupState.Scope.AccountGeneration))
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.StaleGroupState,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);

            var currentTarget = members
                .SelectMany(static member => member.Devices.Select(device => (Member: member, Device: device)))
                .SingleOrDefault(candidate => candidate.Member.AccountId.Equals(exactTarget.Target.AccountId)
                    && candidate.Device.DeviceId.Equals(exactTarget.Target.DeviceId));
            if (currentTarget.Member is null)
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.TargetRemoved,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);

            var expectedBinding = GroupMessageHeadInspection.TargetBinding(
                message, currentTarget.Member, currentTarget.Device);
            if (!exactTarget.DirectoryHeadHash.Equals(currentTarget.Member.DirectoryHeadHash)
                || exactTarget.BindingHash is null
                || !CryptographicOperations.FixedTimeEquals(
                    exactTarget.BindingHash.Span, expectedBinding.Span)
                || !GroupMessageHeadInspection.CurrentHeadBinds(message, head))
                return await BlockAsync(
                    headLease, outbox, exactTarget, capabilityIssuer,
                    GroupMessageFirstDispatchDisposition.StaleGroupState,
                    occurredAt, messageStore, cancellationToken).ConfigureAwait(false);

            using var context = new GroupMessageFirstDispatchContext(outbox, exactTarget);
            await firstDispatch(context, cancellationToken).ConfigureAwait(false);
            return Result(GroupMessageFirstDispatchDisposition.Dispatched);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalDgm1);
        }
    }

    private static LogicalTargetSnapshot? FindExactTarget(
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot supplied)
    {
        if (outbox.PayloadKind != MessagePayloadKind.GroupMessage
            || outbox.Targets.Count is < 1 or > MessagingV1Limits.MaxFanoutTargets)
            throw new InvalidDataException("The durable GroupMessage target set is outside its bound.");

        var targets = outbox.Targets;
        if (targets.Select(static item => item.Target).Distinct().Count() != targets.Count
            || targets.Any(static item => item.OperationId is null || item.BindingHash is null)
            || targets.Select(static item => item.OperationId).Distinct().Count() != targets.Count
            || targets.Select(static item => item.BindingHash).Distinct().Count() != targets.Count)
            throw new InvalidDataException("The durable GroupMessage target set is not canonical.");

        var exact = targets.SingleOrDefault(candidate => ExactTarget(candidate, supplied));
        return exact;
    }

    private static bool IsFirstDurableActiveAttempt(
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target)
    {
        if (target.State != LogicalTargetState.Pending
            || target.LastAttemptId is not null
            || target.OutcomeUnknown)
            return false;
        if (target.ActiveAttemptId is null && target.UnresolvedAttemptId is null)
            return false;
        if (outbox.State is not (LogicalOutboxState.Sending
                or LogicalOutboxState.PartiallyAccepted)
            || target.ActiveAttemptId is null
            || target.UnresolvedAttemptId is null
            || !target.ActiveAttemptId.Equals(target.UnresolvedAttemptId)
            || target.RequestHash is null
            || target.RatchetBeforeHash is null
            || target.RatchetTransitionHash is null)
            throw new InvalidDataException("The durable first GroupMessage attempt is incomplete.");

        var activeAttempt = target.ActiveAttemptId;
        if (outbox.Targets.Any(candidate =>
                !candidate.Target.Equals(target.Target)
                && (candidate.ActiveAttemptId?.Equals(activeAttempt) == true
                    || candidate.LastAttemptId?.Equals(activeAttempt) == true
                    || candidate.UnresolvedAttemptId?.Equals(activeAttempt) == true)))
            throw new InvalidDataException(
                "The durable first GroupMessage attempt is owned by more than one target.");

        var ciphertext = target.Ciphertext;
        try
        {
            if (ciphertext is null
                || ciphertext.Length is < 1 or > MessagingV1Limits.MaxCiphertextBytes
                || !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(ciphertext), target.RequestHash.Span)
                || CryptographicOperations.FixedTimeEquals(
                    target.RatchetBeforeHash.Span, target.RatchetTransitionHash.Span))
                throw new InvalidDataException(
                    "The durable first GroupMessage attempt has inconsistent dispatch material.");
        }
        finally
        {
            if (ciphertext is not null)
                CryptographicOperations.ZeroMemory(ciphertext);
        }
        return true;
    }

    private static bool ExactTarget(LogicalTargetSnapshot left, LogicalTargetSnapshot right) =>
        left.Target.Equals(right.Target)
        && left.DirectoryHeadHash.Equals(right.DirectoryHeadHash)
        && left.State == right.State
        && Equals(left.ActiveAttemptId, right.ActiveAttemptId)
        && Equals(left.LastAttemptId, right.LastAttemptId)
        && Equals(left.UnresolvedAttemptId, right.UnresolvedAttemptId)
        && Equals(left.RequestHash, right.RequestHash)
        && Equals(left.RatchetBeforeHash, right.RatchetBeforeHash)
        && Equals(left.RatchetTransitionHash, right.RatchetTransitionHash)
        && left.OutcomeUnknown == right.OutcomeUnknown
        && Equals(left.OperationId, right.OperationId)
        && Equals(left.BindingHash, right.BindingHash)
        && CiphertextEquals(left, right);

    private static bool CiphertextEquals(LogicalTargetSnapshot left, LogicalTargetSnapshot right)
    {
        var leftBytes = left.Ciphertext;
        var rightBytes = right.Ciphertext;
        try
        {
            return leftBytes is null ? rightBytes is null
                : rightBytes is not null && leftBytes.AsSpan().SequenceEqual(rightBytes);
        }
        finally
        {
            if (leftBytes is not null) CryptographicOperations.ZeroMemory(leftBytes);
            if (rightBytes is not null) CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static void ValidateOutboxBinding(
        LogicalOutboxSnapshot outbox,
        GroupApplicationMessageRecord message,
        ReadOnlySpan<byte> canonicalDgm1)
    {
        if (!message.CanonicalBytes.Span.SequenceEqual(canonicalDgm1)
            || !outbox.EventHash.Span.SequenceEqual(SHA256.HashData(canonicalDgm1))
            || !outbox.AuthorAccountId.Span.SequenceEqual(message.Field(6).Span)
            || !outbox.AuthorDeviceId.Span.SequenceEqual(message.Field(7).Span)
            || !outbox.ConversationId.Span.SequenceEqual(message.Field(2).Span)
            || !outbox.SemanticMessageId.Span.SequenceEqual(message.Field(5).Span)
            || outbox.CreatedAt != UnixMilliseconds(message.Field(9).Span)
            || outbox.ExpiresAt != UnixMilliseconds(message.Field(10).Span)
            || outbox.ExpiresAt <= outbox.CreatedAt
            || outbox.ExpiresAt - outbox.CreatedAt > MessagingV1Limits.MaxEventLifetime)
            throw new InvalidDataException("The durable MSG-01 snapshot is not bound to exact DGM1 bytes.");
        if (!outbox.StoreScope.LocalAccountId.Equals(outbox.AuthorAccountId))
            throw new InvalidDataException("The durable DGM1 author is outside the message-store scope.");
    }

    private static DateTimeOffset UnixMilliseconds(ReadOnlySpan<byte> value)
    {
        var milliseconds = GroupMessageHeadInspection.U64(value);
        if (milliseconds > long.MaxValue)
            throw new InvalidDataException("DGM1 timestamp exceeds the signed clock domain.");
        try { return DateTimeOffset.FromUnixTimeMilliseconds((long)milliseconds); }
        catch (ArgumentOutOfRangeException exception)
        {
            throw new InvalidDataException("DGM1 timestamp is outside the supported clock domain.", exception);
        }
    }

    private static GroupMessageFirstDispatchResult Result(
        GroupMessageFirstDispatchDisposition disposition) => new(disposition);

    private static async ValueTask<GroupMessageFirstDispatchResult> BlockAsync(
        GroupHeadReadLease headLease,
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target,
        IMessageGroupDispatchSafetyHandoff capabilityIssuer,
        GroupMessageFirstDispatchDisposition disposition,
        DateTimeOffset occurredAt,
        IMessageTransactionStore messageStore,
        CancellationToken cancellationToken)
    {
        var capability = capabilityIssuer.MintLocalBlock(
            headLease, outbox, target, disposition, occurredAt);
        var applied = await messageStore.ApplyAsync(
            PreparedMessageMutation.FromLocalGroupDispatchBlock(outbox, capability),
            cancellationToken).ConfigureAwait(false);
        if (applied.CommitResult is not (MessageCommitResult.Applied
            or MessageCommitResult.Idempotent)
            || applied.Snapshot is null)
            throw new InvalidOperationException(
                $"MSG-01 could not commit the local GroupV1 safety block: {applied.CommitResult}.");
        return new GroupMessageFirstDispatchResult(disposition, applied.Snapshot);
    }
}

internal sealed record GroupMessageMemberProjection(
    MessagingAccountId32 AccountId,
    ulong AccountGeneration,
    DirectoryHeadHash32 DirectoryHeadHash,
    IReadOnlyList<GroupMessageDeviceProjection> Devices);

internal sealed record GroupMessageDeviceProjection(
    MessagingDeviceId32 DeviceId,
    byte[] Dpd1Hash);

internal static class GroupMessageHeadInspection
{
    internal static bool CurrentHeadBinds(
        GroupApplicationMessageRecord message,
        GroupHeadSnapshot head) =>
        message.Field(1).Span.SequenceEqual(head.NetworkId.Span)
        && message.Field(2).Span.SequenceEqual(head.GroupId.Span)
        && U64(message.Field(3).Span) == head.Epoch
        && CryptographicOperations.FixedTimeEquals(message.Field(4).Span, head.CommitHash.Span);

    internal static IReadOnlyList<GroupMessageMemberProjection> ReadCurrentMembers(
        GroupHeadSnapshot head)
    {
        var commit = (GroupCommitRecord)GroupCodec.Decode("DGC1", head.ExactCanonicalCommit.Span);
        var package = (GroupCommitPackageRecord)GroupCodec.Decode("GCP1", head.ExactCanonicalPackage.Span);
        var packageHash = SHA256.HashData(head.ExactCanonicalPackage.Span);
        if (!commit.ArtifactHash.Span.SequenceEqual(head.CommitHash.Span)
            || !package.ArtifactHash.Span.SequenceEqual(head.PackageHash.Span)
            || !CryptographicOperations.FixedTimeEquals(packageHash, head.ExactVerifiedGcp1Sha256.Span)
            || !commit.Field(1).Span.SequenceEqual(head.NetworkId.Span)
            || !commit.Field(2).Span.SequenceEqual(head.GroupId.Span)
            || U64(commit.Field(4).Span) != head.Epoch
            || !package.Field(1).Span.SequenceEqual(head.NetworkId.Span)
            || !package.Field(2).Span.SequenceEqual(head.GroupId.Span)
            || U64(package.Field(3).Span) != head.Epoch
            || !ReadLp32(package.Field(4).Span).SequenceEqual(head.ExactCanonicalCommit.Span))
            throw new InvalidDataException("The durable GroupV1 head is not self-consistent.");

        return ReadMembers(commit.Field(12).Span, head.MemberCount, head.DeviceCount);
    }

    internal static bool AuthorIsCurrent(
        IReadOnlyList<GroupMessageMemberProjection> members,
        MessagingAccountId32 authorAccount,
        MessagingDeviceId32 authorDevice,
        ReadOnlySpan<byte> scopedAccount,
        ulong scopedGeneration)
    {
        var member = members.SingleOrDefault(candidate => candidate.AccountId.Equals(authorAccount));
        return member is not null
            && authorAccount.Span.SequenceEqual(scopedAccount)
            && member.AccountGeneration == scopedGeneration
            && member.Devices.Count(device => device.DeviceId.Equals(authorDevice)) == 1;
    }

    internal static MessageBindingHash32 TargetBinding(
        GroupApplicationMessageRecord message,
        GroupMessageMemberProjection member,
        GroupMessageDeviceProjection device)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Group/V1/msg01-target-binding/v1\0"u8);
        hash.AppendData(message.Field(1).Span);
        hash.AppendData(message.Field(2).Span);
        hash.AppendData(message.Field(3).Span);
        hash.AppendData(message.Field(4).Span);
        hash.AppendData(member.AccountId.Span);
        hash.AppendData(device.DeviceId.Span);
        Span<byte> generation = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(generation, member.AccountGeneration);
        hash.AppendData(generation);
        hash.AppendData(member.DirectoryHeadHash.Span);
        hash.AppendData(device.Dpd1Hash);
        return MessageBindingHash32.FromBytes(hash.GetHashAndReset());
    }

    private static IReadOnlyList<GroupMessageMemberProjection> ReadMembers(
        ReadOnlySpan<byte> members,
        ushort expectedMemberCount,
        ushort expectedDeviceCount)
    {
        var result = new List<GroupMessageMemberProjection>(expectedMemberCount);
        var accounts = new HashSet<string>(StringComparer.Ordinal);
        var targets = new HashSet<string>(StringComparer.Ordinal);
        var at = 0;
        var deviceCount = 0;
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

            var account = MessagingAccountId32.FromBytes(member[..32]);
            var generation = U64(member.Slice(141, 8));
            if (generation == 0 || !accounts.Add(Convert.ToHexString(account.Span)))
                throw new InvalidDataException("The durable DGC1 account projection is invalid.");
            var directoryHead = DirectoryHeadHash32.FromBytes(member.Slice(149, 32));
            var devices = new List<GroupMessageDeviceProjection>(count);
            for (var index = 0; index < count; index++)
            {
                var row = member.Slice(220 + index * 70, 70);
                var device = MessagingDeviceId32.FromBytes(row[..32]);
                var reference = row[32..];
                if (!reference[..4].SequenceEqual("DPD1"u8)
                    || reference[4] != 0 || reference[5] != 1
                    || reference[6..].IndexOfAnyExcept((byte)0) < 0
                    || !targets.Add(Convert.ToHexString(account.Span) + Convert.ToHexString(device.Span)))
                    throw new InvalidDataException("The durable DGC1 device projection is invalid.");
                devices.Add(new GroupMessageDeviceProjection(device, reference[6..].ToArray()));
                deviceCount++;
            }
            result.Add(new GroupMessageMemberProjection(account, generation, directoryHead, devices));
        }

        if (result.Count != expectedMemberCount
            || deviceCount != expectedDeviceCount
            || result.Count is < 1 or > GroupFanoutLimits.MaximumMembers
            || deviceCount is < 1 or > GroupFanoutLimits.MaximumTargets)
            throw new InvalidDataException("The durable DGC1 counts are inconsistent.");
        return result;
    }

    internal static ulong U64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8)
            throw new InvalidDataException("GroupV1 u64 field has an invalid width.");
        return BinaryPrimitives.ReadUInt64BigEndian(value);
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

    private static void Require(ReadOnlySpan<byte> value, int at, int length)
    {
        if (at < 0 || length < 0 || length > value.Length - at)
            throw new InvalidDataException("The durable DGC1 member table is truncated.");
    }
}
