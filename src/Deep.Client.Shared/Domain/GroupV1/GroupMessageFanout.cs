using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Domain.GroupV1;

public enum GroupMessageFanoutDisposition
{
    Staged = 1,
    Idempotent = 2,
    NoRemoteTargets = 3,
    GroupNotFound = 4,
    StaleGroupState = 5,
    ForkLatched = 6,
    MessageForkLatched = 7,
    Conflict = 8,
}

public sealed class GroupMessageFanoutTarget
{
    internal GroupMessageFanoutTarget(
        RecipientDeviceTarget target,
        ulong accountGeneration,
        DirectoryHeadHash32 directoryHeadHash,
        MessageTargetOperationId32 operationId,
        MessageBindingHash32 bindingHash)
    {
        if (accountGeneration == 0) throw new ArgumentOutOfRangeException(nameof(accountGeneration));
        Target = new RecipientDeviceTarget(target.AccountId, target.DeviceId);
        AccountGeneration = accountGeneration;
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(directoryHeadHash.Span);
        OperationId = MessageTargetOperationId32.FromBytes(operationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(bindingHash.Span);
    }

    public RecipientDeviceTarget Target { get; }
    public ulong AccountGeneration { get; }
    public DirectoryHeadHash32 DirectoryHeadHash { get; }
    public MessageTargetOperationId32 OperationId { get; }
    public MessageBindingHash32 BindingHash { get; }
}

public sealed record GroupMessageFanoutResult(
    GroupMessageFanoutDisposition Disposition,
    GroupFanoutBatchId32 BatchId,
    GroupId32 GroupId,
    ulong Epoch,
    SemanticMessageId32 SemanticMessageId,
    LogicalOutboxSnapshot? LogicalOutbox);

public enum GroupMessageFirstDispatchDisposition
{
    Dispatched = 1,
    GroupNotFound = 2,
    StaleGroupState = 3,
    ForkLatched = 4,
    NoTarget = 5,
    TargetRemoved = 6,
    NotFirstDispatch = 7,
}

public sealed class GroupMessageFirstDispatchResult
{
    internal GroupMessageFirstDispatchResult(
        GroupMessageFirstDispatchDisposition disposition,
        LogicalOutboxSnapshot? blockedSnapshot = null)
    {
        Disposition = disposition;
        BlockedSnapshot = blockedSnapshot;
    }

    public GroupMessageFirstDispatchDisposition Disposition { get; }
    internal LogicalOutboxSnapshot? BlockedSnapshot { get; }
}

/// <summary>
/// Defensive, callback-scoped input for the first real dispatch of one durable
/// active group attempt. It carries no cryptographic or transport authority
/// and is disposed immediately after the callback completes.
/// </summary>
public sealed class GroupMessageFirstDispatchContext : IDisposable
{
    private byte[]? canonicalDgm1;
    private byte[]? ciphertext;

    internal GroupMessageFirstDispatchContext(
        LogicalOutboxSnapshot outbox,
        LogicalTargetSnapshot target)
    {
        StoreScope = new MessageStoreScope(
            outbox.StoreScope.LocalAccountId,
            outbox.StoreScope.DatabaseGeneration,
            outbox.StoreScope.StoreInstanceId);
        ClaimKey = new SemanticClaimKey(
            outbox.AuthorAccountId,
            outbox.AuthorDeviceId,
            outbox.ConversationId,
            outbox.SemanticMessageId);
        EventHash = MessageEventHash32.FromBytes(outbox.EventHash.Span);
        Target = new RecipientDeviceTarget(target.Target.AccountId, target.Target.DeviceId);
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(target.DirectoryHeadHash.Span);
        OperationId = MessageTargetOperationId32.FromBytes(
            (target.OperationId ?? throw new InvalidOperationException(
                "The first-dispatch target has no operation ID.")).Span);
        BindingHash = MessageBindingHash32.FromBytes(
            (target.BindingHash ?? throw new InvalidOperationException(
                "The first-dispatch target has no binding hash.")).Span);
        AttemptId = TransportAttemptId16.FromBytes(
            (target.ActiveAttemptId ?? throw new InvalidOperationException(
                "The first-dispatch target has no active attempt ID.")).Span);
        RequestHash = TransportRequestHash32.FromBytes(
            (target.RequestHash ?? throw new InvalidOperationException(
                "The first-dispatch target has no request hash.")).Span);
        RatchetBeforeHash = RatchetStateHash32.FromBytes(
            (target.RatchetBeforeHash ?? throw new InvalidOperationException(
                "The first-dispatch target has no prior ratchet hash.")).Span);
        RatchetTransitionHash = RatchetTransitionHash32.FromBytes(
            (target.RatchetTransitionHash ?? throw new InvalidOperationException(
                "The first-dispatch target has no ratchet transition hash.")).Span);
        OutboxRevision = outbox.Revision;
        canonicalDgm1 = outbox.CanonicalPayload;
        ciphertext = target.Ciphertext ?? throw new InvalidOperationException(
            "The first-dispatch target has no durable ciphertext.");
    }

    public MessageStoreScope StoreScope { get; }
    public SemanticClaimKey ClaimKey { get; }
    public MessageEventHash32 EventHash { get; }
    public RecipientDeviceTarget Target { get; }
    public DirectoryHeadHash32 DirectoryHeadHash { get; }
    public MessageTargetOperationId32 OperationId { get; }
    public MessageBindingHash32 BindingHash { get; }
    public TransportAttemptId16 AttemptId { get; }
    public TransportRequestHash32 RequestHash { get; }
    public RatchetStateHash32 RatchetBeforeHash { get; }
    public RatchetTransitionHash32 RatchetTransitionHash { get; }
    public ulong OutboxRevision { get; }

    public ReadOnlyMemory<byte> CanonicalDgm1
    {
        get
        {
            ObjectDisposedException.ThrowIf(canonicalDgm1 is null, this);
            return canonicalDgm1.ToArray();
        }
    }

    public ReadOnlyMemory<byte> Ciphertext
    {
        get
        {
            ObjectDisposedException.ThrowIf(ciphertext is null, this);
            return ciphertext.ToArray();
        }
    }

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref canonicalDgm1, null);
        if (owned is not null)
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(owned);
        owned = Interlocked.Exchange(ref ciphertext, null);
        if (owned is not null)
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(owned);
    }
}

/// <summary>
/// Narrow handoff for one already-durable, current-membership-authorized device
/// target. A future DPE2 implementation owns encryption and network delivery;
/// GroupV1 deliberately provides no fallback or synthetic crypto implementation.
/// </summary>
public interface IGroupMessageDeviceDispatcher
{
    ValueTask DispatchAsync(
        GroupMessageFirstDispatchContext context,
        CancellationToken cancellationToken = default);
}
