using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.MessagingV1;

public static class MessagingV1Limits
{
    public const int MaxFanoutTargets = 500;
    public const int MaxCanonicalEventBytes = 32 * 1024;
    public const int MaxCiphertextBytes = 64 * 1024;
    public const int MaxAuthenticatedEvidenceBytes = 64 * 1024;
    public const int MaxSealedRatchetStateBytes = 64 * 1024;
    public const int MaxRecoveryBatch = 256;
    public static readonly TimeSpan MaxEventLifetime = TimeSpan.FromDays(365);
    public static readonly TimeSpan MaxRecoveryLease = TimeSpan.FromMinutes(5);
}

public enum LogicalOutboxState
{
    Queued = 1, FanoutPrepared = 2, Sending = 3, PartiallyAccepted = 4,
    Accepted = 5, OutcomeUnknown = 6, RecipientMaterialized = 7,
    Expired = 8, Cancelled = 9, TerminalRejected = 10
}

public enum LogicalTargetState
{
    Pending = 1, Accepted = 2, Materialized = 3, Expired = 4,
    RevokedTarget = 5, TerminalRejected = 6
}

public enum MessagePayloadKind
{
    DirectMessage = 1,
    GroupMessage = 2,
    GroupState = 3,
    GroupMailboxRoutes = 4
}

public sealed class MessageRevisionExhaustedException : InvalidOperationException
{
    public MessageRevisionExhaustedException()
        : base("The canonical MSG-01 revision domain is exhausted.") { }
}

public sealed class MessageStoreScope : IEquatable<MessageStoreScope>
{
    public MessageStoreScope(
        MessagingAccountId32 localAccountId, ulong databaseGeneration,
        MessageStoreInstanceId32 storeInstanceId)
    {
        ArgumentNullException.ThrowIfNull(localAccountId);
        ArgumentNullException.ThrowIfNull(storeInstanceId);
        if (databaseGeneration == 0) throw new ArgumentOutOfRangeException(nameof(databaseGeneration));
        LocalAccountId = MessagingAccountId32.FromBytes(localAccountId.Span);
        DatabaseGeneration = databaseGeneration;
        StoreInstanceId = MessageStoreInstanceId32.FromBytes(storeInstanceId.Span);
    }
    public MessagingAccountId32 LocalAccountId { get; }
    public ulong DatabaseGeneration { get; }
    public MessageStoreInstanceId32 StoreInstanceId { get; }
    public bool Equals(MessageStoreScope? other) => other is not null
        && LocalAccountId.Equals(other.LocalAccountId)
        && DatabaseGeneration == other.DatabaseGeneration
        && StoreInstanceId.Equals(other.StoreInstanceId);
    public override bool Equals(object? obj) => Equals(obj as MessageStoreScope);
    public override int GetHashCode() => HashCode.Combine(LocalAccountId, DatabaseGeneration, StoreInstanceId);
    public override string ToString() => "[opaque-message-store-scope]";
}

public sealed class RecipientDeviceTarget : IEquatable<RecipientDeviceTarget>, IComparable<RecipientDeviceTarget>
{
    public RecipientDeviceTarget(MessagingAccountId32 accountId, MessagingDeviceId32 deviceId)
    {
        ArgumentNullException.ThrowIfNull(accountId);
        ArgumentNullException.ThrowIfNull(deviceId);
        AccountId = MessagingAccountId32.FromBytes(accountId.Span);
        DeviceId = MessagingDeviceId32.FromBytes(deviceId.Span);
    }
    public MessagingAccountId32 AccountId { get; }
    public MessagingDeviceId32 DeviceId { get; }
    public bool Equals(RecipientDeviceTarget? other) => other is not null
        && AccountId.Equals(other.AccountId) && DeviceId.Equals(other.DeviceId);
    public override bool Equals(object? obj) => Equals(obj as RecipientDeviceTarget);
    public override int GetHashCode() => HashCode.Combine(AccountId, DeviceId);
    public int CompareTo(RecipientDeviceTarget? other)
    {
        ArgumentNullException.ThrowIfNull(other);
        var account = AccountId.CompareTo(other.AccountId);
        return account != 0 ? account : DeviceId.CompareTo(other.DeviceId);
    }
    public override string ToString() => "[opaque-recipient-device]";
}

public sealed class SemanticClaimKey : IEquatable<SemanticClaimKey>
{
    public SemanticClaimKey(
        MessagingAccountId32 authorAccountId, ConversationId32 conversationId,
        SemanticMessageId32 semanticMessageId)
    {
        ArgumentNullException.ThrowIfNull(authorAccountId);
        ArgumentNullException.ThrowIfNull(conversationId);
        ArgumentNullException.ThrowIfNull(semanticMessageId);
        AuthorAccountId = MessagingAccountId32.FromBytes(authorAccountId.Span);
        ConversationId = ConversationId32.FromBytes(conversationId.Span);
        SemanticMessageId = SemanticMessageId32.FromBytes(semanticMessageId.Span);
    }
    // Device evidence is deliberately not part of equality or the durable
    // semantic key.  It exists only to bind an outbound record and to update
    // duplicate-delivery evidence without duplicating the event.
    public SemanticClaimKey(MessagingAccountId32 authorAccountId, MessagingDeviceId32 authorDeviceId,
        ConversationId32 conversationId, SemanticMessageId32 semanticMessageId)
        : this(authorAccountId, conversationId, semanticMessageId)
    {
        ArgumentNullException.ThrowIfNull(authorDeviceId);
        AuthorDeviceId = MessagingDeviceId32.FromBytes(authorDeviceId.Span);
    }
    public MessagingAccountId32 AuthorAccountId { get; }
    public MessagingDeviceId32? AuthorDeviceId { get; }
    public ConversationId32 ConversationId { get; }
    public SemanticMessageId32 SemanticMessageId { get; }
    public bool Equals(SemanticClaimKey? other) => other is not null
        && AuthorAccountId.Equals(other.AuthorAccountId)
        && ConversationId.Equals(other.ConversationId)
        && SemanticMessageId.Equals(other.SemanticMessageId);
    public override bool Equals(object? obj) => Equals(obj as SemanticClaimKey);
    public override int GetHashCode() => HashCode.Combine(AuthorAccountId, ConversationId, SemanticMessageId);
    public override string ToString() => "[opaque-semantic-claim-key]";
}

public sealed class FanoutTargetSeed : IComparable<FanoutTargetSeed>
{
    public FanoutTargetSeed(RecipientDeviceTarget target, DirectoryHeadHash32 directoryHeadHash,
        MessageTargetOperationId32 operationId, MessageBindingHash32 bindingHash)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(directoryHeadHash);
        Target = new(target.AccountId, target.DeviceId);
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(directoryHeadHash.Span);
        OperationId = MessageTargetOperationId32.FromBytes(operationId.Span);
        BindingHash = MessageBindingHash32.FromBytes(bindingHash.Span);
    }
    public RecipientDeviceTarget Target { get; }
    public MessagingAccountId32 AccountId => Target.AccountId;
    public MessagingDeviceId32 DeviceId => Target.DeviceId;
    public DirectoryHeadHash32 DirectoryHeadHash { get; }
    public MessageTargetOperationId32 OperationId { get; }
    public MessageBindingHash32 BindingHash { get; }
    public int CompareTo(FanoutTargetSeed? other) => Target.CompareTo(
        other?.Target ?? throw new ArgumentNullException(nameof(other)));
}

public sealed class LogicalTargetSnapshot
{
    private readonly byte[]? ciphertext;
    internal LogicalTargetSnapshot(
        RecipientDeviceTarget target, DirectoryHeadHash32 directoryHeadHash,
        LogicalTargetState state, TransportAttemptId16? activeAttemptId,
        TransportAttemptId16? lastAttemptId, TransportAttemptId16? unresolvedAttemptId,
        TransportRequestHash32? requestHash, RatchetTransitionHash32? ratchetTransitionHash,
        bool outcomeUnknown, MessageTargetOperationId32? operationId = null,
        MessageBindingHash32? bindingHash = null,
        ReadOnlySpan<byte> ciphertext = default,
        RatchetStateHash32? ratchetBeforeHash = null)
    {
        Target = new(target.AccountId, target.DeviceId);
        DirectoryHeadHash = DirectoryHeadHash32.FromBytes(directoryHeadHash.Span);
        State = state;
        ActiveAttemptId = Copy(activeAttemptId);
        LastAttemptId = Copy(lastAttemptId);
        UnresolvedAttemptId = Copy(unresolvedAttemptId);
        RequestHash = requestHash is null ? null : TransportRequestHash32.FromBytes(requestHash.Span);
        RatchetBeforeHash = ratchetBeforeHash is null
            ? null : RatchetStateHash32.FromBytes(ratchetBeforeHash.Span);
        RatchetTransitionHash = ratchetTransitionHash is null
            ? null : RatchetTransitionHash32.FromBytes(ratchetTransitionHash.Span);
        OutcomeUnknown = outcomeUnknown;
        OperationId = operationId is null ? null : MessageTargetOperationId32.FromBytes(operationId.Span);
        BindingHash = bindingHash is null ? null : MessageBindingHash32.FromBytes(bindingHash.Span);
        this.ciphertext = ciphertext.IsEmpty ? null : ciphertext.ToArray();
    }
    public RecipientDeviceTarget Target { get; }
    public DirectoryHeadHash32 DirectoryHeadHash { get; }
    public LogicalTargetState State { get; }
    public TransportAttemptId16? ActiveAttemptId { get; }
    public TransportAttemptId16? LastAttemptId { get; }
    public TransportAttemptId16? UnresolvedAttemptId { get; }
    public TransportRequestHash32? RequestHash { get; }
    public RatchetStateHash32? RatchetBeforeHash { get; }
    public RatchetTransitionHash32? RatchetTransitionHash { get; }
    public bool OutcomeUnknown { get; }
    public MessageTargetOperationId32? OperationId { get; }
    public MessageBindingHash32? BindingHash { get; }
    public byte[]? Ciphertext => ciphertext?.ToArray();
    private static TransportAttemptId16? Copy(TransportAttemptId16? value) =>
        value is null ? null : TransportAttemptId16.FromBytes(value.Span);
}

public sealed class MessageRecoveryLease
{
    internal MessageRecoveryLease(MessageRecoveryOwnerId16 ownerId, DateTimeOffset expiresAt)
    {
        OwnerId = MessageRecoveryOwnerId16.FromBytes(ownerId.Span);
        ExpiresAt = LogicalOutboxSeed.Canonical(expiresAt);
    }
    public MessageRecoveryOwnerId16 OwnerId { get; }
    public DateTimeOffset ExpiresAt { get; }
}

public sealed class LogicalOutboxSnapshot
{
    private readonly LogicalTargetSnapshot[] targets;
    private readonly byte[] canonicalPayload;
    internal LogicalOutboxSnapshot(
        MessageStoreScope storeScope, SemanticClaimKey claimKey,
        MessagingDeviceId32 authorDeviceId, MessageEventHash32 eventHash,
        ReadOnlySpan<byte> canonicalPayload,
        DateTimeOffset createdAt, DateTimeOffset expiresAt,
        LogicalOutboxState state, ulong revision,
        IEnumerable<LogicalTargetSnapshot> targets, MessageRecoveryLease? recoveryLease = null,
        MessagePayloadKind payloadKind = MessagePayloadKind.DirectMessage)
    {
        StoreScope = Copy(storeScope);
        ClaimKey = claimKey.AuthorDeviceId is null ? new(claimKey.AuthorAccountId, claimKey.ConversationId, claimKey.SemanticMessageId) : new(claimKey.AuthorAccountId, claimKey.AuthorDeviceId, claimKey.ConversationId, claimKey.SemanticMessageId);
        AuthorDeviceId = MessagingDeviceId32.FromBytes(authorDeviceId.Span);
        EventHash = MessageEventHash32.FromBytes(eventHash.Span);
        this.canonicalPayload = canonicalPayload.ToArray();
        if (this.canonicalPayload.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(this.canonicalPayload), EventHash.Span))
            throw new ArgumentException("MSG-01 canonical payload does not match its event hash.");
        CreatedAt = LogicalOutboxSeed.Canonical(createdAt);
        ExpiresAt = LogicalOutboxSeed.Canonical(expiresAt);
        State = state;
        if (!Enum.IsDefined(payloadKind)) throw new ArgumentOutOfRangeException(nameof(payloadKind));
        PayloadKind = payloadKind;
        Revision = revision;
        this.targets = targets.Select(CloneTarget).ToArray();
        RecoveryLease = recoveryLease is null ? null : new(recoveryLease.OwnerId, recoveryLease.ExpiresAt);
    }
    public MessageStoreScope StoreScope { get; }
    public MessagingAccountId32 LocalAccountId => StoreScope.LocalAccountId;
    public SemanticClaimKey ClaimKey { get; }
    public MessagingAccountId32 AuthorAccountId => ClaimKey.AuthorAccountId;
    public MessagingDeviceId32 AuthorDeviceId { get; }
    public ConversationId32 ConversationId => ClaimKey.ConversationId;
    public SemanticMessageId32 SemanticMessageId => ClaimKey.SemanticMessageId;
    public MessageEventHash32 EventHash { get; }
    public byte[] CanonicalPayload => canonicalPayload.ToArray();
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public LogicalOutboxState State { get; }
    public MessagePayloadKind PayloadKind { get; }
    public ulong Revision { get; }
    public MessageRecoveryLease? RecoveryLease { get; }
    public IReadOnlyList<LogicalTargetSnapshot> Targets => Array.AsReadOnly(targets.Select(CloneTarget).ToArray());
    public TransportAttemptId16? ActiveAttemptId
    {
        get
        {
            var attempts = targets.Where(static x => x.ActiveAttemptId is not null)
                .Select(static x => x.ActiveAttemptId!).Distinct().ToArray();
            return attempts.Length == 1 ? TransportAttemptId16.FromBytes(attempts[0].Span) : null;
        }
    }
    public bool HasAcceptedCiphertext => targets.Any(static target =>
        target.State is LogicalTargetState.Accepted or LogicalTargetState.Materialized);
    internal static MessageStoreScope Copy(MessageStoreScope scope) =>
        new(scope.LocalAccountId, scope.DatabaseGeneration, scope.StoreInstanceId);
    internal static LogicalTargetSnapshot CloneTarget(LogicalTargetSnapshot item) => new(
        item.Target, item.DirectoryHeadHash, item.State, item.ActiveAttemptId, item.LastAttemptId,
        item.UnresolvedAttemptId, item.RequestHash, item.RatchetTransitionHash, item.OutcomeUnknown,
        item.OperationId, item.BindingHash, item.Ciphertext ?? [], item.RatchetBeforeHash);
}

public sealed class LogicalOutboxSeed
{
    private readonly byte[] canonicalPayload;
    private LogicalOutboxSeed(
        MessageStoreScope storeScope, SemanticClaimKey claimKey,
        MessagingDeviceId32 authorDeviceId, MessageEventHash32 eventHash,
        ReadOnlySpan<byte> canonicalPayload,
        DateTimeOffset createdAt, DateTimeOffset expiresAt, MessagePayloadKind payloadKind)
    {
        StoreScope = LogicalOutboxSnapshot.Copy(storeScope);
        ClaimKey = new(claimKey.AuthorAccountId, authorDeviceId, claimKey.ConversationId, claimKey.SemanticMessageId);
        AuthorDeviceId = MessagingDeviceId32.FromBytes(authorDeviceId.Span);
        EventHash = MessageEventHash32.FromBytes(eventHash.Span);
        this.canonicalPayload = canonicalPayload.ToArray();
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        PayloadKind = payloadKind;
    }
    public MessageStoreScope StoreScope { get; }
    public MessagingAccountId32 LocalAccountId => StoreScope.LocalAccountId;
    public SemanticClaimKey ClaimKey { get; }
    public MessagingAccountId32 AuthorAccountId => ClaimKey.AuthorAccountId;
    public MessagingDeviceId32 AuthorDeviceId { get; }
    public ConversationId32 ConversationId => ClaimKey.ConversationId;
    public SemanticMessageId32 SemanticMessageId => ClaimKey.SemanticMessageId;
    public MessageEventHash32 EventHash { get; }
    public byte[] CanonicalPayload => canonicalPayload.ToArray();
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
    public MessagePayloadKind PayloadKind { get; }
    public static LogicalOutboxSeed CreateOutbound(
        MessageStoreScope storeScope, MessagingDeviceId32 localAuthorDeviceId,
        ConversationId32 conversationId, SemanticMessageId32 semanticMessageId,
        MessageEventHash32 eventHash, ReadOnlySpan<byte> canonicalPayload,
        DateTimeOffset createdAt, DateTimeOffset expiresAt,
        MessagePayloadKind payloadKind = MessagePayloadKind.DirectMessage)
    {
        ArgumentNullException.ThrowIfNull(storeScope);
        ArgumentNullException.ThrowIfNull(localAuthorDeviceId);
        ArgumentNullException.ThrowIfNull(conversationId);
        ArgumentNullException.ThrowIfNull(semanticMessageId);
        ArgumentNullException.ThrowIfNull(eventHash);
        if (!Enum.IsDefined(payloadKind)) throw new ArgumentOutOfRangeException(nameof(payloadKind));
        createdAt = Canonical(createdAt);
        expiresAt = Canonical(expiresAt);
        if (createdAt <= DateTimeOffset.UnixEpoch || expiresAt <= createdAt
            || expiresAt - createdAt > MessagingV1Limits.MaxEventLifetime)
            throw new ArgumentOutOfRangeException(nameof(expiresAt));
        if (canonicalPayload.Length is < 1 or > MessagingV1Limits.MaxCanonicalEventBytes
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(canonicalPayload), eventHash.Span))
            throw new ArgumentException("Canonical payload must exactly match eventHash.", nameof(canonicalPayload));
        return new(storeScope, new(storeScope.LocalAccountId, localAuthorDeviceId, conversationId, semanticMessageId),
            localAuthorDeviceId, eventHash, canonicalPayload, createdAt, expiresAt, payloadKind);
    }
    internal static DateTimeOffset Canonical(DateTimeOffset value) =>
        DateTimeOffset.FromUnixTimeMilliseconds(value.ToUnixTimeMilliseconds());
}

public sealed class MessageTombstone
{
    internal MessageTombstone(LogicalOutboxSnapshot snapshot, DateTimeOffset retainedAt)
    {
        StoreScope = LogicalOutboxSnapshot.Copy(snapshot.StoreScope);
        ClaimKey = new(snapshot.AuthorAccountId, snapshot.AuthorDeviceId, snapshot.ConversationId, snapshot.SemanticMessageId);
        EventHash = MessageEventHash32.FromBytes(snapshot.EventHash.Span);
        TerminalState = snapshot.State;
        RetainedAt = LogicalOutboxSeed.Canonical(retainedAt);
    }
    public MessageStoreScope StoreScope { get; }
    public SemanticClaimKey ClaimKey { get; }
    public MessageEventHash32 EventHash { get; }
    public LogicalOutboxState TerminalState { get; }
    public DateTimeOffset RetainedAt { get; }
}

public sealed class InboxEventSnapshot
{
    private readonly byte[] canonicalEvent;
    private readonly MessagingDeviceId32[] observedAuthorDevices;
    internal InboxEventSnapshot(
        MessageStoreScope scope, SemanticClaimKey claimKey, MessageEventHash32 eventHash,
        ReadOnlySpan<byte> canonicalEvent, DateTimeOffset materializedAt,
        MessageReceiptId32 receiptId, IEnumerable<MessagingDeviceId32> observedAuthorDevices)
    {
        StoreScope = LogicalOutboxSnapshot.Copy(scope);
        ClaimKey = claimKey.AuthorDeviceId is null ? new(claimKey.AuthorAccountId, claimKey.ConversationId, claimKey.SemanticMessageId) : new(claimKey.AuthorAccountId, claimKey.AuthorDeviceId, claimKey.ConversationId, claimKey.SemanticMessageId);
        EventHash = MessageEventHash32.FromBytes(eventHash.Span);
        this.canonicalEvent = canonicalEvent.ToArray();
        MaterializedAt = LogicalOutboxSeed.Canonical(materializedAt);
        ReceiptId = MessageReceiptId32.FromBytes(receiptId.Span);
        this.observedAuthorDevices = observedAuthorDevices
            .Select(static value => MessagingDeviceId32.FromBytes(value.Span))
            .OrderBy(static value => value).ToArray();
    }
    public MessageStoreScope StoreScope { get; }
    public SemanticClaimKey ClaimKey { get; }
    public MessageEventHash32 EventHash { get; }
    public byte[] CanonicalEvent => canonicalEvent.ToArray();
    public DateTimeOffset MaterializedAt { get; }
    public MessageReceiptId32 ReceiptId { get; }
    public IReadOnlyList<MessagingDeviceId32> ObservedAuthorDevices =>
        Array.AsReadOnly(observedAuthorDevices
            .Select(static value => MessagingDeviceId32.FromBytes(value.Span)).ToArray());
}

public sealed class PendingMessageReceipt
{
    private readonly byte[] authenticatedReceipt;
    internal PendingMessageReceipt(
        MessageReceiptId32 receiptId, SemanticClaimKey claimKey,
        MessageEvidenceHash32 evidenceHash, ReadOnlySpan<byte> authenticatedReceipt,
        DateTimeOffset createdAt, MessageRecoveryLease? lease)
    {
        ReceiptId = MessageReceiptId32.FromBytes(receiptId.Span);
        ClaimKey = new(claimKey.AuthorAccountId, claimKey.ConversationId, claimKey.SemanticMessageId);
        EvidenceHash = MessageEvidenceHash32.FromBytes(evidenceHash.Span);
        this.authenticatedReceipt = authenticatedReceipt.ToArray();
        CreatedAt = LogicalOutboxSeed.Canonical(createdAt);
        Lease = lease is null ? null : new(lease.OwnerId, lease.ExpiresAt);
    }
    public MessageReceiptId32 ReceiptId { get; }
    public SemanticClaimKey ClaimKey { get; }
    public MessageEvidenceHash32 EvidenceHash { get; }
    public byte[] AuthenticatedReceipt => authenticatedReceipt.ToArray();
    public DateTimeOffset CreatedAt { get; }
    public MessageRecoveryLease? Lease { get; }
}
