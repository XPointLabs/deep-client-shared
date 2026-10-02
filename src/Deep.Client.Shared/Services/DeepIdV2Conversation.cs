using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Services;

/// <summary>Account-owned, key-free selection metadata. Not a trust,
/// acceptance, transport, ratchet or acknowledgement capability.</summary>
public sealed class DeepIdV2Conversation
{
    internal DeepIdV2Conversation(Did2MessagingSessionScope scope) => Scope = scope;
    internal Did2MessagingSessionScope Scope { get; }
    public string ConversationId => Convert.ToHexString(Scope.Conversation);
    public string PeerAccountId => Convert.ToHexString(Scope.RemoteAccount);
    public bool IsInitiator => Scope.IsInitiator;
    public override string ToString() => nameof(DeepIdV2Conversation);
}

public enum DeepIdV2ContactState
{
    IncomingRequest = 1, OutgoingRequest = 2, LocalAcceptanceRetained = 3, PeerAcceptanceRetained = 4,
}

/// <summary>Freshly verified projection; use of its handle rechecks custody.</summary>
public sealed class DeepIdV2ConversationSnapshot
{
    internal DeepIdV2ConversationSnapshot(DeepIdV2Conversation conversation, DeepIdV2ContactState state)
    { Conversation = conversation; ContactState = state; }
    public DeepIdV2Conversation Conversation { get; }
    public DeepIdV2ContactState ContactState { get; }
    public override string ToString() => nameof(DeepIdV2ConversationSnapshot);
}

/// <summary>Mailbox storage receipt, not remote consent, semantic receipt or ACK.</summary>
public sealed class DeepIdV2ContactStartResult
{
    internal DeepIdV2ContactStartResult(DeepIdV2Conversation conversation, ClientMailboxStoreResult receipt)
    { Conversation = conversation; StorageReceipt = receipt; }
    public DeepIdV2Conversation Conversation { get; }
    public ClientMailboxStoreResult StorageReceipt { get; }
    public override string ToString() => nameof(DeepIdV2ContactStartResult);
}

/// <summary>Local retry metadata only; not peer or transport authority.</summary>
public sealed class DeepIdV2ContactOperationSnapshot
{
    private readonly byte[] intent;
    internal DeepIdV2ContactOperationSnapshot(ReadOnlySpan<byte> intent, ReadOnlySpan<byte> peerDid2Hash, ulong created, ulong expires)
    { this.intent = intent.ToArray(); PeerDid2Hash = Convert.ToHexString(peerDid2Hash); CreatedAtUnixMilliseconds = created; ExpiresAtUnixMilliseconds = expires; }
    public ReadOnlyMemory<byte> LogicalIntent => intent.ToArray();
    public string PeerDid2Hash { get; }
    public ulong CreatedAtUnixMilliseconds { get; }
    public ulong ExpiresAtUnixMilliseconds { get; }
    public override string ToString() => nameof(DeepIdV2ContactOperationSnapshot);
}

/// <summary>Local original-command retry data, not network or delivery authority.</summary>
public sealed class DeepIdV2PendingTextSnapshot
{
    private readonly byte[] operation;
    internal DeepIdV2PendingTextSnapshot(ReadOnlySpan<byte> operation, string conversationId, string text, ulong sequence)
    { this.operation = operation.ToArray(); ConversationId = conversationId; Text = text; SenderSequence = sequence; }
    public ReadOnlyMemory<byte> LogicalOperation => operation.ToArray();
    public string ConversationId { get; }
    public string Text { get; }
    public ulong SenderSequence { get; }
    public override string ToString() => nameof(DeepIdV2PendingTextSnapshot);
}
