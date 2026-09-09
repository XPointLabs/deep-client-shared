using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.MessagingV1;

public abstract class MessagingBinaryValue : IEquatable<MessagingBinaryValue>, IComparable<MessagingBinaryValue>
{
    private readonly byte[] value;
    private readonly string label;

    private protected MessagingBinaryValue(ReadOnlySpan<byte> value, int length, string label)
    {
        if (value.Length != length)
        {
            throw new ArgumentException($"{label} must be exactly {length} bytes.", nameof(value));
        }

        if (value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{label} must not be all zero.", nameof(value));
        }

        this.value = value.ToArray();
        this.label = label;
    }

    public byte[] ToArray() => value.ToArray();

    internal ReadOnlySpan<byte> Span => value;

    public bool Equals(MessagingBinaryValue? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as MessagingBinaryValue);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(GetType());
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

    public int CompareTo(MessagingBinaryValue? other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (other.GetType() != GetType())
        {
            throw new ArgumentException("Binary values of different kinds cannot be ordered.", nameof(other));
        }

        return Span.SequenceCompareTo(other.Span);
    }

    public override string ToString() => $"[opaque-{label}]";
}

public sealed class SemanticMessageId32 : MessagingBinaryValue
{
    private SemanticMessageId32(ReadOnlySpan<byte> value) : base(value, 32, "semantic-message-id") { }
    public static SemanticMessageId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class ConversationId32 : MessagingBinaryValue
{
    private ConversationId32(ReadOnlySpan<byte> value) : base(value, 32, "conversation-id") { }
    public static ConversationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessagingAccountId32 : MessagingBinaryValue
{
    private MessagingAccountId32(ReadOnlySpan<byte> value) : base(value, 32, "account-id") { }
    public static MessagingAccountId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessagingDeviceId32 : MessagingBinaryValue
{
    private MessagingDeviceId32(ReadOnlySpan<byte> value) : base(value, 32, "device-id") { }
    public static MessagingDeviceId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class TransportAttemptId16 : MessagingBinaryValue
{
    private TransportAttemptId16(ReadOnlySpan<byte> value) : base(value, 16, "transport-attempt-id") { }
    public static TransportAttemptId16 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageEventHash32 : MessagingBinaryValue
{
    private MessageEventHash32(ReadOnlySpan<byte> value) : base(value, 32, "message-event-hash") { }
    public static MessageEventHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageMutationId32 : MessagingBinaryValue
{
    private MessageMutationId32(ReadOnlySpan<byte> value) : base(value, 32, "message-mutation-id") { }
    public static MessageMutationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageStoreInstanceId32 : MessagingBinaryValue
{
    private MessageStoreInstanceId32(ReadOnlySpan<byte> value) : base(value, 32, "message-store-instance-id") { }
    public static MessageStoreInstanceId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DirectoryHeadHash32 : MessagingBinaryValue
{
    private DirectoryHeadHash32(ReadOnlySpan<byte> value) : base(value, 32, "directory-head-hash") { }
    public static DirectoryHeadHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class TransportRequestHash32 : MessagingBinaryValue
{
    private TransportRequestHash32(ReadOnlySpan<byte> value) : base(value, 32, "transport-request-hash") { }
    public static TransportRequestHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class RatchetTransitionHash32 : MessagingBinaryValue
{
    private RatchetTransitionHash32(ReadOnlySpan<byte> value) : base(value, 32, "ratchet-transition-hash") { }
    public static RatchetTransitionHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class RatchetSessionId32 : MessagingBinaryValue
{
    private RatchetSessionId32(ReadOnlySpan<byte> value) : base(value, 32, "ratchet-session-id") { }
    public static RatchetSessionId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class RatchetStateHash32 : MessagingBinaryValue
{
    private RatchetStateHash32(ReadOnlySpan<byte> value) : base(value, 32, "ratchet-state-hash") { }
    public static RatchetStateHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageEvidenceHash32 : MessagingBinaryValue
{
    private MessageEvidenceHash32(ReadOnlySpan<byte> value) : base(value, 32, "message-evidence-hash") { }
    public static MessageEvidenceHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageReceiptId32 : MessagingBinaryValue
{
    private MessageReceiptId32(ReadOnlySpan<byte> value) : base(value, 32, "message-receipt-id") { }
    public static MessageReceiptId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageRecoveryOwnerId16 : MessagingBinaryValue
{
    private MessageRecoveryOwnerId16(ReadOnlySpan<byte> value) : base(value, 16, "message-recovery-owner-id") { }
    public static MessageRecoveryOwnerId16 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageTargetOperationId32 : MessagingBinaryValue
{
    private MessageTargetOperationId32(ReadOnlySpan<byte> value) : base(value, 32, "message-target-operation-id") { }
    public static MessageTargetOperationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class MessageBindingHash32 : MessagingBinaryValue
{
    private MessageBindingHash32(ReadOnlySpan<byte> value) : base(value, 32, "message-binding-hash") { }
    public static MessageBindingHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}
