using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.DeviceV1;

public abstract class DeviceBinaryValue : IEquatable<DeviceBinaryValue>, IComparable<DeviceBinaryValue>
{
    private readonly byte[] value;
    private readonly string label;

    private protected DeviceBinaryValue(ReadOnlySpan<byte> value, int length, string label)
    {
        if (value.Length != length)
            throw new ArgumentException($"{label} must be exactly {length} bytes.", nameof(value));
        if (value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{label} must not be all zero.", nameof(value));

        this.value = value.ToArray();
        this.label = label;
    }

    public byte[] ToArray() => value.ToArray();
    internal ReadOnlySpan<byte> Span => value;

    public bool Equals(DeviceBinaryValue? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);

    public override bool Equals(object? obj) => Equals(obj as DeviceBinaryValue);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(GetType());
        hash.AddBytes(value);
        return hash.ToHashCode();
    }

    public int CompareTo(DeviceBinaryValue? other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (other.GetType() != GetType())
            throw new ArgumentException("Device binary values of different kinds cannot be ordered.", nameof(other));
        return Span.SequenceCompareTo(other.Span);
    }

    public override string ToString() => $"[opaque-{label}]";
}

public sealed class DeviceAccountId32 : DeviceBinaryValue
{
    private DeviceAccountId32(ReadOnlySpan<byte> value) : base(value, 32, "device-account-id") { }
    public static DeviceAccountId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceIdentifier32 : DeviceBinaryValue
{
    private DeviceIdentifier32(ReadOnlySpan<byte> value) : base(value, 32, "device-id") { }
    public static DeviceIdentifier32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceDirectoryHash32 : DeviceBinaryValue
{
    private DeviceDirectoryHash32(ReadOnlySpan<byte> value) : base(value, 32, "device-directory-hash") { }
    public static DeviceDirectoryHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceRevocationHash32 : DeviceBinaryValue
{
    private DeviceRevocationHash32(ReadOnlySpan<byte> value) : base(value, 32, "device-revocation-hash") { }
    public static DeviceRevocationHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceCertificateHash32 : DeviceBinaryValue
{
    private DeviceCertificateHash32(ReadOnlySpan<byte> value) : base(value, 32, "device-certificate-hash") { }
    public static DeviceCertificateHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceOperationId32 : DeviceBinaryValue
{
    private DeviceOperationId32(ReadOnlySpan<byte> value) : base(value, 32, "device-operation-id") { }
    public static DeviceOperationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class LogicalMessageId32 : DeviceBinaryValue
{
    private LogicalMessageId32(ReadOnlySpan<byte> value) : base(value, 32, "logical-message-id") { }
    public static LogicalMessageId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceContactWorkItemId32 : DeviceBinaryValue
{
    private DeviceContactWorkItemId32(ReadOnlySpan<byte> value) : base(value, 32, "contact-work-item-id") { }
    public static DeviceContactWorkItemId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class DeviceGroupWorkItemId32 : DeviceBinaryValue
{
    private DeviceGroupWorkItemId32(ReadOnlySpan<byte> value) : base(value, 32, "group-work-item-id") { }
    public static DeviceGroupWorkItemId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}
