using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.AccountDirectoryV1;

public abstract class AccountDirectoryBinaryValue : IEquatable<AccountDirectoryBinaryValue>, IComparable<AccountDirectoryBinaryValue>
{
    private readonly byte[] value;
    private readonly string label;

    private protected AccountDirectoryBinaryValue(ReadOnlySpan<byte> value, int length, string label)
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
    public bool Equals(AccountDirectoryBinaryValue? other) => other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as AccountDirectoryBinaryValue);
    public override int GetHashCode() { var hash = new HashCode(); hash.Add(GetType()); hash.AddBytes(value); return hash.ToHashCode(); }
    public int CompareTo(AccountDirectoryBinaryValue? other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (other.GetType() != GetType()) throw new ArgumentException("Values of different kinds cannot be ordered.", nameof(other));
        return Span.SequenceCompareTo(other.Span);
    }
    public override string ToString() => $"[opaque-{label}]";
}

public sealed class AccountDirectoryLeafKey32 : AccountDirectoryBinaryValue
{
    private AccountDirectoryLeafKey32(ReadOnlySpan<byte> value) : base(value, 32, "directory-leaf-key") { }
    public static AccountDirectoryLeafKey32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class AccountDirectoryHash32 : AccountDirectoryBinaryValue
{
    private AccountDirectoryHash32(ReadOnlySpan<byte> value) : base(value, 32, "directory-hash") { }
    public static AccountDirectoryHash32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class AccountDirectoryAuthorizationId32 : AccountDirectoryBinaryValue
{
    private AccountDirectoryAuthorizationId32(ReadOnlySpan<byte> value) : base(value, 32, "authorization-id") { }
    public static AccountDirectoryAuthorizationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class AccountDirectoryDeviceId32 : AccountDirectoryBinaryValue
{
    private AccountDirectoryDeviceId32(ReadOnlySpan<byte> value) : base(value, 32, "device-id") { }
    public static AccountDirectoryDeviceId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class AccountDirectoryStoreId32 : AccountDirectoryBinaryValue
{
    private AccountDirectoryStoreId32(ReadOnlySpan<byte> value) : base(value, 32, "store-id") { }
    public static AccountDirectoryStoreId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}
