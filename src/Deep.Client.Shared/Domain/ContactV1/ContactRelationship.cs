using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Domain.ContactV1;

public enum ContactRelationshipState
{
    Absent = 0,
    BundleVerified = 1,
    RequestQueued = 2,
    RemoteStoreAccepted = 3,
    RequestMaterialized = 4,
    PeerAccepted = 5,
    Active = 6,
    Rejected = 7,
    Expired = 8,
    Blocked = 9,
    Deleted = 10,
    IdentityConflict = 11,
    DirectoryConflict = 12,
    RouteStale = 13,
}

public abstract class ContactIdentifier32 : IEquatable<ContactIdentifier32>, IComparable<ContactIdentifier32>
{
    private readonly byte[] value;
    private readonly string label;

    private protected ContactIdentifier32(ReadOnlySpan<byte> value, string label)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{label} must be exactly 32 nonzero bytes.", nameof(value));
        this.value = value.ToArray();
        this.label = label;
    }

    public byte[] ToArray() => value.ToArray();
    internal ReadOnlySpan<byte> Span => value;

    public bool Equals(ContactIdentifier32? other) =>
        other is not null
        && other.GetType() == GetType()
        && CryptographicOperations.FixedTimeEquals(value, other.value);
    public override bool Equals(object? obj) => Equals(obj as ContactIdentifier32);
    public override int GetHashCode() { var hash = new HashCode(); hash.Add(GetType()); hash.AddBytes(value); return hash.ToHashCode(); }
    public int CompareTo(ContactIdentifier32? other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if (other.GetType() != GetType())
            throw new ArgumentException("Contact identifiers of different kinds cannot be ordered.", nameof(other));
        return value.AsSpan().SequenceCompareTo(other.value);
    }
    public override string ToString() => $"[opaque-{label}]";
}

public sealed class ContactRelationshipId32 : ContactIdentifier32
{
    private ContactRelationshipId32(ReadOnlySpan<byte> value) : base(value, "contact-relationship-id") { }
    public static ContactRelationshipId32 FromBytes(ReadOnlySpan<byte> value) => new(value);
}

public sealed class ContactConversationId32 : ContactIdentifier32
{
    public const string DerivationDomain = "Deep/Application/V1/contact-conversation";

    private ContactConversationId32(ReadOnlySpan<byte> value) : base(value, "contact-conversation-id") { }
    public static ContactConversationId32 FromBytes(ReadOnlySpan<byte> value) => new(value);

    public static ContactConversationId32 Derive(
        ReadOnlySpan<byte> networkId16,
        ContactRelationshipId32 relationshipId,
        ReadOnlySpan<byte> accountA32,
        ReadOnlySpan<byte> accountB32)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        RequireNonzero(networkId16, 16, nameof(networkId16));
        RequireNonzero(accountA32, 32, nameof(accountA32));
        RequireNonzero(accountB32, 32, nameof(accountB32));
        if (accountA32.SequenceEqual(accountB32))
            throw new ArgumentException("A contact conversation requires two distinct accounts.", nameof(accountB32));

        var first = accountA32.SequenceCompareTo(accountB32) < 0 ? accountA32 : accountB32;
        var second = accountA32.SequenceCompareTo(accountB32) < 0 ? accountB32 : accountA32;
        Span<byte> material = stackalloc byte[112];
        networkId16.CopyTo(material);
        relationshipId.Span.CopyTo(material[16..]);
        first.CopyTo(material[48..]);
        second.CopyTo(material[80..]);

        var label = Encoding.ASCII.GetBytes(DerivationDomain);
        var preimage = new byte[label.Length + 5 + material.Length];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(label.Length + 1, 4), checked((uint)material.Length));
        material.CopyTo(preimage.AsSpan(label.Length + 5));
        return new ContactConversationId32(SHA256.HashData(preimage));
    }

    private static void RequireNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"Value must be exactly {length} nonzero bytes.", name);
    }
}
