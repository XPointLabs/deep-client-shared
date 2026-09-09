using System.Security.Cryptography;

namespace Deep.Client.Shared.Domain.ContactV1;

public enum ContactAddressKind
{
    PermanentDeepId = 1,
    OneTimeInvitation = 2,
}

public sealed class ImportedContactAddress : IEquatable<ImportedContactAddress>
{
    private readonly byte[] networkId;
    private readonly byte[] canonicalBytes;

    internal ImportedContactAddress(
        ContactAddressKind kind,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> canonicalBytes,
        string canonicalText,
        ulong? expiresAtUnixSeconds)
    {
        if (kind is not (ContactAddressKind.PermanentDeepId or ContactAddressKind.OneTimeInvitation))
            throw new ArgumentOutOfRangeException(nameof(kind));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be exactly 16 nonzero bytes.", nameof(networkId));
        if (canonicalBytes.IsEmpty)
            throw new ArgumentException("Canonical contact address bytes are required.", nameof(canonicalBytes));
        ArgumentException.ThrowIfNullOrEmpty(canonicalText);
        if (kind == ContactAddressKind.PermanentDeepId && expiresAtUnixSeconds is not null)
            throw new ArgumentException("A permanent Deep ID cannot expire.", nameof(expiresAtUnixSeconds));
        if (kind == ContactAddressKind.OneTimeInvitation && expiresAtUnixSeconds is null or 0)
            throw new ArgumentException("A one-time invitation requires its signed expiry.", nameof(expiresAtUnixSeconds));

        Kind = kind;
        this.networkId = networkId.ToArray();
        this.canonicalBytes = canonicalBytes.ToArray();
        CanonicalText = canonicalText;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ContactAddressKind Kind { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes => canonicalBytes.ToArray();
    public string CanonicalText { get; }
    public ulong? ExpiresAtUnixSeconds { get; }
    public bool IsPermanent => Kind == ContactAddressKind.PermanentDeepId;

    public bool Equals(ImportedContactAddress? other) =>
        other is not null
        && Kind == other.Kind
        && CryptographicOperations.FixedTimeEquals(networkId, other.networkId)
        && CryptographicOperations.FixedTimeEquals(canonicalBytes, other.canonicalBytes);

    public override bool Equals(object? obj) => Equals(obj as ImportedContactAddress);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Kind);
        hash.AddBytes(networkId);
        hash.AddBytes(canonicalBytes);
        return hash.ToHashCode();
    }

    public override string ToString() => $"[{Kind} contact address]";
}

/// <summary>
/// A locally imported address before any resolver, directory or bundle proof
/// has been accepted. It deliberately carries no relationship identifiers.
/// </summary>
public sealed class PendingContactAddress
{
    internal PendingContactAddress(ImportedContactAddress address, DateTimeOffset importedAt)
    {
        Address = address ?? throw new ArgumentNullException(nameof(address));
        ImportedAt = importedAt.ToUniversalTime();
    }

    public ImportedContactAddress Address { get; }
    public DateTimeOffset ImportedAt { get; }
    public ContactRelationshipState RelationshipState => ContactRelationshipState.Absent;
    public ContactRelationshipId32? RelationshipId => null;
    public ContactConversationId32? ConversationId => null;
    public bool BundleVerified => false;
}
