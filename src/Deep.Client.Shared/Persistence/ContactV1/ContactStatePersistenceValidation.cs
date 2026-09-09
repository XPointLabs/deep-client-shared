using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

internal static class ContactStatePersistenceValidation
{
    internal static PendingContactAddress CloneAndValidate(PendingContactAddress pending)
    {
        ArgumentNullException.ThrowIfNull(pending);
        var address = pending.Address;
        var network = address.NetworkId.ToArray();
        var canonical = address.CanonicalBytes.ToArray();
        try
        {
            ValidateCanonical(address.Kind, network, canonical, address.CanonicalText,
                address.ExpiresAtUnixSeconds);
            return new PendingContactAddress(
                new ImportedContactAddress(address.Kind, network, canonical,
                    address.CanonicalText, address.ExpiresAtUnixSeconds),
                pending.ImportedAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(canonical);
        }
    }

    internal static PendingContactAddress Restore(
        int rawKind,
        byte[] networkId,
        byte[] canonicalBytes,
        string canonicalText,
        byte[]? expiresAt,
        long importedAtUtcTicks)
    {
        if (!Enum.IsDefined((ContactAddressKind)rawKind))
            throw new FormatException("Persisted contact address kind is invalid.");
        if (importedAtUtcTicks < 0 || importedAtUtcTicks > DateTimeOffset.MaxValue.Ticks)
            throw new FormatException("Persisted contact import time is invalid.");
        var kind = (ContactAddressKind)rawKind;
        ulong? expiry = expiresAt is null ? null : ReadU64(expiresAt);
        ValidateCanonical(kind, networkId, canonicalBytes, canonicalText, expiry);
        return new PendingContactAddress(
            new ImportedContactAddress(kind, networkId, canonicalBytes, canonicalText, expiry),
            new DateTimeOffset(importedAtUtcTicks, TimeSpan.Zero));
    }

    internal static void ValidateLookup(ContactAddressKind kind, ReadOnlySpan<byte> canonical)
    {
        if (!Enum.IsDefined(kind))
            throw new ArgumentOutOfRangeException(nameof(kind));
        var expected = kind == ContactAddressKind.PermanentDeepId ? 76 : 225;
        if (canonical.Length != expected)
            throw new ArgumentException("The exact canonical contact address has the wrong size.", nameof(canonical));
        if (kind == ContactAddressKind.PermanentDeepId)
            _ = ApplicationCoreCodec.DecodeDid1(canonical);
        else
            _ = ContactCodec.Decode("DIA1", canonical);
    }

    internal static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    internal static ulong ReadU64(byte[] value) => value.Length == 8
        ? BinaryPrimitives.ReadUInt64BigEndian(value)
        : throw new FormatException("Persisted unsigned integer must contain exactly eight bytes.");

    private static void ValidateCanonical(
        ContactAddressKind kind,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> canonical,
        string canonicalText,
        ulong? expiry)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Persisted contact network ID is invalid.");
        ArgumentException.ThrowIfNullOrEmpty(canonicalText);

        switch (kind)
        {
            case ContactAddressKind.PermanentDeepId:
            {
                if (expiry is not null)
                    throw new FormatException("A permanent Deep ID cannot carry an expiry.");
                var did = ApplicationCoreCodec.DecodeDid1(canonical);
                if (!string.Equals(did.Text, canonicalText, StringComparison.Ordinal))
                    throw new FormatException("Persisted permanent Deep ID text is non-canonical.");
                break;
            }
            case ContactAddressKind.OneTimeInvitation:
            {
                var invitation = ContactCodec.Decode("DIA1", canonical);
                if (!CryptographicOperations.FixedTimeEquals(networkId, invitation.Field(1).Span)
                    || expiry is null
                    || expiry != BinaryPrimitives.ReadUInt64BigEndian(invitation.Field(8).Span)
                    || !string.Equals(DeepInvitationTextCodec.EncodeCanonical(invitation),
                        canonicalText, StringComparison.Ordinal))
                {
                    throw new FormatException("Persisted one-time invitation closure is inconsistent.");
                }
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }
    }
}
