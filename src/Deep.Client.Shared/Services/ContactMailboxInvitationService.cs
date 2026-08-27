using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;

namespace Deep.Client.Shared.Services;

public enum ContactMailboxInvitationError
{
    InvalidLength,
    Oversize,
    InvalidTextPrefix,
    InvalidTextEncoding,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidValidityWindow,
    NotYetValid,
    Expired,
    SessionBindingMismatch,
    InvalidSessionSignature,
    InvalidRoute,
    RouteOwnerMismatch,
    InvalidRouteIssuerSignature,
    InvalidRouteOwnerSignature,
    NonCanonical
}

public sealed class ContactMailboxInvitationException(
    ContactMailboxInvitationError error,
    string message,
    Exception? innerException = null) : Exception(message, innerException)
{
    public ContactMailboxInvitationError Error { get; } = error;
}

/// <summary>
/// Frozen, app-authenticated contact route. Registry authority and freshness verification remains
/// the responsibility of the production mailbox importer before the route becomes usable.
/// </summary>
public sealed class VerifiedContactMailboxInvitation
{
    private readonly byte[] _sessionEd25519PublicKey;
    private readonly byte[] _mailboxOwnerEd25519PublicKey;
    private readonly byte[] _canonicalRouteAdvertisement;
    private readonly byte[] _routeDomainHash;
    private readonly byte[] _canonicalRouteAdvertisementHash;

    internal VerifiedContactMailboxInvitation(
        SessionId sessionId,
        ReadOnlySpan<byte> sessionEd25519PublicKey,
        ReadOnlySpan<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlySpan<byte> canonicalRouteAdvertisement,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong routeSequence,
        ReadOnlySpan<byte> routeDomainHash,
        ReadOnlySpan<byte> canonicalRouteAdvertisementHash)
    {
        SessionId = sessionId;
        _sessionEd25519PublicKey = sessionEd25519PublicKey.ToArray();
        _mailboxOwnerEd25519PublicKey = mailboxOwnerEd25519PublicKey.ToArray();
        _canonicalRouteAdvertisement = canonicalRouteAdvertisement.ToArray();
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        RouteSequence = routeSequence;
        _routeDomainHash = routeDomainHash.ToArray();
        _canonicalRouteAdvertisementHash = canonicalRouteAdvertisementHash.ToArray();
    }

    public SessionId SessionId { get; }
    public ReadOnlyMemory<byte> SessionEd25519PublicKey => _sessionEd25519PublicKey.ToArray();
    public ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey =>
        _mailboxOwnerEd25519PublicKey.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteAdvertisement =>
        _canonicalRouteAdvertisement.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ulong RouteSequence { get; }
    public ReadOnlyMemory<byte> RouteDomainHash => _routeDomainHash.ToArray();
    public ReadOnlyMemory<byte> CanonicalRouteAdvertisementHash =>
        _canonicalRouteAdvertisementHash.ToArray();
}

/// <summary>
/// Authors and verifies the app-level CMI1 invitation. CMI1 does not change any Deep protocol wire
/// artifact: it embeds the exact canonical PRA1 bytes and adds a Session-identity signature.
/// </summary>
public static class ContactMailboxInvitationService
{
    public const int CanonicalBinaryLength = ContactMailboxInvitationCodec.CanonicalLength;

    public static string Create(
        SessionIdentityProvider sessionIdentity,
        ReadOnlySpan<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlySpan<byte> canonicalRouteAdvertisement,
        DateTimeOffset expiresAt,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(sessionIdentity);
        var clock = timeProvider ?? TimeProvider.System;
        var now = ToUnixSeconds(clock.GetUtcNow(), "Invitation clock is invalid.");
        var expires = ToUnixSeconds(expiresAt, "Invitation expiry is invalid.");
        var sessionKey = sessionIdentity.GetEd25519PublicKey();
        var sessionId = Convert.FromHexString(sessionIdentity.SessionId.Value);
        var envelope = new ContactMailboxInvitationEnvelope(
            sessionId,
            sessionKey,
            mailboxOwnerEd25519PublicKey.ToArray(),
            canonicalRouteAdvertisement.ToArray(),
            now,
            expires,
            new byte[ContactMailboxInvitationCodec.SignatureLength]);
        byte[]? signingBytes = null;
        try
        {
            ContactMailboxInvitationVerifier.VerifyRouteAndWindow(envelope, now, 0);
            signingBytes = ContactMailboxInvitationCodec.GetSigningBytes(envelope);
            var signature = sessionIdentity.SignDetached(signingBytes);
            try
            {
                return ContactMailboxInvitationCodec.EncodeText(envelope with
                {
                    Signature = signature
                });
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            if (signingBytes is not null)
                CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(sessionKey);
            CryptographicOperations.ZeroMemory(sessionId);
        }
    }

    public static VerifiedContactMailboxInvitation ParseAndVerify(
        string text,
        TimeProvider? timeProvider = null,
        uint clockSkewSeconds = ContactMailboxInvitationCodec.MaximumClockSkewSeconds)
    {
        var envelope = ContactMailboxInvitationCodec.DecodeText(text);
        var now = ToUnixSeconds(
            (timeProvider ?? TimeProvider.System).GetUtcNow(),
            "Invitation clock is invalid.");
        return ContactMailboxInvitationVerifier.Verify(envelope, now, clockSkewSeconds);
    }

    public static byte[] DecodeCanonicalText(string text) =>
        ContactMailboxInvitationCodec.Encode(ContactMailboxInvitationCodec.DecodeText(text));

    public static string EncodeCanonicalBinary(ReadOnlySpan<byte> canonicalInvitation) =>
        ContactMailboxInvitationCodec.EncodeText(
            ContactMailboxInvitationCodec.Decode(canonicalInvitation));

    public static VerifiedContactMailboxInvitation ParseAndVerify(
        ReadOnlySpan<byte> canonicalInvitation,
        TimeProvider? timeProvider = null,
        uint clockSkewSeconds = ContactMailboxInvitationCodec.MaximumClockSkewSeconds)
    {
        var envelope = ContactMailboxInvitationCodec.Decode(canonicalInvitation);
        var now = ToUnixSeconds(
            (timeProvider ?? TimeProvider.System).GetUtcNow(),
            "Invitation clock is invalid.");
        return ContactMailboxInvitationVerifier.Verify(envelope, now, clockSkewSeconds);
    }

    private static ulong ToUnixSeconds(DateTimeOffset value, string message)
    {
        var seconds = value.ToUnixTimeSeconds();
        if (seconds <= 0)
            throw Error(ContactMailboxInvitationError.InvalidField, message);
        return checked((ulong)seconds);
    }

    internal static ContactMailboxInvitationException Error(
        ContactMailboxInvitationError error,
        string message,
        Exception? innerException = null) => new(error, message, innerException);
}

internal sealed record ContactMailboxInvitationEnvelope(
    ReadOnlyMemory<byte> SessionId,
    ReadOnlyMemory<byte> SessionEd25519PublicKey,
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> CanonicalRouteAdvertisement,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> Signature);

internal static class ContactMailboxInvitationCodec
{
    internal const string TextPrefix = "deep-contact-mailbox-invitation-v1:";
    internal const int SessionIdLength = 33;
    internal const int Ed25519PublicKeyLength = 32;
    internal const int SignatureLength = 64;
    internal const int HeaderLength = 8;
    internal const int SessionIdOffset = HeaderLength;
    internal const int SessionEd25519Offset = SessionIdOffset + SessionIdLength;
    internal const int MailboxOwnerEd25519Offset =
        SessionEd25519Offset + Ed25519PublicKeyLength;
    internal const int RouteAdvertisementOffset =
        MailboxOwnerEd25519Offset + Ed25519PublicKeyLength;
    internal const int IssuedAtOffset = RouteAdvertisementOffset +
        ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength;
    internal const int ExpiresAtOffset = IssuedAtOffset + sizeof(ulong);
    internal const int SignatureOffset = ExpiresAtOffset + sizeof(ulong);
    internal const int CanonicalLength = SignatureOffset + SignatureLength;
    internal const uint MaximumClockSkewSeconds =
        ProductionMailboxRouteAdvertisementConstants.MaximumClockSkewSeconds;
    internal const ulong MaximumLifetimeSeconds =
        ProductionMailboxRouteAdvertisementConstants.MaximumLifetimeSeconds;
    internal static readonly int EncodedPayloadLength = ((CanonicalLength + 2) / 3) * 4;
    internal static readonly int CanonicalTextLength = TextPrefix.Length + EncodedPayloadLength;

    private static ReadOnlySpan<byte> Magic => "CMI1"u8;
    private static ReadOnlySpan<byte> SigningDomain =>
        "Deep/contact-mailbox-invitation/v1"u8;

    internal static byte[] GetSigningBytes(ContactMailboxInvitationEnvelope value)
    {
        var frozen = Freeze(value);
        Validate(frozen, requireSignature: false);
        return [.. SigningDomain, .. EncodeCore(frozen, includeSignature: false)];
    }

    internal static byte[] Encode(ContactMailboxInvitationEnvelope value)
    {
        var frozen = Freeze(value);
        Validate(frozen, requireSignature: true);
        return EncodeCore(frozen, includeSignature: true);
    }

    internal static string EncodeText(ContactMailboxInvitationEnvelope value)
    {
        var encoded = Encode(value);
        try
        {
            return TextPrefix + Convert.ToBase64String(encoded)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    internal static ContactMailboxInvitationEnvelope Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length > CanonicalLength)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.Oversize,
                "CMI1 exceeds its exact bounded length.");
        if (encoded.Length != CanonicalLength)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidLength,
                "CMI1 must have its exact fixed length.");

        var frozen = encoded.ToArray();
        if (!frozen.AsSpan(0, 4).SequenceEqual(Magic))
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidMagic,
                "CMI1 magic is invalid.");
        if (frozen[4] != 1)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.UnsupportedVersion,
                "CMI1 version is unsupported.");
        if (frozen.AsSpan(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.ReservedFieldNotZero,
                "CMI1 reserved bytes must be zero.");

        var value = new ContactMailboxInvitationEnvelope(
            frozen.AsMemory(SessionIdOffset, SessionIdLength).ToArray(),
            frozen.AsMemory(SessionEd25519Offset, Ed25519PublicKeyLength).ToArray(),
            frozen.AsMemory(MailboxOwnerEd25519Offset, Ed25519PublicKeyLength).ToArray(),
            frozen.AsMemory(
                RouteAdvertisementOffset,
                ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength)
                .ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(frozen.AsSpan(IssuedAtOffset, sizeof(ulong))),
            BinaryPrimitives.ReadUInt64BigEndian(frozen.AsSpan(ExpiresAtOffset, sizeof(ulong))),
            frozen.AsMemory(SignatureOffset, SignatureLength).ToArray());
        Validate(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeCore(value, includeSignature: true)))
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.NonCanonical,
                "CMI1 binary encoding is not canonical.");
        return Freeze(value);
    }

    internal static ContactMailboxInvitationEnvelope DecodeText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > CanonicalTextLength)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.Oversize,
                "CMI1 text exceeds its exact bounded length.");
        if (text.Length != CanonicalTextLength)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidLength,
                "CMI1 text must have its exact fixed length.");
        if (!text.StartsWith(TextPrefix, StringComparison.Ordinal))
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidTextPrefix,
                "CMI1 text prefix is invalid.");

        var payload = text.AsSpan(TextPrefix.Length);
        for (var index = 0; index < payload.Length; index++)
        {
            var character = payload[index];
            if (!((character >= 'A' && character <= 'Z') ||
                  (character >= 'a' && character <= 'z') ||
                  (character >= '0' && character <= '9') ||
                  character is '-' or '_'))
            {
                throw ContactMailboxInvitationService.Error(
                    ContactMailboxInvitationError.InvalidTextEncoding,
                    "CMI1 text is not canonical unpadded base64url.");
            }
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(payload.ToString()
                .Replace('-', '+')
                .Replace('_', '/'));
        }
        catch (FormatException exception)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidTextEncoding,
                "CMI1 text is not valid base64url.",
                exception);
        }

        try
        {
            var canonical = TextPrefix + Convert.ToBase64String(decoded)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
            if (!string.Equals(canonical, text, StringComparison.Ordinal))
                throw ContactMailboxInvitationService.Error(
                    ContactMailboxInvitationError.NonCanonical,
                    "CMI1 text encoding is not canonical.");
            return Decode(decoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded);
        }
    }

    private static byte[] EncodeCore(ContactMailboxInvitationEnvelope value, bool includeSignature)
    {
        var output = new byte[includeSignature ? CanonicalLength : SignatureOffset];
        Magic.CopyTo(output);
        output[4] = 1;
        value.SessionId.Span.CopyTo(output.AsSpan(SessionIdOffset));
        value.SessionEd25519PublicKey.Span.CopyTo(output.AsSpan(SessionEd25519Offset));
        value.MailboxOwnerEd25519PublicKey.Span.CopyTo(
            output.AsSpan(MailboxOwnerEd25519Offset));
        value.CanonicalRouteAdvertisement.Span.CopyTo(
            output.AsSpan(RouteAdvertisementOffset));
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(IssuedAtOffset, sizeof(ulong)),
            value.IssuedAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(
            output.AsSpan(ExpiresAtOffset, sizeof(ulong)),
            value.ExpiresAtUnixSeconds);
        if (includeSignature)
            value.Signature.Span.CopyTo(output.AsSpan(SignatureOffset));
        return output;
    }

    private static void Validate(ContactMailboxInvitationEnvelope value, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        Fixed(value.SessionId, SessionIdLength, "Session ID");
        if (value.SessionId.Span[0] != 0x05)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidField,
                "CMI1 requires a standard 05 Session ID.");
        FixedNonzero(value.SessionEd25519PublicKey, Ed25519PublicKeyLength, "Session key");
        FixedNonzero(
            value.MailboxOwnerEd25519PublicKey,
            Ed25519PublicKeyLength,
            "mailbox owner key");
        Fixed(
            value.CanonicalRouteAdvertisement,
            ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
            "PRA1");
        if (value.IssuedAtUnixSeconds == 0 ||
            value.ExpiresAtUnixSeconds <= value.IssuedAtUnixSeconds ||
            value.ExpiresAtUnixSeconds - value.IssuedAtUnixSeconds > MaximumLifetimeSeconds)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidValidityWindow,
                "CMI1 validity window is invalid or too long.");
        }
        Fixed(value.Signature, SignatureLength, "Session signature");
        if (requireSignature && value.Signature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidField,
                "CMI1 Session signature is all zero.");
    }

    private static ContactMailboxInvitationEnvelope Freeze(ContactMailboxInvitationEnvelope value) =>
        new(
            value.SessionId.ToArray(),
            value.SessionEd25519PublicKey.ToArray(),
            value.MailboxOwnerEd25519PublicKey.ToArray(),
            value.CanonicalRouteAdvertisement.ToArray(),
            value.IssuedAtUnixSeconds,
            value.ExpiresAtUnixSeconds,
            value.Signature.ToArray());

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidField,
                $"CMI1 {name} length is invalid.");
    }

    private static void FixedNonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidField,
                $"CMI1 {name} is all zero.");
    }
}

internal static class ContactMailboxInvitationVerifier
{
    private static readonly SodiumProductionMailboxRouteSignatureVerifier RouteSignatureVerifier =
        new();

    internal static VerifiedContactMailboxInvitation Verify(
        ContactMailboxInvitationEnvelope envelope,
        ulong nowUnixSeconds,
        uint clockSkewSeconds)
    {
        ValidateClock(nowUnixSeconds, clockSkewSeconds);
        var derivedSessionId = DeriveSessionId(envelope.SessionEd25519PublicKey.Span);
        if (!CryptographicOperations.FixedTimeEquals(
                derivedSessionId,
                envelope.SessionId.Span))
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.SessionBindingMismatch,
                "CMI1 Session key is not bound to its Session ID.");
        }

        var signingBytes = ContactMailboxInvitationCodec.GetSigningBytes(envelope);
        try
        {
            bool signatureValid;
            try
            {
                signatureValid = PublicKeyAuth.VerifyDetached(
                    envelope.Signature.ToArray(),
                    signingBytes,
                    envelope.SessionEd25519PublicKey.ToArray());
            }
            catch (Exception exception) when (exception is not ContactMailboxInvitationException)
            {
                throw ContactMailboxInvitationService.Error(
                    ContactMailboxInvitationError.InvalidSessionSignature,
                    "CMI1 Session signature is invalid.",
                    exception);
            }
            if (!signatureValid)
                throw ContactMailboxInvitationService.Error(
                    ContactMailboxInvitationError.InvalidSessionSignature,
                    "CMI1 Session signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingBytes);
            CryptographicOperations.ZeroMemory(derivedSessionId);
        }

        var advertisement = VerifyRouteAndWindow(envelope, nowUnixSeconds, clockSkewSeconds);
        var sessionId = SessionId.Parse(Convert.ToHexStringLower(envelope.SessionId.Span));
        var routeDomainHash = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
            advertisement.Certificate);
        var advertisementHash = SHA256.HashData(envelope.CanonicalRouteAdvertisement.Span);
        return new VerifiedContactMailboxInvitation(
            sessionId,
            envelope.SessionEd25519PublicKey.Span,
            envelope.MailboxOwnerEd25519PublicKey.Span,
            envelope.CanonicalRouteAdvertisement.Span,
            envelope.IssuedAtUnixSeconds,
            envelope.ExpiresAtUnixSeconds,
            advertisement.Sequence,
            routeDomainHash,
            advertisementHash);
    }

    internal static ProductionMailboxRouteAdvertisement VerifyRouteAndWindow(
        ContactMailboxInvitationEnvelope envelope,
        ulong nowUnixSeconds,
        uint clockSkewSeconds)
    {
        ValidateClock(nowUnixSeconds, clockSkewSeconds);
        VerifyWindow(
            envelope.IssuedAtUnixSeconds,
            envelope.ExpiresAtUnixSeconds,
            nowUnixSeconds,
            clockSkewSeconds,
            "CMI1");

        ProductionMailboxRouteAdvertisement advertisement;
        try
        {
            advertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
                envelope.CanonicalRouteAdvertisement.Span);
        }
        catch (ProductionMailboxRouteAdvertisementException exception)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidRoute,
                "CMI1 PRA1 is not structurally canonical.",
                exception);
        }

        if (!CryptographicOperations.FixedTimeEquals(
                advertisement.Certificate.MailboxOwnerEd25519PublicKey.Span,
                envelope.MailboxOwnerEd25519PublicKey.Span))
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.RouteOwnerMismatch,
                "CMI1 mailbox owner key does not match PRA1.");
        }
        if (envelope.IssuedAtUnixSeconds < advertisement.PublishedAtUnixSeconds ||
            envelope.ExpiresAtUnixSeconds > advertisement.ExpiresAtUnixSeconds)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidValidityWindow,
                "CMI1 validity window must be contained by PRA1.");
        }

        var certificateSigningBytes = ProductionMailboxRouteAdvertisementCodec
            .GetCertificateSigningBytes(advertisement.Certificate);
        if (!RouteSignatureVerifier.Verify(
                advertisement.Certificate.IssuerEd25519PublicKey.Span,
                certificateSigningBytes,
                advertisement.Certificate.IssuerSignature.Span))
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidRouteIssuerSignature,
                "CMI1 PRA1 contains an invalid issuer signature.");
        }

        var expectedSelectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(
                new BlindedPlacementId(advertisement.Certificate.BlindedPlacementId.Span));
        if (!CryptographicOperations.FixedTimeEquals(
                expectedSelectionInput,
                advertisement.Certificate.SelectionInputCommitment.Span))
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidRoute,
                "CMI1 PRA1 selection input does not match its placement ID.");
        }

        var advertisementSigningBytes = ProductionMailboxRouteAdvertisementCodec
            .GetAdvertisementSigningBytes(advertisement);
        if (!RouteSignatureVerifier.Verify(
                envelope.MailboxOwnerEd25519PublicKey.Span,
                advertisementSigningBytes,
                advertisement.OwnerSignature.Span))
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidRouteOwnerSignature,
                "CMI1 PRA1 owner signature is invalid.");
        }
        return advertisement;
    }

    private static byte[] DeriveSessionId(ReadOnlySpan<byte> sessionEd25519PublicKey)
    {
        try
        {
            var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(
                sessionEd25519PublicKey.ToArray());
            var sessionId = new byte[ContactMailboxInvitationCodec.SessionIdLength];
            sessionId[0] = 0x05;
            x25519.CopyTo(sessionId.AsSpan(1));
            CryptographicOperations.ZeroMemory(x25519);
            return sessionId;
        }
        catch (Exception exception)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.SessionBindingMismatch,
                "CMI1 Session Ed25519 key cannot derive a Session ID.",
                exception);
        }
    }

    private static void ValidateClock(ulong nowUnixSeconds, uint clockSkewSeconds)
    {
        if (nowUnixSeconds == 0 ||
            clockSkewSeconds > ContactMailboxInvitationCodec.MaximumClockSkewSeconds)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.InvalidField,
                "CMI1 verification time is incomplete or unsafe.");
        }
    }

    private static void VerifyWindow(
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong nowUnixSeconds,
        uint clockSkewSeconds,
        string name)
    {
        if (nowUnixSeconds < issuedAtUnixSeconds &&
            issuedAtUnixSeconds - nowUnixSeconds > clockSkewSeconds)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.NotYetValid,
                $"{name} is not yet valid.");
        }
        if (nowUnixSeconds > expiresAtUnixSeconds &&
            nowUnixSeconds - expiresAtUnixSeconds > clockSkewSeconds)
        {
            throw ContactMailboxInvitationService.Error(
                ContactMailboxInvitationError.Expired,
                $"{name} has expired.");
        }
    }
}
