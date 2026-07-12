using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Sodium;

namespace Deep.Client.Shared.Services;

public enum E2eeEnvelopeKind : byte
{
    Message = 1,
    Reaction = 2,
    GroupState = 3
}

public sealed class E2eeProtocolException : CryptographicException
{
    public E2eeProtocolException(string message)
        : base(message)
    {
    }

    public E2eeProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class E2eeDecodedEnvelope
{
    internal E2eeDecodedEnvelope(
        E2eeEnvelopeKind kind,
        SessionId sender,
        SessionId recipient,
        byte[] plaintext,
        byte[] envelopeDigest)
    {
        Kind = kind;
        Sender = sender;
        Recipient = recipient;
        Plaintext = plaintext;
        EnvelopeDigest = envelopeDigest;
    }

    public E2eeEnvelopeKind Kind { get; }

    public SessionId Sender { get; }

    public SessionId Recipient { get; }

    public ReadOnlyMemory<byte> Plaintext { get; }

    public ReadOnlyMemory<byte> EnvelopeDigest { get; }

    public string EnvelopeDigestHex => Convert.ToHexStringLower(EnvelopeDigest.Span);
}

public sealed class E2eeDecodedContentEnvelope
{
    internal E2eeDecodedContentEnvelope(E2eeDecodedEnvelope envelope, E2eeContent content)
    {
        Envelope = envelope;
        Content = content;
    }

    public E2eeDecodedEnvelope Envelope { get; }

    public E2eeContent Content { get; }
}

public sealed class E2eeEnvelopeCodec
{
    private static ReadOnlySpan<byte> Magic => "DPE1"u8;

    public const byte ProtocolVersion = 1;
    public const int MaxEnvelopeBytes = 512 * 1024;
    public const int SessionIdSize = 33;
    public const int Ed25519PublicKeySize = 32;
    public const int NonceSize = 12;
    public const int ContentEncryptionKeySize = 32;
    public const int WrappedContentEncryptionKeySize = 80;
    public const int AuthenticationTagSize = 16;
    public const int SignatureSize = 64;

    private const int FlagsSize = sizeof(ushort);
    private const int FixedHeaderSize =
        4 + sizeof(byte) + sizeof(byte) + FlagsSize +
        SessionIdSize + Ed25519PublicKeySize + SessionIdSize + NonceSize +
        sizeof(ushort) + sizeof(uint);
    private const int FixedEnvelopeOverhead =
        FixedHeaderSize + WrappedContentEncryptionKeySize + AuthenticationTagSize + SignatureSize;

    public const int MaxPlaintextBytes = MaxEnvelopeBytes - FixedEnvelopeOverhead;

    private readonly SessionIdentityProvider identity;

    public E2eeEnvelopeCodec(SessionIdentityProvider identity)
    {
        this.identity = identity ?? throw new ArgumentNullException(nameof(identity));
    }

    public SessionId LocalSessionId => identity.SessionId;

    public byte[] EncryptContent(E2eeContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return EncryptContent(content, content.Recipient);
    }

    public byte[] EncryptContent(E2eeContent content, SessionId envelopeRecipient)
    {
        ArgumentNullException.ThrowIfNull(content);
        var encoded = E2eeContentCodec.Encode(content);
        var senderBytes = EncodeStandardSessionId(content.Sender, nameof(content.Sender));
        var localBytes = EncodeStandardSessionId(identity.SessionId, nameof(identity));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(senderBytes, localBytes))
            {
                throw new ArgumentException("DMC1 sender must match the local signing identity.", nameof(content));
            }

            return Encrypt(ToEnvelopeKind(content.Kind), envelopeRecipient, encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
            CryptographicOperations.ZeroMemory(senderBytes);
            CryptographicOperations.ZeroMemory(localBytes);
        }
    }

    public byte[] Encrypt(E2eeEnvelopeKind kind, SessionId recipient, ReadOnlySpan<byte> plaintext)
    {
        ValidateKind(kind, nameof(kind));
        if (plaintext.Length == 0 || plaintext.Length > MaxPlaintextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext), "Envelope plaintext length is outside the DPE1 limit.");
        }

        var recipientBytes = EncodeStandardSessionId(recipient, nameof(recipient));
        var recipientPublicKey = recipientBytes.AsSpan(1).ToArray();
        var sender = identity.GetPublicSnapshot();
        var senderBytes = EncodeStandardSessionId(sender.SessionId, nameof(identity));
        var cek = RandomNumberGenerator.GetBytes(ContentEncryptionKeySize);
        byte[]? envelope = null;

        try
        {
            var wrappedCek = SealedPublicKeyBox.Create(cek, recipientPublicKey);
            if (wrappedCek.Length != WrappedContentEncryptionKeySize)
            {
                throw new CryptographicException("Sealed CEK has an unexpected length.");
            }

            var totalLength = checked(FixedEnvelopeOverhead + plaintext.Length);
            envelope = new byte[totalLength];
            var span = envelope.AsSpan();
            var offset = 0;

            Magic.CopyTo(span[offset..]);
            offset += Magic.Length;
            span[offset++] = ProtocolVersion;
            span[offset++] = (byte)kind;
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, FlagsSize), 0);
            offset += FlagsSize;
            senderBytes.CopyTo(span[offset..]);
            offset += SessionIdSize;
            sender.Ed25519PublicKey.CopyTo(span[offset..]);
            offset += Ed25519PublicKeySize;
            recipientBytes.CopyTo(span[offset..]);
            offset += SessionIdSize;

            var nonce = span.Slice(offset, NonceSize);
            RandomNumberGenerator.Fill(nonce);
            offset += NonceSize;
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(offset, sizeof(ushort)), WrappedContentEncryptionKeySize);
            offset += sizeof(ushort);
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, sizeof(uint)), checked((uint)plaintext.Length));
            offset += sizeof(uint);
            wrappedCek.CopyTo(span[offset..]);
            offset += wrappedCek.Length;

            var associatedData = span[..offset];
            var ciphertext = span.Slice(offset, plaintext.Length);
            offset += plaintext.Length;
            var tag = span.Slice(offset, AuthenticationTagSize);
            offset += AuthenticationTagSize;

            using (var aes = new AesGcm(cek, AuthenticationTagSize))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            var signedBytes = span[..offset].ToArray();
            try
            {
                var signature = identity.SignDetached(signedBytes);
                if (signature.Length != SignatureSize)
                {
                    throw new CryptographicException("Ed25519 produced an unexpected signature length.");
                }

                signature.CopyTo(span[offset..]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signedBytes);
            }

            return envelope;
        }
        catch
        {
            if (envelope is not null)
            {
                CryptographicOperations.ZeroMemory(envelope);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
            CryptographicOperations.ZeroMemory(recipientPublicKey);
            CryptographicOperations.ZeroMemory(recipientBytes);
            CryptographicOperations.ZeroMemory(senderBytes);
            CryptographicOperations.ZeroMemory(sender.Ed25519PublicKey);
            CryptographicOperations.ZeroMemory(sender.X25519PublicKey);
        }
    }

    public E2eeDecodedEnvelope Decrypt(ReadOnlySpan<byte> envelope)
    {
        try
        {
            return DecryptCore(envelope);
        }
        catch (E2eeProtocolException)
        {
            throw;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException or OverflowException)
        {
            throw new E2eeProtocolException("DPE1 envelope authentication failed.", ex);
        }
    }

    public E2eeDecodedContentEnvelope DecryptContent(
        ReadOnlySpan<byte> envelope,
        DateTimeOffset now,
        TimeSpan? maxFutureSkew = null)
    {
        var decodedEnvelope = Decrypt(envelope);
        var content = E2eeContentCodec.Decode(decodedEnvelope.Plaintext.Span, now, maxFutureSkew);
        if (decodedEnvelope.Kind != ToEnvelopeKind(content.Kind) ||
            decodedEnvelope.Sender != content.Sender)
        {
            throw InvalidEnvelope("DMC1 content is not bound to the authenticated DPE1 envelope.");
        }

        return new E2eeDecodedContentEnvelope(decodedEnvelope, content);
    }

    private E2eeDecodedEnvelope DecryptCore(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < FixedEnvelopeOverhead + 1 || envelope.Length > MaxEnvelopeBytes)
        {
            throw InvalidEnvelope("DPE1 envelope length is invalid.");
        }

        var offset = 0;
        if (!envelope.Slice(offset, Magic.Length).SequenceEqual(Magic))
        {
            throw InvalidEnvelope("DPE1 magic is invalid.");
        }

        offset += Magic.Length;
        if (envelope[offset++] != ProtocolVersion)
        {
            throw InvalidEnvelope("DPE1 version is not supported.");
        }

        var kind = (E2eeEnvelopeKind)envelope[offset++];
        ValidateKind(kind, null);

        var flags = BinaryPrimitives.ReadUInt16BigEndian(envelope.Slice(offset, FlagsSize));
        offset += FlagsSize;
        if (flags != 0)
        {
            throw InvalidEnvelope("DPE1 flags contain unsupported bits.");
        }

        var senderBytes = envelope.Slice(offset, SessionIdSize);
        var sender = DecodeStandardSessionId(senderBytes, "sender");
        offset += SessionIdSize;
        var senderEd25519PublicKey = envelope.Slice(offset, Ed25519PublicKeySize);
        offset += Ed25519PublicKeySize;
        var recipientBytes = envelope.Slice(offset, SessionIdSize);
        var recipient = DecodeStandardSessionId(recipientBytes, "recipient");
        offset += SessionIdSize;

        var localBytes = EncodeStandardSessionId(identity.SessionId, nameof(identity));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(recipientBytes, localBytes))
            {
                throw InvalidEnvelope("DPE1 envelope is not addressed to the local Session ID.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(localBytes);
        }

        ValidateSenderBinding(senderBytes, senderEd25519PublicKey);

        var nonce = envelope.Slice(offset, NonceSize);
        offset += NonceSize;
        var wrappedCekLength = BinaryPrimitives.ReadUInt16BigEndian(envelope.Slice(offset, sizeof(ushort)));
        offset += sizeof(ushort);
        var ciphertextLength = BinaryPrimitives.ReadUInt32BigEndian(envelope.Slice(offset, sizeof(uint)));
        offset += sizeof(uint);

        if (wrappedCekLength != WrappedContentEncryptionKeySize || ciphertextLength == 0 ||
            ciphertextLength > MaxPlaintextBytes)
        {
            throw InvalidEnvelope("DPE1 variable field lengths are invalid.");
        }

        var expectedLength = checked((long)FixedEnvelopeOverhead + ciphertextLength);
        if (expectedLength != envelope.Length)
        {
            throw InvalidEnvelope("DPE1 length fields do not match the envelope size.");
        }

        var wrappedCek = envelope.Slice(offset, wrappedCekLength);
        offset += wrappedCekLength;
        var associatedData = envelope[..offset];
        var ciphertext = envelope.Slice(offset, checked((int)ciphertextLength));
        offset += checked((int)ciphertextLength);
        var tag = envelope.Slice(offset, AuthenticationTagSize);
        offset += AuthenticationTagSize;
        var signature = envelope.Slice(offset, SignatureSize);

        var signedBytes = envelope[..offset].ToArray();
        try
        {
            if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), signedBytes, senderEd25519PublicKey.ToArray()))
            {
                throw InvalidEnvelope("DPE1 signature is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signedBytes);
        }

        var cek = identity.OpenSealedBox(wrappedCek.ToArray());
        if (cek.Length != ContentEncryptionKeySize)
        {
            CryptographicOperations.ZeroMemory(cek);
            throw InvalidEnvelope("DPE1 CEK length is invalid.");
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(cek, AuthenticationTagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }

        return new E2eeDecodedEnvelope(kind, sender, recipient, plaintext, SHA256.HashData(envelope));
    }

    private static void ValidateSenderBinding(ReadOnlySpan<byte> senderBytes, ReadOnlySpan<byte> senderEd25519PublicKey)
    {
        var converted = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(senderEd25519PublicKey.ToArray());
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(converted, senderBytes[1..]))
            {
                throw InvalidEnvelope("DPE1 sender signing key is not bound to the sender Session ID.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(converted);
        }
    }

    private static byte[] EncodeStandardSessionId(SessionId sessionId, string? parameterName)
    {
        SessionId parsed;
        try
        {
            parsed = SessionId.Parse(sessionId.Value);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("A valid standard Session ID is required.", parameterName, ex);
        }

        if (!parsed.Value.StartsWith("05", StringComparison.Ordinal))
        {
            throw new ArgumentException("E2EE v1 supports only standard 05 Session IDs.", parameterName);
        }

        return Convert.FromHexString(parsed.Value);
    }

    private static SessionId DecodeStandardSessionId(ReadOnlySpan<byte> bytes, string fieldName)
    {
        if (bytes.Length != SessionIdSize || bytes[0] != 0x05)
        {
            throw InvalidEnvelope($"DPE1 {fieldName} Session ID is invalid.");
        }

        return SessionId.Parse(Convert.ToHexStringLower(bytes));
    }

    private static void ValidateKind(E2eeEnvelopeKind kind, string? parameterName)
    {
        if (kind is E2eeEnvelopeKind.Message or E2eeEnvelopeKind.Reaction or E2eeEnvelopeKind.GroupState)
        {
            return;
        }

        if (parameterName is not null)
        {
            throw new ArgumentOutOfRangeException(parameterName, "Unknown DPE1 envelope kind.");
        }

        throw InvalidEnvelope("DPE1 envelope kind is not supported.");
    }

    private static E2eeEnvelopeKind ToEnvelopeKind(E2eeContentKind kind) => kind switch
    {
        E2eeContentKind.Message => E2eeEnvelopeKind.Message,
        E2eeContentKind.Reaction => E2eeEnvelopeKind.Reaction,
        E2eeContentKind.GroupState => E2eeEnvelopeKind.GroupState,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), "Unknown DMC1 content kind.")
    };

    private static E2eeProtocolException InvalidEnvelope(string message) => new(message);
}
