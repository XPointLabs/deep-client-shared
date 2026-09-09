using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Client.Shared.Services.MessagingV1;

internal sealed class PreparedMessagingDao1 : IDisposable
{
    private byte[]? canonical;

    internal PreparedMessagingDao1(
        ParsedDao1 parsed,
        MessagingV1DepositKind kind,
        ReadOnlySpan<byte> canonical)
    {
        Parsed = parsed ?? throw new ArgumentNullException(nameof(parsed));
        Kind = kind;
        this.canonical = canonical.ToArray();
    }

    internal ParsedDao1 Parsed { get; }
    internal MessagingV1DepositKind Kind { get; }
    internal ReadOnlyMemory<byte> Canonical =>
        (canonical ?? throw new ObjectDisposedException(nameof(PreparedMessagingDao1))).ToArray();

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref canonical, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

internal sealed class MessagingDao1Opened : IDisposable
{
    private byte[]? exactInner;

    internal MessagingDao1Opened(
        ParsedDao1 parsed,
        MessagingV1DepositKind kind,
        ReadOnlySpan<byte> exactInner)
    {
        Parsed = parsed ?? throw new ArgumentNullException(nameof(parsed));
        Kind = kind;
        this.exactInner = exactInner.ToArray();
    }

    internal ParsedDao1 Parsed { get; }
    internal MessagingV1DepositKind Kind { get; }
    internal ReadOnlyMemory<byte> ExactInner =>
        (exactInner ?? throw new ObjectDisposedException(nameof(MessagingDao1Opened))).ToArray();

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref exactInner, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

internal interface IMessagingDao1OpenAuthority
{
    ValueTask<MessagingDao1Opened> OpenAsync(
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Owns one protected per-account PRF seed. The seed never leaves this object.
/// Stable derivation makes retries and crash recovery reproduce byte-identical
/// DAO1 while every distinct inner operation receives an independent
/// pseudorandom deposit ID, X25519 ephemeral scalar and nonce.
/// </summary>
internal sealed class MessagingDao1SealingAuthority : IDisposable
{
    private static ReadOnlySpan<byte> ContextDomain =>
        "Deep/Client/MSG01/DAO1/context-v1"u8;
    private byte[]? seed;

    internal MessagingDao1SealingAuthority(ReadOnlySpan<byte> protectedSeed32)
    {
        if (protectedSeed32.Length != 32 || protectedSeed32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DAO1 sealing seed must contain exactly 32 nonzero bytes.", nameof(protectedSeed32));
        seed = protectedSeed32.ToArray();
    }

    internal PreparedMessagingDao1 Seal(
        MessagingV1LocalContext local,
        VerifiedMessagingRecipientDeposit recipient,
        ReadOnlySpan<byte> exactInner)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(recipient);
        var kind = MessagingDao1Crypto.ValidateOutboundInner(local, recipient, exactInner);
        var innerHash = SHA256.HashData(exactInner);
        var sourceOperationId = kind == MessagingV1DepositKind.InitialSession
            ? Dph2Codec.Decode(exactInner).ClaimOperationId.ToArray()
            : Dpe2Codec.Decode(exactInner).OperationId.ToArray();
        var context = BuildContext(local, recipient, sourceOperationId, innerHash);
        var operationId = Derive("operation", context, 32);
        var ephemeralPrivate = Derive("ephemeral", context, 32);
        var nonce = Derive("nonce", context, 24);
        byte[]? ephemeralPublic = null;
        byte[]? shared = null;
        byte[]? key = null;
        byte[]? plaintext = null;
        byte[]? ciphertext = null;
        byte[]? canonical = null;
        try
        {
            ephemeralPublic = ScalarMult.Base(ephemeralPrivate);
            MessagingDao1Crypto.RequireNonzero(ephemeralPublic, "derived DAO1 ephemeral public key");
            shared = ScalarMult.Mult(ephemeralPrivate, recipient.SealingPublicKey.ToArray());
            MessagingDao1Crypto.RequireNonzero(shared, "DAO1 X25519 shared secret");

            var placeholder = ApplicationCoreCodec.AuthorDao1(
                local.NetworkId,
                recipient.SealingKeyId,
                operationId,
                ephemeralPublic,
                nonce,
                new byte[checked(exactInner.Length + 16)]);
            key = MessagingDao1Crypto.DeriveKey(
                local.NetworkId,
                recipient.SealingKeyId,
                ephemeralPublic,
                operationId,
                shared);
            plaintext = exactInner.ToArray();
            ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(
                plaintext, nonce, key, placeholder.AeadHeader.ToArray());
            var parsed = ApplicationCoreCodec.AuthorDao1(
                local.NetworkId,
                recipient.SealingKeyId,
                operationId,
                ephemeralPublic,
                nonce,
                ciphertext);
            canonical = parsed.CanonicalBytes.ToArray();
            var result = new PreparedMessagingDao1(parsed, kind, canonical);
            canonical = null;
            return result;
        }
        catch (Exception exception) when (exception is not (ArgumentException or CryptographicException))
        {
            throw new CryptographicException("DAO1 sealing failed closed.", exception);
        }
        finally
        {
            Zero(innerHash); Zero(sourceOperationId); Zero(context); Zero(operationId);
            Zero(ephemeralPrivate); Zero(ephemeralPublic); Zero(shared); Zero(key);
            Zero(plaintext); Zero(ciphertext); Zero(canonical);
        }
    }

    public void Dispose() => Zero(Interlocked.Exchange(ref seed, null));

    private byte[] Derive(string purpose, ReadOnlySpan<byte> context, int length)
    {
        var current = seed ?? throw new ObjectDisposedException(nameof(MessagingDao1SealingAuthority));
        var purposeBytes = Encoding.ASCII.GetBytes("Deep/Client/MSG01/DAO1/" + purpose + "-v1");
        var input = new byte[checked(purposeBytes.Length + 1 + context.Length + 1)];
        purposeBytes.CopyTo(input, 0);
        context.CopyTo(input.AsSpan(purposeBytes.Length + 1));
        try
        {
            for (byte counter = 1; counter != 0; counter++)
            {
                input[^1] = counter;
                var block = HMACSHA512.HashData(current, input);
                try
                {
                    var output = block[..length];
                    if (output.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                        return output;
                    CryptographicOperations.ZeroMemory(output);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(block);
                }
            }
            throw new CryptographicException("DAO1 deterministic entropy derivation failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(purposeBytes);
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static byte[] BuildContext(
        MessagingV1LocalContext local,
        VerifiedMessagingRecipientDeposit recipient,
        ReadOnlySpan<byte> sourceOperationId,
        ReadOnlySpan<byte> innerHash)
    {
        var result = new byte[
            ContextDomain.Length + 16 + 32 + 32 + sizeof(ulong) +
            32 + 32 + sizeof(ulong) + sizeof(ulong) + 32 + sizeof(ulong) +
            32 + 32 + 32];
        var offset = 0;
        Append(result, ref offset, ContextDomain);
        Append(result, ref offset, local.NetworkId);
        Append(result, ref offset, local.AccountId);
        Append(result, ref offset, local.DeviceId);
        WriteU64(result, ref offset, local.DeviceGeneration);
        Append(result, ref offset, recipient.AccountId);
        Append(result, ref offset, recipient.DeviceId);
        WriteU64(result, ref offset, recipient.AccountGeneration);
        WriteU64(result, ref offset, recipient.DirectoryGeneration);
        Append(result, ref offset, recipient.SealingKeyId);
        WriteU64(result, ref offset, recipient.DeviceGeneration);
        Append(result, ref offset, sourceOperationId);
        Append(result, ref offset, innerHash);
        Append(result, ref offset, recipient.Selector.ScopeId.Span);
        if (offset != result.Length)
            throw new InvalidOperationException("DAO1 stable context size is inconsistent.");
        return result;
    }

    private static void Append(Span<byte> destination, ref int offset, ReadOnlySpan<byte> value)
    {
        value.CopyTo(destination[offset..]);
        offset += value.Length;
    }

    private static void WriteU64(Span<byte> destination, ref int offset, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination[offset..], value);
        offset += sizeof(ulong);
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

/// <summary>
/// Owns one current recipient metadata-sealing X25519 key. No long-lived raw key
/// or derived content key is exposed to its caller.
/// </summary>
internal sealed class ManagedMessagingDao1OpenAuthority : IMessagingDao1OpenAuthority, IDisposable
{
    private readonly byte[] networkId;
    private readonly byte[] sealingKeyId;
    private readonly byte[] sealingPublicKey;
    private byte[]? sealingPrivateScalar;

    internal ManagedMessagingDao1OpenAuthority(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> sealingPublicKey,
        ReadOnlySpan<byte> sealingPrivateScalar)
    {
        MessagingDao1Crypto.RequireExactNonzero(networkId, 16, nameof(networkId));
        MessagingDao1Crypto.RequireExactNonzero(sealingKeyId, 32, nameof(sealingKeyId));
        MessagingDao1Crypto.RequireExactNonzero(sealingPublicKey, 32, nameof(sealingPublicKey));
        MessagingDao1Crypto.RequireExactNonzero(sealingPrivateScalar, 32, nameof(sealingPrivateScalar));
        var privateCopy = sealingPrivateScalar.ToArray();
        var actual = ScalarMult.Base(privateCopy);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(actual, sealingPublicKey))
                throw new CryptographicException("DAO1 opening key does not match the verified reachability public key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateCopy);
            CryptographicOperations.ZeroMemory(actual);
        }
        this.networkId = networkId.ToArray();
        this.sealingKeyId = sealingKeyId.ToArray();
        this.sealingPublicKey = sealingPublicKey.ToArray();
        this.sealingPrivateScalar = sealingPrivateScalar.ToArray();
    }

    public ValueTask<MessagingDao1Opened> OpenAsync(
        ReadOnlyMemory<byte> exactDao1,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var scalar = sealingPrivateScalar ??
            throw new ObjectDisposedException(nameof(ManagedMessagingDao1OpenAuthority));
        var parsed = ApplicationCoreCodec.DecodeDao1(exactDao1.Span);
        if (!MessagingDao1Crypto.Fixed(parsed.CanonicalBytes.Span, exactDao1.Span) ||
            !MessagingDao1Crypto.Fixed(parsed.NetworkId.Span, networkId) ||
            !MessagingDao1Crypto.Fixed(parsed.SealingKeyId.Span, sealingKeyId))
            throw new CryptographicException("DAO1 is outside the current local reachability key context.");

        byte[]? shared = null;
        byte[]? privateCopy = null;
        byte[]? key = null;
        byte[]? plaintext = null;
        try
        {
            privateCopy = scalar.ToArray();
            shared = ScalarMult.Mult(privateCopy, parsed.EphemeralX25519PublicKey.ToArray());
            MessagingDao1Crypto.RequireNonzero(shared, "DAO1 X25519 shared secret");
            key = MessagingDao1Crypto.DeriveKey(
                networkId,
                sealingKeyId,
                parsed.EphemeralX25519PublicKey.Span,
                parsed.DepositOperationId.Span,
                shared);
            plaintext = SecretAeadXChaCha20Poly1305.Decrypt(
                parsed.SealedRecord.ToArray(), parsed.Nonce.ToArray(), key,
                parsed.AeadHeader.ToArray());
            var kind = MessagingDao1Crypto.ValidateCanonicalInner(plaintext);
            var result = new MessagingDao1Opened(parsed, kind, plaintext);
            return ValueTask.FromResult(result);
        }
        catch (Exception exception) when (exception is not CryptographicException)
        {
            throw new CryptographicException("DAO1 opening failed closed.", exception);
        }
        finally
        {
            MessagingDao1SealingAuthorityZero(shared);
            MessagingDao1SealingAuthorityZero(privateCopy);
            MessagingDao1SealingAuthorityZero(key);
            MessagingDao1SealingAuthorityZero(plaintext);
        }
    }

    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref sealingPrivateScalar, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }

    private static void MessagingDao1SealingAuthorityZero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }
}

internal static class MessagingDao1Crypto
{
    private static ReadOnlySpan<byte> MailboxOperationDomain =>
        "Deep/Client/MSG01/DAO1/mailbox-operation-v1"u8;

    internal static MessagingV1DepositKind ValidateOutboundInner(
        MessagingV1LocalContext local,
        VerifiedMessagingRecipientDeposit recipient,
        ReadOnlySpan<byte> exactInner)
    {
        if (!Fixed(local.NetworkId, recipient.NetworkId))
            throw new CryptographicException("The local and recipient network contexts differ.");
        var kind = ValidateCanonicalInner(exactInner);
        if (kind == MessagingV1DepositKind.InitialSession)
        {
            var record = Dph2Codec.Decode(exactInner);
            if (!Fixed(record.NetworkId.Span, local.NetworkId) ||
                !Fixed(record.InitiatorAccountId.Span, local.AccountId) ||
                !Fixed(record.InitiatorDeviceId.Span, local.DeviceId) ||
                record.InitiatorDeviceGeneration != local.DeviceGeneration ||
                !Fixed(record.ResponderAccountId.Span, recipient.AccountId) ||
                !Fixed(record.ResponderDeviceId.Span, recipient.DeviceId) ||
                record.ResponderDeviceGeneration != recipient.DeviceGeneration)
                throw new CryptographicException("DPH2 is outside the verified sender/recipient generation context.");
        }
        else
        {
            var record = Dpe2Codec.Decode(exactInner);
            if (!Fixed(record.NetworkId.Span, local.NetworkId) ||
                !Fixed(record.SenderDeviceId.Span, local.DeviceId) ||
                !Fixed(record.RecipientDeviceId.Span, recipient.DeviceId))
                throw new CryptographicException("DPE2 is outside the verified sender/recipient context.");
        }
        return kind;
    }

    internal static MessagingV1DepositKind ValidateCanonicalInner(ReadOnlySpan<byte> exactInner)
    {
        if (exactInner.Length < 4)
            throw new CryptographicException("DAO1 plaintext is not a canonical DPH2 or DPE2.");
        byte[] roundTrip;
        MessagingV1DepositKind kind;
        if (exactInner[..4].SequenceEqual("DPH2"u8))
        {
            roundTrip = Dph2Codec.Encode(Dph2Codec.Decode(exactInner));
            kind = MessagingV1DepositKind.InitialSession;
        }
        else if (exactInner[..4].SequenceEqual("DPE2"u8))
        {
            roundTrip = Dpe2Codec.Encode(Dpe2Codec.Decode(exactInner));
            kind = MessagingV1DepositKind.EstablishedSession;
        }
        else
        {
            throw new CryptographicException("DAO1 plaintext magic is not DPH2 or DPE2.");
        }
        try
        {
            if (!Fixed(roundTrip, exactInner))
                throw new CryptographicException("DAO1 plaintext failed canonical round-trip.");
            return kind;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roundTrip);
        }
    }

    internal static byte[] DeriveKey(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> sealingKeyId,
        ReadOnlySpan<byte> ephemeralPublicKey,
        ReadOnlySpan<byte> depositOperationId,
        ReadOnlySpan<byte> sharedSecret)
    {
        var saltValue = new byte[80];
        networkId.CopyTo(saltValue);
        sealingKeyId.CopyTo(saltValue.AsSpan(16));
        ephemeralPublicKey.CopyTo(saltValue.AsSpan(48));
        var saltInput = DomainHashInput("Deep/Application/V1/deposit-salt", saltValue);
        var salt = SHA512.HashData(saltInput);
        var prk = new byte[64];
        var key = new byte[32];
        var label = Encoding.ASCII.GetBytes("Deep/Application/V1/deposit-key");
        var info = new byte[checked(label.Length + 1 + 4 + depositOperationId.Length)];
        label.CopyTo(info, 0);
        BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(label.Length + 1), checked((uint)depositOperationId.Length));
        depositOperationId.CopyTo(info.AsSpan(label.Length + 5));
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA512, sharedSecret, salt, prk) != prk.Length)
                throw new CryptographicException("DAO1 HKDF extract returned an unexpected length.");
            HKDF.Expand(HashAlgorithmName.SHA512, prk, key, info);
            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltValue);
            CryptographicOperations.ZeroMemory(saltInput);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(label);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    internal static byte[] DeriveMailboxOperationId(
        ReadOnlySpan<byte> dao1OperationId)
    {
        RequireExactNonzero(dao1OperationId, 32, nameof(dao1OperationId));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(MailboxOperationDomain);
        hash.AppendData(dao1OperationId);
        var full = hash.GetHashAndReset();
        try
        {
            var result = full[..MailboxClientLimits.OperationIdLength];
            if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new CryptographicException(
                    "The derived mailbox operation ID is invalid.");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(full);
        }
    }

    internal static byte[] DomainHashInput(string label, ReadOnlySpan<byte> value)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var output = new byte[checked(labelBytes.Length + 1 + 4 + value.Length)];
        labelBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(labelBytes.Length + 1), checked((uint)value.Length));
        value.CopyTo(output.AsSpan(labelBytes.Length + 5));
        CryptographicOperations.ZeroMemory(labelBytes);
        return output;
    }

    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static void RequireExactNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must contain exactly {length} nonzero bytes.", name);
    }

    internal static void RequireNonzero(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException($"The {name} is invalid.");
    }
}
