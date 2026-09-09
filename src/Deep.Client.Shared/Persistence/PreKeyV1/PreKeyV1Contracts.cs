using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Persistence.PreKeyV1;

internal static class PreKeyV1Limits
{
    internal const int NetworkIdSize = 16;
    internal const int IdentifierSize = 32;
    internal const int Dpd1ReferenceSize = 38;
    internal const int SqlCipherKeySize = 32;
    internal const int MaximumProviderSecretSize = 4096;
}

internal sealed class PreKeyV1StoreScope
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] dpd1Reference;
    private readonly byte[] dpd1Hash;

    internal PreKeyV1StoreScope(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> dpd1Reference,
        ReadOnlySpan<byte> dpd1Hash,
        ulong databaseGeneration)
    {
        ValidateNonZero(networkId, PreKeyV1Limits.NetworkIdSize, nameof(networkId));
        ValidateNonZero(accountId, PreKeyV1Limits.IdentifierSize, nameof(accountId));
        ValidateNonZero(deviceId, PreKeyV1Limits.IdentifierSize, nameof(deviceId));
        ValidateNonZero(dpd1Hash, PreKeyV1Limits.IdentifierSize, nameof(dpd1Hash));
        if (dpd1Reference.Length != PreKeyV1Limits.Dpd1ReferenceSize ||
            !CryptographicOperations.FixedTimeEquals(dpd1Reference[6..], dpd1Hash))
            throw new ArgumentException("The exact DPD1 ArtifactRef must contain the supplied DPD1 hash.", nameof(dpd1Reference));
        if (!dpd1Reference[..4].SequenceEqual("DPD1"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(dpd1Reference[4..6]) != 1)
            throw new ArgumentException("The exact DPD1 application reference is not canonical v1.", nameof(dpd1Reference));
        if (accountGeneration == 0 || deviceGeneration == 0 || databaseGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(accountGeneration), "All scope generations must be nonzero.");
        this.networkId = networkId.ToArray(); this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray(); this.dpd1Reference = dpd1Reference.ToArray();
        this.dpd1Hash = dpd1Hash.ToArray(); AccountGeneration = accountGeneration;
        DeviceGeneration = deviceGeneration; DatabaseGeneration = databaseGeneration;
    }

    internal ReadOnlySpan<byte> NetworkId => networkId;
    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> DeviceId => deviceId;
    internal ulong DeviceGeneration { get; }
    internal ReadOnlySpan<byte> Dpd1Reference => dpd1Reference;
    internal ReadOnlySpan<byte> Dpd1Hash => dpd1Hash;
    internal ulong DatabaseGeneration { get; }

    internal static void ValidateNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
    }
}

internal sealed class PreKeyV1StoreOptions : IDisposable
{
    private byte[]? encryptionKey;
    internal PreKeyV1StoreOptions(string statePath, ReadOnlySpan<byte> encryptionKey,
        PreKeyV1StoreScope scope, bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath); ArgumentNullException.ThrowIfNull(scope);
        PreKeyV1StoreScope.ValidateNonZero(encryptionKey, PreKeyV1Limits.SqlCipherKeySize, nameof(encryptionKey));
        StatePath = Path.GetFullPath(statePath); this.encryptionKey = encryptionKey.ToArray();
        Scope = scope; AllowCreate = allowCreate;
    }
    internal string StatePath { get; }
    internal PreKeyV1StoreScope Scope { get; }
    internal bool AllowCreate { get; }
    internal byte[] CopyEncryptionKey() => (Volatile.Read(ref encryptionKey) ??
        throw new ObjectDisposedException(nameof(PreKeyV1StoreOptions))).ToArray();
    internal bool IsKeyZeroedForTesting => encryptionKey is null;
    public void Dispose()
    {
        var owned = Interlocked.Exchange(ref encryptionKey, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}

internal enum PreKeyV1StoreOpenFailure { UnreadableOrWrongKey = 1, UnsupportedGeneration = 2, ScopeMismatch = 3, Corrupt = 4 }
internal sealed class PreKeyV1StoreOpenException(PreKeyV1StoreOpenFailure reason, string message, Exception? inner = null)
    : IOException(message, inner) { internal PreKeyV1StoreOpenFailure Reason { get; } = reason; }

internal enum PreKeyV1ClaimDisposition
{
    Reserved = 1, ExactReservedReplay = 2, ExactFinalReplay = 3, Consumed = 4, Burned = 5,
    Unavailable = 6, ForkLatched = 7, AlreadyForkLatched = 8, InvalidState = 9
}

internal enum PreKeyV1ProvisionDisposition { Provisioned = 1, ExactReplay = 2, ForkLatched = 3, AlreadyForkLatched = 4 }

internal sealed record PreKeyV1ClaimResult(
    PreKeyV1ClaimDisposition Disposition,
    bool SecretCallbackInvoked,
    bool ForkLatched,
    ushort LastResortCounter);

/// <summary>
/// Protocol-to-store ownership transfer. Production construction consumes only
/// an AuthoredDpk2Offering and its opaque, single-use secret capability.
/// </summary>
internal sealed class PreKeyV1ProvisioningCapability : IDisposable
{
    private byte[]? exactDpk2;
    private byte[]? sealedSecret;
    private int consumed;

    private PreKeyV1ProvisioningCapability(
        PreKeyV1StoreScope scope,
        ReadOnlySpan<byte> exactDpk2,
        ReadOnlySpan<byte> sealedSecret)
    {
        var record = Dpk2Codec.Decode(exactDpk2);
        var canonical = Dpk2Codec.Encode(record);
        try
        {
            if (!canonical.AsSpan().SequenceEqual(exactDpk2)) throw new FormatException("DPK2 bytes are not canonical.");
            ValidateScope(record, scope);
            _ = Dpk2PreKeyPersistenceBlob.Decode(sealedSecret.ToArray());
            this.exactDpk2 = exactDpk2.ToArray();
            this.sealedSecret = sealedSecret.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(canonical); }
    }

    /// <summary>
    /// Transfers one Protocol-authored offering into the durable first-party
    /// owner without exposing any private key through a public callback or DTO.
    /// </summary>
    internal static PreKeyV1ProvisioningCapability ConsumeAuthored(
        PreKeyV1StoreScope scope,
        AuthoredDpk2Offering offering,
        Dpk2PreKeyPersistenceProtector protector)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(offering);
        var exact = offering.ExactDpk2.ToArray();
        var persistenceScope = new Dpk2PreKeyPersistenceScope(
            scope.NetworkId, scope.AccountId, scope.AccountGeneration,
            scope.DeviceId, scope.DeviceGeneration, scope.Dpd1Reference);
        var blob = offering.SealSecretForPersistence(protector, persistenceScope);
        byte[]? computedHash = null;
        try
        {
            computedHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(
                Dpk2Codec.Decode(exact));
            if (!CryptographicOperations.FixedTimeEquals(
                    offering.ExactDpk2Hash.Span,
                    computedHash))
                throw new CryptographicException("The Protocol DPK2 offering hash changed before persistence.");
            return new PreKeyV1ProvisioningCapability(scope, exact, blob.CanonicalBytes.Span);
        }
        finally
        {
            if (computedHash is not null)
                CryptographicOperations.ZeroMemory(computedHash);
            CryptographicOperations.ZeroMemory(exact);
        }
    }

    internal Payload Consume()
    {
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
            throw new InvalidOperationException("The pre-key provisioning capability is single-use.");
        return new(
            Take(ref exactDpk2),
            Take(ref sealedSecret));
    }
    internal bool IsClearedForTesting => exactDpk2 is null && sealedSecret is null;
    public void Dispose() { Zero(ref exactDpk2); Zero(ref sealedSecret); }

    private static void ValidateScope(Dpk2Record record, PreKeyV1StoreScope scope)
    {
        if (!Fixed(record.NetworkId.Span, scope.NetworkId) || !Fixed(record.ResponderAccountId.Span, scope.AccountId) ||
            !Fixed(record.ResponderDeviceId.Span, scope.DeviceId) || record.ResponderDeviceGeneration != scope.DeviceGeneration ||
            !Fixed(record.ResponderDpd1Ref.Span, scope.Dpd1Reference))
            throw new CryptographicException("DPK2 is outside the exact account/network/device/DPD1 scope.");
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static byte[] Take(ref byte[]? value) => Interlocked.Exchange(ref value, null) ??
        throw new InvalidOperationException("Capability ownership was lost.");
    private static void Zero(ref byte[]? value) { var owned = Interlocked.Exchange(ref value, null); if (owned is not null) CryptographicOperations.ZeroMemory(owned); }

    internal sealed class Payload(
        byte[] exactDpk2,
        byte[] sealedSecret) : IDisposable
    {
        internal byte[] ExactDpk2 { get; } = exactDpk2;
        internal byte[] SealedSecret { get; } = sealedSecret;
        public void Dispose() { CryptographicOperations.ZeroMemory(ExactDpk2); CryptographicOperations.ZeroMemory(SealedSecret); }
    }
}

/// <summary>
/// Closed verified XPC1/full-DPH2 binding. Production construction accepts only
/// Protocol's non-constructible, verifier-minted device-owner reservation DTO.
/// </summary>
internal sealed class PreKeyV1ClaimCapability : IDisposable
{
    private byte[]? operationId, sessionId, exactDpk2Hash, xpc1FullReplayHash, dph2FullReplayHash, x25519PreKeyId, mlKemPreKeyId;
    private int consumed;
    private PreKeyV1ClaimCapability(Dpk2PrekeyKind kind, ushort lastResortCounter,
        ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> xpc1FullReplayHash, ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId, ReadOnlySpan<byte> mlKemPreKeyId)
    {
        PreKeyV1StoreScope.ValidateNonZero(operationId, 32, nameof(operationId));
        PreKeyV1StoreScope.ValidateNonZero(sessionId, 32, nameof(sessionId));
        PreKeyV1StoreScope.ValidateNonZero(exactDpk2Hash, 32, nameof(exactDpk2Hash));
        PreKeyV1StoreScope.ValidateNonZero(xpc1FullReplayHash, 32, nameof(xpc1FullReplayHash));
        PreKeyV1StoreScope.ValidateNonZero(dph2FullReplayHash, 32, nameof(dph2FullReplayHash));
        PreKeyV1StoreScope.ValidateNonZero(mlKemPreKeyId, 32, nameof(mlKemPreKeyId));
        if (kind == Dpk2PrekeyKind.OneTime)
        {
            PreKeyV1StoreScope.ValidateNonZero(x25519PreKeyId, 32, nameof(x25519PreKeyId));
            if (lastResortCounter != 0) throw new ArgumentOutOfRangeException(nameof(lastResortCounter));
        }
        else if (kind == Dpk2PrekeyKind.LastResort)
        {
            if (!x25519PreKeyId.IsEmpty || lastResortCounter is < 1 or > 64)
                throw new ArgumentException("Last-resort claim shape is invalid.");
        }
        else throw new ArgumentOutOfRangeException(nameof(kind));
        Kind = kind; LastResortCounter = lastResortCounter;
        this.operationId = operationId.ToArray(); this.sessionId = sessionId.ToArray();
        this.exactDpk2Hash = exactDpk2Hash.ToArray(); this.xpc1FullReplayHash = xpc1FullReplayHash.ToArray();
        this.dph2FullReplayHash = dph2FullReplayHash.ToArray(); this.x25519PreKeyId = x25519PreKeyId.ToArray();
        this.mlKemPreKeyId = mlKemPreKeyId.ToArray();
    }

    internal static PreKeyV1ClaimCapability ConsumeVerified(
        VerifiedDevicePreKeyClaimReservation verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var operationId = verified.OperationId.ToArray();
        var sessionId = verified.SessionId.ToArray();
        var exactDpk2Hash = verified.ExactDpk2Hash.ToArray();
        var xpc1FullReplayHash = verified.Xpc1FullReplayHash.ToArray();
        var dph2FullReplayHash = verified.Dph2FullReplayHash.ToArray();
        var x25519PreKeyId = verified.X25519PreKeyId.ToArray();
        var mlKemPreKeyId = verified.MlKemPreKeyId.ToArray();
        try
        {
            return new PreKeyV1ClaimCapability(
                verified.Kind,
                verified.LastResortUseCounter,
                operationId,
                sessionId,
                exactDpk2Hash,
                xpc1FullReplayHash,
                dph2FullReplayHash,
                x25519PreKeyId,
                mlKemPreKeyId);
        }
        finally
        {
            verified.Dispose();
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(sessionId);
            CryptographicOperations.ZeroMemory(exactDpk2Hash);
            CryptographicOperations.ZeroMemory(xpc1FullReplayHash);
            CryptographicOperations.ZeroMemory(dph2FullReplayHash);
            CryptographicOperations.ZeroMemory(x25519PreKeyId);
            CryptographicOperations.ZeroMemory(mlKemPreKeyId);
        }
    }
#if DEEP_TEST_INTERNALS
    internal static PreKeyV1ClaimCapability CreateForTests(Dpk2PrekeyKind kind, ushort lastResortCounter,
        ReadOnlySpan<byte> operationId, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> exactDpk2Hash,
        ReadOnlySpan<byte> xpc1FullReplayHash, ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId, ReadOnlySpan<byte> mlKemPreKeyId) =>
        new(kind, lastResortCounter, operationId, sessionId, exactDpk2Hash,
            xpc1FullReplayHash, dph2FullReplayHash, x25519PreKeyId, mlKemPreKeyId);
#endif
    internal Payload Consume()
    {
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
            throw new InvalidOperationException("The verified pre-key claim capability is single-use.");
        return new(Kind, LastResortCounter, Take(ref operationId), Take(ref sessionId), Take(ref exactDpk2Hash),
            Take(ref xpc1FullReplayHash), Take(ref dph2FullReplayHash), Take(ref x25519PreKeyId), Take(ref mlKemPreKeyId));
    }
    internal Dpk2PrekeyKind Kind { get; }
    internal ushort LastResortCounter { get; }
    public void Dispose() { Zero(ref operationId); Zero(ref sessionId); Zero(ref exactDpk2Hash); Zero(ref xpc1FullReplayHash); Zero(ref dph2FullReplayHash); Zero(ref x25519PreKeyId); Zero(ref mlKemPreKeyId); }
    private static byte[] Take(ref byte[]? value) => Interlocked.Exchange(ref value, null) ?? throw new InvalidOperationException("Capability ownership was lost.");
    private static void Zero(ref byte[]? value) { var owned = Interlocked.Exchange(ref value, null); if (owned is not null) CryptographicOperations.ZeroMemory(owned); }
    internal sealed class Payload(Dpk2PrekeyKind kind, ushort lastResortCounter, byte[] operationId, byte[] sessionId,
        byte[] exactDpk2Hash, byte[] xpc1FullReplayHash, byte[] dph2FullReplayHash, byte[] x25519PreKeyId, byte[] mlKemPreKeyId) : IDisposable
    {
        internal Dpk2PrekeyKind Kind { get; } = kind; internal ushort LastResortCounter { get; } = lastResortCounter;
        internal byte[] OperationId { get; } = operationId; internal byte[] SessionId { get; } = sessionId;
        internal byte[] ExactDpk2Hash { get; } = exactDpk2Hash; internal byte[] Xpc1FullReplayHash { get; } = xpc1FullReplayHash;
        internal byte[] Dph2FullReplayHash { get; } = dph2FullReplayHash; internal byte[] X25519PreKeyId { get; } = x25519PreKeyId;
        internal byte[] MlKemPreKeyId { get; } = mlKemPreKeyId;
        public void Dispose() { CryptographicOperations.ZeroMemory(OperationId); CryptographicOperations.ZeroMemory(SessionId); CryptographicOperations.ZeroMemory(ExactDpk2Hash); CryptographicOperations.ZeroMemory(Xpc1FullReplayHash); CryptographicOperations.ZeroMemory(Dph2FullReplayHash); CryptographicOperations.ZeroMemory(X25519PreKeyId); CryptographicOperations.ZeroMemory(MlKemPreKeyId); }
    }
}
