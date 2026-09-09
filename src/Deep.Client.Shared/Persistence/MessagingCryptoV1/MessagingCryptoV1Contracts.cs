using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.PreKeyV1;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

internal static class MessagingCryptoV1Limits
{
    internal const int IdentifierSize = 32;
    internal const int SqlCipherKeySize = 32;
    internal const int MaximumTrs1Bytes = 2 * 1024 * 1024;
    internal const int MaximumJournalEntries = 4096;
}

internal sealed class MessagingCryptoV1StoreScope
{
    private readonly byte[] accountId;
    private readonly byte[] localDeviceId;
    private readonly byte[] conversationId;
    private readonly byte[] sessionId;

    internal MessagingCryptoV1StoreScope(
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> localDeviceId,
        ulong deviceGeneration,
        ReadOnlySpan<byte> conversationId,
        ReadOnlySpan<byte> sessionId,
        ulong databaseGeneration)
    {
        ValidateIdentifier(accountId, nameof(accountId));
        ValidateIdentifier(localDeviceId, nameof(localDeviceId));
        ValidateIdentifier(conversationId, nameof(conversationId));
        ValidateIdentifier(sessionId, nameof(sessionId));
        if (accountGeneration == 0 || deviceGeneration == 0 || databaseGeneration == 0)
            throw new ArgumentOutOfRangeException(nameof(accountGeneration),
                "Account, device, and database generations must be nonzero.");
        this.accountId = CopyIdentifier(accountId, nameof(accountId));
        this.localDeviceId = CopyIdentifier(localDeviceId, nameof(localDeviceId));
        this.conversationId = CopyIdentifier(conversationId, nameof(conversationId));
        this.sessionId = CopyIdentifier(sessionId, nameof(sessionId));
        AccountGeneration = accountGeneration;
        DeviceGeneration = deviceGeneration;
        DatabaseGeneration = databaseGeneration;
    }

    internal ReadOnlySpan<byte> AccountId => accountId;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> LocalDeviceId => localDeviceId;
    internal ulong DeviceGeneration { get; }
    internal ReadOnlySpan<byte> ConversationId => conversationId;
    internal ReadOnlySpan<byte> SessionId => sessionId;
    internal ulong DatabaseGeneration { get; }

    private static byte[] CopyIdentifier(ReadOnlySpan<byte> value, string name)
    {
        ValidateIdentifier(value, name);
        return value.ToArray();
    }

    private static void ValidateIdentifier(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != MessagingCryptoV1Limits.IdentifierSize || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly 32 nonzero bytes.", name);
    }
}

internal sealed class MessagingCryptoV1StoreOptions : IDisposable
{
    private byte[]? encryptionKey;

    internal MessagingCryptoV1StoreOptions(
        string statePath,
        ReadOnlySpan<byte> encryptionKey,
        MessagingCryptoV1StoreScope scope,
        bool allowCreate = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(scope);
        if (encryptionKey.Length != MessagingCryptoV1Limits.SqlCipherKeySize ||
            encryptionKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte SQLCipher key is required.", nameof(encryptionKey));
        StatePath = Path.GetFullPath(statePath);
        this.encryptionKey = encryptionKey.ToArray();
        Scope = scope;
        AllowCreate = allowCreate;
    }

    internal string StatePath { get; }
    internal MessagingCryptoV1StoreScope Scope { get; }
    internal bool AllowCreate { get; }

    internal byte[] CopyEncryptionKey()
    {
        var key = Volatile.Read(ref encryptionKey) ??
            throw new ObjectDisposedException(nameof(MessagingCryptoV1StoreOptions));
        return key.ToArray();
    }

    internal bool IsKeyZeroedForTesting => encryptionKey is null;

    public void Dispose()
    {
        var key = Interlocked.Exchange(ref encryptionKey, null);
        if (key is not null) CryptographicOperations.ZeroMemory(key);
    }
}

internal enum MessagingCryptoV1StoreOpenFailure
{
    UnreadableOrWrongKey = 1,
    UnsupportedGeneration = 2,
    ScopeMismatch = 3,
    Corrupt = 4,
}

internal sealed class MessagingCryptoV1StoreOpenException : IOException
{
    internal MessagingCryptoV1StoreOpenException(
        MessagingCryptoV1StoreOpenFailure reason,
        string message,
        Exception? inner = null) : base(message, inner) => Reason = reason;

    internal MessagingCryptoV1StoreOpenFailure Reason { get; }
}

internal enum MessagingCryptoV1Direction : byte
{
    Send = 1,
    Receive = 2,
    RollbackLatch = 3,
}

internal enum MessagingCryptoV1CommitDisposition
{
    Initialized = 1,
    Committed = 2,
    ExactReplay = 3,
    CasConflict = 4,
    ForkLatched = 5,
    AlreadyForkLatched = 6,
    CapacityExceeded = 7,
    RollbackLatched = 8,
    PreKeyUnavailable = 9,
}

internal sealed record MessagingCryptoV1CommitResult(
    MessagingCryptoV1CommitDisposition Disposition,
    ulong StateGeneration,
    ReadOnlyMemory<byte> StateCommitment,
    ulong JournalGeneration,
    ReadOnlyMemory<byte> JournalHead,
    bool ForkLatched,
    bool TerminallyLatched);

internal sealed record MessagingCryptoV1HeadSnapshot(
    ulong StateGeneration,
    ReadOnlyMemory<byte> StateCommitment,
    ulong JournalGeneration,
    ReadOnlyMemory<byte> JournalHead,
    bool ForkLatched,
    bool TerminallyLatched);

internal enum MessagingCryptoV1InitialPreKeySource
{
    LocalAtomicInventory = 1,
    DeviceWideOneTimeReservation = 2,
    DeviceWideLastResortReservation = 3,
}

/// <summary>
/// Closed handoff from the verified XPC1/DPH2 handshake into durable storage.
/// Production construction is restricted to the device-wide pre-key owner after
/// its durable reservation has been bound to the exact TRS1.
/// </summary>
internal sealed class MessagingCryptoV1InitialSessionHandoff : IDisposable
{
    private byte[]? claimOperationId;
    private byte[]? xpc1FullReplayHash;
    private byte[]? dph2FullReplayHash;
    private byte[]? x25519PreKeyId;
    private byte[]? mlKemPreKeyId;
    private byte[]? exactTrs1;
    private int consumed;
    private readonly MessagingCryptoV1InitialPreKeySource preKeySource;

    private MessagingCryptoV1InitialSessionHandoff(
        MessagingCryptoV1InitialPreKeySource preKeySource,
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        ReadOnlySpan<byte> exactTrs1)
    {
        MessagingCryptoV1PreparedTransition.Validate32(claimOperationId, nameof(claimOperationId));
        MessagingCryptoV1PreparedTransition.Validate32(xpc1FullReplayHash, nameof(xpc1FullReplayHash));
        MessagingCryptoV1PreparedTransition.Validate32(dph2FullReplayHash, nameof(dph2FullReplayHash));
        if (!Enum.IsDefined(preKeySource)) throw new ArgumentOutOfRangeException(nameof(preKeySource));
        if (preKeySource == MessagingCryptoV1InitialPreKeySource.DeviceWideLastResortReservation)
        {
            if (!x25519PreKeyId.IsEmpty)
                throw new ArgumentException("A last-resort reservation has no one-time X25519 pre-key ID.", nameof(x25519PreKeyId));
        }
        else MessagingCryptoV1PreparedTransition.Validate32(x25519PreKeyId, nameof(x25519PreKeyId));
        MessagingCryptoV1PreparedTransition.Validate32(mlKemPreKeyId, nameof(mlKemPreKeyId));
        MessagingCryptoV1PreparedTransition.ValidateTrs1(exactTrs1, nameof(exactTrs1));
        this.preKeySource = preKeySource;
        this.claimOperationId = MessagingCryptoV1PreparedTransition.Copy32(claimOperationId, nameof(claimOperationId));
        this.xpc1FullReplayHash = MessagingCryptoV1PreparedTransition.Copy32(xpc1FullReplayHash, nameof(xpc1FullReplayHash));
        this.dph2FullReplayHash = MessagingCryptoV1PreparedTransition.Copy32(dph2FullReplayHash, nameof(dph2FullReplayHash));
        this.x25519PreKeyId = x25519PreKeyId.ToArray();
        this.mlKemPreKeyId = MessagingCryptoV1PreparedTransition.Copy32(mlKemPreKeyId, nameof(mlKemPreKeyId));
        this.exactTrs1 = MessagingCryptoV1PreparedTransition.CopyBoundedTrs1(exactTrs1, nameof(exactTrs1));
    }

#if DEEP_TEST_INTERNALS
    internal static MessagingCryptoV1InitialSessionHandoff CreateForTests(
        ReadOnlySpan<byte> claimOperationId,
        ReadOnlySpan<byte> xpc1FullReplayHash,
        ReadOnlySpan<byte> dph2FullReplayHash,
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> mlKemPreKeyId,
        ReadOnlySpan<byte> exactTrs1) => new(MessagingCryptoV1InitialPreKeySource.LocalAtomicInventory,
            claimOperationId, xpc1FullReplayHash, dph2FullReplayHash,
            x25519PreKeyId, mlKemPreKeyId, exactTrs1);
#endif

    internal static MessagingCryptoV1InitialSessionHandoff CreateFromDeviceWidePreKeyOwner(
        SqlitePreKeyV1SecretOwner.InitialSessionCommitPermit permit)
    {
        ArgumentNullException.ThrowIfNull(permit);
        using var payload = permit.Consume();
        return new MessagingCryptoV1InitialSessionHandoff(
            payload.PreKeySource,
            payload.ClaimOperationId,
            payload.Xpc1FullReplayHash,
            payload.Dph2FullReplayHash,
            payload.X25519PreKeyId,
            payload.MlKemPreKeyId,
            payload.ExactTrs1);
    }

    internal InitializationPayload Consume()
    {
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
            throw new InvalidOperationException("The verified initial-session handoff is single-use.");
        return new InitializationPayload(
            preKeySource,
            Take(ref claimOperationId),
            Take(ref xpc1FullReplayHash),
            Take(ref dph2FullReplayHash),
            Take(ref x25519PreKeyId),
            Take(ref mlKemPreKeyId),
            Take(ref exactTrs1));
    }

    internal bool IsClearedForTesting => claimOperationId is null && xpc1FullReplayHash is null &&
        dph2FullReplayHash is null && x25519PreKeyId is null && mlKemPreKeyId is null && exactTrs1 is null;

    public void Dispose()
    {
        Zero(Interlocked.Exchange(ref claimOperationId, null));
        Zero(Interlocked.Exchange(ref xpc1FullReplayHash, null));
        Zero(Interlocked.Exchange(ref dph2FullReplayHash, null));
        Zero(Interlocked.Exchange(ref x25519PreKeyId, null));
        Zero(Interlocked.Exchange(ref mlKemPreKeyId, null));
        Zero(Interlocked.Exchange(ref exactTrs1, null));
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null) CryptographicOperations.ZeroMemory(value);
    }

    private static byte[] Take(ref byte[]? value) =>
        Interlocked.Exchange(ref value, null) ??
        throw new InvalidOperationException(
            "The verified initial-session handoff lost ownership.");

    internal sealed class InitializationPayload(
        MessagingCryptoV1InitialPreKeySource preKeySource,
        byte[] claimOperationId,
        byte[] xpc1FullReplayHash,
        byte[] dph2FullReplayHash,
        byte[] x25519PreKeyId,
        byte[] mlKemPreKeyId,
        byte[] exactTrs1) : IDisposable
    {
        internal MessagingCryptoV1InitialPreKeySource PreKeySource { get; } = preKeySource;
        internal byte[] ClaimOperationId { get; } = claimOperationId;
        internal byte[] Xpc1FullReplayHash { get; } = xpc1FullReplayHash;
        internal byte[] Dph2FullReplayHash { get; } = dph2FullReplayHash;
        internal byte[] X25519PreKeyId { get; } = x25519PreKeyId;
        internal byte[] MlKemPreKeyId { get; } = mlKemPreKeyId;
        internal byte[] ExactTrs1 { get; } = exactTrs1;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(ClaimOperationId);
            CryptographicOperations.ZeroMemory(Xpc1FullReplayHash);
            CryptographicOperations.ZeroMemory(Dph2FullReplayHash);
            CryptographicOperations.ZeroMemory(X25519PreKeyId);
            CryptographicOperations.ZeroMemory(MlKemPreKeyId);
            CryptographicOperations.ZeroMemory(ExactTrs1);
        }
    }
}

/// <summary>
/// Legacy persistence input retained only for internal store fault tests.
/// Production has no factory: authenticated DPE2 transitions enter through the
/// protocol-owned plan and exact durable authority instead of a raw TRS1 mutation API.
/// </summary>
internal sealed class MessagingCryptoV1PreparedTransition : IDisposable
{
    private byte[]? operationId;
    private byte[]? replayToken;
    private byte[]? envelopeHash;
    private byte[]? journalPredecessor;
    private byte[]? priorTrs1;
    private byte[]? nextTrs1;
    private byte[]? deletionManifestCommitment;
    private byte[]? messageKeyDeletionEvidence;
    private byte[]? replayEvidenceCommitment;
    private byte[]? pqFenceMutationCommitment;
    private byte[]? terminalStateCommitment;
    private int consumed;

    private MessagingCryptoV1PreparedTransition(
        MessagingCryptoV1Direction direction,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> replayToken,
        ReadOnlySpan<byte> envelopeHash,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> priorTrs1,
        ReadOnlySpan<byte> nextTrs1,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> messageKeyDeletionEvidence,
        ReadOnlySpan<byte> replayEvidenceCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment,
        ReadOnlySpan<byte> terminalStateCommitment)
    {
        if (!Enum.IsDefined(direction)) throw new ArgumentOutOfRangeException(nameof(direction));
        Validate32(operationId, nameof(operationId));
        Validate32(replayToken, nameof(replayToken));
        Validate32(envelopeHash, nameof(envelopeHash));
        Validate32(journalPredecessor, nameof(journalPredecessor));
        ValidateTrs1(priorTrs1, nameof(priorTrs1));
        ValidateTrs1(nextTrs1, nameof(nextTrs1));
        Validate32(deletionManifestCommitment, nameof(deletionManifestCommitment));
        Validate32(messageKeyDeletionEvidence, nameof(messageKeyDeletionEvidence));
        Validate32(replayEvidenceCommitment, nameof(replayEvidenceCommitment));
        ValidateOptional32(pqFenceMutationCommitment, nameof(pqFenceMutationCommitment));
        ValidateOptional32(terminalStateCommitment, nameof(terminalStateCommitment));
        Direction = direction;
        this.operationId = Copy32(operationId, nameof(operationId));
        this.replayToken = Copy32(replayToken, nameof(replayToken));
        this.envelopeHash = Copy32(envelopeHash, nameof(envelopeHash));
        this.journalPredecessor = Copy32(journalPredecessor, nameof(journalPredecessor));
        this.priorTrs1 = CopyBoundedTrs1(priorTrs1, nameof(priorTrs1));
        this.nextTrs1 = CopyBoundedTrs1(nextTrs1, nameof(nextTrs1));
        this.deletionManifestCommitment = Copy32(deletionManifestCommitment, nameof(deletionManifestCommitment));
        this.messageKeyDeletionEvidence = Copy32(messageKeyDeletionEvidence, nameof(messageKeyDeletionEvidence));
        this.replayEvidenceCommitment = Copy32(replayEvidenceCommitment, nameof(replayEvidenceCommitment));
        this.pqFenceMutationCommitment = CopyOptional32(pqFenceMutationCommitment, nameof(pqFenceMutationCommitment));
        this.terminalStateCommitment = CopyOptional32(terminalStateCommitment, nameof(terminalStateCommitment));
    }

#if DEEP_TEST_INTERNALS
    internal static MessagingCryptoV1PreparedTransition CreateForTests(
        MessagingCryptoV1Direction direction,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> replayToken,
        ReadOnlySpan<byte> envelopeHash,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> priorTrs1,
        ReadOnlySpan<byte> nextTrs1,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> messageKeyDeletionEvidence,
        ReadOnlySpan<byte> replayEvidenceCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment = default,
        ReadOnlySpan<byte> terminalStateCommitment = default) =>
        new(direction, operationId, replayToken, envelopeHash, journalPredecessor,
            priorTrs1, nextTrs1, deletionManifestCommitment, messageKeyDeletionEvidence,
            replayEvidenceCommitment, pqFenceMutationCommitment, terminalStateCommitment);
#endif

    internal MessagingCryptoV1Direction Direction { get; }

    internal TransitionPayload Consume()
    {
        if (Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
            throw new InvalidOperationException("The prepared transition is single-use.");
        return new TransitionPayload(
            Direction,
            Take(ref operationId), Take(ref replayToken), Take(ref envelopeHash),
            Take(ref journalPredecessor), Take(ref priorTrs1), Take(ref nextTrs1),
            Take(ref deletionManifestCommitment), Take(ref messageKeyDeletionEvidence),
            Take(ref replayEvidenceCommitment), Take(ref pqFenceMutationCommitment, optional: true),
            Take(ref terminalStateCommitment, optional: true));
    }

    internal bool IsClearedForTesting => operationId is null && replayToken is null && envelopeHash is null &&
        journalPredecessor is null && priorTrs1 is null && nextTrs1 is null &&
        deletionManifestCommitment is null && messageKeyDeletionEvidence is null &&
        replayEvidenceCommitment is null && pqFenceMutationCommitment is null &&
        terminalStateCommitment is null;

    public void Dispose()
    {
        Zero(ref operationId); Zero(ref replayToken); Zero(ref envelopeHash); Zero(ref journalPredecessor);
        Zero(ref priorTrs1); Zero(ref nextTrs1); Zero(ref deletionManifestCommitment);
        Zero(ref messageKeyDeletionEvidence); Zero(ref replayEvidenceCommitment);
        Zero(ref pqFenceMutationCommitment); Zero(ref terminalStateCommitment);
    }

    internal static byte[] Copy32(ReadOnlySpan<byte> value, string name)
    {
        Validate32(value, name);
        return value.ToArray();
    }

    internal static byte[] CopyBoundedTrs1(ReadOnlySpan<byte> value, string name)
    {
        ValidateTrs1(value, name);
        return value.ToArray();
    }

    private static byte[]? CopyOptional32(ReadOnlySpan<byte> value, string name) =>
        value.IsEmpty ? null : Copy32(value, name);

    internal static void Validate32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly 32 nonzero bytes.", name);
    }

    private static void ValidateOptional32(ReadOnlySpan<byte> value, string name)
    {
        if (!value.IsEmpty) Validate32(value, name);
    }

    internal static void ValidateTrs1(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length is < 600 or > MessagingCryptoV1Limits.MaximumTrs1Bytes)
            throw new ArgumentOutOfRangeException(name, "TRS1 must be within the closed 600-byte..2-MiB bound.");
    }

    private static byte[] Take(ref byte[]? value, bool optional = false)
    {
        var result = Interlocked.Exchange(ref value, null);
        if (result is null && !optional) throw new InvalidOperationException("Prepared transition ownership was lost.");
        return result ?? [];
    }

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }

    internal sealed class TransitionPayload(
        MessagingCryptoV1Direction direction,
        byte[] operationId,
        byte[] replayToken,
        byte[] envelopeHash,
        byte[] journalPredecessor,
        byte[] priorTrs1,
        byte[] nextTrs1,
        byte[] deletionManifestCommitment,
        byte[] messageKeyDeletionEvidence,
        byte[] replayEvidenceCommitment,
        byte[] pqFenceMutationCommitment,
        byte[] terminalStateCommitment) : IDisposable
    {
        internal MessagingCryptoV1Direction Direction { get; } = direction;
        internal byte[] OperationId { get; } = operationId;
        internal byte[] ReplayToken { get; } = replayToken;
        internal byte[] EnvelopeHash { get; } = envelopeHash;
        internal byte[] JournalPredecessor { get; } = journalPredecessor;
        internal byte[] PriorTrs1 { get; } = priorTrs1;
        internal byte[] NextTrs1 { get; } = nextTrs1;
        internal byte[] DeletionManifestCommitment { get; } = deletionManifestCommitment;
        internal byte[] MessageKeyDeletionEvidence { get; } = messageKeyDeletionEvidence;
        internal byte[] ReplayEvidenceCommitment { get; } = replayEvidenceCommitment;
        internal byte[] PqFenceMutationCommitment { get; } = pqFenceMutationCommitment;
        internal byte[] TerminalStateCommitment { get; } = terminalStateCommitment;

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(OperationId);
            CryptographicOperations.ZeroMemory(ReplayToken);
            CryptographicOperations.ZeroMemory(EnvelopeHash);
            CryptographicOperations.ZeroMemory(JournalPredecessor);
            CryptographicOperations.ZeroMemory(PriorTrs1);
            CryptographicOperations.ZeroMemory(NextTrs1);
            CryptographicOperations.ZeroMemory(DeletionManifestCommitment);
            CryptographicOperations.ZeroMemory(MessageKeyDeletionEvidence);
            CryptographicOperations.ZeroMemory(ReplayEvidenceCommitment);
            CryptographicOperations.ZeroMemory(PqFenceMutationCommitment);
            CryptographicOperations.ZeroMemory(TerminalStateCommitment);
        }
    }
}
