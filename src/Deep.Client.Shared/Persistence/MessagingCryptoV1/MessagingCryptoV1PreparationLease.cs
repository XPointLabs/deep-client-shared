using System.Security.Cryptography;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

internal enum MessagingCryptoV1PreparationKind : byte
{
    Send = 1,
    Receive = 2,
}

/// <summary>
/// Single-use object capability over one atomic durable TRS1/replay snapshot.
/// The caller can ask the protocol producer to prepare the bound transition,
/// but cannot select checkpoint, journal, replay-retention, or CAS values.
/// </summary>
internal sealed class MessagingCryptoV1PreparationLease : IDisposable
{
    private readonly object sync = new();
    private byte[]? exactTrs1;
    private byte[]? expectedStateCommitment;
    private byte[]? latestProtectedCommitment;
    private byte[]? journalPredecessor;
    private byte[]? retentionCommitment;
    private byte[]? exactReceiveEnvelope;
    private int consumedOrDisposed;

    internal MessagingCryptoV1PreparationLease(
        MessagingCryptoV1PreparationKind kind,
        ReadOnlySpan<byte> exactTrs1,
        ulong expectedStateGeneration,
        ReadOnlySpan<byte> expectedStateCommitment,
        ulong latestProtectedGeneration,
        ReadOnlySpan<byte> latestProtectedCommitment,
        ulong expectedJournalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment,
        ExactDpe2ReceiveReplayDisposition receiveReplayDisposition,
        ReadOnlySpan<byte> exactReceiveEnvelope = default)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        MessagingCryptoV1PreparedTransition.ValidateTrs1(exactTrs1, nameof(exactTrs1));
        MessagingCryptoV1PreparedTransition.Validate32(
            expectedStateCommitment, nameof(expectedStateCommitment));
        MessagingCryptoV1PreparedTransition.Validate32(
            latestProtectedCommitment, nameof(latestProtectedCommitment));
        MessagingCryptoV1PreparedTransition.Validate32(
            journalPredecessor, nameof(journalPredecessor));
        MessagingCryptoV1PreparedTransition.Validate32(
            retentionCommitment, nameof(retentionCommitment));
        if (expectedStateGeneration == 0 || latestProtectedGeneration < expectedStateGeneration)
            throw new ArgumentOutOfRangeException(nameof(expectedStateGeneration));
        if (!Enum.IsDefined(receiveReplayDisposition))
            throw new ArgumentOutOfRangeException(nameof(receiveReplayDisposition));
        if (kind == MessagingCryptoV1PreparationKind.Send)
        {
            if (!exactReceiveEnvelope.IsEmpty ||
                receiveReplayDisposition != ExactDpe2ReceiveReplayDisposition.Fresh)
                throw new ArgumentException("A send preparation cannot carry receive replay state.");
        }
        else if (!IsExactDpe2Size(exactReceiveEnvelope.Length))
        {
            throw new ArgumentOutOfRangeException(
                nameof(exactReceiveEnvelope), "The bound receive envelope has no legal DPE2 size.");
        }

        Kind = kind;
        ExpectedStateGeneration = expectedStateGeneration;
        LatestProtectedGeneration = latestProtectedGeneration;
        ExpectedJournalGeneration = expectedJournalGeneration;
        ReceiveReplayDisposition = receiveReplayDisposition;
        this.exactTrs1 = exactTrs1.ToArray();
        this.expectedStateCommitment = expectedStateCommitment.ToArray();
        this.latestProtectedCommitment = latestProtectedCommitment.ToArray();
        this.journalPredecessor = journalPredecessor.ToArray();
        this.retentionCommitment = retentionCommitment.ToArray();
        this.exactReceiveEnvelope = exactReceiveEnvelope.IsEmpty ? null : exactReceiveEnvelope.ToArray();
    }

    internal MessagingCryptoV1PreparationKind Kind { get; }
    internal ulong ExpectedStateGeneration { get; }
    internal ulong LatestProtectedGeneration { get; }
    internal ulong ExpectedJournalGeneration { get; }
    internal ExactDpe2ReceiveReplayDisposition ReceiveReplayDisposition { get; }

    internal ExactDpe2PreparedSend PrepareSend(
        ReadOnlySpan<byte> exactDmc2,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> operationId)
    {
        lock (sync)
        {
            BeginConsume(MessagingCryptoV1PreparationKind.Send);
            try
            {
                var context = CreateContext();
                return ExactDpe2DurableTransactionProducer.PrepareSend(
                    exactTrs1!, context, exactDmc2, expectedNetworkId, operationId);
            }
            finally { ClearOwned(); }
        }
    }

    internal ExactDpe2PreparedReceive PrepareReceive()
    {
        lock (sync)
        {
            BeginConsume(MessagingCryptoV1PreparationKind.Receive);
            try
            {
                var context = CreateContext();
                return ExactDpe2DurableTransactionProducer.PrepareReceive(
                    exactTrs1!, context, exactReceiveEnvelope!);
            }
            finally { ClearOwned(); }
        }
    }

#if DEEP_TEST_INTERNALS
    internal MessagingCryptoV1PreparationSnapshot CaptureForTesting()
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(consumedOrDisposed != 0, this);
            var context = CreateContext();
            return new MessagingCryptoV1PreparationSnapshot(
                Kind,
                SHA256.HashData(exactTrs1!),
                context.ExpectedStateGeneration,
                context.ExpectedStateCommitment.Span,
                context.LatestProtectedGeneration,
                context.LatestProtectedCommitment.Span,
                context.ExpectedJournalGeneration,
                context.JournalPredecessor.Span,
                context.RetentionCommitment.Span,
                context.ReceiveReplayDisposition,
                exactReceiveEnvelope is null ? [] : SHA256.HashData(exactReceiveEnvelope));
        }
    }

    internal bool IsClearedForTesting
    {
        get
        {
            lock (sync)
                return exactTrs1 is null && expectedStateCommitment is null &&
                    latestProtectedCommitment is null && journalPredecessor is null &&
                    retentionCommitment is null && exactReceiveEnvelope is null;
        }
    }
#endif

    public void Dispose()
    {
        lock (sync)
        {
            if (Interlocked.Exchange(ref consumedOrDisposed, 1) != 0) return;
            ClearOwned();
        }
    }

    private ExactDpe2DurableTransitionContext CreateContext() => new(
        ExpectedStateGeneration,
        expectedStateCommitment!,
        LatestProtectedGeneration,
        latestProtectedCommitment!,
        ExpectedJournalGeneration,
        journalPredecessor!,
        retentionCommitment!,
        ReceiveReplayDisposition);

    private void BeginConsume(MessagingCryptoV1PreparationKind expectedKind)
    {
        if (Kind != expectedKind)
            throw new InvalidOperationException($"This lease is bound to {Kind}, not {expectedKind}.");
        if (Interlocked.Exchange(ref consumedOrDisposed, 1) != 0)
            throw new ObjectDisposedException(nameof(MessagingCryptoV1PreparationLease));
    }

    private void ClearOwned()
    {
        Zero(ref exactTrs1);
        Zero(ref expectedStateCommitment);
        Zero(ref latestProtectedCommitment);
        Zero(ref journalPredecessor);
        Zero(ref retentionCommitment);
        Zero(ref exactReceiveEnvelope);
    }

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }

    private static bool IsExactDpe2Size(int length) => length is
        4_513 or 4_609 or 4_673 or 5_473 or 5_665 or
        16_801 or 16_897 or 16_961 or 17_761 or 17_953 or
        33_185 or 33_281 or 33_345 or 34_145 or 34_337 or
        49_553 or 49_649 or 49_713 or 50_513 or 50_705;
}

#if DEEP_TEST_INTERNALS
internal sealed class MessagingCryptoV1PreparationSnapshot : IDisposable
{
    internal MessagingCryptoV1PreparationSnapshot(
        MessagingCryptoV1PreparationKind kind,
        byte[] exactTrs1Hash,
        ulong expectedStateGeneration,
        ReadOnlySpan<byte> expectedStateCommitment,
        ulong latestProtectedGeneration,
        ReadOnlySpan<byte> latestProtectedCommitment,
        ulong expectedJournalGeneration,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> retentionCommitment,
        ExactDpe2ReceiveReplayDisposition receiveReplayDisposition,
        byte[] exactReceiveEnvelopeHash)
    {
        Kind = kind;
        ExactTrs1Hash = exactTrs1Hash;
        ExpectedStateGeneration = expectedStateGeneration;
        ExpectedStateCommitment = expectedStateCommitment.ToArray();
        LatestProtectedGeneration = latestProtectedGeneration;
        LatestProtectedCommitment = latestProtectedCommitment.ToArray();
        ExpectedJournalGeneration = expectedJournalGeneration;
        JournalPredecessor = journalPredecessor.ToArray();
        RetentionCommitment = retentionCommitment.ToArray();
        ReceiveReplayDisposition = receiveReplayDisposition;
        ExactReceiveEnvelopeHash = exactReceiveEnvelopeHash;
    }

    internal MessagingCryptoV1PreparationKind Kind { get; }
    internal byte[] ExactTrs1Hash { get; }
    internal ulong ExpectedStateGeneration { get; }
    internal byte[] ExpectedStateCommitment { get; }
    internal ulong LatestProtectedGeneration { get; }
    internal byte[] LatestProtectedCommitment { get; }
    internal ulong ExpectedJournalGeneration { get; }
    internal byte[] JournalPredecessor { get; }
    internal byte[] RetentionCommitment { get; }
    internal ExactDpe2ReceiveReplayDisposition ReceiveReplayDisposition { get; }
    internal byte[] ExactReceiveEnvelopeHash { get; }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(ExactTrs1Hash);
        CryptographicOperations.ZeroMemory(ExpectedStateCommitment);
        CryptographicOperations.ZeroMemory(LatestProtectedCommitment);
        CryptographicOperations.ZeroMemory(JournalPredecessor);
        CryptographicOperations.ZeroMemory(RetentionCommitment);
        CryptographicOperations.ZeroMemory(ExactReceiveEnvelopeHash);
    }
}
#endif
