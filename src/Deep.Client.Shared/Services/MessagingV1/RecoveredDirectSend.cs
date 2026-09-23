#if DEEP_CLEAN_PRODUCTION
using System.Security.Cryptography;

namespace Deep.Client.Shared.Services.MessagingV1;

/// <summary>
/// Exact DPE2 recovered from the committed SQLCipher ratchet journal. It is
/// not a new encryption or an assertion of delivery. Fresh peer and mailbox
/// authority are still required before dispatch.
/// </summary>
internal sealed class RecoveredDirectSend : IDisposable
{
    private byte[]? exactDpe2;
    private byte[]? operationId;
    private byte[]? envelopeHash;

    internal RecoveredDirectSend(
        ReadOnlySpan<byte> exactDpe2,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> envelopeHash)
    {
        this.exactDpe2 = exactDpe2.ToArray();
        this.operationId = operationId.ToArray();
        this.envelopeHash = envelopeHash.ToArray();
    }

    internal ReadOnlyMemory<byte> OperationId => Copy(operationId);
    internal ReadOnlyMemory<byte> EnvelopeHash => Copy(envelopeHash);
    internal byte[] TakeExactEnvelope() =>
        Interlocked.Exchange(ref exactDpe2, null) ??
        throw new ObjectDisposedException(nameof(RecoveredDirectSend));

    public void Dispose()
    {
        Zero(ref exactDpe2);
        Zero(ref operationId);
        Zero(ref envelopeHash);
    }

    private static ReadOnlyMemory<byte> Copy(byte[]? value) =>
        (value ?? throw new ObjectDisposedException(nameof(RecoveredDirectSend))).ToArray();

    private static void Zero(ref byte[]? value)
    {
        var owned = Interlocked.Exchange(ref value, null);
        if (owned is not null) CryptographicOperations.ZeroMemory(owned);
    }
}
#endif
