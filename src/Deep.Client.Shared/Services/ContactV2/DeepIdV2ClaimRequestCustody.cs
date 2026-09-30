using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>Account-owned exact request/result custody, not claim or session
/// authority. A retained pair must still be checked against current network,
/// peer and replica evidence. This does not persist initiator secret material.</summary>
internal sealed class DeepIdV2ClaimRequestCustody(IDeepIdV2ClaimRequestCustodyStore store)
{
    internal ValueTask<ReadOnlyMemory<byte>> ReserveAsync(ReadOnlyMemory<byte> exactRequest,
        CancellationToken ct) => store.ReserveAsync(exactRequest, ct);

    internal ValueTask<ReadOnlyMemory<byte>?> FindAsync(ReadOnlyMemory<byte> operationId,
        CancellationToken ct) => store.FindAsync(operationId, ct);

    internal ValueTask<ReadOnlyMemory<byte>?> FindResultAsync(ReadOnlyMemory<byte> operationId,
        CancellationToken ct) => store.FindResultAsync(operationId, ct);

    internal ValueTask<ReadOnlyMemory<byte>> RecordVerifiedResultAsync(
        VerifiedXpc1V2ReplicaSignatures verified, CancellationToken ct) =>
        store.RecordVerifiedResultAsync(verified, ct);
}

internal interface IDeepIdV2ClaimRequestCustodyStore
{
    ValueTask<ReadOnlyMemory<byte>> ReserveAsync(ReadOnlyMemory<byte> exactRequest, CancellationToken ct);
    ValueTask<ReadOnlyMemory<byte>?> FindAsync(ReadOnlyMemory<byte> operationId, CancellationToken ct);
    ValueTask<ReadOnlyMemory<byte>?> FindResultAsync(ReadOnlyMemory<byte> operationId, CancellationToken ct);
    ValueTask<ReadOnlyMemory<byte>> RecordVerifiedResultAsync(VerifiedXpc1V2ReplicaSignatures verified,
        CancellationToken ct);
}
