using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.PreKeyV1;

internal enum PreKeyV1InventoryStageDisposition
{
    Staged = 1,
    ExactReplay = 2,
    ForkLatched = 3,
    AlreadyForkLatched = 4,
}

/// <summary>
/// Exact, durable XPP1 publication request and its XPI1 commitment.  All byte
/// properties are defensive copies; this object carries no private material.
/// </summary>
internal sealed class PreKeyV1PublicationRequest
{
    private readonly byte[] operationId;
    private readonly byte[] predecessorXpi1Hash;
    private readonly byte[] currentDmd1Hash;
    private readonly byte[] xpi1Hash;
    private readonly byte[] exactXpi1;
    private readonly byte[] exactXpp1;

    internal PreKeyV1PublicationRequest(
        ulong inventoryEpoch,
        ulong serviceGeneration,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> predecessorXpi1Hash,
        ulong currentDmd1Generation,
        ReadOnlySpan<byte> currentDmd1Hash,
        ReadOnlySpan<byte> xpi1Hash,
        ReadOnlySpan<byte> exactXpi1,
        ReadOnlySpan<byte> exactXpp1)
    {
        if (inventoryEpoch == 0 || serviceGeneration == 0 || currentDmd1Generation == 0)
            throw new ArgumentOutOfRangeException(nameof(inventoryEpoch));
        PreKeyV1StoreScope.ValidateNonZero(operationId, 32, nameof(operationId));
        if (predecessorXpi1Hash.Length != 32)
            throw new ArgumentException("The predecessor XPI1 hash must be exactly 32 bytes.", nameof(predecessorXpi1Hash));
        PreKeyV1StoreScope.ValidateNonZero(currentDmd1Hash, 32, nameof(currentDmd1Hash));
        PreKeyV1StoreScope.ValidateNonZero(xpi1Hash, 32, nameof(xpi1Hash));
        var xpi1 = Xpi1Codec.Decode(exactXpi1);
        var xpp1 = Xpp1Codec.Decode(exactXpp1);
        if (!CryptographicOperations.FixedTimeEquals(xpi1.CanonicalBytes.Span, xpp1.Manifest.CanonicalBytes.Span) ||
            !CryptographicOperations.FixedTimeEquals(xpi1Hash, xpi1.Xpi1Hash.Span) ||
            !CryptographicOperations.FixedTimeEquals(operationId, xpp1.PublicationOperationId.Span) ||
            xpi1.InventoryEpoch != inventoryEpoch || xpi1.ServiceGeneration != serviceGeneration ||
            !CryptographicOperations.FixedTimeEquals(predecessorXpi1Hash, xpi1.PredecessorXpi1Hash.Span) ||
            !CryptographicOperations.FixedTimeEquals(currentDmd1Hash, xpi1.CurrentDmd1Hash.Span))
            throw new CryptographicException("The exact XPI1/XPP1 request differs from its durable lineage metadata.");
        InventoryEpoch = inventoryEpoch;
        ServiceGeneration = serviceGeneration;
        CurrentDmd1Generation = currentDmd1Generation;
        this.operationId = operationId.ToArray();
        this.predecessorXpi1Hash = predecessorXpi1Hash.ToArray();
        this.currentDmd1Hash = currentDmd1Hash.ToArray();
        this.xpi1Hash = xpi1Hash.ToArray();
        this.exactXpi1 = exactXpi1.ToArray();
        this.exactXpp1 = exactXpp1.ToArray();
    }

    internal ulong InventoryEpoch { get; }
    internal ulong ServiceGeneration { get; }
    internal ulong CurrentDmd1Generation { get; }
    internal ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    internal ReadOnlyMemory<byte> PredecessorXpi1Hash => predecessorXpi1Hash.ToArray();
    internal ReadOnlyMemory<byte> CurrentDmd1Hash => currentDmd1Hash.ToArray();
    internal ReadOnlyMemory<byte> Xpi1Hash => xpi1Hash.ToArray();
    internal ReadOnlyMemory<byte> ExactXpi1 => exactXpi1.ToArray();
    internal ReadOnlyMemory<byte> ExactPublicationRequest => exactXpp1.ToArray();

    internal ReadOnlySpan<byte> OperationIdSpan => operationId;
    internal ReadOnlySpan<byte> PredecessorXpi1HashSpan => predecessorXpi1Hash;
    internal ReadOnlySpan<byte> CurrentDmd1HashSpan => currentDmd1Hash;
    internal ReadOnlySpan<byte> Xpi1HashSpan => xpi1Hash;
    internal ReadOnlySpan<byte> ExactXpi1Span => exactXpi1;
    internal ReadOnlySpan<byte> ExactXpp1Span => exactXpp1;
}

internal sealed record PreKeyV1InventoryStageResult(
    PreKeyV1InventoryStageDisposition Disposition,
    PreKeyV1PublicationRequest? Publication,
    bool ForkLatched);
