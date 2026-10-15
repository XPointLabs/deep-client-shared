namespace Deep.Client.Shared.Services.ContactV2;

// Exact phase-6 XPL1 for reusable publication; strict current XPU1 for one-time.
// Shipping activation requires the private authenticated
// contact-service path; this interface does not permit a registry HTTP fallback.
internal interface IDid2ContactReplicaPublicationTransport
{
    Task<ReadOnlyMemory<byte>> PublishAsync(ReadOnlyMemory<byte> exactXpu1, Did2OwnedContactTransportContext operation, CancellationToken ct);
}
