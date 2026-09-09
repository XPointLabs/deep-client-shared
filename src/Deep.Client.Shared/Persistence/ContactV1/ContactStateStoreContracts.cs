using Deep.Client.Shared.Domain.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public enum PendingContactAddressWriteDisposition
{
    Added = 1,
    Idempotent = 2,
    CapacityExceeded = 3,
}

public sealed record PendingContactAddressWriteResult(
    PendingContactAddressWriteDisposition Disposition,
    PendingContactAddress? Address);

public interface IContactStateStore
{
    ContactStoreScope Scope { get; }

    ValueTask<PendingContactAddressWriteResult> PutPendingAddressAsync(
        PendingContactAddress address,
        CancellationToken cancellationToken = default);

    ValueTask<PendingContactAddress?> ReadPendingAddressAsync(
        ContactAddressKind kind,
        ReadOnlyMemory<byte> exactCanonicalAddress,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<PendingContactAddress>> ReadPendingAddressesAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ContactRelationshipSnapshot?> ReadRelationshipAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<ContactRelationshipSnapshot>> ReadRelationshipsAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ContactVerifiedPeerPackageEvidence?> ReadVerifiedPeerPackageAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default);

    ValueTask<ContactRelationshipCommitResult> CommitRelationshipAsync(
        ContactRelationshipMutationPlan mutation,
        CancellationToken cancellationToken = default);

}

internal interface IContactResolveOperationStore
{
    ValueTask<ContactResolveOperationStageResult> StageResolveOperationAsync(
        ContactResolveOperationIntent intent,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);

    ValueTask<ContactResolveOperationSnapshot?> ReadResolveOperationAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<ContactResolveOperationSnapshot>> ReadResolveOperationsAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ContactResolveOperationSnapshot> BeginResolveDispatchAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);

    ValueTask<ContactResolveOperationSnapshot> RecordResolveOutcomeAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ContactResolveOutcomeUpdate update,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken = default);
}
