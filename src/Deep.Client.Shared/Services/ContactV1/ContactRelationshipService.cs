using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public sealed class ContactRelationshipService
{
    private readonly IContactStateStore store;

    public ContactRelationshipService(IContactStateStore store) =>
        this.store = store ?? throw new ArgumentNullException(nameof(store));

    public ValueTask<ContactRelationshipCommitResult> RecordBundleVerifiedAsync(
        ContactResolverTrustedVerificationResult verification,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verification);
        ArgumentNullException.ThrowIfNull(operationId);
        var evidence = verification.Evidence;
        RequireScope(evidence.Scope);
        return store.CommitRelationshipAsync(
            new ContactRelationshipMutationPlan(
                store.Scope, operationId, occurredAt, evidence, verification.RecoveryPackage),
            cancellationToken);
    }

    public ValueTask<ContactRelationshipCommitResult> ApplyVerifiedTransitionAsync(
        VerifiedContactTransitionEvidence evidence,
        ulong expectedRevision,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(operationId);
        RequireScope(evidence.Scope);
        return store.CommitRelationshipAsync(
            new ContactRelationshipMutationPlan(store.Scope, operationId, occurredAt, expectedRevision, evidence),
            cancellationToken);
    }

    public ValueTask<ContactRelationshipCommitResult> BlockAsync(
        ContactRelationshipId32 relationshipId,
        ulong expectedRevision,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken = default) =>
        ApplyLocalAsync(relationshipId, expectedRevision, operationId, occurredAt, delete: false, cancellationToken);

    public ValueTask<ContactRelationshipCommitResult> DeleteAsync(
        ContactRelationshipId32 relationshipId,
        ulong expectedRevision,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        CancellationToken cancellationToken = default) =>
        ApplyLocalAsync(relationshipId, expectedRevision, operationId, occurredAt, delete: true, cancellationToken);

    private ValueTask<ContactRelationshipCommitResult> ApplyLocalAsync(
        ContactRelationshipId32 relationshipId,
        ulong expectedRevision,
        ContactMutationId32 operationId,
        DateTimeOffset occurredAt,
        bool delete,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        ArgumentNullException.ThrowIfNull(operationId);
        return store.CommitRelationshipAsync(new ContactRelationshipMutationPlan(store.Scope,
            operationId, occurredAt, relationshipId, expectedRevision, delete), cancellationToken);
    }

    private void RequireScope(ContactStoreScope evidenceScope)
    {
        if (!store.Scope.Equals(evidenceScope))
            throw new ArgumentException("Verified contact evidence belongs to another exact account scope.", nameof(evidenceScope));
    }
}
