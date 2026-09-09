using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed partial class InMemoryContactStateStore
{
    private readonly Dictionary<string, ContactRelationshipSnapshot> relationships = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ContactOperationRecord> relationshipOperations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ContactVerifiedPeerPackageEvidence> verifiedPeerPackages = new(StringComparer.Ordinal);

    public ValueTask<ContactRelationshipSnapshot?> ReadRelationshipAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            relationships.TryGetValue(Key(relationshipId), out var relationship);
            return ValueTask.FromResult(relationship?.Copy());
        }
    }

    public ValueTask<IReadOnlyList<ContactRelationshipSnapshot>> ReadRelationshipsAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            IReadOnlyList<ContactRelationshipSnapshot> result = relationships.Values
                .OrderBy(static value => value.UpdatedAt)
                .ThenBy(static value => Convert.ToHexString(value.RelationshipId.Span), StringComparer.Ordinal)
                .Select(static value => value.Copy())
                .ToArray();
            return ValueTask.FromResult(result);
        }
    }

    public ValueTask<ContactVerifiedPeerPackageEvidence?> ReadVerifiedPeerPackageAsync(
        ContactRelationshipId32 relationshipId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relationshipId);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            verifiedPeerPackages.TryGetValue(Key(relationshipId), out var package);
            return ValueTask.FromResult(package?.Copy());
        }
    }

    public ValueTask<ContactRelationshipCommitResult> CommitRelationshipAsync(
        ContactRelationshipMutationPlan mutation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutation);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Scope.Equals(mutation.Scope))
            throw new ArgumentException("The contact mutation belongs to another exact account scope.", nameof(mutation));

        lock (gate)
        {
            var operationKey = Key(mutation.OperationId);
            if (relationshipOperations.TryGetValue(operationKey, out var replay))
            {
                if (!CryptographicOperations.FixedTimeEquals(replay.Fingerprint, mutation.Fingerprint)
                    || !replay.RelationshipId.Equals(mutation.RelationshipId))
                {
                    return ValueTask.FromResult(new ContactRelationshipCommitResult(
                        ContactRelationshipCommitDisposition.Conflict,
                        ReadCopy(mutation.RelationshipId), null));
                }
                return ValueTask.FromResult(new ContactRelationshipCommitResult(
                    ContactRelationshipCommitDisposition.Idempotent,
                    ReadCopy(replay.RelationshipId), replay.CommittedRevision));
            }

            var relationshipKey = Key(mutation.RelationshipId);
            if (mutation.Kind == ContactRelationshipMutationKind.BundleVerified)
                return ValueTask.FromResult(CreateVerifiedBundle(mutation, relationshipKey, operationKey));

            if (!relationships.TryGetValue(relationshipKey, out var current))
                return ValueTask.FromResult(new ContactRelationshipCommitResult(
                    ContactRelationshipCommitDisposition.NotFound, null, null));

            var transition = ContactRelationshipStateMachine.Apply(current, mutation);
            if (transition.Disposition != ContactRelationshipCommitDisposition.Applied)
                return ValueTask.FromResult(transition with { Relationship = transition.Relationship?.Copy() });
            var next = transition.Relationship!;
            relationships[relationshipKey] = next;
            relationshipOperations.Add(operationKey, new(mutation.Fingerprint.ToArray(),
                mutation.RelationshipId, next.Revision));
            return ValueTask.FromResult(new ContactRelationshipCommitResult(
                ContactRelationshipCommitDisposition.Applied, next.Copy(), next.Revision));
        }
    }

    private ContactRelationshipCommitResult CreateVerifiedBundle(
        ContactRelationshipMutationPlan mutation,
        string relationshipKey,
        string operationKey)
    {
        var evidence = mutation.BundleEvidence!;
        if (relationships.TryGetValue(relationshipKey, out var collision))
            return new(ContactRelationshipCommitDisposition.Conflict, collision.Copy(), null);
        if (relationships.Count >= maximumPendingAddresses)
            return new(ContactRelationshipCommitDisposition.CapacityExceeded, null, null);
        var pendingKey = Key(evidence.Address.Kind, evidence.Address.CanonicalBytes.Span);
        if (!pending.TryGetValue(pendingKey, out var imported) || !imported.Address.Equals(evidence.Address))
            return new(ContactRelationshipCommitDisposition.NotFound, null, null);
        if (mutation.OccurredAt < imported.ImportedAt)
            return new(ContactRelationshipCommitDisposition.InvalidTransition, null, null);

        var created = new ContactRelationshipSnapshot(evidence.RelationshipId, evidence.ConversationId,
            evidence.RemoteAccountId, evidence.Address.Kind, evidence.Address.CanonicalBytes.Span,
            ContactRelationshipState.BundleVerified, 1, mutation.OccurredAt, mutation.OccurredAt,
            evidence.ArtifactHashes);
        relationships.Add(relationshipKey, created);
        verifiedPeerPackages.Add(relationshipKey, mutation.RecoveryPackage!.Copy());
        relationshipOperations.Add(operationKey, new(mutation.Fingerprint.ToArray(),
            mutation.RelationshipId, created.Revision));
        return new(ContactRelationshipCommitDisposition.Applied, created.Copy(), created.Revision);
    }

    private ContactRelationshipSnapshot? ReadCopy(ContactRelationshipId32 relationshipId) =>
        relationships.TryGetValue(Key(relationshipId), out var relationship) ? relationship.Copy() : null;

    private static string Key(ContactIdentifier32 value) => Convert.ToHexString(value.Span);

    private sealed record ContactOperationRecord(
        byte[] Fingerprint,
        ContactRelationshipId32 RelationshipId,
        ulong CommittedRevision);
}
