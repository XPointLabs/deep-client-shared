using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Services.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed partial class InMemoryContactStateStore
{
    private readonly Dictionary<string, ContactResolveOperationSnapshot> resolveOperations =
        new(StringComparer.Ordinal);

    ValueTask<ContactResolveOperationStageResult> IContactResolveOperationStore.StageResolveOperationAsync(
        ContactResolveOperationIntent intent,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        cancellationToken.ThrowIfCancellationRequested();
        var candidate = ContactResolveOperationPersistenceValidation.NewPrepared(
            Scope, intent, CanonicalTime(updatedAt));
        var key = Convert.ToHexString(candidate.OperationIdSpan);
        lock (gate)
        {
            EnsurePending(candidate.PendingAddress);
            EnsureRelationshipBinding(candidate);
            if (resolveOperations.TryGetValue(key, out var existing))
            {
                if (!SameIntent(existing, candidate))
                    throw new ContactResolveOperationConflictException();
                return ValueTask.FromResult(new ContactResolveOperationStageResult(
                    ContactResolveOperationStageDisposition.ExactReplay,
                    ContactResolveOperationPersistenceValidation.Validate(existing, Scope)));
            }
            if (resolveOperations.Count >= ContactResolveOperationPersistenceValidation.MaximumOperations
                || resolveOperations.Values.Count(value =>
                    ContactResolveOperationPersistenceValidation.Exact(
                        value.RelationshipIdSpan, candidate.RelationshipIdSpan))
                    >= ContactResolveOperationPersistenceValidation.MaximumOperationsPerRelationship)
                throw new ContactResolveOperationCapacityException();
            resolveOperations.Add(key, candidate);
            return ValueTask.FromResult(new ContactResolveOperationStageResult(
                ContactResolveOperationStageDisposition.Added,
                candidate.Copy()));
        }
    }

    ValueTask<ContactResolveOperationSnapshot?> IContactResolveOperationStore.ReadResolveOperationAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateOperationId(operationId32.Span);
        lock (gate)
        {
            resolveOperations.TryGetValue(Convert.ToHexString(operationId32.Span), out var value);
            return ValueTask.FromResult(value is null
                ? null
                : ContactResolveOperationPersistenceValidation.Validate(value, Scope));
        }
    }

    ValueTask<IReadOnlyList<ContactResolveOperationSnapshot>> IContactResolveOperationStore.ReadResolveOperationsAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            IReadOnlyList<ContactResolveOperationSnapshot> result = resolveOperations.Values
                .OrderBy(static value => value.UpdatedAt)
                .ThenBy(static value => Convert.ToHexString(value.OperationId.Span), StringComparer.Ordinal)
                .Select(value => ContactResolveOperationPersistenceValidation.Validate(value, Scope))
                .ToArray();
            return ValueTask.FromResult(result);
        }
    }

    ValueTask<ContactResolveOperationSnapshot> IContactResolveOperationStore.BeginResolveDispatchAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateOperationId(operationId32.Span);
        RequireHash(expectedRequestHash32.Span, nameof(expectedRequestHash32));
        lock (gate)
        {
            var current = Required(operationId32.Span);
            EnsureRequestHash(current, expectedRequestHash32.Span);
            if (current.State is not (ContactResolveOperationState.Prepared or ContactResolveOperationState.RetryPending))
                throw new ContactResolveOperationStateException("Only a prepared or retry-pending resolver operation can dispatch.");
            var updated = current.WithDispatch(CanonicalTime(updatedAt));
            resolveOperations[Convert.ToHexString(operationId32.Span)] = updated;
            return ValueTask.FromResult(updated.Copy());
        }
    }

    ValueTask<ContactResolveOperationSnapshot> IContactResolveOperationStore.RecordResolveOutcomeAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ContactResolveOutcomeUpdate update,
        DateTimeOffset updatedAt,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(update);
        ValidateOperationId(operationId32.Span);
        RequireHash(expectedRequestHash32.Span, nameof(expectedRequestHash32));
        lock (gate)
        {
            var current = Required(operationId32.Span);
            EnsureRequestHash(current, expectedRequestHash32.Span);
            if (current.DispatchCount == 0)
                throw new ContactResolveOperationStateException("A resolver outcome cannot precede durable dispatch intent.");
            if (update.Disposition == ContactResolverDisposition.Verified
                && !relationships.ContainsKey(Convert.ToHexString(current.RelationshipIdSpan)))
                throw new ContactResolveOperationStateException("A verified resolver outcome has no idempotently linked relationship.");
            var updated = current.WithOutcome(update, CanonicalTime(updatedAt));
            updated = ContactResolveOperationPersistenceValidation.Validate(updated, Scope);
            resolveOperations[Convert.ToHexString(operationId32.Span)] = updated;
            return ValueTask.FromResult(updated.Copy());
        }
    }

    private ContactResolveOperationSnapshot Required(ReadOnlySpan<byte> operationId32) =>
        resolveOperations.TryGetValue(Convert.ToHexString(operationId32), out var value)
            ? value
            : throw new KeyNotFoundException("The resolver operation does not exist in this account scope.");

    private void EnsurePending(PendingContactAddress value)
    {
        var key = Key(value.Address.Kind, value.Address.CanonicalBytes.Span);
        if (!pending.TryGetValue(key, out var persisted)
            || !persisted.Address.Equals(value.Address)
            || persisted.ImportedAt != value.ImportedAt)
            throw new ContactResolveOperationMissingAddressException();
    }

    private void EnsureRelationshipBinding(ContactResolveOperationSnapshot candidate)
    {
        var conflict = resolveOperations.Values.FirstOrDefault(value =>
            ContactResolveOperationPersistenceValidation.Exact(
                value.RelationshipIdSpan, candidate.RelationshipIdSpan)
            && (value.PendingAddress.Address.Kind != candidate.PendingAddress.Address.Kind
                || !ContactResolveOperationPersistenceValidation.Exact(
                    value.PendingAddress.Address.CanonicalBytes.Span,
                    candidate.PendingAddress.Address.CanonicalBytes.Span)));
        if (conflict is not null) throw new ContactResolveOperationConflictException();
    }

    private static bool SameIntent(
        ContactResolveOperationSnapshot left,
        ContactResolveOperationSnapshot right) =>
        ContactResolveOperationPersistenceValidation.Exact(left.RequestHashSpan, right.RequestHashSpan)
        && ContactResolveOperationPersistenceValidation.Exact(left.RelationshipIdSpan, right.RelationshipIdSpan)
        && left.PendingAddress.Address.Equals(right.PendingAddress.Address)
        && left.PendingAddress.ImportedAt == right.PendingAddress.ImportedAt
        && ContactResolveOperationPersistenceValidation.Exact(left.ExactXiq1Span, right.ExactXiq1Span);

    private static void EnsureRequestHash(ContactResolveOperationSnapshot value, ReadOnlySpan<byte> expected)
    {
        if (!ContactResolveOperationPersistenceValidation.Exact(value.RequestHashSpan, expected))
            throw new ContactResolveOperationConflictException();
    }

    private static void ValidateOperationId(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte resolver operation ID is required.", nameof(value));
    }

    private static void RequireHash(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte resolver request hash is required.", name);
    }

    private static DateTimeOffset CanonicalTime(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        if (utc.Ticks < 0) throw new ArgumentOutOfRangeException(nameof(value));
        return utc;
    }
}
