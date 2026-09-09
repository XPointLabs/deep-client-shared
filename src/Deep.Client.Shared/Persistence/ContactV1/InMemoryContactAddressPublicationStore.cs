using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public sealed class InMemoryContactAddressPublicationStore : IContactAddressPublicationStore
{
    private readonly object gate = new();
    private readonly Dictionary<string, ContactAddressPublicationSnapshot> operations =
        new(StringComparer.Ordinal);

    public InMemoryContactAddressPublicationStore(ContactStoreScope scope) =>
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));

    public ContactStoreScope Scope { get; }

    public ValueTask<ContactAddressPublicationStageResult> StageAttemptAsync(
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var candidate = ContactAddressPublicationPersistenceValidation.NewPending(
            Scope, exactXpu1.Span, attemptCount: 1);
        var key = Convert.ToHexString(candidate.OperationIdSpan);
        lock (gate)
        {
            if (operations.TryGetValue(key, out var existing))
            {
                if (!ContactAddressPublicationPersistenceValidation.ExactEquals(
                        existing.ExactXpu1Span, candidate.ExactXpu1Span))
                {
                    throw new ContactAddressPublicationConflictException();
                }

                var next = existing.State == ContactAddressPublicationState.Pending
                    ? existing.WithAttemptCount(checked(existing.AttemptCount + 1))
                    : existing.Copy();
                operations[key] = next;
                return ValueTask.FromResult(new ContactAddressPublicationStageResult(
                    ContactAddressPublicationStageDisposition.ExactReplay, next.Copy()));
            }

            operations.Add(key, candidate);
            return ValueTask.FromResult(new ContactAddressPublicationStageResult(
                ContactAddressPublicationStageDisposition.Added, candidate.Copy()));
        }
    }

    public ValueTask<ContactAddressPublicationSnapshot?> ReadAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContactAddressPublicationPersistenceValidation.ValidateOperationId(operationId32.Span);
        lock (gate)
        {
            operations.TryGetValue(Convert.ToHexString(operationId32.Span), out var value);
            return ValueTask.FromResult(value?.Copy());
        }
    }

    public ValueTask<ContactAddressPublicationSnapshot> RecordValidatedResultAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ReadOnlyMemory<byte> exactXpo1,
        ContactAddressPublicationState state,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContactAddressPublicationPersistenceValidation.ValidateOperationId(operationId32.Span);
        if (expectedRequestHash32.Length != 32)
            throw new ArgumentException("The expected request hash must be 32 bytes.", nameof(expectedRequestHash32));

        lock (gate)
        {
            var key = Convert.ToHexString(operationId32.Span);
            if (!operations.TryGetValue(key, out var current))
                throw new InvalidOperationException("The publication must be staged before recording a result.");
            if (!CryptographicOperations.FixedTimeEquals(
                    current.RequestHashSpan, expectedRequestHash32.Span))
            {
                throw new ContactAddressPublicationConflictException();
            }

            var decoded = Xpo1Codec.Decode(exactXpo1.Span, current.ExactXpu1Span);
            if (ContactAddressPublicationPersistenceValidation.StateFor(decoded.Status) != state)
                throw new ArgumentException("The requested state does not match the exact XPO1 result.", nameof(state));

            var updated = ContactAddressPublicationPersistenceValidation.Validate(
                current.WithResult(state, decoded, exactXpo1.Span), Scope);
            operations[key] = updated;
            return ValueTask.FromResult(updated.Copy());
        }
    }
}
