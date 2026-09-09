using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public enum ContactAddressPublicationState
{
    Pending = 1,
    Confirmed = 2,
    Rejected = 3,
}

public enum ContactAddressPublicationStageDisposition
{
    Added = 1,
    ExactReplay = 2,
}

public sealed record ContactAddressPublicationStageResult(
    ContactAddressPublicationStageDisposition Disposition,
    ContactAddressPublicationSnapshot Operation);

/// <summary>
/// Durable, account-scoped journal entry for one exact XPU1 publication.
/// The exact request is retained so an ambiguous retry can never rebuild different bytes.
/// </summary>
public sealed class ContactAddressPublicationSnapshot
{
    private readonly byte[] operationId;
    private readonly byte[] requestHash;
    private readonly byte[] exactXpu1;
    private readonly byte[]? exactXpo1;

    internal ContactAddressPublicationSnapshot(
        ContactStoreScope scope,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> exactXpu1,
        ContactAddressPublicationState state,
        ulong attemptCount,
        Xpo1Status? lastStatus,
        ContactServiceMutationOutcome? lastMutationOutcome,
        ulong? lastServerTimeUnixSeconds,
        uint? retryAfterSeconds,
        ReadOnlySpan<byte> exactXpo1)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        if (operationId32.Length != 32 || IsZero(operationId32))
            throw new ArgumentException("The publication operation ID must be a nonzero 32-byte value.", nameof(operationId32));
        if (requestHash32.Length != 32 || IsZero(requestHash32))
            throw new ArgumentException("The publication request hash must be a nonzero 32-byte value.", nameof(requestHash32));
        if (exactXpu1.IsEmpty)
            throw new ArgumentException("The exact XPU1 request is required.", nameof(exactXpu1));
        if (!Enum.IsDefined(state) || attemptCount == 0)
            throw new ArgumentOutOfRangeException(nameof(state));
        if ((lastStatus is null) != exactXpo1.IsEmpty
            || (lastMutationOutcome is null) != exactXpo1.IsEmpty
            || (lastServerTimeUnixSeconds is null) != exactXpo1.IsEmpty
            || (retryAfterSeconds is null) != exactXpo1.IsEmpty)
        {
            throw new ArgumentException("A persisted XPO1 result must be complete or absent.", nameof(exactXpo1));
        }

        Scope = scope;
        operationId = operationId32.ToArray();
        requestHash = requestHash32.ToArray();
        this.exactXpu1 = exactXpu1.ToArray();
        State = state;
        AttemptCount = attemptCount;
        LastStatus = lastStatus;
        LastMutationOutcome = lastMutationOutcome;
        LastServerTimeUnixSeconds = lastServerTimeUnixSeconds;
        RetryAfterSeconds = retryAfterSeconds;
        this.exactXpo1 = exactXpo1.IsEmpty ? null : exactXpo1.ToArray();
    }

    public ContactStoreScope Scope { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    public ReadOnlyMemory<byte> ExactXpu1 => exactXpu1.ToArray();
    public ContactAddressPublicationState State { get; }
    public ulong AttemptCount { get; }
    public Xpo1Status? LastStatus { get; }
    public ContactServiceMutationOutcome? LastMutationOutcome { get; }
    public ulong? LastServerTimeUnixSeconds { get; }
    public uint? RetryAfterSeconds { get; }
    public ReadOnlyMemory<byte> ExactXpo1 => exactXpo1?.ToArray() ?? ReadOnlyMemory<byte>.Empty;

    internal ReadOnlySpan<byte> OperationIdSpan => operationId;
    internal ReadOnlySpan<byte> RequestHashSpan => requestHash;
    internal ReadOnlySpan<byte> ExactXpu1Span => exactXpu1;
    internal ReadOnlySpan<byte> ExactXpo1Span => exactXpo1;

    internal ContactAddressPublicationSnapshot WithAttemptCount(ulong attemptCount) => new(
        Scope, operationId, requestHash, exactXpu1, State, attemptCount, LastStatus,
        LastMutationOutcome, LastServerTimeUnixSeconds, RetryAfterSeconds,
        exactXpo1 ?? []);

    internal ContactAddressPublicationSnapshot WithResult(
        ContactAddressPublicationState state,
        Xpo1Result result,
        ReadOnlySpan<byte> exactResult) => new(
            Scope, operationId, requestHash, exactXpu1, state, AttemptCount,
            result.Status, result.MutationOutcome, result.ServerTimeUnixSeconds,
            result.RetryAfterSeconds, exactResult);

    internal ContactAddressPublicationSnapshot Copy() => new(
        Scope, operationId, requestHash, exactXpu1, State, AttemptCount, LastStatus,
        LastMutationOutcome, LastServerTimeUnixSeconds, RetryAfterSeconds,
        exactXpo1 ?? []);

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var octet in value) aggregate |= octet;
        return aggregate == 0;
    }
}

public interface IContactAddressPublicationStore
{
    ContactStoreScope Scope { get; }

    ValueTask<ContactAddressPublicationStageResult> StageAttemptAsync(
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default);

    ValueTask<ContactAddressPublicationSnapshot?> ReadAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default);

    ValueTask<ContactAddressPublicationSnapshot> RecordValidatedResultAsync(
        ReadOnlyMemory<byte> operationId32,
        ReadOnlyMemory<byte> expectedRequestHash32,
        ReadOnlyMemory<byte> exactXpo1,
        ContactAddressPublicationState state,
        CancellationToken cancellationToken = default);
}

public sealed class ContactAddressPublicationConflictException : InvalidOperationException
{
    public ContactAddressPublicationConflictException()
        : base("The publication operation ID is already bound to different exact XPU1 bytes.") { }
}

internal static class ContactAddressPublicationPersistenceValidation
{
    internal static ContactAddressPublicationSnapshot NewPending(
        ContactStoreScope scope,
        ReadOnlySpan<byte> exactXpu1,
        ulong attemptCount)
    {
        var decoded = Xpu1Codec.Decode(exactXpu1);
        return new ContactAddressPublicationSnapshot(
            scope,
            decoded.OperationId.Span,
            decoded.RequestHash.Span,
            decoded.CanonicalBytes.Span,
            ContactAddressPublicationState.Pending,
            attemptCount,
            null,
            null,
            null,
            null,
            []);
    }

    internal static ContactAddressPublicationSnapshot Validate(
        ContactAddressPublicationSnapshot value,
        ContactStoreScope expectedScope)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.Scope.Equals(expectedScope))
            throw new InvalidOperationException("The publication belongs to another Deep account scope.");

        var request = Xpu1Codec.Decode(value.ExactXpu1Span);
        if (!CryptographicOperations.FixedTimeEquals(request.OperationId.Span, value.OperationIdSpan)
            || !CryptographicOperations.FixedTimeEquals(request.RequestHash.Span, value.RequestHashSpan))
        {
            throw new FormatException("The durable publication identity is not bound to its exact XPU1 request.");
        }

        if (value.State == ContactAddressPublicationState.Pending && value.ExactXpo1Span.IsEmpty)
            return value.Copy();
        if (value.ExactXpo1Span.IsEmpty || value.LastStatus is null
            || value.LastMutationOutcome is null || value.LastServerTimeUnixSeconds is null
            || value.RetryAfterSeconds is null)
        {
            throw new FormatException("The durable publication result is incomplete.");
        }

        var result = Xpo1Codec.Decode(value.ExactXpo1Span, value.ExactXpu1Span);
        if (result.Status != value.LastStatus
            || result.MutationOutcome != value.LastMutationOutcome
            || result.ServerTimeUnixSeconds != value.LastServerTimeUnixSeconds
            || result.RetryAfterSeconds != value.RetryAfterSeconds)
        {
            throw new FormatException("The durable publication result metadata is not canonical.");
        }

        var expectedState = StateFor(result.Status);
        if (expectedState != value.State)
            throw new FormatException("The durable publication state does not match its exact XPO1 result.");
        return value.Copy();
    }

    internal static ContactAddressPublicationState StateFor(Xpo1Status status) => status switch
    {
        Xpo1Status.Committed or Xpo1Status.ExactReplay => ContactAddressPublicationState.Confirmed,
        Xpo1Status.OutcomeUnknown or Xpo1Status.RateLimited or Xpo1Status.TemporarilyUnavailable
            => ContactAddressPublicationState.Pending,
        Xpo1Status.Expired or Xpo1Status.Unauthorized or Xpo1Status.StaleView or Xpo1Status.Conflict
            => ContactAddressPublicationState.Rejected,
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    internal static void ValidateOperationId(ReadOnlySpan<byte> operationId32)
    {
        if (operationId32.Length != 32 || operationId32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A nonzero 32-byte publication operation ID is required.", nameof(operationId32));
    }

    internal static bool ExactEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
