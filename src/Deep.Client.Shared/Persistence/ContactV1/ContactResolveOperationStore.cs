using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.ContactV1;

public enum ContactResolveOperationState
{
    Prepared = 1,
    RetryPending = 2,
    AwaitingRefreshedContext = 3,
    Terminal = 4,
    RelationshipLinked = 5,
    FailClosed = 6,
}

public enum ContactResolveOperationStageDisposition
{
    Added = 1,
    ExactReplay = 2,
}

public sealed record ContactResolveOperationStageResult(
    ContactResolveOperationStageDisposition Disposition,
    ContactResolveOperationSnapshot Operation);

public sealed class ContactResolveOperationSnapshot
{
    private readonly byte[] operationId;
    private readonly byte[] requestHash;
    private readonly byte[] relationshipId;
    private readonly byte[] exactXiq1;
    private readonly byte[]? exactXis1;
    private readonly byte[]? requiredViewHash;

    internal ContactResolveOperationSnapshot(
        ContactStoreScope scope,
        PendingContactAddress pendingAddress,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> relationshipId32,
        ReadOnlySpan<byte> exactXiq1,
        ContactResolveOperationState state,
        ulong dispatchCount,
        ulong transportAttemptCount,
        ContactResolverDisposition? lastDisposition,
        ContactResolverRetryClassification? lastRetry,
        uint? retryAfterSeconds,
        ReadOnlySpan<byte> requiredViewHash32,
        ReadOnlySpan<byte> exactXis1,
        DateTimeOffset updatedAt)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        PendingAddress = pendingAddress ?? throw new ArgumentNullException(nameof(pendingAddress));
        RequireNonzero(operationId32, 32, nameof(operationId32));
        RequireNonzero(requestHash32, 32, nameof(requestHash32));
        RequireNonzero(relationshipId32, 32, nameof(relationshipId32));
        if (exactXiq1.IsEmpty) throw new ArgumentException("Exact XIQ1 is required.", nameof(exactXiq1));
        if (!Enum.IsDefined(state)) throw new ArgumentOutOfRangeException(nameof(state));
        if ((lastDisposition is null) != (lastRetry is null))
            throw new ArgumentException("A durable resolver outcome must be complete.", nameof(lastDisposition));
        if (requiredViewHash32.Length is not (0 or 32))
            throw new ArgumentException("Required view hash must be absent or exactly 32 bytes.", nameof(requiredViewHash32));
        if (!requiredViewHash32.IsEmpty && requiredViewHash32.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Required view hash cannot be zero.", nameof(requiredViewHash32));
        if (updatedAt.Offset != TimeSpan.Zero || updatedAt.Ticks < 0)
            throw new ArgumentOutOfRangeException(nameof(updatedAt));

        this.operationId = operationId32.ToArray();
        this.requestHash = requestHash32.ToArray();
        relationshipId = relationshipId32.ToArray();
        this.exactXiq1 = exactXiq1.ToArray();
        this.exactXis1 = exactXis1.IsEmpty ? null : exactXis1.ToArray();
        requiredViewHash = requiredViewHash32.IsEmpty ? null : requiredViewHash32.ToArray();
        State = state;
        DispatchCount = dispatchCount;
        TransportAttemptCount = transportAttemptCount;
        LastDisposition = lastDisposition;
        LastRetry = lastRetry;
        RetryAfterSeconds = retryAfterSeconds;
        UpdatedAt = updatedAt;
    }

    public ContactStoreScope Scope { get; }
    public PendingContactAddress PendingAddress { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    public ContactRelationshipId32 RelationshipId => ContactRelationshipId32.FromBytes(relationshipId);
    public ReadOnlyMemory<byte> ExactXiq1 => exactXiq1.ToArray();
    public ContactResolveOperationState State { get; }
    public ulong DispatchCount { get; }
    public ulong TransportAttemptCount { get; }
    public ContactResolverDisposition? LastDisposition { get; }
    public ContactResolverRetryClassification? LastRetry { get; }
    public uint? RetryAfterSeconds { get; }
    public ReadOnlyMemory<byte> RequiredViewHash => requiredViewHash?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> ExactXis1 => exactXis1?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public DateTimeOffset UpdatedAt { get; }

    internal ReadOnlySpan<byte> OperationIdSpan => operationId;
    internal ReadOnlySpan<byte> RequestHashSpan => requestHash;
    internal ReadOnlySpan<byte> RelationshipIdSpan => relationshipId;
    internal ReadOnlySpan<byte> ExactXiq1Span => exactXiq1;
    internal ReadOnlySpan<byte> ExactXis1Span => exactXis1 is null ? [] : exactXis1;
    internal ReadOnlySpan<byte> RequiredViewHashSpan => requiredViewHash is null ? [] : requiredViewHash;

    internal ContactResolveOperationSnapshot Copy() => new(
        Scope,
        ContactStatePersistenceValidation.CloneAndValidate(PendingAddress),
        operationId,
        requestHash,
        relationshipId,
        exactXiq1,
        State,
        DispatchCount,
        TransportAttemptCount,
        LastDisposition,
        LastRetry,
        RetryAfterSeconds,
        requiredViewHash ?? [],
        exactXis1 ?? [],
        UpdatedAt);

    internal ContactResolveOperationSnapshot WithDispatch(DateTimeOffset updatedAt) => new(
        Scope,
        PendingAddress,
        operationId,
        requestHash,
        relationshipId,
        exactXiq1,
        State,
        checked(DispatchCount + 1),
        TransportAttemptCount,
        LastDisposition,
        LastRetry,
        RetryAfterSeconds,
        requiredViewHash ?? [],
        exactXis1 ?? [],
        updatedAt);

    internal ContactResolveOperationSnapshot WithOutcome(
        ContactResolveOutcomeUpdate update,
        DateTimeOffset updatedAt) => new(
            Scope,
            PendingAddress,
            operationId,
            requestHash,
            relationshipId,
            exactXiq1,
            ContactResolveOperationPersistenceValidation.StateFor(update),
            DispatchCount,
            checked(TransportAttemptCount + (ulong)update.TransportAttemptCount),
            update.Disposition,
            update.Retry,
            update.RetryAfterSeconds,
            update.RequiredViewHash.Span,
            update.ExactXis1.Span,
            updatedAt);

    private static void RequireNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
    }
}

internal sealed class ContactResolveOperationIntent
{
    internal ContactResolveOperationIntent(
        PendingContactAddress pendingAddress,
        ContactRelationshipId32 relationshipId,
        ReadOnlySpan<byte> exactXiq1)
    {
        PendingAddress = ContactStatePersistenceValidation.CloneAndValidate(
            pendingAddress ?? throw new ArgumentNullException(nameof(pendingAddress)));
        RelationshipId = relationshipId ?? throw new ArgumentNullException(nameof(relationshipId));
        ExactXiq1 = exactXiq1.ToArray();
    }

    internal PendingContactAddress PendingAddress { get; }
    internal ContactRelationshipId32 RelationshipId { get; }
    internal byte[] ExactXiq1 { get; }
}

internal sealed record ContactResolveOutcomeUpdate(
    ContactResolverDisposition Disposition,
    ContactResolverRetryClassification Retry,
    int TransportAttemptCount,
    uint? RetryAfterSeconds,
    ReadOnlyMemory<byte> RequiredViewHash,
    ReadOnlyMemory<byte> ExactXis1);

public sealed class ContactResolveOperationConflictException : InvalidOperationException
{
    public ContactResolveOperationConflictException()
        : base("The resolver operation ID is already bound to another immutable XIQ1 intent.") { }
}

public sealed class ContactResolveOperationCapacityException : InvalidOperationException
{
    public ContactResolveOperationCapacityException()
        : base("The bounded ContactV1 resolve-operation journal is full.") { }
}

public sealed class ContactResolveOperationStateException : InvalidOperationException
{
    internal ContactResolveOperationStateException(string message) : base(message) { }
}

public sealed class ContactResolveOperationMissingAddressException : InvalidOperationException
{
    internal ContactResolveOperationMissingAddressException()
        : base("The resolver intent has no exact imported pending address.") { }
}

internal static class ContactResolveOperationPersistenceValidation
{
    internal const int MaximumOperations = 10_000;
    internal const int MaximumOperationsPerRelationship = 16;

    internal static ContactResolveOperationSnapshot NewPrepared(
        ContactStoreScope scope,
        ContactResolveOperationIntent intent,
        DateTimeOffset updatedAt)
    {
        var request = Xiq1Codec.Decode(intent.ExactXiq1);
        ValidateAddressBinding(intent.PendingAddress, request);
        return new ContactResolveOperationSnapshot(
            scope,
            intent.PendingAddress,
            request.OperationId.Span,
            request.RequestHash.Span,
            intent.RelationshipId.Span,
            request.CanonicalBytes.Span,
            ContactResolveOperationState.Prepared,
            0,
            0,
            null,
            null,
            null,
            [],
            [],
            updatedAt);
    }

    internal static ContactResolveOperationSnapshot Validate(
        ContactResolveOperationSnapshot value,
        ContactStoreScope scope)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.Scope.Equals(scope))
            throw new InvalidOperationException("The resolver operation belongs to another account scope.");
        var request = Xiq1Codec.Decode(value.ExactXiq1Span);
        if (!Exact(request.OperationId.Span, value.OperationIdSpan)
            || !Exact(request.RequestHash.Span, value.RequestHashSpan))
            throw new FormatException("Durable resolver identity is not bound to exact XIQ1 bytes.");
        ValidateAddressBinding(value.PendingAddress, request);

        var hasOutcome = value.LastDisposition is not null;
        if (hasOutcome != (value.LastRetry is not null))
            throw new FormatException("Durable resolver classification is incomplete.");
        if (!hasOutcome && (value.State != ContactResolveOperationState.Prepared
                || !value.ExactXis1Span.IsEmpty || value.RetryAfterSeconds is not null
                || !value.RequiredViewHashSpan.IsEmpty || value.TransportAttemptCount != 0))
            throw new FormatException("Prepared resolver state contains result metadata.");
        if (hasOutcome && value.TransportAttemptCount == 0)
            throw new FormatException("A durable resolver outcome has no transport attempts.");
        if (!value.ExactXis1Span.IsEmpty)
        {
            var result = Xis1Codec.Decode(value.ExactXis1Span, value.ExactXiq1Span);
            var trustedRejected = value.LastDisposition == ContactResolverDisposition.ProtocolRejected
                && value.LastRetry == ContactResolverRetryClassification.FailClosed
                && result.Status == Xis1Status.Success;
            if ((!trustedRejected
                    && (MapDisposition(result.Status) != value.LastDisposition
                        || MapRetry(result.Status) != value.LastRetry))
                || result.RetryAfterSeconds != (value.RetryAfterSeconds ?? 0))
                throw new FormatException("Durable XIS1 metadata differs from its classification.");
            if (result.Status == Xis1Status.StaleView
                && !Exact(result.Field(16).Span, value.RequiredViewHashSpan))
                throw new FormatException("Durable StaleView hint differs from exact XIS1.");
        }
        ValidateState(value);
        return value.Copy();
    }

    internal static ContactResolveOperationState StateFor(ContactResolveOutcomeUpdate update) =>
        update.Disposition == ContactResolverDisposition.Verified
            ? ContactResolveOperationState.RelationshipLinked
            : update.Retry switch
            {
                ContactResolverRetryClassification.RetrySameExactRequest => ContactResolveOperationState.RetryPending,
                ContactResolverRetryClassification.RefreshViewAndCreateNewOperation => ContactResolveOperationState.AwaitingRefreshedContext,
                ContactResolverRetryClassification.Terminal => ContactResolveOperationState.Terminal,
                ContactResolverRetryClassification.FailClosed => ContactResolveOperationState.FailClosed,
                _ => throw new ArgumentException("A non-success resolver outcome has an invalid retry classification.", nameof(update)),
            };

    internal static ContactResolverDisposition MapDisposition(Xis1Status status) => status switch
    {
        Xis1Status.Success => ContactResolverDisposition.Verified,
        Xis1Status.Expired => ContactResolverDisposition.Expired,
        Xis1Status.AlreadyClaimed => ContactResolverDisposition.AlreadyClaimed,
        Xis1Status.NotFound => ContactResolverDisposition.NotFound,
        Xis1Status.TemporarilyUnavailable => ContactResolverDisposition.TemporarilyUnavailable,
        Xis1Status.RateLimited => ContactResolverDisposition.RateLimited,
        Xis1Status.StaleView => ContactResolverDisposition.StaleView,
        Xis1Status.Conflict => ContactResolverDisposition.Conflict,
        Xis1Status.OutcomeUnknown => ContactResolverDisposition.OutcomeUnknown,
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    internal static ContactResolverRetryClassification MapRetry(Xis1Status status) => status switch
    {
        Xis1Status.Success => ContactResolverRetryClassification.None,
        Xis1Status.Expired or Xis1Status.AlreadyClaimed or Xis1Status.NotFound =>
            ContactResolverRetryClassification.Terminal,
        Xis1Status.TemporarilyUnavailable or Xis1Status.RateLimited or Xis1Status.OutcomeUnknown =>
            ContactResolverRetryClassification.RetrySameExactRequest,
        Xis1Status.StaleView => ContactResolverRetryClassification.RefreshViewAndCreateNewOperation,
        Xis1Status.Conflict => ContactResolverRetryClassification.FailClosed,
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    internal static bool Exact(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void ValidateAddressBinding(PendingContactAddress pending, Xiq1Request request)
    {
        if (!Exact(pending.Address.NetworkId.Span, request.NetworkId.Span))
            throw new FormatException("Durable XIQ1 belongs to another network.");
        var expectedLocator = ContactCodecHash.OneTimeOrPermanentLocator(pending.Address);
        try
        {
            if (!Exact(expectedLocator, request.LocatorHash.Span))
                throw new FormatException("Durable XIQ1 is not bound to the imported address.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedLocator);
        }
    }

    private static void ValidateState(ContactResolveOperationSnapshot value)
    {
        if (value.LastDisposition is null) return;
        var update = new ContactResolveOutcomeUpdate(
            value.LastDisposition.Value,
            value.LastRetry!.Value,
            checked((int)value.TransportAttemptCount),
            value.RetryAfterSeconds,
            value.RequiredViewHash,
            value.ExactXis1);
        if (StateFor(update) != value.State)
            throw new FormatException("Durable resolver state differs from its retry classification.");
        if ((value.LastDisposition == ContactResolverDisposition.StaleView)
            != !value.RequiredViewHashSpan.IsEmpty)
            throw new FormatException("Only StaleView may persist a required-view hint.");
    }
}
