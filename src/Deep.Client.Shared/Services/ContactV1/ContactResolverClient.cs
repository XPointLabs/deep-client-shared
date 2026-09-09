using System.Collections.Concurrent;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

public enum ContactResolverRetryClassification
{
    None = 0,
    RetrySameExactRequest = 1,
    RefreshViewAndCreateNewOperation = 2,
    Terminal = 3,
    FailClosed = 4,
}

public enum ContactResolverDisposition
{
    Verified = 1,
    Expired = 2,
    AlreadyClaimed = 3,
    NotFound = 4,
    TemporarilyUnavailable = 5,
    RateLimited = 6,
    StaleView = 7,
    Conflict = 8,
    OutcomeUnknown = 9,
    TransportUnavailable = 10,
    ProtocolRejected = 11,
}

public sealed record ContactResolverResult(
    ContactResolverDisposition Disposition,
    ContactResolverRetryClassification Retry,
    int AttemptCount,
    ContactRelationshipCommitResult? Commit,
    TimeSpan? RetryAfter,
    ReadOnlyMemory<byte> RequiredViewHash)
{
    private byte[] exactXis1 = [];

    internal static ContactResolverResult WithExactXis1(
        ContactResolverResult result,
        ReadOnlySpan<byte> exactXis1)
    {
        ArgumentNullException.ThrowIfNull(result);
        result.exactXis1 = exactXis1.ToArray();
        return result;
    }

    internal ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();
}

public sealed class ContactResolverCommand
{
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;

    private ContactResolverCommand(
        PendingContactAddress pendingAddress,
        ContactMutationId32 operationId,
        ContactRelationshipId32 relationshipId,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong requestedGeneration = 0,
        ContactServicePaddingClass responsePaddingClass = ContactServicePaddingClass.Bytes16384)
    {
        PendingAddress = pendingAddress ?? throw new ArgumentNullException(nameof(pendingAddress));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        RelationshipId = relationshipId ?? throw new ArgumentNullException(nameof(relationshipId));
        RequireHash(viewHash32, nameof(viewHash32));
        RequireHash(placementHash32, nameof(placementHash32));
        if (issuedAtUnixSeconds >= expiresAtUnixSeconds)
            throw new ArgumentException("XIQ1 issued-at must precede expires-at.", nameof(expiresAtUnixSeconds));
        if (issuedAtUnixSeconds > 253_402_300_799UL)
            throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));
        if (expiresAtUnixSeconds > 253_402_300_799UL)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        if (responsePaddingClass is < ContactServicePaddingClass.Bytes256 or > ContactServicePaddingClass.Bytes16384)
            throw new ArgumentOutOfRangeException(nameof(responsePaddingClass));
        if (pendingAddress.Address.ExpiresAtUnixSeconds is { } invitationExpiry &&
            issuedAtUnixSeconds >= invitationExpiry)
            throw new ArgumentException("The one-time invitation is already expired at request issue time.", nameof(pendingAddress));
        if (pendingAddress.Address.ExpiresAtUnixSeconds is { } requestBound
            && expiresAtUnixSeconds > requestBound)
            throw new ArgumentException("The XIQ1 request cannot outlive its one-time invitation.", nameof(expiresAtUnixSeconds));

        viewHash = viewHash32.ToArray();
        placementHash = placementHash32.ToArray();
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds((long)issuedAtUnixSeconds);
        RelationshipOccurredAt = issuedAt < pendingAddress.ImportedAt
            ? pendingAddress.ImportedAt
            : issuedAt;
        RequestedGeneration = requestedGeneration;
        ResponsePaddingClass = responsePaddingClass;
    }

    public PendingContactAddress PendingAddress { get; }
    public ContactMutationId32 OperationId { get; }
    public ContactRelationshipId32 RelationshipId { get; }
    public ReadOnlyMemory<byte> ViewHash => viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ulong RequestedGeneration { get; }
    public ContactServicePaddingClass ResponsePaddingClass { get; }
    public DateTimeOffset RelationshipOccurredAt { get; }

    internal static ContactResolverCommand CreateVerified(
        PendingContactAddress pendingAddress,
        VerifiedContactResolverPlacementContext verifiedContext,
        ContactMutationId32 operationId,
        ContactRelationshipId32 relationshipId,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong requestedGeneration = 0,
        ContactServicePaddingClass responsePaddingClass = ContactServicePaddingClass.Bytes16384)
    {
        ArgumentNullException.ThrowIfNull(verifiedContext);
        if (!verifiedContext.PendingAddress.Address.Equals(pendingAddress.Address)
            || verifiedContext.PendingAddress.ImportedAt != pendingAddress.ImportedAt)
            throw new CryptographicException("Verified resolver placement belongs to another imported address.");
        return new ContactResolverCommand(
            pendingAddress,
            operationId,
            relationshipId,
            verifiedContext.ViewHashSpan,
            verifiedContext.PlacementHashSpan,
            issuedAtUnixSeconds,
            expiresAtUnixSeconds,
            requestedGeneration,
            responsePaddingClass);
    }

#if DEEP_TEST_INTERNALS
    internal static ContactResolverCommand CreateUnverifiedForTests(
        PendingContactAddress pendingAddress,
        ContactMutationId32 operationId,
        ContactRelationshipId32 relationshipId,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong requestedGeneration = 0,
        ContactServicePaddingClass responsePaddingClass = ContactServicePaddingClass.Bytes16384) =>
        new(pendingAddress, operationId, relationshipId, viewHash32, placementHash32,
            issuedAtUnixSeconds, expiresAtUnixSeconds, requestedGeneration, responsePaddingClass);
#endif

    internal static ContactResolverCommand RestoreExact(
        PendingContactAddress pendingAddress,
        ContactRelationshipId32 relationshipId,
        ReadOnlySpan<byte> exactXiq1)
    {
        var request = Xiq1Codec.Decode(exactXiq1);
        return new ContactResolverCommand(
            pendingAddress,
            ContactMutationId32.FromBytes(request.OperationId.Span),
            relationshipId,
            request.ViewHash.Span,
            request.PlacementHash.Span,
            request.IssuedAtUnixSeconds,
            request.ExpiresAtUnixSeconds,
            request.RequestedGeneration,
            request.ResponsePaddingClass);
    }

    private static void RequireHash(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A resolver correlation hash must be exactly 32 nonzero bytes.", name);
    }
}

public sealed class ContactResolverClientOptions
{
    public ContactResolverClientOptions(
        int maximumAttempts = 3,
        TimeSpan? maximumAutomaticServerDelay = null,
        int rememberedOperationCount = 4_096)
    {
        if (maximumAttempts is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(maximumAttempts));
        var delay = maximumAutomaticServerDelay ?? TimeSpan.FromSeconds(30);
        if (delay < TimeSpan.Zero || delay > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(maximumAutomaticServerDelay));
        if (rememberedOperationCount is < 64 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(rememberedOperationCount));
        MaximumAttempts = maximumAttempts;
        MaximumAutomaticServerDelay = delay;
        RememberedOperationCount = rememberedOperationCount;
    }

    public int MaximumAttempts { get; }
    public TimeSpan MaximumAutomaticServerDelay { get; }
    public int RememberedOperationCount { get; }
}

public sealed class ContactResolverClient
{
    private readonly IContactStateStore store;
    private readonly ContactRelationshipService relationships;
    private readonly IContactResolverTransport transport;
    private readonly IContactResolverTrustedVerifier verifier;
    private readonly ContactResolverClientOptions options;
    private readonly ConcurrentDictionary<string, Lazy<Task<ContactResolverResult>>> inflight = new(StringComparer.Ordinal);
    private readonly object correlationGate = new();
    private readonly Dictionary<string, string> operationRequestHashes = new(StringComparer.Ordinal);
    private readonly Queue<string> operationOrder = new();

    public ContactResolverClient(
        IContactStateStore store,
        IContactResolverTransport transport,
        IContactResolverTrustedVerifier verifier,
        ContactResolverClientOptions? options = null)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.options = options ?? new ContactResolverClientOptions();
        relationships = new ContactRelationshipService(store);
    }

    public async ValueTask<ContactResolverResult> ResolveAsync(
        ContactResolverCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        var exactXiq1 = BuildExactXiq1(command);
        var decoded = Xiq1Codec.Decode(exactXiq1);
        RememberCorrelation(decoded.OperationId.Span, decoded.RequestHash.Span, command);
        var key = Convert.ToHexString(decoded.RequestHash.Span);
        var candidate = new Lazy<Task<ContactResolverResult>>(
            // The exact resolver operation is shared by request hash. A caller may
            // stop waiting, but it must not cancel the operation for other callers
            // that joined the same durable operation.
            () => ResolveCoreAsync(command, decoded, exactXiq1, CancellationToken.None),
            LazyThreadSafetyMode.ExecutionAndPublication);
        var active = inflight.GetOrAdd(key, candidate);
        if (ReferenceEquals(active, candidate))
        {
            _ = active.Value.ContinueWith(
                completed =>
                {
                    // A bounded dispatch can finish after every UI waiter has
                    // canceled. Observe its terminal exception before eviction.
                    _ = completed.Exception;
                    inflight.TryRemove(
                        new KeyValuePair<string, Lazy<Task<ContactResolverResult>>>(key, active));
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        return await active.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<ContactResolverResult> ResolveCoreAsync(
        ContactResolverCommand command,
        Xiq1Request decodedRequest,
        byte[] exactXiq1,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= options.MaximumAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ContactResolverTransportResponse transportResponse;
            try
            {
                transportResponse = await transport.SendXiq1Async(
                    new ContactResolverTransportRequest(exactXiq1, NewAttemptId()), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ContactResolverTransportException exception)
            {
                if (exception.Failure != ContactResolverTransportFailureKind.Permanent &&
                    attempt < options.MaximumAttempts)
                    continue;
                return new(ContactResolverDisposition.TransportUnavailable,
                    exception.Failure == ContactResolverTransportFailureKind.Permanent
                        ? ContactResolverRetryClassification.Terminal
                        : ContactResolverRetryClassification.RetrySameExactRequest,
                    attempt, null, null, ReadOnlyMemory<byte>.Empty);
            }

            Xis1Result result;
            try
            {
                result = Xis1Codec.Decode(transportResponse.ExactXis1.Span, exactXiq1);
            }
            catch (Exception exception) when (exception is ContactFormatException or ArgumentException or OverflowException)
            {
                throw new CryptographicException("The invite store returned malformed or uncorrelated XIS1.", exception);
            }

            if (result.Status == Xis1Status.Success)
            {
                ContactResolverTrustedVerificationResult verification;
                try
                {
                    verification = await verifier.VerifyAsync(
                        new ContactResolverVerificationInput(command.PendingAddress.Address, decodedRequest, result),
                        store.Scope, command.RelationshipId, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is
                    CryptographicException or FormatException or ArgumentException or InvalidOperationException)
                {
                    throw new ContactResolverTrustedVerificationException(
                        transportResponse.ExactXis1.Span, exception);
                }
                var evidence = verification.Evidence;
                ValidateVerifierCorrelation(evidence, command);
                var commit = await relationships.RecordBundleVerifiedAsync(
                    verification, command.OperationId, command.RelationshipOccurredAt,
                    cancellationToken).ConfigureAwait(false);
                if (commit.Disposition is ContactRelationshipCommitDisposition.Applied or
                    ContactRelationshipCommitDisposition.Idempotent)
                    return ContactResolverResult.WithExactXis1(new ContactResolverResult(ContactResolverDisposition.Verified,
                        ContactResolverRetryClassification.None, attempt, commit, null,
                        ReadOnlyMemory<byte>.Empty), transportResponse.ExactXis1.Span);
                throw new ContactResolverLocalLinkException(
                    transportResponse.ExactXis1.Span,
                    commit.Disposition);
            }

            var classified = Classify(result, attempt);
            if (ShouldAutomaticallyRetry(result, attempt))
            {
                if (result.RetryAfterSeconds > 0)
                    await Task.Delay(TimeSpan.FromSeconds(result.RetryAfterSeconds), cancellationToken).ConfigureAwait(false);
                continue;
            }
            return ContactResolverResult.WithExactXis1(classified, transportResponse.ExactXis1.Span);
        }
        throw new InvalidOperationException("The bounded resolver attempt loop did not terminate.");
    }

    internal static byte[] BuildExactXiq1(ContactResolverCommand command)
    {
        var address = command.PendingAddress.Address;
        var locatorHash = ContactCodecHash.OneTimeOrPermanentLocator(address);
        try
        {
            return Xiq1Codec.Encode(address.NetworkId.Span, command.OperationId.ToArray(),
                command.ViewHash.Span, command.PlacementHash.Span,
                command.IssuedAtUnixSeconds, command.ExpiresAtUnixSeconds,
                locatorHash, command.RequestedGeneration, Xiq1AntiSpamTokenType.None,
                ReadOnlySpan<byte>.Empty, command.ResponsePaddingClass);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locatorHash);
        }
    }

    private ContactResolverResult Classify(Xis1Result result, int attempts)
    {
        var retryAfter = result.RetryAfterSeconds == 0
            ? (TimeSpan?)null
            : TimeSpan.FromSeconds(result.RetryAfterSeconds);
        return result.Status switch
        {
            Xis1Status.Expired => Result(ContactResolverDisposition.Expired, ContactResolverRetryClassification.Terminal),
            Xis1Status.AlreadyClaimed => Result(ContactResolverDisposition.AlreadyClaimed, ContactResolverRetryClassification.Terminal),
            Xis1Status.NotFound => Result(ContactResolverDisposition.NotFound, ContactResolverRetryClassification.Terminal),
            Xis1Status.TemporarilyUnavailable => Result(ContactResolverDisposition.TemporarilyUnavailable, ContactResolverRetryClassification.RetrySameExactRequest),
            Xis1Status.RateLimited => Result(ContactResolverDisposition.RateLimited, ContactResolverRetryClassification.RetrySameExactRequest),
            Xis1Status.OutcomeUnknown => Result(ContactResolverDisposition.OutcomeUnknown, ContactResolverRetryClassification.RetrySameExactRequest),
            Xis1Status.StaleView => new(ContactResolverDisposition.StaleView,
                ContactResolverRetryClassification.RefreshViewAndCreateNewOperation, attempts, null, null, result.Field(16)),
            Xis1Status.Conflict => new(ContactResolverDisposition.Conflict,
                ContactResolverRetryClassification.FailClosed, attempts, null, null, ReadOnlyMemory<byte>.Empty),
            _ => throw new CryptographicException("A closed XIS1 status escaped protocol validation."),
        };

        ContactResolverResult Result(ContactResolverDisposition disposition, ContactResolverRetryClassification retry) =>
            new(disposition, retry, attempts, null, retryAfter, ReadOnlyMemory<byte>.Empty);
    }

    private bool ShouldAutomaticallyRetry(Xis1Result result, int attempt)
    {
        if (attempt >= options.MaximumAttempts || result.Status is not
            (Xis1Status.TemporarilyUnavailable or Xis1Status.RateLimited or Xis1Status.OutcomeUnknown))
            return false;
        if (result.RetryAfterSeconds == 0) return true;
        return TimeSpan.FromSeconds(result.RetryAfterSeconds) <= options.MaximumAutomaticServerDelay;
    }

    private void ValidateVerifierCorrelation(
        VerifiedContactBundleEvidence evidence,
        ContactResolverCommand command)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.Scope.Equals(store.Scope))
            throw new CryptographicException("Trusted verifier returned an invalid scope.");
        if (!evidence.RelationshipId.Equals(command.RelationshipId) ||
            !evidence.Address.Equals(command.PendingAddress.Address))
            throw new CryptographicException("Trusted verifier returned evidence for another resolver operation.");
    }

    private void RememberCorrelation(
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> requestHash,
        ContactResolverCommand command)
    {
        var operation = Convert.ToHexString(operationId);
        var relationship = command.RelationshipId.ToArray();
        var address = command.PendingAddress.Address.CanonicalBytes.ToArray();
        var intent = new byte[checked(requestHash.Length + relationship.Length + 1 + address.Length)];
        string hash;
        try
        {
            requestHash.CopyTo(intent);
            relationship.CopyTo(intent, requestHash.Length);
            intent[requestHash.Length + relationship.Length] = (byte)command.PendingAddress.Address.Kind;
            address.CopyTo(intent, requestHash.Length + relationship.Length + 1);
            hash = Convert.ToHexString(SHA256.HashData(intent));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(relationship);
            CryptographicOperations.ZeroMemory(address);
            CryptographicOperations.ZeroMemory(intent);
        }
        lock (correlationGate)
        {
            if (operationRequestHashes.TryGetValue(operation, out var prior))
            {
                if (!StringComparer.Ordinal.Equals(prior, hash))
                    throw new InvalidOperationException("An XIQ1 operation ID was reused for a different canonical request.");
                return;
            }
            operationRequestHashes.Add(operation, hash);
            operationOrder.Enqueue(operation);
            while (operationOrder.Count > options.RememberedOperationCount)
                operationRequestHashes.Remove(operationOrder.Dequeue());
        }
    }

    private static ContactResolverTransportAttemptId32 NewAttemptId()
    {
        var bytes = new byte[32];
        do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        try { return new ContactResolverTransportAttemptId32(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}

internal sealed class ContactResolverTrustedVerificationException : CryptographicException
{
    private readonly byte[] exactXis1;

    internal ContactResolverTrustedVerificationException(
        ReadOnlySpan<byte> exactXis1,
        Exception innerException)
        : base("The structurally valid XIS1 failed trusted closure verification.", innerException) =>
        this.exactXis1 = exactXis1.ToArray();

    internal ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();
}

internal sealed class ContactResolverLocalLinkException : CryptographicException
{
    private readonly byte[] exactXis1;

    internal ContactResolverLocalLinkException(
        ReadOnlySpan<byte> exactXis1,
        ContactRelationshipCommitDisposition disposition)
        : base($"Verified relationship persistence failed closed: {disposition}.") =>
        this.exactXis1 = exactXis1.ToArray();

    internal ReadOnlyMemory<byte> ExactXis1 => exactXis1.ToArray();
}
