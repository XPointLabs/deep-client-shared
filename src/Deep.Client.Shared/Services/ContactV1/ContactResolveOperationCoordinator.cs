using System.Security.Cryptography;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV1;

/// <summary>
/// Non-serializable authority capability binding one imported address to one
/// verified current resolver placement. External assemblies can consume it but
/// can mint it only from a protocol-verified XPoint placement.
/// </summary>
public sealed class VerifiedContactResolverPlacementContext
{
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;

    private VerifiedContactResolverPlacementContext(
        ContactStoreScope scope,
        PendingContactAddress pendingAddress,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ulong validUntilUnixSeconds)
    {
        Scope = scope;
        PendingAddress = ContactStatePersistenceValidation.CloneAndValidate(pendingAddress);
        viewHash = viewHash32.ToArray();
        placementHash = placementHash32.ToArray();
        ValidUntilUnixSeconds = validUntilUnixSeconds;
    }

    internal ContactStoreScope Scope { get; }
    internal PendingContactAddress PendingAddress { get; }
    internal ReadOnlySpan<byte> ViewHashSpan => viewHash;
    internal ReadOnlySpan<byte> PlacementHashSpan => placementHash;
    internal ulong ValidUntilUnixSeconds { get; }

    public static VerifiedContactResolverPlacementContext Create(
        ContactStoreScope accountScope,
        PendingContactAddress pendingAddress,
        VerifiedContactServicePlacement placement) =>
        CreateCore(accountScope, pendingAddress, placement, TimeProvider.System.GetUtcNow());

#if DEEP_TEST_INTERNALS
    internal static VerifiedContactResolverPlacementContext CreateForTests(
        ContactStoreScope accountScope,
        PendingContactAddress pendingAddress,
        VerifiedContactServicePlacement placement,
        DateTimeOffset now) =>
        CreateCore(accountScope, pendingAddress, placement, now);
#endif

    private static VerifiedContactResolverPlacementContext CreateCore(
        ContactStoreScope accountScope,
        PendingContactAddress pendingAddress,
        VerifiedContactServicePlacement placement,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(accountScope);
        ArgumentNullException.ThrowIfNull(pendingAddress);
        ArgumentNullException.ThrowIfNull(placement);

        var networkId = placement.Network.NetworkId;
        if (!CryptographicOperations.FixedTimeEquals(
                networkId.Span,
                pendingAddress.Address.NetworkId.Span))
            throw new CryptographicException("The verified resolver placement belongs to another network.");

        var locatorHash = ContactCodecHash.OneTimeOrPermanentLocator(pendingAddress.Address);
        try
        {
            if (!placement.Binds(ContactServiceRequestKind.ResolveInvite, locatorHash))
                throw new CryptographicException("The verified service placement does not authorize resolving this imported address.");

            var nowUnixSeconds = checked((ulong)now.ToUniversalTime().ToUnixTimeSeconds());
            if (placement.ValidUntilUnixSeconds <= nowUnixSeconds)
                throw new CryptographicException("The verified resolver placement has expired.");

            var verifiedViewHash = placement.ViewHash;
            var verifiedPlacementHash = placement.PlacementHash;
            RequireHash(verifiedViewHash.Span, nameof(placement));
            RequireHash(verifiedPlacementHash.Span, nameof(placement));
            if (placement.ValidUntilUnixSeconds > 253_402_300_799UL)
                throw new CryptographicException("The verified resolver placement expiry is outside the supported range.");

            return new VerifiedContactResolverPlacementContext(
                accountScope,
                pendingAddress,
                verifiedViewHash.Span,
                verifiedPlacementHash.Span,
                placement.ValidUntilUnixSeconds);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(locatorHash);
        }
    }

    private static void RequireHash(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A verified resolver context hash must be exactly 32 nonzero bytes.", name);
    }
}

public sealed class ContactResolveRequestParameters
{
    public ContactResolveRequestParameters(
        TimeSpan? requestLifetime = null,
        ulong requestedGeneration = 0,
        ContactServicePaddingClass responsePaddingClass = ContactServicePaddingClass.Bytes16384)
    {
        var lifetime = requestLifetime ?? TimeSpan.FromMinutes(5);
        if (lifetime < TimeSpan.FromSeconds(1) || lifetime > TimeSpan.FromHours(1)
            || lifetime.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentOutOfRangeException(nameof(requestLifetime));
        if (responsePaddingClass is < ContactServicePaddingClass.Bytes256 or > ContactServicePaddingClass.Bytes16384)
            throw new ArgumentOutOfRangeException(nameof(responsePaddingClass));
        RequestLifetime = lifetime;
        RequestedGeneration = requestedGeneration;
        ResponsePaddingClass = responsePaddingClass;
    }

    public TimeSpan RequestLifetime { get; }
    public ulong RequestedGeneration { get; }
    public ContactServicePaddingClass ResponsePaddingClass { get; }
}

public sealed record ContactResolveOperationResult(
    ContactResolverResult Result,
    ContactResolveOperationSnapshot DurableState);

/// <summary>
/// Bounded, restart-safe ContactV1 resolve coordinator. It journals exact XIQ1
/// before dispatch, retries only the durable bytes after ambiguous completion,
/// and exposes every durable non-success classification to the caller.
/// </summary>
public sealed class ContactResolveOperationCoordinator
{
    private readonly IContactStateStore contactStore;
    private readonly IContactResolveOperationStore operationStore;
    private readonly ContactResolverClient resolver;
    private readonly TimeProvider timeProvider;

    public ContactResolveOperationCoordinator(
        IContactStateStore store,
        IContactResolverTransport transport,
        IContactResolverTrustedVerifier verifier,
        ContactResolverClientOptions? resolverOptions = null,
        TimeProvider? timeProvider = null)
    {
        contactStore = store ?? throw new ArgumentNullException(nameof(store));
        operationStore = store as IContactResolveOperationStore
            ?? throw new ArgumentException("The ContactV1 store does not provide the sealed resolve-operation journal.", nameof(store));
        var singleDispatch = resolverOptions
            ?? new ContactResolverClientOptions(1, TimeSpan.Zero, 4_096);
        if (singleDispatch.MaximumAttempts != 1)
            throw new ArgumentException(
                "The durable coordinator requires one transport attempt per persisted transition.",
                nameof(resolverOptions));
        resolver = new ContactResolverClient(store, transport, verifier, singleDispatch);
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public ValueTask<ContactResolveOperationResult> StartAsync(
        PendingContactAddress pendingAddress,
        VerifiedContactResolverPlacementContext verifiedContext,
        ContactResolveRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pendingAddress);
        ArgumentNullException.ThrowIfNull(verifiedContext);
        EnsureContext(pendingAddress, verifiedContext);
        var command = NewCommand(
            pendingAddress,
            verifiedContext,
            NewMutationId(),
            NewRelationshipId(),
            parameters ?? new ContactResolveRequestParameters());
        return StageAndRunAsync(command, cancellationToken);
    }

    public async ValueTask<ContactResolveOperationResult> ResumeAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = await operationStore.ReadResolveOperationAsync(
            operationId32, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("The ContactV1 resolve operation does not exist in this account scope.");
        return await RunDurableAsync(snapshot, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<ContactResolveOperationResult> RestartAfterStaleViewAsync(
        ReadOnlyMemory<byte> staleOperationId32,
        VerifiedContactResolverPlacementContext refreshedContext,
        ContactResolveRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshedContext);
        cancellationToken.ThrowIfCancellationRequested();
        var stale = await operationStore.ReadResolveOperationAsync(
            staleOperationId32, cancellationToken).ConfigureAwait(false)
            ?? throw new KeyNotFoundException("The stale ContactV1 resolve operation does not exist.");
        if (stale.State != ContactResolveOperationState.AwaitingRefreshedContext
            || stale.LastDisposition != ContactResolverDisposition.StaleView)
            throw new InvalidOperationException("Only a durable StaleView operation can be replaced.");
        EnsureContext(stale.PendingAddress, refreshedContext);
        var previous = Xiq1Codec.Decode(stale.ExactXiq1.Span);
        if (CryptographicOperations.FixedTimeEquals(previous.ViewHash.Span, refreshedContext.ViewHashSpan))
            throw new CryptographicException("StaleView requires a separately verified successor context and a new operation.");
        var command = NewCommand(
            stale.PendingAddress,
            refreshedContext,
            NewMutationId(),
            stale.RelationshipId,
            parameters ?? new ContactResolveRequestParameters());
        return await StageAndRunAsync(command, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<ContactResolveOperationSnapshot?> ReadAsync(
        ReadOnlyMemory<byte> operationId32,
        CancellationToken cancellationToken = default) =>
        operationStore.ReadResolveOperationAsync(operationId32, cancellationToken);

    public ValueTask<IReadOnlyList<ContactResolveOperationSnapshot>> ReadAllAsync(
        CancellationToken cancellationToken = default) =>
        operationStore.ReadResolveOperationsAsync(cancellationToken);

    private async ValueTask<ContactResolveOperationResult> StageAndRunAsync(
        ContactResolverCommand command,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var exactXiq1 = ContactResolverClient.BuildExactXiq1(command);
        var staged = await operationStore.StageResolveOperationAsync(
            new ContactResolveOperationIntent(command.PendingAddress, command.RelationshipId, exactXiq1),
            UtcNow(), cancellationToken).ConfigureAwait(false);
        return await RunDurableAsync(staged.Operation, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<ContactResolveOperationResult> RunDurableAsync(
        ContactResolveOperationSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        snapshot = ContactResolveOperationPersistenceValidation.Validate(snapshot, contactStore.Scope);
        if (snapshot.State is ContactResolveOperationState.AwaitingRefreshedContext
            or ContactResolveOperationState.Terminal
            or ContactResolveOperationState.RelationshipLinked
            or ContactResolveOperationState.FailClosed)
            return new ContactResolveOperationResult(await RestoreResultAsync(snapshot, cancellationToken).ConfigureAwait(false), snapshot);

        var dispatched = await operationStore.BeginResolveDispatchAsync(
            snapshot.OperationId,
            snapshot.RequestHash,
            UtcNow(),
            cancellationToken).ConfigureAwait(false);
        var command = ContactResolverCommand.RestoreExact(
            dispatched.PendingAddress,
            dispatched.RelationshipId,
            dispatched.ExactXiq1.Span);
        var rebuilt = ContactResolverClient.BuildExactXiq1(command);
        if (!ContactResolveOperationPersistenceValidation.Exact(rebuilt, dispatched.ExactXiq1.Span))
            throw new CryptographicException("Persisted XIQ1 could not be reproduced byte-identically.");

        ContactResolverResult result;
        try
        {
            result = await resolver.ResolveAsync(command, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CryptographicException exception)
        {
            var rejected = new ContactResolveOutcomeUpdate(
                ContactResolverDisposition.ProtocolRejected,
                ContactResolverRetryClassification.FailClosed,
                1,
                null,
                ReadOnlyMemory<byte>.Empty,
                exception switch
                {
                    ContactResolverTrustedVerificationException trusted => trusted.ExactXis1,
                    ContactResolverLocalLinkException local => local.ExactXis1,
                    _ => ReadOnlyMemory<byte>.Empty,
                });
            var failed = await operationStore.RecordResolveOutcomeAsync(
                dispatched.OperationId, dispatched.RequestHash, rejected, UtcNow(),
                CancellationToken.None).ConfigureAwait(false);
            throw new ContactResolveOperationFailClosedException(failed, exception);
        }

        var retryAfterSeconds = result.RetryAfter is null
            ? (uint?)null
            : checked((uint)result.RetryAfter.Value.TotalSeconds);
        var update = new ContactResolveOutcomeUpdate(
            result.Disposition,
            result.Retry,
            result.AttemptCount,
            retryAfterSeconds,
            result.RequiredViewHash,
            result.ExactXis1);
        var persisted = await operationStore.RecordResolveOutcomeAsync(
            dispatched.OperationId,
            dispatched.RequestHash,
            update,
            UtcNow(),
            CancellationToken.None).ConfigureAwait(false);
        return new ContactResolveOperationResult(result, persisted);
    }

    private async ValueTask<ContactResolverResult> RestoreResultAsync(
        ContactResolveOperationSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        if (snapshot.LastDisposition is null || snapshot.LastRetry is null)
            throw new FormatException("A terminal durable resolver operation has no UI classification.");
        ContactRelationshipCommitResult? commit = null;
        if (snapshot.State == ContactResolveOperationState.RelationshipLinked)
        {
            var relationship = await contactStore.ReadRelationshipAsync(
                snapshot.RelationshipId, cancellationToken).ConfigureAwait(false)
                ?? throw new FormatException("A completed resolver operation lost its linked relationship.");
            commit = new ContactRelationshipCommitResult(
                ContactRelationshipCommitDisposition.Idempotent,
                relationship,
                relationship.Revision);
        }
        return new ContactResolverResult(
            snapshot.LastDisposition.Value,
            snapshot.LastRetry.Value,
            checked((int)snapshot.TransportAttemptCount),
            commit,
            snapshot.RetryAfterSeconds is null
                ? null
                : TimeSpan.FromSeconds(snapshot.RetryAfterSeconds.Value),
            snapshot.RequiredViewHash);
    }

    private ContactResolverCommand NewCommand(
        PendingContactAddress pendingAddress,
        VerifiedContactResolverPlacementContext context,
        ContactMutationId32 operationId,
        ContactRelationshipId32 relationshipId,
        ContactResolveRequestParameters parameters)
    {
        var now = UtcNow();
        var issuedAt = checked((ulong)now.ToUnixTimeSeconds());
        if (context.ValidUntilUnixSeconds <= issuedAt)
            throw new CryptographicException("The verified resolver placement expired before the operation could be journaled.");
        if (pendingAddress.Address.ExpiresAtUnixSeconds is { } invitationExpiry
            && invitationExpiry <= issuedAt)
            throw new CryptographicException("The one-time invitation expired before the operation could be journaled.");

        var requestedExpiry = checked(issuedAt + (ulong)parameters.RequestLifetime.TotalSeconds);
        var expiresAt = Math.Min(requestedExpiry, context.ValidUntilUnixSeconds);
        if (pendingAddress.Address.ExpiresAtUnixSeconds is { } invitationBound)
            expiresAt = Math.Min(expiresAt, invitationBound);
        if (expiresAt <= issuedAt)
            throw new CryptographicException("The resolver request has no live authorized interval.");
        return ContactResolverCommand.CreateVerified(
            pendingAddress,
            context,
            operationId,
            relationshipId,
            issuedAt,
            expiresAt,
            parameters.RequestedGeneration,
            parameters.ResponsePaddingClass);
    }

    private void EnsureContext(
        PendingContactAddress pendingAddress,
        VerifiedContactResolverPlacementContext context)
    {
        if (!context.Scope.Equals(contactStore.Scope)
            || !context.PendingAddress.Address.Equals(pendingAddress.Address)
            || context.PendingAddress.ImportedAt != pendingAddress.ImportedAt)
            throw new CryptographicException("Verified resolver placement belongs to another account or imported address.");
    }

    private DateTimeOffset UtcNow() => timeProvider.GetUtcNow().ToUniversalTime();

    private static ContactMutationId32 NewMutationId() =>
        ContactMutationId32.FromBytes(NewIdentifierBytes());

    private static ContactRelationshipId32 NewRelationshipId() =>
        ContactRelationshipId32.FromBytes(NewIdentifierBytes());

    private static byte[] NewIdentifierBytes()
    {
        var bytes = new byte[32];
        do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return bytes;
    }
}

public sealed class ContactResolveOperationFailClosedException : CryptographicException
{
    internal ContactResolveOperationFailClosedException(
        ContactResolveOperationSnapshot durableState,
        CryptographicException innerException)
        : base("The resolver response or trusted verification failed closed.", innerException) =>
        DurableState = durableState;

    public ContactResolveOperationSnapshot DurableState { get; }
}
