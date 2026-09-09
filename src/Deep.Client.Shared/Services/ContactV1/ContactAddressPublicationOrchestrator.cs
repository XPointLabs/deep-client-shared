using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Services.ContactV1;

internal enum ContactDirectoryAuthorizationVerdict
{
    Authorized = 1,
    Rejected = 2,
    Indeterminate = 3,
}

/// <summary>
/// Trust boundary owned by the account-directory implementation. It MUST verify the
/// current directory closure, threshold-authorized XPA1, its permanent-address kind,
/// and its account binding.
/// This client layer never creates or substitutes an XPA1.
/// </summary>
internal interface IContactDirectoryPublicationAuthorityBoundary
{
    ValueTask<ContactDirectoryAuthorizationVerdict> VerifyPermanentAddressAuthorizedXpu1Async(
        ContactStoreScope accountScope,
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Account-bound exact XPU1 admitted by an explicit directory-authority boundary.
/// Instances cannot be created by bypassing that boundary.
/// </summary>
public sealed class DirectoryAuthorizedXpu1
{
    private readonly byte[] exactXpu1;

    private DirectoryAuthorizedXpu1(ContactStoreScope scope, ReadOnlySpan<byte> exactXpu1)
    {
        Scope = scope;
        this.exactXpu1 = exactXpu1.ToArray();
    }

    public ContactStoreScope Scope { get; }
    public ReadOnlyMemory<byte> ExactBytes => exactXpu1.ToArray();
    internal ReadOnlySpan<byte> ExactSpan => exactXpu1;

    internal static async ValueTask<DirectoryAuthorizedXpu1> AdmitAsync(
        IContactDirectoryPublicationAuthorityBoundary authorityBoundary,
        ContactStoreScope accountScope,
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorityBoundary);
        ArgumentNullException.ThrowIfNull(accountScope);

        try
        {
            _ = Xpu1Codec.Decode(exactXpu1.Span);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ContactAddressPublicationException(
                ContactAddressPublicationFailure.MalformedAuthorizedRequest,
                "The directory boundary returned a malformed XPU1 request.",
                exception);
        }

        var verdict = await authorityBoundary.VerifyPermanentAddressAuthorizedXpu1Async(
            accountScope, exactXpu1, cancellationToken).ConfigureAwait(false);
        if (verdict != ContactDirectoryAuthorizationVerdict.Authorized)
        {
            throw new ContactAddressPublicationException(
                ContactAddressPublicationFailure.DirectoryAuthorizationRejected,
                "The directory-authority boundary did not authorize this publication.");
        }

        return new DirectoryAuthorizedXpu1(accountScope, exactXpu1.Span);
    }
}

/// <summary>
/// Opaque XPoint contact-service path. Implementations transport exact service bytes;
/// they do not expose direct HTTP or rebuild protocol records.
/// </summary>
public interface IOpaqueContactAddressPublicationTransport
{
    ValueTask<ReadOnlyMemory<byte>> PublishAsync(
        ReadOnlyMemory<byte> exactXpu1,
        CancellationToken cancellationToken = default);
}

public enum ContactAddressPublicationFailure
{
    DirectoryAuthorizationRejected = 1,
    MalformedAuthorizedRequest = 2,
    AccountScopeMismatch = 3,
    MalformedServiceResult = 4,
}

public sealed class ContactAddressPublicationException : InvalidOperationException
{
    public ContactAddressPublicationException(
        ContactAddressPublicationFailure failure,
        string message,
        Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    public ContactAddressPublicationFailure Failure { get; }
}

public enum ContactAddressPublicationDisposition
{
    Confirmed = 1,
    AlreadyConfirmed = 2,
    RetryRequired = 3,
    Rejected = 4,
}

public sealed record ContactAddressPublicationResult(
    ContactAddressPublicationDisposition Disposition,
    Xpo1Status? Status,
    uint RetryAfterSeconds,
    ContactAddressPublicationSnapshot DurableState);

/// <summary>
/// Crash/retry-safe CONTACT-CLIENT-01 address-publication coordinator.
/// It persists exact authorized XPU1 bytes before the first transport attempt and
/// reuses those persisted bytes after every ambiguous outcome or process restart.
/// </summary>
public sealed class ContactAddressPublicationOrchestrator
{
    private readonly IContactAddressPublicationStore store;
    private readonly IOpaqueContactAddressPublicationTransport transport;

    public ContactAddressPublicationOrchestrator(
        IContactAddressPublicationStore store,
        IOpaqueContactAddressPublicationTransport transport)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    public async ValueTask<ContactAddressPublicationResult> PublishAsync(
        DirectoryAuthorizedXpu1 authorizedPublication,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorizedPublication);
        if (!authorizedPublication.Scope.Equals(store.Scope))
        {
            throw new ContactAddressPublicationException(
                ContactAddressPublicationFailure.AccountScopeMismatch,
                "The authorized publication belongs to another Deep account scope.");
        }

        var staged = await store.StageAttemptAsync(
            authorizedPublication.ExactBytes, cancellationToken).ConfigureAwait(false);
        var operation = ContactAddressPublicationPersistenceValidation.Validate(
            staged.Operation, store.Scope);
        if (!ContactAddressPublicationPersistenceValidation.ExactEquals(
                operation.ExactXpu1Span, authorizedPublication.ExactSpan))
        {
            throw new ContactAddressPublicationConflictException();
        }
        if (operation.State == ContactAddressPublicationState.Confirmed)
        {
            return new ContactAddressPublicationResult(
                ContactAddressPublicationDisposition.AlreadyConfirmed,
                operation.LastStatus,
                0,
                operation);
        }
        if (operation.State == ContactAddressPublicationState.Rejected)
        {
            return new ContactAddressPublicationResult(
                ContactAddressPublicationDisposition.Rejected,
                operation.LastStatus,
                operation.RetryAfterSeconds ?? 0,
                operation);
        }

        // Send the durable copy, never caller-owned bytes. If transport completion is
        // ambiguous, the pending row survives and the next call sends these same bytes.
        var exactResult = await transport.PublishAsync(
            operation.ExactXpu1, cancellationToken).ConfigureAwait(false);

        Xpo1Result result;
        try
        {
            result = Xpo1Codec.Decode(exactResult.Span, operation.ExactXpu1.Span);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            throw new ContactAddressPublicationException(
                ContactAddressPublicationFailure.MalformedServiceResult,
                "The contact service returned a malformed or uncorrelated XPO1 result.",
                exception);
        }

        var durableState = ContactAddressPublicationPersistenceValidation.StateFor(result.Status);
        var updated = await store.RecordValidatedResultAsync(
            operation.OperationId,
            operation.RequestHash,
            exactResult,
            durableState,
            cancellationToken).ConfigureAwait(false);
        updated = ContactAddressPublicationPersistenceValidation.Validate(updated, store.Scope);
        if (!ContactAddressPublicationPersistenceValidation.ExactEquals(
                operation.OperationIdSpan, updated.OperationIdSpan)
            || !ContactAddressPublicationPersistenceValidation.ExactEquals(
                operation.RequestHashSpan, updated.RequestHashSpan))
        {
            throw new ContactAddressPublicationConflictException();
        }

        var disposition = durableState switch
        {
            ContactAddressPublicationState.Confirmed => ContactAddressPublicationDisposition.Confirmed,
            ContactAddressPublicationState.Pending => ContactAddressPublicationDisposition.RetryRequired,
            ContactAddressPublicationState.Rejected => ContactAddressPublicationDisposition.Rejected,
            _ => throw new InvalidOperationException("Unknown durable publication state."),
        };
        return new ContactAddressPublicationResult(
            disposition,
            result.Status,
            result.RetryAfterSeconds,
            updated);
    }
}
