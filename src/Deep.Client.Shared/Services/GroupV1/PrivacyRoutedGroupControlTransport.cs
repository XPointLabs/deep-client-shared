using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.GroupV1;

public sealed class GroupControlIngressRoute
{
    private readonly byte[] entryRouterId;

    public GroupControlIngressRoute(
        Uri entryOrigin,
        ReadOnlySpan<byte> entryRouterId)
    {
        ArgumentNullException.ThrowIfNull(entryOrigin);
        if (!entryOrigin.IsAbsoluteUri ||
            entryOrigin.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(entryOrigin.UserInfo) ||
            entryOrigin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(entryOrigin.Query) ||
            !string.IsNullOrEmpty(entryOrigin.Fragment))
        {
            throw new ArgumentException(
                "A GroupControl ingress route requires a clean HTTPS entry origin.",
                nameof(entryOrigin));
        }

        if (entryRouterId.Length != 32 ||
            entryRouterId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A GroupControl ingress route requires one nonzero 32-byte entry-router ID.",
                nameof(entryRouterId));
        }

        EntryOrigin = entryOrigin;
        this.entryRouterId = entryRouterId.ToArray();
    }

    public Uri EntryOrigin { get; }

    public ReadOnlyMemory<byte> EntryRouterId => entryRouterId.ToArray();

    public override string ToString() =>
        $"GroupControlIngressRoute {{ Entry = {EntryOrigin}, Router = [verified-binding] }}";
}

public enum GroupControlTransportFailure
{
    InvalidRequest = 1,
    RouteUnavailable = 2,
    TerminalRejected = 3,
    OutcomeUnknown = 4,
    ProtocolViolation = 5,
}

public sealed class GroupControlTransportException : IOException
{
    internal GroupControlTransportException(
        GroupControlTransportFailure failure,
        string message,
        Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    public GroupControlTransportFailure Failure { get; }
}

internal interface IGroupControlPrivacyBuiltRequest : IDisposable
{
    ReadOnlyMemory<byte> Frame { get; }
}

internal sealed record GroupControlPrivacyOpenedResponse(
    OnionOperation Operation,
    OnionTerminalResultKind Kind,
    OnionFailureCode? FailureCode,
    ReadOnlyMemory<byte> Body);

internal interface IGroupControlPrivacyCodec
{
    ValueTask<IGroupControlPrivacyBuiltRequest> BuildAsync(
        VerifiedOnionPathContext path,
        VerifiedCanonicalOnionRequest request,
        CancellationToken cancellationToken);

    ValueTask<GroupControlPrivacyOpenedResponse> OpenResponseAsync(
        ReadOnlyMemory<byte> frame,
        IGroupControlPrivacyBuiltRequest builtRequest,
        CancellationToken cancellationToken);
}

internal sealed class ProductionGroupControlPrivacyCodec : IGroupControlPrivacyCodec
{
    private readonly PrivacyRoutingCodec codec;

    internal ProductionGroupControlPrivacyCodec(PrivacyRoutingCodec codec) =>
        this.codec = codec ?? throw new ArgumentNullException(nameof(codec));

    public async ValueTask<IGroupControlPrivacyBuiltRequest> BuildAsync(
        VerifiedOnionPathContext path,
        VerifiedCanonicalOnionRequest request,
        CancellationToken cancellationToken) =>
        new Built(await codec.BuildAsync(path, request, cancellationToken).ConfigureAwait(false));

    public async ValueTask<GroupControlPrivacyOpenedResponse> OpenResponseAsync(
        ReadOnlyMemory<byte> frame,
        IGroupControlPrivacyBuiltRequest builtRequest,
        CancellationToken cancellationToken)
    {
        var built = builtRequest as Built ?? throw new ArgumentException(
            "The GroupControl reply context was not produced by the production privacy codec.",
            nameof(builtRequest));
        var opened = await codec.OpenResponseAsync(
            frame,
            built.Value.ReplyContext,
            cancellationToken).ConfigureAwait(false);
        return new GroupControlPrivacyOpenedResponse(
            opened.Result.Operation,
            opened.Result.Kind,
            opened.Result.FailureCode,
            opened.Result.Body);
    }

    private sealed class Built(PrivacyRoutingBuiltRequest value) : IGroupControlPrivacyBuiltRequest
    {
        internal PrivacyRoutingBuiltRequest Value { get; } =
            value ?? throw new ArgumentNullException(nameof(value));

        public ReadOnlyMemory<byte> Frame => Value.Frame;

        public void Dispose() => Value.Dispose();
    }
}

/// <summary>
/// Sends exact Protocol-authored GSW1/GSQ1 only through a verified GroupControl
/// onion path. A second privacy ingress may be attempted only when the primary
/// ingress proves that forwarding did not start. There is no direct service
/// endpoint fallback and no caller-provided cryptographic authority.
/// </summary>
public sealed class PrivacyRoutedGroupControlTransport :
    IDeepGroupControlTransport,
    IDisposable
{
    private readonly GroupControlIngressRoute primaryRoute;
    private readonly GroupControlIngressRoute fallbackRoute;
    private readonly IGroupControlPrivacyPathProvider pathProvider;
    private readonly IGroupControlPrivacyCodec codec;
    private readonly IPrivacyManagedIngressTransport primary;
    private readonly IPrivacyManagedIngressTransport fallback;
    private readonly IPrivacyMailboxRouteSelectionObserver? observer;
    private int disposed;

    internal PrivacyRoutedGroupControlTransport(
        GroupControlIngressRoute primaryRoute,
        GroupControlIngressRoute fallbackRoute,
        GroupControlPrivacyPathProvider pathProvider,
        PrivacyRoutingCodec codec,
        IPrivacyManagedIngressTransport primary,
        IPrivacyManagedIngressTransport fallback,
        IPrivacyMailboxRouteSelectionObserver? observer = null)
        : this(
            primaryRoute,
            fallbackRoute,
            pathProvider,
            new ProductionGroupControlPrivacyCodec(codec),
            primary,
            fallback,
            observer)
    {
    }

    internal PrivacyRoutedGroupControlTransport(
        GroupControlIngressRoute primaryRoute,
        GroupControlIngressRoute fallbackRoute,
        IGroupControlPrivacyPathProvider pathProvider,
        IGroupControlPrivacyCodec codec,
        IPrivacyManagedIngressTransport primary,
        IPrivacyManagedIngressTransport fallback,
        IPrivacyMailboxRouteSelectionObserver? observer = null)
    {
        this.primaryRoute = primaryRoute ?? throw new ArgumentNullException(nameof(primaryRoute));
        this.fallbackRoute = fallbackRoute ?? throw new ArgumentNullException(nameof(fallbackRoute));
        this.pathProvider = pathProvider ?? throw new ArgumentNullException(nameof(pathProvider));
        this.codec = codec ?? throw new ArgumentNullException(nameof(codec));
        this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
        this.fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        this.observer = observer;

        if (Fixed(primaryRoute.EntryRouterId.Span, fallbackRoute.EntryRouterId.Span))
        {
            throw new ArgumentException(
                "Primary and fallback GroupControl privacy ingress routes must bind different entry routers.",
                nameof(fallbackRoute));
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> ExecuteAsync(
        VerifiedGroupControlRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequestCapability(request);

        try
        {
            return await DispatchAsync(
                request,
                primaryRoute,
                primary,
                PrivacyMailboxRouteSelection.Primary,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception) when (exception.Retryable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await DispatchAsync(
                    request,
                    fallbackRoute,
                    fallback,
                    PrivacyMailboxRouteSelection.Fallback,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (PrivacyIngressRejectedBeforeForwardException fallbackException)
            {
                throw BeforeDispatch(fallbackException);
            }
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception)
        {
            throw BeforeDispatch(exception);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        primary.Dispose();
        if (!ReferenceEquals(primary, fallback))
        {
            fallback.Dispose();
        }
    }

    private async ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        VerifiedGroupControlRequest request,
        GroupControlIngressRoute route,
        IPrivacyManagedIngressTransport transport,
        PrivacyMailboxRouteSelection selection,
        CancellationToken cancellationToken)
    {
        PrivacyMailboxOnionAttempt attempt;
        try
        {
            attempt = await pathProvider.PrepareAsync(
                request,
                route,
                selection,
                cancellationToken).ConfigureAwait(false);
            if (attempt is null ||
                attempt.Request.Operation != OnionOperation.GroupControl ||
                !Fixed(attempt.Request.CanonicalBytes.Span, request.CanonicalBytes.Span) ||
                !Fixed(attempt.EntryRouterId.Span, route.EntryRouterId.Span))
            {
                throw Failure(
                    GroupControlTransportFailure.ProtocolViolation,
                    "The GroupControl path provider returned another operation, request, or ingress binding.");
            }
        }
        catch (GroupControlTransportException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            GroupControlPathException or OnionBoundaryException or
            CryptographicException or ArgumentException or InvalidDataException)
        {
            throw Failure(
                GroupControlTransportFailure.RouteUnavailable,
                "GroupControl privacy path selection failed closed.",
                exception);
        }

        using var built = await codec.BuildAsync(
            attempt.Path,
            attempt.Request,
            cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> encryptedResponse;
        try
        {
            encryptedResponse = await transport.ForwardAsync(
                built.Frame,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PrivacyIngressRejectedBeforeForwardException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            IOException or HttpRequestException or OperationCanceledException or
            InvalidDataException)
        {
            throw Failure(
                GroupControlTransportFailure.OutcomeUnknown,
                "The GroupControl privacy dispatch outcome is unknown.",
                exception);
        }

        GroupControlPrivacyOpenedResponse opened;
        try
        {
            opened = await codec.OpenResponseAsync(
                encryptedResponse,
                built,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is
            OnionBoundaryException or CryptographicException or
            ArgumentException or InvalidDataException or IOException)
        {
            throw Failure(
                GroupControlTransportFailure.OutcomeUnknown,
                "The GroupControl privacy response could not be authenticated after forwarding.",
                exception);
        }

        if (opened.Operation != OnionOperation.GroupControl)
        {
            throw Failure(
                GroupControlTransportFailure.ProtocolViolation,
                "The GroupControl privacy response changed the terminal operation.");
        }

        if (opened.Kind == OnionTerminalResultKind.Failure)
        {
            throw Failure(
                GroupControlTransportFailure.TerminalRejected,
                $"The GroupControl exit rejected the operation with {opened.FailureCode?.ToString() ?? "an unknown failure"}.");
        }

        if (opened.Kind != OnionTerminalResultKind.Success ||
            opened.Body.Length is < 1 or > OnionLimits.MaximumGroupControlResponseBytes)
        {
            throw Failure(
                GroupControlTransportFailure.ProtocolViolation,
                "The GroupControl success response has an invalid terminal kind or hostile length.");
        }

        VerifiedGroupControlResult verified;
        try
        {
            verified = GroupControlProductionClient.VerifyResult(request, opened.Body);
        }
        catch (Exception exception) when (exception is
            GroupControlClientException or CryptographicException or
            ArgumentException or InvalidDataException or OverflowException)
        {
            throw Failure(
                GroupControlTransportFailure.ProtocolViolation,
                "GSS1 failed exact request, operation, placement, or receipt binding.",
                exception);
        }

        PublishRouteSelection(selection, attempt.EntryRouterId);
        return verified.CanonicalBytes;
    }

    private static void ValidateRequestCapability(VerifiedGroupControlRequest request)
    {
        var validKind = request.Kind switch
        {
            GroupControlRequestKind.Write => string.Equals(
                request.Record.Magic,
                "GSW1",
                StringComparison.Ordinal),
            GroupControlRequestKind.Fetch => string.Equals(
                request.Record.Magic,
                "GSQ1",
                StringComparison.Ordinal),
            _ => false,
        };
        if (!validKind ||
            request.CanonicalBytes.Length is < 1 or > OnionLimits.MaximumGroupControlRequestBytes)
        {
            throw Failure(
                GroupControlTransportFailure.InvalidRequest,
                "The GroupControl transport accepts only exact Protocol-authored GSW1 or GSQ1 capabilities.");
        }
    }

    private void PublishRouteSelection(
        PrivacyMailboxRouteSelection selection,
        ReadOnlyMemory<byte> entryRouterId)
    {
        try
        {
            observer?.Observe(selection, entryRouterId);
        }
        catch
        {
            // Diagnostics must never alter authenticated GroupControl behavior.
        }
    }

    private static GroupControlTransportException BeforeDispatch(
        PrivacyIngressRejectedBeforeForwardException exception) =>
        Failure(
            GroupControlTransportFailure.RouteUnavailable,
            "The GroupControl privacy ingress rejected the request before forwarding.",
            exception);

    private static GroupControlTransportException Failure(
        GroupControlTransportFailure failure,
        string message,
        Exception? innerException = null) =>
        new(failure, message, innerException);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
