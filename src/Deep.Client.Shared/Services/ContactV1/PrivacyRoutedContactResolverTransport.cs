using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Client.Shared.Services.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV1;

internal sealed record ExactContactResolveOnionResponse(
    ReadOnlyMemory<byte> ExactBody,
    ContactResolvePathAuthority? PathAuthority);

internal interface IExactContactResolveOnionTransport
{
    ValueTask<ExactContactResolveOnionResponse> SendExactAsync(
        ContactResolveCanonicalPathRequest request,
        ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Sends exact canonical ContactResolve requests through a verified three-hop
/// ONION attempt. The
/// fallback route is eligible solely when the primary ingress proves that it
/// rejected the opaque frame before forwarding.
/// </summary>
public sealed class PrivacyRoutedContactResolverTransport :
    IContactResolverTransport,
    IExactContactResolveOnionTransport,
    IDisposable
{
    private readonly PrivacyMailboxRoute primaryRoute;
    private readonly PrivacyMailboxRoute fallbackRoute;
    private readonly IPrivacyManagedIngressTransport primary;
    private readonly IPrivacyManagedIngressTransport fallback;
    private readonly PrivacyRoutingCodec codec;
    private readonly IPrivacyMailboxRouteSelectionObserver? observer;
    private int disposed;

    public PrivacyRoutedContactResolverTransport(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        PrivacyRoutingCodec codec,
        IPrivacyMailboxRouteSelectionObserver? observer = null)
        : this(
            primaryRoute,
            fallbackRoute,
            codec,
            CreateOwned(primaryRoute, fallbackRoute),
            observer)
    {
    }

    private PrivacyRoutedContactResolverTransport(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        PrivacyRoutingCodec codec,
        OwnedTransports transports,
        IPrivacyMailboxRouteSelectionObserver? observer)
        : this(
            primaryRoute,
            fallbackRoute,
            codec,
            transports.Primary,
            transports.Fallback,
            observer)
    {
    }

    internal PrivacyRoutedContactResolverTransport(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        PrivacyRoutingCodec codec,
        IPrivacyManagedIngressTransport primary,
        IPrivacyManagedIngressTransport fallback,
        IPrivacyMailboxRouteSelectionObserver? observer = null)
    {
        this.primaryRoute = primaryRoute ?? throw new ArgumentNullException(nameof(primaryRoute));
        this.fallbackRoute = fallbackRoute ?? throw new ArgumentNullException(nameof(fallbackRoute));
        this.codec = codec ?? throw new ArgumentNullException(nameof(codec));
        this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
        this.fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        this.observer = observer;
    }

    public async ValueTask<ContactResolverTransportResponse> SendXiq1Async(
        ContactResolverTransportRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateCanonicalXiq1(request.ExactXiq1.Span);

        var canonicalRequest = ContactResolveCanonicalPathRequest.Decode(
            request.ExactXiq1.Span);
        var exact = await SendExactCoreAsync(
                canonicalRequest,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);
        ContactResolverTransportResponse response;
        try
        {
            response = new ContactResolverTransportResponse(exact.ExactBody.Span);
            ValidateCanonicalXis1(request.ExactXiq1.Span, response.ExactXis1.Span);
        }
        catch (Exception exception) when (exception is ArgumentException or ContactFormatException
            or InvalidDataException or OverflowException)
        {
            throw Unknown(exception);
        }
        return response;
    }

    ValueTask<ExactContactResolveOnionResponse> IExactContactResolveOnionTransport.SendExactAsync(
        ContactResolveCanonicalPathRequest request,
        ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken) =>
        SendExactCoreAsync(request, requiredExitReplicaId, cancellationToken);

    private async ValueTask<ExactContactResolveOnionResponse> SendExactCoreAsync(
        ContactResolveCanonicalPathRequest request,
        ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            return await DispatchAsync(
                primaryRoute,
                primary,
                PrivacyMailboxRouteSelection.Primary,
                request,
                requiredExitReplicaId,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception) when (exception.Retryable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await DispatchAsync(
                    fallbackRoute,
                    fallback,
                    PrivacyMailboxRouteSelection.Fallback,
                    request,
                    requiredExitReplicaId,
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
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        primary.Dispose();
        if (!ReferenceEquals(primary, fallback)) fallback.Dispose();
    }

    private async ValueTask<ExactContactResolveOnionResponse> DispatchAsync(
        PrivacyMailboxRoute route,
        IPrivacyManagedIngressTransport transport,
        PrivacyMailboxRouteSelection selection,
        ContactResolveCanonicalPathRequest request,
        ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken)
    {
        PrivacyMailboxOnionAttempt attempt;
        ContactResolvePathAuthority? pathAuthority = null;
        PrivacyRoutingBuiltRequest built;
        try
        {
            if (route.PathProvider is ContactResolvePrivacyPathProvider exactProvider)
            {
                var prepared = await exactProvider.PrepareExactAsync(
                        OnionOperation.ContactResolve,
                        request,
                        requiredExitReplicaId,
                        cancellationToken)
                    .ConfigureAwait(false);
                attempt = prepared.Attempt;
                pathAuthority = prepared.Authority;
            }
            else
            {
                attempt = await route.PathProvider.PrepareAsync(
                    OnionOperation.ContactResolve,
                    request.ExactRequest,
                    cancellationToken).ConfigureAwait(false);
            }
            if (attempt is null ||
                attempt.Request.Operation != OnionOperation.ContactResolve ||
                !CryptographicOperations.FixedTimeEquals(
                    attempt.Request.CanonicalBytes.Span,
                    request.ExactRequest.Span))
            {
                throw new ContactResolverTransportException(
                    ContactResolverTransportFailureKind.Permanent,
                    "The verified path provider returned a mismatched ContactResolve attempt.");
            }
            built = await codec.BuildAsync(
                attempt.Path,
                attempt.Request,
                cancellationToken).ConfigureAwait(false);
        }
        catch (ContactResolverTransportException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new ContactResolverTransportException(
                ContactResolverTransportFailureKind.Permanent,
                "ContactResolve ONION construction failed closed.",
                exception);
        }

        using (built)
        {
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
            catch (ClientMailboxDispatchOutcomeUnknownException exception)
            {
                throw Unknown(exception);
            }

            PrivacyRoutingOpenedResponse opened;
            try
            {
                opened = await codec.OpenResponseAsync(
                    encryptedResponse,
                    built.ReplyContext,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is OnionBoundaryException or CryptographicException)
            {
                throw Unknown(exception);
            }

            var result = opened.Result;
            if (result.Operation != OnionOperation.ContactResolve)
                throw Unknown(new InvalidDataException("The terminal changed the ONION operation."));
            if (result.Kind == OnionTerminalResultKind.Failure)
                throw TerminalFailure(result);

            Observe(selection, attempt.EntryRouterId);
            return new ExactContactResolveOnionResponse(
                result.Body.ToArray(),
                pathAuthority);
        }
    }

    private static void ValidateCanonicalXiq1(ReadOnlySpan<byte> exact)
    {
        try
        {
            var decoded = Xiq1Codec.Decode(exact);
            if (!CryptographicOperations.FixedTimeEquals(exact, decoded.CanonicalBytes.Span))
                throw new InvalidDataException("XIQ1 is not canonical.");
        }
        catch (Exception exception) when (exception is ArgumentException or ContactFormatException or InvalidDataException or OverflowException)
        {
            throw new ContactResolverTransportException(
                ContactResolverTransportFailureKind.Permanent,
                "ContactResolve transport rejected malformed XIQ1 before path selection.",
                exception);
        }
    }

    private static void ValidateCanonicalXis1(ReadOnlySpan<byte> exactXiq1, ReadOnlySpan<byte> exactXis1)
    {
        var decoded = Xis1Codec.Decode(exactXis1, exactXiq1);
        if (!CryptographicOperations.FixedTimeEquals(exactXis1, decoded.CanonicalBytes.Span))
            throw new InvalidDataException("XIS1 is not canonical.");
    }

    private void Observe(
        PrivacyMailboxRouteSelection selection,
        ReadOnlyMemory<byte> entryRouterId)
    {
        try { observer?.Observe(selection, entryRouterId); }
        catch { }
    }

    private static OwnedTransports CreateOwned(
        PrivacyMailboxRoute? primaryRoute,
        PrivacyMailboxRoute? fallbackRoute)
    {
        ArgumentNullException.ThrowIfNull(primaryRoute);
        ArgumentNullException.ThrowIfNull(fallbackRoute);
        PrivacyManagedIngressHttpTransport? primary = null;
        try
        {
            primary = new PrivacyManagedIngressHttpTransport(primaryRoute.EntryOrigin);
            return new OwnedTransports(
                primary,
                new PrivacyManagedIngressHttpTransport(fallbackRoute.EntryOrigin));
        }
        catch
        {
            primary?.Dispose();
            throw;
        }
    }

    private static ContactResolverTransportException BeforeDispatch(
        PrivacyIngressRejectedBeforeForwardException exception) => new(
            exception.Retryable
                ? ContactResolverTransportFailureKind.TransientBeforeDispatch
                : ContactResolverTransportFailureKind.Permanent,
            "ContactResolve ingress rejected the opaque frame before forwarding.",
            exception);

    private static ContactResolverTransportException Unknown(Exception exception) => new(
        ContactResolverTransportFailureKind.OutcomeUnknown,
        "ContactResolve may have been forwarded; reconciliation must reuse the exact XIQ1 operation.",
        exception);

    private static ContactResolverTransportException TerminalFailure(
        VerifiedOnionTerminalResult result)
    {
        var code = result.FailureCode ?? OnionFailureCode.InternalFailure;
        var permanent = code is OnionFailureCode.MalformedRequest
            or OnionFailureCode.AuthenticationRejected
            or OnionFailureCode.AuthorizationRejected
            or OnionFailureCode.ReplayRejected
            or OnionFailureCode.Conflict;
        return new ContactResolverTransportException(
            permanent
                ? ContactResolverTransportFailureKind.Permanent
                : ContactResolverTransportFailureKind.OutcomeUnknown,
            $"ContactResolve exit returned authenticated terminal failure {code}.");
    }

    private sealed record OwnedTransports(
        IPrivacyManagedIngressTransport Primary,
        IPrivacyManagedIngressTransport Fallback);
}
