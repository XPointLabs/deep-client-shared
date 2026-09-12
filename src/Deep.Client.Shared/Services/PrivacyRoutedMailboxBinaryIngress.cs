using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services;

public enum PrivacyMailboxRouteSelection
{
    Primary = 1,
    Fallback = 2
}

public interface IPrivacyMailboxRouteSelectionObserver
{
    void Observe(
        PrivacyMailboxRouteSelection selection,
        ReadOnlyMemory<byte> entryRouterId);
}

public sealed class PrivacyMailboxOnionAttempt
{
    public PrivacyMailboxOnionAttempt(
        VerifiedOnionPathContext path,
        VerifiedCanonicalOnionRequest request)
    {
        Path = path ?? throw new ArgumentNullException(nameof(path));
        Request = request ?? throw new ArgumentNullException(nameof(request));
    }

    public VerifiedOnionPathContext Path { get; }
    public VerifiedCanonicalOnionRequest Request { get; }
    public ReadOnlyMemory<byte> EntryRouterId => Path.EntryRouterId;
}

public interface IPrivacyMailboxPathProvider
{
    ValueTask<PrivacyMailboxOnionAttempt> PrepareAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken);
}

public sealed class PrivacyMailboxRoute
{
    private readonly byte[] expectedEntryRouterId;

    public PrivacyMailboxRoute(
        Uri entryOrigin,
        IPrivacyMailboxPathProvider pathProvider)
        : this(entryOrigin, pathProvider, ReadOnlyMemory<byte>.Empty)
    {
    }

    public PrivacyMailboxRoute(
        Uri entryOrigin,
        IPrivacyMailboxPathProvider pathProvider,
        ReadOnlyMemory<byte> expectedEntryRouterId)
    {
        ArgumentNullException.ThrowIfNull(entryOrigin);
        ArgumentNullException.ThrowIfNull(pathProvider);
        if (!entryOrigin.IsAbsoluteUri ||
            entryOrigin.Scheme != Uri.UriSchemeHttp &&
            entryOrigin.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(entryOrigin.UserInfo) ||
            entryOrigin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(entryOrigin.Query) ||
            !string.IsNullOrEmpty(entryOrigin.Fragment) ||
            entryOrigin.Scheme == Uri.UriSchemeHttp && !entryOrigin.IsLoopback)
        {
            throw new ArgumentException(
                "A privacy mailbox route requires clean HTTPS or an explicit loopback HTTP origin.",
                nameof(entryOrigin));
        }
        if (!expectedEntryRouterId.IsEmpty &&
            (expectedEntryRouterId.Length != 32 ||
             expectedEntryRouterId.Span.IndexOfAnyExcept((byte)0) < 0))
        {
            throw new ArgumentException(
                "An expected entry router ID must be empty or exactly 32 non-zero bytes.",
                nameof(expectedEntryRouterId));
        }

        EntryOrigin = entryOrigin;
        PathProvider = pathProvider;
        this.expectedEntryRouterId = expectedEntryRouterId.ToArray();
    }

    public Uri EntryOrigin { get; }

    public IPrivacyMailboxPathProvider PathProvider { get; }

    public ReadOnlyMemory<byte> ExpectedEntryRouterId => expectedEntryRouterId.ToArray();

    public override string ToString() =>
        $"PrivacyMailboxRoute {{ Entry = {EntryOrigin}, Path = [verified-attempt-provider] }}";
}

/// <summary>
/// Wraps exact canonical MAU2 in a three-hop Deep-native privacy frame. A best-effort fallback
/// attempt is allowed only when the primary ingress proves that forwarding never started. There is no
/// direct mailbox HTTPS fallback. Every response is opened with the per-attempt reply context
/// before the existing mailbox adapter verifies and journals its canonical durable evidence.
/// </summary>
public sealed class PrivacyRoutedMailboxBinaryIngress :
    IClientMailboxBinaryIngress,
    IDisposable
{
    private readonly PrivacyMailboxRoute primaryRoute;
    private readonly PrivacyMailboxRoute fallbackRoute;
    private readonly IPrivacyManagedIngressTransport primary;
    private readonly IPrivacyManagedIngressTransport fallback;
    private readonly IMailboxClientDecodePolicyProvider decodePolicies;
    private readonly PrivacyRoutingCodec codec;
    private readonly IPrivacyMailboxRouteSelectionObserver? routeSelectionObserver;
    private readonly int paddingBlockBytes;
    private int disposed;

    public PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        PrivacyRoutingCodec codec,
        int paddingBlockBytes = OnionLimits.DefaultPaddingBlockBytes)
        : this(
            primaryRoute,
            fallbackRoute,
            decodePolicies,
            codec,
            CreateOwned(primaryRoute, fallbackRoute, decodePolicies, paddingBlockBytes),
            paddingBlockBytes)
    {
    }

    private PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        PrivacyRoutingCodec codec,
        OwnedTransports transports,
        int paddingBlockBytes)
        : this(
            primaryRoute,
            fallbackRoute,
            decodePolicies,
            codec,
            transports.Primary,
            transports.Fallback,
            paddingBlockBytes)
    {
    }

    internal PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        PrivacyRoutingCodec codec,
        IPrivacyManagedIngressTransport primary,
        IPrivacyManagedIngressTransport fallback,
        int paddingBlockBytes = OnionLimits.DefaultPaddingBlockBytes,
        IPrivacyMailboxRouteSelectionObserver? routeSelectionObserver = null)
    {
        this.primaryRoute = primaryRoute ??
            throw new ArgumentNullException(nameof(primaryRoute));
        this.fallbackRoute = fallbackRoute ??
            throw new ArgumentNullException(nameof(fallbackRoute));
        this.decodePolicies = decodePolicies ??
            throw new ArgumentNullException(nameof(decodePolicies));
        this.codec = codec ?? throw new ArgumentNullException(nameof(codec));
        this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
        this.fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        this.routeSelectionObserver = routeSelectionObserver;
        ValidatePadding(paddingBlockBytes);
        this.paddingBlockBytes = paddingBlockBytes;
    }

    public Task<ReadOnlyMemory<byte>> StoreAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Store,
            OnionOperation.Store,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Retrieve,
            OnionOperation.Retrieve,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Ack,
            OnionOperation.Acknowledge,
            cancellationToken);

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

    private async Task<ReadOnlyMemory<byte>> SendAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        MailboxAuthenticatedOperation expectedMau2Operation,
        OnionOperation privacyOperation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        _ = ValidateCanonicalMau2(
            canonicalMau2.Span,
            expectedMau2Operation);

        try
        {
            var response = await DispatchAsync(
                primaryRoute,
                primary,
                privacyOperation,
                canonicalMau2,
                cancellationToken).ConfigureAwait(false);
            return response;
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception)
            when (exception.Retryable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var response = await DispatchAsync(
                    fallbackRoute,
                    fallback,
                    privacyOperation,
                    canonicalMau2,
                    cancellationToken).ConfigureAwait(false);
                return response;
            }
            catch (PrivacyIngressRejectedBeforeForwardException fallbackException)
            {
                throw Rejected(fallbackException);
            }
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception)
        {
            throw Rejected(exception);
        }
    }

    private void PublishRouteSelection(
        PrivacyMailboxRouteSelection selection,
        ReadOnlyMemory<byte> entryRouterId)
    {
        try
        {
            routeSelectionObserver?.Observe(
                selection,
                entryRouterId);
        }
        catch
        {
            // A diagnostic observer must never alter authenticated delivery.
        }
    }

    private async Task<ReadOnlyMemory<byte>> DispatchAsync(
        PrivacyMailboxRoute route,
        IPrivacyManagedIngressTransport transport,
        OnionOperation operation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken)
    {
        try
        {
            var attempt = await route.PathProvider.PrepareAsync(
                    operation,
                    canonicalMau2,
                    cancellationToken)
                .ConfigureAwait(false);
            if (attempt is null ||
                attempt.Request.Operation != operation ||
                !CryptographicOperations.FixedTimeEquals(
                    attempt.Request.CanonicalBytes.Span,
                    canonicalMau2.Span))
            {
                throw new ClientMailboxTransportException(
                    ClientMailboxTransportFailure.ProtocolViolation,
                    retryable: false,
                    "The privacy route provider returned an attempt for another operation or canonical request.");
            }

            using var request = await codec.BuildAsync(
                attempt.Path,
                attempt.Request,
                cancellationToken).ConfigureAwait(false);
            var encryptedResponse = await transport.ForwardAsync(
                request.Frame,
                cancellationToken).ConfigureAwait(false);
            PrivacyRoutingOpenedResponse opened;
            try
            {
                opened = await codec.OpenResponseAsync(
                    encryptedResponse,
                    request.ReplyContext,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OnionBoundaryException exception)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox response authentication failed after forwarding.",
                    exception);
            }

            var terminal = opened.Result;

            if (terminal.Operation != operation)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox terminal result changed operation.");
            }

            if (terminal.Kind == OnionTerminalResultKind.Failure)
            {
                throw MapTerminalFailure(terminal);
            }

            ValidateCanonicalResponse(terminal.Body.Span, operation);
            PublishRouteSelection(
                ReferenceEquals(route, primaryRoute)
                    ? PrivacyMailboxRouteSelection.Primary
                    : PrivacyMailboxRouteSelection.Fallback,
                attempt.EntryRouterId);
            return terminal.Body;
        }
        catch (PrivacyIngressRejectedBeforeForwardException)
        {
            throw;
        }
        catch (ClientMailboxDispatchOutcomeUnknownException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Privacy-routing request construction failed closed.",
                exception);
        }
    }

    private static ReadOnlyMemory<byte> ValidateCanonicalMau2(
        ReadOnlySpan<byte> canonicalMau2,
        MailboxAuthenticatedOperation expectedOperation)
    {
        MailboxAuthenticatedClientRequest request;
        byte[] roundTrip;
        try
        {
            request = MailboxAuthenticatedClientRequestCodec.Decode(canonicalMau2);
            roundTrip = MailboxAuthenticatedClientRequestCodec.Encode(request);
        }
        catch (Exception exception) when (
            exception is ArgumentException or OverflowException or
                MailboxClientException or MailboxAuthenticatedCapabilityException)
        {
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "Privacy ingress rejected malformed MAU2.",
                exception);
        }

        try
        {
            if (request.Binding.Operation != expectedOperation ||
                request.Presentation.Operation != expectedOperation ||
                !CryptographicOperations.FixedTimeEquals(roundTrip, canonicalMau2))
            {
                throw new ClientMailboxTransportException(
                    ClientMailboxTransportFailure.MalformedRequest,
                    retryable: false,
                    "Privacy ingress rejected a non-canonical or mismatched MAU2 operation.");
            }

            return request.Presentation.Grant.NetworkId.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roundTrip);
        }
    }

    private void ValidateCanonicalResponse(
        ReadOnlySpan<byte> response,
        OnionOperation operation)
    {
        byte[] roundTrip;
        try
        {
            roundTrip = operation switch
            {
                OnionOperation.Store =>
                    MailboxReceiptV3Codec.EncodeDurableQuorum(
                        MailboxReceiptV3Codec.DecodeDurableQuorum(response)),
                OnionOperation.Retrieve =>
                    MailboxClientCodec.EncodeRetrievePage(
                        MailboxClientCodec.DecodeRetrievePage(
                            response,
                            decodePolicies.GetCurrent())),
                OnionOperation.Acknowledge =>
                    MailboxAggregateAckCodec.EncodeMqr3(
                        MailboxAggregateAckCodec.DecodeMqr3(response)),
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
        }
        catch (Exception exception) when (
            exception is ArgumentException or OverflowException or
                MailboxClientException or MailboxReceiptException)
        {
            throw new ClientMailboxDispatchOutcomeUnknownException(
                "Privacy-routed mailbox response is not a canonical expected frame.",
                exception);
        }

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(roundTrip, response))
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox response failed canonical round-trip.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roundTrip);
        }
    }

    private static OwnedTransports CreateOwned(
        PrivacyMailboxRoute? primaryRoute,
        PrivacyMailboxRoute? fallbackRoute,
        IMailboxClientDecodePolicyProvider? decodePolicies,
        int paddingBlockBytes)
    {
        ArgumentNullException.ThrowIfNull(primaryRoute);
        ArgumentNullException.ThrowIfNull(fallbackRoute);
        ArgumentNullException.ThrowIfNull(decodePolicies);
        ValidatePadding(paddingBlockBytes);
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

    private static void ValidatePadding(int paddingBlockBytes)
    {
        if (paddingBlockBytes is < OnionLimits.MinimumPaddingBlockBytes or
            > OnionLimits.MaximumPaddingBlockBytes ||
            (paddingBlockBytes & (paddingBlockBytes - 1)) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(paddingBlockBytes),
                "Privacy padding must be a supported power-of-two block size.");
        }
    }

    private static ClientMailboxTransportException Rejected(
        PrivacyIngressRejectedBeforeForwardException exception) => new(
            ClientMailboxTransportFailure.DependencyUnavailable,
            exception.Retryable,
            "Privacy ingress rejected the request before forwarding.",
            exception);

    private static Exception MapTerminalFailure(
        VerifiedOnionTerminalResult terminal)
    {
        var code = terminal.FailureCode ?? throw new ClientMailboxDispatchOutcomeUnknownException(
            "Privacy-routing failure omitted its canonical code.");
        if (code == OnionFailureCode.OutcomeUnknown)
        {
            return new ClientMailboxDispatchOutcomeUnknownException(
                "Mailbox exit reported an outcome-unknown terminal failure.");
        }

        var failure = code switch
        {
            OnionFailureCode.MalformedRequest =>
                ClientMailboxTransportFailure.MalformedRequest,
            OnionFailureCode.AuthenticationRejected =>
                ClientMailboxTransportFailure.AuthenticationRejected,
            OnionFailureCode.AuthorizationRejected =>
                ClientMailboxTransportFailure.AuthorizationRejected,
            OnionFailureCode.ReplayRejected or
                OnionFailureCode.MailboxNotFound or
                OnionFailureCode.Conflict =>
                ClientMailboxTransportFailure.ConflictOrExpired,
            OnionFailureCode.CapacityExceeded =>
                ClientMailboxTransportFailure.Throttled,
            OnionFailureCode.Unavailable or
                OnionFailureCode.InternalFailure =>
                ClientMailboxTransportFailure.DependencyUnavailable,
            _ => throw new ClientMailboxDispatchOutcomeUnknownException(
                "Mailbox exit reported an unsupported terminal failure.")
        };
        return new ClientMailboxTransportException(
            failure,
            terminal.Retryable,
            $"Mailbox exit rejected the operation with {code}.");
    }

    private sealed record OwnedTransports(
        IPrivacyManagedIngressTransport Primary,
        IPrivacyManagedIngressTransport Fallback);
}
