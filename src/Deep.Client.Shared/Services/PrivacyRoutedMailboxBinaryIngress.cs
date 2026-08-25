using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services;

public sealed class PrivacyMailboxRoute
{
    private readonly PrivacyRoutingHop[] hops;

    public PrivacyMailboxRoute(
        Uri entryOrigin,
        IReadOnlyList<PrivacyRoutingHop> hops)
    {
        ArgumentNullException.ThrowIfNull(entryOrigin);
        ArgumentNullException.ThrowIfNull(hops);
        if (!entryOrigin.IsAbsoluteUri ||
            entryOrigin.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(entryOrigin.UserInfo) ||
            entryOrigin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(entryOrigin.Query) ||
            !string.IsNullOrEmpty(entryOrigin.Fragment))
        {
            throw new ArgumentException(
                "A privacy mailbox route requires a clean HTTPS entry origin.",
                nameof(entryOrigin));
        }

        if (hops.Count != PrivacyRoutingLimits.RouteHopCount ||
            hops.Any(static hop => hop is null))
        {
            throw new ArgumentException(
                "A privacy mailbox route requires exactly three pinned hops.",
                nameof(hops));
        }

        for (var left = 0; left < hops.Count; left++)
        {
            for (var right = left + 1; right < hops.Count; right++)
            {
                if (CryptographicOperations.FixedTimeEquals(
                    hops[left].RouterId.Span,
                    hops[right].RouterId.Span) ||
                    CryptographicOperations.FixedTimeEquals(
                        hops[left].X25519PublicKey.Span,
                        hops[right].X25519PublicKey.Span))
                {
                    throw new ArgumentException(
                        "A privacy mailbox route cannot repeat a router identity or X25519 key.",
                        nameof(hops));
                }
            }
        }

        EntryOrigin = entryOrigin;
        this.hops = hops.ToArray();
    }

    public Uri EntryOrigin { get; }

    public IReadOnlyList<PrivacyRoutingHop> Hops => hops.ToArray();

    internal IReadOnlyList<PrivacyRoutingHop> PinnedHops => hops;

    public override string ToString() =>
        $"PrivacyMailboxRoute {{ Entry = {EntryOrigin}, Hops = {hops.Length}, Keys = [configured] }}";
}

/// <summary>
/// Wraps exact canonical MAU2 in a three-hop Deep-native privacy frame. A disjoint fallback route
/// is attempted only when the primary ingress proves that forwarding never started. There is no
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
    private readonly int paddingBlockBytes;
    private int disposed;

    public PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
        : this(
            primaryRoute,
            fallbackRoute,
            decodePolicies,
            CreateOwned(primaryRoute, fallbackRoute, decodePolicies, paddingBlockBytes),
            paddingBlockBytes)
    {
    }

    private PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        OwnedTransports transports,
        int paddingBlockBytes)
        : this(
            primaryRoute,
            fallbackRoute,
            decodePolicies,
            transports.Primary,
            transports.Fallback,
            paddingBlockBytes)
    {
    }

    internal PrivacyRoutedMailboxBinaryIngress(
        PrivacyMailboxRoute primaryRoute,
        PrivacyMailboxRoute fallbackRoute,
        IMailboxClientDecodePolicyProvider decodePolicies,
        IPrivacyManagedIngressTransport primary,
        IPrivacyManagedIngressTransport fallback,
        int paddingBlockBytes = PrivacyRoutingLimits.DefaultPaddingBlockBytes)
    {
        this.primaryRoute = primaryRoute ??
            throw new ArgumentNullException(nameof(primaryRoute));
        this.fallbackRoute = fallbackRoute ??
            throw new ArgumentNullException(nameof(fallbackRoute));
        this.decodePolicies = decodePolicies ??
            throw new ArgumentNullException(nameof(decodePolicies));
        this.primary = primary ?? throw new ArgumentNullException(nameof(primary));
        this.fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        ValidatePadding(paddingBlockBytes);
        this.paddingBlockBytes = paddingBlockBytes;
        EnsureDisjoint(primaryRoute, fallbackRoute);
    }

    public Task<ReadOnlyMemory<byte>> StoreAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Store,
            PrivacyRoutingOperation.Store,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Retrieve,
            PrivacyRoutingOperation.Retrieve,
            cancellationToken);

    public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(
            canonicalMau2,
            MailboxAuthenticatedOperation.Ack,
            PrivacyRoutingOperation.Acknowledge,
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
        PrivacyRoutingOperation privacyOperation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        cancellationToken.ThrowIfCancellationRequested();
        ValidateCanonicalMau2(canonicalMau2.Span, expectedMau2Operation);

        try
        {
            return await DispatchAsync(
                primaryRoute,
                primary,
                privacyOperation,
                canonicalMau2,
                cancellationToken).ConfigureAwait(false);
        }
        catch (PrivacyIngressRejectedBeforeForwardException exception)
            when (exception.Retryable)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await DispatchAsync(
                    fallbackRoute,
                    fallback,
                    privacyOperation,
                    canonicalMau2,
                    cancellationToken).ConfigureAwait(false);
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

    private async Task<ReadOnlyMemory<byte>> DispatchAsync(
        PrivacyMailboxRoute route,
        IPrivacyManagedIngressTransport transport,
        PrivacyRoutingOperation operation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = PrivacyRoutingRequestBuilder.BuildForCanonicalMailboxRequest(
                route.PinnedHops,
                operation,
                canonicalMau2.Span,
                paddingBlockBytes);
            var encryptedResponse = await transport.ForwardAsync(
                request.Frame,
                cancellationToken).ConfigureAwait(false);
            PrivacyRoutingOpenedResponse opened;
            try
            {
                opened = PrivacyRoutingResponseCodec.Open(
                    encryptedResponse.Span,
                    request.ReplyContext);
            }
            catch (PrivacyRoutingProtocolException exception)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox response authentication failed after forwarding.",
                    exception);
            }

            PrivacyRoutingTerminalResult terminal;
            try
            {
                terminal = PrivacyRoutingResultCodec.Decode(opened.Payload.Span);
            }
            catch (PrivacyRoutingProtocolException exception)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox terminal result is not canonical.",
                    exception);
            }

            if (terminal.Operation != operation)
            {
                throw new ClientMailboxDispatchOutcomeUnknownException(
                    "Privacy-routed mailbox terminal result changed operation.");
            }

            if (terminal.Kind == PrivacyRoutingResultKind.Failure)
            {
                throw MapTerminalFailure(terminal);
            }

            ValidateCanonicalResponse(terminal.Body.Span, operation);
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
        catch (PrivacyRoutingProtocolException exception)
        {
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.ProtocolViolation,
                retryable: false,
                "Privacy-routing request construction failed closed.",
                exception);
        }
    }

    private static void ValidateCanonicalMau2(
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
        }
        finally
        {
            CryptographicOperations.ZeroMemory(roundTrip);
        }
    }

    private void ValidateCanonicalResponse(
        ReadOnlySpan<byte> response,
        PrivacyRoutingOperation operation)
    {
        byte[] roundTrip;
        try
        {
            roundTrip = operation switch
            {
                PrivacyRoutingOperation.Store =>
                    MailboxReceiptV3Codec.EncodeDurableQuorum(
                        MailboxReceiptV3Codec.DecodeDurableQuorum(response)),
                PrivacyRoutingOperation.Retrieve =>
                    MailboxClientCodec.EncodeRetrievePage(
                        MailboxClientCodec.DecodeRetrievePage(
                            response,
                            decodePolicies.GetCurrent())),
                PrivacyRoutingOperation.Acknowledge =>
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

    private static void EnsureDisjoint(
        PrivacyMailboxRoute primary,
        PrivacyMailboxRoute fallback)
    {
        if (Uri.Compare(
                primary.EntryOrigin,
                fallback.EntryOrigin,
                UriComponents.SchemeAndServer,
                UriFormat.SafeUnescaped,
                StringComparison.OrdinalIgnoreCase) == 0)
        {
            throw new ArgumentException(
                "Primary and fallback privacy entry origins must be distinct.",
                nameof(fallback));
        }

        foreach (var primaryHop in primary.PinnedHops)
        {
            if (fallback.PinnedHops.Any(fallbackHop =>
                    CryptographicOperations.FixedTimeEquals(
                        primaryHop.RouterId.Span,
                        fallbackHop.RouterId.Span) ||
                    CryptographicOperations.FixedTimeEquals(
                        primaryHop.X25519PublicKey.Span,
                        fallbackHop.X25519PublicKey.Span)))
            {
                throw new ArgumentException(
                    "Primary and fallback privacy routes must be identity/key-disjoint.",
                    nameof(fallback));
            }
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
        EnsureDisjoint(primaryRoute, fallbackRoute);
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
        if (paddingBlockBytes is < PrivacyRoutingLimits.MinimumPaddingBlockBytes or
            > PrivacyRoutingLimits.MaximumPaddingBlockBytes ||
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
        PrivacyRoutingTerminalResult terminal)
    {
        var code = terminal.FailureCode ?? throw new ClientMailboxDispatchOutcomeUnknownException(
            "Privacy-routing failure omitted its canonical code.");
        if (code == PrivacyRoutingFailureCode.OutcomeUnknown)
        {
            return new ClientMailboxDispatchOutcomeUnknownException(
                "Mailbox exit reported an outcome-unknown terminal failure.");
        }

        var failure = code switch
        {
            PrivacyRoutingFailureCode.MalformedRequest =>
                ClientMailboxTransportFailure.MalformedRequest,
            PrivacyRoutingFailureCode.AuthenticationRejected =>
                ClientMailboxTransportFailure.AuthenticationRejected,
            PrivacyRoutingFailureCode.AuthorizationRejected =>
                ClientMailboxTransportFailure.AuthorizationRejected,
            PrivacyRoutingFailureCode.ReplayRejected or
                PrivacyRoutingFailureCode.MailboxNotFound or
                PrivacyRoutingFailureCode.Conflict =>
                ClientMailboxTransportFailure.ConflictOrExpired,
            PrivacyRoutingFailureCode.CapacityExceeded =>
                ClientMailboxTransportFailure.Throttled,
            PrivacyRoutingFailureCode.Unavailable or
                PrivacyRoutingFailureCode.InternalFailure =>
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
