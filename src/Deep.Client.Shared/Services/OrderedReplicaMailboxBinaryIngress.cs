using System.Net.Http;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Routes MAU2 by its signed grant epoch and preserves the PMS1 replica order. The secondary is
/// used only after a definite non-accepting response or a transport failure known to precede HTTP
/// dispatch. Ambiguous timeouts and response-stream failures stay on the same operation path.
/// </summary>
public sealed class OrderedReplicaMailboxBinaryIngress :
    IClientMailboxBinaryIngress,
    IDisposable
{
    private readonly ulong currentEpoch;
    private readonly ulong nextEpoch;
    private readonly ReplicaLane current;
    private readonly ReplicaLane next;
    private int disposed;

    public OrderedReplicaMailboxBinaryIngress(
        ProductionMailboxReplicaIngressRoute current,
        ProductionMailboxReplicaIngressRoute next,
        IMailboxClientDecodePolicyProvider decodePolicies)
        : this(
            current?.Epoch ?? 0,
            next?.Epoch ?? 0,
            CreateOwned(current, next, decodePolicies))
    {
    }

    private OrderedReplicaMailboxBinaryIngress(
        ulong currentEpoch,
        ulong nextEpoch,
        OwnedIngresses owned)
        : this(
            currentEpoch,
            nextEpoch,
            owned.CurrentPrimary,
            owned.CurrentSecondary,
            owned.NextPrimary,
            owned.NextSecondary)
    {
    }

    internal OrderedReplicaMailboxBinaryIngress(
        ulong currentEpoch,
        ulong nextEpoch,
        IClientMailboxBinaryIngress currentPrimary,
        IClientMailboxBinaryIngress currentSecondary,
        IClientMailboxBinaryIngress nextPrimary,
        IClientMailboxBinaryIngress nextSecondary)
    {
        if (currentEpoch == 0 || nextEpoch != checked(currentEpoch + 1))
            throw new ArgumentException("Ordered replica ingress requires exact E/E+1.");
        this.currentEpoch = currentEpoch;
        this.nextEpoch = nextEpoch;
        current = new(currentPrimary, currentSecondary);
        next = new(nextPrimary, nextSecondary);
    }

    private static OwnedIngresses CreateOwned(
        ProductionMailboxReplicaIngressRoute? current,
        ProductionMailboxReplicaIngressRoute? next,
        IMailboxClientDecodePolicyProvider decodePolicies)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(decodePolicies);
        if (current.Epoch == 0 || current.Epoch == ulong.MaxValue ||
            next.Epoch != current.Epoch + 1)
            throw new ArgumentException(
                "Ordered replica ingress requires exact E/E+1.");
        HttpClientMailboxBinaryIngress? currentPrimary = null;
        HttpClientMailboxBinaryIngress? currentSecondary = null;
        HttpClientMailboxBinaryIngress? nextPrimary = null;
        HttpClientMailboxBinaryIngress? nextSecondary = null;
        try
        {
            currentPrimary = HttpClientMailboxBinaryIngress.CreateProduction(
                current.FirstEndpoint, decodePolicies, current.FirstPins);
            currentSecondary = HttpClientMailboxBinaryIngress.CreateProduction(
                current.SecondEndpoint, decodePolicies, current.SecondPins);
            nextPrimary = HttpClientMailboxBinaryIngress.CreateProduction(
                next.FirstEndpoint, decodePolicies, next.FirstPins);
            nextSecondary = HttpClientMailboxBinaryIngress.CreateProduction(
                next.SecondEndpoint, decodePolicies, next.SecondPins);
            return new(
                currentPrimary, currentSecondary, nextPrimary, nextSecondary);
        }
        catch
        {
            currentPrimary?.Dispose();
            currentSecondary?.Dispose();
            nextPrimary?.Dispose();
            nextSecondary?.Dispose();
            throw;
        }
    }

    public Task<ReadOnlyMemory<byte>> StoreAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(canonicalMau2, MailboxAuthenticatedOperation.Store, cancellationToken);

    public Task<ReadOnlyMemory<byte>> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(canonicalMau2, MailboxAuthenticatedOperation.Retrieve, cancellationToken);

    public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken = default) =>
        SendAsync(canonicalMau2, MailboxAuthenticatedOperation.Ack, cancellationToken);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        current.Dispose();
        next.Dispose();
    }

    private async Task<ReadOnlyMemory<byte>> SendAsync(
        ReadOnlyMemory<byte> canonicalMau2,
        MailboxAuthenticatedOperation expectedOperation,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        MailboxAuthenticatedClientRequest decoded;
        try
        {
            decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonicalMau2.Span);
        }
        catch (Exception exception) when (
            exception is ArgumentException or MailboxAuthenticatedCapabilityException)
        {
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "Ordered replica ingress rejected malformed MAU2.",
                exception);
        }
        if (decoded.Binding.Operation != expectedOperation ||
            decoded.Presentation.Operation != expectedOperation)
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.MalformedRequest,
                retryable: false,
                "Ordered replica ingress rejected a mismatched MAU2 operation.");
        var epoch = decoded.Presentation.Grant.Epoch;
        var lane = epoch == currentEpoch
            ? current
            : epoch == nextEpoch
                ? next
                : throw new ClientMailboxTransportException(
                    ClientMailboxTransportFailure.ConflictOrExpired,
                    retryable: false,
                    "MAU2 epoch is outside the provisioned PMS1 pair.");
        return await lane.SendAsync(
            expectedOperation, canonicalMau2, cancellationToken).ConfigureAwait(false);
    }

    private sealed class ReplicaLane(
        IClientMailboxBinaryIngress primary,
        IClientMailboxBinaryIngress secondary) : IDisposable
    {
        private readonly IClientMailboxBinaryIngress primary = primary ??
            throw new ArgumentNullException(nameof(primary));
        private readonly IClientMailboxBinaryIngress secondary = secondary ??
            throw new ArgumentNullException(nameof(secondary));

        public async Task<ReadOnlyMemory<byte>> SendAsync(
            MailboxAuthenticatedOperation operation,
            ReadOnlyMemory<byte> request,
            CancellationToken cancellationToken)
        {
            try
            {
                return await Dispatch(primary, operation, request, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ClientMailboxTransportException exception)
                when (CanFailOver(exception))
            {
                return await Dispatch(secondary, operation, request, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        public void Dispose()
        {
            (primary as IDisposable)?.Dispose();
            if (!ReferenceEquals(primary, secondary))
                (secondary as IDisposable)?.Dispose();
        }

        private static Task<ReadOnlyMemory<byte>> Dispatch(
            IClientMailboxBinaryIngress ingress,
            MailboxAuthenticatedOperation operation,
            ReadOnlyMemory<byte> request,
            CancellationToken cancellationToken) => operation switch
            {
                MailboxAuthenticatedOperation.Store =>
                    ingress.StoreAsync(request, cancellationToken),
                MailboxAuthenticatedOperation.Retrieve =>
                    ingress.RetrieveAsync(request, cancellationToken),
                MailboxAuthenticatedOperation.Ack =>
                    ingress.AcknowledgeAsync(request, cancellationToken),
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };

        private static bool CanFailOver(ClientMailboxTransportException exception)
        {
            if (!exception.Retryable) return false;
            // An HTTP status is a definite non-accepting response in this ingress contract.
            if (exception.InnerException is null) return true;
            if (exception.Failure != ClientMailboxTransportFailure.NetworkUnavailable ||
                exception.InnerException is not HttpRequestException request)
                return false;
            return request.HttpRequestError is
                HttpRequestError.NameResolutionError or
                HttpRequestError.SecureConnectionError or
                HttpRequestError.ProxyTunnelError;
        }
    }

    private sealed record OwnedIngresses(
        IClientMailboxBinaryIngress CurrentPrimary,
        IClientMailboxBinaryIngress CurrentSecondary,
        IClientMailboxBinaryIngress NextPrimary,
        IClientMailboxBinaryIngress NextSecondary);
}
