using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Services;

/// <summary>
/// Explicit ownership wrapper for a transport operated outside the official Deep cloud.
/// It delegates only authenticated inbox semantics and never implements the direct-P2P or
/// official-mailbox capability.
/// </summary>
public sealed class UserManagedSessionMessageTransport :
    IUserManagedSessionMessageTransport,
    IAuthenticatedInboxTransport,
    IMetadataPrivateSessionMessageTransport,
    IDisposable
{
    private readonly ISessionMessageTransport inner;
    private readonly IAuthenticatedInboxTransport inbox;
    private readonly bool ownsInner;
    private int disposed;

    public UserManagedSessionMessageTransport(
        ISessionMessageTransport inner,
        bool ownsInner = false)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        inbox = inner as IAuthenticatedInboxTransport ?? throw new ArgumentException(
            "A user-managed network must provide authenticated inbox retrieval.", nameof(inner));
        if (inner is IAuthenticatedOpaqueMailboxTransport)
            throw new ArgumentException(
                "Official mailbox transports cannot be re-labelled as user-managed.", nameof(inner));
        if (inner is IDirectP2pSessionMessageTransport)
            throw new ArgumentException(
                "Direct P2P must retain its distinct ownership capability.", nameof(inner));
        this.ownsInner = ownsInner;
    }

    public int InboxNamespace => inbox.InboxNamespace;

    public bool UsesMetadataPrivateTransport =>
        inner is IMetadataPrivateSessionMessageTransport metadataPrivate &&
        metadataPrivate.UsesMetadataPrivateTransport;

    public Task SendAsync(
        OutboundMessageEnvelope envelope,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return inner.SendAsync(envelope, cancellationToken);
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
        SessionId recipient,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return inner.ReceiveAsync(recipient, cancellationToken);
    }

    public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
        SessionIdentityProvider identity,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return inbox.ReceiveAuthenticatedAsync(identity, cancellationToken);
    }

    public Task<AuthenticatedInboxBatch> RetrieveAuthenticatedAsync(
        SessionIdentityProvider identity,
        string? cursor,
        int limit,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return inbox.RetrieveAuthenticatedAsync(identity, cursor, limit, cancellationToken);
    }

    public bool TryDecodeInboxEntry(
        DurableInboxWireEntry entry,
        SessionId recipient,
        out InboundMessageEnvelope envelope)
    {
        ThrowIfDisposed();
        return inbox.TryDecodeInboxEntry(entry, recipient, out envelope);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0 && ownsInner && inner is IDisposable disposable)
            disposable.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(
        Volatile.Read(ref disposed) != 0, this);
}
