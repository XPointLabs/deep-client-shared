using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>One exact three-hop DID2 publication attempt. Its TLS entry is
/// derived after exit-specific path selection, never from a fixed URL or an
/// unsigned route hint. No direct request or outcome-unknown fallback exists.</summary>
internal sealed class DeepIdV2PublicationOnionTransport : IExactContactResolveOnionTransport
{
    private readonly ContactResolvePrivacyPathProvider paths;
    private readonly PrivacyRoutingCodec codec;
    private readonly DeepIdV2OnionClientCustody custody;

    internal DeepIdV2PublicationOnionTransport(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody)
    {
        source.RequireAccountOwner(custody.Owner);
        this.custody = custody;
        paths = new(source, custody.Guards);
        codec = new(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new NoClientReceiveVault()));
    }

    public async ValueTask<ExactContactResolveOnionResponse> SendExactAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        CancellationToken cancellationToken = default)
    {
        var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve,
            request, requiredExitReplicaId, cancellationToken).ConfigureAwait(false);
        return await SendPreparedAsync(prepared, null, cancellationToken).ConfigureAwait(false);
    }

    internal async ValueTask<ExactContactResolveOnionResponse> SendOwnedExactAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        Did2OwnedContactTransportContext operation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        operation.RequireActive();
        if (!ReferenceEquals(custody, operation.Custody))
            throw new CryptographicException("The owned transport belongs to another custody loan.");
        var placement = ContactServicePlacementFactory.Create(operation.Network,
            request.RequestKind, request.ShardKey);
        var authority = new ContactResolvePathAuthority(operation.Network, placement);
        var prepared = await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve,
            request, requiredExitReplicaId, authority, cancellationToken).ConfigureAwait(false);
        operation.RequireActive();
        var result = await SendPreparedAsync(prepared, operation, cancellationToken).ConfigureAwait(false);
        operation.RequireActive();
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    private async ValueTask<ExactContactResolveOnionResponse> SendPreparedAsync(
        ContactResolvePreparedPath prepared, Did2OwnedContactTransportContext? ownedOperation, CancellationToken cancellationToken)
    {
        var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
        using var transport = new PrivacyManagedIngressHttpTransport(entry);
        using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request,
            cancellationToken).ConfigureAwait(false);
        ownedOperation?.RequireActive();
        cancellationToken.ThrowIfCancellationRequested();
        var response = await ForwardOnceAsync(transport, built.Frame, cancellationToken).ConfigureAwait(false);
        ownedOperation?.RequireActive();
        PrivacyRoutingOpenedResponse opened;
        try { opened = await codec.OpenResponseAsync(response, built.ReplyContext, cancellationToken).ConfigureAwait(false); }
        catch (Exception error) when (error is CryptographicException or OnionBoundaryException)
        { throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 ONION publication reply could not be authenticated.", error); }
        if (opened.Result.Operation != OnionOperation.ContactResolve ||
            opened.Result.Kind != OnionTerminalResultKind.Success)
            throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 ONION publication has no successful authenticated terminal result.");
        entry.EnsureCurrent();
        ownedOperation?.RequireActive();
        cancellationToken.ThrowIfCancellationRequested();
        return new(opened.Result.Body, prepared.Authority);
    }

    internal static async Task<ReadOnlyMemory<byte>> ForwardOnceAsync(
        IPrivacyManagedIngressTransport transport, ReadOnlyMemory<byte> frame,
        CancellationToken ct)
    {
        try { return await transport.ForwardAsync(frame, ct).ConfigureAwait(false); }
        catch (PrivacyIngressRejectedBeforeForwardException error)
        {
            // Preserve the existing ingress certainty, rather than losing it
            // as an untyped IOException. No route fallback/retry is performed.
            throw new ClientMailboxTransportException(
                ClientMailboxTransportFailure.DependencyUnavailable, error.Retryable,
                "The selected DID2 contact ingress rejected the request before forwarding.", error);
        }
    }

    private sealed class NoClientReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromException<byte[]>(new NotSupportedException(
                "A DID2 client does not own an XNode receive key."));
        }
    }
}
