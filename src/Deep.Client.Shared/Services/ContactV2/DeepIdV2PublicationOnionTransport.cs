using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// Explicit owned loan; a generic transport cannot silently bypass it.
internal interface IDid2OwnedExactContactResolveOnionTransport : IExactContactResolveOnionTransport
{
    ValueTask<ExactContactResolveOnionResponse> SendOwnedExactAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        Did2OwnedContactTransportContext operation, CancellationToken ct);
}

/// <summary>One exact three-hop DID2 publication attempt. Its TLS entry is
/// derived after exit-specific path selection, never from a fixed URL or an
/// unsigned route hint. No direct request or outcome-unknown fallback exists.</summary>
internal sealed class DeepIdV2PublicationOnionTransport : IDid2OwnedExactContactResolveOnionTransport
{
    private readonly ContactResolvePrivacyPathProvider paths;
    private readonly PrivacyRoutingCodec codec;
    private readonly DeepIdV2OnionClientCustody custody;
    private readonly DeepIdV2ContactPathAuthoritySource source;

    internal DeepIdV2PublicationOnionTransport(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody)
    {
        source.RequireAccountOwner(custody.Owner);
        this.custody = custody;
        this.source = source;
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
            request, requiredExitReplicaId, authority, cancellationToken, operation.RetainedReadRequest, operation).ConfigureAwait(false);
        operation.RequireActive();
        var result = await SendPreparedAsync(prepared, operation, cancellationToken).ConfigureAwait(false);
        operation.RequireActive();
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    // One command's independently verified context, never an account-lease
    // bypass or retained currentness cache. Every suspended local preparation
    // is followed by the ordinary protected-floor/proof/time recheck.
    internal async ValueTask<ExactContactResolveOnionResponse> SendPreKeyPublicationExactAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        var prepared = await PreparePreKeyPublicationAsync(request, requiredExitReplicaId, fresh, ct).ConfigureAwait(false);
        return await SendPreparedAsync(prepared, null, ct, fresh).ConfigureAwait(false);
    }

    // A prepared path alone is not dispatch permission: SendPreparedAsync must
    // still recheck after frame construction and after authenticated return.
    internal async ValueTask<ContactResolvePreparedPath> PreparePreKeyPublicationAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(fresh);
        if (request.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory)
            throw new ArgumentException("Prekey publication accepts only its exact fragment kind.", nameof(request));
        await source.RecheckOwnPreKeyAuthoringAsync(fresh, ct).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(fresh.Network,
            request.RequestKind, request.ShardKey);
        return await paths.PrepareWithAuthorityAsync(OnionOperation.ContactResolve,
            request, requiredExitReplicaId, new(fresh.Network, placement), ct).ConfigureAwait(false);
    }

    ValueTask<ExactContactResolveOnionResponse> IDid2OwnedExactContactResolveOnionTransport.SendOwnedExactAsync(
        ContactResolveCanonicalPathRequest request, ReadOnlyMemory<byte> requiredExitReplicaId,
        Did2OwnedContactTransportContext operation, CancellationToken ct)
        => SendOwnedExactAsync(request, requiredExitReplicaId, operation, ct);

    private async ValueTask<ExactContactResolveOnionResponse> SendPreparedAsync(
        ContactResolvePreparedPath prepared, Did2OwnedContactTransportContext? ownedOperation, CancellationToken cancellationToken,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority? prekeyPublication = null)
    {
        var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
        using var transport = new PrivacyManagedIngressHttpTransport(entry);
        using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request,
            cancellationToken).ConfigureAwait(false);
        if (ownedOperation?.RetainedReadRequest is { } retained)
            await retained.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        if (prekeyPublication is not null)
            await source.RecheckOwnPreKeyAuthoringAsync(prekeyPublication, cancellationToken).ConfigureAwait(false);
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
        {
            var rejected = new ClientMailboxDispatchOutcomeUnknownException("The DID2 ONION publication has no successful authenticated terminal result.");
            if (opened.Result.FailureCode is { } code && Enum.IsDefined(code))
                rejected.Data["Deep.ContactResolve.TerminalFailure"] = (ushort)code;
            throw rejected;
        }
        entry.EnsureCurrent();
        if (ownedOperation?.RetainedReadRequest is { } returnedRetained)
            await returnedRetained.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        if (prekeyPublication is not null)
            await source.RecheckOwnPreKeyAuthoringAsync(prekeyPublication, cancellationToken).ConfigureAwait(false);
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
