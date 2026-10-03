using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>One route-bound mailbox attempt using the DID2 owner's protected
/// network/guards/entropy and the exact selected entry. No static URL or
/// automatic second dispatch. Does not mint grants or authorize semantic ACK.</summary>
internal sealed class DeepIdV2MailboxOnionTransport :
    IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress
{
    private readonly MailboxPrivacyPathProvider paths;
    private readonly PrivacyRoutingCodec codec;
    private readonly IMailboxClientDecodePolicyProvider decodePolicies;
    private readonly Did2OwnedMailboxTransportContext? heldDispatch;

    internal DeepIdV2MailboxOnionTransport(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody, PrivacyMailboxRouteSelection selection,
        IMailboxClientDecodePolicyProvider decodePolicies)
    {
        ArgumentNullException.ThrowIfNull(source);
        this.decodePolicies = decodePolicies ?? throw new ArgumentNullException(nameof(decodePolicies));
        paths = source.CreateOwnMailboxPaths(custody, selection);
        codec = new(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new NoClientReceiveVault()));
    }

    internal DeepIdV2MailboxOnionTransport(Did2OwnedMailboxTransportContext dispatch,
        PrivacyMailboxRouteSelection selection, IMailboxClientDecodePolicyProvider decodePolicies)
    {
        heldDispatch = dispatch ?? throw new ArgumentNullException(nameof(dispatch));
        this.decodePolicies = decodePolicies ?? throw new ArgumentNullException(nameof(decodePolicies));
        paths = dispatch.Source.CreateOwnHeldMailboxPaths(dispatch, selection);
        codec = new(new OnionEntropyAuthority(dispatch.Custody.Entropy),
            new OnionKeyAgreementAuthority(new NoClientReceiveVault()));
    }

    public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Unscoped(ct);
    public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Unscoped(ct);
    public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Unscoped(ct);

    public Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request,
        ScopedMailboxResolvedRoute route, CancellationToken ct) =>
        SendAsync(request, route, OnionOperation.Store, MailboxAuthenticatedOperation.Store, ct);
    public Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> request,
        ScopedMailboxResolvedRoute route, CancellationToken ct) =>
        SendAsync(request, route, OnionOperation.Retrieve, MailboxAuthenticatedOperation.Retrieve, ct);
    public Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> request,
        ScopedMailboxResolvedRoute route, CancellationToken ct) =>
        SendAsync(request, route, OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Ack, ct);

    private async Task<ReadOnlyMemory<byte>> SendAsync(ReadOnlyMemory<byte> request,
        ScopedMailboxResolvedRoute route, OnionOperation operation,
        MailboxAuthenticatedOperation mailboxOperation, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(route);
        if (request.Length > MailboxAuthenticatedClientRequestCodec.HeaderLength +
            MailboxAuthenticatedCapabilityLimits.PresentationLength + MailboxClientLimits.MaximumPageBytes)
            throw new ClientMailboxTransportException(ClientMailboxTransportFailure.PayloadTooLarge,
                false, "The DID2 mailbox request exceeds its canonical bound.");
        // Own caller bytes across all awaits; Protocol verifies this same copy.
        var exact = request.ToArray();
        try
        {
            _ = PrivacyRoutedMailboxBinaryIngress.ValidateCanonicalMau3(exact, mailboxOperation);
            var attempt = await paths.PrepareOnRouteAsync(operation, exact, route, ct).ConfigureAwait(false);
            var entry = OnionEntryTransportFactory.Create(attempt.Path);
            using var transport = new PrivacyManagedIngressHttpTransport(entry);
            using var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct).ConfigureAwait(false);
            if (heldDispatch is not null) await heldDispatch.RequireCurrentAsync(ct).ConfigureAwait(false);
            var response = await transport.ForwardAsync(built.Frame, ct).ConfigureAwait(false);
            PrivacyRoutingOpenedResponse opened;
            try { opened = await codec.OpenResponseAsync(response, built.ReplyContext, ct).ConfigureAwait(false); }
            catch (Exception error) when (error is CryptographicException or OnionBoundaryException or OperationCanceledException)
            { throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 mailbox reply could not be authenticated after forwarding.", error); }
            if (opened.Result.Operation != operation)
                throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 mailbox reply changed operation.");
            if (opened.Result.Kind == OnionTerminalResultKind.Failure)
                throw PrivacyRoutedMailboxBinaryIngress.MapTerminalFailure(opened.Result);
            if (opened.Result.Kind != OnionTerminalResultKind.Success)
                throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 mailbox reply has no successful terminal result.");
            // No local policy/freshness rejection after forwarding is a
            // definitive non-delivery result, even if response decoding fails.
            try
            {
                PrivacyRoutedMailboxBinaryIngress.ValidateCanonicalResponse(opened.Result.Body.Span, operation, decodePolicies);
                entry.EnsureCurrent();
                if (heldDispatch is not null) await heldDispatch.RequireCurrentAsync(ct).ConfigureAwait(false);
            }
            catch (Exception error) when (error is OnionBoundaryException or CryptographicException or
                InvalidOperationException or IOException or OperationCanceledException)
            { throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 mailbox reply failed post-dispatch policy or freshness checks.", error); }
            return opened.Result.Body;
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private static Task<ReadOnlyMemory<byte>> Unscoped(CancellationToken ct) => ct.IsCancellationRequested
        ? Task.FromCanceled<ReadOnlyMemory<byte>>(ct)
        : Task.FromException<ReadOnlyMemory<byte>>(new ClientMailboxTransportException(
            ClientMailboxTransportFailure.ProtocolViolation, false,
            "DID2 mailbox dispatch requires the exact scoped credential route."));

    private sealed class NoClientReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle handle,
            ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromException<byte[]>(new NotSupportedException("A DID2 client owns no XNode receive key."));
        }
    }
}
