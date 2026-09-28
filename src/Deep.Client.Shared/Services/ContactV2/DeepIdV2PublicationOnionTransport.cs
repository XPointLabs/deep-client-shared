using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Services.ContactV2;

/// <summary>One exact three-hop DID2 publication attempt. Its TLS entry is
/// derived after exit-specific path selection, never from a fixed URL or an
/// unsigned route hint. No direct request or outcome-unknown fallback exists.</summary>
internal sealed class DeepIdV2PublicationOnionTransport : IExactContactResolveOnionTransport
{
    private readonly ContactResolvePrivacyPathProvider paths;
    private readonly PrivacyRoutingCodec codec;

    internal DeepIdV2PublicationOnionTransport(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody)
    {
        source.RequireAccountOwner(custody.Owner);
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
        var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
        using var transport = new PrivacyManagedIngressHttpTransport(entry);
        using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request,
            cancellationToken).ConfigureAwait(false);
        var response = await transport.ForwardAsync(built.Frame, cancellationToken).ConfigureAwait(false);
        PrivacyRoutingOpenedResponse opened;
        try { opened = await codec.OpenResponseAsync(response, built.ReplyContext, cancellationToken).ConfigureAwait(false); }
        catch (Exception error) when (error is CryptographicException or OnionBoundaryException)
        { throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 ONION publication reply could not be authenticated.", error); }
        if (opened.Result.Operation != OnionOperation.ContactResolve ||
            opened.Result.Kind != OnionTerminalResultKind.Success)
            throw new ClientMailboxDispatchOutcomeUnknownException("The DID2 ONION publication has no successful authenticated terminal result.");
        entry.EnsureCurrent();
        return new(opened.Result.Body, prepared.Authority);
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
