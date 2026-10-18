using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;

namespace Deep.Client.Shared.Services.ContactV2;

// Available only to the actual protected owner with borrowed same-account
// guards/entropy. No direct service URL, caller signer or alternate transport.
internal static class Did2GroupControlOnionTransport
{
    internal static async Task<GroupControlResultRecord> ExchangeAsync(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody, VerifiedGroupControlPlacement placement, GroupRecord request,
        Func<CancellationToken, Task> guard, CancellationToken ct)
    {
        source.RequireAccountOwner(custody.Owner);
        var attempt = await new ContactResolvePrivacyPathProvider(source, custody.Guards).PrepareGroupControlAsync(
            placement, request.CanonicalBytes, placement.ReplicaIds[0], ct).ConfigureAwait(false);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy), new OnionKeyAgreementAuthority(new NoReceiveVault()));
        using var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct).ConfigureAwait(false);
        using var transport = new PrivacyManagedIngressHttpTransport(OnionEntryTransportFactory.Create(attempt.Path));
        await guard(ct).ConfigureAwait(false);
        var response = await DeepIdV2PublicationOnionTransport.ForwardOnceAsync(transport, built.Frame, ct).ConfigureAwait(false);
        var opened = await codec.OpenResponseAsync(response, built.ReplyContext, ct).ConfigureAwait(false);
        if (opened.Result.Operation != OnionOperation.GroupControl || opened.Result.Kind != OnionTerminalResultKind.Success)
            throw new ClientMailboxDispatchOutcomeUnknownException("Control has no authenticated successful terminal response.");
        await guard(ct).ConfigureAwait(false);
        return GroupControlProductionClient.VerifyResult(placement, request, opened.Result.Body.Span);
    }
    private sealed class NoReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle handle, ReadOnlyMemory<byte> peer, CancellationToken ct) =>
            ValueTask.FromException<byte[]>(new NotSupportedException("Client has no node receive-key custody."));
    }
}
