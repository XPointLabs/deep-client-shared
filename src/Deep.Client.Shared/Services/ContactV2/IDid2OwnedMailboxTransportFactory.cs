namespace Deep.Client.Shared.Services.ContactV2;

// Internal test seam only. It receives no signer, seed, repository or issuer.
internal interface IDid2OwnedMailboxTransportFactory
{
    IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext context, IMailboxClientDecodePolicyProvider policy);
}

internal sealed class Did2OwnedMailboxOnionTransportFactory : IDid2OwnedMailboxTransportFactory
{
    public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext context, IMailboxClientDecodePolicyProvider policy) =>
        new DeepIdV2MailboxOnionTransport(context, PrivacyMailboxRouteSelection.Primary, policy);
}
