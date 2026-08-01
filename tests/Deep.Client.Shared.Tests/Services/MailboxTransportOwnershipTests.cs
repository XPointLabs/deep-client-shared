using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MailboxTransportOwnershipTests
{
    [Fact]
    public async Task UserManagedPolicyIsFreeButDistinctFromDirectAndOfficialCloud()
    {
        var envelope = new OutboundMessageEnvelope(
            new SessionId(new string('a', 64)),
            new SessionId(new string('b', 64)),
            "dpe1:AQ", [], DateTimeOffset.UnixEpoch.AddDays(1),
            DateTimeOffset.UnixEpoch.AddDays(2));
        var decision = await new UserManagedMailboxDeliveryPolicy().DecideAsync(
            new MailboxDeliveryRequest(envelope, MailboxDeliveryKind.Direct));

        decision.Validate();
        Assert.Equal(MailboxDeliveryMode.UserManagedNetwork, decision.Mode);
        Assert.Null(decision.OfficialAuthority);
        Assert.Null(decision.Selector);
    }

    [Fact]
    public void OwnershipCapabilitiesCannotRelabelOfficialMailboxAsFree()
    {
        Assert.False(typeof(IDirectP2pSessionMessageTransport)
            .IsAssignableFrom(typeof(NativeMau2MailboxTransport)));
        Assert.False(typeof(IUserManagedSessionMessageTransport)
            .IsAssignableFrom(typeof(NativeMau2MailboxTransport)));
        Assert.Throws<ArgumentException>(() =>
            new UserManagedSessionMessageTransport(new FakeOfficialMailbox()));
    }

    [Fact]
    public void UserManagedWrapperDelegatesMetadataPrivacyWithoutClaimingDirectP2p()
    {
        var inner = new FakePrivateTransport();
        using var wrapped = new UserManagedSessionMessageTransport(inner);

        Assert.True(wrapped.UsesMetadataPrivateTransport);
        Assert.IsAssignableFrom<IUserManagedSessionMessageTransport>(wrapped);
        Assert.IsNotAssignableFrom<IDirectP2pSessionMessageTransport>(wrapped);
    }

    private sealed class FakePrivateTransport :
        ISessionMessageTransport,
        IAuthenticatedInboxTransport,
        IMetadataPrivateSessionMessageTransport
    {
        public bool UsesMetadataPrivateTransport => true;
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
    }

    private sealed class FakeOfficialMailbox :
        IAuthenticatedOpaqueMailboxTransport,
        IAuthenticatedInboxTransport
    {
        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>> PrepareScopedMailboxBatchAsync(
            IMailboxOperationSigner signer, IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>([]);
        public Task SendPreparedMailboxAuthenticatedAsync(
            IPreparedMailboxAuthenticatedSend preparedSend,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer, OpaqueMailboxContinuation continuation,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task AcknowledgeOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer, string opaqueItemHandle,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
    }
}
