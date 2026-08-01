using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MailboxTransportOwnershipTests
{
    [Theory]
    [InlineData(MailboxInfrastructureOwnership.UserManaged)]
    [InlineData(MailboxInfrastructureOwnership.OfficialManaged)]
    public void AuthenticatedMau2OwnershipAlwaysRequiresAuthorityAndSelector(
        MailboxInfrastructureOwnership ownership)
    {
        Assert.Throws<InvalidOperationException>(() => new MailboxDeliveryDecision(
            MailboxTransportProtocol.AuthenticatedMau2,
            ownership,
            null,
            null).Validate());
    }

    [Fact]
    public void UserManagedMau2IsNotDirectP2pAndNativeTransportHasNoFreeMarker()
    {
        Assert.False(typeof(IDirectP2pSessionMessageTransport)
            .IsAssignableFrom(typeof(NativeMau2MailboxTransport)));
        Assert.True(typeof(IMailboxIdentityAuthenticatedRawTransport)
            .IsAssignableFrom(typeof(NativeMau2MailboxTransport)));
        Assert.Throws<InvalidOperationException>(() => new MailboxDeliveryDecision(
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.UserManaged,
            null).Validate());
    }

    [Fact]
    public void DirectP2pCannotCarryBillingOrMailboxAuthority()
    {
        new MailboxDeliveryDecision(
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.DirectP2p,
            null).Validate();
        Assert.Throws<InvalidOperationException>(() => new MailboxDeliveryDecision(
            MailboxTransportProtocol.AuthenticatedMau2,
            MailboxInfrastructureOwnership.DirectP2p,
            null).Validate());
    }
}
