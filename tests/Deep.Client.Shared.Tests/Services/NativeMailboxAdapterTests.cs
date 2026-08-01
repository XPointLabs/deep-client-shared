using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class NativeMailboxAdapterTests
{
    [Fact]
    public void Native_cloud_operations_select_scoped_credentials_not_a_mailbox_epoch_seam()
    {
        var retrieve = typeof(ClientMailboxAdapter).GetMethod(nameof(ClientMailboxAdapter.RetrieveAsync));
        var acknowledge = typeof(ClientMailboxAdapter).GetMethod(nameof(ClientMailboxAdapter.AcknowledgeAsync));
        Assert.NotNull(retrieve);
        Assert.NotNull(acknowledge);
        Assert.Contains(retrieve!.GetParameters(),
            parameter => parameter.ParameterType == typeof(MailboxCredentialSelector));
        Assert.Contains(acknowledge!.GetParameters(),
            parameter => parameter.ParameterType == typeof(MailboxCredentialSelector));
        Assert.DoesNotContain(retrieve.GetParameters(),
            parameter => parameter.ParameterType == typeof(BlindedMailboxId) ||
                         parameter.ParameterType == typeof(ulong));
        Assert.DoesNotContain(acknowledge.GetParameters(),
            parameter => parameter.ParameterType == typeof(BlindedMailboxId) ||
                         parameter.ParameterType == typeof(ulong));
    }

    [Fact]
    public void Factory_only_accepts_scoped_atomic_credential_preparation()
    {
        var constructor = Assert.Single(typeof(MailboxAuthenticatedRequestFactory).GetConstructors());
        Assert.Equal(typeof(IScopedMailboxCredentialRepository),
            constructor.GetParameters()[0].ParameterType);
        Assert.Null(typeof(MailboxAuthenticatedRequestFactory).GetMethod("LeaseCredentialAsync"));
        Assert.Null(Type.GetType(
            "Deep.Client.Shared.Persistence.IClientMailboxCredentialStateRepository, Deep.Client.Shared"));
    }

    [Fact]
    public void Direct_p2p_cannot_be_given_an_official_cloud_authority()
    {
        new MailboxDeliveryDecision(
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.DirectP2p,
            null).Validate();
        Assert.Throws<InvalidOperationException>(() => new MailboxDeliveryDecision(
            MailboxTransportProtocol.DirectP2p,
            MailboxInfrastructureOwnership.DirectP2p,
            new VerifiedOfficialMailboxAuthority(
                Enumerable.Repeat((byte)1, 16).ToArray(),
                1,
                [new MailboxCapabilityIssuerAuthority
                {
                    PublicKey = Enumerable.Repeat((byte)2, 32).ToArray(),
                    Domain = MailboxCapabilityDomain.Deposit,
                    AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                    MinimumGeneration = 1,
                    MaximumGeneration = 1,
                    ValidFromUnixSeconds = 1,
                    ValidUntilUnixSeconds = ulong.MaxValue
                }],
                true, static () => true, new NoRevocations(),
                TimeProvider.System)).Validate());
    }

    private sealed class NoRevocations : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }
}
