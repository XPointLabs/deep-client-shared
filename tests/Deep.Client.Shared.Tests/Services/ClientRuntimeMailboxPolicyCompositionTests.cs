using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Tests.MessagingV1;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ClientRuntimeMailboxPolicyCompositionTests
{
    [Fact]
    public void Authenticated_mailbox_without_production_E2EE01_authority_is_typed_fail_closed()
    {
        var path = TempPath();
        var store = new SqliteSessionStore(new SqliteSessionStoreOptions(
            path, new string('A', 64)));
        try
        {
            var exception = Assert.Throws<MessagingV1CryptoUnavailableException>(() =>
                new ClientRuntime(
                    store,
                    ClientFeatureFlags.ReleaseDefaults with
                    {
                        MetadataPrivateTransportRequired = false
                    },
                    new SystemClock(),
                    new AuthenticatedTransport(),
                    requireE2eeTransport: true,
                    mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
                    messagingV1Persistence: new MessagingV1PersistenceOptions(
                        path + ".msg01", new string('A', 64))));

            Assert.Equal(
                MessagingV1CryptoUnavailableException.ProductionCapabilityUnavailable,
                exception.Code);
            Assert.False(File.Exists(path + ".msg01"));
            Assert.Contains("not accepted as fallbacks", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            store.Dispose();
            Delete(path);
            Delete(path + ".msg01");
        }
    }

    [Fact]
    public void Persistent_factory_requires_explicit_policy_for_required_transport()
    {
        var path = TempPath();
        try
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                ClientRuntime.CreatePersistent(
                    path,
                    ClientFeatureFlags.ReleaseDefaults with
                    {
                        MetadataPrivateTransportRequired = false
                    },
                    backend: new TestVerifiedMsg01Transport()));
            Assert.Contains(
                "explicit mailbox delivery policy",
                exception.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            Delete(path);
        }
    }

    [Fact]
    public void Persistent_factory_composes_explicit_policy_into_e2ee_runtime()
    {
        var path = TempPath();
        try
        {
            using var runtime = new ClientRuntime(
                new SqliteSessionStore(new SqliteSessionStoreOptions(
                    path, new string('A', 64))),
                ClientFeatureFlags.ReleaseDefaults with
                {
                    MetadataPrivateTransportRequired = false
                },
                new SystemClock(),
                new TestVerifiedMsg01Transport(),
                requireE2eeTransport: true,
                mailboxDeliveryPolicy:
                    new DirectP2pMailboxDeliveryPolicy(),
                messagingV1Persistence: new MessagingV1PersistenceOptions(
                    path + ".msg01", new string('A', 64)));
            Assert.Equal("Msg01AuthoritativeTransport", runtime.MessageTransport.GetType().Name);
        }
        finally
        {
            Delete(path);
        }
    }

    private sealed class AuthenticatedTransport :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport
    {
        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<IReadOnlyList<InboundMessageEnvelope>>
            ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
    }

    private static string TempPath() => Path.Combine(
        Path.GetTempPath(),
        $"deep-runtime-policy-{Guid.NewGuid():N}.db");

    private static void Delete(string path)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }
}
