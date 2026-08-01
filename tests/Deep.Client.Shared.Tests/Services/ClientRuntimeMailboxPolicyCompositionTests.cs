using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ClientRuntimeMailboxPolicyCompositionTests
{
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
                    backend: new AuthenticatedTransport()));
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
            using var runtime = ClientRuntime.CreatePersistent(
                path,
                ClientFeatureFlags.ReleaseDefaults with
                {
                    MetadataPrivateTransportRequired = false
                },
                backend: new AuthenticatedTransport(),
                mailboxDeliveryPolicy:
                    new DirectP2pMailboxDeliveryPolicy());
            Assert.IsType<E2eeClientTransport>(runtime.MessageTransport);
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
