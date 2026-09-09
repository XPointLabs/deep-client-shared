using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.GroupV1;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class IdentityBoundMessagingV1CompositionTests
{
    [Fact]
    public void IdentityBoundOwnerAcceptsOnlyExactTransportAccountAlias()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "deep-msg-identity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var scope = MessageScope(0x31);
            var alias = SessionId.Parse("05" + new string('a', 64));
            using var owner = MessagingV1RuntimeOwner.CreatePersistent(
                Path.Combine(directory, "state.db"),
                new string('K', 64),
                Msg01VerifiedSessionAuthority.CreateTestEd25519(Bytes(32, 0x21)),
                scope,
                alias);

            Assert.NotNull(owner.OpenForAccount(alias));
            var error = Assert.Throws<InvalidOperationException>(() =>
                owner.OpenForAccount(SessionId.Parse("05" + new string('b', 64))));
            Assert.Contains("does not prove", error.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ClientRuntimeRejectsGroupStoreWithoutMatchingDeepAccountMessageScope()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-group-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var groupScope = GroupScope(0x41);
        using var groupOptions = new SqliteGroupStateStoreOptions(
            Path.Combine(directory, "group.db"),
            Bytes(32, 0x71),
            groupScope);
        using var groupStore = new SqliteGroupStateStore(groupOptions);
        var transport = new AuthenticatedTransport();
        try
        {
            var missingIdentity = Assert.Throws<InvalidOperationException>(() =>
                new ClientRuntime(
                    new InMemorySessionStore(),
                    ClientFeatureFlags.ReleaseDefaults with { MetadataPrivateTransportRequired = false },
                    new FrozenClock(DateTimeOffset.Parse("2026-09-08T00:00:00Z")),
                    transport,
                    requireE2eeTransport: true,
                    mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
                    messagingV1Persistence: new MessagingV1PersistenceOptions(
                        Path.Combine(directory, "missing.msg01"), new string('A', 64)),
                    groupV1StateStore: groupStore));
            Assert.Contains("DeepAccount-bound", missingIdentity.Message, StringComparison.Ordinal);

            var wrongIdentity = Assert.Throws<InvalidOperationException>(() =>
                new ClientRuntime(
                    new InMemorySessionStore(),
                    ClientFeatureFlags.ReleaseDefaults with { MetadataPrivateTransportRequired = false },
                    new FrozenClock(DateTimeOffset.Parse("2026-09-08T00:00:00Z")),
                    transport,
                    requireE2eeTransport: true,
                    mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
                    messagingV1Persistence: new MessagingV1PersistenceOptions(
                        Path.Combine(directory, "wrong.msg01"),
                        new string('A', 64),
                        MessageScope(0x51),
                        SessionId.Parse("05" + new string('c', 64))),
                    groupV1StateStore: groupStore));
            Assert.Contains("different account generations", wrongIdentity.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            transport.Dispose();
            groupStore.Dispose();
            groupOptions.Dispose();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static MessageStoreScope MessageScope(byte marker)
    {
        var identity = Identity(marker);
        return new MessageStoreScope(
            MessagingAccountId32.FromBytes(identity.AccountId.Bytes.Span),
            identity.AccountGeneration,
            MessageStoreInstanceId32.FromBytes(Bytes(32, (byte)(marker + 1))));
    }

    private static GroupStoreScope GroupScope(byte marker)
    {
        var identity = Identity(marker);
        return GroupStoreScope.ForCurrentAccount(identity.AccountId, identity.AccountGeneration);
    }

    private static DeepAccountIdentityCapability Identity(byte marker) =>
        DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Bytes(16, 0x11)),
            1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, marker)));

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class AuthenticatedTransport :
        ISessionMessageTransport,
        IMsg01AuthenticatedEvidenceSource,
        IDisposable
    {
        public Msg01VerifiedSessionAuthority EvidenceAuthority { get; } =
            Msg01VerifiedSessionAuthority.CreateTestEd25519(Bytes(32, 0x61));
        public ValueTask<SessionId> GetLocalAccountAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SessionId.Parse("05" + new string('d', 64)));
        public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
            Msg01ResolveFanoutTargetRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
            Msg01PrepareAttemptRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
            Msg01InboundEvidenceRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public ValueTask AcknowledgeReceiptAsync(ReadOnlyMemory<byte> authenticatedReceipt,
            CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task SendAsync(OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        public void Dispose() { }
    }
}
