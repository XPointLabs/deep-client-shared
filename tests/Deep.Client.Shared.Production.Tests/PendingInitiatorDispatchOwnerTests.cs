using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Client.Shared.Tests.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Tests.Services.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed class PendingInitiatorDispatchOwnerTests
{
    [Fact]
    public async Task RecoveredPendingDispatchReplaysExactDao1ThroughMessagingTransport()
    {
        const ulong now = 1_800_000_000;
        var root = Path.Combine(
            Path.GetTempPath(), "deep-pending-dispatch-owner", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(
            new InMemoryDeepAccountStore(), secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds((long)now)), network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x72));
            using var source = new ManagedInitiatorInitialSessionSqliteAdapterTests.Fixture(identity);
            var session = DeepDirectMessagingVerifiedSessionBinding.FromInitiatorScope(
                source.VerifiedScope, source.SessionId);

            await using (var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                var opened = Assert.IsType<DeepDirectMessagingSessionStoreBinding>(
                    await owner.TryOpenSessionAsync(session, createIfMissing: true));
                var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(
                    opened.Store, source.VerifiedScope);
                using var snapshot = source.Snapshot(opened.Store);
                Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
                    (await adapter.CommitForTestsAsync(snapshot)).Disposition);
            }

            var outbox = OutboxAccountScope.FromBytes(Bytes(32, 0x51));
            var local = new MessagingV1LocalContext(
                outbox, network, source.LocalAccountId,
                source.LocalDeviceId, source.LocalDeviceGeneration);
            var mailbox = new PrivacyRoutedMessagingTransportTests.FakeMailbox();
            var signer = new PrivacyRoutedMessagingTransportTests.FakeSigner(0x61);
            var selector = new MailboxCredentialSelector(
                outbox, MailboxCredentialScopeKind.Peer,
                Bytes(32, 0x61), Bytes(32, 0x6f));
            var sealingPrivate = Bytes(32, 0x41);
            var sealingPublic = ScalarMult.Base(sealingPrivate);
            var recipient = VerifiedMessagingRecipientDeposit.CreateForTests(
                outbox, selector, signer, network,
                source.RemoteAccountId, source.RemoteAccountGeneration, 19,
                source.RemoteDeviceId, source.RemoteDeviceGeneration,
                Bytes(32, 0x43), sealingPublic, now + 3_600);
            using var opener = new ManagedMessagingDao1OpenAuthority(
                network, Bytes(32, 0x43), sealingPublic, sealingPrivate);
            await using var restarted = await DeepDirectMessagingStorageOwner.OpenAsync(
                root, secrets, accounts, identity, authority);
            using var pending = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
                await restarted.TryReadPendingInitiatorDispatchAsync(
                    source.VerifiedScope, source.SessionId));
            using var sealer = new MessagingDao1SealingAuthority(Bytes(32, 0x42));
            var transport = new PrivacyRoutedMessagingTransport(
                local, mailbox, sealer, opener,
                new PrivacyRoutedMessagingTransportTests.FixedTimeProvider(
                    DateTimeOffset.FromUnixTimeSeconds((long)now)));

            mailbox.StoreFailure = new ClientMailboxDispatchOutcomeUnknownException("unknown");
            var uncertain = await Assert.ThrowsAsync<MessagingV1DispatchException>(() =>
                transport.SendInitialSessionAsync(pending, recipient, now + 600).AsTask());
            Assert.Equal(MessagingV1DispatchFailureClass.OutcomeUnknown, uncertain.FailureClass);
            mailbox.StoreFailure = null;
            using var stillPending = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
                await restarted.TryReadPendingInitiatorDispatchAsync(
                    source.VerifiedScope, source.SessionId));
            Assert.Equal(source.ExactDph2, stillPending.ExactDph2.ToArray());

            var first = await transport.SendInitialSessionAsync(
                stillPending, recipient, now + 600);
            var firstDao1 = Assert.Single(mailbox.Stored).Ciphertext.ToArray();
            var decoded = ApplicationCoreCodec.DecodeDao1(firstDao1);
            using var openedDao1 = await opener.OpenAsync(decoded.CanonicalBytes);
            Assert.Equal(source.ExactDph2, openedDao1.ExactInner.ToArray());
            Assert.Equal(source.SessionId, first.SessionId.ToArray());

            mailbox.StoreDisposition = MailboxReplicaDisposition.Duplicate;
            using var replaySealer = new MessagingDao1SealingAuthority(Bytes(32, 0x42));
            var replayTransport = new PrivacyRoutedMessagingTransport(
                local, mailbox, replaySealer, opener,
                new PrivacyRoutedMessagingTransportTests.FixedTimeProvider(
                    DateTimeOffset.FromUnixTimeSeconds((long)now)));
            var replay = await replayTransport.SendInitialSessionAsync(
                pending, recipient, now + 600);
            Assert.True(replay.ExactReplay);
            Assert.Equal(firstDao1, mailbox.Stored.Last().Ciphertext.ToArray());
            Assert.Equal(first.Dao1OperationId.ToArray(), replay.Dao1OperationId.ToArray());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExactPendingDispatchSurvivesOwnerRestartButRejectsPeerDrift()
    {
        var root = Path.Combine(
            Path.GetTempPath(), "deep-pending-dispatch-owner", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(
            new InMemoryDeepAccountStore(), secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x72));
            using var source = new ManagedInitiatorInitialSessionSqliteAdapterTests.Fixture(identity);
            var session = DeepDirectMessagingVerifiedSessionBinding.FromInitiatorScope(
                source.VerifiedScope, source.SessionId);

            await using (var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                             root, secrets, accounts, identity, authority))
            {
                var opened = Assert.IsType<DeepDirectMessagingSessionStoreBinding>(
                    await owner.TryOpenSessionAsync(session, createIfMissing: true));
                var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(
                    opened.Store, source.VerifiedScope);
                using var snapshot = source.Snapshot(opened.Store);
                Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
                    (await adapter.CommitForTestsAsync(snapshot)).Disposition);
                using var pending = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
                    await owner.TryReadPendingInitiatorDispatchAsync(
                        source.VerifiedScope, source.SessionId));
                Assert.Equal(source.ExactDph2, pending.ExactDph2.ToArray());
            }

            await using var restarted = await DeepDirectMessagingStorageOwner.OpenAsync(
                root, secrets, accounts, identity, authority);
            using var recovered = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
                await restarted.TryReadPendingInitiatorDispatchAsync(
                    source.VerifiedScope, source.SessionId));
            Assert.Equal(source.ExactDph2, recovered.ExactDph2.ToArray());
            Assert.Equal(source.SessionId, recovered.SessionId.ToArray());

            var drifted = source.ScopeWith(remoteDirectoryGeneration: 20);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await restarted.TryReadPendingInitiatorDispatchAsync(
                    drifted, source.SessionId));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await restarted.TryReadPendingInitiatorDispatchAsync(
                    source.VerifiedScope, Bytes(32, 0x75)));
            Assert.Single(await restarted.ReadCatalogAsync());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MissingDispatchDoesNotCreateSessionAndForeignPeerScopeFailsClosed()
    {
        var root = Path.Combine(
            Path.GetTempPath(), "deep-pending-dispatch-owner", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        using var secrets = new InMemoryDeepSecureStorage();
        var network = Bytes(16, 0x11);
        var accounts = new DeepAccountService(
            new InMemoryDeepAccountStore(), secrets,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000)),
            network);
        try
        {
            var identity = (await accounts.CreateAsync("Alice")).Identity;
            var authority = DeepDirectMessagingLocalAuthorityBinding.CreateForTests(
                identity, Bytes(32, 0x72));
            await using var owner = await DeepDirectMessagingStorageOwner.OpenAsync(
                root, secrets, accounts, identity, authority);
            var scope = Scope(network, identity.Account.AccountIdentity.AccountId.Bytes.Span);
            var sessionId = Bytes(32, 0x73);

            Assert.Null(await owner.TryReadPendingInitiatorDispatchAsync(scope, sessionId));
            Assert.Empty(await owner.ReadCatalogAsync());

            var foreign = Scope(network, Bytes(32, 0x74));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await owner.TryReadPendingInitiatorDispatchAsync(foreign, sessionId));
            Assert.Empty(await owner.ReadCatalogAsync());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static InitiatorInitialSessionVerifiedScope Scope(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> localAccount) =>
        InitiatorInitialSessionVerifiedScope.CreateForTests(
            network, localAccount, contactStoreGeneration: 1,
            Bytes(32, 0x21), Bytes(32, 0x22), Bytes(32, 0x23),
            Bytes(32, 0x24), Bytes(32, 0x31),
            remoteAccountGeneration: 1, remoteDirectoryGeneration: 1,
            Bytes(32, 0x32), remoteDeviceGeneration: 1);

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
}
