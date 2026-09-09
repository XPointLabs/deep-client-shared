using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Client.Shared.Tests.Services.MessagingV1;

public sealed class PrivacyRoutedMessagingTransportTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public async Task InitialSession_ProducesExactDao1AndTypedDurableReceipt()
    {
        using var fixture = new Fixture();
        using var pending = fixture.PendingDph2();

        var receipt = await fixture.Transport.SendInitialSessionAsync(
            pending, fixture.Recipient, Now + 600);

        var envelope = Assert.Single(fixture.Mailbox.Stored);
        var dao1 = ApplicationCoreCodec.DecodeDao1(envelope.Ciphertext.Span);
        Assert.Equal(MessagingV1DepositKind.InitialSession, receipt.Kind);
        Assert.Equal(pending.OperationId.ToArray(), receipt.InnerOperationId.ToArray());
        Assert.Equal(dao1.DepositOperationId.ToArray(), receipt.Dao1OperationId.ToArray());
        Assert.Equal(dao1.DepositOperationId.ToArray(), receipt.LogicalOperationId.ToArray());
        Assert.Equal(envelope.OperationId.ToArray(), receipt.MailboxOperationId.ToArray());
        Assert.Equal(MailboxClientLimits.OperationIdLength, envelope.OperationId.Length);
        Assert.Equal(
            MessagingDao1Crypto.DeriveMailboxOperationId(dao1.DepositOperationId.Span),
            envelope.OperationId.ToArray());
        Assert.Equal(SHA256.HashData(envelope.Ciphertext.Span), receipt.ExactDao1Hash.ToArray());
        Assert.Equal(fixture.RemoteDevice, receipt.RecipientDeviceId.ToArray());
        Assert.Equal(MailboxReplicaDisposition.Stored, fixture.Mailbox.StoreDisposition);
        Assert.Equal(1UL, receipt.Cursor);
    }

    [Fact]
    public async Task Restart_ReproducesStableLogicalOperationAndExactDao1()
    {
        using var fixture = new Fixture();
        using var pending1 = fixture.PendingDph2();
        var first = await fixture.Transport.SendInitialSessionAsync(
            pending1, fixture.Recipient, Now + 600);
        var firstDao = fixture.Mailbox.Stored.Single().Ciphertext.ToArray();

        fixture.Mailbox.StoreDisposition = MailboxReplicaDisposition.Duplicate;
        using var restartedSealer = new MessagingDao1SealingAuthority(fixture.SealingSeed);
        var restarted = fixture.CreateTransport(restartedSealer);
        using var pending2 = fixture.PendingDph2();
        var second = await restarted.SendInitialSessionAsync(
            pending2, fixture.Recipient, Now + 600);

        Assert.Equal(first.LogicalOperationId.ToArray(), second.LogicalOperationId.ToArray());
        Assert.Equal(first.MailboxOperationId.ToArray(), second.MailboxOperationId.ToArray());
        Assert.Equal(firstDao, fixture.Mailbox.Stored.Last().Ciphertext.ToArray());
        Assert.True(second.ExactReplay);
    }

    [Fact]
    public async Task InitialDelivery_AloneActivatesMatchingDpe2Route()
    {
        using var fixture = new Fixture();
        using var pending = fixture.PendingDph2();
        var delivered = await fixture.Transport.SendInitialSessionAsync(
            pending, fixture.Recipient, Now + 600);

        var route = delivered.Activate(fixture.Recipient);
        Assert.Equal(pending.SessionId.ToArray(), route.SessionId.ToArray());
        Assert.Same(fixture.Recipient, route.Recipient);

        var wrongGeneration = fixture.RemoteRecipient(deviceGeneration: 2);
        Assert.Throws<CryptographicException>(() => delivered.Activate(wrongGeneration));
    }

    [Fact]
    public async Task InitialSession_InvalidMailboxTtlRejectsBeforeMutation()
    {
        using var fixture = new Fixture();
        using var pending = fixture.PendingDph2();

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.SendInitialSessionAsync(
                pending, fixture.Recipient, Now + 59).AsTask());

        Assert.Empty(fixture.Mailbox.Stored);
    }

    [Fact]
    public async Task InitialSession_WrongRecipientRejectsBeforeMailboxMutation()
    {
        using var fixture = new Fixture();
        using var pending = fixture.PendingDph2(responderDevice: Bytes(32, 0x7f));

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.SendInitialSessionAsync(
                pending, fixture.Recipient, Now + 600).AsTask());

        Assert.Empty(fixture.Mailbox.Stored);
    }

    [Fact]
    public async Task InitialSession_WrongDurableOperationRejectsBeforeMailboxMutation()
    {
        using var fixture = new Fixture();
        using var valid = fixture.PendingDph2();
        using var wrong = new InitiatorInitialSessionDispatchEnvelope(
            valid.ExactDph2.Span,
            Bytes(32, 0xe1),
            valid.SessionId.Span,
            valid.ReplayHash.Span);

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.SendInitialSessionAsync(
                wrong, fixture.Recipient, Now + 600).AsTask());

        Assert.Empty(fixture.Mailbox.Stored);
    }

    [Fact]
    public async Task Store_PreForwardRejectAndOutcomeUnknownRemainDistinct()
    {
        using var fixture = new Fixture();
        using var first = fixture.PendingDph2();
        fixture.Mailbox.StoreFailure = new ClientMailboxTransportException(
            ClientMailboxTransportFailure.DependencyUnavailable,
            retryable: true,
            "rejected",
            new PrivacyIngressRejectedBeforeForwardException(true, "pre-forward"));
        var rejected = await Assert.ThrowsAsync<MessagingV1DispatchException>(() =>
            fixture.Transport.SendInitialSessionAsync(
                first, fixture.Recipient, Now + 600).AsTask());
        Assert.Equal(MessagingV1DispatchFailureClass.RejectedBeforeForward, rejected.FailureClass);
        Assert.True(rejected.Retryable);

        using var second = fixture.PendingDph2();
        fixture.Mailbox.StoreFailure = new ClientMailboxDispatchOutcomeUnknownException("unknown");
        var unknown = await Assert.ThrowsAsync<MessagingV1DispatchException>(() =>
            fixture.Transport.SendInitialSessionAsync(
                second, fixture.Recipient, Now + 600).AsTask());
        Assert.Equal(MessagingV1DispatchFailureClass.OutcomeUnknown, unknown.FailureClass);
        Assert.True(unknown.Retryable);
    }

    [Fact]
    public async Task Receive_OpensExactDpe2AndWaitsForCommitReceiptBeforeAck()
    {
        using var fixture = new Fixture();
        fixture.EnqueueInbound(fixture.ExactInboundDpe2());

        using var batch = await fixture.Transport.RetrieveAsync(
            fixture.SelfSelector, maximumItems: 8);

        var item = Assert.Single(batch.Items);
        Assert.Equal(MessagingV1DepositKind.EstablishedSession, item.Kind);
        Assert.Equal(fixture.ExactInboundDpe2(), item.ExactInner.ToArray());
        Assert.Empty(fixture.Mailbox.Acknowledged);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Transport.AcknowledgeAsync(
                fixture.SelfSelector, batch, [], default).AsTask());
        var committed = MessagingV1InboundCommitReceipt.CreateForTests(item);
        await fixture.Transport.AcknowledgeAsync(
            fixture.SelfSelector, batch, [committed]);
        Assert.Single(fixture.Mailbox.Acknowledged);
        Assert.Equal(MailboxClientLimits.OperationIdLength,
            Assert.Single(fixture.Mailbox.AckOperationIds).Length);
    }

    [Fact]
    public async Task Receive_WrongRecipientAndEnvelopeContextRejectWithoutAck()
    {
        using var fixture = new Fixture();
        var wrongDevice = Bytes(32, 0x99);
        fixture.EnqueueInbound(
            fixture.ExactInboundDpe2(recipient: wrongDevice),
            fixture.RecipientForLocalDevice(wrongDevice));
        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.RetrieveAsync(fixture.SelfSelector, 8).AsTask());
        Assert.Empty(fixture.Mailbox.Acknowledged);

        fixture.Mailbox.Durable.Clear();
        fixture.EnqueueInbound(fixture.ExactInboundDpe2());
        var original = fixture.Mailbox.Durable[0];
        fixture.Mailbox.Durable[0] = original with
        {
            Envelope = original.Envelope with { OperationId = Bytes(16, 0xee) },
        };
        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.RetrieveAsync(fixture.SelfSelector, 8).AsTask());
        Assert.Empty(fixture.Mailbox.Acknowledged);
    }

    [Fact]
    public async Task Receive_WrongTypedMailboxRouteRejectsWithoutOpenOrAck()
    {
        using var fixture = new Fixture();
        fixture.EnqueueInbound(fixture.ExactInboundDpe2());
        var original = fixture.Mailbox.Durable[0];
        fixture.Mailbox.Durable[0] = original with
        {
            Envelope = original.Envelope with
            {
                MailboxId = new BlindedMailboxId(Bytes(32, 0xef)),
            },
        };

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.RetrieveAsync(fixture.SelfSelector, 8).AsTask());

        Assert.Empty(fixture.Mailbox.Acknowledged);
    }

    [Fact]
    public async Task Receive_WrongSelfHolderRejectsBeforeMailboxMutation()
    {
        using var fixture = new Fixture();
        var wrong = new MailboxCredentialSelector(
            fixture.Scope,
            MailboxCredentialScopeKind.Self,
            Bytes(32, 0xec),
            Bytes(32, 0x6f));

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.RetrieveAsync(wrong, 8).AsTask());

        Assert.Equal(0, fixture.Mailbox.RetrieveCalls);
    }

    [Fact]
    public async Task Receive_WrongCommitReceiptCannotAcknowledgeAnotherReplay()
    {
        using var fixture = new Fixture();
        fixture.EnqueueInbound(fixture.ExactInboundDpe2());
        using var batch = await fixture.Transport.RetrieveAsync(fixture.SelfSelector, 8);
        var item = Assert.Single(batch.Items);

        var otherInner = fixture.ExactInboundDpe2(operation: Bytes(32, 0xa9));
        using var otherDao = fixture.Sealer.Seal(
            fixture.RemoteLocal, fixture.LocalRecipient, otherInner);
        var otherEnvelope = fixture.MailboxEnvelope(otherDao.Canonical.Span, cursor: 2);
        using var opened = await fixture.Opener.OpenAsync(otherEnvelope.Envelope.Ciphertext);
        using var other = new MessagingV1ReceivedDeposit(
            opened.Kind, opened.Parsed, opened.ExactInner.Span, otherEnvelope);
        var wrong = MessagingV1InboundCommitReceipt.CreateForTests(other);

        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.Transport.AcknowledgeAsync(
                fixture.SelfSelector, batch, [wrong], default).AsTask());
        Assert.Empty(fixture.Mailbox.Acknowledged);
        Assert.NotNull(item);
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly byte[] Network = Bytes(16, 0x11);
        internal readonly byte[] LocalAccount = Bytes(32, 0x21);
        internal readonly byte[] LocalDevice = Bytes(32, 0x22);
        internal readonly byte[] RemoteAccount = Bytes(32, 0x31);
        internal readonly byte[] RemoteDevice = Bytes(32, 0x32);
        internal readonly byte[] SealingPrivate = Bytes(32, 0x41);
        internal readonly byte[] SealingSeed = Bytes(32, 0x42);
        internal readonly OutboxAccountScope Scope = OutboxAccountScope.FromBytes(Bytes(32, 0x51));
        internal readonly FakeMailbox Mailbox = new();
        internal readonly FakeSigner Signer = new();
        internal readonly MessagingV1LocalContext Local;
        internal readonly MessagingV1LocalContext RemoteLocal;
        internal readonly MailboxCredentialSelector RecipientSelector;
        internal readonly MailboxCredentialSelector SelfSelector;
        internal readonly MailboxCredentialSelector LocalDepositSelector;
        internal readonly VerifiedMessagingRecipientDeposit Recipient;
        internal readonly VerifiedMessagingRecipientDeposit LocalRecipient;
        internal readonly MessagingDao1SealingAuthority Sealer;
        internal readonly ManagedMessagingDao1OpenAuthority Opener;
        internal readonly PrivacyRoutedMessagingTransport Transport;

        internal Fixture()
        {
            var sealingPublic = ScalarMult.Base(SealingPrivate);
            Local = new MessagingV1LocalContext(Scope, Network, LocalAccount, LocalDevice, 1);
            RemoteLocal = new MessagingV1LocalContext(Scope, Network, RemoteAccount, RemoteDevice, 1);
            RecipientSelector = Selector(MailboxCredentialScopeKind.Peer, 0x61);
            SelfSelector = Selector(MailboxCredentialScopeKind.Self, 0xd1);
            LocalDepositSelector = Selector(MailboxCredentialScopeKind.Peer, 0x63);
            Recipient = VerifiedMessagingRecipientDeposit.CreateForTests(
                Scope, RecipientSelector, Network, RemoteAccount, 1, 1,
                RemoteDevice, 1, Bytes(32, 0x43), sealingPublic, Now + 3_600);
            LocalRecipient = VerifiedMessagingRecipientDeposit.CreateForTests(
                Scope, LocalDepositSelector, Network, LocalAccount, 1, 1,
                LocalDevice, 1, Bytes(32, 0x43), sealingPublic, Now + 3_600);
            Sealer = new MessagingDao1SealingAuthority(SealingSeed);
            Opener = new ManagedMessagingDao1OpenAuthority(
                Network, Bytes(32, 0x43), sealingPublic, SealingPrivate);
            Transport = CreateTransport(Sealer);
        }

        internal PrivacyRoutedMessagingTransport CreateTransport(
            MessagingDao1SealingAuthority sealer) => new(
                Local, Signer, Mailbox, sealer, Opener,
                new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds((long)Now)));

        internal InitiatorInitialSessionDispatchEnvelope PendingDph2(
            byte[]? responderDevice = null)
        {
            var record = Dph2(
                LocalAccount, LocalDevice, RemoteAccount,
                responderDevice ?? RemoteDevice, Bytes(32, 0x71));
            var exact = Dph2Codec.Encode(record);
            return new InitiatorInitialSessionDispatchEnvelope(
                exact,
                record.ClaimOperationId.Span,
                record.SessionId.Span,
                MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record));
        }

        internal byte[] ExactInboundDpe2(
            byte[]? recipient = null,
            byte[]? operation = null) => Dpe2Codec.Encode(new Dpe2Record(
                Network,
                Bytes(32, 0x81),
                RemoteDevice,
                recipient ?? LocalDevice,
                operation ?? Bytes(32, 0x82),
                new Dtr2Record(
                    Network, Bytes(32, 0x83), 0, 1, 1, 0, 1, 1,
                    Dtr2BraidMessage.None()),
                Dpe2Ciphertext.Import(Bytes(4112, 0x84))));

        internal void EnqueueInbound(
            byte[] exactInner,
            VerifiedMessagingRecipientDeposit? recipient = null)
        {
            using var dao = Sealer.Seal(
                RemoteLocal, recipient ?? LocalRecipient, exactInner);
            Mailbox.Durable.Add(MailboxEnvelope(dao.Canonical.Span, 1));
        }

        internal VerifiedMessagingRecipientDeposit RecipientForLocalDevice(
            ReadOnlySpan<byte> deviceId) =>
            VerifiedMessagingRecipientDeposit.CreateForTests(
                Scope, LocalDepositSelector, Network, LocalAccount, 1, 1,
                deviceId, 1, Bytes(32, 0x43), ScalarMult.Base(SealingPrivate),
                Now + 3_600);

        internal VerifiedMessagingRecipientDeposit RemoteRecipient(
            ulong deviceGeneration) =>
            VerifiedMessagingRecipientDeposit.CreateForTests(
                Scope, RecipientSelector, Network, RemoteAccount, 1, 1,
                RemoteDevice, deviceGeneration, Bytes(32, 0x43),
                ScalarMult.Base(SealingPrivate), Now + 3_600);

        internal MailboxRetrievedEnvelope MailboxEnvelope(
            ReadOnlySpan<byte> exactDao1,
            ulong cursor)
        {
            var dao = ApplicationCoreCodec.DecodeDao1(exactDao1);
            return new MailboxRetrievedEnvelope
            {
                Cursor = cursor,
                Envelope = new MailboxEncryptedEnvelope
                {
                    Epoch = Mailbox.Route.Epoch,
                    MailboxId = Mailbox.Route.MailboxId,
                    PlacementId = Mailbox.Route.PlacementId,
                    OperationId = MessagingDao1Crypto.DeriveMailboxOperationId(
                        dao.DepositOperationId.Span),
                    DeduplicationDigest = SHA256.HashData(exactDao1),
                    CreatedAtUnixSeconds = Now,
                    ExpiresAtUnixSeconds = Now + 600,
                    Ciphertext = exactDao1.ToArray(),
                },
            };
        }

        private MailboxCredentialSelector Selector(MailboxCredentialScopeKind kind, byte marker) =>
            new(Scope, kind, Bytes(32, marker), Bytes(32, 0x6f));

        public void Dispose()
        {
            Sealer.Dispose();
            Opener.Dispose();
        }
    }

    private sealed class FakeMailbox : IPrivacyRoutedMessagingMailboxClient
    {
        internal readonly List<MailboxEncryptedEnvelope> Stored = [];
        internal readonly List<MailboxRetrievedEnvelope> Durable = [];
        internal readonly List<MailboxAcknowledgement> Acknowledged = [];
        internal readonly List<byte[]> AckOperationIds = [];
        internal Exception? StoreFailure { get; set; }
        internal int RetrieveCalls { get; private set; }
        internal MailboxReplicaDisposition StoreDisposition { get; set; } =
            MailboxReplicaDisposition.Stored;
        internal ScopedMailboxResolvedRoute Route { get; } = new(
            1,
            Now + 3_600,
            new BlindedMailboxId(Bytes(32, 0xb1)),
            new BlindedPlacementId(Bytes(32, 0xb2)),
            Bytes(32, 0xb3),
            Bytes(32, 0xb4),
            new MailboxCredentialReplicaPair(
                Bytes(32, 0xb5), Bytes(32, 0xb6),
                Bytes(32, 0xb7), Bytes(32, 0xb8)));

        public ValueTask<ScopedMailboxResolvedRoute> ReadRouteAsync(
            MailboxCredentialSelector selector,
            CancellationToken cancellationToken) => ValueTask.FromResult(Route);

        public ValueTask<ClientMailboxStoreResult> StoreAsync(
            OutboxAccountScope scope,
            IMailboxOperationSigner signer,
            MailboxCredentialSelector selector,
            MailboxEncryptedEnvelope envelope,
            CancellationToken cancellationToken)
        {
            if (StoreFailure is { } failure) throw failure;
            _ = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
            Stored.Add(envelope);
            return ValueTask.FromResult(new ClientMailboxStoreResult(
                1, StoreDisposition, true, Bytes(32, 0xc1)));
        }

        public ValueTask<ClientMailboxRetrieveResult> RetrieveAsync(
            OutboxAccountScope scope,
            IMailboxOperationSigner signer,
            MailboxCredentialSelector selector,
            ushort maximumItems,
            CancellationToken cancellationToken)
        {
            RetrieveCalls++;
            return ValueTask.FromResult(new ClientMailboxRetrieveResult(
                    Durable.LastOrDefault()?.Cursor ?? 0,
                    false,
                    ReadOnlyMemory<byte>.Empty,
                    Durable.ToArray()));
        }

        public ValueTask<IReadOnlyList<MailboxRetrievedEnvelope>> ReadDurableInboxAsync(
            MailboxCredentialSelector selector,
            CancellationToken cancellationToken) => ValueTask.FromResult<IReadOnlyList<MailboxRetrievedEnvelope>>(
                Durable.ToArray());

        public ValueTask<ClientMailboxAckResult> AcknowledgeAsync(
            OutboxAccountScope scope,
            IMailboxOperationSigner signer,
            MailboxCredentialSelector selector,
            ReadOnlyMemory<byte> operationId,
            bool isFinalPage,
            ReadOnlyMemory<byte> continuationToken,
            IReadOnlyList<MailboxAcknowledgement> acknowledgements,
            CancellationToken cancellationToken)
        {
            if (operationId.Length != MailboxClientLimits.OperationIdLength ||
                operationId.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException("The acknowledgement operation ID is not canonical.");
            AckOperationIds.Add(operationId.ToArray());
            Acknowledged.AddRange(acknowledgements);
            return ValueTask.FromResult(new ClientMailboxAckResult(
                false, acknowledgements.Count));
        }
    }

    private sealed class FakeSigner : IMailboxOperationSigner
    {
        public SessionId SessionId => default;
        public byte[] GetEd25519PublicKey() => Bytes(32, 0xd1);
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> canonicalPresentationSigningBytes) => Bytes(64, 0xd2);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static Dph2Record Dph2(
        byte[] initiatorAccount,
        byte[] initiatorDevice,
        byte[] responderAccount,
        byte[] responderDevice,
        byte[] claimOperation) => new(
            Bytes(16, 0x11),
            initiatorAccount,
            initiatorDevice,
            1,
            Bytes(38, 0x91),
            responderAccount,
            responderDevice,
            1,
            Bytes(32, 0x92),
            claimOperation,
            Bytes(32, 0x93),
            0,
            Bytes(32, 0x94),
            Bytes(32, 0x95),
            Dph2SelectedPrekey.OneTime(
                Bytes(32, 0x96), Bytes(32, 0x97), Bytes(32, 0x98)),
            Bytes(1088, 0x99),
            Bytes(32, 0x9a),
            Bytes(24, 0x9b),
            Dph2InitialCiphertext.Import(Bytes(4112, 0x9c)));

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();
}
