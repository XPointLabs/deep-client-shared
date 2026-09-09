using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class Msg01MessageServiceIntegrationTests
{
    [Fact]
    public async Task ConcurrentGroupPreparationAndRecoveryCannotAdvanceSessionTwice()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-ratchet-gate-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var statePath = Path.Combine(directory, "alice.db");
        const string cipherKey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        var network = new AuthenticatedLoopbackTransport
        {
            PreparationDelay = TimeSpan.FromMilliseconds(10)
        };
        try
        {
            using var runtime = CreateRuntime(statePath, cipherKey, network);
            var alice = await runtime.Accounts.RegisterAsync("Alice");
            var bob = SessionId.CreateNew();
            network.SetLocalAccount(alice.SessionId);
            var now = DateTimeOffset.UtcNow;
            var sends = Enumerable.Range(0, 16).Select(index =>
            {
                var group = new Group(
                    ConversationId.CreateGroupV2(),
                    $"Concurrent {index}",
                    alice.SessionId,
                    now,
                    [
                        new GroupMember(alice.SessionId, GroupMemberRole.Admin, now),
                        new GroupMember(bob, GroupMemberRole.Standard, now)
                    ],
                    Revision: 1);
                return runtime.GroupSyncTransport.PublishGroupStateAsync(group, now, [bob]);
            });

            await Task.WhenAll(sends);

            Assert.Equal(1, network.MaximumConcurrentPreparation);
            Assert.Equal(16, network.PrepareKinds.Count(static kind =>
                kind == MessagePayloadKind.GroupState));
            Assert.Equal(16, network.DispatchKinds.Count(static kind =>
                kind == MessagePayloadKind.GroupState));
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(statePath + ".msg01");
            TryDeleteDirectory(directory);
        }
    }

    [Fact]
    public async Task GroupStateAndMessageUseMsg01TransactionBoundaryWithoutRawGroupDispatch()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-group-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var statePath = Path.Combine(directory, "alice.db");
        const string cipherKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        var network = new AuthenticatedLoopbackTransport();
        SessionAccount alice;
        var bob = SessionId.CreateNew();
        var group = default(Group)!;
        var groupMessage = new MessageId("msg01-group-transaction");
        try
        {
            using (var runtime = CreateRuntime(statePath, cipherKey, network))
            {
                alice = await runtime.Accounts.RegisterAsync("Alice");
                network.SetLocalAccount(alice.SessionId);
                group = new Group(
                    ConversationId.CreateGroupV2(),
                    "MSG-01 group",
                    alice.SessionId,
                    DateTimeOffset.UtcNow.AddMinutes(-1),
                    [
                        new GroupMember(alice.SessionId, GroupMemberRole.Admin, DateTimeOffset.UtcNow.AddMinutes(-1)),
                        new GroupMember(bob, GroupMemberRole.Standard, DateTimeOffset.UtcNow)
                    ],
                    Revision: 1);

                await runtime.GroupSyncTransport.PublishGroupStateAsync(
                    group, DateTimeOffset.UtcNow, [bob]);
                await runtime.GroupSyncTransport.SendGroupMessageAsync(
                    new OutboundGroupMessageEnvelope(
                        groupMessage, group.Id, alice.SessionId, "canonical group payload", [],
                        DateTimeOffset.UtcNow, null, NotifyRecipients: [bob]));
            }

            Assert.Equal(
                [MessagePayloadKind.GroupState, MessagePayloadKind.GroupMessage],
                network.DispatchKinds);
            Assert.Equal(0, network.RawGroupDispatchCount);

            var scope = Scope(alice.SessionId);
            var msgKey = DeriveMsgKey(cipherKey);
            try
            {
                await using var store = SqliteMessageStoreBootstrap.Open(
                    new SqliteMessageStoreOptions(
                        statePath + ".msg01", msgKey, scope,
                        MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false));
                var state = await store.ReadAsync(new SemanticClaimKey(
                    scope.LocalAccountId,
                    ConversationId32.FromBytes(Hash("conversation", group.Id.Value)),
                    SemanticMessageId32.FromBytes(Hash("semantic", "group-state:1"))), default);
                var message = await store.ReadAsync(new SemanticClaimKey(
                    scope.LocalAccountId,
                    ConversationId32.FromBytes(Hash("conversation", group.Id.Value)),
                    SemanticMessageId32.FromBytes(Hash("semantic", groupMessage.Value))), default);
                Assert.Equal(LogicalOutboxState.Accepted, state!.State);
                Assert.Equal(LogicalOutboxState.Accepted, message!.State);
                Assert.DoesNotContain(bob.Value, Encoding.UTF8.GetString(message.CanonicalPayload),
                    StringComparison.Ordinal);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(msgKey);
            }
        }
        finally
        {
            await SqliteMessageStoreBootstrap.ResetAsync(statePath + ".msg01");
            if (File.Exists(statePath)) File.Delete(statePath);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    [Fact]
    public async Task ProductionMessageServiceSendAndReceiveAreAuthoritativeMsg01Transactions()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"deep-msg-service-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var alicePath = Path.Combine(directory, "alice.db");
        var bobPath = Path.Combine(directory, "bob.db");
        const string cipherKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var network = new AuthenticatedLoopbackTransport();
        SessionAccount alice;
        SessionAccount bob;
        Message sent;
        try
        {
            using (var aliceRuntime = CreateRuntime(alicePath, cipherKey, network))
            using (var bobRuntime = CreateRuntime(bobPath, cipherKey, network))
            {
                Assert.Equal("Msg01AuthoritativeTransport", aliceRuntime.MessageTransport.GetType().Name);
                Assert.Same(aliceRuntime.MessageTransport, aliceRuntime.GroupSyncTransport);
                alice = await aliceRuntime.Accounts.RegisterAsync("Alice");
                bob = await bobRuntime.Accounts.RegisterAsync("Bob");

                sent = await aliceRuntime.Messages.SendOneToOneAsync(
                    alice.SessionId, bob.SessionId, "MSG-01 authoritative hello");
                Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);

                var received = await bobRuntime.Messages.ReceiveAsync(bob.SessionId);
                var delivered = Assert.Single(received);
                Assert.Equal(sent.Id, delivered.Id);
                Assert.Equal("MSG-01 authoritative hello", delivered.Body);
                Assert.Empty(await bobRuntime.Messages.ReceiveAsync(bob.SessionId));
            }

            var aliceScope = Scope(alice.SessionId);
            var bobScope = Scope(bob.SessionId);
            var msgKey = DeriveMsgKey(cipherKey);
            try
            {
                await using (var aliceStore = SqliteMessageStoreBootstrap.Open(
                    new SqliteMessageStoreOptions(
                        alicePath + ".msg01", msgKey, aliceScope,
                        MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false)))
                {
                    var outbound = await aliceStore.ReadAsync(
                        new SemanticClaimKey(
                            aliceScope.LocalAccountId,
                            ConversationId32.FromBytes(Hash("conversation", ConversationId.ForOneToOne(bob.SessionId).Value)),
                            SemanticMessageId32.FromBytes(Hash("semantic", sent.Id.Value))),
                        default);
                    Assert.NotNull(outbound);
                    Assert.Equal(LogicalOutboxState.Accepted, outbound!.State);
                    Assert.Single(outbound.Targets);
                    Assert.All(outbound.Targets, target =>
                        Assert.Equal(LogicalTargetState.Accepted, target.State));
                }

                await using (var bobStore = SqliteMessageStoreBootstrap.Open(
                    new SqliteMessageStoreOptions(
                        bobPath + ".msg01", msgKey, bobScope,
                        MessagingV1Fixture.CreateEvidenceAuthority(), allowCreate: false)))
                {
                    var inbound = await bobStore.ReadInboxAsync(
                        new SemanticClaimKey(
                            MessagingAccountId32.FromBytes(Hash("account", alice.SessionId.Value)),
                            ConversationId32.FromBytes(Hash("conversation", ConversationId.ForOneToOne(alice.SessionId).Value)),
                            SemanticMessageId32.FromBytes(Hash("semantic", sent.Id.Value))),
                        default);
                    Assert.NotNull(inbound);
                    Assert.Equal(MessageEventHash32.FromBytes(SHA256.HashData(inbound!.CanonicalEvent)), inbound.EventHash);
                    Assert.Empty(await bobStore.ClaimPendingReceiptsAsync(
                        MessageRecoveryOwnerId16.FromBytes(Hash("test-recovery", "bob")[..16]),
                        DateTimeOffset.UtcNow,
                        MessagingV1Limits.MaxRecoveryBatch,
                        default));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(msgKey);
            }
        }
        finally
        {
            foreach (var path in new[] { alicePath, bobPath, alicePath + ".msg01", bobPath + ".msg01" })
            {
                await SqliteMessageStoreBootstrap.ResetAsync(path);
            }
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    private static ClientRuntime CreateRuntime(
        string path,
        string cipherKey,
        AuthenticatedLoopbackTransport network) =>
        new(
            new Deep.Client.Shared.Persistence.SqliteSessionStore(
                new Deep.Client.Shared.Persistence.SqliteSessionStoreOptions(path, cipherKey)),
            ClientFeatureFlags.ReleaseDefaults with { MetadataPrivateTransportRequired = false },
            new SystemClock(),
            network,
            requireE2eeTransport: true,
            mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
            messagingV1Persistence: new MessagingV1PersistenceOptions(path + ".msg01", cipherKey));

    private static MessageStoreScope Scope(SessionId account) => new(
        MessagingAccountId32.FromBytes(Hash("account", account.Value)),
        1,
        MessageStoreInstanceId32.FromBytes(Hash("store-instance", account.Value)));

    private static byte[] DeriveMsgKey(string cipherKey)
    {
        var input = Encoding.UTF8.GetBytes(cipherKey);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/MSG-01/sqlcipher-key-v1\0"u8);
            hash.AppendData(input);
            return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    private static byte[] Hash(string domain, string value)
    {
        var bytes = Encoding.UTF8.GetBytes($"Deep/MSG-01/{domain}/v1\0{value}");
        try { return SHA256.HashData(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { Directory.Delete(path, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed class AuthenticatedLoopbackTransport :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport,
        IGroupSyncTransport,
        IMsg01AuthenticatedEvidenceSource
    {
        private readonly Msg01VerifiedSessionAuthority evidenceAuthority =
            MessagingV1Fixture.CreateEvidenceAuthority();
        private readonly ConcurrentDictionary<string, ConcurrentQueue<InboundMessageEnvelope>> inboxes = new(StringComparer.Ordinal);
        private long sequence;
        private int rawGroupDispatchCount;
        private int activePreparations;
        private int maximumConcurrentPreparation;
        private SessionId? localAccount;
        private readonly ConcurrentQueue<MessagePayloadKind> dispatchKinds = new();
        private readonly ConcurrentQueue<MessagePayloadKind> prepareKinds = new();

        internal IReadOnlyList<MessagePayloadKind> DispatchKinds => dispatchKinds.ToArray();
        internal IReadOnlyList<MessagePayloadKind> PrepareKinds => prepareKinds.ToArray();
        internal int RawGroupDispatchCount => Volatile.Read(ref rawGroupDispatchCount);
        internal int MaximumConcurrentPreparation => Volatile.Read(ref maximumConcurrentPreparation);
        internal TimeSpan PreparationDelay { get; init; }
        internal void SetLocalAccount(SessionId account) => localAccount = account;

        public Msg01VerifiedSessionAuthority EvidenceAuthority => evidenceAuthority;

        public ValueTask<SessionId> GetLocalAccountAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return localAccount is { } account
                ? ValueTask.FromResult(account)
                : ValueTask.FromException<SessionId>(new InvalidOperationException("No test session is active."));
        }

        public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
            Msg01ResolveFanoutTargetRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(DirectoryHeadHash32.FromBytes(Hash(
                "directory", Convert.ToHexString(request.Target.AccountId.ToArray()))));
        }

        public async ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
            Msg01PrepareAttemptRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var active = Interlocked.Increment(ref activePreparations);
            UpdateMaximum(ref maximumConcurrentPreparation, active);
            prepareKinds.Enqueue(request.Kind);
            try
            {
                if (PreparationDelay > TimeSpan.Zero)
                    await Task.Delay(PreparationDelay, cancellationToken).ConfigureAwait(false);
                if (request.Kind == MessagePayloadKind.DirectMessage)
                    localAccount = JsonSerializer.Deserialize<DirectWirePayload>(request.CanonicalPayload.Span)!.Sender;
                return new Msg01PreparedTransportAttempt(
                    DirectoryHeadHash32.FromBytes(Hash("directory", Convert.ToHexString(request.Target.AccountId.ToArray()))),
                    RatchetStateHash32.FromBytes(Hash("ratchet-before", Convert.ToHexString(request.Target.DeviceId.ToArray()))),
                    RatchetTransitionHash32.FromBytes(Hash("ratchet-after", Convert.ToHexString(request.AttemptId.ToArray()))),
                    request.CanonicalPayload.Span);
            }
            finally
            {
                Interlocked.Decrement(ref activePreparations);
            }
        }

        public ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            dispatchKinds.Enqueue(request.Kind);
            if (request.Kind == MessagePayloadKind.DirectMessage)
            {
                var payload = JsonSerializer.Deserialize<DirectWirePayload>(request.Ciphertext.Span)!;
                var recipientTarget = MessagingAccountId32.FromBytes(Hash("account", payload.Recipient.Value));
                if (recipientTarget.Equals(request.Target.AccountId))
                    SendAsync(new OutboundMessageEnvelope(payload.Sender, payload.Recipient, payload.Body,
                        payload.Attachments, payload.CreatedAt, payload.ExpiresAt, payload.Id,
                        payload.ReplyTo, payload.Reaction), cancellationToken).GetAwaiter().GetResult();
            }
            return ValueTask.FromResult(AuthenticatedResult(
                request, MessageEvidencePurpose.TargetOutcome,
                VerifiedTargetOutcomeKind.Accepted));
        }

        public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
            Msg01DispatchEvidenceRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(AuthenticatedResult(
                request, MessageEvidencePurpose.AttemptReconciliation,
                VerifiedTargetOutcomeKind.Accepted));
        }

        public ValueTask AcknowledgeReceiptAsync(ReadOnlyMemory<byte> authenticatedReceipt, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return ValueTask.CompletedTask; }

        public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
            Msg01InboundEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var before = RatchetStateHash32.FromBytes(Hash("test-ratchet-before", "loopback"));
            var sealedState = Hash(
                "test-ratchet-state", Convert.ToHexString(request.CanonicalEnvelope.Span));
            var after = RatchetStateHash32.FromBytes(SHA256.HashData(sealedState));
            var replay = checked((ulong)Interlocked.Increment(ref sequence));
            var nonce = Hash("test-replay-nonce", replay.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var context = new MessageCapabilityTrustedContext(
                MessageEvidencePurpose.InboundMaterialization,
                request.Scope,
                request.Claim.Key,
                receiptId: request.ReceiptId,
                requestHash: SHA256.HashData(request.CanonicalEnvelope.Span),
                envelopeHash: request.Claim.EventHash.ToArray(),
                ratchetBeforeHash: before.ToArray(),
                ratchetAfterHash: after.ToArray(),
                replayCounter: replay,
                replayNonce: nonce,
                ratchetSessionId: RatchetSessionId32.FromBytes(Hash("test-ratchet-session", "loopback")));
            return ValueTask.FromResult(new Msg01AuthenticatedInboundResult(
                RatchetSessionId32.FromBytes(Hash("test-ratchet-session", "loopback")),
                before, after, sealedState, replay, nonce,
                MessagingV1Fixture.Authenticate(context, SHA256.HashData(request.CanonicalEnvelope.Span))));
        }

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var serverHash = Interlocked.Increment(ref sequence).ToString("x16");
            inboxes.GetOrAdd(envelope.Recipient.Value, static _ => new())
                .Enqueue(new InboundMessageEnvelope(
                    envelope.Id ?? MessageId.NewId(), envelope.Sender, envelope.Recipient,
                    envelope.Body, envelope.Attachments, envelope.CreatedAt, envelope.ExpiresAt,
                    serverHash, envelope.ReplyTo, envelope.Reaction));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient, CancellationToken cancellationToken = default) =>
            DrainAsync(recipient, cancellationToken);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity, CancellationToken cancellationToken = default) =>
            DrainAsync(identity.SessionId, cancellationToken);

        public Task PublishGroupStateAsync(Group group, DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref rawGroupDispatchCount);
            return Task.FromException(new InvalidOperationException("Raw group-state dispatch is forbidden."));
        }

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>([]);

        public Task SendGroupMessageAsync(OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref rawGroupDispatchCount);
            return Task.FromException(new InvalidOperationException("Raw group-message dispatch is forbidden."));
        }

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>([]);

        private Task<IReadOnlyList<InboundMessageEnvelope>> DrainAsync(
            SessionId recipient, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!inboxes.TryGetValue(recipient.Value, out var queue))
            {
                return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
            }
            var result = new List<InboundMessageEnvelope>();
            while (queue.TryDequeue(out var item)) result.Add(item);
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(result);
        }

        private Msg01AuthenticatedDispatchResult AuthenticatedResult(
            Msg01DispatchEvidenceRequest request, MessageEvidencePurpose purpose,
            VerifiedTargetOutcomeKind outcome)
        {
            var replay = checked((ulong)Interlocked.Increment(ref sequence));
            var nonce = Hash("dispatch-nonce", replay.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var context = new MessageCapabilityTrustedContext(purpose,
                request.Scope, request.ClaimKey, request.Target, request.AttemptId, outcome,
                targetOperationId: request.OperationId, bindingHash: request.BindingHash,
                requestHash: request.RequestHash.ToArray(), envelopeHash: request.EnvelopeHash.ToArray(),
                ratchetBeforeHash: request.RatchetBeforeHash.ToArray(), ratchetAfterHash: request.RatchetAfterHash.ToArray(),
                replayCounter: replay, replayNonce: nonce);
            var evidence = MessagingV1Fixture.Authenticate(context, SHA256.HashData(request.Ciphertext.Span));
            return new Msg01AuthenticatedDispatchResult(outcome, false, replay, nonce, evidence);
        }

        private static void UpdateMaximum(ref int location, int candidate)
        {
            var observed = Volatile.Read(ref location);
            while (candidate > observed)
            {
                var prior = Interlocked.CompareExchange(ref location, candidate, observed);
                if (prior == observed) return;
                observed = prior;
            }
        }

        private sealed record DirectWirePayload(MessageId Id, SessionId Sender, SessionId Recipient,
            string Body, IReadOnlyList<AttachmentMetadata> Attachments, DateTimeOffset CreatedAt,
            DateTimeOffset? ExpiresAt, MessageReply? ReplyTo, MessageReactionUpdate? Reaction);
    }
}
