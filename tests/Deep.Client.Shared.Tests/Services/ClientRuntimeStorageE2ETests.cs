using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Client.Shared.Tests.MessagingV1;

namespace Deep.Client.Shared.Tests.Services;

/// <summary>
/// Runtime-level E2E coverage for the authoritative MSG-01 storage boundary. Each client gets
/// its own authenticated session endpoint while the harness shares only opaque network queues.
/// Raw direct/group sends are rejected, so every delivered copy must pass through MSG-01.
/// </summary>
public sealed class ClientRuntimeStorageE2ETests
{
    [Fact]
    public async Task AuthoritativeMsg01Runtime_RoundTripsOneToOneMessage()
    {
        using var harness = new SharedMsg01TestBus();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice MSG01");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob MSG01");
        var body = $"client-msg01-e2e-{Guid.NewGuid():N}";

        var sent = await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId, bobAccount.SessionId, body);
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Contains(received, message =>
            message.Body == body &&
            message.Sender == aliceAccount.SessionId &&
            message.Recipient == bobAccount.SessionId &&
            !string.IsNullOrWhiteSpace(message.ServerHash));
        Assert.Equal(1, harness.PreparedBatchCount);
        Assert.Equal(1, harness.DispatchedCount);
        Assert.Equal(0, harness.RawSendCount);
    }

    [Fact]
    public async Task AuthoritativeMsg01Runtime_RoundTripsRepliesAndReactions()
    {
        using var harness = new SharedMsg01TestBus();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Reply MSG01");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Reply MSG01");
        var original = await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            $"reply-root-{Guid.NewGuid():N}");
        var bobOriginal = Assert.Single(
            await bob.Messages.ReceiveAsync(bobAccount.SessionId));
        var reply = await bob.Messages.SendOneToOneAsync(
            bobAccount.SessionId,
            aliceAccount.SessionId,
            "reply-msg01",
            replyToMessageId: bobOriginal.Id);
        var aliceReply = Assert.Single(
            await alice.Messages.ReceiveAsync(aliceAccount.SessionId));
        await alice.Messages.SendReactionOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            aliceReply.Id,
            "👍");
        await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var bobReply = await ((IMessageRepository)bob.Store).GetAsync(reply.Id);

        Assert.Equal(original.Id, aliceReply.ReplyTo?.MessageId);
        Assert.Equal(original.Body, aliceReply.ReplyTo?.Body);
        Assert.Contains(bobReply!.ReactionItems, reaction =>
            reaction.Emoji == "👍" && reaction.Reactor == aliceAccount.SessionId);
        Assert.Equal(0, harness.RawSendCount);
    }

    [Fact]
    public async Task AuthoritativeMsg01Runtime_RoundTripsAttachmentMetadata()
    {
        using var harness = new SharedMsg01TestBus();
        var attachments = new InMemoryAttachmentTransport();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Attachment MSG01");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Attachment MSG01");
        var attachmentBytes = System.Text.Encoding.UTF8.GetBytes(
            $"attachment-msg01-{Guid.NewGuid():N}");
        await using var upload = new MemoryStream(attachmentBytes);
        var attachment = await attachments.UploadAsync(
            new AttachmentFileUpload("proof.txt", "text/plain", upload));

        await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "attachment over MSG01",
            [attachment]);
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var message = Assert.Single(received, item => item.Body == "attachment over MSG01");
        var receivedAttachment = Assert.Single(message.Attachments);
        var download = await attachments.DownloadAsync(receivedAttachment);

        Assert.True(receivedAttachment.IsUploaded);
        Assert.True(receivedAttachment.HasEncryptedPointer);
        Assert.Equal("proof.txt", download.FileName);
        Assert.Equal("text/plain", download.ContentType);
        Assert.Equal(attachmentBytes, download.Content);
        Assert.Equal(0, harness.RawSendCount);
    }

    [Fact]
    public async Task AuthoritativeMsg01Runtime_RoundTripsExplicitVoiceAttachmentMetadataToRecipient()
    {
        using var harness = new SharedMsg01TestBus();
        var attachments = new InMemoryAttachmentTransport();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Voice MSG01");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Voice MSG01");
        await using var upload = new MemoryStream(Enumerable.Repeat((byte)0x56, 4_096).ToArray());
        var voice = await attachments.UploadAsync(new AttachmentFileUpload(
            "voice-message.wav",
            "audio/wav",
            upload,
            Duration: TimeSpan.FromSeconds(4),
            Kind: AttachmentKind.VoiceMessage));

        await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "[Голосовое сообщение]",
            [voice]);
        var message = Assert.Single(await bob.Messages.ReceiveAsync(bobAccount.SessionId));
        var receivedVoice = Assert.Single(message.Attachments);

        Assert.Equal(voice, receivedVoice);
        Assert.Equal(AttachmentKind.VoiceMessage, receivedVoice.Kind);
        Assert.Equal(TimeSpan.FromSeconds(4), receivedVoice.Duration);
        Assert.Equal("audio/wav", receivedVoice.ContentType);
        Assert.Equal(0, harness.RawSendCount);
    }

    [Fact]
    public async Task AuthoritativeMsg01Runtime_SyncsGroupStateMessagesRepliesAndReactions()
    {
        using var harness = new SharedMsg01TestBus();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Group MSG01");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Group MSG01");
        var group = await alice.Conversations.CreateGroupScaffoldAsync(
            aliceAccount.SessionId,
            $"msg01-group-{Guid.NewGuid():N}",
            [bobAccount.SessionId]);

        var bobGroupUpdates = await bob.Conversations.ReceiveGroupUpdatesAsync(
            bobAccount.SessionId);
        var bobGroup = await bob.Conversations.GetGroupAsync(group.Id);
        Assert.Contains(bobGroupUpdates, update => update.Id == group.Id);
        Assert.NotNull(bobGroup);
        Assert.Equal(group.Name, bobGroup!.Name);

        var body = $"group-msg01-message-{Guid.NewGuid():N}";
        var sent = await alice.Messages.SendGroupAsync(
            aliceAccount.SessionId, group.Id, body);
        var received = await bob.Messages.ReceiveGroupAsync(
            bobAccount.SessionId, group.Id);
        var bobOriginal = received.Single(message => message.Body == body);
        var reply = await bob.Messages.SendGroupAsync(
            bobAccount.SessionId,
            group.Id,
            "group-msg01-reply",
            replyToMessageId: bobOriginal.Id);
        var aliceReply = Assert.Single(
            await alice.Messages.ReceiveGroupAsync(aliceAccount.SessionId, group.Id));
        await alice.Messages.SendGroupReactionAsync(
            aliceAccount.SessionId, group.Id, aliceReply.Id, "❤️");
        await bob.Messages.ReceiveGroupAsync(bobAccount.SessionId, group.Id);
        var bobReply = await ((IMessageRepository)bob.Store).GetAsync(reply.Id);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Equal(sent.Id, aliceReply.ReplyTo?.MessageId);
        Assert.Contains(bobReply!.ReactionItems, reaction =>
            reaction.Emoji == "❤️" && reaction.Reactor == aliceAccount.SessionId);
        Assert.Equal(0, harness.RawSendCount);
    }

    private static ClientRuntime CreateRuntime(SharedMsg01TestBus harness) =>
        CreateRuntimeCore(harness, new VerifiedMsg01Endpoint(harness));

    private static ClientRuntime CreateRuntimeCore(
        SharedMsg01TestBus harness,
        VerifiedMsg01Endpoint endpoint) => new(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults with
            {
                MetadataPrivateTransportRequired = false
            },
            new SystemClock(),
            endpoint,
            groupSyncTransport: endpoint,
            requireE2eeTransport: true,
            mailboxDeliveryPolicy: new DirectP2pMailboxDeliveryPolicy(),
            messagingV1Persistence: harness.NewMessagingPersistence());

    private sealed class SharedMsg01TestBus : IDisposable
    {
        internal readonly ConcurrentDictionary<string, ConcurrentQueue<InboundMessageEnvelope>>
            inboxes = new(StringComparer.Ordinal);
        internal readonly ConcurrentDictionary<string, ConcurrentQueue<InboundGroupStateEnvelope>>
            groupStates = new(StringComparer.Ordinal);
        internal readonly ConcurrentDictionary<string, ConcurrentQueue<InboundGroupMessageEnvelope>>
            groupMessages = new(StringComparer.Ordinal);
        private readonly ConcurrentBag<string> messagingPaths = [];
        internal int preparedBatchCount;
        internal int dispatchedCount;
        internal int rawSendCount;

        public int PreparedBatchCount => Volatile.Read(ref preparedBatchCount);
        public int DispatchedCount => Volatile.Read(ref dispatchedCount);
        public int RawSendCount => Volatile.Read(ref rawSendCount);

        internal MessagingV1PersistenceOptions NewMessagingPersistence()
        {
            var path = Path.Combine(
                Path.GetTempPath(),
                $"deep-msg01-storage-{Guid.NewGuid():N}.db");
            messagingPaths.Add(path);
            return new MessagingV1PersistenceOptions(path, new string('A', 64));
        }

        public void Dispose()
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var path in messagingPaths)
            {
                foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
                {
                    if (File.Exists(candidate))
                    {
                        File.Delete(candidate);
                    }
                }
            }
        }

    }

    private sealed class VerifiedMsg01Endpoint :
        IDirectP2pSessionMessageTransport,
        IAuthenticatedInboxTransport,
        IGroupSyncTransport,
        IMsg01AuthenticatedEvidenceSource,
        IAccountGenerationLifecycle
    {
        private readonly SharedMsg01TestBus bus;
        private readonly Msg01VerifiedSessionAuthority evidenceAuthority =
            MessagingV1Fixture.CreateEvidenceAuthority();
        private readonly ConcurrentDictionary<string, byte[]> inboundRatchetHeads =
            new(StringComparer.Ordinal);
        private SessionId? localAccount;
        private long sequence;

        internal VerifiedMsg01Endpoint(SharedMsg01TestBus bus) =>
            this.bus = bus;

        public Msg01VerifiedSessionAuthority EvidenceAuthority => evidenceAuthority;

        public void Resume(SessionId account) => localAccount = account;

        public Task StopAsync(
            SessionId account,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (localAccount == account)
            {
                localAccount = null;
            }
            return Task.CompletedTask;
        }

        public ValueTask<SessionId> GetLocalAccountAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return localAccount is { } account
                ? ValueTask.FromResult(account)
                : ValueTask.FromException<SessionId>(
                    new InvalidOperationException("No test MSG-01 account is active."));
        }

        public ValueTask<DirectoryHeadHash32> ResolveFanoutTargetAsync(
            Msg01ResolveFanoutTargetRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(DirectoryHeadHash32.FromBytes(Hash(
                "directory",
                Convert.ToHexString(request.Target.AccountId.ToArray()))));
        }

        public ValueTask<Msg01PreparedTransportAttempt> PrepareAttemptAsync(
            Msg01PrepareAttemptRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref bus.preparedBatchCount);
            return ValueTask.FromResult(new Msg01PreparedTransportAttempt(
                DirectoryHeadHash32.FromBytes(Hash(
                    "directory",
                    Convert.ToHexString(request.Target.AccountId.ToArray()))),
                RatchetStateHash32.FromBytes(Hash(
                    "ratchet-before",
                    Convert.ToHexString(request.Target.DeviceId.ToArray()))),
                RatchetTransitionHash32.FromBytes(Hash(
                    "ratchet-after",
                    Convert.ToHexString(request.AttemptId.ToArray()))),
                request.CanonicalPayload.Span));
        }

        public ValueTask<Msg01AuthenticatedDispatchResult> DispatchPreparedAsync(
            Msg01DispatchEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DispatchPayload(request);
            Interlocked.Increment(ref bus.dispatchedCount);
            return ValueTask.FromResult(AuthenticatedResult(
                request,
                MessageEvidencePurpose.TargetOutcome));
        }

        public ValueTask<Msg01AuthenticatedDispatchResult> ReconcilePreparedAsync(
            Msg01DispatchEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(AuthenticatedResult(
                request,
                MessageEvidencePurpose.AttemptReconciliation));
        }

        public ValueTask<Msg01AuthenticatedInboundResult> GetInboundResultAsync(
            Msg01InboundEvidenceRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ratchetKey = Convert.ToHexString(request.Claim.Key.AuthorAccountId.ToArray())
                + Convert.ToHexString(request.Claim.Key.ConversationId.ToArray());
            byte[] beforeBytes;
            byte[] sealedState;
            byte[] afterBytes;
            lock (inboundRatchetHeads)
            {
                beforeBytes = inboundRatchetHeads.TryGetValue(ratchetKey, out var current)
                    ? current.ToArray()
                    : Hash("inbound-before", ratchetKey);
                sealedState = Hash(
                    "inbound-state",
                    Convert.ToHexString(beforeBytes)
                    + Convert.ToHexString(request.CanonicalEnvelope.Span));
                afterBytes = SHA256.HashData(sealedState);
                inboundRatchetHeads[ratchetKey] = afterBytes.ToArray();
            }
            var before = RatchetStateHash32.FromBytes(beforeBytes);
            var after = RatchetStateHash32.FromBytes(afterBytes);
            var replay = checked((ulong)Interlocked.Increment(ref sequence));
            var nonce = Hash(
                "inbound-nonce",
                replay.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var sessionId = RatchetSessionId32.FromBytes(Hash("session", ratchetKey));
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
                ratchetSessionId: sessionId);
            return ValueTask.FromResult(new Msg01AuthenticatedInboundResult(
                sessionId,
                before,
                after,
                sealedState,
                replay,
                nonce,
                MessagingV1Fixture.Authenticate(
                    context,
                    SHA256.HashData(request.CanonicalEnvelope.Span))));
        }

        public ValueTask AcknowledgeReceiptAsync(
            ReadOnlyMemory<byte> authenticatedReceipt,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.CompletedTask;
        }

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref bus.rawSendCount);
            return Task.FromException(
                new InvalidOperationException("MSG-01 forbids raw direct dispatch."));
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(
                Drain(bus.inboxes, recipient.Value));
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            ReceiveAsync(identity.SessionId, cancellationToken);

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default) =>
            RawGroupDispatch();

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            RawGroupDispatch();

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>(
                Drain(bus.groupStates, member.Value));
        }

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>(
                Drain(bus.groupMessages, groupId.Value));
        }

        private Task RawGroupDispatch()
        {
            Interlocked.Increment(ref bus.rawSendCount);
            return Task.FromException(
                new InvalidOperationException("MSG-01 forbids raw group dispatch."));
        }

        private void DispatchPayload(Msg01DispatchEvidenceRequest request)
        {
            switch (request.Kind)
            {
                case MessagePayloadKind.DirectMessage:
                {
                    var payload = Deserialize<DirectWirePayload>(request.Ciphertext.Span);
                    RequireTarget(payload.Recipient, request.Target);
                    bus.inboxes.GetOrAdd(payload.Recipient.Value, static _ => new())
                        .Enqueue(new InboundMessageEnvelope(
                            payload.Id,
                            payload.Sender,
                            payload.Recipient,
                            payload.Body,
                            payload.Attachments,
                            payload.CreatedAt,
                            payload.ExpiresAt,
                            NextServerHash(),
                            payload.ReplyTo,
                            payload.Reaction));
                    break;
                }
                case MessagePayloadKind.GroupState:
                {
                    var payload = Deserialize<GroupStateWirePayload>(request.Ciphertext.Span);
                    var recipient = payload.Group.Members
                        .Select(static item => item.SessionId)
                        .Single(candidate => TargetAccount(candidate).Equals(request.Target.AccountId));
                    bus.groupStates.GetOrAdd(recipient.Value, static _ => new())
                        .Enqueue(new InboundGroupStateEnvelope(
                            payload.Group,
                            payload.UpdatedAt,
                            NextServerHash(),
                            payload.Group.CreatedBy));
                    break;
                }
                case MessagePayloadKind.GroupMessage:
                {
                    var payload = Deserialize<GroupMessageWirePayload>(request.Ciphertext.Span);
                    bus.groupMessages.GetOrAdd(payload.GroupId.Value, static _ => new())
                        .Enqueue(new InboundGroupMessageEnvelope(
                            payload.Id,
                            payload.GroupId,
                            payload.Sender,
                            payload.Body,
                            payload.Attachments,
                            payload.CreatedAt,
                            payload.ExpiresAt,
                            NextServerHash(),
                            payload.ReplyTo,
                            payload.Reaction));
                    break;
                }
                case MessagePayloadKind.GroupMailboxRoutes:
                    break;
                default:
                    throw new InvalidDataException("Unsupported MSG-01 test payload kind.");
            }
        }

        private Msg01AuthenticatedDispatchResult AuthenticatedResult(
            Msg01DispatchEvidenceRequest request,
            MessageEvidencePurpose purpose)
        {
            var replay = checked((ulong)Interlocked.Increment(ref sequence));
            var nonce = Hash(
                "dispatch-nonce",
                replay.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var context = new MessageCapabilityTrustedContext(
                purpose,
                request.Scope,
                request.ClaimKey,
                request.Target,
                request.AttemptId,
                VerifiedTargetOutcomeKind.Accepted,
                targetOperationId: request.OperationId,
                bindingHash: request.BindingHash,
                requestHash: request.RequestHash.ToArray(),
                envelopeHash: request.EnvelopeHash.ToArray(),
                ratchetBeforeHash: request.RatchetBeforeHash.ToArray(),
                ratchetAfterHash: request.RatchetAfterHash.ToArray(),
                replayCounter: replay,
                replayNonce: nonce);
            return new Msg01AuthenticatedDispatchResult(
                VerifiedTargetOutcomeKind.Accepted,
                false,
                replay,
                nonce,
                MessagingV1Fixture.Authenticate(
                    context,
                    SHA256.HashData(request.Ciphertext.Span)));
        }

        private void RequireTarget(SessionId recipient, RecipientDeviceTarget target)
        {
            if (!TargetAccount(recipient).Equals(target.AccountId))
                throw new InvalidDataException("MSG-01 payload was dispatched to another target.");
        }

        private string NextServerHash() =>
            $"msg01-{Interlocked.Increment(ref sequence):x16}";

        private static MessagingAccountId32 TargetAccount(SessionId account) =>
            MessagingAccountId32.FromBytes(Hash("account", account.Value));

        private static T Deserialize<T>(ReadOnlySpan<byte> payload) =>
            JsonSerializer.Deserialize<T>(payload)
            ?? throw new InvalidDataException("MSG-01 test payload is malformed.");

        private static IReadOnlyList<T> Drain<T>(
            ConcurrentDictionary<string, ConcurrentQueue<T>> queues,
            string key)
        {
            if (!queues.TryGetValue(key, out var queue))
                return [];
            var result = new List<T>();
            while (queue.TryDequeue(out var item))
                result.Add(item);
            return result;
        }

        private static byte[] Hash(string domain, string value)
        {
            var input = Encoding.UTF8.GetBytes($"Deep/MSG-01/{domain}/v1\0{value}");
            try
            {
                return SHA256.HashData(input);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        private sealed record DirectWirePayload(
            MessageId Id,
            SessionId Sender,
            SessionId Recipient,
            string Body,
            IReadOnlyList<AttachmentMetadata> Attachments,
            DateTimeOffset CreatedAt,
            DateTimeOffset? ExpiresAt,
            MessageReply? ReplyTo,
            MessageReactionUpdate? Reaction);

        private sealed record GroupMessageWirePayload(
            MessageId Id,
            ConversationId GroupId,
            SessionId Sender,
            string Body,
            IReadOnlyList<AttachmentMetadata> Attachments,
            DateTimeOffset CreatedAt,
            DateTimeOffset? ExpiresAt,
            MessageReply? ReplyTo,
            MessageReactionUpdate? Reaction);

        private sealed record GroupStateWirePayload(Group Group, DateTimeOffset UpdatedAt);
    }

    private sealed class InMemoryAttachmentTransport : IAttachmentFileTransport
    {
        private readonly ConcurrentDictionary<string, AttachmentFileDownload> files = new();
        public bool IsEnabled => true;

        public async Task<AttachmentMetadata> UploadAsync(
            AttachmentFileUpload upload,
            CancellationToken cancellationToken = default)
        {
            using var buffer = new MemoryStream();
            await upload.Content.CopyToAsync(buffer, cancellationToken);
            var id = Guid.NewGuid().ToString("N");
            var content = buffer.ToArray();
            files[id] = new AttachmentFileDownload(
                upload.FileName, upload.ContentType, content);
            return new AttachmentMetadata(
                id,
                upload.FileName,
                upload.ContentType,
                content.Length,
                new Uri($"https://attachments.invalid/{id}"),
                Convert.ToBase64String(Enumerable.Repeat((byte)0x51, 32).ToArray()),
                Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(content)),
                upload.Width,
                upload.Height,
                upload.Duration,
                upload.IsDocument,
                upload.Kind);
        }

        public Task<AttachmentFileDownload> DownloadAsync(
            AttachmentMetadata metadata,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(files[metadata.AttachmentId]);

        public async Task<AttachmentFileDownloadInfo> DownloadToAsync(
            AttachmentMetadata metadata,
            Stream destination,
            CancellationToken cancellationToken = default)
        {
            var file = files[metadata.AttachmentId];
            await destination.WriteAsync(file.Content, cancellationToken);
            return new AttachmentFileDownloadInfo(file.FileName, file.ContentType);
        }
    }
}
