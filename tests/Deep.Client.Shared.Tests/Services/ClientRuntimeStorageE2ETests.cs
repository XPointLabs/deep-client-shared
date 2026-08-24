using System.Collections.Concurrent;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

/// <summary>
/// Runtime-level E2E coverage for the authenticated MAU2 composition boundary. The harness is
/// deliberately not a direct-P2P transport and rejects raw SendAsync, so every delivered copy
/// must pass through one scoped authenticated batch before dispatch.
/// </summary>
public sealed class ClientRuntimeStorageE2ETests
{
    [Fact]
    public async Task AuthenticatedMau2Runtime_RoundTripsOneToOneMessage()
    {
        var harness = new AuthenticatedMau2RuntimeHarness();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice MAU2");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob MAU2");
        var body = $"client-mau2-e2e-{Guid.NewGuid():N}";

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
        Assert.Equal(2, harness.DispatchedCount);
        Assert.Equal(0, harness.RawSendCount);
    }

    [Fact]
    public async Task AuthenticatedMau2Runtime_RoundTripsRepliesAndReactions()
    {
        var harness = new AuthenticatedMau2RuntimeHarness();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Reply MAU2");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Reply MAU2");
        var original = await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            $"reply-root-{Guid.NewGuid():N}");
        var bobOriginal = Assert.Single(
            await bob.Messages.ReceiveAsync(bobAccount.SessionId));
        var reply = await bob.Messages.SendOneToOneAsync(
            bobAccount.SessionId,
            aliceAccount.SessionId,
            "reply-mau2",
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
    public async Task AuthenticatedMau2Runtime_RoundTripsAttachmentMetadata()
    {
        var harness = new AuthenticatedMau2RuntimeHarness();
        var attachments = new InMemoryAttachmentTransport();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Attachment MAU2");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Attachment MAU2");
        var attachmentBytes = System.Text.Encoding.UTF8.GetBytes(
            $"attachment-mau2-{Guid.NewGuid():N}");
        await using var upload = new MemoryStream(attachmentBytes);
        var attachment = await attachments.UploadAsync(
            new AttachmentFileUpload("proof.txt", "text/plain", upload));

        await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "attachment over MAU2",
            [attachment]);
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var message = Assert.Single(received, item => item.Body == "attachment over MAU2");
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
    public async Task AuthenticatedMau2Runtime_RoundTripsExplicitVoiceAttachmentMetadataToRecipient()
    {
        var harness = new AuthenticatedMau2RuntimeHarness();
        var attachments = new InMemoryAttachmentTransport();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Voice MAU2");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Voice MAU2");
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
    public async Task AuthenticatedMau2Runtime_SyncsGroupStateMessagesRepliesAndReactions()
    {
        var harness = new AuthenticatedMau2RuntimeHarness();
        using var alice = CreateRuntime(harness);
        using var bob = CreateRuntime(harness);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice Group MAU2");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob Group MAU2");
        var group = await alice.Conversations.CreateGroupScaffoldAsync(
            aliceAccount.SessionId,
            $"mau2-group-{Guid.NewGuid():N}",
            [bobAccount.SessionId]);

        var bobGroupUpdates = await bob.Conversations.ReceiveGroupUpdatesAsync(
            bobAccount.SessionId);
        var bobGroup = await bob.Conversations.GetGroupAsync(group.Id);
        Assert.Contains(bobGroupUpdates, update => update.Id == group.Id);
        Assert.NotNull(bobGroup);
        Assert.Equal(group.Name, bobGroup!.Name);

        var body = $"group-mau2-message-{Guid.NewGuid():N}";
        var sent = await alice.Messages.SendGroupAsync(
            aliceAccount.SessionId, group.Id, body);
        var received = await bob.Messages.ReceiveGroupAsync(
            bobAccount.SessionId, group.Id);
        var bobOriginal = received.Single(message => message.Body == body);
        var reply = await bob.Messages.SendGroupAsync(
            bobAccount.SessionId,
            group.Id,
            "group-mau2-reply",
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

    private static ClientRuntime CreateRuntime(AuthenticatedMau2RuntimeHarness harness) =>
        new(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            harness,
            requireE2eeTransport: true,
            mailboxDeliveryPolicy: harness.Policy);

    private sealed class AuthenticatedMau2RuntimeHarness :
        IAuthenticatedOpaqueMailboxTransport,
        IAuthenticatedInboxTransport,
        IMetadataPrivateSessionMessageTransport,
        IResumableMailboxIdentityAuthenticatedRawTransport
    {
        private readonly ConcurrentDictionary<string, ConcurrentQueue<InboundMessageEnvelope>>
            inboxes = new(StringComparer.Ordinal);
        private readonly VerifiedOfficialMailboxAuthority authority;
        private readonly MailboxCredentialSelector selector;
        private int preparedBatchCount;
        private int dispatchedCount;
        private int rawSendCount;

        public AuthenticatedMau2RuntimeHarness()
        {
            var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            var issuer = Enumerable.Repeat((byte)0x31, 32).ToArray();
            authority = new VerifiedOfficialMailboxAuthority(
                Enumerable.Repeat((byte)0x21, 16).ToArray(),
                1,
                [
                    Issuer(issuer, MailboxCapabilityDomain.Deposit, now),
                    Issuer(issuer, MailboxCapabilityDomain.Retrieve, now)
                ],
                requiresManagedEntitlement: false,
                static () => false,
                new EmptyRevocations(),
                TimeProvider.System);
            selector = new MailboxCredentialSelector(
                OutboxAccountScope.FromBytes(Enumerable.Repeat((byte)0x41, 32).ToArray()),
                MailboxCredentialScopeKind.Peer,
                Enumerable.Repeat((byte)0x42, 32).ToArray(),
                Enumerable.Repeat((byte)0x43, 32).ToArray());
            Policy = new AuthenticatedMau2MailboxDeliveryPolicy(
                MailboxInfrastructureOwnership.UserManaged,
                authority,
                _ => selector);
        }

        public IMailboxDeliveryPolicy Policy { get; }
        public int PreparedBatchCount => Volatile.Read(ref preparedBatchCount);
        public int DispatchedCount => Volatile.Read(ref dispatchedCount);
        public int RawSendCount => Volatile.Read(ref rawSendCount);
        public int InboxNamespace => unchecked((int)0x4d415532);
        public bool UsesMetadataPrivateTransport => true;

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
            PrepareScopedMailboxLogicalBatchAsync(
                IMailboxOperationSigner signer,
                MailboxLogicalSendBatch batch,
                IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
                CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.NotEmpty(targets);
            Assert.All(targets, target =>
            {
                Assert.Same(authority, target.Authority);
                Assert.Equal(signer.SessionId, target.Envelope.Sender);
                Assert.Equal(selector.ScopeId.ToArray(), target.Selector.ScopeId.ToArray());
            });
            Interlocked.Increment(ref preparedBatchCount);
            return Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>(
                targets.Select(target =>
                    (IPreparedMailboxAuthenticatedSend)new Prepared(this, target.Envelope))
                    .ToArray());
        }

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>
            TryResumeScopedMailboxBatchAsync(
                IMailboxOperationSigner signer,
                MailboxLogicalSendBatch batch,
                CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPreparedMailboxAuthenticatedSend>?>(null);

        public Task<IReadOnlyList<IPreparedMailboxAuthenticatedSend>>
            PrepareScopedMailboxBatchAsync(
                IMailboxOperationSigner signer,
                IReadOnlyList<MailboxAuthenticatedSendTarget> targets,
                CancellationToken cancellationToken = default) =>
            PrepareScopedMailboxLogicalBatchAsync(
                signer, Logical(targets), targets, cancellationToken);

        private static MailboxLogicalSendBatch Logical(
            IReadOnlyList<MailboxAuthenticatedSendTarget> targets) =>
            new(targets[0].Envelope.Id!.Value, MailboxDeliveryKind.Direct,
                targets.Select(target => new MailboxLogicalSendTarget(
                    target.Envelope.Id!.Value,
                    target.Selector,
                    target.Authority,
                    target.Envelope.Sender,
                    target.Envelope.Recipient)).ToArray());

        public Task SendPreparedMailboxAuthenticatedAsync(
            IPreparedMailboxAuthenticatedSend preparedSend,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var prepared = Assert.IsType<Prepared>(preparedSend);
            Assert.Same(this, prepared.Owner);
            Assert.Equal(0, Interlocked.Exchange(ref prepared.Dispatched, 1));
            var envelope = prepared.Envelope;
            var inbound = new InboundMessageEnvelope(
                envelope.Id ?? MessageId.NewId(),
                envelope.Sender,
                envelope.Recipient,
                envelope.Body,
                envelope.Attachments,
                envelope.CreatedAt,
                envelope.ExpiresAt,
                $"mau2-{Interlocked.Increment(ref dispatchedCount)}",
                envelope.ReplyTo,
                envelope.Reaction);
            inboxes.GetOrAdd(envelope.Recipient.Value, static _ => new())
                .Enqueue(inbound);
            return Task.CompletedTask;
        }

        public Task SendAsync(
            OutboundMessageEnvelope envelope,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref rawSendCount);
            throw new InvalidOperationException("Authenticated MAU2 forbids raw-send fallback.");
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromException<IReadOnlyList<InboundMessageEnvelope>>(
                new InvalidOperationException("Authenticated MAU2 requires the holder identity."));

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = new List<InboundMessageEnvelope>();
            if (inboxes.TryGetValue(identity.SessionId.Value, out var inbox))
                while (inbox.TryDequeue(out var envelope)) result.Add(envelope);
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(result);
        }

        public Task<OpaqueMailboxInboxPage> RetrieveOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer,
            OpaqueMailboxContinuation continuation,
            CancellationToken cancellationToken = default) =>
            Task.FromException<OpaqueMailboxInboxPage>(new NotSupportedException());

        public Task AcknowledgeOpaqueMailboxInboxAsync(
            IMailboxOperationSigner signer,
            string opaqueItemHandle,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        private static MailboxCapabilityIssuerAuthority Issuer(
            byte[] key,
            MailboxCapabilityDomain domain,
            ulong now) => new()
            {
                PublicKey = key,
                Domain = domain,
                AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                MinimumGeneration = 1,
                MaximumGeneration = 2,
                ValidFromUnixSeconds = now - 60,
                ValidUntilUnixSeconds = now + 3_600
            };

        private sealed class EmptyRevocations : IFreshMailboxCapabilityRevocationSource
        {
            public void ValidateFreshness() { }
            public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
        }

        private sealed class Prepared(
            AuthenticatedMau2RuntimeHarness owner,
            OutboundMessageEnvelope envelope) : IPreparedMailboxAuthenticatedSend
        {
            public AuthenticatedMau2RuntimeHarness Owner { get; } = owner;
            public OutboundMessageEnvelope Envelope { get; } = envelope;
            public int Dispatched;
        }
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
