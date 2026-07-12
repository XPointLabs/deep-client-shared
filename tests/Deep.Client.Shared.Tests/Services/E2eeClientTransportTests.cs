using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Sodium;

namespace Deep.Client.Shared.Tests.Services;

public sealed class E2eeClientTransportTests
{
    private const string AlicePhrase = "amber anchor april arrow atom aurora autumn badge bamboo beacon berry blade";
    private const string BobPhrase = "cactus canyon cedar circle cloud comet coral crystal dawn delta dune ember";
    private const string CharliePhrase = "fabric feather fern flame forest frost galaxy garden glacier grove harbor hazel";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-10T10:00:00Z");
    private static readonly ConversationId GroupId = ConversationId.Parse("03" + new string('c', 64));
    private static readonly TimeSpan ConcurrencyTimeout = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task DirectSend_FansOutRecipientAndSenderCopiesWithoutPlaintextOuterFields()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        var attachment = CreateAttachment();
        var messageId = new MessageId("semantic-message-id");
        var message = new OutboundMessageEnvelope(
            aliceIdentity.SessionId,
            bobIdentity.SessionId,
            "private-body-marker-49152",
            [attachment],
            Now,
            Now.AddHours(2),
            messageId,
            new MessageReply(new MessageId("private-reply-id"), bobIdentity.SessionId, "private reply quote"));

        await alice.SendAsync(message);

        var sent = raw.SentSnapshot();
        Assert.Equal([bobIdentity.SessionId, aliceIdentity.SessionId], sent.Select(static item => item.Recipient));
        Assert.All(sent, item =>
        {
            Assert.StartsWith(E2eeClientTransport.WireBodyPrefix, item.Body, StringComparison.Ordinal);
            Assert.Empty(item.Attachments);
            Assert.Null(item.ReplyTo);
            Assert.Null(item.Reaction);
            Assert.NotEqual(messageId, item.Id);
            Assert.DoesNotContain(message.Body, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(attachment.FileName, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(attachment.RemoteUri!.OriginalString, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(attachment.EncryptionKeyBase64!, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(message.ReplyTo!.Body, item.Body, StringComparison.Ordinal);
        });

        var restoredOutgoing = Assert.Single(await alice.ReceiveAsync(aliceIdentity.SessionId));
        Assert.Equal(aliceIdentity.SessionId, restoredOutgoing.Sender);
        Assert.Equal(bobIdentity.SessionId, restoredOutgoing.Recipient);
        Assert.Equal(messageId, restoredOutgoing.Id);
        Assert.Equal(message.Body, restoredOutgoing.Body);
        Assert.Equal(message.ReplyTo, restoredOutgoing.ReplyTo);
        Assert.Equal(attachment, Assert.Single(restoredOutgoing.Attachments));

        var incoming = Assert.Single(await bob.ReceiveAsync(bobIdentity.SessionId));
        Assert.Equal(bobIdentity.SessionId, incoming.Recipient);
        Assert.Equal(messageId, incoming.Id);
        Assert.Equal(message.Body, incoming.Body);
        Assert.Equal(0, raw.StandardReceiveCalls);
        Assert.True(raw.LastAuthenticationVerified);

        const string reactionMarker = "private-reaction-marker";
        await alice.SendAsync(message with
        {
            Id = new MessageId("reaction-id"),
            Body = string.Empty,
            Attachments = [],
            ReplyTo = null,
            Reaction = new MessageReactionUpdate(messageId, reactionMarker, Remove: false)
        });
        Assert.All(raw.SentSnapshot().Skip(2), item =>
        {
            Assert.Null(item.Reaction);
            Assert.DoesNotContain(reactionMarker, item.Body, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task GroupFanout_UsesOnlyPersonalInboxesAndGroupStateRoundTripsAuthenticatedSender()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        using var charlieIdentity = new SessionIdentityProvider(CharliePhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        var group = CreateGroup(aliceIdentity.SessionId, bobIdentity.SessionId, charlieIdentity.SessionId) with
        {
            CreatedBy = charlieIdentity.SessionId,
            Revision = 23,
            IsKicked = true
        };

        await alice.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            new MessageId("group-message-1"),
            GroupId,
            aliceIdentity.SessionId,
            "group secret marker",
            [],
            Now,
            null,
            NotifyRecipients: [bobIdentity.SessionId, charlieIdentity.SessionId, bobIdentity.SessionId]));
        await alice.PublishGroupStateAsync(group, Now, [bobIdentity.SessionId]);

        var sent = raw.SentSnapshot();
        var groupMessageCopies = sent.Take(3).ToArray();
        Assert.Equal(
            new[] { bobIdentity.SessionId, charlieIdentity.SessionId, aliceIdentity.SessionId }
                .OrderBy(static recipient => recipient.Value),
            groupMessageCopies.Select(static item => item.Recipient).OrderBy(static recipient => recipient.Value));
        Assert.All(groupMessageCopies, item =>
        {
            Assert.DoesNotContain(GroupId.Value, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain("group secret marker", item.Body, StringComparison.Ordinal);
            Assert.Empty(item.Attachments);
            Assert.Null(item.ReplyTo);
            Assert.Null(item.Reaction);
        });

        var groupStateCopies = sent.Skip(3).ToArray();
        Assert.Equal(
            new[] { bobIdentity.SessionId, charlieIdentity.SessionId, aliceIdentity.SessionId }
                .OrderBy(static recipient => recipient.Value),
            groupStateCopies.Select(static item => item.Recipient).OrderBy(static recipient => recipient.Value));
        Assert.All(groupStateCopies, item =>
        {
            Assert.DoesNotContain(GroupId.Value, item.Body, StringComparison.Ordinal);
            Assert.DoesNotContain(group.Name, item.Body, StringComparison.Ordinal);
        });

        var inboundMessage = Assert.Single(await bob.ReceiveGroupMessagesAsync(GroupId));
        Assert.Equal(GroupId, inboundMessage.GroupId);
        Assert.Equal("group secret marker", inboundMessage.Body);

        var inboundState = Assert.Single(await bob.ReceiveGroupStatesAsync(bobIdentity.SessionId));
        Assert.Equal(aliceIdentity.SessionId, inboundState.Sender);
        Assert.Equal(group.Id, inboundState.Group.Id);
        Assert.Equal(group.Name, inboundState.Group.Name);
        Assert.Equal(group.CreatedBy, inboundState.Group.CreatedBy);
        Assert.Equal(group.CreatedAt, inboundState.Group.CreatedAt);
        Assert.Equal(group.Revision, inboundState.Group.Revision);
        Assert.Equal(group.IsDestroyed, inboundState.Group.IsDestroyed);
        Assert.Equal(group.IsKicked, inboundState.Group.IsKicked);
        Assert.Equal(group.Members, inboundState.Group.Members);
        Assert.False(string.IsNullOrWhiteSpace(inboundState.ServerHash));
    }

    [Fact]
    public async Task GroupFanout_IsBoundedConcurrentAndRetryUsesStableWireIds()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        var raw = new AuthenticatedRawTransport
        {
            SendDelay = TimeSpan.FromMilliseconds(20)
        };
        using var alice = CreateTransport(raw, () => AlicePhrase);
        var recipients = Enumerable.Range(0, 31)
            .Select(_ => SessionId.CreateNew())
            .ToArray();
        var envelope = new OutboundGroupMessageEnvelope(
            new MessageId("bounded-fanout-message"),
            GroupId,
            aliceIdentity.SessionId,
            "bounded",
            [],
            Now,
            null,
            NotifyRecipients: recipients);

        await alice.SendGroupMessageAsync(envelope);
        var firstAttempt = raw.SentSnapshot();
        await alice.SendGroupMessageAsync(envelope);
        var allAttempts = raw.SentSnapshot();
        var secondAttempt = allAttempts.Skip(firstAttempt.Count).ToArray();

        Assert.Equal(recipients.Length + 1, firstAttempt.Count);
        Assert.InRange(raw.MaxConcurrentSends, 2, 8);
        Assert.Equal(
            firstAttempt.ToDictionary(static copy => copy.Recipient, static copy => copy.Id),
            secondAttempt.ToDictionary(static copy => copy.Recipient, static copy => copy.Id));
    }

    [Fact]
    public async Task RepeatedGroupStatePublishUsesStableOuterIdsForStorageIdempotency()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        var group = CreateGroup(aliceIdentity.SessionId, bobIdentity.SessionId, aliceIdentity.SessionId);

        await alice.PublishGroupStateAsync(group, Now, [bobIdentity.SessionId]);
        var first = raw.SentSnapshot();
        await alice.PublishGroupStateAsync(group, Now, [bobIdentity.SessionId]);
        var second = raw.SentSnapshot().Skip(first.Count).ToArray();

        Assert.Equal(first.Count, second.Length);
        var secondByRecipient = second.ToDictionary(static item => item.Recipient);
        Assert.All(first, item => Assert.Equal(item.Id, secondByRecipient[item.Recipient].Id));
        Assert.All(first, static item => Assert.NotNull(item.Id));
    }

    [Fact]
    public async Task GroupReceive_RejectsRawSenderThatDoesNotMatchAuthenticatedSemanticSender()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        using var charlieIdentity = new SessionIdentityProvider(CharliePhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);

        await alice.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            new MessageId("sender-binding"),
            GroupId,
            aliceIdentity.SessionId,
            "bound sender",
            [],
            Now,
            null,
            NotifyRecipients: [bobIdentity.SessionId]));
        var valid = Assert.Single(raw.TakeInbox(bobIdentity.SessionId));
        raw.Enqueue(valid with
        {
            Sender = charlieIdentity.SessionId,
            ServerHash = "mismatched-group-sender"
        });

        var received = await bob.ReceiveGroupMessagesAsync(GroupId);

        Assert.Empty(received);
    }

    [Fact]
    public async Task MixedInbox_DemultiplexesInOrderWithoutAdditionalFetches()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        var group = CreateGroup(aliceIdentity.SessionId, bobIdentity.SessionId, aliceIdentity.SessionId);

        await alice.SendAsync(CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "direct-1", "first"));
        await alice.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            new MessageId("group-1"), GroupId, aliceIdentity.SessionId, "middle", [], Now, null,
            NotifyRecipients: [bobIdentity.SessionId]));
        await alice.SendAsync(CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "direct-2", "second"));
        await alice.PublishGroupStateAsync(group, Now, [bobIdentity.SessionId]);

        var states = await bob.ReceiveGroupStatesAsync(bobIdentity.SessionId);
        var directs = await bob.ReceiveAsync(bobIdentity.SessionId);
        var groupMessages = await bob.ReceiveGroupMessagesAsync(GroupId);

        Assert.Single(states);
        Assert.Equal(["direct-1", "direct-2"], directs.Select(static item => item.Id.Value));
        Assert.Equal("group-1", Assert.Single(groupMessages).Id.Value);
        Assert.Equal(1, raw.AuthenticatedReceiveCount(bobIdentity.SessionId));
    }

    [Fact]
    public async Task Receive_SkipsPlaintextMalformedOuterAndTamperedEntriesButContinuesBatch()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        await alice.SendAsync(CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "valid-id", "valid body"));
        var valid = Assert.Single(raw.TakeInbox(bobIdentity.SessionId));

        raw.Enqueue(valid with { Body = "plaintext fallback", ServerHash = "plaintext" });
        raw.Enqueue(valid with { Body = TamperWireBody(valid.Body), ServerHash = "tampered" });
        raw.Enqueue(valid with { Attachments = [CreateAttachment()], ServerHash = "outer-fields" });
        raw.Enqueue(valid);

        var received = await bob.ReceiveAsync(bobIdentity.SessionId);

        Assert.Equal("valid-id", Assert.Single(received).Id.Value);
    }

    [Fact]
    public async Task Replay_SameDigestIsIgnoredAndDifferentDigestForLogicalIdIsRejected()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        var message = CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "replay-id", "first body");

        await alice.SendAsync(message);
        var exactWireCopy = Assert.Single(raw.SentSnapshot(), item => item.Recipient == bobIdentity.SessionId);
        raw.Enqueue(AuthenticatedRawTransport.ToInbound(exactWireCopy, "same-digest-copy"));
        await alice.SendAsync(message with { Body = "different body" });

        var received = await bob.ReceiveAsync(bobIdentity.SessionId);

        var accepted = Assert.Single(received);
        Assert.Equal("first body", accepted.Body);
        Assert.Equal("replay-id", accepted.Id.Value);
    }

    [Fact]
    public async Task ConcurrentReceivers_ShareOneAuthenticatedFetchWithoutLossOrRace()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var alice = CreateTransport(raw, () => AlicePhrase);
        using var bob = CreateTransport(raw, () => BobPhrase);
        var group = CreateGroup(aliceIdentity.SessionId, bobIdentity.SessionId, aliceIdentity.SessionId);

        await alice.SendAsync(CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "direct", "direct"));
        await alice.SendGroupMessageAsync(new OutboundGroupMessageEnvelope(
            new MessageId("group"), GroupId, aliceIdentity.SessionId, "group", [], Now, null,
            NotifyRecipients: [bobIdentity.SessionId]));
        await alice.PublishGroupStateAsync(group, Now, [bobIdentity.SessionId]);

        var directTask = bob.ReceiveAsync(bobIdentity.SessionId);
        var stateTask = bob.ReceiveGroupStatesAsync(bobIdentity.SessionId);
        var groupTask = bob.ReceiveGroupMessagesAsync(GroupId);
        await Task.WhenAll(directTask, stateTask, groupTask);

        Assert.Single(await directTask);
        Assert.Single(await stateTask);
        Assert.Single(await groupTask);
        Assert.Equal(1, raw.AuthenticatedReceiveCount(bobIdentity.SessionId));
        Assert.Equal(1, raw.MaxConcurrentAuthenticatedReceives);
    }

    [Fact]
    public async Task BlockedReceive_DoesNotBlockSendGroupSyncOrIdentityRefresh()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var phrase = AlicePhrase;
        var raw = new AuthenticatedRawTransport(blockAuthenticatedReceives: true);
        var transport = CreateTransport(raw, () => phrase);
        var receiveTask = transport.ReceiveAsync(aliceIdentity.SessionId);
        var concurrentOperations = new List<Task>();
        SessionIdentityProvider? receivingIdentity = null;

        try
        {
            await raw.WaitForAuthenticatedReceiveAsync().WaitAsync(ConcurrencyTimeout);
            receivingIdentity = Assert.IsType<SessionIdentityProvider>(raw.LastIdentity);

            var sendTask = transport.SendAsync(
                CreateDirect(aliceIdentity.SessionId, bobIdentity.SessionId, "parallel-direct", "body"));
            concurrentOperations.Add(sendTask);
            await sendTask.WaitAsync(ConcurrencyTimeout);

            var groupSyncTask = transport.PublishGroupStateAsync(
                CreateGroup(aliceIdentity.SessionId, bobIdentity.SessionId, aliceIdentity.SessionId),
                Now,
                [bobIdentity.SessionId]);
            concurrentOperations.Add(groupSyncTask);
            await groupSyncTask.WaitAsync(ConcurrencyTimeout);

            phrase = BobPhrase;
            var refreshedSendTask = transport.SendAsync(
                CreateDirect(bobIdentity.SessionId, aliceIdentity.SessionId, "refreshed-direct", "body"));
            concurrentOperations.Add(refreshedSendTask);
            await refreshedSendTask.WaitAsync(ConcurrencyTimeout);

            Assert.Equal(6, raw.SentSnapshot().Count);
            Assert.NotEmpty(receivingIdentity.SignDetached("lease-still-active"u8));
        }
        finally
        {
            raw.ReleaseAuthenticatedReceive();
            await Task.WhenAll(concurrentOperations.Append(receiveTask)).WaitAsync(ConcurrencyTimeout);
            transport.Dispose();
        }

        Assert.NotNull(receivingIdentity);
        Assert.Throws<ObjectDisposedException>(() => receivingIdentity!.SignDetached("lease-released"u8));
    }

    [Fact]
    public async Task Dispose_DuringBlockedReceiveReturnsAndDefersIdentityZeroization()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        var raw = new AuthenticatedRawTransport(blockAuthenticatedReceives: true);
        var transport = CreateTransport(raw, () => AlicePhrase);
        var receiveTask = transport.ReceiveAsync(aliceIdentity.SessionId);
        Task? disposeTask = null;
        SessionIdentityProvider? receivingIdentity = null;

        try
        {
            await raw.WaitForAuthenticatedReceiveAsync().WaitAsync(ConcurrencyTimeout);
            receivingIdentity = Assert.IsType<SessionIdentityProvider>(raw.LastIdentity);

            disposeTask = Task.Run(transport.Dispose);
            await disposeTask.WaitAsync(ConcurrencyTimeout);

            Assert.NotEmpty(receivingIdentity.SignDetached("dispose-lease-active"u8));
        }
        finally
        {
            raw.ReleaseAuthenticatedReceive();
            await receiveTask.WaitAsync(ConcurrencyTimeout);
            if (disposeTask is not null)
            {
                await disposeTask.WaitAsync(ConcurrencyTimeout);
            }

            transport.Dispose();
        }

        Assert.NotNull(receivingIdentity);
        Assert.Throws<ObjectDisposedException>(() => receivingIdentity!.SignDetached("dispose-lease-released"u8));
    }

    [Fact]
    public async Task PhraseAndAccountMismatch_FailsBeforeRawTransportUse()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var raw = new AuthenticatedRawTransport();
        using var transport = CreateTransport(raw, () => AlicePhrase);

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.SendAsync(
            CreateDirect(bobIdentity.SessionId, aliceIdentity.SessionId, "wrong-sender", "body")));
        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.ReceiveAsync(bobIdentity.SessionId));

        Assert.Empty(raw.SentSnapshot());
        Assert.Equal(0, raw.AuthenticatedReceiveCount(aliceIdentity.SessionId));
        Assert.Equal(0, raw.StandardReceiveCalls);
    }

    [Fact]
    public async Task PhraseChange_DisposesPriorCachedIdentity()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        using var bobIdentity = new SessionIdentityProvider(BobPhrase);
        var phrase = AlicePhrase;
        var raw = new AuthenticatedRawTransport();
        using var transport = CreateTransport(raw, () => phrase);

        Assert.Empty(await transport.ReceiveAsync(aliceIdentity.SessionId));
        var priorIdentity = Assert.IsType<SessionIdentityProvider>(raw.LastIdentity);
        phrase = BobPhrase;
        Assert.Empty(await transport.ReceiveAsync(bobIdentity.SessionId));

        Assert.Throws<ObjectDisposedException>(() => priorIdentity.SignDetached("probe"u8));
    }

    [Fact]
    public async Task Receive_FailsClosedWhenRawTransportLacksAuthenticatedInboxContract()
    {
        using var aliceIdentity = new SessionIdentityProvider(AlicePhrase);
        var raw = new UnauthenticatedRawTransport();
        using var transport = new E2eeClientTransport(
            raw,
            _ => Task.FromResult<string?>(AlicePhrase),
            new FrozenClock(Now),
            new InMemorySessionStore());

        await Assert.ThrowsAsync<InvalidOperationException>(() => transport.ReceiveAsync(aliceIdentity.SessionId));
        Assert.Equal(0, raw.ReceiveCalls);
    }

    private static E2eeClientTransport CreateTransport(
        AuthenticatedRawTransport raw,
        Func<string> phraseProvider) =>
        new(
            raw,
            _ => Task.FromResult<string?>(phraseProvider()),
            new FrozenClock(Now),
            new InMemorySessionStore());

    private static OutboundMessageEnvelope CreateDirect(
        SessionId sender,
        SessionId recipient,
        string id,
        string body) =>
        new(sender, recipient, body, [], Now, null, new MessageId(id));

    private static Group CreateGroup(SessionId alice, SessionId bob, SessionId creator) =>
        new(
            GroupId,
            "Encrypted team state",
            creator,
            Now.AddDays(-5),
            [
                new GroupMember(alice, GroupMemberRole.Admin, Now.AddDays(-5)),
                new GroupMember(bob, GroupMemberRole.Standard, Now.AddDays(-2), IsPendingRemoval: true)
            ],
            IsDestroyed: false,
            IsKicked: false,
            Revision: 9);

    private static AttachmentMetadata CreateAttachment() => new(
        "attachment-private-id",
        "private-filename.pdf",
        "application/pdf",
        42,
        new Uri("https://files.example.test/private-uri"),
        Convert.ToBase64String(Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray()),
        Convert.ToBase64String(Enumerable.Range(32, 32).Select(static value => (byte)value).ToArray()));

    private static string TamperWireBody(string body)
    {
        var payload = body[E2eeClientTransport.WireBodyPrefix.Length..]
            .Replace('-', '+')
            .Replace('_', '/');
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');
        var bytes = Convert.FromBase64String(payload);
        bytes[^1] ^= 1;
        return E2eeClientTransport.WireBodyPrefix + Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed class AuthenticatedRawTransport : ISessionMessageTransport, IAuthenticatedInboxTransport
    {
        private readonly bool blockAuthenticatedReceives;
        private readonly object gate = new();
        private readonly List<OutboundMessageEnvelope> sent = [];
        private readonly Dictionary<SessionId, Queue<InboundMessageEnvelope>> inboxes = [];
        private readonly Dictionary<SessionId, int> authenticatedReceiveCounts = [];
        private readonly TaskCompletionSource<bool> authenticatedReceiveStarted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> authenticatedReceiveRelease =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int nextHash;
        private int activeSends;
        private int maxConcurrentSends;
        private int activeAuthenticatedReceives;
        private int maxConcurrentAuthenticatedReceives;

        public AuthenticatedRawTransport(bool blockAuthenticatedReceives = false)
        {
            this.blockAuthenticatedReceives = blockAuthenticatedReceives;
        }

        public int StandardReceiveCalls { get; private set; }

        public TimeSpan SendDelay { get; init; }

        public int MaxConcurrentSends => maxConcurrentSends;

        public int MaxConcurrentAuthenticatedReceives => maxConcurrentAuthenticatedReceives;

        public bool LastAuthenticationVerified { get; private set; }

        public SessionIdentityProvider? LastIdentity { get; private set; }

        public async Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
        {
            var active = Interlocked.Increment(ref activeSends);
            UpdateMaximum(ref maxConcurrentSends, active);
            try
            {
                if (SendDelay > TimeSpan.Zero)
                {
                    await Task.Delay(SendDelay, cancellationToken);
                }

                lock (gate)
                {
                    sent.Add(envelope);
                    EnqueueCore(ToInbound(envelope, $"wire-{++nextHash}"));
                }
            }
            finally
            {
                Interlocked.Decrement(ref activeSends);
            }
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default)
        {
            StandardReceiveCalls++;
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        }

        public async Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default)
        {
            var active = Interlocked.Increment(ref activeAuthenticatedReceives);
            UpdateMaximum(ref maxConcurrentAuthenticatedReceives, active);
            try
            {
                await Task.Yield();
                cancellationToken.ThrowIfCancellationRequested();
                const long timestamp = 1_789_000_000_000;
                var canonical = Encoding.UTF8.GetBytes("retrieve0" + timestamp);
                var signature = identity.SignDetached(canonical);
                LastAuthenticationVerified = PublicKeyAuth.VerifyDetached(
                    signature,
                    canonical,
                    identity.GetEd25519PublicKey());
                LastIdentity = identity;
                authenticatedReceiveStarted.TrySetResult(true);
                if (blockAuthenticatedReceives)
                {
                    await authenticatedReceiveRelease.Task.WaitAsync(cancellationToken);
                }

                lock (gate)
                {
                    authenticatedReceiveCounts[identity.SessionId] = AuthenticatedReceiveCount(identity.SessionId) + 1;
                    if (!inboxes.TryGetValue(identity.SessionId, out var queue))
                    {
                        return [];
                    }

                    var values = queue.ToArray();
                    queue.Clear();
                    return values;
                }
            }
            finally
            {
                Interlocked.Decrement(ref activeAuthenticatedReceives);
            }
        }

        public Task WaitForAuthenticatedReceiveAsync() => authenticatedReceiveStarted.Task;

        public void ReleaseAuthenticatedReceive() => authenticatedReceiveRelease.TrySetResult(true);

        public IReadOnlyList<OutboundMessageEnvelope> SentSnapshot()
        {
            lock (gate)
            {
                return sent.ToArray();
            }
        }

        public IReadOnlyList<InboundMessageEnvelope> TakeInbox(SessionId recipient)
        {
            lock (gate)
            {
                if (!inboxes.TryGetValue(recipient, out var queue))
                {
                    return [];
                }

                var values = queue.ToArray();
                queue.Clear();
                return values;
            }
        }

        public void Enqueue(InboundMessageEnvelope envelope)
        {
            lock (gate)
            {
                EnqueueCore(envelope);
            }
        }

        public int AuthenticatedReceiveCount(SessionId recipient)
        {
            lock (gate)
            {
                return authenticatedReceiveCounts.GetValueOrDefault(recipient);
            }
        }

        public static InboundMessageEnvelope ToInbound(OutboundMessageEnvelope envelope, string serverHash) =>
            new(
                envelope.Id ?? MessageId.NewId(),
                envelope.Sender,
                envelope.Recipient,
                envelope.Body,
                envelope.Attachments,
                envelope.CreatedAt,
                envelope.ExpiresAt,
                serverHash,
                envelope.ReplyTo,
                envelope.Reaction);

        private void EnqueueCore(InboundMessageEnvelope envelope)
        {
            if (!inboxes.TryGetValue(envelope.Recipient, out var queue))
            {
                queue = new Queue<InboundMessageEnvelope>();
                inboxes.Add(envelope.Recipient, queue);
            }

            queue.Enqueue(envelope);
        }

        private static void UpdateMaximum(ref int location, int value)
        {
            var current = Volatile.Read(ref location);
            while (value > current)
            {
                var observed = Interlocked.CompareExchange(ref location, value, current);
                if (observed == current)
                {
                    return;
                }

                current = observed;
            }
        }
    }

    private sealed class UnauthenticatedRawTransport : ISessionMessageTransport
    {
        public int ReceiveCalls { get; private set; }

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default)
        {
            ReceiveCalls++;
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
        }
    }
}
