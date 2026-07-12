using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class MessageFlowTests
{
    [Fact]
    public async Task RegisterSendReceiveOneToOneThroughStubbedBackend()
    {
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")), backend: backend);
        var bob = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:01Z")), backend: backend);

        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");

        var sent = await alice.Messages.SendOneToOneAsync(aliceAccount.SessionId, bobAccount.SessionId, "hello bob");
        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Single(received);
        Assert.Equal("hello bob", received[0].Body);
        Assert.Equal(aliceAccount.SessionId, received[0].Sender);
    }

    [Fact]
    public async Task InboxSync_CreatesConversationForPreviouslyUnknownSender()
    {
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(
            clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            backend: backend);
        var bob = ClientRuntime.CreateStubbed(
            clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:01Z")),
            backend: backend);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");
        await alice.Messages.SendOneToOneAsync(aliceAccount.SessionId, bobAccount.SessionId, "hello from unknown sender");

        var sync = await bob.Inbox.SynchronizeAsync();
        var conversations = await bob.Conversations.ListAsync();
        var contact = await ((IContactRepository)bob.Store).GetAsync(aliceAccount.SessionId);

        Assert.Equal(1, sync.DirectMessages);
        Assert.Contains(conversations, conversation => conversation.Id == ConversationId.ForOneToOne(aliceAccount.SessionId));
        Assert.NotNull(contact);
        Assert.False(contact!.IsApproved);
        Assert.False(contact.IsBlocked);
    }

    [Fact]
    public async Task InboxSync_DoesNotCreateEmptySelfConversation()
    {
        var runtime = ClientRuntime.CreateStubbed();
        await runtime.Accounts.RegisterAsync("Owner");

        await runtime.Inbox.SynchronizeAsync();

        Assert.Empty(await runtime.Conversations.ListAsync());
    }

    [Fact]
    public async Task OutgoingConversationApprovesContact()
    {
        var runtime = ClientRuntime.CreateStubbed();
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();

        await runtime.Messages.SendOneToOneAsync(sender.SessionId, recipient, "hello");
        var contact = await runtime.Conversations.GetContactAsync(recipient);

        Assert.NotNull(contact);
        Assert.True(contact!.IsApproved);
        Assert.True(contact.IsTrusted);
    }

    [Fact]
    public async Task BlockedContactCannotSendOrReceiveMessages()
    {
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(backend: backend);
        var bob = ClientRuntime.CreateStubbed(backend: backend);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");
        await bob.Conversations.SetContactBlockedAsync(aliceAccount.SessionId, true);
        await alice.Messages.SendOneToOneAsync(aliceAccount.SessionId, bobAccount.SessionId, "blocked inbound");

        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        Assert.Empty(received);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            bob.Messages.SendOneToOneAsync(bobAccount.SessionId, aliceAccount.SessionId, "blocked outbound"));
    }

    [Fact]
    public async Task RepliesAndReactionsRoundTripThroughMessageTransport()
    {
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(backend: backend);
        var bob = ClientRuntime.CreateStubbed(backend: backend);
        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");
        var original = await alice.Messages.SendOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "original");
        var bobOriginal = Assert.Single(await bob.Messages.ReceiveAsync(bobAccount.SessionId));

        var reply = await bob.Messages.SendOneToOneAsync(
            bobAccount.SessionId,
            aliceAccount.SessionId,
            "reply",
            replyToMessageId: bobOriginal.Id);
        var aliceReply = Assert.Single(await alice.Messages.ReceiveAsync(aliceAccount.SessionId));
        await alice.Messages.SendReactionOneToOneAsync(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            aliceReply.Id,
            "👍");
        await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var bobReply = await ((IMessageRepository)bob.Store).GetAsync(reply.Id);

        Assert.Equal(original.Id, aliceReply.ReplyTo?.MessageId);
        Assert.Equal("original", aliceReply.ReplyTo?.Body);
        var reaction = Assert.Single(bobReply!.ReactionItems);
        Assert.Equal("👍", reaction.Emoji);
        Assert.Equal(aliceAccount.SessionId, reaction.Reactor);
    }

    [Fact]
    public async Task SendReceiveToSelf_PreservesSingleOutgoingMessage()
    {
        var backend = new StubSessionBackend();
        var runtime = ClientRuntime.CreateStubbed(
            clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            backend: backend);
        var account = await runtime.Accounts.RegisterAsync("Notes");

        var sent = await runtime.Messages.SendOneToOneAsync(account.SessionId, account.SessionId, "remember this");
        var received = await runtime.Messages.ReceiveAsync(account.SessionId);
        var messages = await runtime.Messages.ListConversationMessagesAsync(sent.ConversationId);

        Assert.Empty(received);
        Assert.Collection(messages, message =>
        {
            Assert.Equal(sent.Id, message.Id);
            Assert.Equal(MessageDirection.Outgoing, message.Direction);
            Assert.Equal("remember this", message.Body);
        });
    }

    [Fact]
    public async Task QueueAndDispatchOneToOne_ExposeSendingBeforeNetworkCompletion()
    {
        var transport = new QueuedMessageTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();

        var pending = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, recipient, "optimistic");

        Assert.Equal(MessageDeliveryState.Sending, pending.DeliveryState);
        Assert.Equal(0, transport.SendCount);

        var sent = await runtime.Messages.DispatchOneToOneAsync(pending);

        Assert.Equal(MessageDeliveryState.Sent, sent.DeliveryState);
        Assert.Equal(1, transport.SendCount);
    }

    [Fact]
    public async Task DispatchOneToOne_MarksQueuedMessageFailedWhenTransportFails()
    {
        var transport = new QueuedMessageTransport { SendException = new HttpRequestException("offline") };
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, SessionId.CreateNew(), "retry me");

        await Assert.ThrowsAsync<HttpRequestException>(() => runtime.Messages.DispatchOneToOneAsync(pending));
        var stored = await ((IMessageRepository)runtime.Store).GetAsync(pending.Id);

        Assert.Equal(MessageDeliveryState.Failed, stored?.DeliveryState);
    }

    [Fact]
    public async Task DispatchPendingMessages_RetriesPersistedFailureAfterRestartCycle()
    {
        var transport = new QueuedMessageTransport { SendException = new HttpRequestException("offline") };
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            transport);
        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var pending = await runtime.Messages.QueueOneToOneAsync(sender.SessionId, SessionId.CreateNew(), "retry me");
        await Assert.ThrowsAsync<HttpRequestException>(() => runtime.Messages.DispatchOneToOneAsync(pending));
        transport.SendException = null;

        var dispatched = await runtime.Messages.DispatchPendingMessagesAsync(sender.SessionId);
        var stored = await ((IMessageRepository)runtime.Store).GetAsync(pending.Id);

        Assert.Equal(1, dispatched);
        Assert.Equal(2, transport.SendCount);
        Assert.Equal(MessageDeliveryState.Sent, stored?.DeliveryState);
    }

    [Fact]
    public async Task ReceiveAsync_RemovesLegacySelfEcho()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());
        var account = await runtime.Accounts.RegisterAsync("Notes");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(account.SessionId);
        var sent = new Message(
            MessageId.NewId(), conversation.Id, account.SessionId, account.SessionId, "legacy",
            MessageDirection.Outgoing, MessageDeliveryState.Sent, clock.UtcNow, []);
        var echo = sent with { Id = MessageId.NewId(), Direction = MessageDirection.Incoming };
        var store = (IMessageRepository)runtime.Store;
        await store.AppendAsync(sent);
        await store.AppendAsync(echo);

        var removed = await runtime.Messages.RepairSelfConversationAsync(account.SessionId, CancellationToken.None);
        var messages = await runtime.Messages.ListConversationMessagesAsync(conversation.Id);

        Assert.Equal(1, removed);
        Assert.Collection(messages, message => Assert.Equal(sent.Id, message.Id));
    }

    [Fact]
    public async Task ReceiveAsync_DoesNotReinsertLegacySelfEchoReturnedByTransport()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var transport = new QueuedMessageTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            transport);
        var account = await runtime.Accounts.RegisterAsync("Notes");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(account.SessionId);
        var sent = new Message(
            MessageId.NewId(), conversation.Id, account.SessionId, account.SessionId, "legacy",
            MessageDirection.Outgoing, MessageDeliveryState.Sent, clock.UtcNow, []);
        await ((IMessageRepository)runtime.Store).AppendAsync(sent);
        transport.Enqueue(new InboundMessageEnvelope(
            MessageId.NewId(), account.SessionId, account.SessionId, sent.Body, sent.Attachments,
            sent.CreatedAt, sent.ExpiresAt, "legacy-server-hash"));

        var received = await runtime.Messages.ReceiveAsync(account.SessionId);
        var stored = await runtime.Messages.ListConversationMessagesAsync(conversation.Id);

        Assert.Empty(received);
        Assert.Collection(stored, message => Assert.Equal(sent.Id, message.Id));
    }

    [Fact]
    public async Task ReceiveAsync_StoresUnseenSelfMessageFromAnotherDeviceAsOutgoing()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var transport = new QueuedMessageTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            transport);
        var account = await runtime.Accounts.RegisterAsync("Notes");
        transport.Enqueue(new InboundMessageEnvelope(
            MessageId.NewId(), account.SessionId, account.SessionId, "from another device", [],
            clock.UtcNow, null, "other-device-hash"));

        var received = await runtime.Messages.ReceiveAsync(account.SessionId);

        Assert.Collection(received, message => Assert.Equal(MessageDirection.Outgoing, message.Direction));
    }

    [Fact]
    public async Task CreateGroupScaffoldPersistsConversationAndAdmin()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var owner = await runtime.Accounts.RegisterAsync("Owner");
        var member = SessionId.CreateNew();

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner.SessionId, "Core team", [member]);
        var conversation = await ((IConversationRepository)runtime.Store).GetAsync(group.Id);

        Assert.StartsWith("03", group.Id.Value);
        Assert.True(group.HasAdmin(owner.SessionId));
        Assert.Equal(ConversationKind.GroupV2, conversation?.Kind);
    }

    [Fact]
    public async Task ListConversationMessages_ExcludesExpiredMessages()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var alice = await runtime.Accounts.RegisterAsync("Alice");
        var bob = SessionId.CreateNew();
        var sent = await runtime.Messages.SendOneToOneAsync(alice.SessionId, bob, "fresh");

        var expired = new Message(
            MessageId.NewId(),
            sent.ConversationId,
            alice.SessionId,
            bob,
            "expired",
            MessageDirection.Outgoing,
            MessageDeliveryState.Sent,
            clock.UtcNow.AddMinutes(-2),
            [],
            clock.UtcNow.AddMinutes(-1));

        await ((IMessageRepository)runtime.Store).AppendAsync(expired);

        var listed = await runtime.Messages.ListConversationMessagesAsync(sent.ConversationId);

        Assert.DoesNotContain(listed, item => item.Body == "expired");
        Assert.Contains(listed, item => item.Body == "fresh");
    }

    [Fact]
    public async Task ListRecentConversationMessages_ReturnsNewestMessagesInConversationOrder()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient);

        for (var index = 0; index < 5; index++)
        {
            await ((IMessageRepository)runtime.Store).AppendAsync(new Message(
                MessageId.NewId(),
                conversation.Id,
                sender.SessionId,
                recipient,
                $"message-{index}",
                MessageDirection.Outgoing,
                MessageDeliveryState.Sent,
                clock.UtcNow.AddSeconds(index),
                []));
        }

        var recent = await runtime.Messages.ListRecentConversationMessagesAsync(conversation.Id, 3);

        Assert.Equal(["message-2", "message-3", "message-4"], recent.Select(item => item.Body));
    }

    [Fact]
    public async Task ListConversationMessagesBefore_ReturnsPreviousPageInConversationOrder()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient);

        var messageIds = new List<MessageId>();
        for (var index = 0; index < 6; index++)
        {
            var messageId = MessageId.NewId();
            messageIds.Add(messageId);
            await ((IMessageRepository)runtime.Store).AppendAsync(new Message(
                messageId,
                conversation.Id,
                sender.SessionId,
                recipient,
                $"message-{index}",
                MessageDirection.Outgoing,
                MessageDeliveryState.Sent,
                clock.UtcNow.AddSeconds(index),
                []));
        }

        var before = await runtime.Messages.ListConversationMessagesBeforeAsync(
            conversation.Id,
            clock.UtcNow.AddSeconds(4),
            messageIds[4],
            3);

        Assert.Equal(["message-1", "message-2", "message-3"], before.Select(item => item.Body));
    }

    [Fact]
    public async Task ReceiveAsync_DropsAlreadyExpiredInboundMessages()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(clock: clock, backend: backend);
        var bob = ClientRuntime.CreateStubbed(clock: clock, backend: backend);

        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");

        await backend.SendAsync(new OutboundMessageEnvelope(
            aliceAccount.SessionId,
            bobAccount.SessionId,
            "too-late",
            [],
            clock.UtcNow.AddMinutes(-2),
            clock.UtcNow.AddMinutes(-1)));

        var received = await bob.Messages.ReceiveAsync(bobAccount.SessionId);

        Assert.Empty(received);
    }

    [Fact]
    public async Task MarkAsRead_SetsReadCursor_AndUpdatesDeliveryState()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var backend = new StubSessionBackend();
        var alice = ClientRuntime.CreateStubbed(clock: clock, backend: backend);
        var bob = ClientRuntime.CreateStubbed(clock: clock, backend: backend);

        var aliceAccount = await alice.Accounts.RegisterAsync("Alice");
        var bobAccount = await bob.Accounts.RegisterAsync("Bob");
        await alice.Messages.SendOneToOneAsync(aliceAccount.SessionId, bobAccount.SessionId, "mark-read");

        var incoming = await bob.Messages.ReceiveAsync(bobAccount.SessionId);
        var updated = await bob.Messages.MarkAsReadAsync(incoming[0].Id);
        var cursor = await bob.Messages.GetReadCursorAsync(incoming[0].ConversationId);

        Assert.NotNull(updated);
        Assert.Equal(MessageDeliveryState.Read, updated!.DeliveryState);
        Assert.NotNull(updated.ReadAt);
        Assert.NotNull(cursor);
    }

    [Fact]
    public async Task MarkConversationAsRead_AtomicallyMarksIncomingMessagesAndSetsCursor()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(sender.SessionId);
        var message = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender.SessionId,
            recipient,
            "incoming",
            MessageDirection.Incoming,
            MessageDeliveryState.Delivered,
            clock.UtcNow.AddSeconds(-5),
            []);
        await ((IMessageRepository)runtime.Store).AppendAsync(message);

        var cursor = await runtime.Messages.MarkConversationAsReadAsync(conversation.Id);
        var stored = await ((IMessageRepository)runtime.Store).GetAsync(message.Id);

        Assert.Equal(clock.UtcNow, cursor);
        Assert.Equal(cursor, await runtime.Messages.GetReadCursorAsync(conversation.Id));
        Assert.Equal(MessageDeliveryState.Read, stored!.DeliveryState);
        Assert.Equal(cursor, stored.ReadAt);
    }

    [Fact]
    public async Task ApplyReadCursor_MarksOlderIncomingMessagesAsRead()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(sender.SessionId);

        var first = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient, "first", MessageDirection.Incoming, MessageDeliveryState.Delivered, clock.UtcNow.AddSeconds(-20), []);
        var second = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient, "second", MessageDirection.Incoming, MessageDeliveryState.Delivered, clock.UtcNow.AddSeconds(-10), []);
        await ((IMessageRepository)runtime.Store).AppendAsync(first);
        await ((IMessageRepository)runtime.Store).AppendAsync(second);

        var changed = await runtime.Messages.ApplyReadCursorAsync(conversation.Id, clock.UtcNow.AddSeconds(-15));
        var firstState = await ((IMessageRepository)runtime.Store).GetAsync(first.Id);
        var secondState = await ((IMessageRepository)runtime.Store).GetAsync(second.Id);

        Assert.Equal(1, changed);
        Assert.Equal(MessageDeliveryState.Read, firstState!.DeliveryState);
        Assert.Equal(MessageDeliveryState.Delivered, secondState!.DeliveryState);
    }

    [Fact]
    public async Task PruneExpiredConversationMessages_RemovesExpiredRowsFromStore()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:10:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = SessionId.CreateNew();
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient);

        var expired = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient, "expired", MessageDirection.Outgoing, MessageDeliveryState.Sent, clock.UtcNow.AddMinutes(-2), [], clock.UtcNow.AddMinutes(-1));
        await ((IMessageRepository)runtime.Store).AppendAsync(expired);

        var removed = await runtime.Messages.PruneExpiredConversationMessagesAsync(conversation.Id);
        var after = await ((IMessageRepository)runtime.Store).GetAsync(expired.Id);

        Assert.Equal(1, removed);
        Assert.Null(after);
    }

    [Fact]
    public async Task GroupAdminOperations_RequireAdminPrivileges_AndUpdateMembers()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var owner = await runtime.Accounts.RegisterAsync("Owner");
        var outsider = SessionId.CreateNew();
        var member = SessionId.CreateNew();

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner.SessionId, "Ops", [member]);
        var unauthorized = await runtime.Conversations.RemoveMemberAsync(group.Id, outsider, member);
        var pending = await runtime.Conversations.MarkMemberPendingRemovalAsync(group.Id, owner.SessionId, member, true);
        var removed = await runtime.Conversations.RemoveMemberAsync(group.Id, owner.SessionId, member);

        Assert.Null(unauthorized);
        Assert.NotNull(pending);
        Assert.True(pending!.Members.Single(m => m.SessionId == member).IsPendingRemoval);
        Assert.NotNull(removed);
        Assert.DoesNotContain(removed!.Members, item => item.SessionId == member);
        Assert.True(removed.HasAdmin(owner.SessionId));
    }

    [Fact]
    public async Task GroupRoleUpdates_PromoteAndDemote_Work_WithAdminSafeguard()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var owner = await runtime.Accounts.RegisterAsync("Owner");
        var secondAdmin = SessionId.CreateNew();

        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner.SessionId, "Leads", [secondAdmin]);
        var promoted = await runtime.Conversations.PromoteMemberAsync(group.Id, owner.SessionId, secondAdmin);
        var demotedOwner = await runtime.Conversations.DemoteMemberAsync(group.Id, owner.SessionId, owner.SessionId);
        var demoteLastAdmin = await runtime.Conversations.DemoteMemberAsync(group.Id, secondAdmin, secondAdmin);

        Assert.NotNull(promoted);
        Assert.True(promoted!.HasAdmin(secondAdmin));
        Assert.NotNull(demotedOwner);
        Assert.False(demotedOwner!.HasAdmin(owner.SessionId));
        Assert.True(demotedOwner.HasAdmin(secondAdmin));
        Assert.Null(demoteLastAdmin);
    }

    [Fact]
    public async Task GroupLifecycle_LeaveDestroyAndRename_UpdatePersistedConversationState()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var owner = await runtime.Accounts.RegisterAsync("Owner");
        var member = SessionId.CreateNew();
        var group = await runtime.Conversations.CreateGroupScaffoldAsync(owner.SessionId, "Initial", [member]);

        var renamed = await runtime.Conversations.UpdateGroupNameAsync(group.Id, owner.SessionId, "Renamed");
        var left = await runtime.Conversations.LeaveGroupAsync(group.Id, member);
        var destroyed = await runtime.Conversations.DestroyGroupAsync(group.Id, owner.SessionId);
        var conversation = await ((IConversationRepository)runtime.Store).GetAsync(group.Id);

        Assert.NotNull(renamed);
        Assert.Equal("Renamed", renamed!.Name);
        Assert.NotNull(left);
        Assert.Single(left!.Members);
        Assert.NotNull(destroyed);
        Assert.True(destroyed!.IsDestroyed);
        Assert.NotNull(conversation);
        Assert.Equal("Renamed", conversation!.DisplayName);
        Assert.True(conversation.IsHidden);
    }

    [Fact]
    public async Task ReceiveGroupAsync_RejectsOutsiderMessageWithoutPersistingConversationOrMessage()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var groupSync = new RecordingGroupSyncTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            new QueuedMessageTransport(),
            groupSync);
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var activeMember = SessionId.CreateNew();
        var outsider = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Accepted revision",
            recipient.SessionId,
            clock.UtcNow.AddDays(-1),
            [
                new GroupMember(recipient.SessionId, GroupMemberRole.Admin, clock.UtcNow.AddDays(-1)),
                new GroupMember(activeMember, GroupMemberRole.Standard, clock.UtcNow.AddHours(-1))
            ],
            Revision: 7);
        await ((IGroupRepository)runtime.Store).UpsertAsync(group);
        var messageId = new MessageId("outsider-message");
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            messageId,
            group.Id,
            outsider,
            "not authorized",
            [],
            clock.UtcNow,
            null,
            "outsider-message-hash"));

        var received = await runtime.Messages.ReceiveGroupAsync(recipient.SessionId, group.Id);

        Assert.Empty(received);
        Assert.Null(await ((IConversationRepository)runtime.Store).GetAsync(group.Id));
        Assert.Null(await ((IMessageRepository)runtime.Store).GetAsync(messageId));
    }

    [Fact]
    public async Task ReceiveGroupAsync_RejectsRemovedRecipientBeforeFetchingEntries()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var groupSync = new RecordingGroupSyncTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            new QueuedMessageTransport(),
            groupSync);
        var recipient = await runtime.Accounts.RegisterAsync("Removed recipient");
        var sender = SessionId.CreateNew();
        var owner = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Accepted revision",
            owner,
            clock.UtcNow.AddDays(-1),
            [
                new GroupMember(owner, GroupMemberRole.Admin, clock.UtcNow.AddDays(-1)),
                new GroupMember(sender, GroupMemberRole.Standard, clock.UtcNow.AddHours(-1))
            ],
            Revision: 8);
        await ((IGroupRepository)runtime.Store).UpsertAsync(group);
        var messageId = new MessageId("removed-recipient-message");
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            messageId,
            group.Id,
            sender,
            "not for removed recipients",
            [],
            clock.UtcNow,
            null,
            "removed-recipient-hash"));

        var received = await runtime.Messages.ReceiveGroupAsync(recipient.SessionId, group.Id);

        Assert.Empty(received);
        Assert.Equal(0, groupSync.ReceiveGroupMessagesCount);
        Assert.Null(await ((IConversationRepository)runtime.Store).GetAsync(group.Id));
        Assert.Null(await ((IMessageRepository)runtime.Store).GetAsync(messageId));
    }

    [Fact]
    public async Task ReceiveGroupAsync_RejectsRemovedOrPendingMemberReactionsWithoutUpdatingTarget()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var groupSync = new RecordingGroupSyncTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            new QueuedMessageTransport(),
            groupSync);
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var activeMember = SessionId.CreateNew();
        var removedMember = SessionId.CreateNew();
        var pendingRemovalMember = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Accepted revision",
            recipient.SessionId,
            clock.UtcNow.AddDays(-1),
            [
                new GroupMember(recipient.SessionId, GroupMemberRole.Admin, clock.UtcNow.AddDays(-1)),
                new GroupMember(activeMember, GroupMemberRole.Standard, clock.UtcNow.AddHours(-1)),
                new GroupMember(pendingRemovalMember, GroupMemberRole.Standard, clock.UtcNow.AddHours(-1), IsPendingRemoval: true)
            ],
            Revision: 9);
        await ((IGroupRepository)runtime.Store).UpsertAsync(group);
        var target = new Message(
            new MessageId("reaction-target"),
            group.Id,
            activeMember,
            Recipient: null,
            "existing message",
            MessageDirection.Incoming,
            MessageDeliveryState.Delivered,
            clock.UtcNow.AddMinutes(-1),
            []);
        await ((IMessageRepository)runtime.Store).AppendAsync(target);
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            new MessageId("removed-reaction"),
            group.Id,
            removedMember,
            string.Empty,
            [],
            clock.UtcNow,
            null,
            "removed-reaction-hash",
            Reaction: new MessageReactionUpdate(target.Id, "👍", Remove: false)));
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            new MessageId("pending-removal-reaction"),
            group.Id,
            pendingRemovalMember,
            string.Empty,
            [],
            clock.UtcNow,
            null,
            "pending-removal-reaction-hash",
            Reaction: new MessageReactionUpdate(target.Id, "👍", Remove: false)));

        var received = await runtime.Messages.ReceiveGroupAsync(recipient.SessionId, group.Id);
        var storedTarget = await ((IMessageRepository)runtime.Store).GetAsync(target.Id);

        Assert.Empty(received);
        Assert.Null(await ((IConversationRepository)runtime.Store).GetAsync(group.Id));
        Assert.Empty(storedTarget!.ReactionItems);
    }

    [Fact]
    public async Task ReceiveGroupAsync_AcceptsActiveMemberMessageAndReaction()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var groupSync = new RecordingGroupSyncTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            clock,
            new QueuedMessageTransport(),
            groupSync);
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var sender = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Accepted revision",
            recipient.SessionId,
            clock.UtcNow.AddDays(-1),
            [
                new GroupMember(recipient.SessionId, GroupMemberRole.Admin, clock.UtcNow.AddDays(-1)),
                new GroupMember(sender, GroupMemberRole.Standard, clock.UtcNow.AddHours(-1))
            ],
            Revision: 10);
        await ((IGroupRepository)runtime.Store).UpsertAsync(group);
        var messageId = new MessageId("active-member-message");
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            messageId,
            group.Id,
            sender,
            "accepted",
            [],
            clock.UtcNow,
            null,
            "active-member-message-hash"));

        var messages = await runtime.Messages.ReceiveGroupAsync(recipient.SessionId, group.Id);

        Assert.Equal("accepted", Assert.Single(messages).Body);
        Assert.NotNull(await ((IConversationRepository)runtime.Store).GetAsync(group.Id));
        groupSync.Enqueue(new InboundGroupMessageEnvelope(
            new MessageId("active-member-reaction"),
            group.Id,
            sender,
            string.Empty,
            [],
            clock.UtcNow,
            null,
            "active-member-reaction-hash",
            Reaction: new MessageReactionUpdate(messageId, "👍", Remove: false)));

        var reactions = await runtime.Messages.ReceiveGroupAsync(recipient.SessionId, group.Id);
        var storedMessage = await ((IMessageRepository)runtime.Store).GetAsync(messageId);

        Assert.Single(reactions);
        Assert.Collection(storedMessage!.ReactionItems, reaction =>
        {
            Assert.Equal(sender, reaction.Reactor);
            Assert.Equal("👍", reaction.Emoji);
        });
    }

    [Fact]
    public async Task SendGroupAsync_IncludesMemberWakeRecipientsForPushDrivenSync()
    {
        var groupSync = new RecordingGroupSyncTransport();
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            Deep.Client.Shared.Features.ClientFeatureFlags.Defaults,
            new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")),
            new QueuedMessageTransport(),
            groupSync);
        var owner = await runtime.Accounts.RegisterAsync("Owner");
        var firstMember = SessionId.CreateNew();
        var secondMember = SessionId.CreateNew();
        var group = await runtime.Conversations.CreateGroupScaffoldAsync(
            owner.SessionId,
            "Push group",
            [firstMember, secondMember]);

        await runtime.Messages.SendGroupAsync(owner.SessionId, group.Id, "wake everyone");

        var envelope = Assert.Single(groupSync.SentMessages);
        Assert.Equal(group.Id, envelope.GroupId);
        Assert.Equal([firstMember, secondMember], envelope.NotifyRecipients);
        Assert.DoesNotContain(owner.SessionId, envelope.NotifyRecipients ?? []);
    }

    private sealed class QueuedMessageTransport : ISessionMessageTransport
    {
        private readonly Queue<InboundMessageEnvelope> envelopes = new();

        public Exception? SendException { get; set; }

        public int SendCount { get; private set; }

        public void Enqueue(InboundMessageEnvelope envelope) => envelopes.Enqueue(envelope);

        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default)
        {
            SendCount++;
            return SendException is null ? Task.CompletedTask : Task.FromException(SendException);
        }

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default)
        {
            var result = envelopes
                .Where(envelope => envelope.Recipient == recipient)
                .ToArray();
            envelopes.Clear();
            return Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>(result);
        }
    }

    private sealed class RecordingGroupSyncTransport : IGroupSyncTransport
    {
        private readonly Queue<InboundGroupMessageEnvelope> incomingMessages = new();

        public List<OutboundGroupMessageEnvelope> SentMessages { get; } = [];

        public int ReceiveGroupMessagesCount { get; private set; }

        public void Enqueue(InboundGroupMessageEnvelope envelope) => incomingMessages.Enqueue(envelope);

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>([]);

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default)
        {
            SentMessages.Add(envelope);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default)
        {
            ReceiveGroupMessagesCount++;
            var envelopes = incomingMessages.ToArray();
            incomingMessages.Clear();
            return Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>(envelopes);
        }
    }
}
