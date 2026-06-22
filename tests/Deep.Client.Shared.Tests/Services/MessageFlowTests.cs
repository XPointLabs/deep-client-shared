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
        var bob = await runtime.Accounts.RegisterAsync("Bob");
        var sent = await runtime.Messages.SendOneToOneAsync(alice.SessionId, bob.SessionId, "fresh");

        var expired = new Message(
            MessageId.NewId(),
            sent.ConversationId,
            alice.SessionId,
            bob.SessionId,
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
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient.SessionId);

        for (var index = 0; index < 5; index++)
        {
            await ((IMessageRepository)runtime.Store).AppendAsync(new Message(
                MessageId.NewId(),
                conversation.Id,
                sender.SessionId,
                recipient.SessionId,
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
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient.SessionId);

        for (var index = 0; index < 6; index++)
        {
            await ((IMessageRepository)runtime.Store).AppendAsync(new Message(
                MessageId.NewId(),
                conversation.Id,
                sender.SessionId,
                recipient.SessionId,
                $"message-{index}",
                MessageDirection.Outgoing,
                MessageDeliveryState.Sent,
                clock.UtcNow.AddSeconds(index),
                []));
        }

        var before = await runtime.Messages.ListConversationMessagesBeforeAsync(
            conversation.Id,
            clock.UtcNow.AddSeconds(4),
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
    public async Task MarkConversationAsRead_SetsCursorWithoutRewritingMessages()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(sender.SessionId);
        var message = new Message(
            MessageId.NewId(),
            conversation.Id,
            sender.SessionId,
            recipient.SessionId,
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
        Assert.Equal(MessageDeliveryState.Delivered, stored!.DeliveryState);
    }

    [Fact]
    public async Task ApplyReadCursor_MarksOlderIncomingMessagesAsRead()
    {
        var clock = new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z"));
        var runtime = ClientRuntime.CreateStubbed(clock: clock, backend: new StubSessionBackend());

        var sender = await runtime.Accounts.RegisterAsync("Sender");
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(sender.SessionId);

        var first = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient.SessionId, "first", MessageDirection.Incoming, MessageDeliveryState.Delivered, clock.UtcNow.AddSeconds(-20), []);
        var second = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient.SessionId, "second", MessageDirection.Incoming, MessageDeliveryState.Delivered, clock.UtcNow.AddSeconds(-10), []);
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
        var recipient = await runtime.Accounts.RegisterAsync("Recipient");
        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(recipient.SessionId);

        var expired = new Message(MessageId.NewId(), conversation.Id, sender.SessionId, recipient.SessionId, "expired", MessageDirection.Outgoing, MessageDeliveryState.Sent, clock.UtcNow.AddMinutes(-2), [], clock.UtcNow.AddMinutes(-1));
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
}
