using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.Services;

public sealed class DurableInboxDomainAckTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-10T10:00:00Z");

    [Fact]
    public async Task GroupState_RestartAcknowledgesAtomicPersistenceAfterCrash()
    {
        var statePath = NewStatePath();
        var recipient = SessionId.CreateNew();
        var owner = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Durable group state",
            owner,
            Now.AddDays(-1),
            [
                new GroupMember(owner, GroupMemberRole.Admin, Now.AddDays(-1)),
                new GroupMember(recipient, GroupMemberRole.Standard, Now.AddHours(-1))
            ],
            Revision: 1);
        var sync = new PersistentGroupSyncInbox();
        sync.Enqueue(new InboundGroupStateEnvelope(group, Now, "group-state-hash", owner));

        try
        {
            var store = new InMemorySessionStore(statePath);
            var service = CreateConversationService(
                store,
                new ThrowAfterGroupStatePersistRepository(store),
                sync);

            await Assert.ThrowsAsync<InjectedDomainCrashException>(() =>
                service.ReceiveGroupUpdatesAsync(recipient));

            Assert.Equal(0, sync.AckCount);
            Assert.NotNull(await ((IGroupRepository)store).GetAsync(group.Id));
            Assert.NotNull(await ((IConversationRepository)store).GetAsync(group.Id));

            var restarted = new InMemorySessionStore(statePath);
            var resumed = CreateConversationService(restarted, restarted, sync);
            Assert.Empty(await resumed.ReceiveGroupUpdatesAsync(recipient));

            Assert.Equal(1, sync.AckCount);
            Assert.NotNull(await ((IGroupRepository)restarted).GetAsync(group.Id));
            Assert.NotNull(await ((IConversationRepository)restarted).GetAsync(group.Id));
        }
        finally
        {
            File.Delete(statePath);
        }
    }

    [Fact]
    public async Task GroupMessage_RestartRepairsPartialPersistenceBeforeAck()
    {
        var statePath = NewStatePath();
        var recipient = SessionId.CreateNew();
        var sender = SessionId.CreateNew();
        var group = new Group(
            ConversationId.CreateGroupV2(),
            "Durable group message",
            recipient,
            Now.AddDays(-1),
            [
                new GroupMember(recipient, GroupMemberRole.Admin, Now.AddDays(-1)),
                new GroupMember(sender, GroupMemberRole.Standard, Now.AddHours(-1))
            ],
            Revision: 4);
        var message = new InboundGroupMessageEnvelope(
            MessageId.Parse("durable-group-message"),
            group.Id,
            sender,
            "persist before ack",
            [],
            Now,
            null,
            "group-message-hash");
        var sync = new PersistentGroupSyncInbox();
        sync.Enqueue(message);

        try
        {
            var store = new InMemorySessionStore(statePath);
            await ((IGroupRepository)store).UpsertAsync(group);
            var conversations = CreateConversationService(store, store, sync);
            var crashingMessages = new ThrowAfterMessageAppendRepository(store);
            var service = new MessageService(
                conversations,
                store,
                crashingMessages,
                store,
                new FrozenClock(Now),
                new MessageNetworkRuntime(
                    crashingMessages,
                    new EmptySessionTransport(),
                    sync,
                    null));

            await Assert.ThrowsAsync<InjectedDomainCrashException>(() =>
                service.ReceiveGroupAsync(recipient, group.Id));

            Assert.Equal(0, sync.AckCount);
            Assert.NotNull(await ((IMessageRepository)store).GetAsync(message.Id));
            Assert.Null(await ((IConversationRepository)store).GetAsync(group.Id));

            var restarted = new InMemorySessionStore(statePath);
            var resumedConversations = CreateConversationService(restarted, restarted, sync);
            var resumed = new MessageService(
                resumedConversations,
                restarted,
                restarted,
                restarted,
                new FrozenClock(Now),
                new MessageNetworkRuntime(
                    restarted,
                    new EmptySessionTransport(),
                    sync,
                    null));
            Assert.Empty(await resumed.ReceiveGroupAsync(recipient, group.Id));

            Assert.Equal(1, sync.AckCount);
            Assert.NotNull(await ((IMessageRepository)restarted).GetAsync(message.Id));
            Assert.NotNull(await ((IConversationRepository)restarted).GetAsync(group.Id));
        }
        finally
        {
            File.Delete(statePath);
        }
    }

    [Fact]
    public async Task GroupStateRevisionGapRemainsUnackedUntilMissingRevisionArrives()
    {
        var recipient = SessionId.CreateNew();
        var owner = SessionId.CreateNew();
        var groupId = ConversationId.CreateGroupV2();
        var revisionOne = new Group(
            groupId,
            "Revision one",
            owner,
            Now.AddDays(-1),
            [
                new GroupMember(owner, GroupMemberRole.Admin, Now.AddDays(-1)),
                new GroupMember(recipient, GroupMemberRole.Standard, Now.AddHours(-1))
            ],
            Revision: 1);
        var revisionTwo = revisionOne with { Name = "Revision two", Revision = 2 };
        var sync = new PersistentGroupSyncInbox();
        sync.Enqueue(new InboundGroupStateEnvelope(revisionTwo, Now.AddMinutes(1), "revision-2", owner));
        var store = new InMemorySessionStore();
        var service = CreateConversationService(store, store, sync);

        Assert.Empty(await service.ReceiveGroupUpdatesAsync(recipient));
        Assert.Equal(0, sync.AckCount);
        Assert.Null(await ((IGroupRepository)store).GetAsync(groupId));

        sync.Enqueue(new InboundGroupStateEnvelope(revisionOne, Now, "revision-1", owner));
        var applied = await service.ReceiveGroupUpdatesAsync(recipient);

        Assert.Equal([1L, 2L], applied.Select(static group => group.Revision));
        Assert.Equal(2, sync.AckCount);
        Assert.Equal(2, (await ((IGroupRepository)store).GetAsync(groupId))!.Revision);
    }

    private static ConversationService CreateConversationService(
        ILocalSessionStore store,
        IGroupStatePersistenceRepository groupStatePersistence,
        IGroupSyncTransport sync) =>
        new(
            store,
            store,
            store,
            groupStatePersistence,
            new FrozenClock(Now),
            ClientFeatureFlags.Defaults,
            sync);

    private static string NewStatePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-client-domain-ack-{Guid.NewGuid():N}.json");

    private sealed class InjectedDomainCrashException : Exception;

    private sealed class ThrowAfterGroupStatePersistRepository(IGroupStatePersistenceRepository inner)
        : IGroupStatePersistenceRepository
    {
        private int faulted;

        public async Task PersistGroupStateAsync(
            Group group,
            Conversation conversation,
            DateTimeOffset updatedAt,
            GroupStateOutboxItem? outboxItem,
            CancellationToken cancellationToken = default)
        {
            await inner.PersistGroupStateAsync(group, conversation, updatedAt, outboxItem, cancellationToken);
            if (Interlocked.Exchange(ref faulted, 1) == 0)
            {
                throw new InjectedDomainCrashException();
            }
        }

        public Task<IReadOnlyList<GroupStateOutboxItem>> ListPendingGroupStatePublishesAsync(
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListPendingGroupStatePublishesAsync(limit, cancellationToken);

        public Task AcknowledgeGroupStatePublishAsync(
            string operationId,
            CancellationToken cancellationToken = default) =>
            inner.AcknowledgeGroupStatePublishAsync(operationId, cancellationToken);
    }

    private sealed class ThrowAfterMessageAppendRepository(IMessageRepository inner) : IMessageRepository
    {
        private int faulted;

        public async Task AppendAsync(Message message, CancellationToken cancellationToken = default)
        {
            await inner.AppendAsync(message, cancellationToken);
            if (Interlocked.Exchange(ref faulted, 1) == 0)
            {
                throw new InjectedDomainCrashException();
            }
        }

        public Task UpdateAsync(Message message, CancellationToken cancellationToken = default) =>
            inner.UpdateAsync(message, cancellationToken);

        public Task DeleteAsync(MessageId id, CancellationToken cancellationToken = default) =>
            inner.DeleteAsync(id, cancellationToken);

        public Task<Message?> GetAsync(MessageId id, CancellationToken cancellationToken = default) =>
            inner.GetAsync(id, cancellationToken);

        public IAsyncEnumerable<Message> ListForConversationAsync(
            ConversationId conversationId,
            CancellationToken cancellationToken = default) =>
            inner.ListForConversationAsync(conversationId, cancellationToken);

        public IAsyncEnumerable<Message> ListRecentForConversationAsync(
            ConversationId conversationId,
            DateTimeOffset now,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListRecentForConversationAsync(conversationId, now, limit, cancellationToken);

        public IAsyncEnumerable<Message> ListBeforeForConversationAsync(
            ConversationId conversationId,
            DateTimeOffset beforeCreatedAt,
            MessageId beforeMessageId,
            DateTimeOffset now,
            int limit,
            CancellationToken cancellationToken = default) =>
            inner.ListBeforeForConversationAsync(
                conversationId,
                beforeCreatedAt,
                beforeMessageId,
                now,
                limit,
                cancellationToken);

        public Task<int> CountUnreadForConversationAsync(
            ConversationId conversationId,
            DateTimeOffset? readCursor,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            inner.CountUnreadForConversationAsync(conversationId, readCursor, now, cancellationToken);
    }

    private sealed class PersistentGroupSyncInbox : IGroupSyncTransport, IDurableInboxAcknowledger
    {
        private readonly List<InboundGroupStateEnvelope> states = [];
        private readonly List<InboundGroupMessageEnvelope> messages = [];

        public int AckCount { get; private set; }

        public void Enqueue(InboundGroupStateEnvelope state) => states.Add(state);

        public void Enqueue(InboundGroupMessageEnvelope message) => messages.Add(message);

        public Task PublishGroupStateAsync(
            Group group,
            DateTimeOffset updatedAt,
            IEnumerable<SessionId>? recipients = null,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundGroupStateEnvelope>> ReceiveGroupStatesAsync(
            SessionId member,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupStateEnvelope>>(states.ToArray());

        public Task SendGroupMessageAsync(
            OutboundGroupMessageEnvelope envelope,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundGroupMessageEnvelope>> ReceiveGroupMessagesAsync(
            ConversationId groupId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundGroupMessageEnvelope>>(
                messages.Where(message => message.GroupId == groupId).ToArray());

        public Task AcknowledgeInboxItemAsync(
            SessionId account,
            string serverHash,
            CancellationToken cancellationToken = default)
        {
            states.RemoveAll(state => string.Equals(state.ServerHash, serverHash, StringComparison.Ordinal));
            messages.RemoveAll(message => string.Equals(message.ServerHash, serverHash, StringComparison.Ordinal));
            AckCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class EmptySessionTransport : ISessionMessageTransport
    {
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
    }
}
