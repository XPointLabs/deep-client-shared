using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class IncomingMessageNotificationRepositoryTests
{
    [Fact]
    public async Task StoresQueueOnlyNewIncomingMessagesUntilPresented()
    {
        await ForEachStoreAsync(async store =>
        {
            var now = DateTimeOffset.UtcNow;
            var account = SessionId.CreateNew();
            var counterpart = SessionId.CreateNew();
            var conversation = NewConversation(counterpart, now);
            var historicalIncoming = NewMessage(
                conversation.Id,
                counterpart,
                account,
                MessageDirection.Incoming,
                now.AddSeconds(-1));
            var incoming = NewMessage(
                conversation.Id,
                counterpart,
                account,
                MessageDirection.Incoming,
                now);
            var selfSync = NewMessage(
                conversation.Id,
                account,
                counterpart,
                MessageDirection.Outgoing,
                now.AddSeconds(1));

            await store.AppendAsync(historicalIncoming);
            await store.AppendMessageAndTouchConversationAsync(incoming, conversation.Touch(now));
            await store.AppendMessageAndTouchConversationAsync(selfSync, conversation.Touch(now.AddSeconds(1)));

            Assert.Equal(
                [NotificationFor(incoming)],
                await store.ListPendingIncomingMessageNotificationIdsAsync(16));

            await store.MarkIncomingMessageNotificationsPresentedAsync([incoming.Id, incoming.Id]);
            await store.MarkIncomingMessageNotificationsPresentedAsync([incoming.Id]);

            Assert.Empty(await store.ListPendingIncomingMessageNotificationIdsAsync(16));

            await store.AppendMessageAndTouchConversationAsync(incoming, conversation.Touch(now.AddSeconds(2)));
            Assert.Empty(await store.ListPendingIncomingMessageNotificationIdsAsync(16));
        });
    }

    [Fact]
    public async Task StoresExcludeReadDeletedAndExpiredIncomingMessages()
    {
        await ForEachStoreAsync(async store =>
        {
            var now = DateTimeOffset.UtcNow;
            var account = SessionId.CreateNew();
            var counterpart = SessionId.CreateNew();
            var conversation = NewConversation(counterpart, now);
            var pending = NewMessage(conversation.Id, counterpart, account, MessageDirection.Incoming, now);
            var read = NewMessage(conversation.Id, counterpart, account, MessageDirection.Incoming, now.AddSeconds(1));
            var deleted = NewMessage(conversation.Id, counterpart, account, MessageDirection.Incoming, now.AddSeconds(2));
            var expired = NewMessage(
                conversation.Id,
                counterpart,
                account,
                MessageDirection.Incoming,
                now.AddSeconds(3),
                now.AddMinutes(-1));

            foreach (var message in new[] { pending, read, deleted, expired })
            {
                await store.AppendMessageAndTouchConversationAsync(message, conversation.Touch(message.CreatedAt));
            }

            await store.UpdateAsync(read.Mark(MessageDeliveryState.Read, now.AddMinutes(1)));
            await store.DeleteAsync(deleted.Id);

            Assert.Equal(
                [NotificationFor(pending)],
                await store.ListPendingIncomingMessageNotificationIdsAsync(16));

            await store.UpdateAsync(read);
            await store.AppendAsync(deleted);
            await store.UpdateAsync(expired with { ExpiresAt = now.AddMinutes(5) });

            Assert.Equal(
                [NotificationFor(pending)],
                await store.ListPendingIncomingMessageNotificationIdsAsync(16));
        });
    }

    [Fact]
    public async Task InMemoryQueueAndPresentedStateSurviveReload()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-notifications-{Guid.NewGuid():N}.json");
        try
        {
            var message = await AppendIncomingAsync(new InMemorySessionStore(statePath));

            var restarted = new InMemorySessionStore(statePath);
            Assert.Equal(
                [NotificationFor(message)],
                await restarted.ListPendingIncomingMessageNotificationIdsAsync(16));

            await restarted.MarkIncomingMessageNotificationsPresentedAsync([message.Id]);

            var presentedRestart = new InMemorySessionStore(statePath);
            Assert.Empty(await presentedRestart.ListPendingIncomingMessageNotificationIdsAsync(16));
        }
        finally
        {
            File.Delete(statePath);
        }
    }

    [Fact]
    public async Task SqliteQueueAndPresentedStateSurviveReload()
    {
        var statePath = NewSqlitePath();
        try
        {
            Message message;
            using (var store = new SqliteSessionStore(statePath))
            {
                message = await AppendIncomingAsync(store);
            }

            using (var restarted = new SqliteSessionStore(statePath))
            {
                Assert.Equal(
                    [NotificationFor(message)],
                    await restarted.ListPendingIncomingMessageNotificationIdsAsync(16));
                await restarted.MarkIncomingMessageNotificationsPresentedAsync([message.Id]);
            }

            using var presentedRestart = new SqliteSessionStore(statePath);
            Assert.Empty(await presentedRestart.ListPendingIncomingMessageNotificationIdsAsync(16));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqlitePhysicalMigrationDoesNotBackfillExistingMessages()
    {
        var statePath = NewSqlitePath();
        try
        {
            using (var oldStore = new SqliteSessionStore(statePath))
            {
                var now = DateTimeOffset.UtcNow;
                var account = SessionId.CreateNew();
                var counterpart = SessionId.CreateNew();
                var conversation = NewConversation(counterpart, now);
                await oldStore.UpsertAsync(conversation);
                await oldStore.AppendAsync(NewMessage(
                    conversation.Id,
                    counterpart,
                    account,
                    MessageDirection.Incoming,
                    now));
            }

            await using (var connection = new SqliteConnection($"Data Source={statePath};Pooling=False"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    DROP TABLE incoming_message_notifications;
                    PRAGMA user_version=6;
                    """;
                await command.ExecuteNonQueryAsync();
            }

            using var migrated = new SqliteSessionStore(statePath);
            Assert.Empty(await migrated.ListPendingIncomingMessageNotificationIdsAsync(16));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task AccountPurgeClearsPendingIncomingMessageNotifications()
    {
        await ForEachStoreAsync(async store =>
        {
            await AppendIncomingAsync(store);
            Assert.NotEmpty(await store.ListPendingIncomingMessageNotificationIdsAsync(16));

            await store.PurgeAccountDataAsync();

            Assert.Empty(await store.ListPendingIncomingMessageNotificationIdsAsync(16));
        });
    }

    [Fact]
    public async Task MessageServiceUsesTheAccountGenerationBarrierForNotificationQueueAccess()
    {
        var inner = new InMemorySessionStore();
        using var runtime = new ClientRuntime(
            inner,
            ClientFeatureFlags.Defaults,
            new FrozenClock(DateTimeOffset.UtcNow),
            new StubSessionBackend());
        await runtime.Accounts.RegisterAsync("Alice");
        var message = await AppendIncomingAsync(runtime.Store);

        Assert.Equal(
            [NotificationFor(message)],
            await runtime.Messages.ListPendingIncomingMessageNotificationIdsAsync(16));

        await runtime.Messages.MarkIncomingMessageNotificationsPresentedAsync([message.Id]);
        Assert.Empty(await runtime.Messages.ListPendingIncomingMessageNotificationIdsAsync(16));

        await runtime.Accounts.SignOutAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => runtime.Messages.ListPendingIncomingMessageNotificationIdsAsync(16));
    }

    private static async Task<Message> AppendIncomingAsync(ILocalSessionStore store)
    {
        var now = DateTimeOffset.UtcNow;
        var account = SessionId.CreateNew();
        var counterpart = SessionId.CreateNew();
        var conversation = NewConversation(counterpart, now);
        var message = NewMessage(
            conversation.Id,
            counterpart,
            account,
            MessageDirection.Incoming,
            now);
        await store.AppendMessageAndTouchConversationAsync(message, conversation);
        return message;
    }

    private static Conversation NewConversation(SessionId counterpart, DateTimeOffset now) =>
        new(
            ConversationId.ForOneToOne(counterpart),
            ConversationKind.OneToOne,
            "Notification test",
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now);

    private static PendingIncomingMessageNotification NotificationFor(Message message) =>
        new(message.Id, message.ConversationId);

    private static Message NewMessage(
        ConversationId conversationId,
        SessionId sender,
        SessionId? recipient,
        MessageDirection direction,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt = null) =>
        new(
            MessageId.NewId(),
            conversationId,
            sender,
            recipient,
            "notification test",
            direction,
            direction == MessageDirection.Incoming
                ? MessageDeliveryState.Delivered
                : MessageDeliveryState.Sent,
            createdAt,
            [],
            expiresAt);

    private static async Task ForEachStoreAsync(Func<ILocalSessionStore, Task> assertion)
    {
        await assertion(new InMemorySessionStore());

        var statePath = NewSqlitePath();
        try
        {
            using var sqlite = new SqliteSessionStore(statePath);
            await assertion(sqlite);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static string NewSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-client-notifications-{Guid.NewGuid():N}.db");

    private static void DeleteSqliteFiles(string statePath)
    {
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
