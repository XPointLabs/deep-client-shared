using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Microsoft.Data.Sqlite;
using System.Globalization;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class PersistenceTests
{
    [Fact]
    public async Task SqliteSessionStore_MarksReadWithoutRewritingMessagePayload()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-read-columns-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(statePath);
            var sender = SessionId.CreateNew();
            var recipient = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(sender);
            var message = new Message(
                MessageId.NewId(),
                conversationId,
                sender,
                recipient,
                "read without JSON rewrite",
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                DateTimeOffset.Parse("2026-05-28T00:00:00Z"),
                []);
            await store.AppendAsync(message);
            var payloadBefore = await ReadRawMessagePayloadAsync(statePath, message.Id);
            var readAt = message.CreatedAt.AddSeconds(5);

            var result = await store.MarkConversationReadIfUnreadAsync(conversationId, readAt);

            var payloadAfter = await ReadRawMessagePayloadAsync(statePath, message.Id);
            var reloaded = await store.GetAsync(message.Id);
            Assert.Equal(1, result.ChangedMessageCount);
            Assert.Equal(payloadBefore, payloadAfter);
            Assert.Equal(MessageDeliveryState.Read, reloaded?.DeliveryState);
            Assert.Equal(readAt, reloaded?.ReadAt);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_DoesNotBlockCallerWhileDatabaseIsBusy()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-busy-{Guid.NewGuid():N}.db");
        var lockAcquired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseLock = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            using var store = new SqliteSessionStore(statePath);
            var lockTask = Task.Run(async () =>
            {
                try
                {
                    await using var connection = new SqliteConnection($"Data Source={statePath};Pooling=False");
                    await connection.OpenAsync();
                    await using var transaction = connection.BeginTransaction();
                    await using var command = connection.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandText = "UPDATE schema_meta SET version = version WHERE id = 1;";
                    await command.ExecuteNonQueryAsync();
                    lockAcquired.TrySetResult();
                    await releaseLock.Task;
                    await transaction.RollbackAsync();
                }
                catch (Exception exception)
                {
                    lockAcquired.TrySetException(exception);
                    throw;
                }
            });

            await lockAcquired.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
            var conversation = new Conversation(
                ConversationId.CreateGroupV2(),
                ConversationKind.GroupV2,
                "Busy database",
                ConversationSettings.Default(ConversationKind.GroupV2),
                now,
                now);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var writeTask = store.UpsertAsync(conversation);
            stopwatch.Stop();

            Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(250), $"Store call blocked for {stopwatch.Elapsed}.");
            Assert.False(writeTask.IsCompleted);

            releaseLock.TrySetResult();
            await writeTask.WaitAsync(TimeSpan.FromSeconds(2));
            await lockTask.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(conversation, await store.GetAsync(conversation.Id));
        }
        finally
        {
            releaseLock.TrySetResult();
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task StoreListsMessagesInConversationOrder()
    {
        var store = new InMemorySessionStore();
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(recipient);
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");

        await store.UpsertAsync(new Conversation(
            conversationId,
            ConversationKind.OneToOne,
            "Alice",
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now));

        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "second", MessageDirection.Outgoing, MessageDeliveryState.Sent, now.AddSeconds(2), []));
        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "first", MessageDirection.Outgoing, MessageDeliveryState.Sent, now.AddSeconds(1), []));

        var messages = new List<Message>();
        await foreach (var message in ((IMessageRepository)store).ListForConversationAsync(conversationId))
        {
            messages.Add(message);
        }

        Assert.Equal(["first", "second"], messages.Select(item => item.Body));
    }

    [Fact]
    public async Task LocalSchemaMigratorAppliesAllVersionsOnce()
    {
        var store = new InMemorySessionStore();
        var migrator = new LocalSchemaMigrator(LocalSchemaMigrations.Default);

        var version = await migrator.MigrateAsync(store);
        var secondRunVersion = await migrator.MigrateAsync(store);

        Assert.Equal(LocalSchemaMigrations.LatestVersion, version);
        Assert.Equal(version, secondRunVersion);
        Assert.Equal("sync-cursors", await store.GetSchemaValueAsync("schema.3"));
    }

    [Fact]
    public async Task PersistentSessionStore_ReloadsConversationMessageAndSchemaState()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-shared-{Guid.NewGuid():N}.json");
        try
        {
            var store = new InMemorySessionStore(statePath);
            var sender = SessionId.CreateNew();
            var recipient = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(recipient);
            var groupConversationId = ConversationId.CreateGroupV2();
            var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
            var messageId = MessageId.NewId();

            await store.UpsertAsync(new Conversation(
                conversationId,
                ConversationKind.OneToOne,
                "Persisted",
                ConversationSettings.Default(ConversationKind.OneToOne),
                now,
                now));
            await store.UpsertAsync(Contact.Self(sender, "Sender", now));
            await store.UpsertAsync(new Group(
                groupConversationId,
                "Persisted Group",
                sender,
                now,
                [new GroupMember(sender, GroupMemberRole.Admin, now)]));
            await store.AppendAsync(new Message(messageId, conversationId, sender, recipient, "hello", MessageDirection.Outgoing, MessageDeliveryState.Sent, now, []));
            await store.SetAsync("ui.theme", "ember");
            await store.SetSchemaVersionAsync(3);
            await store.SetSchemaValueAsync("schema.3", "sync-cursors");

            var recovered = new InMemorySessionStore(statePath);
            var conversation = await recovered.GetAsync(conversationId);
            var recoveredMessage = await recovered.GetAsync(messageId);
            var recoveredContact = await recovered.GetAsync(sender);
            var recoveredGroup = await ((IGroupRepository)recovered).GetAsync(groupConversationId);

            var messages = new List<Message>();
            await foreach (var item in ((IMessageRepository)recovered).ListForConversationAsync(conversationId))
            {
                messages.Add(item);
            }

            Assert.NotNull(conversation);
            Assert.Equal("Persisted", conversation!.DisplayName);
            Assert.NotNull(recoveredMessage);
            Assert.Equal("hello", recoveredMessage!.Body);
            Assert.NotNull(recoveredContact);
            Assert.Equal("Sender", recoveredContact!.DisplayName);
            Assert.NotNull(recoveredGroup);
            Assert.Equal("Persisted Group", recoveredGroup!.Name);
            Assert.Equal("ember", await recovered.GetAsync<string>("ui.theme"));
            Assert.Equal(3, await recovered.GetSchemaVersionAsync());
            Assert.Equal("sync-cursors", await recovered.GetSchemaValueAsync("schema.3"));
            Assert.Single(messages);
            Assert.Equal("hello", messages[0].Body);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_ReloadsConversationMessageAndSchemaState()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-shared-{Guid.NewGuid():N}.db");
        try
        {
            var store = new SqliteSessionStore(statePath);
            var sender = SessionId.CreateNew();
            var recipient = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(recipient);
            var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
            var messageId = MessageId.NewId();

            await store.UpsertAsync(new Conversation(
                conversationId,
                ConversationKind.OneToOne,
                "SQLite",
                ConversationSettings.Default(ConversationKind.OneToOne),
                now,
                now));
            await store.AppendAsync(new Message(messageId, conversationId, sender, recipient, "hello-sqlite", MessageDirection.Outgoing, MessageDeliveryState.Sent, now, []));
            await store.SetAsync("ui.theme", "cinder");
            await store.SetSchemaVersionAsync(7);
            await store.SetSchemaValueAsync("schema.7", "sqlite-cursors");

            var recovered = new SqliteSessionStore(statePath);
            var conversation = await recovered.GetAsync(conversationId);
            var recoveredMessage = await recovered.GetAsync(messageId);

            Assert.NotNull(conversation);
            Assert.Equal("SQLite", conversation!.DisplayName);
            Assert.NotNull(recoveredMessage);
            Assert.Equal("hello-sqlite", recoveredMessage!.Body);
            Assert.Equal("cinder", await recovered.GetAsync<string>("ui.theme"));
            Assert.Equal(7, await recovered.GetSchemaVersionAsync());
            Assert.Equal("sqlite-cursors", await recovered.GetSchemaValueAsync("schema.7"));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_DoesNotInterpretSqlLikeKeyInputAsExecutableSql()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-shared-{Guid.NewGuid():N}.db");
        try
        {
            var store = new SqliteSessionStore(statePath);
            const string maliciousKey = "schema.7'; DROP TABLE schema_values; --";
            await store.SetSchemaValueAsync(maliciousKey, "safe");
            await store.SetSchemaValueAsync("schema.safe", "still-there");

            Assert.Equal("safe", await store.GetSchemaValueAsync(maliciousKey));
            Assert.Equal("still-there", await store.GetSchemaValueAsync("schema.safe"));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_OpenOneToOneConversation_ReturnsEncryptedLocalSnapshot()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-shared-{Guid.NewGuid():N}.db");
        const string encryptionKey = "fast-open-test-key";
        try
        {
            var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
            var store = new SqliteSessionStore(new SqliteSessionStoreOptions(statePath, encryptionKey));
            var account = new SessionAccount(SessionId.CreateNew(), "Alice", now);
            var recipient = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(recipient);
            var message = new Message(
                MessageId.NewId(),
                conversationId,
                recipient,
                account.SessionId,
                "hello from sqlite",
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                now.AddSeconds(5),
                []);

            await store.SetAsync(LocalSettingsKeys.ActiveAccount, account);
            await store.AppendAsync(message);
            await store.AppendAsync(new Message(
                MessageId.NewId(),
                conversationId,
                recipient,
                account.SessionId,
                "expired",
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                now.AddSeconds(10),
                [],
                ExpiresAt: now.AddSeconds(30)));

            var snapshot = await store.OpenOneToOneConversationAsync(
                recipient,
                "Bob",
                messageLimit: 1,
                now: now.AddMinutes(1));

            Assert.NotNull(snapshot);
            Assert.Equal(account.SessionId, snapshot!.ActiveAccount.SessionId);
            Assert.Equal("Bob", snapshot.Conversation.DisplayName);
            Assert.Equal("Bob", snapshot.Contact?.DisplayName);
            Assert.Equal([message.Id], snapshot.RecentMessages.Select(item => item.Id));
            Assert.Equal(now.AddMinutes(1), snapshot.ReadAt);
            Assert.Equal(MessageDeliveryState.Read, snapshot.RecentMessages[0].DeliveryState);
            Assert.Equal(snapshot.ReadAt, snapshot.RecentMessages[0].ReadAt);
            Assert.Equal(
                now.AddMinutes(1).ToString("O", CultureInfo.InvariantCulture),
                await store.GetAsync<string>("sync.read-cursor." + conversationId.Value));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_OpenOneToOneConversation_DisplayNameHintDoesNotOverwriteExplicitRename()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-open-name-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(statePath);

            await AssertOpenDisplayNameHintDoesNotOverwriteExplicitRenameAsync(store, store);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task InMemorySessionStore_OpenOneToOneConversation_DisplayNameHintDoesNotOverwriteExplicitRename()
    {
        var store = new InMemorySessionStore();

        await AssertOpenDisplayNameHintDoesNotOverwriteExplicitRenameAsync(store, store);
    }

    [Fact]
    public void ClientRuntime_CreatePersistent_RequiresAnExplicitTransport()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-runtime-{Guid.NewGuid():N}.db");
        try
        {
            Assert.Throws<ArgumentNullException>(() => ClientRuntime.CreatePersistent(statePath));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public void ClientRuntime_ReleaseFlagsRejectUnauthenticatedTransport()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            new StubSessionBackend()));

        Assert.Contains("authenticated E2EE", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ClientRuntime_ReleaseFlagsWrapAuthenticatedTransportWithE2ee()
    {
        var runtime = new ClientRuntime(
            new InMemorySessionStore(),
            ClientFeatureFlags.ReleaseDefaults,
            new SystemClock(),
            new AuthenticatedTestTransport());

        Assert.IsType<E2eeClientTransport>(runtime.MessageTransport);
        runtime.Dispose();
        Assert.True(runtime.IsDisposed);
    }

    [Fact]
    public async Task ClientRuntime_CreatePersistent_PreservesRestoredAccountAcrossRestart()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-runtime-{Guid.NewGuid():N}.db");

        try
        {
            var runtime = ClientRuntime.CreatePersistent(statePath, backend: new StubSessionBackend());
            await runtime.Accounts.RegisterAsync("Recovered User");
            var recoveryPhrase = await runtime.Accounts.GetRecoveryPhraseAsync();
            await runtime.Accounts.LoginAsync(recoveryPhrase!, "Recovered User");
            var restoredAccount = await runtime.Accounts.GetActiveAccountAsync();

            var restarted = ClientRuntime.CreatePersistent(statePath, backend: new StubSessionBackend());
            var active = await restarted.Accounts.GetActiveAccountAsync();

            Assert.NotNull(active);
            Assert.NotNull(restoredAccount);
            Assert.Equal(restoredAccount!.SessionId, active!.SessionId);
            Assert.True(active.IsRestoredAccount);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task ClientRuntime_CreatePersistent_MigratesLegacyInMemorySnapshotWithoutDataLoss()
    {
        var legacyPath = Path.Combine(Path.GetTempPath(), $"deep-client-legacy-{Guid.NewGuid():N}.json");
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-runtime-{Guid.NewGuid():N}.db");

        try
        {
            var legacyStore = new InMemorySessionStore(legacyPath);
            var sender = SessionId.CreateNew();
            var recipient = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(recipient);
            var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
            var messageId = MessageId.NewId();

            await legacyStore.UpsertAsync(new Conversation(
                conversationId,
                ConversationKind.OneToOne,
                "Legacy",
                ConversationSettings.Default(ConversationKind.OneToOne),
                now,
                now));
            await legacyStore.AppendAsync(new Message(messageId, conversationId, sender, recipient, "legacy-message", MessageDirection.Outgoing, MessageDeliveryState.Sent, now, []));
            await legacyStore.SetSchemaVersionAsync(2);
            await legacyStore.SetSchemaValueAsync("schema.2", "attachment-pointer-metadata");

            var runtime = ClientRuntime.CreatePersistentForTests(sqlitePath, legacyInMemoryStatePath: legacyPath);
            var recoveredConversation = await ((IConversationRepository)runtime.Store).GetAsync(conversationId);
            var recoveredMessage = await ((IMessageRepository)runtime.Store).GetAsync(messageId);
            var schemaVersion = await runtime.Store.GetSchemaVersionAsync();

            Assert.NotNull(recoveredConversation);
            Assert.Equal("Legacy", recoveredConversation!.DisplayName);
            Assert.NotNull(recoveredMessage);
            Assert.Equal("legacy-message", recoveredMessage!.Body);
            Assert.True(schemaVersion >= LocalSchemaMigrations.LatestVersion);
            Assert.False(File.Exists(legacyPath));
            Assert.False(File.Exists(legacyPath + ".migrated.bak"));
        }
        finally
        {
            if (File.Exists(legacyPath))
            {
                File.Delete(legacyPath);
            }

            if (File.Exists(legacyPath + ".migrated.bak"))
            {
                File.Delete(legacyPath + ".migrated.bak");
            }

            DeleteSqliteFiles(sqlitePath);
        }
    }

    [Fact]
    public async Task StoresCountUnreadMessagesWithoutLoadingConversationHistory()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-unread-{Guid.NewGuid():N}.db");
        try
        {
            await AssertUnreadCountAsync(new InMemorySessionStore());
            await AssertUnreadCountAsync(new SqliteSessionStore(sqlitePath));
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
        }
    }

    [Fact]
    public async Task StoresPageMessagesWithStableCompositeCursor()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-paging-{Guid.NewGuid():N}.db");
        try
        {
            await AssertStableMessagePagingAsync(new InMemorySessionStore());
            await AssertStableMessagePagingAsync(new SqliteSessionStore(sqlitePath));
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
        }
    }

    private static async Task AssertStableMessagePagingAsync(ILocalSessionStore store)
    {
        var repository = (IMessageRepository)store;
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(recipient);
        var createdAt = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var now = createdAt.AddMinutes(1);

        foreach (var id in new[] { "a", "b", "c", "d", "e" })
        {
            await repository.AppendAsync(new Message(
                MessageId.Parse(id),
                conversationId,
                sender,
                recipient,
                id,
                MessageDirection.Outgoing,
                MessageDeliveryState.Sent,
                createdAt,
                []));
        }

        await repository.AppendAsync(new Message(
            MessageId.Parse("z"),
            conversationId,
            sender,
            recipient,
            "expired",
            MessageDirection.Outgoing,
            MessageDeliveryState.Sent,
            createdAt,
            [],
            ExpiresAt: createdAt.AddSeconds(1)));

        var recent = new List<Message>();
        await foreach (var message in repository.ListRecentForConversationAsync(conversationId, now, 2))
        {
            recent.Add(message);
        }

        var previous = new List<Message>();
        await foreach (var message in repository.ListBeforeForConversationAsync(
                           conversationId,
                           recent[0].CreatedAt,
                           recent[0].Id,
                           now,
                           2))
        {
            previous.Add(message);
        }

        var oldest = new List<Message>();
        await foreach (var message in repository.ListBeforeForConversationAsync(
                           conversationId,
                           previous[0].CreatedAt,
                           previous[0].Id,
                           now,
                           2))
        {
            oldest.Add(message);
        }

        Assert.Equal(["d", "e"], recent.Select(item => item.Body));
        Assert.Equal(["b", "c"], previous.Select(item => item.Body));
        Assert.Equal(["a"], oldest.Select(item => item.Body));
        Assert.Equal(["a", "b", "c", "d", "e"], oldest.Concat(previous).Concat(recent).Select(item => item.Body));
    }

    private static async Task AssertUnreadCountAsync(ILocalSessionStore store)
    {
        var repository = (IMessageRepository)store;
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(sender);
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var readCursor = now.AddMinutes(-10);

        await repository.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "old", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(-20), []));
        await repository.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "new", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(-5), []));
        await repository.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "read", MessageDirection.Incoming, MessageDeliveryState.Read, now.AddMinutes(-3), []));
        await repository.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "sent", MessageDirection.Outgoing, MessageDeliveryState.Sent, now.AddMinutes(-2), []));
        await repository.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "expired", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(-1), [], ExpiresAt: now.AddSeconds(-1)));

        var count = await repository.CountUnreadForConversationAsync(conversationId, readCursor, now);

        Assert.Equal(2, count);
    }

    [Fact]
    public async Task StoresConversationListSummariesInBatch()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-summary-{Guid.NewGuid():N}.db");
        try
        {
            await AssertConversationListSummaryAsync(new InMemorySessionStore());
            await AssertConversationListSummaryAsync(new SqliteSessionStore(sqlitePath));
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
        }
    }

    [Fact]
    public async Task SqliteConversationSummariesHandleFortyThousandRequestedConversations()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-large-summary-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(sqlitePath);
            var now = DateTimeOffset.Parse("2026-07-12T00:00:00Z");
            var conversationIds = Enumerable
                .Range(0, 40_000)
                .Select(static index => new ConversationId($"bulk-{index:D5}"))
                .ToArray();
            var populatedConversationId = conversationIds[20_000];
            await store.AppendAsync(new Message(
                MessageId.NewId(),
                populatedConversationId,
                SessionId.CreateNew(),
                SessionId.CreateNew(),
                "large batch unread",
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                now,
                []));

            var summaries = await store
                .GetConversationSummariesAsync(conversationIds, now.AddSeconds(1))
                .WaitAsync(TimeSpan.FromSeconds(30));

            Assert.Equal(conversationIds.Length, summaries.Count);
            Assert.Equal(1, summaries[populatedConversationId].UnreadCount);
            Assert.Equal("large batch unread", summaries[populatedConversationId].LastMessage?.Body);
            Assert.Equal(0, summaries[conversationIds[0]].UnreadCount);
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
        }
    }

    [Fact]
    public async Task StoresOpenConversationListAsSingleConsistentSnapshot()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-list-open-{Guid.NewGuid():N}.db");
        try
        {
            await AssertConversationListOpenSnapshotAsync(new InMemorySessionStore());
            await AssertConversationListOpenSnapshotAsync(new SqliteSessionStore(sqlitePath));
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
        }
    }

    private static async Task AssertConversationListOpenSnapshotAsync(ILocalSessionStore store)
    {
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var account = new SessionAccount(SessionId.CreateNew(), "Owner", now);
        var remote = SessionId.CreateNew();
        var conversation = new Conversation(
            ConversationId.ForOneToOne(remote),
            ConversationKind.OneToOne,
            "Remote",
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now);
        var message = new Message(
            MessageId.NewId(),
            conversation.Id,
            remote,
            account.SessionId,
            "snapshot message",
            MessageDirection.Incoming,
            MessageDeliveryState.Delivered,
            now,
            []);

        await store.SetAsync(LocalSettingsKeys.ActiveAccount, account);
        await store.UpsertAsync(conversation);
        await store.UpsertAsync(Contact.Request(remote, "Remote", now));
        await store.AppendAsync(message);

        var snapshot = await store.OpenConversationListAsync(now.AddSeconds(1));

        Assert.Equal(account, snapshot.ActiveAccount);
        Assert.Equal(conversation.Id, Assert.Single(snapshot.Conversations).Id);
        var summary = Assert.Single(snapshot.Summaries).Value;
        Assert.Equal(message.Id, summary.LastMessage?.Id);
        Assert.Equal(1, summary.UnreadCount);
        Assert.Equal("Remote", summary.Contact?.DisplayName);
    }

    private static async Task AssertOpenDisplayNameHintDoesNotOverwriteExplicitRenameAsync(
        ILocalSessionStore store,
        IOneToOneConversationOpenRepository openRepository)
    {
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var account = new SessionAccount(SessionId.CreateNew(), "Alice", now);
        var recipient = SessionId.CreateNew();
        await store.SetAsync(LocalSettingsKeys.ActiveAccount, account);

        var initial = await openRepository.OpenOneToOneConversationAsync(
            recipient,
            "Initial",
            messageLimit: 1,
            now: now);
        Assert.NotNull(initial);
        Assert.NotNull(initial!.Contact);
        Assert.Equal("Initial", initial.Conversation.DisplayName);
        Assert.Equal("Initial", initial.Contact!.DisplayName);

        var renamedAt = now.AddMinutes(1);
        await store.UpsertAsync(initial.Contact with { DisplayName = "Renamed", UpdatedAt = renamedAt });
        await store.UpsertAsync(initial.Conversation with { DisplayName = "Renamed", UpdatedAt = renamedAt });

        var reopened = await openRepository.OpenOneToOneConversationAsync(
            recipient,
            "Initial",
            messageLimit: 1,
            now: now.AddMinutes(2));
        var persistedContact = await ((IContactRepository)store).GetAsync(recipient);
        var persistedConversation = await ((IConversationRepository)store).GetAsync(initial.Conversation.Id);

        Assert.NotNull(reopened);
        Assert.Equal("Renamed", reopened!.Conversation.DisplayName);
        Assert.Equal("Renamed", reopened.Contact?.DisplayName);
        Assert.Equal("Renamed", persistedContact?.DisplayName);
        Assert.Equal("Renamed", persistedConversation?.DisplayName);
    }

    private static async Task AssertConversationListSummaryAsync(ILocalSessionStore store)
    {
        var sender = SessionId.CreateNew();
        var recipient = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(sender);
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        var readCursor = now.AddMinutes(-10);

        await store.UpsertAsync(new Conversation(
            conversationId,
            ConversationKind.OneToOne,
            "Alice",
            ConversationSettings.Default(ConversationKind.OneToOne),
            now,
            now));
        await store.UpsertAsync(Contact.Request(sender, "Alice", now));
        await store.SetAsync($"sync.read-cursor.{conversationId.Value}", readCursor.ToString("O"));
        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "old", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(-20), []));
        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "new", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(-5), []));
        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "sent", MessageDirection.Outgoing, MessageDeliveryState.Sent, now.AddMinutes(-2), []));
        await store.AppendAsync(new Message(MessageId.NewId(), conversationId, sender, recipient, "expired", MessageDirection.Incoming, MessageDeliveryState.Delivered, now.AddMinutes(1), [], ExpiresAt: now.AddSeconds(-1)));

        var summaries = await store.GetConversationSummariesAsync([conversationId], now);

        var summary = Assert.Single(summaries).Value;
        Assert.Equal(conversationId, summary.ConversationId);
        Assert.Equal(readCursor, summary.ReadCursor);
        Assert.Equal("sent", summary.LastMessage?.Body);
        Assert.Equal(2, summary.UnreadCount);
        Assert.Equal("Alice", summary.Contact?.DisplayName);
    }

    [Fact]
    public async Task SqliteSessionStore_MigratesPlaintextDatabaseToSqlCipher()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-encrypted-{Guid.NewGuid():N}.db");
        var encryptionKey = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var conversationId = ConversationId.CreateGroupV2();
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        try
        {
            using (var plaintext = new SqliteSessionStore(sqlitePath))
            {
                await plaintext.UpsertAsync(new Conversation(
                    conversationId,
                    ConversationKind.GroupV2,
                    "Encrypted",
                    ConversationSettings.Default(ConversationKind.GroupV2),
                    now,
                    now));
            }

            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);
            Assert.ThrowsAny<Exception>(() => new SqliteSessionStore(sqlitePath));

            var encrypted = new SqliteSessionStore(new SqliteSessionStoreOptions(sqlitePath, encryptionKey));
            var recovered = await encrypted.GetAsync(conversationId);

            Assert.NotNull(recovered);
            Assert.Equal("Encrypted", recovered!.DisplayName);
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
            DeleteSqliteFiles(sqlitePath + ".encrypted-migration");
            DeleteSqliteFiles(sqlitePath + ".plaintext-migration");
        }
    }

    [Fact]
    public async Task SqliteSessionStore_RecoversInterruptedMigrationFromPlaintextBackup()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-recover-backup-{Guid.NewGuid():N}.db");
        var encryptionKey = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var conversationId = ConversationId.CreateGroupV2();
        var backupPath = sqlitePath + ".plaintext-migration";
        try
        {
            await CreatePlaintextConversationAsync(sqlitePath, conversationId, "Recovered backup");
            File.Move(sqlitePath, backupPath);

            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);

            Assert.False(File.Exists(backupPath));
            await AssertEncryptedConversationAsync(sqlitePath, encryptionKey, conversationId, "Recovered backup");
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
            DeleteSqliteFiles(sqlitePath + ".encrypted-migration");
            DeleteSqliteFiles(backupPath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_RecoversInterruptedMigrationFromEncryptedTemp()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-recover-temp-{Guid.NewGuid():N}.db");
        var encryptionKey = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var conversationId = ConversationId.CreateGroupV2();
        var snapshotPath = sqlitePath + ".plaintext-snapshot";
        var tempPath = sqlitePath + ".encrypted-migration";
        var backupPath = sqlitePath + ".plaintext-migration";
        try
        {
            await CreatePlaintextConversationAsync(sqlitePath, conversationId, "Recovered temp");
            File.Copy(sqlitePath, snapshotPath);
            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);
            File.Move(sqlitePath, tempPath);
            File.Move(snapshotPath, backupPath);

            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);

            Assert.False(File.Exists(tempPath));
            Assert.False(File.Exists(backupPath));
            await AssertEncryptedConversationAsync(sqlitePath, encryptionKey, conversationId, "Recovered temp");
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
            DeleteSqliteFiles(tempPath);
            DeleteSqliteFiles(backupPath);
            DeleteSqliteFiles(snapshotPath);
        }
    }

    [Fact]
    public async Task SqliteSessionStore_RemovesPlaintextBackupAfterCompletedMigration()
    {
        var sqlitePath = Path.Combine(Path.GetTempPath(), $"deep-client-clean-backup-{Guid.NewGuid():N}.db");
        var encryptionKey = Convert.ToHexString(Guid.NewGuid().ToByteArray()).ToLowerInvariant();
        var conversationId = ConversationId.CreateGroupV2();
        var snapshotPath = sqlitePath + ".plaintext-snapshot";
        var backupPath = sqlitePath + ".plaintext-migration";
        try
        {
            await CreatePlaintextConversationAsync(sqlitePath, conversationId, "Clean backup");
            File.Copy(sqlitePath, snapshotPath);
            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);
            File.Move(snapshotPath, backupPath);

            SqliteSessionStore.EnsureEncryptedDatabase(sqlitePath, encryptionKey);

            Assert.False(File.Exists(backupPath));
            await AssertEncryptedConversationAsync(sqlitePath, encryptionKey, conversationId, "Clean backup");
        }
        finally
        {
            DeleteSqliteFiles(sqlitePath);
            DeleteSqliteFiles(sqlitePath + ".encrypted-migration");
            DeleteSqliteFiles(backupPath);
            DeleteSqliteFiles(snapshotPath);
        }
    }

    private static async Task CreatePlaintextConversationAsync(
        string sqlitePath,
        ConversationId conversationId,
        string displayName)
    {
        var now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");
        using var store = new SqliteSessionStore(sqlitePath);
        await store.UpsertAsync(new Conversation(
            conversationId,
            ConversationKind.GroupV2,
            displayName,
            ConversationSettings.Default(ConversationKind.GroupV2),
            now,
            now));
    }

    private static async Task AssertEncryptedConversationAsync(
        string sqlitePath,
        string encryptionKey,
        ConversationId conversationId,
        string expectedDisplayName)
    {
        using var encrypted = new SqliteSessionStore(new SqliteSessionStoreOptions(sqlitePath, encryptionKey));
        var recovered = await encrypted.GetAsync(conversationId);
        Assert.NotNull(recovered);
        Assert.Equal(expectedDisplayName, recovered!.DisplayName);
    }

    private static async Task<string> ReadRawMessagePayloadAsync(string statePath, MessageId messageId)
    {
        await using var connection = new SqliteConnection($"Data Source={statePath};Pooling=False");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT payload_json FROM messages WHERE id = $id;";
        command.Parameters.AddWithValue("$id", messageId.Value);
        return Assert.IsType<string>(await command.ExecuteScalarAsync());
    }

    private static void DeleteSqliteFiles(string statePath)
    {
        foreach (var path in new[] { statePath, statePath + "-wal", statePath + "-shm" })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class AuthenticatedTestTransport : ISessionMessageTransport, IAuthenticatedInboxTransport
    {
        public Task SendAsync(OutboundMessageEnvelope envelope, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAsync(
            SessionId recipient,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);

        public Task<IReadOnlyList<InboundMessageEnvelope>> ReceiveAuthenticatedAsync(
            SessionIdentityProvider identity,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<InboundMessageEnvelope>>([]);
    }
}
