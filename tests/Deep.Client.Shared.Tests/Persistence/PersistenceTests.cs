using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class PersistenceTests
{
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
    public void ClientRuntime_CreatePersistent_UsesSqliteStore_AndHttpTransportByDefault()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-runtime-{Guid.NewGuid():N}.db");
        try
        {
            var runtime = ClientRuntime.CreatePersistent(statePath);
            Assert.IsType<SqliteSessionStore>(runtime.Store);
            Assert.IsType<HttpSessionTransport>(runtime.MessageTransport);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
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

            var runtime = ClientRuntime.CreatePersistent(sqlitePath, legacyInMemoryStatePath: legacyPath);
            var recoveredConversation = await ((IConversationRepository)runtime.Store).GetAsync(conversationId);
            var recoveredMessage = await ((IMessageRepository)runtime.Store).GetAsync(messageId);
            var schemaVersion = await runtime.Store.GetSchemaVersionAsync();

            Assert.NotNull(recoveredConversation);
            Assert.Equal("Legacy", recoveredConversation!.DisplayName);
            Assert.NotNull(recoveredMessage);
            Assert.Equal("legacy-message", recoveredMessage!.Body);
            Assert.True(schemaVersion >= LocalSchemaMigrations.LatestVersion);
            Assert.True(File.Exists(legacyPath + ".migrated.bak"));
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

        Assert.Equal(1, count);
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
        Assert.Equal(1, summary.UnreadCount);
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
            var plaintext = new SqliteSessionStore(sqlitePath);
            await plaintext.UpsertAsync(new Conversation(
                conversationId,
                ConversationKind.GroupV2,
                "Encrypted",
                ConversationSettings.Default(ConversationKind.GroupV2),
                now,
                now));

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
}
