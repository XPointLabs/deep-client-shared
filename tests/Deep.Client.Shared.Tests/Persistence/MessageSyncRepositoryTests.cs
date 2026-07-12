using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Microsoft.Data.Sqlite;
using System.Text.Json;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class MessageSyncRepositoryTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-11T00:00:00Z");

    [Fact]
    public async Task Stores_UseAddressedSyncQueriesAndDoNotAdvanceAnAlreadyReadCursor()
    {
        await ForEachStoreAsync(async (store, syncRepository) =>
        {
            var account = SessionId.CreateNew();
            var remote = SessionId.CreateNew();
            var conversationId = ConversationId.ForOneToOne(remote);
            var selfConversationId = ConversationId.ForOneToOne(account);
            var attachment = new AttachmentMetadata("a-1", "one.txt", "text/plain", 3);

            var selfOutgoing = new Message(
                MessageId.NewId(),
                selfConversationId,
                account,
                account,
                "self",
                MessageDirection.Outgoing,
                MessageDeliveryState.Sent,
                Now,
                [attachment]);
            var selfDuplicate = selfOutgoing with
            {
                Id = MessageId.NewId(),
                Direction = MessageDirection.Incoming,
                DeliveryState = MessageDeliveryState.Delivered
            };
            var incoming = new Message(
                MessageId.NewId(),
                conversationId,
                remote,
                account,
                "indexed",
                MessageDirection.Incoming,
                MessageDeliveryState.Delivered,
                Now.AddSeconds(1),
                [],
                ServerHash: "indexed-server-hash");
            var firstPending = new Message(
                MessageId.NewId(),
                conversationId,
                account,
                remote,
                "first pending",
                MessageDirection.Outgoing,
                MessageDeliveryState.Failed,
                Now.AddSeconds(2),
                []);
            var secondPending = firstPending with
            {
                Id = MessageId.NewId(),
                Body = "second pending",
                DeliveryState = MessageDeliveryState.Sending,
                CreatedAt = Now.AddSeconds(3)
            };

            foreach (var message in new[] { selfOutgoing, selfDuplicate, incoming, firstPending, secondPending })
            {
                await store.AppendAsync(message);
            }

            Assert.True(await syncRepository.ContainsServerHashAsync(conversationId, incoming.ServerHash!));
            Assert.False(await syncRepository.ContainsServerHashAsync(conversationId, "missing"));
            Assert.True(await syncRepository.ContainsMatchingSelfOutgoingAsync(
                selfConversationId,
                account,
                selfDuplicate.CreatedAt,
                selfDuplicate.Body,
                selfDuplicate.Attachments));
            Assert.Equal(1, await syncRepository.DeleteDuplicateSelfIncomingAsync(selfConversationId, account));
            Assert.Equal([firstPending.Id, secondPending.Id],
                (await syncRepository.ListPendingOutgoingAsync(account)).Select(static message => message.Id));

            var firstReadAt = Now.AddMinutes(1);
            var firstRead = await syncRepository.MarkConversationReadIfUnreadAsync(conversationId, firstReadAt);
            var persistedCursor = await store.GetAsync<string>($"sync.read-cursor.{conversationId.Value}");
            var repeatedRead = await syncRepository.MarkConversationReadIfUnreadAsync(
                conversationId,
                firstReadAt.AddMinutes(5));

            Assert.Equal(1, firstRead.ChangedMessageCount);
            Assert.Equal(firstReadAt, firstRead.ReadCursor);
            Assert.Equal(0, repeatedRead.ChangedMessageCount);
            Assert.Equal(firstReadAt, repeatedRead.ReadCursor);
            Assert.Equal(persistedCursor, await store.GetAsync<string>($"sync.read-cursor.{conversationId.Value}"));
        });
    }

    [Fact]
    public void SqliteStore_CreatesAllMessageSyncIndexes()
    {
        var statePath = NewSqlitePath();
        try
        {
            using (var store = new SqliteSessionStore(statePath))
            {
            }

            using (var connection = new SqliteConnection($"Data Source={statePath};Pooling=False"))
            {
                connection.Open();
                using var versionCommand = connection.CreateCommand();
                versionCommand.CommandText = "PRAGMA user_version;";
                Assert.Equal(6L, (long)versionCommand.ExecuteScalar()!);

                using var columnsCommand = connection.CreateCommand();
                columnsCommand.CommandText = "PRAGMA table_info(messages);";
                using var columnsReader = columnsCommand.ExecuteReader();
                var columns = new HashSet<string>(StringComparer.Ordinal);
                while (columnsReader.Read())
                {
                    columns.Add(columnsReader.GetString(1));
                }

                Assert.Contains("read_at", columns);

                using var indexCommand = connection.CreateCommand();
                indexCommand.CommandText = "PRAGMA index_list(messages);";
                using var reader = indexCommand.ExecuteReader();
                var indexes = new HashSet<string>(StringComparer.Ordinal);
                while (reader.Read())
                {
                    indexes.Add(reader.GetString(1));
                }

                Assert.Contains("idx_messages_server_hash", indexes);
                Assert.Contains("idx_messages_self_echo", indexes);
                Assert.Contains("idx_messages_pending_outgoing", indexes);
                Assert.Contains("idx_messages_unread", indexes);
            }
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteStore_UpgradesVersion4MessagesAndBackfillsSyncKeys()
    {
        var statePath = NewSqlitePath();
        var account = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(account);
        var legacyMessage = new Message(
            MessageId.NewId(),
            conversationId,
            account,
            account,
            "legacy pending",
            MessageDirection.Outgoing,
            MessageDeliveryState.Failed,
            Now,
            [],
            ServerHash: "legacy-server-hash");
        try
        {
            using (var connection = new SqliteConnection($"Data Source={statePath};Pooling=False"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE messages (
                        id TEXT PRIMARY KEY,
                        conversation_id TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        direction INTEGER NOT NULL,
                        delivery_state INTEGER NOT NULL,
                        expires_at TEXT NULL,
                        payload_json TEXT NOT NULL);
                    INSERT INTO messages (
                        id, conversation_id, created_at, direction, delivery_state, expires_at, payload_json)
                    VALUES (
                        $id, $conversationId, $createdAt, $direction, $deliveryState, NULL, $payload);
                    PRAGMA user_version=4;
                    """;
                command.Parameters.AddWithValue("$id", legacyMessage.Id.Value);
                command.Parameters.AddWithValue("$conversationId", legacyMessage.ConversationId.Value);
                command.Parameters.AddWithValue("$createdAt", legacyMessage.CreatedAt.ToUnixTimeMilliseconds());
                command.Parameters.AddWithValue("$direction", (int)legacyMessage.Direction);
                command.Parameters.AddWithValue("$deliveryState", (int)legacyMessage.DeliveryState);
                command.Parameters.AddWithValue(
                    "$payload",
                    JsonSerializer.Serialize(legacyMessage, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
                command.ExecuteNonQuery();
            }

            using (var store = new SqliteSessionStore(statePath))
            {
                Assert.True(await store.ContainsServerHashAsync(conversationId, legacyMessage.ServerHash!));
                Assert.True(await store.ContainsMatchingSelfOutgoingAsync(
                    conversationId,
                    account,
                    legacyMessage.CreatedAt,
                    legacyMessage.Body,
                    legacyMessage.Attachments));
                Assert.Equal(legacyMessage.Id, Assert.Single(await store.ListPendingOutgoingAsync(account)).Id);
            }
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static async Task ForEachStoreAsync(
        Func<ILocalSessionStore, IMessageSyncRepository, Task> assertion)
    {
        var inMemory = new InMemorySessionStore();
        await assertion(inMemory, inMemory);

        var statePath = NewSqlitePath();
        try
        {
            using var sqlite = new SqliteSessionStore(statePath);
            await assertion(sqlite, sqlite);
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static string NewSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-message-sync-{Guid.NewGuid():N}.db");

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
