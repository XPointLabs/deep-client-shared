using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ConversationServiceTests
{
    [Fact]
    public async Task UpdateContactDisplayName_PersistsContactAndConversationTitle()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var contactId = SessionId.Parse("05" + new string('1', 64));

        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(
            contactId,
            "Initial Name",
            approve: true);

        var updated = await runtime.Conversations.UpdateContactDisplayNameAsync(contactId, "Renamed Contact");
        var contact = await ((IContactRepository)runtime.Store).GetAsync(contactId);
        var refreshed = await runtime.Conversations.GetOrCreateOneToOneAsync(contactId);

        Assert.Equal("Renamed Contact", updated.DisplayName);
        Assert.Equal("Renamed Contact", contact?.DisplayName);
        Assert.Equal(conversation.Id, refreshed.Id);
        Assert.Equal("Renamed Contact", refreshed.DisplayName);
    }

    [Fact]
    public async Task GetOrCreateOneToOne_DisplayNameHintDoesNotOverwriteExplicitRename()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var contactId = SessionId.Parse("05" + new string('5', 64));

        var initial = await runtime.Conversations.GetOrCreateOneToOneAsync(contactId, "Initial", approve: true);
        await runtime.Conversations.UpdateContactDisplayNameAsync(contactId, "Renamed");

        var reopened = await runtime.Conversations.GetOrCreateOneToOneAsync(contactId, "Initial", approve: true);
        var contact = await ((IContactRepository)runtime.Store).GetAsync(contactId);

        Assert.Equal("Initial", initial.DisplayName);
        Assert.Equal("Renamed", reopened.DisplayName);
        Assert.Equal("Renamed", contact?.DisplayName);
    }

    [Fact]
    public async Task UpdateContactDisplayName_PersistsThroughSqliteStore()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-contact-{Guid.NewGuid():N}.db");
        try
        {
            using var store = new SqliteSessionStore(statePath);
            using var runtime = ClientRuntime.CreatePersistentForTests(
                statePath,
                clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
            var contactId = SessionId.Parse("05" + new string('2', 64));

            await runtime.Conversations.GetOrCreateOneToOneAsync(contactId, "Initial", approve: true);
            await runtime.Conversations.UpdateContactDisplayNameAsync(contactId, "SQLite Name");

            using var reopened = new SqliteSessionStore(statePath);
            var persistedContact = await ((IContactRepository)reopened).GetAsync(contactId);
            var persistedConversation = await ((IConversationRepository)reopened).GetAsync(ConversationId.ForOneToOne(contactId));

            Assert.NotNull(store);
            Assert.Equal("SQLite Name", persistedContact?.DisplayName);
            Assert.Equal("SQLite Name", persistedConversation?.DisplayName);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { statePath, statePath + "-wal", statePath + "-shm" })
            {
                if (File.Exists(candidate))
                {
                    File.Delete(candidate);
                }
            }
        }
    }

    [Fact]
    public async Task RawSessionIdDisplayName_IsNotStoredAsContactName()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var contactId = SessionId.Parse("05" + new string('3', 64));

        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(
            contactId,
            contactId.Value,
            approve: true);
        var contact = await ((IContactRepository)runtime.Store).GetAsync(contactId);

        Assert.Null(contact?.DisplayName);
        Assert.Equal(contactId.Value, conversation.DisplayName);
    }

    [Fact]
    public async Task GeneratedFallbackDisplayName_IsNotStoredAsContactName()
    {
        var runtime = ClientRuntime.CreateStubbed(clock: new FrozenClock(DateTimeOffset.Parse("2026-05-28T00:00:00Z")));
        var contactId = SessionId.Parse("05" + new string('4', 58) + "765d4b");

        var conversation = await runtime.Conversations.GetOrCreateOneToOneAsync(
            contactId,
            "Deep 765d4b",
            approve: true);
        var contact = await ((IContactRepository)runtime.Store).GetAsync(contactId);

        Assert.Null(contact?.DisplayName);
        Assert.Equal(contactId.Value, conversation.DisplayName);
    }
}
