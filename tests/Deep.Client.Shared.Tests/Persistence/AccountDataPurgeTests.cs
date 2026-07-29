using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.State;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class AccountDataPurgeTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-05-28T00:00:00Z");

    [Fact]
    public async Task SignOut_PurgesAccountStateBeforeAnotherAccountUsesTheSameRuntime()
    {
        var innerStore = new InMemorySessionStore();
        using var runtime = new ClientRuntime(
            innerStore,
            ClientFeatureFlags.Defaults,
            new FrozenClock(Now),
            new StubSessionBackend());
        var oldState = await PopulateAccountStateAsync(runtime);

        await runtime.Accounts.SignOutAsync();

        await AssertAccountStatePurgedAsync(innerStore, oldState, verifyReplayClaim: false);
        var secondAccount = await runtime.Accounts.RegisterAsync("Bob");

        await AssertReplayStatePurgedAsync(runtime.Store, oldState);

        Assert.NotEqual(oldState.Account.SessionId, secondAccount.SessionId);
        Assert.Empty(await ToListAsync(((IConversationRepository)runtime.Store).ListAsync()));
        Assert.Empty(await ToListAsync(((IGroupRepository)runtime.Store).ListAsync()));
        Assert.DoesNotContain(
            await ToListAsync(((IContactRepository)runtime.Store).ListAsync()),
            contact => contact.Id == oldState.Account.SessionId);
    }

    [Fact]
    public async Task SqliteSignOut_PurgesAccountStateAcrossRestartAndPreservesSchemaMetadata()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-account-purge-{Guid.NewGuid():N}.db");
        try
        {
            AccountState oldState;
            ILocalSessionStore? innerStore = null;
            using (var runtime = ClientRuntime.CreatePersistentForTests(
                       statePath,
                       clock: new FrozenClock(Now),
                       backend: new StubSessionBackend(),
                       storeDecorator: store => innerStore = store))
            {
                oldState = await PopulateAccountStateAsync(runtime);
                await runtime.Accounts.SignOutAsync();
                await AssertAccountStatePurgedAsync(
                    innerStore ?? throw new InvalidOperationException("The SQLite store was not captured."),
                    oldState,
                    verifyReplayClaim: false);
            }

            using var restarted = ClientRuntime.CreatePersistentForTests(
                statePath,
                clock: new FrozenClock(Now),
                backend: new StubSessionBackend());

            await AssertAccountStatePurgedAsync(restarted.Store, oldState, verifyReplayClaim: false);
            var secondAccount = await restarted.Accounts.RegisterAsync("Bob");

            await AssertReplayStatePurgedAsync(restarted.Store, oldState);

            Assert.NotNull(secondAccount);
            Assert.Empty(await ToListAsync(((IConversationRepository)restarted.Store).ListAsync()));
            Assert.Empty(await ToListAsync(((IGroupRepository)restarted.Store).ListAsync()));
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    [Fact]
    public async Task SqliteSignOut_DoesNotReportCancellationAfterPurgeCommit()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-client-account-purge-commit-{Guid.NewGuid():N}.db");
        try
        {
            using var runtime = ClientRuntime.CreatePersistentForTests(
                statePath,
                clock: new FrozenClock(Now),
                backend: new StubSessionBackend());
            await runtime.Accounts.RegisterAsync("Alice");

            await using var blockingConnection = new SqliteConnection(ReadOnlyConnectionString(statePath));
            await blockingConnection.OpenAsync();
            await using var blockingTransaction = blockingConnection.BeginTransaction();
            await using var blockingCommand = blockingConnection.CreateCommand();
            blockingCommand.Transaction = blockingTransaction;
            blockingCommand.CommandText = "SELECT payload_json FROM settings WHERE key = $key;";
            blockingCommand.Parameters.AddWithValue("$key", LocalSettingsKeys.ActiveAccount);
            await using var blockingReader = await blockingCommand.ExecuteReaderAsync();
            Assert.True(await blockingReader.ReadAsync());

            using var cancellation = new CancellationTokenSource();
            var signOut = runtime.Accounts.SignOutAsync(cancellation.Token);
            await WaitForSettingDeletionAsync(
                statePath,
                LocalSettingsKeys.ActiveAccount,
                TimeSpan.FromSeconds(5));

            Assert.False(signOut.IsCompleted);
            cancellation.Cancel();
            await Task.Delay(100);
            await blockingReader.DisposeAsync();
            await blockingTransaction.RollbackAsync();

            await signOut.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Null(await runtime.Accounts.GetActiveAccountAsync());
            Assert.Null(await runtime.Accounts.GetRecoveryPhraseAsync());
        }
        finally
        {
            DeleteSqliteFiles(statePath);
        }
    }

    private static async Task<AccountState> PopulateAccountStateAsync(ClientRuntime runtime)
    {
        var store = runtime.Store;
        var account = await runtime.Accounts.RegisterAsync("Alice");
        var counterpart = SessionId.CreateNew();
        var conversationId = ConversationId.ForOneToOne(counterpart);
        var groupId = ConversationId.CreateGroupV2();
        var messageId = MessageId.NewId();

        await store.UpsertAsync(new Conversation(
            conversationId,
            ConversationKind.OneToOne,
            "Counterpart",
            ConversationSettings.Default(ConversationKind.OneToOne),
            Now,
            Now));
        await store.UpsertAsync(Contact.Request(counterpart, "Counterpart", Now));
        await store.UpsertAsync(new Group(
            groupId,
            "Old group",
            account.SessionId,
            Now,
            [new GroupMember(account.SessionId, GroupMemberRole.Admin, Now)]));
        await store.AppendAsync(new Message(
            messageId,
            conversationId,
            account.SessionId,
            counterpart,
            "old account message",
            MessageDirection.Outgoing,
            MessageDeliveryState.Sent,
            Now,
            []));
        await store.TryClaimAsync(counterpart, messageId, Digest, Now.AddDays(1));
        await store.SetAsync("account.test-setting", "old-account");

        return new AccountState(account, counterpart, conversationId, groupId, messageId);
    }

    private static async Task AssertAccountStatePurgedAsync(
        ILocalSessionStore store,
        AccountState oldState,
        bool verifyReplayClaim = true)
    {
        Assert.Null(await store.GetAsync<SessionAccount>(LocalSettingsKeys.ActiveAccount));
        Assert.Null(await store.GetAsync<string>(LocalSettingsKeys.ActiveRecoveryPhrase));
        Assert.Null(await store.GetAsync<string>("account.test-setting"));
        Assert.Empty(await ToListAsync(((IConversationRepository)store).ListAsync()));
        Assert.Empty(await ToListAsync(((IContactRepository)store).ListAsync()));
        Assert.Empty(await ToListAsync(((IGroupRepository)store).ListAsync()));
        Assert.Null(await ((IConversationRepository)store).GetAsync(oldState.ConversationId));
        Assert.Null(await ((IContactRepository)store).GetAsync(oldState.Counterpart));
        Assert.Null(await ((IGroupRepository)store).GetAsync(oldState.GroupId));
        Assert.Null(await ((IMessageRepository)store).GetAsync(oldState.MessageId));
        Assert.Empty(await ToListAsync(((IMessageRepository)store).ListForConversationAsync(oldState.ConversationId)));

        if (verifyReplayClaim)
        {
            await AssertReplayStatePurgedAsync(store, oldState);
        }
    }

    private static async Task AssertReplayStatePurgedAsync(ILocalSessionStore store, AccountState oldState)
    {
        var replayResult = await store.TryClaimAsync(
            oldState.Counterpart,
            oldState.MessageId,
            Digest,
            Now.AddDays(1));
        Assert.Equal(MessageReplayClaimResult.Accepted, replayResult);
    }

    private static async Task<List<T>> ToListAsync<T>(IAsyncEnumerable<T> source)
    {
        var values = new List<T>();
        await foreach (var item in source)
        {
            values.Add(item);
        }

        return values;
    }

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

    private static async Task WaitForSettingDeletionAsync(
        string statePath,
        string key,
        TimeSpan timeout)
    {
        using var timeoutCancellation = new CancellationTokenSource(timeout);
        await using var connection = new SqliteConnection(ReadOnlyConnectionString(statePath));
        await connection.OpenAsync(timeoutCancellation.Token);
        while (true)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM settings WHERE key = $key;";
            command.Parameters.AddWithValue("$key", key);
            var count = Convert.ToInt32(
                await command.ExecuteScalarAsync(timeoutCancellation.Token),
                System.Globalization.CultureInfo.InvariantCulture);
            if (count == 0)
            {
                return;
            }

            await Task.Delay(10, timeoutCancellation.Token);
        }
    }

    private static string ReadOnlyConnectionString(string statePath) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = statePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false
        }.ToString();

    private sealed record AccountState(
        SessionAccount Account,
        SessionId Counterpart,
        ConversationId ConversationId,
        ConversationId GroupId,
        MessageId MessageId);
}
