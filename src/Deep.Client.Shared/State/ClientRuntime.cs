using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.State;

public sealed class ClientRuntime
{
    public ClientRuntime(
        ILocalSessionStore store,
        ClientFeatureFlags featureFlags,
        IClock clock,
        ISessionMessageTransport messageTransport,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null)
    {
        Store = store;
        FeatureFlags = featureFlags;
        Clock = clock;
        MessageTransport = messageTransport;
        GroupSyncTransport = groupSyncTransport ?? new DisabledGroupSyncTransport();
        AvatarProfiles = avatarProfiles ?? new DisabledAvatarProfileTransport();
        Accounts = new SessionAccountService(store, store, clock, messageTransport as IRecoveryProfileLookup);
        Conversations = new ConversationService(store, store, store, store, clock, featureFlags, GroupSyncTransport);
        Messages = new MessageService(Conversations, store, store, store, messageTransport, GroupSyncTransport, clock);
        Inbox = new InboxSyncService(Accounts, Conversations, Messages);
        Sync = new SyncOrchestrator();
        Notifications = new NotificationPlanner();
        Migrations = new LocalSchemaMigrator(LocalSchemaMigrations.Default);
    }

    public ILocalSessionStore Store { get; }

    public ClientFeatureFlags FeatureFlags { get; }

    public IClock Clock { get; }

    public ISessionMessageTransport MessageTransport { get; }

    public IGroupSyncTransport GroupSyncTransport { get; }

    public IAvatarProfileTransport AvatarProfiles { get; }

    public SessionAccountService Accounts { get; }

    public ConversationService Conversations { get; }

    public MessageService Messages { get; }

    public InboxSyncService Inbox { get; }

    public SyncOrchestrator Sync { get; }

    public NotificationPlanner Notifications { get; }

    public LocalSchemaMigrator Migrations { get; }

    public static ClientRuntime CreateStubbed(
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        StubSessionBackend? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null) =>
        new(
            new InMemorySessionStore(),
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock ?? new SystemClock(),
            backend ?? new StubSessionBackend(),
            groupSyncTransport,
            avatarProfiles);

    public static ClientRuntime CreatePersistent(
        string statePath,
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        ISessionMessageTransport? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        string? legacyInMemoryStatePath = null,
        string? sqlCipherKey = null)
    {
        var store = new SqliteSessionStore(new SqliteSessionStoreOptions(statePath, sqlCipherKey));
        if (!string.IsNullOrWhiteSpace(legacyInMemoryStatePath))
        {
            LocalStateMigration
                .MigrateLegacyInMemorySnapshotAsync(legacyInMemoryStatePath, store)
                .GetAwaiter()
                .GetResult();
        }

        new LocalSchemaMigrator(LocalSchemaMigrations.Default)
            .MigrateAsync(store)
            .GetAwaiter()
            .GetResult();

        var transport = backend ?? new HttpSessionTransport(
            new HttpClient(),
            new HttpSessionTransportOptions("http://127.0.0.1:8080"));

        return new(
            store,
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock ?? new SystemClock(),
            transport,
            groupSyncTransport,
            avatarProfiles);
    }
}
