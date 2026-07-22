using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.State;

public sealed class ClientRuntime : IDisposable
{
    private readonly IDisposable? ownedMessageTransport;
    private readonly AccountGenerationMutationBarrier mutationBarrier;
    private int disposed;

    public ClientRuntime(
        ILocalSessionStore store,
        ClientFeatureFlags featureFlags,
        IClock clock,
        ISessionMessageTransport messageTransport,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        bool requireE2eeTransport = false)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(featureFlags);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(messageTransport);

        mutationBarrier = new AccountGenerationMutationBarrier();
        Store = AccountGenerationSessionStore.Create(store, mutationBarrier);
        FeatureFlags = featureFlags;
        Clock = clock;
        AvatarProfiles = avatarProfiles ?? new DisabledAvatarProfileTransport();
        Accounts = new SessionAccountService(store, store, clock, messageTransport as IRecoveryProfileLookup);

        var transportRequired = requireE2eeTransport || featureFlags.TransportRequired;
        if (transportRequired && messageTransport is not IAuthenticatedInboxTransport)
        {
            throw new InvalidOperationException(
                "TransportRequired is enabled, but the configured transport is not authenticated E2EE.");
        }

        if (featureFlags.MetadataPrivateTransportRequired &&
            (messageTransport is not IMetadataPrivateSessionTransport metadataTransport ||
             !metadataTransport.UsesOpaqueMetadata))
        {
            throw new InvalidOperationException(
                "MetadataPrivateTransportRequired is enabled, but the configured transport is not opaque P03.");
        }

        if (transportRequired)
        {
            var encryptedTransport = new E2eeClientTransport(
                messageTransport,
                Accounts.GetRecoveryPhraseAsync,
                clock,
                Store);
            MessageTransport = encryptedTransport;
            GroupSyncTransport = encryptedTransport;
            ownedMessageTransport = encryptedTransport;
            Accounts.AccountStateChanged += encryptedTransport.RetireCachedIdentity;
        }
        else
        {
            MessageTransport = messageTransport;
            GroupSyncTransport = groupSyncTransport ?? new DisabledGroupSyncTransport();
        }

        Conversations = new ConversationService(Store, Store, Store, Store, clock, featureFlags, GroupSyncTransport);
        Messages = new MessageService(Conversations, Store, Store, Store, MessageTransport, GroupSyncTransport, clock);
        Inbox = new InboxSyncService(Accounts, Conversations, Messages);
        Accounts.RegisterAccountGenerationLifecycle(
            new CompositeAccountGenerationLifecycle(mutationBarrier, Inbox, Messages));
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

    public bool IsDisposed => Volatile.Read(ref disposed) != 0;

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
        string? sqlCipherKey = null,
        Func<ILocalSessionStore, ILocalSessionStore>? storeDecorator = null,
        bool requireE2eeTransport = false)
    {
        var resolvedFeatureFlags = featureFlags ?? ClientFeatureFlags.Defaults;
        if (backend is null)
        {
            throw new ArgumentNullException(
                nameof(backend),
                "A transport must be supplied explicitly. Use CreatePersistentForTests for a named stubbed test runtime.");
        }

        if ((requireE2eeTransport || resolvedFeatureFlags.TransportRequired) &&
            backend is not IAuthenticatedInboxTransport)
        {
            throw new InvalidOperationException(
                "TransportRequired is enabled, but the configured transport is not authenticated E2EE.");
        }

        if (resolvedFeatureFlags.MetadataPrivateTransportRequired &&
            (backend is not IMetadataPrivateSessionTransport metadataTransport ||
             !metadataTransport.UsesOpaqueMetadata))
        {
            throw new InvalidOperationException(
                "MetadataPrivateTransportRequired is enabled, but the configured transport is not opaque P03.");
        }

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

        var runtimeStore = storeDecorator?.Invoke(store) ?? store;

        return new(
            runtimeStore,
            resolvedFeatureFlags,
            clock ?? new SystemClock(),
            backend,
            groupSyncTransport,
            avatarProfiles,
            requireE2eeTransport);
    }

    public static ClientRuntime CreatePersistentForTests(
        string statePath,
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        StubSessionBackend? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        string? legacyInMemoryStatePath = null,
        string? sqlCipherKey = null,
        Func<ILocalSessionStore, ILocalSessionStore>? storeDecorator = null) =>
        CreatePersistent(
            statePath,
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock,
            backend ?? new StubSessionBackend(),
            groupSyncTransport,
            avatarProfiles,
            legacyInMemoryStatePath,
            sqlCipherKey,
            storeDecorator,
            requireE2eeTransport: false);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        Inbox.Dispose();
        mutationBarrier.Dispose();
        ownedMessageTransport?.Dispose();
        if (Store is IDisposable disposableStore)
        {
            disposableStore.Dispose();
        }
    }
}
