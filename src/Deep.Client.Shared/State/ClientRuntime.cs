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
        bool requireE2eeTransport = false,
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null,
        IMailboxDeliveryPolicy? mailboxDeliveryPolicy = null,
        bool ownsMessageTransport = false)
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

        if (featureFlags.PersistentTransportOutboxEnabled)
        {
            if (store is not ITransportOutboxRepository outboxRepository)
            {
                throw new InvalidOperationException(
                    "PersistentTransportOutboxEnabled is enabled, but the configured store has no transport outbox repository.");
            }
            if (transportOutboxExecutor is null)
            {
                throw new InvalidOperationException(
                    "PersistentTransportOutboxEnabled is enabled, but no external killable transport outbox executor is configured.");
            }

            TransportOutbox = new TransportOutboxDispatcher(
                outboxRepository,
                transportOutboxExecutor,
                clock);
        }
        else if (transportOutboxExecutor is not null)
        {
            throw new InvalidOperationException(
                "A transport outbox executor was configured while PersistentTransportOutboxEnabled is disabled.");
        }

        var transportRequired = requireE2eeTransport || featureFlags.TransportRequired;
        if (transportRequired && messageTransport is not IAuthenticatedInboxTransport)
        {
            throw new InvalidOperationException(
                "TransportRequired is enabled, but the configured transport is not authenticated E2EE.");
        }

        if (featureFlags.MetadataPrivateTransportRequired &&
            !IsTrustedOpaqueTransport(messageTransport))
        {
            throw new InvalidOperationException(
                "MetadataPrivateTransportRequired is enabled, but the configured transport is not opaque P03.");
        }

        if (transportRequired)
        {
            if (mailboxDeliveryPolicy is null)
            {
                throw new InvalidOperationException(
                    "TransportRequired requires an explicit mailbox delivery policy.");
            }
            var encryptedTransport = new E2eeClientTransport(
                messageTransport,
                Accounts.GetRecoveryPhraseAsync,
                clock,
                Store,
                mailboxDeliveryPolicy,
                ownsMessageTransport);
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
        var accountLifecycles = new List<IAccountGenerationLifecycle>
        {
            mutationBarrier,
            Inbox,
            Messages
        };
        if (messageTransport is IAccountGenerationLifecycle transportLifecycle)
        {
            accountLifecycles.Add(transportLifecycle);
        }
        Accounts.RegisterAccountGenerationLifecycle(
            new CompositeAccountGenerationLifecycle(accountLifecycles));
        Sync = new SyncOrchestrator();
        Notifications = new NotificationPlanner();
    }

    public ILocalSessionStore Store { get; }

    public ClientFeatureFlags FeatureFlags { get; }

    public IClock Clock { get; }

    public ISessionMessageTransport MessageTransport { get; }

    public IGroupSyncTransport GroupSyncTransport { get; }

    public IAvatarProfileTransport AvatarProfiles { get; }

    public TransportOutboxDispatcher? TransportOutbox { get; }

    public SessionAccountService Accounts { get; }

    public ConversationService Conversations { get; }

    public MessageService Messages { get; }

    public InboxSyncService Inbox { get; }

    public SyncOrchestrator Sync { get; }

    public NotificationPlanner Notifications { get; }

    public bool IsDisposed => Volatile.Read(ref disposed) != 0;

    public static ClientRuntime CreateStubbed(
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        StubSessionBackend? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null) =>
        new(
            new InMemorySessionStore(),
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock ?? new SystemClock(),
            backend ?? new StubSessionBackend(),
            groupSyncTransport,
            avatarProfiles,
            transportOutboxExecutor: transportOutboxExecutor);

    public static ClientRuntime CreatePersistent(
        string statePath,
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        ISessionMessageTransport? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        string? sqlCipherKey = null,
        Func<ILocalSessionStore, ILocalSessionStore>? storeDecorator = null,
        bool requireE2eeTransport = false,
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null,
        IMailboxDeliveryPolicy? mailboxDeliveryPolicy = null,
        bool ownsMessageTransport = false)
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

        if ((requireE2eeTransport || resolvedFeatureFlags.TransportRequired) &&
            mailboxDeliveryPolicy is null)
        {
            throw new InvalidOperationException(
                "TransportRequired requires an explicit mailbox delivery policy.");
        }

        if (resolvedFeatureFlags.MetadataPrivateTransportRequired &&
            !IsTrustedOpaqueTransport(backend))
        {
            throw new InvalidOperationException(
                "MetadataPrivateTransportRequired is enabled, but the configured transport is not opaque P03.");
        }

        var store = new SqliteSessionStore(new SqliteSessionStoreOptions(statePath, sqlCipherKey));

        var runtimeStore = storeDecorator?.Invoke(store) ?? store;

        return new(
            runtimeStore,
            resolvedFeatureFlags,
            clock ?? new SystemClock(),
            backend,
            groupSyncTransport,
            avatarProfiles,
            requireE2eeTransport,
            transportOutboxExecutor,
            mailboxDeliveryPolicy,
            ownsMessageTransport);
    }

    public static ClientRuntime CreatePersistentForTests(
        string statePath,
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        StubSessionBackend? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        string? sqlCipherKey = null,
        Func<ILocalSessionStore, ILocalSessionStore>? storeDecorator = null,
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null) =>
        CreatePersistent(
            statePath,
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock,
            backend ?? new StubSessionBackend(),
            groupSyncTransport,
            avatarProfiles,
            sqlCipherKey,
            storeDecorator,
            requireE2eeTransport: false,
            transportOutboxExecutor);

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

    private static bool IsTrustedOpaqueTransport(ISessionMessageTransport transport) =>
        transport switch
        {
            SessionStorageMessageTransport direct => direct.UsesOpaqueMetadata,
            RoutedSessionStorageMessageTransport routed => routed.UsesOpaqueMetadata,
            IMetadataPrivateSessionMessageTransport opaque => opaque.UsesMetadataPrivateTransport,
            _ => false
        };
}
