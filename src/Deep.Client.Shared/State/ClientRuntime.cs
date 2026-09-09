using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.GroupV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.GroupV1;

namespace Deep.Client.Shared.State;

public sealed class ClientRuntime : IDisposable, IAsyncDisposable
{
    private readonly IDisposable? ownedMessageTransport;
    private readonly MessageNetworkRuntime messageNetwork;
    private readonly AccountGenerationMutationBarrier mutationBarrier;
    private readonly TaskCompletionSource<bool> disposalCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
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
        bool ownsMessageTransport = false,
        IMessageDispatchFailureObserver? messageDispatchFailureObserver = null,
        IGroupMailboxRouteExchange? groupMailboxRoutes = null,
        MessagingV1PersistenceOptions? messagingV1Persistence = null,
        SqliteGroupStateStore? groupV1StateStore = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(featureFlags);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(messageTransport);
        var transportRequired = requireE2eeTransport || featureFlags.TransportRequired;
        if (transportRequired && featureFlags.PersistentTransportOutboxEnabled)
        {
            throw new InvalidOperationException(
                "MSG-01 and the legacy transport outbox cannot own the same production dispatch path.");
        }

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

        if (transportRequired && messageTransport is not IMsg01AuthenticatedEvidenceSource)
        {
            throw new MessagingV1CryptoUnavailableException();
        }

        if (featureFlags.MetadataPrivateTransportRequired &&
            !IsTrustedOpaqueTransport(messageTransport))
        {
            throw new InvalidOperationException(
                "MetadataPrivateTransportRequired is enabled, but the configured transport is not opaque P03.");
        }

        if (transportRequired)
        {
            if (messagingV1Persistence is null)
            {
                throw new InvalidOperationException(
                    "TransportRequired requires persistent MSG-01 authoritative state options.");
            }
            if (mailboxDeliveryPolicy is null)
            {
                throw new InvalidOperationException(
                    "TransportRequired requires an explicit mailbox delivery policy.");
            }
            GroupMessageDispatchSafetyService? groupDispatchSafety = null;
            if (groupV1StateStore is not null)
            {
                var messageScope = messagingV1Persistence.IdentityScope
                    ?? throw new InvalidOperationException(
                        "A production GroupV1 store requires an exact DeepAccount-bound MSG-01 scope.");
                if (!messageScope.LocalAccountId.Span.SequenceEqual(
                        groupV1StateStore.Scope.AccountId.Bytes.Span)
                    || messageScope.DatabaseGeneration !=
                        groupV1StateStore.Scope.AccountGeneration)
                {
                    throw new InvalidOperationException(
                        "The production MSG-01 and GroupV1 stores belong to different account generations.");
                }
                groupDispatchSafety = new GroupMessageDispatchSafetyService(groupV1StateStore);
            }
            var verifiedSession = (IMsg01AuthenticatedEvidenceSource)messageTransport;
            Msg01AuthoritativeTransport authoritativeTransport;
            var messagingOwner = messagingV1Persistence.CreateOwner(
                verifiedSession.EvidenceAuthority);
            try
            {
                authoritativeTransport = new Msg01AuthoritativeTransport(
                    messageTransport,
                    groupSyncTransport,
                    verifiedSession,
                    messagingOwner,
                    clock,
                    ownsMessageTransport,
                    groupDispatchSafety);
            }
            catch
            {
                messagingOwner.Dispose();
                throw;
            }
            MessageTransport = authoritativeTransport;
            GroupSyncTransport = authoritativeTransport;
            ownedMessageTransport = authoritativeTransport;
            HasGroupV1FirstDispatchAuthority = groupDispatchSafety is not null;
        }
        else
        {
            if (groupV1StateStore is not null)
            {
                throw new InvalidOperationException(
                    "A GroupV1 production store cannot be attached while the authoritative MSG-01 transport is disabled.");
            }
            MessageTransport = messageTransport;
            GroupSyncTransport = groupSyncTransport ?? new DisabledGroupSyncTransport();
        }

        Conversations = new ConversationService(
            Store, Store, Store, Store, clock, featureFlags, GroupSyncTransport, groupMailboxRoutes);
        messageNetwork = new MessageNetworkRuntime(
            Store,
            MessageTransport,
            GroupSyncTransport,
            messageDispatchFailureObserver);
        Messages = new MessageService(
            Conversations,
            Store,
            Store,
            Store,
            clock,
            messageNetwork);
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

    internal bool HasGroupV1FirstDispatchAuthority { get; }

    public static ClientRuntime CreateStubbed(
        ClientFeatureFlags? featureFlags = null,
        IClock? clock = null,
        StubSessionBackend? backend = null,
        IGroupSyncTransport? groupSyncTransport = null,
        IAvatarProfileTransport? avatarProfiles = null,
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null,
        IGroupMailboxRouteExchange? groupMailboxRoutes = null) =>
        new(
            new InMemorySessionStore(),
            featureFlags ?? ClientFeatureFlags.Defaults,
            clock ?? new SystemClock(),
            backend ?? new StubSessionBackend(),
            groupSyncTransport,
            avatarProfiles,
            transportOutboxExecutor: transportOutboxExecutor,
            groupMailboxRoutes: groupMailboxRoutes);

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
        bool ownsMessageTransport = false,
        IGroupMailboxRouteExchange? groupMailboxRoutes = null)
    {
        var resolvedFeatureFlags = featureFlags ?? ClientFeatureFlags.Defaults;
        if (backend is null)
        {
            throw new ArgumentNullException(
                nameof(backend),
                "A transport must be supplied explicitly. Use CreatePersistentForTests for a named stubbed test runtime.");
        }

        if ((requireE2eeTransport || resolvedFeatureFlags.TransportRequired) &&
            backend is not IMsg01AuthenticatedEvidenceSource)
        {
            throw new MessagingV1CryptoUnavailableException();
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
        ILocalSessionStore? runtimeStore = null;
        try
        {
            runtimeStore = storeDecorator?.Invoke(store) ?? store;
            var messagingV1Persistence = requireE2eeTransport || resolvedFeatureFlags.TransportRequired
                ? new MessagingV1PersistenceOptions(
                    statePath + ".msg01",
                    !string.IsNullOrWhiteSpace(sqlCipherKey)
                        ? sqlCipherKey
                        : throw new InvalidOperationException(
                            "TransportRequired requires a nonempty SQLCipher key for MSG-01."))
                : null;

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
                ownsMessageTransport,
                groupMailboxRoutes: groupMailboxRoutes,
                messagingV1Persistence: messagingV1Persistence);
        }
        catch
        {
            DisposeStartupFailureStore(runtimeStore, store);
            throw;
        }
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
        IExternalTransportOutboxExecutor? transportOutboxExecutor = null,
        IGroupMailboxRouteExchange? groupMailboxRoutes = null) =>
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
            transportOutboxExecutor,
            groupMailboxRoutes: groupMailboxRoutes);

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
        {
            await disposalCompletion.Task.ConfigureAwait(false);
            return;
        }
        try
        {
            Inbox.Dispose();
            mutationBarrier.Dispose();
            await messageNetwork.DisposeAsync().ConfigureAwait(false);
            if (ownedMessageTransport is IAsyncDisposable asyncTransport)
                await asyncTransport.DisposeAsync().ConfigureAwait(false);
            else
                ownedMessageTransport?.Dispose();
            if (Store is IAsyncDisposable asyncStore)
                await asyncStore.DisposeAsync().ConfigureAwait(false);
            else if (Store is IDisposable disposableStore)
                disposableStore.Dispose();
            disposalCompletion.TrySetResult(true);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
    }

    private static bool IsTrustedOpaqueTransport(ISessionMessageTransport transport) =>
        transport switch
        {
            IMetadataPrivateSessionMessageTransport opaque => opaque.UsesMetadataPrivateTransport,
            _ => false
        };

    private static void DisposeStartupFailureStore(
        ILocalSessionStore? runtimeStore,
        SqliteSessionStore store)
    {
        if (!ReferenceEquals(runtimeStore, store))
        {
            DisposeStartupResource(runtimeStore);
        }

        DisposeStartupResource(store);
    }

    private static void DisposeStartupResource(ILocalSessionStore? store)
    {
        if (store is null)
        {
            return;
        }

        try
        {
            if (store is IAsyncDisposable asyncStore)
            {
                asyncStore.DisposeAsync().GetAwaiter().GetResult();
            }
            else if (store is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        catch
        {
        }
    }
}
