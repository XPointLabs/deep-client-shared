using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;

namespace Deep.Client.Shared.Persistence.MessagingV1;

public sealed class MessagingV1PersistenceOptions
{
    private readonly string statePath;
    private readonly string sqlCipherKey;
    private readonly MessageStoreScope? identityScope;
    private readonly SessionId? identityAccountAlias;

    public MessagingV1PersistenceOptions(
        string statePath,
        string sqlCipherKey,
        MessageStoreScope? identityScope = null,
        SessionId? identityAccountAlias = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sqlCipherKey);
        this.statePath = Path.GetFullPath(statePath);
        this.sqlCipherKey = sqlCipherKey;
        this.identityScope = identityScope is null ? null : CopyScope(identityScope);
        if (identityScope is null && identityAccountAlias is not null)
        {
            throw new ArgumentException(
                "A legacy transport alias cannot exist without an identity-bound MSG-01 scope.");
        }
        this.identityAccountAlias = identityAccountAlias is null
            ? null
            : SessionId.Parse(identityAccountAlias.Value.Value);
    }

    internal MessageStoreScope? IdentityScope =>
        identityScope is null ? null : CopyScope(identityScope);

    internal MessagingV1RuntimeOwner CreateOwner(Msg01VerifiedSessionAuthority evidenceAuthority) =>
        MessagingV1RuntimeOwner.CreatePersistent(
            statePath,
            sqlCipherKey,
            evidenceAuthority,
            identityScope,
            identityAccountAlias);

    private static MessageStoreScope CopyScope(MessageStoreScope scope) =>
        new(
            MessagingAccountId32.FromBytes(scope.LocalAccountId.Span),
            scope.DatabaseGeneration,
            MessageStoreInstanceId32.FromBytes(scope.StoreInstanceId.Span));
}

/// <summary>
/// Owns one MSG-01 store and its unique, non-exportable capability trust root.
/// The verified transport handoff is consumed only by the authoritative MSG-01
/// runtime and accepts externally authenticated, exact-context evidence.
/// </summary>
internal sealed class SharedMessagingV1Composition : IDisposable, IAsyncDisposable
{
    private IMessageTransactionStore? store;

    private SharedMessagingV1Composition(IMessageTransactionStore store)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        VerifiedTransport = store.ClaimVerifiedTransportHandoff();
        GroupDispatchSafety = store.ClaimGroupDispatchSafetyHandoff();
    }

    internal IMessageTransactionStore Store =>
        store ?? throw new ObjectDisposedException(nameof(SharedMessagingV1Composition));

    internal IMessageVerifiedTransportHandoff VerifiedTransport { get; }

    internal IMessageGroupDispatchSafetyHandoff GroupDispatchSafety { get; }

    internal bool IsDisposed => Volatile.Read(ref store) is null;

    internal static SharedMessagingV1Composition CreateInMemory(
        MessageStoreScope scope,
        Msg01VerifiedSessionAuthority evidenceAuthority) =>
        new(new InMemoryMessageTransactionStore(scope, evidenceAuthority));

    internal static SharedMessagingV1Composition AttachOwned(IMessageTransactionStore store) =>
        new(store);

    internal static SharedMessagingV1Composition OpenPersistent(
        string statePath,
        ReadOnlyMemory<byte> encryptionKey,
        Msg01VerifiedSessionAuthority evidenceAuthority,
        MessageStoreScope scope,
        bool allowCreate = true) =>
        new(SqliteMessageStoreBootstrap.Open(
            new SqliteMessageStoreOptions(
                statePath, encryptionKey, scope, evidenceAuthority, allowCreate)));

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        var ownedStore = Interlocked.Exchange(ref store, null);
        if (ownedStore is not null)
        {
            await ownedStore.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Runtime-owned persistent MSG-01 root. It retains only a derived SQLCipher key
/// and opens one account-bound composition when the authenticated session knows
/// the permanent account scope.
/// </summary>
internal sealed class MessagingV1RuntimeOwner : IDisposable, IAsyncDisposable
{
    private readonly string statePath;
    private readonly byte[] encryptionKey;
    private readonly Msg01VerifiedSessionAuthority evidenceAuthority;
    private readonly object sync = new();
    private readonly TaskCompletionSource<bool> disposalCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private SharedMessagingV1Composition? active;
    private string? activeAccount;
    private MessageStoreScope? activeIdentityScope;
    private SessionId? activeIdentityAccountAlias;
    private int disposed;

    private MessagingV1RuntimeOwner(
        string statePath,
        byte[] encryptionKey,
        Msg01VerifiedSessionAuthority evidenceAuthority)
    {
        this.statePath = Path.GetFullPath(statePath);
        this.encryptionKey = encryptionKey;
        this.evidenceAuthority = evidenceAuthority ?? throw new ArgumentNullException(nameof(evidenceAuthority));
    }

    internal bool IsDisposed => Volatile.Read(ref disposed) != 0;

    internal SharedMessagingV1Composition Open(MessageStoreScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (active is not null)
            {
                throw new InvalidOperationException(
                    "The production runtime already owns an active MSG-01 account composition.");
            }
            active = SharedMessagingV1Composition.OpenPersistent(
                statePath, encryptionKey, evidenceAuthority, scope);
            activeIdentityScope = CopyScope(scope);
            return active;
        }
    }

    internal SharedMessagingV1Composition OpenForIdentity(
        MessageStoreScope scope,
        SessionId? transportAccountAlias = null)
    {
        ArgumentNullException.ThrowIfNull(scope);
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (active is not null)
            {
                if (activeIdentityScope is null || !activeIdentityScope.Equals(scope))
                {
                    throw new InvalidOperationException(
                        "The MSG-01 runtime is already bound to another exact identity scope.");
                }
                if (!Equals(activeIdentityAccountAlias, transportAccountAlias))
                {
                    throw new InvalidOperationException(
                        "The MSG-01 runtime is already bound to another transport account alias.");
                }
                return active;
            }

            active = SharedMessagingV1Composition.OpenPersistent(
                statePath, encryptionKey, evidenceAuthority, scope);
            activeIdentityScope = CopyScope(scope);
            activeIdentityAccountAlias = transportAccountAlias is null
                ? null
                : SessionId.Parse(transportAccountAlias.Value.Value);
            return active;
        }
    }

    internal SharedMessagingV1Composition OpenForAccount(SessionId account)
    {
        if (string.IsNullOrWhiteSpace(account.Value))
        {
            throw new ArgumentException("A canonical local account is required.", nameof(account));
        }
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            if (active is not null)
            {
                if (activeIdentityScope is not null)
                {
                    if (activeIdentityAccountAlias is null
                        || !activeIdentityAccountAlias.Equals(account))
                    {
                        throw new InvalidOperationException(
                            "The legacy transport account does not prove the active DeepAccount identity.");
                    }
                    return active;
                }
                if (!string.Equals(activeAccount, account.Value, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        "The MSG-01 runtime is already bound to another local account.");
                }
                return active;
            }

            var accountId = MessagingAccountId32.FromBytes(Hash("account", account.Value));
            var instanceId = MessageStoreInstanceId32.FromBytes(Hash("store-instance", account.Value));
            active = SharedMessagingV1Composition.OpenPersistent(
                statePath, encryptionKey, evidenceAuthority,
                new MessageStoreScope(accountId, 1, instanceId));
            activeAccount = account.Value;
            return active;
        }
    }

    internal SharedMessagingV1Composition? TryGetActiveForAccount(SessionId account)
    {
        lock (sync)
        {
            return !IsDisposed && ((activeIdentityScope is not null
                        && activeIdentityAccountAlias?.Equals(account) == true)
                    || string.Equals(activeAccount, account.Value, StringComparison.Ordinal))
                ? active
                : null;
        }
    }

    internal SharedMessagingV1Composition? TryGetActiveForIdentity(MessageStoreScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        lock (sync)
        {
            return !IsDisposed && activeIdentityScope is not null
                && activeIdentityScope.Equals(scope)
                ? active
                : null;
        }
    }

    internal static MessagingV1RuntimeOwner CreatePersistent(
        string statePath,
        string sqlCipherKey,
        Msg01VerifiedSessionAuthority evidenceAuthority,
        MessageStoreScope? identityScope = null,
        SessionId? identityAccountAlias = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sqlCipherKey);
        var input = Encoding.UTF8.GetBytes(sqlCipherKey);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/MSG-01/sqlcipher-key-v1\0"u8);
            hash.AppendData(input);
            var owner = new MessagingV1RuntimeOwner(
                statePath, hash.GetHashAndReset(), evidenceAuthority);
            try
            {
                if (identityScope is not null)
                {
                    _ = owner.OpenForIdentity(identityScope, identityAccountAlias);
                }
                return owner;
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public async ValueTask DisposeAsync()
    {
        SharedMessagingV1Composition? owned;
        var first = false;
        lock (sync)
        {
            if (Interlocked.CompareExchange(ref disposed, 1, 0) != 0)
            {
                owned = null;
            }
            else
            {
                first = true;
                owned = active;
                active = null;
                activeAccount = null;
                activeIdentityScope = null;
                activeIdentityAccountAlias = null;
                CryptographicOperations.ZeroMemory(encryptionKey);
            }
        }
        if (!first)
        {
            await disposalCompletion.Task.ConfigureAwait(false);
            return;
        }
        try
        {
            if (owned is not null) await owned.DisposeAsync().ConfigureAwait(false);
            disposalCompletion.TrySetResult(true);
        }
        catch (Exception exception)
        {
            disposalCompletion.TrySetException(exception);
            throw;
        }
    }

    private static byte[] Hash(string domain, string value)
    {
        var bytes = Encoding.UTF8.GetBytes($"Deep/MSG-01/{domain}/v1\0{value}");
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static MessageStoreScope CopyScope(MessageStoreScope scope) =>
        new(
            MessagingAccountId32.FromBytes(scope.LocalAccountId.Span),
            scope.DatabaseGeneration,
            MessageStoreInstanceId32.FromBytes(scope.StoreInstanceId.Span));
}
