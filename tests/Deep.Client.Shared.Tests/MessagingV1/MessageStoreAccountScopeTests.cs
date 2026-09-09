using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Domain;
using Deep.Client.Shared.Domain.MessagingV1;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;

namespace Deep.Client.Shared.Tests.MessagingV1;

public sealed class MessageStoreAccountScopeTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-07T00:00:00Z");
    private static readonly byte[] NetworkId = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray();

    [Fact]
    public async Task InMemoryScopeUsesExactAccountAndIsStableAcrossServiceRestart()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var firstService = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(firstService, "Alice");

        var first = await firstService.GetMessageStoreScopeAsync(created.Identity);
        var restartedService = CreateService(store, secureStorage);
        var restartedIdentity = Assert.IsType<DeepLocalIdentitySnapshot>(
            await restartedService.GetLocalIdentityAsync());
        var second = await restartedService.GetMessageStoreScopeAsync(restartedIdentity);

        Assert.Equal(created.Identity.Account.AccountIdentity.AccountId.Bytes.ToArray(), first.LocalAccountId.ToArray());
        Assert.Equal((ulong)DeepAccountStoreContract.CurrentStoreGeneration, first.DatabaseGeneration);
        Assert.True(first.StoreInstanceId.ToArray().AsSpan().IndexOfAnyExcept((byte)0) >= 0);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task SqliteScopeIsStableAcrossDatabaseRestart()
    {
        var path = TempPath("account");
        using var secureStorage = new InMemoryDeepSecureStorage();
        MessageStoreScope first;
        try
        {
            await using (var store = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
            {
                var service = CreateService(store, secureStorage);
                var created = await CreateConfirmedAsync(service, "Alice");
                first = await service.GetMessageStoreScopeAsync(created.Identity);
            }

            await using (var reopened = await SqliteDeepAccountStoreBootstrap.OpenAsync(path, secureStorage))
            {
                var service = CreateService(reopened, secureStorage);
                var identity = Assert.IsType<DeepLocalIdentitySnapshot>(await service.GetLocalIdentityAsync());
                var second = await service.GetMessageStoreScopeAsync(identity);
                Assert.Equal(first, second);
                Assert.Equal(identity.Account.AccountIdentity.AccountId.Bytes.ToArray(), second.LocalAccountId.ToArray());
            }
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task RestoreAsNewDeviceKeepsAccountButGetsNewStoreInstance()
    {
        await using var firstStore = new InMemoryDeepAccountStore();
        await using var secondStore = new InMemoryDeepAccountStore();
        using var firstStorage = new InMemoryDeepSecureStorage();
        using var secondStorage = new InMemoryDeepSecureStorage();
        var firstService = CreateService(firstStore, firstStorage);
        var secondService = CreateService(secondStore, secondStorage);
        var (firstResult, phrase) = await CreateConfirmedWithPhraseAsync(firstService, "Alice");
        try
        {
            var firstScope = await firstService.GetMessageStoreScopeAsync(firstResult.Identity);
            using var recovery = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phrase);
            var restored = await secondService.RestoreAsNewDeviceAsync(recovery, "Alice restored");
            var restoredScope = await secondService.GetMessageStoreScopeAsync(restored.Identity);

            Assert.Equal(firstScope.LocalAccountId, restoredScope.LocalAccountId);
            Assert.NotEqual(firstScope.StoreInstanceId, restoredScope.StoreInstanceId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(phrase);
        }
    }

    [Fact]
    public async Task ResetDeletesStoreInstanceAndFreshAccountGetsAnotherValue()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var first = await CreateConfirmedAsync(service, "Alice");
        var firstScope = await service.GetMessageStoreScopeAsync(first.Identity);
        var slot = first.Identity.SecureSlots.MessageStoreInstanceId;

        await service.ResetLocalAccountAsync();
        using (var removed = await secureStorage.ReadOwnedAsync(slot))
        {
            Assert.Null(removed);
        }

        var fresh = await CreateConfirmedAsync(service, "Alice fresh");
        var freshScope = await service.GetMessageStoreScopeAsync(fresh.Identity);
        Assert.NotEqual(firstScope.StoreInstanceId, freshScope.StoreInstanceId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrTamperedStoreInstanceFailsClosed(bool tamper)
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var slot = created.Identity.SecureSlots.MessageStoreInstanceId;
        await secureStorage.DeleteBatchAsync([slot]);
        if (tamper)
        {
            var replacement = Enumerable.Range(0, 32).Select(static value => (byte)(0xa0 + value)).ToArray();
            try
            {
                await secureStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, replacement)]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(replacement);
            }
        }

        var error = await Assert.ThrowsAsync<LocalStateResetRequiredException>(() =>
            service.GetMessageStoreScopeAsync(created.Identity));
        Assert.Equal(LocalStateResetRequiredReason.InvalidCurrentSchema, error.Reason);
    }

    [Fact]
    public async Task ForeignSnapshotCannotSelectCurrentAccountScope()
    {
        await using var firstStore = new InMemoryDeepAccountStore();
        await using var secondStore = new InMemoryDeepAccountStore();
        using var firstStorage = new InMemoryDeepSecureStorage();
        using var secondStorage = new InMemoryDeepSecureStorage();
        var firstService = CreateService(firstStore, firstStorage);
        var secondService = CreateService(secondStore, secondStorage);
        _ = await CreateConfirmedAsync(firstService, "Alice");
        var foreign = await CreateConfirmedAsync(secondService, "Bob");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            firstService.GetMessageStoreScopeAsync(foreign.Identity));
    }

    [Fact]
    public async Task RuntimeOwnerBindsOnlyTheExactIdentityScope()
    {
        await using var store = new InMemoryDeepAccountStore();
        using var secureStorage = new InMemoryDeepSecureStorage();
        var service = CreateService(store, secureStorage);
        var created = await CreateConfirmedAsync(service, "Alice");
        var scope = await service.GetMessageStoreScopeAsync(created.Identity);
        var foreign = new MessageStoreScope(
            scope.LocalAccountId,
            scope.DatabaseGeneration,
            MessageStoreInstanceId32.FromBytes(Enumerable.Repeat((byte)0x5a, 32).ToArray()));
        var path = TempPath("messages");
        try
        {
            await using var owner = MessagingV1RuntimeOwner.CreatePersistent(
                path,
                "message-store-account-scope-test-key",
                MessagingV1Fixture.CreateEvidenceAuthority());
            var active = owner.OpenForIdentity(scope);

            Assert.Same(active, owner.OpenForIdentity(scope));
            Assert.Same(active, owner.TryGetActiveForIdentity(scope));
            Assert.Null(owner.TryGetActiveForIdentity(foreign));
            Assert.Throws<InvalidOperationException>(() => owner.OpenForIdentity(foreign));

            var accountMethod = typeof(DeepAccountService).GetMethod(
                "GetMessageStoreScopeAsync",
                BindingFlags.Instance | BindingFlags.NonPublic);
            var ownerMethod = typeof(MessagingV1RuntimeOwner).GetMethod(
                "OpenForIdentity",
                BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(accountMethod);
            Assert.NotNull(ownerMethod);
            Assert.DoesNotContain(accountMethod!.GetParameters(), parameter => parameter.ParameterType == typeof(SessionId));
            Assert.DoesNotContain(ownerMethod!.GetParameters(), parameter => parameter.ParameterType == typeof(SessionId));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    private static DeepAccountService CreateService(
        IDeepAccountStore store,
        IDeepSecureStorage secureStorage) =>
        new(store, secureStorage, new FrozenClock(Now), NetworkId);

    private static async Task<DeepAccountCreationResult> CreateConfirmedAsync(
        DeepAccountService service,
        string displayName)
    {
        var (result, phrase) = await CreateConfirmedWithPhraseAsync(service, displayName);
        CryptographicOperations.ZeroMemory(phrase);
        return result;
    }

    private static async Task<(DeepAccountCreationResult Result, byte[] Phrase)>
        CreateConfirmedWithPhraseAsync(DeepAccountService service, string displayName)
    {
        using var draft = service.PrepareCreate(displayName);
        byte[]? phrase = null;
        draft.RevealCanonicalPhraseOnce(value => phrase = value.ToArray());
        try
        {
            using var confirmation = DeepOwnedRecoveryPhraseUtf8.CopyFrom(phrase!);
            var result = await service.CommitPreparedAsync(draft, confirmation);
            return (result, phrase!);
        }
        catch
        {
            if (phrase is not null) CryptographicOperations.ZeroMemory(phrase);
            throw;
        }
    }

    private static string TempPath(string kind) =>
        Path.Combine(Path.GetTempPath(), $"deep-msg-scope-{kind}-{Guid.NewGuid():N}.db");

    private static void DeleteSqliteFiles(string path)
    {
        foreach (var candidate in new[]
                 {
                     path, path + "-wal", path + "-shm", path + ".creating",
                     path + ".creating-wal", path + ".creating-shm",
                     path + ".bootstrap.lock", path + ".account.lock",
                     path + ".creating.generation.lock"
                 })
        {
            if (File.Exists(candidate)) File.Delete(candidate);
        }
    }
}
