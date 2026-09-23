using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2NamespacePurgeTests
{
    [Fact]
    public async Task PurgeRemovesOnlyExactV2NamespaceAndIsIdempotent()
    {
        using var storage = new InMemoryDeepSecureStorage();
        await storage.WriteBatchAsync(
        [
            new DeepSecureStorageWrite("deep.store.v2.account.genesis-contact", new byte[] { 1 }),
            new DeepSecureStorageWrite("deep.store.v2.account.recovery-phrase", new byte[] { 2 }),
            new DeepSecureStorageWrite("deep.store.v1.account.genesis-contact", new byte[] { 3 }),
            new DeepSecureStorageWrite("deep.store.v20.account", new byte[] { 4 }),
            new DeepSecureStorageWrite("other.deep.store.v2.account", new byte[] { 5 })
        ]);

        await storage.PurgeStoreV2NamespaceAsync();
        await storage.PurgeStoreV2NamespaceAsync();

        Assert.Null(await storage.ReadOwnedAsync(
            "deep.store.v2.account.genesis-contact"));
        Assert.Null(await storage.ReadOwnedAsync(
            "deep.store.v2.account.recovery-phrase"));
        foreach (var slot in new[] { "deep.store.v1.account.genesis-contact",
                     "deep.store.v20.account", "other.deep.store.v2.account" })
        {
            using var retained = await storage.ReadOwnedAsync(slot);
            Assert.NotNull(retained);
        }
    }
}
