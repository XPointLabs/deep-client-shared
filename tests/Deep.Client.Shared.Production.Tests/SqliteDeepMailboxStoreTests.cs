using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SqliteDeepMailboxStoreTests
{
    [Fact]
    public async Task ObjectHorizonCoordinatorReceiptPersistsAcrossColdReopenAndRejectsExtension()
    {
        // Actual SQLCipher journal component test. Raw scoped statement facts
        // are not a signed grant, transport receipt or device-E2E authority.
        using var fixture = new StoreFixture();
        var key = RandomNumberGenerator.GetBytes(32);
        var scope = ClientMailboxJournalScope.Derive(Enumerable.Repeat((byte)1, 32).ToArray());
        var membership = Enumerable.Repeat((byte)2, 32).ToArray();
        var coordinator = Enumerable.Repeat((byte)3, 32).ToArray();
        var digest = Enumerable.Repeat((byte)4, 32).ToArray();
        const ulong now = 1_100;
        const ulong expiry = now + 30UL * 24 * 60 * 60;
        Assert.Equal(30UL * 24 * 60 * 60, ClientMailboxStateLimits.MaximumActiveInboxAgeSeconds);
        try
        {
            using (var store = new SqliteDeepMailboxStore(new(fixture.Path, key)))
                Assert.Equal(ClientMailboxCoordinatorRecordResult.Applied,
                    await store.RecordCoordinatorStatementAsync(scope, membership, 1, coordinator, 1, digest, expiry, now));
            using (var store = new SqliteDeepMailboxStore(new(fixture.Path, key)))
            {
                Assert.Equal(ClientMailboxCoordinatorRecordResult.Idempotent,
                    await store.RecordCoordinatorStatementAsync(scope, membership, 1, coordinator, 1, digest, expiry, now));
                await Assert.ThrowsAsync<ArgumentException>(() =>
                    store.RecordCoordinatorStatementAsync(scope, membership, 1, coordinator, 1, digest, expiry + 1, now));
                Assert.Equal(ClientMailboxCoordinatorRecordResult.Idempotent,
                    await store.RecordCoordinatorStatementAsync(scope, membership, 1, coordinator, 1, digest, expiry, now));
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Fact]
    public void FreshStoreReopensOnlyWithTheSameKey()
    {
        using var fixture = new StoreFixture();
        var key = RandomNumberGenerator.GetBytes(32);
        using (new SqliteDeepMailboxStore(new(fixture.Path, key))) { }
        using (new SqliteDeepMailboxStore(new(fixture.Path, key))) { }

        var wrongKey = RandomNumberGenerator.GetBytes(32);
        Assert.Throws<LocalStateResetRequiredException>(() =>
            new SqliteDeepMailboxStore(new(fixture.Path, wrongKey)));
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(wrongKey);
    }

    [Fact]
    public void ZeroKeyIsRejectedBeforeStateCreation()
    {
        using var fixture = new StoreFixture();
        Assert.Throws<ArgumentException>(() =>
            new SqliteDeepMailboxStore(new(fixture.Path, new byte[32])));
        Assert.False(File.Exists(fixture.Path));
    }

    [Fact]
    public void OptionsNeverPrintTheEncryptionKey()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var options = new SqliteDeepMailboxStoreOptions("store.db", key);
        Assert.Contains("[redacted]", options.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(key), options.ToString(), StringComparison.Ordinal);
        CryptographicOperations.ZeroMemory(key);
    }

    private sealed class StoreFixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "deep-clean-mailbox-" + Guid.NewGuid().ToString("N"));

        public StoreFixture() => Directory.CreateDirectory(directory);

        public string Path => System.IO.Path.Combine(directory, "mailbox.db");

        public void Dispose() => Directory.Delete(directory, recursive: true);
    }
}
