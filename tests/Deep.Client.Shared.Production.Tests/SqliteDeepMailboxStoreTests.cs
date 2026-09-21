using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SqliteDeepMailboxStoreTests
{
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
