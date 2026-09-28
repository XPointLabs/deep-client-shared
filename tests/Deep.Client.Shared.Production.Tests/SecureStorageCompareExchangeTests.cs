using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExactReplacementRejectsMissingConflictCancellationAndPreservesForeignSlots(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        var store = fixture.Store;
        const string slot = "deep.store.v2.test-floor";
        byte[] initial = [1], next = [2];
        Assert.False(await store.CompareExchangeAsync(slot, initial, next));
        await store.WriteBatchAsync([new(slot, initial), new("foreign", new byte[] { 9 })]);
        Assert.False(await store.CompareExchangeAsync(slot, next, initial));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.CompareExchangeAsync(slot, initial, next, cancelled.Token));
        for (byte revision = 2; revision <= 8; revision++)
            Assert.True(await store.CompareExchangeAsync(slot, new byte[] { (byte)(revision - 1) }, new byte[] { revision }));
        using var actual = await store.ReadOwnedAsync(slot);
        Assert.True(actual!.Use(value => value.SequenceEqual(new byte[] { 8 })));
        using var foreign = await store.ReadOwnedAsync("foreign");
        Assert.True(foreign!.Use(value => value[0] == 9));
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteBatchAsync([new(slot, next)]));
        await Assert.ThrowsAsync<ArgumentException>(() => store.CompareExchangeAsync(slot, initial, ReadOnlyMemory<byte>.Empty));
        if (journaled)
        {
            using var reopened = fixture.OpenJournaled();
            using var persisted = await reopened.ReadOwnedAsync(slot);
            Assert.True(persisted!.Use(value => value[0] == 8));
        }
    }

    [Fact]
    public async Task IndependentJournaledInstancesHaveOneCasWinnerAndProtectionFailureDoesNotCommit()
    {
        using var fixture = new Fixture(true);
        using var second = fixture.OpenJournaled();
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 })]);
        var results = await Task.WhenAll(
            fixture.Store.CompareExchangeAsync("floor", new byte[] { 1 }, new byte[] { 2 }),
            second.CompareExchangeAsync("floor", new byte[] { 1 }, new byte[] { 3 }));
        Assert.Single(results, value => value);
        using var before = await second.ReadOwnedAsync("floor");
        var expected = before!.Use(value => value.ToArray());
        fixture.Protector.FailProtect = true;
        await Assert.ThrowsAsync<IOException>(() => fixture.Store.CompareExchangeAsync("floor", expected, new byte[] { 4 }));
        using var after = await second.ReadOwnedAsync("floor");
        Assert.True(after!.Use(value => value.SequenceEqual(expected)));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-storage-cas-tests", Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        internal readonly Protector Protector;
        internal readonly IDeepSecureStorage Store;
        internal Fixture(bool journaled)
        {
            Directory.CreateDirectory(root);
            Protector = new(key);
            Store = journaled ? new JournaledDeepSecureStorage(Path.Combine(root, "protected.bin"), Protector) : new InMemoryDeepSecureStorage();
        }
        internal JournaledDeepSecureStorage OpenJournaled() => new(Path.Combine(root, "protected.bin"), new Protector(key));
        public void Dispose()
        {
            ((IDisposable)Store).Dispose(); Protector.Dispose(); CryptographicOperations.ZeroMemory(key);
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class Protector(ReadOnlySpan<byte> value) : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key = value.ToArray();
        internal bool FailProtect;
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            if (FailProtect) throw new IOException("Injected protection failure before commit.");
            var result = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(result.AsSpan(0, 12), plaintext, result.AsSpan(28), result.AsSpan(12, 16));
            return result;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> bytes)
        {
            var result = new byte[bytes.Length - 28];
            try { using var aes = new AesGcm(key, 16); aes.Decrypt(bytes[..12], bytes[28..], bytes.Slice(12, 16), result); return result; }
            catch { CryptographicOperations.ZeroMemory(result); throw; }
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
}
