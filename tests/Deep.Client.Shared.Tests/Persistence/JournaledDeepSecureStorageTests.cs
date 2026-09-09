using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class JournaledDeepSecureStorageTests
{
    [Fact]
    public async Task BinaryAggregate_RoundTripsWithoutPlaintextOnDisk()
    {
        using var fixture = new Fixture();
        var secret = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        await fixture.Store.WriteBatchAsync([new("deep.store.v1.secret", secret)]);

        using var read = await fixture.Store.ReadOwnedAsync("deep.store.v1.secret");
        Assert.NotNull(read);
        Assert.True(read!.Use(value => value.SequenceEqual(secret)));

        var disk = await File.ReadAllBytesAsync(fixture.StatePath);
        Assert.DoesNotContain(Convert.ToHexString(secret), Convert.ToHexString(disk));
        Assert.False(disk.AsSpan().IndexOf(secret) >= 0);
    }

    [Fact]
    public async Task DuplicateWrite_IsRejectedWithoutPartialMutation()
    {
        using var fixture = new Fixture();
        await fixture.Store.WriteBatchAsync([new("deep.store.v1.a", new byte[] { 1 })]);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fixture.Store.WriteBatchAsync(
            [
                new("deep.store.v1.b", new byte[] { 2 }),
                new("deep.store.v1.a", new byte[] { 3 })
            ]));

        Assert.Null(await fixture.Store.ReadOwnedAsync("deep.store.v1.b"));
        using var original = await fixture.Store.ReadOwnedAsync("deep.store.v1.a");
        Assert.True(original!.Use(static value => value.SequenceEqual(new byte[] { 1 })));
    }

    [Fact]
    public async Task DeleteAndNamespacePurge_AreAtomicAndScoped()
    {
        using var fixture = new Fixture();
        await fixture.Store.WriteBatchAsync(
        [
            new("deep.store.v1.a", new byte[] { 1 }),
            new("deep.store.v1.b", new byte[] { 2 }),
            new("another.namespace", new byte[] { 3 })
        ]);

        await fixture.Store.DeleteBatchAsync(["deep.store.v1.a", "deep.store.v1.a"]);
        Assert.Null(await fixture.Store.ReadOwnedAsync("deep.store.v1.a"));
        using (var retained = await fixture.Store.ReadOwnedAsync("deep.store.v1.b"))
        {
            Assert.NotNull(retained);
        }

        await fixture.Store.PurgeStoreV1NamespaceAsync();
        Assert.Null(await fixture.Store.ReadOwnedAsync("deep.store.v1.b"));
        using var foreign = await fixture.Store.ReadOwnedAsync("another.namespace");
        Assert.True(foreign!.Use(static value => value.SequenceEqual(new byte[] { 3 })));
    }

    [Fact]
    public async Task ModifiedAggregate_FailsClosed()
    {
        using var fixture = new Fixture();
        await fixture.Store.WriteBatchAsync([new("deep.store.v1.a", new byte[] { 1, 2, 3 })]);
        var disk = await File.ReadAllBytesAsync(fixture.StatePath);
        disk[^1] ^= 0x80;
        await File.WriteAllBytesAsync(fixture.StatePath, disk);

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            fixture.Store.ReadOwnedAsync("deep.store.v1.a"));
    }

    [Fact]
    public async Task PendingFile_IsNeverPromoted()
    {
        using var fixture = new Fixture();
        await fixture.Store.WriteBatchAsync([new("deep.store.v1.a", new byte[] { 1 })]);
        await File.WriteAllBytesAsync(fixture.StatePath + ".pending", RandomNumberGenerator.GetBytes(64));

        using var value = await fixture.Store.ReadOwnedAsync("deep.store.v1.a");
        Assert.NotNull(value);
        Assert.False(File.Exists(fixture.StatePath + ".pending"));
    }

    [Fact]
    public async Task ConcurrentDistinctWriters_DoNotLoseEntries()
    {
        using var fixture = new Fixture();
        await Task.WhenAll(Enumerable.Range(0, 24).Select(index =>
            fixture.Store.WriteBatchAsync(
                [new($"deep.store.v1.concurrent-{index:D2}", new byte[] { checked((byte)(index + 1)) })])));

        for (var index = 0; index < 24; index++)
        {
            using var value = await fixture.Store.ReadOwnedAsync($"deep.store.v1.concurrent-{index:D2}");
            Assert.True(value!.Use(bytes => bytes[0] == index + 1));
        }
    }

    [Fact]
    public async Task IndependentStoreInstances_SerializeThroughProcessLease()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "deep-journaled-secure-storage-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "secure.bin");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var first = new JournaledDeepSecureStorage(path, new TestAeadProtector(key));
            using var second = new JournaledDeepSecureStorage(path, new TestAeadProtector(key));
            await Task.WhenAll(Enumerable.Range(0, 24).Select(index =>
                (index % 2 == 0 ? first : second).WriteBatchAsync(
                    [new($"deep.store.v1.process-{index:D2}", new byte[] { checked((byte)(index + 1)) })])));

            for (var index = 0; index < 24; index++)
            {
                using var value = await first.ReadOwnedAsync($"deep.store.v1.process-{index:D2}");
                Assert.True(value!.Use(bytes => bytes[0] == index + 1));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(
            Path.GetTempPath(),
            "deep-journaled-secure-storage-tests",
            Guid.NewGuid().ToString("N"));

        public Fixture()
        {
            Directory.CreateDirectory(root);
            StatePath = Path.Combine(root, "secure.bin");
            Store = new JournaledDeepSecureStorage(StatePath, new TestAeadProtector());
        }

        public string StatePath { get; }
        public JournaledDeepSecureStorage Store { get; }

        public void Dispose()
        {
            Store.Dispose();
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class TestAeadProtector : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key;

        public TestAeadProtector()
        {
            key = RandomNumberGenerator.GetBytes(32);
        }

        public TestAeadProtector(ReadOnlySpan<byte> key)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException("Test key must contain 32 bytes.", nameof(key));
            }
            this.key = key.ToArray();
        }

        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            var output = new byte[4 + 12 + 16 + plaintext.Length];
            "TSP1"u8.CopyTo(output);
            RandomNumberGenerator.Fill(output.AsSpan(4, 12));
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(
                output.AsSpan(4, 12),
                plaintext,
                output.AsSpan(32),
                output.AsSpan(16, 16),
                "Deep/Test/JournaledStorage"u8);
            return output;
        }

        public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes)
        {
            if (protectedBytes.Length < 32 || !protectedBytes[..4].SequenceEqual("TSP1"u8))
            {
                throw new CryptographicException("Invalid test envelope.");
            }
            var plaintext = new byte[protectedBytes.Length - 32];
            try
            {
                using var aes = new AesGcm(key, 16);
                aes.Decrypt(
                    protectedBytes.Slice(4, 12),
                    protectedBytes[32..],
                    protectedBytes.Slice(16, 16),
                    plaintext,
                    "Deep/Test/JournaledStorage"u8);
                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
}
