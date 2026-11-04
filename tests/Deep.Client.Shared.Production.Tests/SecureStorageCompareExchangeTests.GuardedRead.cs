using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GuardedReadChecksCompletePlaintextAndAbsenceWithIndependentBounds(bool journaled)
    {
        using var f = new Fixture(journaled);
        await f.Store.WriteBatchAsync([new("first", new byte[] { 1, 2 }), new("second", new byte[] { 3 })]);
        var guards = Enumerable.Range(0, 1022).ToDictionary(i => "absent" + i, _ => (byte[]?)null, StringComparer.Ordinal);
        guards.Add("first", SHA256.HashData(new byte[] { 1, 2 }));
        guards.Add("second", SHA256.HashData(new byte[] { 3 }));
        var returns = new[] { "second", "missing", "first" }.Concat(Enumerable.Range(0, 29).Select(i => "returned" + i)).ToArray();
        using var result = await f.Store.ReadOwnedGuardedBatchAsync(returns, guards);
        Assert.Equal(32, result.Count); Assert.Null(result[1]);
        Assert.Equal(3, result[0]!.Use(bytes => bytes[0]));
        Assert.Equal(new byte[] { 1, 2 }, result[2]!.Use(bytes => bytes.ToArray()));
        using var proof = await f.Store.ReadOwnedGuardedBatchAsync([], guards);
        Assert.Equal(0, proof.Count);
        guards["first"] = SHA256.HashData(new byte[] { 1 }); // Prefix is not the complete exact value.
        await Assert.ThrowsAsync<CryptographicException>(() => f.Store.ReadOwnedGuardedBatchAsync(["second"], guards));
        guards["first"] = null;
        await Assert.ThrowsAsync<CryptographicException>(() => f.Store.ReadOwnedGuardedBatchAsync([], guards));
        guards["first"] = SHA256.HashData(new byte[] { 1, 2 });
        guards["absent0"] = new byte[32];
        await Assert.ThrowsAsync<CryptographicException>(() => f.Store.ReadOwnedGuardedBatchAsync([], guards));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GuardedReadRejectsMalformedInputsBeforeProviderAccess(bool journaled)
    {
        using var f = new Fixture(journaled);
        var before = f.Protector.UnprotectCalls;
        IReadOnlyDictionary<string, byte[]?>[] invalid = [new Dictionary<string, byte[]?>(),
            new Dictionary<string, byte[]?> { ["bad\nslot"] = null },
            new Dictionary<string, byte[]?> { ["a"] = [] },
            new Dictionary<string, byte[]?> { ["a"] = new byte[31] },
            new Dictionary<string, byte[]?> { ["a"] = new byte[33] },
            Enumerable.Range(0, 1025).ToDictionary(i => "a" + i, _ => (byte[]?)null),
            new HostileGuardDictionary([new("a", null), new("a", null)], 2),
            new HostileGuardDictionary([new("a", null)], 2)];
        foreach (var guards in invalid)
            await Assert.ThrowsAnyAsync<ArgumentException>(() => f.Store.ReadOwnedGuardedBatchAsync([], guards));
        var valid = new Dictionary<string, byte[]?> { ["a"] = null };
        foreach (var returned in new string[][] { ["a", "a"], ["bad\nslot"], Enumerable.Range(0, 33).Select(i => "a" + i).ToArray() })
            await Assert.ThrowsAnyAsync<ArgumentException>(() => f.Store.ReadOwnedGuardedBatchAsync(returned, valid));
        await Assert.ThrowsAsync<ArgumentNullException>(() => f.Store.ReadOwnedGuardedBatchAsync(null!, valid));
        await Assert.ThrowsAsync<ArgumentNullException>(() => f.Store.ReadOwnedGuardedBatchAsync([], null!));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Store.ReadOwnedGuardedBatchAsync([], valid, cancelled.Token));
        Assert.Equal(before, f.Protector.UnprotectCalls);
    }

    [Fact]
    public async Task GuardedReadCapturesCountsOnceAndCopiesSelectorsAndHashesBeforeProvider()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("first", new byte[] { 1 }), new("second", new byte[] { 2 })]);
        var returns = new ChangingCountSelectors();
        var hash = SHA256.HashData(new byte[] { 1 });
        var guards = new HostileGuardDictionary([new("first", hash)], 1);
        f.Protector.AfterUnprotect = () => hash.AsSpan().Clear();
        try
        {
            using var result = await f.Store.ReadOwnedGuardedBatchAsync(returns, guards);
            Assert.Equal(1, result[0]!.Use(bytes => bytes[0]));
            Assert.Equal(1, returns.CountReads); Assert.Equal(1, guards.CountReads);
        }
        finally { f.Protector.AfterUnprotect = null; }
        var slots = new[] { "first" };
        var expected = SHA256.HashData(new byte[] { 1 });
        var mutable = new Dictionary<string, byte[]?> { ["first"] = expected };
        f.Protector.AfterUnprotect = () => { slots[0] = "second"; mutable.Clear(); expected.AsSpan().Clear(); };
        try
        {
            using var result = await f.Store.ReadOwnedGuardedBatchAsync(slots, mutable);
            Assert.Equal(1, result[0]!.Use(bytes => bytes[0]));
        }
        finally { f.Protector.AfterUnprotect = null; }
    }

    [Fact]
    public async Task GuardedReadCopiesCallerInputsBeforeProcessLeaseAwait()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("first", new byte[] { 1 }), new("second", new byte[] { 2 })]);
        var slots = new[] { "first" }; var hash = SHA256.HashData(new byte[] { 1 });
        var guards = new Dictionary<string, byte[]?> { ["first"] = hash };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task<OwnedDeepSecretBatch> reading;
        using (var blocker = new FileStream(f.StatePath + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            reading = f.Store.ReadOwnedGuardedBatchAsync(slots, guards, timeout.Token);
            Assert.False(reading.IsCompleted);
            slots[0] = "second"; hash.AsSpan().Clear(); guards.Clear();
        }
        using var result = await reading;
        Assert.Equal(1, result[0]!.Use(bytes => bytes[0]));
    }

    [Fact]
    public async Task GuardedReadOverlapDecryptsActualObjectOnceAndReturnsOwnedData()
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("first", new byte[] { 1 })]);
        var store = Assert.IsType<JournaledDeepSecureStorage>(f.Store);
        var before = store.ReadWorkSnapshot();
        var batch = await f.Store.ReadOwnedGuardedBatchAsync(["first"], new Dictionary<string, byte[]?> { ["first"] = SHA256.HashData(new byte[] { 1 }) });
        Assert.Equal(1, store.ReadWorkSnapshot().ObjectReads - before.ObjectReads);
        var secret = batch[0]!; Assert.Equal(1, secret.Use(bytes => bytes[0]));
        batch.Dispose(); Assert.Throws<ObjectDisposedException>(() => secret.Use(bytes => bytes[0]));
    }

    [Theory]
    [InlineData("corrupt")]
    [InlineData("missing")]
    public async Task GuardedReadAuthenticatesDependencyObjectUnderUnchangedManifest(string defect)
    {
        using var f = new Fixture(true);
        await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 9 })]);
        var path = Dss2ObjectPath(f, Dss2ReadEntries(f)[1]);
        var manifest = File.ReadAllBytes(f.StatePath);
        if (defect == "missing") File.Delete(path);
        else { var changed = File.ReadAllBytes(path); changed[^1] ^= 1; File.WriteAllBytes(path, changed); }
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Store.ReadOwnedGuardedBatchAsync(["a"],
            new Dictionary<string, byte[]?> { ["z"] = SHA256.HashData(new byte[] { 9 }) }));
        Assert.Equal(manifest, File.ReadAllBytes(f.StatePath));
        using var selected = await f.Store.ReadOwnedAsync("a"); Assert.Equal(1, selected!.Use(bytes => bytes[0]));
    }

    [Theory]
    [InlineData(false, false)] [InlineData(false, true)]
    [InlineData(true, false)] [InlineData(true, true)]
    public async Task GuardOnlyAndAllAbsentReadsFenceFinalSourceAndCancellation(bool noReturns, bool cancellation)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 })]);
        var original = File.ReadAllBytes(f.StatePath); var changed = original.ToArray(); changed[^1] ^= 1;
        using var cancelled = new CancellationTokenSource();
        f.Protector.AfterUnprotect = () => { if (cancellation) cancelled.Cancel(); else File.WriteAllBytes(f.StatePath, changed); };
        try
        {
            var task = f.Store.ReadOwnedGuardedBatchAsync(noReturns ? [] : ["absent"],
                new Dictionary<string, byte[]?> { ["missing"] = null }, cancelled.Token);
            if (cancellation) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
            else await Assert.ThrowsAnyAsync<CryptographicException>(() => task);
        }
        finally { f.Protector.AfterUnprotect = null; }
        Assert.Equal(cancellation ? original : changed, File.ReadAllBytes(f.StatePath));
    }

    [Fact]
    public async Task GuardedReadUnsupportedDecoratorFailsClosedWithoutPublicReadFallback()
    {
        IDeepSecureStorage storage = new UnsupportedGuardedReadStorage();
        await Assert.ThrowsAsync<NotSupportedException>(() => storage.ReadOwnedGuardedBatchAsync([], new Dictionary<string, byte[]?> { ["missing"] = null }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedGuardedReadDoesNotConsumeColdAuditMarker(bool finalSourceFailure)
    {
        using var f = new Fixture(true); await f.Store.WriteBatchAsync([new("a", new byte[] { 1 }), new("z", new byte[] { 9 })]);
        var original = File.ReadAllBytes(f.StatePath); var changedManifest = original.ToArray(); changedManifest[^1] ^= 1;
        using var protector = f.NewProtector(); using var cold = new JournaledDeepSecureStorage(f.StatePath, protector);
        if (finalSourceFailure) protector.AfterUnprotect = () => File.WriteAllBytes(f.StatePath, changedManifest);
        try
        {
            await Assert.ThrowsAsync<CryptographicException>(() => ((IDeepSecureStorage)cold).ReadOwnedGuardedBatchAsync([],
                finalSourceFailure ? new Dictionary<string, byte[]?> { ["missing"] = null } : new Dictionary<string, byte[]?> { ["a"] = new byte[32] }));
        }
        finally { protector.AfterUnprotect = null; File.WriteAllBytes(f.StatePath, original); }
        var path = Dss2ObjectPath(f, Dss2ReadEntries(f)[1]);
        var changed = File.ReadAllBytes(path); changed[^1] ^= 1; File.WriteAllBytes(path, changed);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => ((IDeepSecureStorage)cold).ReadOwnedGuardedBatchAsync(["a"], new Dictionary<string, byte[]?> { ["missing"] = null }));
    }

    private sealed class UnsupportedGuardedReadStorage : IDeepSecureStorage
    {
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Public read fallback is forbidden.");
        public Task<OwnedDeepSecretBatch> ReadOwnedBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Public read fallback is forbidden.");
        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task<bool> CompareAndDeleteAsync(string guardSlot, ReadOnlyMemory<byte> expected, IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException();
        public Task PurgeStoreV2NamespaceAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException();
    }

    private sealed class HostileGuardDictionary(KeyValuePair<string, byte[]?>[] entries, int count) : IReadOnlyDictionary<string, byte[]?>
    {
        internal int CountReads;
        public int Count { get { CountReads++; return count; } }
        public IEnumerable<string> Keys => entries.Select(pair => pair.Key);
        public IEnumerable<byte[]?> Values => entries.Select(pair => pair.Value);
        public byte[]? this[string key] => throw new NotSupportedException();
        public bool ContainsKey(string key) => throw new NotSupportedException();
        public bool TryGetValue(string key, out byte[]? value) => throw new NotSupportedException();
        public IEnumerator<KeyValuePair<string, byte[]?>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, byte[]?>>)entries).GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
