using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Fact]
    public async Task ReadGroupCapturesCallerCountOnceBeforeAllocating()
    {
        using var fixture = new Fixture(false);
        var selectors = new ChangingCountSelectors();
        using var batch = await fixture.Store.ReadOwnedBatchAsync(selectors);
        Assert.Equal(1, selectors.CountReads);
        Assert.Equal(1, batch.Count);
        Assert.Null(batch[0]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AtomicReadGroupPreservesOrderMissingSlotsOwnershipAndActualReacquisition(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("first", new byte[] { 1 }), new("second", new byte[] { 2 })]);
        var before = fixture.Protector.UnprotectCalls;
        var batch = await fixture.Store.ReadOwnedBatchAsync(["second", "absent", "first"]);
        Assert.Equal(3, batch.Count); Assert.Null(batch[1]);
        var child = batch[0]!;
        Assert.Equal(2, child.Use(bytes => bytes[0]));
        Assert.Equal(journaled ? 1 : 0, fixture.Protector.UnprotectCalls - before);
        Assert.True(await fixture.Store.CompareExchangeAsync("second", new byte[] { 2 }, new byte[] { 3 }));
        using var current = await fixture.Store.ReadOwnedBatchAsync(["second", "first"]);
        Assert.Equal(3, current[0]!.Use(bytes => bytes[0]));
        Assert.Equal(2, child.Use(bytes => bytes[0])); // Exact prior data, not current authority.
        batch.Dispose(); batch.Dispose();
        Assert.Throws<ObjectDisposedException>(() => child.Use(bytes => bytes[0]));
        Assert.Throws<ObjectDisposedException>(() => batch.Count);
        Assert.Equal(1, current[1]!.Use(bytes => bytes[0]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AtomicReadGroupRejectsMalformedAndCancelledInputsBeforeLoading(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("first", new byte[] { 1 })]);
        var before = fixture.Protector.UnprotectCalls;
        foreach (var slots in new string[][] { [], ["first", "first"], ["bad\nslot"],
                     [new string('x', 513)], Enumerable.Range(0, 33).Select(i => "slot" + i).ToArray() })
            await Assert.ThrowsAnyAsync<ArgumentException>(() => fixture.Store.ReadOwnedBatchAsync(slots));
        await Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Store.ReadOwnedBatchAsync(null!));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.ReadOwnedBatchAsync(["first"], cancelled.Token));
        Assert.Equal(before, fixture.Protector.UnprotectCalls);
        using var maximum = await fixture.Store.ReadOwnedBatchAsync(Enumerable.Range(0, 32).Select(i => "slot" + i).ToArray());
        Assert.Equal(32, maximum.Count);
        for (var i = 0; i < maximum.Count; i++) Assert.Null(maximum[i]);
    }

    [Fact]
    public async Task JournaledReadGroupCapturesSelectorsBeforeAwaitAndHoldsNativeInventoryLease()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("first", new byte[] { 1 }), new("second", new byte[] { 2 })]);
        var slots = new[] { "first", "second" }; var checkedLease = false;
        fixture.Protector.AfterUnprotect = () => {
            slots[0] = "second";
            Assert.Throws<IOException>(() => { using var denied = new FileStream(fixture.StatePath + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None); });
            checkedLease = true;
        };
        try
        {
            using var batch = await fixture.Store.ReadOwnedBatchAsync(slots);
            Assert.True(checkedLease);
            Assert.Equal(1, batch[0]!.Use(bytes => bytes[0]));
            Assert.Equal(2, batch[1]!.Use(bytes => bytes[0]));
        }
        finally { fixture.Protector.AfterUnprotect = null; }
    }

    [Fact]
    public async Task CancelledReadAfterAuthenticationDoesNotReturnSecretsOrChangeInventory()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("first", new byte[] { 1 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        using var cancelled = new CancellationTokenSource();
        fixture.Protector.AfterUnprotect = cancelled.Cancel;
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.ReadOwnedBatchAsync(["first"], cancelled.Token)); }
        finally { fixture.Protector.AfterUnprotect = null; }
        Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        using var current = await fixture.Store.ReadOwnedBatchAsync(["first"]);
        Assert.Equal(1, current[0]!.Use(bytes => bytes[0]));
    }

    [Fact]
    public async Task TamperedInventoryCannotProduceAnyReadGroup()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("first", new byte[] { 1 })]);
        var tampered = File.ReadAllBytes(fixture.StatePath); tampered[^1] ^= 1;
        File.WriteAllBytes(fixture.StatePath, tampered);
        await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.Store.ReadOwnedBatchAsync(["absent", "first"]));
        Assert.Equal(tampered, File.ReadAllBytes(fixture.StatePath));
    }

    private sealed class ChangingCountSelectors : IReadOnlyList<string>
    {
        internal int CountReads;
        public int Count => ++CountReads == 1 ? 1 : 33;
        public string this[int index] => index == 0 ? "first" : throw new IndexOutOfRangeException();
        public IEnumerator<string> GetEnumerator() => throw new NotSupportedException();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
