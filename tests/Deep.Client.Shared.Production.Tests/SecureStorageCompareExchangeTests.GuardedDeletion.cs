using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class SecureStorageCompareExchangeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GuardedDeletion_DeletesOnlyPartsAndNoopDoesNotRewrite(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var loads = fixture.Protector.UnprotectCalls;
        Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["part", "absent"]));
        if (journaled) Assert.Equal(loads + 1, fixture.Protector.UnprotectCalls);
        using (var part = await fixture.Store.ReadOwnedAsync("part")) Assert.Null(part);
        using (var guard = await fixture.Store.ReadOwnedAsync("floor")) Assert.Equal(1, guard!.Use(bytes => bytes[0]));
        using (var foreign = await fixture.Store.ReadOwnedAsync("foreign")) Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
        var original = journaled ? File.ReadAllBytes(fixture.StatePath) : [];
        var protects = fixture.Protector.ProtectCalls;
        loads = fixture.Protector.UnprotectCalls;
        Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["part", "absent"]));
        if (journaled)
        {
            Assert.Equal(loads + 1, fixture.Protector.UnprotectCalls);
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
            using var reopened = fixture.OpenJournaled();
            using var guard = await reopened.ReadOwnedAsync("floor");
            using var part = await reopened.ReadOwnedAsync("part");
            using var foreign = await reopened.ReadOwnedAsync("foreign");
            Assert.Equal(1, guard!.Use(bytes => bytes[0])); Assert.Null(part);
            Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
        }
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public async Task GuardedDeletion_MissingOrStaleGuardCannotDelete(bool journaled, bool missing)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = journaled ? File.ReadAllBytes(fixture.StatePath) : [];
        var loads = fixture.Protector.UnprotectCalls; var protects = fixture.Protector.ProtectCalls;
        Assert.False(await fixture.Store.CompareAndDeleteAsync(missing ? "missing" : "floor", new byte[] { 2 }, ["part"]));
        if (journaled)
        {
            Assert.Equal(loads + 1, fixture.Protector.UnprotectCalls);
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        }
        await AssertGuardedInventoryUnchanged(fixture.Store);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task GuardedDeletion_InvalidInputsAndCancellationRejectBeforeMutation(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = journaled ? File.ReadAllBytes(fixture.StatePath) : [];
        var loads = fixture.Protector.UnprotectCalls; var protects = fixture.Protector.ProtectCalls;
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["floor"]));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["part", "part"]));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, []));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", ReadOnlyMemory<byte>.Empty, ["part"]));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[1024 * 1024 + 1], ["part"]));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, [new string('x', 513)]));
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 },
            Enumerable.Range(0, 1025).Select(index => "part-" + index).ToArray()));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.CompareAndDeleteAsync("floor",
            new byte[] { 1 }, ["part"], cancelled.Token));
        if (journaled)
        {
            Assert.Equal(loads, fixture.Protector.UnprotectCalls);
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        }
        await AssertGuardedInventoryUnchanged(fixture.Store);
    }

    [Fact]
    public async Task GuardedDeletion_OwnsInputsBeforeAuthenticatedLoad()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        byte[] expected = [1]; string[] slots = ["part"];
        fixture.Protector.AfterUnprotect = () => { expected[0] = 2; slots[0] = "foreign"; };
        try { Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", expected, slots)); }
        finally { fixture.Protector.AfterUnprotect = null; }
        using var part = await fixture.Store.ReadOwnedAsync("part"); Assert.Null(part);
        using var foreign = await fixture.Store.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
        using var floor = await fixture.Store.ReadOwnedAsync("floor"); Assert.Equal(1, floor!.Use(bytes => bytes[0]));
    }

    [Fact]
    public async Task GuardedDeletion_CancellationDuringLoadCannotDelete()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        using var cancelled = new CancellationTokenSource();
        fixture.Protector.AfterUnprotect = cancelled.Cancel;
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.CompareAndDeleteAsync(
            "floor", new byte[] { 1 }, ["part"], cancelled.Token)); }
        finally { fixture.Protector.AfterUnprotect = null; }
        Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        await AssertGuardedInventoryUnchanged(fixture.Store);
    }

    [Fact]
    public async Task GuardedDeletion_ProtectionFailureAndTamperedNoopCannotCommit()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        fixture.Protector.FailProtect = true;
        await Assert.ThrowsAsync<IOException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["part"]));
        Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        await AssertGuardedInventoryUnchanged(fixture.Store);
        fixture.Protector.FailProtect = false;
        original[^1] ^= 1; File.WriteAllBytes(fixture.StatePath, original);
        // An absent deletion target must not bypass aggregate authentication.
        await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.Store.CompareAndDeleteAsync(
            "floor", new byte[] { 1 }, ["absent"]));
        Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
    }

    private static async Task AssertGuardedInventoryUnchanged(IDeepSecureStorage store)
    {
        using var floor = await store.ReadOwnedAsync("floor"); Assert.Equal(1, floor!.Use(bytes => bytes[0]));
        using var part = await store.ReadOwnedAsync("part"); Assert.Equal(7, part!.Use(bytes => bytes[0]));
        using var foreign = await store.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
    }
}
