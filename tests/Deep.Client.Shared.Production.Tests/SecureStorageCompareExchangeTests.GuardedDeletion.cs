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
        // DSS2 mutating admission is repeated after Protect and for cleanup;
        // the exact-one promise applies to the clean no-op/read below.
        if (journaled) Assert.True(fixture.Protector.UnprotectCalls > loads + 1);
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
    public Task GuardedDeletion_MissingOrStaleGuardCannotDelete(bool journaled, bool missing) =>
        CheckGuardedDeletionRejected(journaled, missing, selfGuard: false);

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)]
    [InlineData(false, true)] [InlineData(true, true)]
    public Task GuardedDeletion_SelfGuardMissingOrStaleGuardCannotDelete(bool journaled, bool missing) =>
        CheckGuardedDeletionRejected(journaled, missing, selfGuard: true);

    private static async Task CheckGuardedDeletionRejected(bool journaled, bool missing, bool selfGuard)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = journaled ? File.ReadAllBytes(fixture.StatePath) : [];
        var loads = fixture.Protector.UnprotectCalls; var protects = fixture.Protector.ProtectCalls;
        var guardSlot = missing ? "missing" : "floor";
        Assert.False(await fixture.Store.CompareAndDeleteAsync(guardSlot, new byte[] { 2 },
            selfGuard ? [guardSlot, "part"] : ["part"]));
        if (journaled)
        {
            Assert.Equal(loads + 1, fixture.Protector.UnprotectCalls);
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        }
        await AssertGuardedInventoryUnchanged(fixture.Store);
        if (journaled)
        { using var reopened = fixture.OpenJournaled(); await AssertGuardedInventoryUnchanged(reopened); }
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
        await Assert.ThrowsAsync<ArgumentException>(() => fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["floor", "floor"]));
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
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.CompareAndDeleteAsync("floor",
            new byte[] { 1 }, ["floor", "part"], cancelled.Token));
        if (journaled)
        {
            Assert.Equal(loads, fixture.Protector.UnprotectCalls);
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        }
        await AssertGuardedInventoryUnchanged(fixture.Store);
    }

    [Fact]
    public Task GuardedDeletion_OwnsInputsBeforeAuthenticatedLoad() => CheckGuardedDeletionInputOwnership(selfGuard: false);

    [Fact]
    public Task GuardedDeletion_SelfGuardOwnsInputsBeforeAuthenticatedLoad() => CheckGuardedDeletionInputOwnership(selfGuard: true);

    private static async Task CheckGuardedDeletionInputOwnership(bool selfGuard)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        byte[] expected = [1]; string[] slots = selfGuard ? ["part", "floor"] : ["part"];
        fixture.Protector.AfterUnprotect = () => { expected[0] = 2; slots[0] = "foreign"; };
        try { Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", expected, slots)); }
        finally { fixture.Protector.AfterUnprotect = null; }
        using var part = await fixture.Store.ReadOwnedAsync("part"); Assert.Null(part);
        using var foreign = await fixture.Store.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
        using var floor = await fixture.Store.ReadOwnedAsync("floor");
        if (selfGuard) Assert.Null(floor); else Assert.Equal(1, floor!.Use(bytes => bytes[0]));
        using var reopened = fixture.OpenJournaled();
        using var persisted = await reopened.ReadOwnedBatchAsync(["floor", "part", "foreign"]);
        if (selfGuard) Assert.Null(persisted[0]); else Assert.Equal(1, persisted[0]!.Use(bytes => bytes[0]));
        Assert.Null(persisted[1]); Assert.Equal(9, persisted[2]!.Use(bytes => bytes[0]));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task GuardedDeletion_SelfGuardCommitsWholeDeletionAndMissingRetryDoesNotRewrite(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var entries = journaled ? Dss2ReadEntries(fixture) : [];
        var foreign = entries.SingleOrDefault(entry => entry.Slot == "foreign");
        var foreignExact = foreign is null ? [] : File.ReadAllBytes(Dss2ObjectPath(fixture, foreign));
        Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["part", "floor", "absent"]));
        await AssertSelfGuardDeleted(fixture.Store);
        var original = journaled ? File.ReadAllBytes(fixture.StatePath) : [];
        var protects = fixture.Protector.ProtectCalls;
        Assert.False(await fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["floor", "part"]));
        await AssertSelfGuardDeleted(fixture.Store);
        if (journaled)
        {
            Assert.Equal(protects, fixture.Protector.ProtectCalls);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
            using var reopened = fixture.OpenJournaled(); await AssertSelfGuardDeleted(reopened); await reopened.AuditAsync();
            var retained = Assert.Single(Dss2ReadEntries(fixture));
            Assert.Equal("foreign", retained.Slot); Assert.Equal(foreign!.Id, retained.Id);
            Assert.Equal(foreignExact, File.ReadAllBytes(Dss2ObjectPath(fixture, foreign!)));
            Assert.All(entries.Where(entry => entry.Slot != "foreign"),
                entry => Assert.False(File.Exists(Dss2ObjectPath(fixture, entry))));
            Assert.False(File.Exists(fixture.StatePath + ".pending")); Assert.False(File.Exists(fixture.StatePath + ".backup"));
            Assert.Single(Directory.GetFiles(fixture.StatePath + ".objects", "*.dvo"));
        }
    }

    [Theory]
    [InlineData("AfterPendingManifest", false)] [InlineData("BeforeManifestReplace", false)]
    [InlineData("AfterManifestReplace", true)] [InlineData("AfterRetirementTombstone", true)]
    [InlineData("AfterRetirementUnlink", true)] [InlineData("BeforeCleanupManifest", true)]
    [InlineData("AfterCleanupManifest", true)]
    public async Task GuardedDeletion_SelfGuardCrashColdRecoversExactInventoryAndCleanup(string point, bool committed)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var entries = Dss2ReadEntries(fixture);
        var foreign = entries.Single(entry => entry.Slot == "foreign");
        var foreignExact = File.ReadAllBytes(Dss2ObjectPath(fixture, foreign));
        using (var crash = JournaledDeepSecureStorageTestHooks.PushCrashOnce(Enum.Parse<JournaledDeepSecureStorageFailpoint>(point)))
        {
            var error = await Assert.ThrowsAsync<IOException>(() => fixture.Store.CompareAndDeleteAsync(
                "floor", new byte[] { 1 }, ["part", "floor"]));
            Assert.Equal("Injected DSS2 crash cutpoint.", error.Message); Assert.True(crash.Reached);
        }
        using var reopened = fixture.OpenJournaled();
        if (committed) await AssertSelfGuardDeleted(reopened); else await AssertGuardedInventoryUnchanged(reopened);
        await reopened.AuditAsync();
        var actual = Dss2ReadEntries(fixture);
        Assert.Equal(committed ? new[] { "foreign" } : new[] { "floor", "foreign", "part" }, actual.Select(entry => entry.Slot).ToArray());
        Assert.Equal(foreign.Id, actual.Single(entry => entry.Slot == "foreign").Id);
        Assert.Equal(foreignExact, File.ReadAllBytes(Dss2ObjectPath(fixture, foreign)));
        foreach (var entry in entries.Where(entry => entry.Slot != "foreign"))
            Assert.Equal(!committed, File.Exists(Dss2ObjectPath(fixture, entry)));
        Assert.Equal(actual.Count, Directory.GetFiles(fixture.StatePath + ".objects", "*.dvo").Length);
        Assert.False(File.Exists(fixture.StatePath + ".pending")); Assert.False(File.Exists(fixture.StatePath + ".backup"));
        // A committed guard is absent, so an exact retry cannot report another
        // deletion. A precommit crash retains the exact source for an explicit retry.
        Assert.Equal(!committed, await reopened.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["floor", "part"]));
        await AssertSelfGuardDeleted(reopened);
        using var cold = fixture.OpenJournaled(); await AssertSelfGuardDeleted(cold);
    }

    [Theory]
    [InlineData("protect")] [InlineData("before-commit")]
    public async Task GuardedDeletion_SelfGuardChangedAtFinalCallbackCannotDeleteActualSource(string edge)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var source = File.ReadAllBytes(fixture.StatePath);
        var entries = Dss2ReadEntries(fixture);
        var retained = entries.Where(entry => entry.Slot != "floor")
            .Select(entry => (Path: Dss2ObjectPath(fixture, entry), Exact: File.ReadAllBytes(Dss2ObjectPath(fixture, entry)))).ToArray();
        var guard = entries.Single(entry => entry.Slot == "floor");
        var guardPath = Dss2ObjectPath(fixture, guard); var guardExact = File.ReadAllBytes(guardPath);
        Assert.True(await fixture.Store.CompareExchangeAsync("floor", new byte[] { 1 }, new byte[] { 2 }));
        var changed = false;
        void RestoreActualGuard()
        {
            fixture.Protector.AfterProtect = null;
            File.WriteAllBytes(guardPath, guardExact); File.WriteAllBytes(fixture.StatePath, source); changed = true;
        }
        using var callback = edge == "before-commit" ? JournaledDeepSecureStorageTestHooks.PushCallbackOnce(
            JournaledDeepSecureStorageFailpoint.BeforeManifestReplace, RestoreActualGuard) : null;
        if (edge == "protect") fixture.Protector.AfterProtect = RestoreActualGuard;
        try
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.Store.CompareAndDeleteAsync(
                "floor", new byte[] { 2 }, ["floor", "part"]));
        }
        finally { fixture.Protector.AfterProtect = null; }
        Assert.True(changed); Assert.Equal(source, File.ReadAllBytes(fixture.StatePath));
        Assert.Equal(guardExact, File.ReadAllBytes(guardPath));
        foreach (var item in retained) Assert.Equal(item.Exact, File.ReadAllBytes(item.Path));
        using var reopened = fixture.OpenJournaled();
        if (edge == "protect")
        { await AssertGuardedInventoryUnchanged(reopened); await reopened.AuditAsync(); }
        else
        {
            // The callback replaced the source after pending publication. Its
            // authentic but unrelated pending successor must never be adopted.
            Assert.True(callback!.Reached);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => reopened.ReadOwnedAsync("floor"));
            Assert.Equal(source, File.ReadAllBytes(fixture.StatePath));
            Assert.Equal(guardExact, File.ReadAllBytes(guardPath));
            foreach (var item in retained) Assert.Equal(item.Exact, File.ReadAllBytes(item.Path));
        }
    }

    [Fact]
    public async Task GuardedDeletion_SelfGuardCommittedCallbackReadsSuccessorWithoutRequiringDeletedGuard()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var foreign = Dss2ReadEntries(fixture).Single(entry => entry.Slot == "foreign");
        using var observer = fixture.NewProtector();
        using var callback = JournaledDeepSecureStorageTestHooks.PushCallbackOnce(JournaledDeepSecureStorageFailpoint.AfterManifestReplace, () =>
        {
            var plain = observer.Unprotect(File.ReadAllBytes(fixture.StatePath));
            try
            {
                var retained = Assert.Single(Dss2Entries(plain));
                Assert.Equal("foreign", retained.Slot); Assert.Equal(foreign.Id, retained.Id);
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        });
        Assert.True(await fixture.Store.CompareAndDeleteAsync("floor", new byte[] { 1 }, ["floor", "part"]));
        Assert.True(callback.Reached);
        using var reopened = fixture.OpenJournaled(); await AssertSelfGuardDeleted(reopened); await reopened.AuditAsync();
    }

    [Fact]
    public Task GuardedDeletion_CancellationDuringLoadCannotDelete() => CheckGuardedDeletionCancellationDuringLoad(selfGuard: false);

    [Fact]
    public Task GuardedDeletion_SelfGuardCancellationDuringLoadCannotDelete() => CheckGuardedDeletionCancellationDuringLoad(selfGuard: true);

    private static async Task CheckGuardedDeletionCancellationDuringLoad(bool selfGuard)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("floor", new byte[] { 1 }),
            new("part", new byte[] { 7 }), new("foreign", new byte[] { 9 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        using var cancelled = new CancellationTokenSource();
        fixture.Protector.AfterUnprotect = cancelled.Cancel;
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Store.CompareAndDeleteAsync(
            "floor", new byte[] { 1 }, selfGuard ? ["floor", "part"] : ["part"], cancelled.Token)); }
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

    private static async Task AssertSelfGuardDeleted(IDeepSecureStorage store)
    {
        using var current = await store.ReadOwnedBatchAsync(["floor", "part", "foreign"]);
        Assert.Null(current[0]); Assert.Null(current[1]); Assert.Equal(9, current[2]!.Use(bytes => bytes[0]));
    }
}
