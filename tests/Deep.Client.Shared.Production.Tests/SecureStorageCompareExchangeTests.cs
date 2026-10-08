using System.ComponentModel;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;

namespace Deep.Client.Shared.Production.Tests;

public sealed class SecureStorageCompareExchangeTests
{
    [WindowsStorageFact]
    public Task AtomicReplacementSurvivesTemporaryDeleteSharingConflict() =>
        CheckWindowsReplacementAsync("release");

    [WindowsStorageFact]
    public Task AtomicReplacementCancellationPreservesWholePreviousInventory() =>
        CheckWindowsReplacementAsync("cancel");

    [WindowsStorageFact]
    public Task AtomicReplacementPersistentDeleteSharingConflictFailsClosed() =>
        CheckWindowsReplacementAsync("exhaust");

    [WindowsStorageFact]
    public async Task AtomicReplacementReadOnlyDestinationFailsWithoutChangingPermissionsOrState()
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("catalog", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        var attributes = File.GetAttributes(fixture.StatePath);
        try
        {
            File.SetAttributes(fixture.StatePath, attributes | FileAttributes.ReadOnly);
            var error = await Assert.ThrowsAsync<Win32Exception>(() => fixture.Store.CompareExchangeAsync(
                "catalog", new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal(5, error.NativeErrorCode);
            Assert.True(File.GetAttributes(fixture.StatePath).HasFlag(FileAttributes.ReadOnly));
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        }
        finally { File.SetAttributes(fixture.StatePath, attributes); }
        using var reopened = fixture.OpenJournaled();
        using var current = await reopened.ReadOwnedAsync("catalog");
        using var foreign = await reopened.ReadOwnedAsync("foreign");
        Assert.Equal(1, current!.Use(value => value[0]));
        Assert.Equal(9, foreign!.Use(value => value[0]));
    }

    private static async Task CheckWindowsReplacementAsync(string outcome)
    {
        using var fixture = new Fixture(true);
        await fixture.Store.WriteBatchAsync([new("catalog", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        var original = File.ReadAllBytes(fixture.StatePath);
        using var cancelled = new CancellationTokenSource();
        var locked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        FileStream? blocker = null;
        fixture.Protector.AfterProtect = () =>
        {
            // Real native handle: reads/writes are shared, atomic rename/delete is not.
            blocker = new FileStream(fixture.StatePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite);
            locked.SetResult();
        };
        var commit = Task.Run(() => fixture.Store.CompareExchangeAndInsertAsync("catalog",
            new byte[] { 1 }, new byte[] { 2 }, [new("new-floor", new byte[] { 3 })], cancelled.Token));
        try
        {
            await locked.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // Longer than the old 127ms retry window. No test-only storage seam.
            await Task.Delay(350);
            Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
            if (commit.IsFaulted) await commit;
            if (outcome == "release")
            {
                Assert.False(commit.IsCompleted);
                blocker!.Dispose(); blocker = null;
                Assert.True(await commit.WaitAsync(TimeSpan.FromSeconds(10)));
            }
            else if (outcome == "cancel")
            {
                Assert.False(commit.IsCompleted);
                cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => commit.WaitAsync(TimeSpan.FromSeconds(10)));
            }
            else
            {
                var error = await Assert.ThrowsAsync<Win32Exception>(() => commit.WaitAsync(TimeSpan.FromSeconds(10)));
                Assert.Contains(error.NativeErrorCode, new[] { 5, 32, 33 });
            }
        }
        finally
        {
            cancelled.Cancel(); blocker?.Dispose(); fixture.Protector.AfterProtect = null;
            // Drain the owner before fixture disposal, including assertion failures.
            try { await commit.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (OperationCanceledException) { }
            catch (Win32Exception) { }
        }
        var succeeded = outcome == "release";
        if (!succeeded) Assert.Equal(original, File.ReadAllBytes(fixture.StatePath));
        using var reopened = fixture.OpenJournaled();
        using var current = await reopened.ReadOwnedAsync("catalog");
        using var foreign = await reopened.ReadOwnedAsync("foreign");
        using var floor = await reopened.ReadOwnedAsync("new-floor");
        Assert.Equal(succeeded ? 2 : 1, current!.Use(value => value[0]));
        Assert.Equal(9, foreign!.Use(value => value[0]));
        if (succeeded) Assert.Equal(3, floor!.Use(value => value[0]));
        else Assert.Null(floor);
        Assert.False(File.Exists(fixture.StatePath + ".pending"));
        Assert.False(File.Exists(fixture.StatePath + ".backup"));
    }

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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RegistrationIsAtomicInsertOnlyAndRejectsEveryConflictWithoutPartialMutation(bool journaled)
    {
        using var fixture = new Fixture(journaled); var store = fixture.Store;
        var insertions = new DeepSecureStorageWrite[] { new("floor-a", new byte[] { 10 }), new("floor-b", new byte[] { 11 }) };
        Assert.False(await store.CompareExchangeAndInsertAsync("catalog", new byte[] { 1 }, new byte[] { 2 }, insertions));
        await store.WriteBatchAsync([new("catalog", new byte[] { 1 }), new("foreign", new byte[] { 9 })]);
        Assert.False(await store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 }, insertions));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.CompareExchangeAndInsertAsync("catalog", new byte[] { 1 }, new byte[] { 2 }, insertions, cancelled.Token));
        using (var missing = await store.ReadOwnedAsync("floor-a")) Assert.Null(missing);
        Assert.True(await store.CompareExchangeAndInsertAsync("catalog", new byte[] { 1 }, new byte[] { 2 }, insertions));
        Assert.False(await store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 },
            [new("floor-a", new byte[] { 12 }), new("floor-c", new byte[] { 13 })]));
        using (var missing = await store.ReadOwnedAsync("floor-c")) Assert.Null(missing);
        await Assert.ThrowsAsync<ArgumentException>(() => store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 }, [new("catalog", new byte[] { 4 })]));
        await Assert.ThrowsAsync<ArgumentException>(() => store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 }, [new("repeat", new byte[] { 4 }), new("repeat", new byte[] { 5 })]));
        await Assert.ThrowsAsync<ArgumentException>(() => store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 }, [new(new string('x', 513), new byte[] { 4 })]));
        await Assert.ThrowsAsync<ArgumentException>(() => store.CompareExchangeAndInsertAsync("catalog", new byte[] { 2 }, new byte[] { 3 }, [new("oversized", new byte[1024 * 1024 + 1])]));
        using var current = await store.ReadOwnedAsync("catalog"); Assert.Equal(2, current!.Use(value => value[0]));
        using var foreign = await store.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(value => value[0]));
        using var floorA = await store.ReadOwnedAsync("floor-a"); Assert.Equal(10, floorA!.Use(value => value[0]));
        using var floorB = await store.ReadOwnedAsync("floor-b"); Assert.Equal(11, floorB!.Use(value => value[0]));
        if (journaled)
        {
            using var reopened = fixture.OpenJournaled();
            using var persisted = await reopened.ReadOwnedAsync("floor-b"); Assert.Equal(11, persisted!.Use(value => value[0]));
        }
    }

    [Fact]
    public async Task IndependentRegistrationHasOneCompleteWinnerAndProtectionFailureCannotPublishHalfInventory()
    {
        using var fixture = new Fixture(true); using var second = fixture.OpenJournaled();
        await fixture.Store.WriteBatchAsync([new("catalog", new byte[] { 1 })]);
        var outcomes = await Task.WhenAll(
            fixture.Store.CompareExchangeAndInsertAsync("catalog", new byte[] { 1 }, new byte[] { 2 }, [new("floor-a", new byte[] { 2 })]),
            second.CompareExchangeAndInsertAsync("catalog", new byte[] { 1 }, new byte[] { 3 }, [new("floor-b", new byte[] { 3 })]));
        Assert.Single(outcomes, value => value);
        using var before = await second.ReadOwnedAsync("catalog"); var expected = before!.Use(value => value.ToArray());
        using var winner = await second.ReadOwnedAsync(outcomes[0] ? "floor-a" : "floor-b"); Assert.Equal(expected[0], winner!.Use(value => value[0]));
        using var loser = await second.ReadOwnedAsync(outcomes[0] ? "floor-b" : "floor-a"); Assert.Null(loser);
        fixture.Protector.FailProtect = true;
        await Assert.ThrowsAsync<IOException>(() => fixture.Store.CompareExchangeAndInsertAsync("catalog", expected, new byte[] { 4 }, [new("floor-failed", new byte[] { 4 })]));
        using var after = await second.ReadOwnedAsync("catalog"); Assert.True(after!.Use(value => value.SequenceEqual(expected)));
        using var absent = await second.ReadOwnedAsync("floor-failed"); Assert.Null(absent);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InventoryAccommodates512FloorsAndOne18PartPayloadButHardCapRejectsAtomically(bool journaled)
    {
        using var fixture = new Fixture(journaled); var store = fixture.Store;
        var inventory = Enumerable.Range(0, 1024).Select(index => new DeepSecureStorageWrite("slot-" + index, new byte[] { 1 })).ToArray();
        await store.WriteBatchAsync(inventory);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.CompareExchangeAndInsertAsync("slot-0", new byte[] { 1 }, new byte[] { 2 }, [new("overflow", new byte[] { 3 })]));
        using var original = await store.ReadOwnedAsync("slot-0"); Assert.Equal(1, original!.Use(value => value[0]));
        using var absent = await store.ReadOwnedAsync("overflow"); Assert.Null(absent);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WriteBatchAsync([new("another-overflow", new byte[] { 4 })]));
        if (journaled)
        {
            using var reopened = fixture.OpenJournaled();
            using var last = await reopened.ReadOwnedAsync("slot-1023"); Assert.Equal(1, last!.Use(value => value[0]));
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-storage-cas-tests", Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        internal readonly Protector Protector;
        internal readonly IDeepSecureStorage Store;
        internal string StatePath => Path.Combine(root, "protected.bin");
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
        internal Action? AfterProtect;
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            if (FailProtect) throw new IOException("Injected protection failure before commit.");
            var result = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(result.AsSpan(0, 12), plaintext, result.AsSpan(28), result.AsSpan(12, 16));
            AfterProtect?.Invoke();
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

public sealed class WindowsStorageFactAttribute : FactAttribute
{
    public WindowsStorageFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires native Windows file-sharing and MoveFileEx semantics.";
    }
}
