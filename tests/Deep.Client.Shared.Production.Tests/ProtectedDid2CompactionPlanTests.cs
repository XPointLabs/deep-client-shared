using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2CompactionPlan;

namespace Deep.Client.Shared.Production.Tests;

// Actual file-lock/protected-storage staging, not authorized compaction SQL.
// Scope/terminal descriptors below are metadata fixtures, not native evidence.
public sealed class ProtectedDid2CompactionPlanTests
{
    private static readonly byte[] Network = Enumerable.Repeat((byte)1, 16).ToArray();
    private static readonly byte[] Account = Enumerable.Repeat((byte)2, 32).ToArray();
    private static readonly byte[] Instance = Enumerable.Repeat((byte)3, 32).ToArray();
    private static byte[] B(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static Preparation Prepare(Did2CompactionPlan idle)
    {
        var successor = Enumerable.Repeat((byte)11, PartBytes + 7).ToArray();
        return idle.Prepare(SqlTarget.ProtectedOnly, B(4), B(5), new byte[32], new byte[32],
            [new(RootKind.Grant, B(6), B(7), SHA256.HashData(successor), false, successor),
             new(RootKind.AccountRegistration, B(8), B(9), B(9), true, default),
             new(RootKind.NativeFence, B(10), B(9), B(9), true, default)],
            [new(Disposition.ReplayScope, B(12), B(13))]);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ExactStagingIsAtomicOwnedAndColdReopenDoesNotRecreateParts(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        using var held = await fixture.Lease.AcquireAsync(default);
        var custody = fixture.Custody();
        await Assert.ThrowsAsync<InvalidDataException>(() => custody.ReadAsync(held, default));
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        using var preparation = Prepare(idle);
        await custody.StageAsync(idle, preparation, held, default);
        using var readback = await custody.ReadSuccessorsAsync(preparation.Plan, held, default);
        var expectedBytes = preparation.Successors.Use(bytes => bytes.ToArray());
        try { Assert.True(readback.Use(bytes => bytes.SequenceEqual(expectedBytes))); }
        finally { CryptographicOperations.ZeroMemory(expectedBytes); }
        await custody.StageAsync(idle, preparation, held, default);
        using var current = await custody.ReadAsync(held, default);
        Assert.Equal(preparation.Plan.Exact.ToArray(), current.Exact.ToArray());
        if (journaled)
        {
            using var reopened = fixture.OpenJournaled();
            var cold = fixture.Custody(reopened);
            using var persisted = await cold.ReadSuccessorsAsync(current, held, default);
            Assert.True(persisted.Use(bytes => bytes.SequenceEqual(readback.Use(value => value.ToArray()))));
        }
        await fixture.Store.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(1)]);
        await Assert.ThrowsAsync<InvalidDataException>(() => custody.StageAsync(idle, preparation, held, default));
        using var absent = await fixture.Store.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(1));
        Assert.Null(absent);
    }

    [Theory]
    [InlineData("missing")] [InlineData("tampered")] [InlineData("truncated")]
    [InlineData("extra")] [InlineData("root")] [InlineData("instance")]
    public async Task ColdSuccessorReadRejectsMissingChangedExtraAndForeignCustody(string defect)
    {
        using var fixture = new Fixture(true);
        using var held = await fixture.Lease.AcquireAsync(default);
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        using var preparation = Prepare(idle);
        var custody = fixture.Custody();
        await custody.StageAsync(idle, preparation, held, default);
        if (defect == "missing") await fixture.Store.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)]);
        else if (defect == "extra") await fixture.Store.WriteBatchAsync([new(ProtectedDid2CompactionPlan.PartSlot(2), B(99))]);
        else if (defect == "root")
        {
            using var changed = preparation.Plan.WithSqlCommitted();
            Assert.True(await fixture.Store.CompareExchangeAsync(Slot, preparation.Plan.Exact, changed.Exact));
        }
        else if (defect is "tampered" or "truncated")
        {
            using var part = await fixture.Store.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(1));
            var original = part!.Use(bytes => bytes.ToArray());
            var changed = defect == "truncated" ? original[..^1] : original.Select(value => (byte)(value ^ 1)).ToArray();
            Assert.True(await fixture.Store.CompareExchangeAsync(ProtectedDid2CompactionPlan.PartSlot(1), original, changed));
        }
        using var reopened = fixture.OpenJournaled();
        var cold = defect == "instance" ? new ProtectedDid2CompactionPlan(reopened, fixture.Lease, Network, Account, B(99)) : fixture.Custody(reopened);
        if (defect == "root")
            await Assert.ThrowsAsync<CryptographicException>(() => cold.ReadSuccessorsAsync(preparation.Plan, held, default));
        else await Assert.ThrowsAsync<InvalidDataException>(() => cold.ReadSuccessorsAsync(preparation.Plan, held, default));
        using var retained = await fixture.Store.ReadOwnedAsync(Slot);
        Assert.NotNull(retained);
    }

    [Fact]
    public async Task ProtectionFailureAndPartConflictCannotPublishHalfAPlan()
    {
        using var fixture = new Fixture(true);
        using var held = await fixture.Lease.AcquireAsync(default);
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        using var preparation = Prepare(idle);
        var custody = fixture.Custody(); fixture.Protector.FailProtect = true;
        await Assert.ThrowsAsync<IOException>(() => custody.StageAsync(idle, preparation, held, default));
        fixture.Protector.FailProtect = false;
        using (var current = await custody.ReadAsync(held, default)) Assert.Equal(idle.Exact.ToArray(), current.Exact.ToArray());
        for (var index = 0; index < preparation.Plan.PartCount; index++)
        { using var part = await fixture.Store.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)); Assert.Null(part); }
        await fixture.Store.WriteBatchAsync([new(ProtectedDid2CompactionPlan.PartSlot(1), B(99))]);
        await Assert.ThrowsAsync<InvalidDataException>(() => custody.StageAsync(idle, preparation, held, default));
        using var unchanged = await custody.ReadAsync(held, default);
        Assert.Equal(idle.Exact.ToArray(), unchanged.Exact.ToArray());
        using var first = await fixture.Store.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(0)); Assert.Null(first);
    }

    [Fact]
    public async Task LostPublicationResponseRetainsExactCompletePlanForColdRetry()
    {
        using var fixture = new Fixture(true);
        using var held = await fixture.Lease.AcquireAsync(default);
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        using var preparation = Prepare(idle);
        var custody = fixture.Custody(new LostResponseStorage(fixture.Store));
        await Assert.ThrowsAsync<IOException>(() => custody.StageAsync(idle, preparation, held, default));
        using var reopened = fixture.OpenJournaled(); var cold = fixture.Custody(reopened);
        await cold.StageAsync(idle, preparation, held, default);
        using var exact = await cold.ReadSuccessorsAsync(preparation.Plan, held, default);
        Assert.Equal(preparation.Plan.SuccessorBytes, exact.Length);
    }

    [Fact]
    public async Task WrongDisposedAndCancelledActualLeasesCannotStageOrReleaseResults()
    {
        using var fixture = new Fixture(false);
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        using var preparation = Prepare(idle); var custody = fixture.Custody();
        var foreign = new DeepIdV2AccountFileLease(Path.Combine(fixture.Root, "foreign.lock"));
        using var wrong = await foreign.AcquireAsync(default);
        await Assert.ThrowsAsync<CryptographicException>(() => custody.StageAsync(idle, preparation, wrong, default));
        using var held = await fixture.Lease.AcquireAsync(default);
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => custody.StageAsync(idle, preparation, held, cancellation.Token));
        held.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => custody.ReadAsync(held, default));
        using var current = await fixture.Store.ReadOwnedAsync(Slot); Assert.Equal(idle.Exact.ToArray(), current!.Use(bytes => bytes.ToArray()));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task ExistingStorageCapacityRejectsWithoutChangingPlanOrInsertingParts(bool journaled)
    {
        using var fixture = new Fixture(journaled);
        using var held = await fixture.Lease.AcquireAsync(default);
        using var idle = RegisteredEmpty(Network, Account, Instance);
        await fixture.Store.WriteBatchAsync([new(Slot, idle.Exact)]);
        await fixture.Store.WriteBatchAsync(Enumerable.Range(0, 1023)
            .Select(index => new DeepSecureStorageWrite("unrelated-" + index, new byte[] { 1 })).ToArray());
        using var preparation = Prepare(idle); var custody = fixture.Custody();
        await Assert.ThrowsAsync<InvalidOperationException>(() => custody.StageAsync(idle, preparation, held, default));
        using var current = await custody.ReadAsync(held, default); Assert.Equal(idle.Exact.ToArray(), current.Exact.ToArray());
        for (var index = 0; index < preparation.Plan.PartCount; index++)
        { using var absent = await fixture.Store.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)); Assert.Null(absent); }
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "deep-compaction-staging-tests", Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        internal readonly Protector Protector;
        internal readonly IDeepSecureStorage Store;
        internal readonly DeepIdV2AccountFileLease Lease;
        internal Fixture(bool journaled)
        {
            Directory.CreateDirectory(Root); Protector = new(key);
            Store = journaled ? OpenJournaled(Protector) : new InMemoryDeepSecureStorage();
            Lease = new(Path.Combine(Root, "account.lock"));
        }
        private JournaledDeepSecureStorage OpenJournaled(Protector protector) => new(Path.Combine(Root, "protected.bin"), protector);
        // Each store owns/disposes its protector. Sharing it with a cold handle
        // would erase the first store's key when that handle closes.
        internal JournaledDeepSecureStorage OpenJournaled() => OpenJournaled(new Protector(key));
        internal ProtectedDid2CompactionPlan Custody(IDeepSecureStorage? storage = null) => new(storage ?? Store, Lease, Network, Account, Instance);
        public void Dispose()
        { ((IDisposable)Store).Dispose(); Protector.Dispose(); CryptographicOperations.ZeroMemory(key); Directory.Delete(Root, recursive: true); }
    }
    private sealed class Protector(ReadOnlySpan<byte> secret) : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key = secret.ToArray();
        internal bool FailProtect;
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            if (FailProtect) throw new IOException("Injected protection failure before atomic staging.");
            var result = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
            using var aes = new AesGcm(key, 16); aes.Encrypt(result.AsSpan(0, 12), plaintext, result.AsSpan(28), result.AsSpan(12, 16)); return result;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> ciphertext)
        {
            var result = new byte[ciphertext.Length - 28];
            try { using var aes = new AesGcm(key, 16); aes.Decrypt(ciphertext[..12], ciphertext[28..], ciphertext.Slice(12, 16), result); return result; }
            catch { CryptographicOperations.ZeroMemory(result); throw; }
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
    private sealed class LostResponseStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        public async Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken ct = default)
        { var result = await inner.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, ct); if (result) throw new IOException("Injected lost response after complete staging."); return result; }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default) => inner.ReadOwnedAsync(slot, ct);
        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default) => inner.WriteBatchAsync(writes, ct);
        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken ct = default) => inner.CompareExchangeAsync(slot, expected, replacement, ct);
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) => inner.DeleteBatchAsync(slots, ct);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV2NamespaceAsync(ct);
    }
}
