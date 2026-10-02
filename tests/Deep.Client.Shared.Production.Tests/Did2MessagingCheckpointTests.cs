using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Structural storage tests use opaque bytes, not authenticated TRS/DPE2.
// They do not mint a session, retirement permission, message or ACK.
public sealed class Did2MessagingCheckpointTests
{
    [Fact]
    public void ScopeAndFloorRejectMissingUnknownAndNoncanonicalFields()
    {
        var scope = Scope(); var empty = Did2MessagingFloor.Empty(scope);
        Assert.Equal(404, scope.Exact.Length); Assert.Equal(188, empty.Exact.Length);
        Assert.Equal(0UL, empty.Ordinal); Assert.Equal((byte)0, empty.Status);
        foreach (var offset in new[] { 0, 1, 2, 3 })
        {
            var corrupt = scope.Exact.ToArray(); corrupt[offset] = 0xff;
            Assert.Throws<InvalidDataException>(() => Did2MessagingSessionScope.RestoreMetadata(corrupt));
        }
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 })
        {
            var corrupt = scope.Exact.ToArray(); corrupt.AsSpan(offset, 32).Clear();
            Assert.Throws<InvalidDataException>(() => Did2MessagingSessionScope.RestoreMetadata(corrupt));
        }
        foreach (var offset in new[] { 84, 124, 164, 204 })
        {
            var corrupt = scope.Exact.ToArray(); corrupt.AsSpan(offset, 8).Clear();
            Assert.Throws<InvalidDataException>(() => Did2MessagingSessionScope.RestoreMetadata(corrupt));
        }
        var same = scope.Exact.ToArray(); scope.LocalAccount.CopyTo(same.AsSpan(132));
        Assert.Throws<CryptographicException>(() => Did2MessagingSessionScope.RestoreMetadata(same));
        Assert.Throws<CryptographicException>(() => Did2MessagingFloor.Decode(empty.Exact.Span, Scope(9)));
        Assert.Throws<InvalidDataException>(() => Did2MessagingFloor.PartsFor(Did2MessagingFloor.MaximumPendingBytes + 1));
        var payload = OpaquePayload(608); var pending = Pending(scope, empty, payload);
        Assert.Equal(1UL, pending.Ordinal); Assert.Equal((byte)2, pending.Phase);
        Assert.Throws<InvalidDataException>(() => pending.Stable(scope));
        Assert.Throws<InvalidDataException>(() => empty.Cleanup(scope));
        foreach (var offset in new[] { 184, 185, 186, 187 })
        {
            var corrupt = pending.Exact.ToArray(); corrupt[offset] = 0xff;
            Assert.ThrowsAny<Exception>(() => Did2MessagingFloor.Decode(corrupt, scope));
        }
        var corruptEmpty = empty.Exact.ToArray(); corruptEmpty[2] = 1;
        Assert.Throws<InvalidDataException>(() => Did2MessagingFloor.Decode(corruptEmpty, scope));
        var corruptLatch = pending.Exact.ToArray(); corruptLatch[2] = 2;
        Assert.Throws<InvalidDataException>(() => Did2MessagingFloor.Decode(corruptLatch, scope));
    }

    [Theory]
    [InlineData(608)]
    [InlineData(131072)]
    [InlineData(131073)]
    [InlineData(Did2MessagingFloor.MaximumPendingBytes)]
    public async Task SegmentedPendingRoundtripsAndErasesEveryPartBeforeStable(int size)
    {
        using var storage = new InMemoryDeepSecureStorage(); var scope = Scope();
        var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
        await owner.InitializeRegisteredSessionAsync(default);
        var empty = await owner.ReadAsync(default); var payload = OpaquePayload(size);
        var pending = Pending(scope, empty, payload);
        await owner.StageAsync(empty, pending, payload, default);
        using (var retained = await owner.ReadPendingAsync(pending, default))
            Assert.Equal(payload, retained.Use(bytes => bytes.ToArray()));
        await owner.StageAsync(empty, pending, payload, default); // exact lost-response retry
        var stable = await owner.FinishVerifiedSqlCommitAsync(pending, default);
        Assert.Equal((byte)1, stable.Phase); Assert.Equal(1UL, stable.Ordinal);
        Assert.Equal((byte)0, stable.Status); // cleanup does NOT activate messaging
        Assert.Equal(stable.Exact.ToArray(), (await owner.ReadAsync(default)).Exact.ToArray());
        await AssertNoParts(storage, scope);
        await owner.FinishVerifiedSqlCommitAsync(pending, default);
        await AssertNoParts(storage, scope);
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.InitializeRegisteredSessionAsync(default));
    }

    [Theory]
    [InlineData("write")]
    [InlineData("pending")]
    [InlineData("cleanup")]
    [InlineData("erase")]
    [InlineData("stable")]
    public async Task ExactRecoverySurvivesLostResponseAtEachProtectedBoundary(string boundary)
    {
        using var storage = new InMemoryDeepSecureStorage(); var scope = Scope();
        var fault = new LostResponseStorage(storage); var owner = new Did2MessagingProtectedCheckpoint(fault, scope);
        await owner.InitializeRegisteredSessionAsync(default);
        var empty = await owner.ReadAsync(default); var payload = OpaquePayload(131073);
        var pending = Pending(scope, empty, payload);
        if (boundary is "write" or "pending")
        {
            fault.Armed = boundary;
            await Assert.ThrowsAsync<IOException>(() => owner.StageAsync(empty, pending, payload, default));
            await owner.StageAsync(empty, pending, payload, default);
        }
        else
        {
            await owner.StageAsync(empty, pending, payload, default); fault.Armed = boundary;
            await Assert.ThrowsAsync<IOException>(() => owner.FinishVerifiedSqlCommitAsync(pending, default));
        }
        // A newly constructed owner has no transient recovery information.
        var restarted = new Did2MessagingProtectedCheckpoint(storage, scope);
        var stable = await restarted.FinishVerifiedSqlCommitAsync(pending, default);
        Assert.Equal((byte)1, stable.Phase); await AssertNoParts(storage, scope);
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("truncated")]
    [InlineData("changed")]
    [InlineData("extra")]
    public async Task MissingAlteredOrExtraPendingPartsRejectWithoutFloorAdvance(string defect)
    {
        using var storage = new InMemoryDeepSecureStorage(); var scope = Scope();
        var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
        await owner.InitializeRegisteredSessionAsync(default); var empty = await owner.ReadAsync(default);
        var payload = OpaquePayload(131073); var pending = Pending(scope, empty, payload);
        await owner.StageAsync(empty, pending, payload, default);
        var slot = scope.FloorSlot + ".pending.1";
        if (defect == "extra") await storage.WriteBatchAsync([new(scope.FloorSlot + ".pending.2", new byte[] { 1 })]);
        else if (defect == "absent") await storage.DeleteBatchAsync([slot]);
        else
        {
            using var current = await storage.ReadOwnedAsync(slot); Assert.NotNull(current);
            Assert.True(await storage.CompareExchangeAsync(slot, current.Use(bytes => bytes.ToArray()),
                defect == "truncated" ? new byte[] { 1, 2 } : new byte[] { 255 }));
        }
        await Assert.ThrowsAnyAsync<Exception>(async () => { using var rejected = await owner.ReadPendingAsync(pending, default); });
        Assert.Equal(pending.Exact.ToArray(), (await owner.ReadAsync(default)).Exact.ToArray());
    }

    [Fact]
    public async Task ChangedOrMissingFloorCannotOverwriteRetainedPending()
    {
        using var storage = new InMemoryDeepSecureStorage(); var scope = Scope();
        var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
        await Assert.ThrowsAsync<InvalidDataException>(() => owner.ReadAsync(default));
        await owner.InitializeRegisteredSessionAsync(default); var empty = await owner.ReadAsync(default);
        var first = OpaquePayload(608); var pending = Pending(scope, empty, first);
        await owner.StageAsync(empty, pending, first, default);
        var second = first.ToArray(); second[^1] ^= 1;
        var conflicting = Pending(scope, empty, second);
        await Assert.ThrowsAsync<CryptographicException>(() => owner.StageAsync(empty, conflicting, second, default));
        using var retained = await owner.ReadPendingAsync(pending, default);
        Assert.Equal(first, retained.Use(bytes => bytes.ToArray()));
        await storage.DeleteBatchAsync([scope.FloorSlot]);
        await Assert.ThrowsAsync<InvalidDataException>(() => owner.StageAsync(empty, pending, first, default));
    }

    [Fact]
    public async Task JournaledPlatformStorageKeepsExistingValueBoundAndPersistsSegmentedRecovery()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-msg-checkpoint-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); var path = Path.Combine(directory, "storage.bin");
        var key = RandomNumberGenerator.GetBytes(32); var scope = Scope(); var payload = OpaquePayload(Did2MessagingFloor.MaximumPendingBytes);
        try
        {
            Did2MessagingFloor pending;
            using (var storage = new JournaledDeepSecureStorage(path, new Protector(key)))
            {
                var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
                await owner.InitializeRegisteredSessionAsync(default); var empty = await owner.ReadAsync(default);
                await Assert.ThrowsAsync<ArgumentException>(() => storage.WriteBatchAsync([new("unrelated.oversized", new byte[1024 * 1024 + 1])]));
                await storage.WriteBatchAsync([new("unrelated.keep", new byte[] { 1 })]);
                pending = Pending(scope, empty, payload); await owner.StageAsync(empty, pending, payload, default);
            }
            using (var storage = new JournaledDeepSecureStorage(path, new Protector(key)))
            {
                var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
                using (var retained = await owner.ReadPendingAsync(pending, default))
                    Assert.Equal(payload, retained.Use(bytes => bytes.ToArray()));
                await owner.FinishVerifiedSqlCommitAsync(pending, default); await AssertNoParts(storage, scope);
                using var untouched = await storage.ReadOwnedAsync("unrelated.keep"); Assert.NotNull(untouched);
            }
            Assert.False(File.Exists(path + ".backup")); Assert.False(File.Exists(path + ".pending"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(payload);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    private static Did2MessagingSessionScope Scope(byte instance = 1)
    {
        var bytes = new byte[404]; bytes[0] = 1; bytes[1] = 1; bytes.AsSpan(4, 16).Fill(9);
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 }) bytes.AsSpan(offset, 32).Fill(checked((byte)(offset % 251 + 1)));
        bytes.AsSpan(20, 32).Fill(instance);
        foreach (var offset in new[] { 84, 124, 164, 204 }) BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), 1);
        return Did2MessagingSessionScope.RestoreMetadata(bytes);
    }
    private static byte[] OpaquePayload(int size) { var bytes = new byte[size]; RandomNumberGenerator.Fill(bytes); return bytes; }
    private static Did2MessagingFloor Pending(Did2MessagingSessionScope scope, Did2MessagingFloor empty, byte[] payload) =>
        Did2MessagingFloor.Pending(scope, empty, 0, 1, Enumerable.Repeat((byte)1, 32).ToArray(), Enumerable.Repeat((byte)2, 32).ToArray(), payload.AsSpan(0, Did2MessagingFloor.MetadataBytes), payload);
    private static async Task AssertNoParts(IDeepSecureStorage storage, Did2MessagingSessionScope scope)
    {
        for (var index = 0; index < Did2MessagingFloor.MaximumParts; index++)
        { using var part = await storage.ReadOwnedAsync(scope.FloorSlot + ".pending." + index); Assert.Null(part); }
    }

    private sealed class LostResponseStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        public Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected,
            ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions,
            CancellationToken ct = default) => inner.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, ct);
        internal string? Armed { get; set; }
        private void Fail(string boundary) { if (Armed != boundary) return; Armed = null; throw new IOException("Injected lost commit response."); }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default) => inner.ReadOwnedAsync(slot, ct);
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        { await inner.WriteBatchAsync(writes, ct); if (writes.Any(write => write.Slot.Contains(".pending."))) Fail("write"); }
        public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken ct = default)
        { var result = await inner.CompareExchangeAsync(slot, expected, replacement, ct); if (result) Fail(replacement.Span[1] switch { 1 => "stable", 2 => "pending", _ => "cleanup" }); return result; }
        public async Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) { await inner.DeleteBatchAsync(slots, ct); Fail("erase"); }
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV2NamespaceAsync(ct);
    }
    private sealed class Protector(byte[] key) : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] ownedKey = key.ToArray();
        public byte[] Protect(ReadOnlySpan<byte> bytes)
        {
            var result = new byte[28 + bytes.Length]; RandomNumberGenerator.Fill(result.AsSpan(0, 12));
            using var cipher = new AesGcm(ownedKey, 16); cipher.Encrypt(result.AsSpan(0, 12), bytes, result.AsSpan(28), result.AsSpan(12, 16)); return result;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> bytes)
        {
            var result = new byte[bytes.Length - 28];
            try { using var cipher = new AesGcm(ownedKey, 16); cipher.Decrypt(bytes[..12], bytes[28..], bytes.Slice(12, 16), result); return result; }
            catch { CryptographicOperations.ZeroMemory(result); throw; }
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(ownedKey);
    }
}
