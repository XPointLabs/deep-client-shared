using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class Did2MessagingCheckpointTests
{
    // Structural checkpoint/backend mechanics, not authenticated ratchet,
    // message/ACK authority, native PQ or physical delivery evidence.
    [Theory]
    [InlineData("parts")] [InlineData("empty")] [InlineData("pending")]
    [InlineData("absent")] [InlineData("malformed")] [InlineData("corrupt")]
    public async Task StableOrphanCleanup_UsesOneAuthenticatedGuardedDeletionAndRejectsChangedFloor(string defect)
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-guarded-cleanup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "protected.bin");
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var protector = new CountingCleanupProtector(key);
            using var store = new JournaledDeepSecureStorage(path, protector);
            var scope = Scope(); var stable = Did2MessagingFloor.Empty(scope);
            var owner = new Did2MessagingProtectedCheckpoint(store, scope);
            await owner.InitializeRegisteredSessionAsync(default);
            await store.WriteBatchAsync([new("foreign", new byte[] { 9 })]);
            var part = scope.FloorSlot + ".pending.0";
            byte[] expectedPart = [7];
            if (defect is not ("empty" or "pending")) await store.WriteBatchAsync([new(part, expectedPart)]);
            if (defect == "pending")
            {
                expectedPart = OpaquePayload(Did2MessagingFloor.MetadataBytes);
                var pending = Pending(scope, stable, expectedPart);
                await owner.StageAsync(stable, pending, expectedPart, default);
                using var owned = await owner.ReadPendingAsync(pending, default);
                Assert.True(owned.Use(bytes => bytes.SequenceEqual(expectedPart)));
            }
            if (defect == "absent") await store.DeleteBatchAsync([scope.FloorSlot]);
            if (defect == "malformed")
            {
                var malformed = stable.Exact.ToArray(); malformed[0] = 0xff;
                Assert.True(await store.CompareExchangeAsync(scope.FloorSlot, stable.Exact, malformed));
            }
            var original = File.ReadAllBytes(path);
            if (defect == "corrupt") { original[^1] ^= 1; File.WriteAllBytes(path, original); }
            var loads = protector.UnprotectCalls; var protects = protector.ProtectCalls;
            if (defect is "parts" or "empty")
            {
                await owner.EraseStableOrphansAsync(stable, default);
                Assert.Equal(loads + 1, protector.UnprotectCalls);
                Assert.Equal(protects + (defect == "parts" ? 1 : 0), protector.ProtectCalls);
                if (defect == "empty") Assert.Equal(original, File.ReadAllBytes(path));
                using var reopened = new JournaledDeepSecureStorage(path, new CountingCleanupProtector(key));
                using var missing = await reopened.ReadOwnedAsync(part); Assert.Null(missing);
                var current = await new Did2MessagingProtectedCheckpoint(reopened, scope).ReadAsync(default);
                Assert.Equal(stable.Exact.ToArray(), current.Exact.ToArray());
                using var foreign = await reopened.ReadOwnedAsync("foreign"); Assert.Equal(9, foreign!.Use(bytes => bytes[0]));
            }
            else
            {
                if (defect == "absent")
                    await Assert.ThrowsAsync<InvalidDataException>(() => owner.EraseStableOrphansAsync(stable, default));
                else
                    await Assert.ThrowsAnyAsync<CryptographicException>(() => owner.EraseStableOrphansAsync(stable, default));
                Assert.Equal(protects, protector.ProtectCalls);
                Assert.Equal(original, File.ReadAllBytes(path));
                if (defect != "corrupt")
                {
                    using var retained = await store.ReadOwnedAsync(part);
                    Assert.True(retained!.Use(bytes => bytes.SequenceEqual(expectedPart)));
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            foreach (var file in Directory.EnumerateFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    private sealed class CountingCleanupProtector(ReadOnlySpan<byte> value) : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key = value.ToArray();
        internal int ProtectCalls, UnprotectCalls;
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            ProtectCalls++;
            var bytes = new byte[plaintext.Length + 28]; RandomNumberGenerator.Fill(bytes.AsSpan(0, 12));
            using var cipher = new AesGcm(key, 16);
            cipher.Encrypt(bytes.AsSpan(0, 12), plaintext, bytes.AsSpan(28), bytes.AsSpan(12, 16));
            return bytes;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> bytes)
        {
            UnprotectCalls++;
            var plaintext = new byte[bytes.Length - 28];
            try
            {
                using var cipher = new AesGcm(key, 16);
                cipher.Decrypt(bytes[..12], bytes[28..], bytes.Slice(12, 16), plaintext);
                return plaintext;
            }
            catch { CryptographicOperations.ZeroMemory(plaintext); throw; }
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
}
