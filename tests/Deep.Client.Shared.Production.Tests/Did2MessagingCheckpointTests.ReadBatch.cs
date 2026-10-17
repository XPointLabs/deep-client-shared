using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class Did2MessagingCheckpointTests
{
    [Theory]
    [InlineData("none")] [InlineData("missing-floor")] [InlineData("missing-part")]
    [InlineData("truncated")] [InlineData("tampered")] [InlineData("extra")]
    [InlineData("foreign-floor")] [InlineData("cancelled")]
    public async Task PendingInventoryReadIsFreshAtomicAndRejectsBrokenCustodyWithoutWrites(string fault)
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-pending-batch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "protected.bin");
        var key = RandomNumberGenerator.GetBytes(32);
        var payload = OpaquePayload(Did2MessagingFloor.PartBytes + 1);
        try
        {
            using var protector = new Protector(key);
            using var storage = new JournaledDeepSecureStorage(path, protector);
            var scope = Scope(); var owner = new Did2MessagingProtectedCheckpoint(storage, scope);
            await owner.InitializeRegisteredSessionAsync(default);
            var empty = await owner.ReadAsync(default); var pending = Pending(scope, empty, payload);
            await owner.StageAsync(empty, pending, payload, default);
            var part = scope.FloorSlot + ".pending.1";
            if (fault == "missing-floor") await storage.DeleteBatchAsync([scope.FloorSlot]);
            if (fault == "missing-part") await storage.DeleteBatchAsync([part]);
            if (fault is "truncated" or "tampered")
            {
                using var old = await storage.ReadOwnedAsync(part) ?? throw new InvalidDataException();
                var exact = old.Use(bytes => bytes.ToArray());
                var changed = fault == "truncated" ? new byte[2] : new[] { (byte)(exact[0] ^ 1) };
                Assert.True(await storage.CompareExchangeAsync(part, exact, changed));
                CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(changed);
            }
            if (fault == "extra") await storage.WriteBatchAsync([new(scope.FloorSlot + ".pending.17", new byte[] { 1 })]);
            if (fault == "foreign-floor")
                Assert.True(await storage.CompareExchangeAsync(scope.FloorSlot, pending.Exact,
                    Pending(Scope(9), Did2MessagingFloor.Empty(Scope(9)), payload).Exact));
            using var cancelled = new CancellationTokenSource();
            if (fault == "cancelled") protector.AfterUnprotect = cancelled.Cancel;
            var before = await File.ReadAllBytesAsync(path); var reads = protector.UnprotectCalls;
            if (fault == "none")
            {
                using (var actual = await owner.ReadPendingAsync(pending, default))
                    Assert.Equal(payload, actual.Use(bytes => bytes.ToArray()));
                Assert.Equal(reads + 1, protector.UnprotectCalls);
                using (var actual = await owner.ReadPendingAsync(pending, default))
                    Assert.Equal(payload, actual.Use(bytes => bytes.ToArray()));
                Assert.Equal(reads + 2, protector.UnprotectCalls); // No cross-call plaintext snapshot.
            }
            else
            {
                var error = await Record.ExceptionAsync(() => owner.ReadPendingAsync(pending, cancelled.Token));
                if (fault == "cancelled") Assert.IsAssignableFrom<OperationCanceledException>(error);
                else Assert.True(error is InvalidDataException or CryptographicException);
                Assert.Equal(reads + 1, protector.UnprotectCalls);
            }
            Assert.Equal(before, await File.ReadAllBytesAsync(path));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(payload);
            Directory.Delete(directory, recursive: true);
        }
    }
}
