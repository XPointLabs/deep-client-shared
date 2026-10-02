using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class HeldDeepIdV2AccountLeaseTests
{
    [Fact]
    public async Task ActualBorrowRetainsExclusiveLockAndDisposedOwnerCannotReleaseResults()
    {
        var directory = Path.Combine(Path.GetTempPath(), "did2-held-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "account.lock"));
            var foreign = new DeepIdV2AccountFileLease(Path.Combine(directory, "foreign.lock"));
            using var held = await lease.AcquireAsync(default);
            Assert.Throws<CryptographicException>(() => held.BorrowFor(foreign));
            var borrow = held.BorrowFor(lease);
            held.Dispose();
            Assert.Throws<ObjectDisposedException>(held.RequireActive);
            Assert.Throws<ObjectDisposedException>(() => held.BorrowFor(lease));
            using (var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lease.AcquireAsync(cancelled.Token).AsTask());
            borrow.Dispose(); borrow.Dispose(); // The borrow releases once.
            using var reopened = await lease.AcquireAsync(default);
            reopened.RequireOwner(lease);
        }
        finally { Directory.Delete(directory, recursive: true); } // Exact test-created directory only.
    }
}
