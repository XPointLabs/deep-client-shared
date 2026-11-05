using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class DeepIdV2OrdinaryStoreLeaseTests
{
    [Fact]
    public void StoreGrantFlights_HaveFixedBoundAndCollisionOnlySerializes()
    {
        var first = new byte[32]; first[0] = 1; first[31] = 4;
        var sameStripe = first.ToArray(); sameStripe[31] = 5;
        var distinct = first.ToArray(); distinct[0] = 2;
        Assert.Equal(ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(first),
            ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(sameStripe));
        Assert.NotEqual(ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(first),
            ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(distinct));
        Assert.Equal(256, Enumerable.Range(0, 256).Select(index =>
        {
            var hash = new byte[32]; hash[0] = (byte)index;
            return ProtectedDeepIdV2AccountOwner.MailboxGrantFlightStripe(hash);
        }).Distinct().Count());
    }

    [Fact]
    public async Task StoreWait_DisablesBorrowAndOwnerUntilActualFileRejoin()
    {
        var directory = Path.Combine(Path.GetTempPath(), "deep-store-wait-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "account.lock"));
            using var held = await lease.AcquireAsync(default);
            using (held.BorrowFor(lease))
                Assert.Throws<InvalidOperationException>(held.SuspendForNetworkWait);
            held.RequireOwner(lease);
            held.SuspendForNetworkWait();
            Assert.Throws<ObjectDisposedException>(held.RequireActive);
            Assert.Throws<ObjectDisposedException>(() => held.BorrowFor(lease));
            using (var sibling = lease.TryAcquire())
            {
                Assert.NotNull(sibling);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => held.RejoinAfterNetworkWaitAsync(cancelled.Token));
                Assert.Throws<ObjectDisposedException>(held.RequireActive);
            }
            await held.RejoinAfterNetworkWaitAsync(default);
            held.RequireOwner(lease);
            Assert.Null(lease.TryAcquire());
        }
        finally { Directory.Delete(directory, true); }
    }
}
