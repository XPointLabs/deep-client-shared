using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class XPointNetworkStateClientTests
{
    [Fact]
    public async Task ForwardCheckpoint_AtomicallyAdvancesAndIsIdempotent()
    {
        var store = await StoreWithAsync(XPointNetworkStateStoreTests.Lkg(7, 0x21));
        var client = new XPointNetworkStateClient(store);
        var advance = new TestAdvance(
            XPointNetworkStateStoreTests.Lkg(7, 0x21),
            XPointNetworkStateStoreTests.Lkg(8, 0x31));

        var applied = await client.ApplyAsync(advance, default);
        var replay = await client.ApplyAsync(advance, default);

        Assert.Equal(XPointNetworkAdvanceDisposition.Applied, applied.Disposition);
        Assert.Equal(2UL, applied.Snapshot.Revision);
        Assert.Equal(XPointNetworkAdvanceDisposition.Idempotent, replay.Disposition);
        Assert.Equal(2UL, replay.Snapshot.Revision);
    }

    [Fact]
    public async Task OperationalSuccessor_PreservesExistingForwardCheckpointFloor()
    {
        var checkpointReference = XPointNetworkStateStoreTests.Reference("XNF1", 0x61);
        var current = LkgWithCheckpoint(7, 0x21, checkpointReference, 4);
        var next = LkgWithCheckpoint(8, 0x31, checkpointReference, 4);
        var store = await StoreWithAsync(current);
        var client = new XPointNetworkStateClient(store);

        var result = await client.ApplyAsync(new TestAdvance(current, next), default);

        Assert.Equal(XPointNetworkAdvanceDisposition.Applied, result.Disposition);
        Assert.Equal(4UL, result.Snapshot.ProtectedLkg.LastForwardCheckpointGeneration);
        Assert.Equal(checkpointReference,
            result.Snapshot.ProtectedLkg.LastForwardCheckpointCoreReference.ToArray());
    }

    [Fact]
    public async Task StaleCapability_CannotReplaceNewerProtectedFloor()
    {
        var current = XPointNetworkStateStoreTests.Lkg(8, 0x31);
        var store = await StoreWithAsync(current);
        var client = new XPointNetworkStateClient(store);

        var result = await client.ApplyAsync(
            new TestAdvance(
                XPointNetworkStateStoreTests.Lkg(7, 0x21),
                XPointNetworkStateStoreTests.Lkg(9, 0x41)),
            default);

        Assert.Equal(XPointNetworkAdvanceDisposition.StaleCapability, result.Disposition);
        Assert.Equal(current.ViewCoreReference.ToArray(),
            result.Snapshot.ProtectedLkg.ViewCoreReference.ToArray());
    }

    [Fact]
    public async Task NonMonotonicVerifiedAdvance_FailsClosed()
    {
        var current = XPointNetworkStateStoreTests.Lkg(8, 0x31);
        var store = await StoreWithAsync(current);
        var client = new XPointNetworkStateClient(store);

        await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            await client.ApplyAsync(
                new TestAdvance(current, XPointNetworkStateStoreTests.Lkg(7, 0x21)),
                default));
    }

    [Fact]
    public async Task ForkLatch_BlocksEveryFurtherAdvance()
    {
        var store = new InMemoryXPointNetworkStateStore();
        var current = XPointNetworkStateStoreTests.Lkg(8, 0x31);
        await store.CompareExchangeAsync(
            null,
            new XPointNetworkStateSnapshot(1, current, true),
            default);
        var client = new XPointNetworkStateClient(store);

        var result = await client.ApplyAsync(
            new TestAdvance(current, XPointNetworkStateStoreTests.Lkg(9, 0x41)),
            default);

        Assert.Equal(XPointNetworkAdvanceDisposition.ForkLatched, result.Disposition);
        Assert.Equal(1UL, result.Snapshot.Revision);
    }

    [Fact]
    public async Task MissingBootstrapLkg_CannotBeFilledFromForwardCapability()
    {
        var client = new XPointNetworkStateClient(new InMemoryXPointNetworkStateStore());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await client.ApplyAsync(
                new TestAdvance(
                    XPointNetworkStateStoreTests.Lkg(7, 0x21),
                    XPointNetworkStateStoreTests.Lkg(8, 0x31)),
                default));
    }

    [Fact]
    public async Task InitialVerifiedContextShape_InstallsFirstProtectedFloor()
    {
        var store = new InMemoryXPointNetworkStateStore();
        var client = new XPointNetworkStateClient(store);
        var first = XPointNetworkStateStoreTests.Lkg(7, 0x21);

        var result = await client.ApplyAsync(new TestAdvance(null, first), default);

        Assert.Equal(XPointNetworkAdvanceDisposition.Applied, result.Disposition);
        Assert.Equal(1UL, result.Snapshot.Revision);
        Assert.Equal(first.HeadRoot.ToArray(),
            (await client.RestoreProtectedLkgAsync())!.HeadRoot.ToArray());
    }

    private static async Task<InMemoryXPointNetworkStateStore> StoreWithAsync(
        XPointNetworkProtectedLkg lkg)
    {
        var store = new InMemoryXPointNetworkStateStore();
        await store.CompareExchangeAsync(
            null,
            new XPointNetworkStateSnapshot(1, lkg, false),
            default);
        return store;
    }

    private static XPointNetworkProtectedLkg LkgWithCheckpoint(
        ulong viewGeneration,
        byte marker,
        byte[] checkpointReference,
        ulong checkpointGeneration) => new(
            XPointNetworkStateStoreTests.Bytes(16, 0x11),
            XPointNetworkStateStoreTests.Reference("XNH1", marker),
            checked(viewGeneration + 1),
            XPointNetworkStateStoreTests.Bytes(32, (byte)(marker + 1)),
            XPointNetworkStateStoreTests.Reference("XNV1", (byte)(marker + 2)),
            viewGeneration,
            XPointNetworkStateStoreTests.Reference("XNA1", (byte)(marker + 3)),
            checkpointReference,
            checkpointGeneration);

    private sealed class TestAdvance(
        XPointNetworkProtectedLkg? prior,
        XPointNetworkProtectedLkg next) : IXPointNetworkVerifiedAdvance
    {
        public XPointNetworkProtectedLkg? Prior { get; } = prior;
        public XPointNetworkProtectedLkg Next { get; } = next;
    }
}
