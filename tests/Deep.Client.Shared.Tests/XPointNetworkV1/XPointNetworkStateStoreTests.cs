using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class XPointNetworkStateStoreTests
{
    [Fact]
    public async Task InMemory_CasAndDefensiveCopiesPreserveRollbackFloor()
    {
        IXPointNetworkStateStore store = new InMemoryXPointNetworkStateStore();
        var initial = new XPointNetworkStateSnapshot(1, Lkg(7, 0x21), false);

        var applied = await store.CompareExchangeAsync(null, initial, default);
        Assert.Equal(XPointNetworkStoreWriteDisposition.Applied, applied.Disposition);
        var escaped = applied.Snapshot!.ProtectedLkg.HeadRoot.ToArray();
        escaped[0] ^= 0xff;

        var current = await store.ReadAsync(default);
        Assert.Equal(Lkg(7, 0x21).HeadRoot.ToArray(), current!.ProtectedLkg.HeadRoot.ToArray());
        var conflict = await store.CompareExchangeAsync(
            null,
            new XPointNetworkStateSnapshot(1, Lkg(8, 0x31), false),
            default);
        Assert.Equal(XPointNetworkStoreWriteDisposition.Conflict, conflict.Disposition);
        Assert.Equal(1UL, conflict.Snapshot!.Revision);

        var next = new XPointNetworkStateSnapshot(2, Lkg(8, 0x31), true);
        Assert.Equal(
            XPointNetworkStoreWriteDisposition.Applied,
            (await store.CompareExchangeAsync(1, next, default)).Disposition);
        Assert.True((await store.ReadAsync(default))!.ForkLatched);
    }

    [Fact]
    public async Task InMemory_RequiresStrictNextRevision()
    {
        IXPointNetworkStateStore store = new InMemoryXPointNetworkStateStore();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.CompareExchangeAsync(
                null,
                new XPointNetworkStateSnapshot(2, Lkg(7, 0x21), false),
                default));
    }

    [Fact]
    public async Task InMemory_ForkLatchCannotBeCleared()
    {
        IXPointNetworkStateStore store = new InMemoryXPointNetworkStateStore();
        await store.CompareExchangeAsync(
            null,
            new XPointNetworkStateSnapshot(1, Lkg(7, 0x21), true),
            default);

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.CompareExchangeAsync(
                1,
                new XPointNetworkStateSnapshot(2, Lkg(8, 0x31), false),
                default));
        Assert.True((await store.ReadAsync(default))!.ForkLatched);
    }

    internal static XPointNetworkProtectedLkg Lkg(ulong generation, byte marker) => new(
        Bytes(16, 0x11),
        Reference("XNH1", marker),
        checked(generation + 1),
        Bytes(32, (byte)(marker + 1)),
        Reference("XNV1", (byte)(marker + 2)),
        generation,
        Reference("XNA1", (byte)(marker + 3)),
        Reference("XNF1", (byte)(marker + 4)),
        generation);

    internal static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        Bytes(32, marker).CopyTo(value, 6);
        return value;
    }

    internal static byte[] Bytes(int length, byte marker) =>
        Enumerable.Range(0, length).Select(index => (byte)(marker + index)).ToArray();
}
