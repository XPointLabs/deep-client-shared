using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed class OwnedByteExportsTests
{
    [Fact]
    public void TakeArrayTransfersTheFullOwnedArrayToTheCaller()
    {
        var bytes = new byte[] { 1, 2, 3, 4 };
        var taken = OwnedByteExports.TakeArray(bytes);
        Assert.Same(bytes, taken);
        CryptographicOperations.ZeroMemory(taken);
        Assert.All(bytes, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void SliceFallbackCopiesOnlyItsRangeAndErasesOnlyThatOwnedRange()
    {
        var bytes = new byte[] { 1, 2, 3, 4 };
        var taken = OwnedByteExports.TakeArray(bytes.AsMemory(1, 2));
        try
        {
            Assert.Equal(new byte[] { 2, 3 }, taken);
            Assert.Equal(new byte[] { 1, 0, 0, 4 }, bytes);
        }
        finally { CryptographicOperations.ZeroMemory(taken); CryptographicOperations.ZeroMemory(bytes); }
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(2, false)]
    public void EqualityConsumesTheExportForEveryResultWithoutTouchingExpected(int change, bool equal)
    {
        var owned = new byte[] { 1, 2, 3, 4 };
        var expected = change == 2 ? new byte[] { 1, 2, 3 } : new byte[] { 1, 2, 3, 4 };
        if (change == 1) expected[1] ^= 1;
        var before = expected.ToArray();
        try
        {
            Assert.Equal(equal, OwnedByteExports.EqualAndErase(owned, expected));
            Assert.All(owned, value => Assert.Equal((byte)0, value));
            Assert.Equal(before, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(owned); CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(before);
        }
    }

    [Fact]
    public void ErasingARealManifestExportDoesNotDisposeOrEraseTheBorrowedManifest()
    {
        using var manifest = ApplicationCoreCodec.AuthorDam1(
            Bytes(16, 1), Bytes(32, 2), Bytes(32, 3), Bytes(32, 4), 1,
            new[] { new Dam1ChunkEntry(0, 17, Bytes(32, 5)) }, 2000, "owned.bin", "application/octet-stream");
        var exported = manifest.CanonicalBytes;
        var expected = exported.ToArray();
        var taken = OwnedByteExports.TakeArray(exported);
        try
        {
            Assert.True(MemoryMarshal.TryGetArray(exported, out var backing));
            Assert.Same(backing.Array, taken);
            CryptographicOperations.ZeroMemory(taken);
            Assert.True(exported.Span.IndexOfAnyExcept((byte)0) < 0);
            var reexported = manifest.CanonicalBytes;
            Assert.True(OwnedByteExports.EqualAndErase(reexported, expected));
            Assert.True(reexported.Span.IndexOfAnyExcept((byte)0) < 0);
            var stillReadable = manifest.CanonicalBytes;
            try { Assert.True(stillReadable.Span.SequenceEqual(expected)); }
            finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(stillReadable).Span); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(taken); CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exported).Span);
        }
    }

    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();

    [Fact]
    public void ConsumingAnActualOutboxExportPreservesItsIndependentEntry()
    {
        using var entry = new DirectTextOutboxEntry([1, 2, 3, 4], Bytes(32, 6), Bytes(32, 7), 3);
        var export = entry.ExactDmc2;
        var taken = OwnedByteExports.TakeArray(export);
        CryptographicOperations.ZeroMemory(taken);
        Assert.True(export.Span.IndexOfAnyExcept((byte)0) < 0);
        var next = OwnedByteExports.TakeArray(entry.ExactDmc2);
        try { Assert.Equal(new byte[] { 1, 2, 3, 4 }, next); }
        finally { CryptographicOperations.ZeroMemory(next); }
    }
}
