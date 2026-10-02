using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2ContactStartCustodyTests
{
    [Theory]
    [InlineData(780, 6199, true)] [InlineData(1830, 6199, true)]
    [InlineData(780, 15145, true)] [InlineData(1830, 14095, true)]
    [InlineData(780, 15146, false)] [InlineData(1830, 14096, false)]
    [InlineData(779, 6199, false)] [InlineData(1831, 6199, false)]
    [InlineData(780, 6198, false)] [InlineData(780, 25351, false)]
    [InlineData(int.MaxValue, int.MaxValue, false)]
    public void ExactInitialPreflightUsesTheUnchangedWorstCaseBucket(int init, int hello, bool allowed)
    {
        if (allowed) ProtectedDid2ContactStartJournal.RequireInitialBucket(init, hello);
        else Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.RequireInitialBucket(init, hello));
    }

    [Fact]
    public void MandatoryEmptyRootRejectsForeignUnknownHostileAndTrailingFraming()
    {
        var network = B(16, 1); var account = B(32, 2); var instance = B(32, 3);
        var exact = ProtectedDid2ContactStartJournal.Empty(network, account, instance);
        using var empty = ProtectedDid2ContactStartJournal.Decode(exact, network, account, instance);
        Assert.Empty(empty.Entries); Assert.Equal(92, exact.Length);
        foreach (var offset in new[] { 0, 1, 2, 11, 12, 28, 60 })
        {
            var bad = exact.ToArray(); bad[offset] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => ProtectedDid2ContactStartJournal.Decode(bad, network, account, instance));
        }
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(exact[..^1], network, account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode([.. exact, 0], network, account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(new byte[ProtectedDid2ContactStartJournal.MaximumBytes + 1], network, account, instance));
        var hostile = exact.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(hostile.AsSpan(2), 129);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(hostile, network, account, instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2ContactStartJournal.Decode(exact, network, account, B(32, 4)));
        CryptographicOperations.ZeroMemory(exact);
    }
    private static byte[] B(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
