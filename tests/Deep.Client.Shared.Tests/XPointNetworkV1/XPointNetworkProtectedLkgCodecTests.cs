using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Tests.XPointNetworkV1;

public sealed class XPointNetworkProtectedLkgCodecTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RoundTrip_PreservesExactRollbackFloor(bool withCheckpoint)
    {
        var original = Lkg(withCheckpoint);

        var encoded = XPointNetworkProtectedLkgCodec.Encode(original);
        var restored = XPointNetworkProtectedLkgCodec.Decode(encoded);

        Assert.Equal(265, encoded.Length);
        AssertLkg(original, restored);
        Assert.Equal(encoded, XPointNetworkProtectedLkgCodec.Encode(restored));
    }

    [Fact]
    public void Decode_RejectsEverySingleByteTamper()
    {
        var encoded = XPointNetworkProtectedLkgCodec.Encode(Lkg(true));
        for (var index = 0; index < encoded.Length; index++)
        {
            var changed = encoded.ToArray();
            changed[index] ^= 0x01;
            Assert.Throws<FormatException>(() => XPointNetworkProtectedLkgCodec.Decode(changed));
        }
    }

    [Fact]
    public void Decode_RejectsNonCanonicalAbsentCheckpointPayloadEvenWithValidChecksum()
    {
        var encoded = XPointNetworkProtectedLkgCodec.Encode(Lkg(false));
        encoded[196] = 0x44;
        RewriteChecksum(encoded);

        Assert.Throws<FormatException>(() => XPointNetworkProtectedLkgCodec.Decode(encoded));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(264)]
    [InlineData(266)]
    public void Decode_RejectsWrongExactLength(int length)
    {
        Assert.Throws<FormatException>(() =>
            XPointNetworkProtectedLkgCodec.Decode(new byte[length]));
    }

    private static XPointNetworkProtectedLkg Lkg(bool withCheckpoint) => new(
        Bytes(16, 0x11),
        Reference("XNH1", 0x21),
        8,
        Bytes(32, 0x31),
        Reference("XNV1", 0x41),
        7,
        Reference("XNA1", 0x51),
        withCheckpoint ? Reference("XNF1", 0x61) : default,
        withCheckpoint ? 5UL : null);

    private static void AssertLkg(
        XPointNetworkProtectedLkg expected,
        XPointNetworkProtectedLkg actual)
    {
        Assert.Equal(expected.NetworkId.ToArray(), actual.NetworkId.ToArray());
        Assert.Equal(expected.HeadCoreReference.ToArray(), actual.HeadCoreReference.ToArray());
        Assert.Equal(expected.HeadTreeSize, actual.HeadTreeSize);
        Assert.Equal(expected.HeadRoot.ToArray(), actual.HeadRoot.ToArray());
        Assert.Equal(expected.ViewCoreReference.ToArray(), actual.ViewCoreReference.ToArray());
        Assert.Equal(expected.ViewGeneration, actual.ViewGeneration);
        Assert.Equal(expected.AuthorityCoreReference.ToArray(), actual.AuthorityCoreReference.ToArray());
        Assert.Equal(
            expected.LastForwardCheckpointCoreReference.ToArray(),
            actual.LastForwardCheckpointCoreReference.ToArray());
        Assert.Equal(
            expected.LastForwardCheckpointGeneration,
            actual.LastForwardCheckpointGeneration);
    }

    private static byte[] Reference(string magic, byte marker)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        Bytes(32, marker).CopyTo(value, 6);
        return value;
    }

    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Range(0, length).Select(index => (byte)(marker + index)).ToArray();

    private static void RewriteChecksum(byte[] encoded)
    {
        const string domain = "Deep/Client/XPointNetworkV1/protected-lkg";
        var label = System.Text.Encoding.ASCII.GetBytes(domain);
        var payloadLength = encoded.Length - 32;
        var preimage = new byte[label.Length + 5 + payloadLength];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(label.Length + 1, 4),
            (uint)payloadLength);
        encoded.AsSpan(0, payloadLength).CopyTo(preimage.AsSpan(label.Length + 5));
        System.Security.Cryptography.SHA256.HashData(preimage).CopyTo(encoded, payloadLength);
    }
}
