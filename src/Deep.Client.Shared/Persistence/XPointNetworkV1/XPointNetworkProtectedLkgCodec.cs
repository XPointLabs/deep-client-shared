using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.XPointNetworkV1;

/// <summary>
/// Canonical local-store encoding for the public-network rollback floor. XLK1
/// is an encrypted-database payload, not a network record or trust source.
/// </summary>
public static class XPointNetworkProtectedLkgCodec
{
    private const int HeaderBytes = 8;
    private const int BodyBytes = 225;
    private const int ChecksumBytes = 32;
    private const int EncodedBytes = HeaderBytes + BodyBytes + ChecksumBytes;
    private const string ChecksumDomain = "Deep/Client/XPointNetworkV1/protected-lkg";
    private static readonly byte[] Magic = "XLK1"u8.ToArray();

    public static byte[] Encode(XPointNetworkProtectedLkg value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var encoded = new byte[EncodedBytes];
        Magic.CopyTo(encoded, 0);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6), 0);

        var offset = HeaderBytes;
        Copy(value.NetworkId.Span, encoded, ref offset, 16);
        Copy(value.HeadCoreReference.Span, encoded, ref offset, 38);
        WriteU64(value.HeadTreeSize, encoded, ref offset);
        Copy(value.HeadRoot.Span, encoded, ref offset, 32);
        Copy(value.ViewCoreReference.Span, encoded, ref offset, 38);
        WriteU64(value.ViewGeneration, encoded, ref offset);
        Copy(value.AuthorityCoreReference.Span, encoded, ref offset, 38);

        var hasCheckpoint = value.LastForwardCheckpointGeneration.HasValue;
        encoded[offset++] = hasCheckpoint ? (byte)1 : (byte)0;
        if (hasCheckpoint)
        {
            Copy(value.LastForwardCheckpointCoreReference.Span, encoded, ref offset, 38);
            WriteU64(value.LastForwardCheckpointGeneration!.Value, encoded, ref offset);
        }
        else
        {
            offset += 46;
        }

        if (offset != HeaderBytes + BodyBytes)
            throw new InvalidOperationException("XLK1 body length invariant failed.");
        var checksum = Hash(encoded.AsSpan(0, offset));
        checksum.CopyTo(encoded, offset);
        CryptographicOperations.ZeroMemory(checksum);
        return encoded;
    }

    public static XPointNetworkProtectedLkg Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedBytes)
            throw new FormatException("XLK1 has an invalid exact length.");
        if (!encoded[..4].SequenceEqual(Magic)
            || BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != 1
            || BinaryPrimitives.ReadUInt16BigEndian(encoded[6..8]) != 0)
            throw new FormatException("XLK1 header is not canonical.");

        var checksum = Hash(encoded[..^ChecksumBytes]);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(checksum, encoded[^ChecksumBytes..]))
                throw new FormatException("XLK1 checksum verification failed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(checksum);
        }

        var offset = HeaderBytes;
        var networkId = Read(encoded, ref offset, 16);
        var headReference = Read(encoded, ref offset, 38);
        var headTreeSize = ReadU64(encoded, ref offset);
        var headRoot = Read(encoded, ref offset, 32);
        var viewReference = Read(encoded, ref offset, 38);
        var viewGeneration = ReadU64(encoded, ref offset);
        var authorityReference = Read(encoded, ref offset, 38);
        var presence = encoded[offset++];
        if (presence > 1)
            throw new FormatException("XLK1 checkpoint presence flag is invalid.");
        var checkpointReference = Read(encoded, ref offset, 38);
        var checkpointGeneration = ReadU64(encoded, ref offset);
        if (offset != HeaderBytes + BodyBytes)
            throw new FormatException("XLK1 body has trailing bytes.");
        if (presence == 0 && (checkpointReference.IndexOfAnyExcept((byte)0) >= 0
                              || checkpointGeneration != 0))
            throw new FormatException("XLK1 absent checkpoint fields must be canonical zero values.");

        try
        {
            return new XPointNetworkProtectedLkg(
                networkId.ToArray(),
                headReference.ToArray(),
                headTreeSize,
                headRoot.ToArray(),
                viewReference.ToArray(),
                viewGeneration,
                authorityReference.ToArray(),
                presence == 1 ? checkpointReference.ToArray() : default,
                presence == 1 ? checkpointGeneration : null);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            throw new FormatException("XLK1 payload is invalid.", exception);
        }
    }

    private static void Copy(ReadOnlySpan<byte> value, byte[] destination, ref int offset, int length)
    {
        if (value.Length != length)
            throw new InvalidOperationException("Protected LKG exposed a non-canonical field length.");
        value.CopyTo(destination.AsSpan(offset, length));
        offset += length;
    }

    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> value, ref int offset, int length)
    {
        var result = value.Slice(offset, length);
        offset += length;
        return result;
    }

    private static void WriteU64(ulong value, byte[] destination, ref int offset)
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination.AsSpan(offset, 8), value);
        offset += 8;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value, ref int offset)
    {
        var result = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(offset, 8));
        offset += 8;
        return result;
    }

    private static byte[] Hash(ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(ChecksumDomain);
        var preimage = new byte[checked(label.Length + 5 + payload.Length)];
        try
        {
            label.CopyTo(preimage, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                preimage.AsSpan(label.Length + 1, 4),
                checked((uint)payload.Length));
            payload.CopyTo(preimage.AsSpan(label.Length + 5));
            return SHA256.HashData(preimage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(preimage);
        }
    }
}
