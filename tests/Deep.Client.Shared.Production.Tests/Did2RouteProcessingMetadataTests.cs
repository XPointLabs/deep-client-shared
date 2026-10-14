using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Closed local grammar only. Raw structural bytes do not mint a receive
// outcome, mutation, semantic handoff, current route or ACK authority.
public sealed class Did2RouteProcessingMetadataTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void CanonicalAbsentOrProtectedProcessingMetadataHasOneEncoding(byte classification)
    {
        var raw = Metadata(classification);
        Did2RouteProcessingMetadata.RequireShape(raw);
        Assert.Equal(64, raw.Length);
        Assert.Equal(raw, Metadata(classification));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("long")]
    [InlineData("unknown")]
    [InlineData("reserved-first")]
    [InlineData("reserved-last")]
    [InlineData("absent-time")]
    [InlineData("absent-sample")]
    [InlineData("absent-boot")]
    [InlineData("zero-lower")]
    [InlineData("inverted-interval")]
    [InlineData("zero-boot")]
    public void ClosedShapeRejectsHostileProcessingFields(string defect)
    {
        var raw = Metadata(1);
        switch (defect)
        {
            case "short": raw = raw[..^1]; break;
            case "long": raw = [..raw, 0]; break;
            case "unknown": raw[0] = 3; break;
            case "reserved-first": raw[1] = 1; break;
            case "reserved-last": raw[7] = 1; break;
            case "absent-time": raw = Metadata(0); raw[8] = 1; break;
            case "absent-sample": raw = Metadata(0); raw[24] = 1; break;
            case "absent-boot": raw = Metadata(0); raw[32] = 1; break;
            case "zero-lower": raw.AsSpan(8, 8).Clear(); break;
            case "inverted-interval": BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1001); break;
            case "zero-boot": raw.AsSpan(32).Clear(); break;
            default: throw new InvalidOperationException();
        }
        var before = raw.ToArray();
        Assert.Throws<InvalidDataException>(() => Did2RouteProcessingMetadata.RequireShape(raw));
        Assert.Equal(before, raw);
    }

    [Fact]
    public void SampleZeroAndInclusiveEqualIntervalAreCanonical()
    {
        var raw = Metadata(2); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1000);
        Did2RouteProcessingMetadata.RequireShape(raw);
    }

    private static byte[] Metadata(byte classification)
    {
        var raw = new byte[64]; raw[0] = classification;
        if (classification != 0)
        {
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 900);
            BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(16), 1000);
            raw.AsSpan(32).Fill(1);
        }
        return raw;
    }
}
