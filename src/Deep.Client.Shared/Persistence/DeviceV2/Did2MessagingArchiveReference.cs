using System.Buffers.Binary;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Authenticated locator framing; actual SQL bytes still require full selected verification.</summary>
internal sealed class Did2MessagingArchiveReference
{
    internal const int Bytes = 88;
    private readonly byte[] exact;
    private Did2MessagingArchiveReference(byte[] exact) => this.exact = exact;
    internal ReadOnlyMemory<byte> Exact => exact;
    internal byte Kind => exact[0];
    internal byte Direction => exact[1];
    internal bool IsAbsent => Kind == 0;
    internal ulong Ordinal => U64(exact, 8);
    internal ulong RowId => U64(exact, 16);
    internal ReadOnlySpan<byte> Operation => exact.AsSpan(24, 32);
    internal ReadOnlySpan<byte> MetadataHash => exact.AsSpan(56, 32);

    internal static Did2MessagingArchiveReference Decode(ReadOnlySpan<byte> raw, bool allowAbsent = true)
    {
        if (raw.Length != Bytes || !Zero(raw.Slice(2, 6))) throw Bad();
        if (raw[0] == 0)
        {
            if (!allowAbsent || !Zero(raw)) throw Bad();
            return new(raw.ToArray());
        }
        RequireHash(raw.Slice(56, 32));
        var ordinal = U64(raw, 8); var rowId = U64(raw, 16);
        if (raw[0] == 1)
        {
            // Initial singleton is an INTEGER PRIMARY KEY alias. Operation zero
            // is a reference tag, never the initial metadata's claim operation.
            if (raw[1] != 0 || ordinal != 1 || rowId != 1 || !Zero(raw.Slice(24, 32))) throw Bad();
        }
        else if ((raw[0] == 2 ? raw[1] is < 1 or > 4 : raw[0] != 3 || raw[1] != 0) || ordinal == 0 || ordinal > long.MaxValue ||
            rowId == 0 || rowId > long.MaxValue || Zero(raw.Slice(24, 32))) throw Bad();
        return new(raw.ToArray());
    }

    internal static Did2MessagingArchiveReference Absent() => Decode(new byte[Bytes]);

    internal static Did2MessagingArchiveReference Initial(ReadOnlySpan<byte> metadataHash)
    {
        RequireHash(metadataHash);
        var raw = new byte[Bytes]; raw[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(16), 1);
        metadataHash.CopyTo(raw.AsSpan(56)); return Decode(raw, false);
    }

    internal static Did2MessagingArchiveReference Event(byte direction, ulong ordinal, ulong rowId,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> metadataHash)
    {
        RequireHash(operation); RequireHash(metadataHash);
        var raw = new byte[Bytes]; raw[0] = 2; raw[1] = direction;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), ordinal);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(16), rowId);
        operation.CopyTo(raw.AsSpan(24)); metadataHash.CopyTo(raw.AsSpan(56)); return Decode(raw, false);
    }

    internal static Did2MessagingArchiveReference Decision(ulong ordinal, ulong rowId,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> metadataHash)
    {
        RequireHash(operation); RequireHash(metadataHash);
        var raw = new byte[Bytes]; raw[0] = 3;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), ordinal);
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(16), rowId);
        operation.CopyTo(raw.AsSpan(24)); metadataHash.CopyTo(raw.AsSpan(56)); return Decode(raw, false);
    }

    internal void RequireAtBasis(ulong basisOrdinal)
    { if (!IsAbsent && Ordinal > basisOrdinal) throw Bad(); }
}
