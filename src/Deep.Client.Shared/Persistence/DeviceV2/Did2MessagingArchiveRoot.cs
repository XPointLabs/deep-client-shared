using System.Buffers.Binary;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Independent archive commitment facts, never permission to enroll or reconstruct a missing root.</summary>
internal sealed class Did2MessagingArchiveRoot
{
    internal const int Bytes = 608;
    private readonly byte[] exact;
    private Did2MessagingArchiveRoot(byte[] exact, Did2MessagingHistoryCheckpoint source, Did2MessagingFloor basis)
    { this.exact = exact; Source = source; Basis = basis; }
    internal ReadOnlyMemory<byte> Exact => exact;
    internal ulong Revision => U64(exact, 4);
    internal Did2MessagingHistoryCheckpoint Source { get; }
    internal Did2MessagingFloor Basis { get; }
    internal ulong ArchiveCount => U64(exact, 536);
    internal ReadOnlySpan<byte> PatriciaHash => exact.AsSpan(544, 32);
    internal ReadOnlySpan<byte> SummaryHash => exact.AsSpan(576, 32);
    internal static string Slot(Did2MessagingSessionScope scope) => scope.FloorSlot + ".archive";

    internal static Did2MessagingArchiveRoot Decode(ReadOnlySpan<byte> raw, Did2MessagingSessionScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (raw.Length != Bytes || raw[0] != 1 || !Zero(raw.Slice(1, 3)) || U64(raw, 4) == 0 ||
            !Fixed(raw.Slice(12, 32), scope.Hash)) throw Bad();
        var source = Did2MessagingHistoryCheckpoint.Decode(raw.Slice(44, Did2MessagingHistoryCheckpoint.Bytes), scope);
        var basis = RequireBasis(raw.Slice(348, Did2MessagingFloor.Bytes), scope);
        var count = U64(raw, 536);
        RequireHash(raw.Slice(544, 32)); RequireHash(raw.Slice(576, 32));
        if (source.Basis.Ordinal > basis.Ordinal || source.Basis.RatchetGeneration > basis.RatchetGeneration ||
            source.HistoryCount > count || (basis.Ordinal == 0 ? count != 0 : count > basis.Ordinal - 2) ||
            (basis.Ordinal == 0 || count != 0) &&
                ((basis.Ordinal == 0) != Fixed(raw.Slice(544, 32), EmptyHash(scope)))) throw Bad();
        if (basis.Ordinal == 0 && (!Fixed(source.Exact.Span, Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope).Exact.Span) ||
            !Fixed(raw.Slice(576, 32), Did2MessagingArchiveReducer.Empty(scope).Digest.Span))) throw Bad();
        return new(raw.ToArray(), source, basis);
    }

    internal static Did2MessagingArchiveRoot Create(Did2MessagingSessionScope scope, ulong revision,
        Did2MessagingHistoryCheckpoint source, Did2MessagingFloor basis, ulong archiveCount,
        ReadOnlySpan<byte> patriciaHash, ReadOnlySpan<byte> summaryHash)
    {
        ArgumentNullException.ThrowIfNull(source); ArgumentNullException.ThrowIfNull(basis);
        RequireHash(patriciaHash); RequireHash(summaryHash);
        var raw = new byte[Bytes]; raw[0] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(4), revision); scope.Hash.CopyTo(raw.AsSpan(12));
        source.Exact.Span.CopyTo(raw.AsSpan(44)); basis.Exact.Span.CopyTo(raw.AsSpan(348));
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(536), archiveCount);
        patriciaHash.CopyTo(raw.AsSpan(544)); summaryHash.CopyTo(raw.AsSpan(576)); return Decode(raw, scope);
    }

    internal static Did2MessagingArchiveRoot Empty(Did2MessagingSessionScope scope) => Create(scope, 1,
        Did2MessagingHistoryCheckpoint.RegisteredEmpty(scope), Did2MessagingFloor.Empty(scope), 0,
        EmptyHash(scope), Did2MessagingArchiveReducer.Empty(scope).Digest.Span);

    internal void RequireSource(Did2MessagingHistoryCheckpoint actual)
    {
        ArgumentNullException.ThrowIfNull(actual);
        if (!Fixed(Source.Exact.Span, actual.Exact.Span)) throw Bad();
    }
}
