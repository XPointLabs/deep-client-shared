using System.Buffers.Binary;
using System.Security.Cryptography;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Closed data framing only. Decoding does not qualify a public transition or
// authorize staging. Only the account owner's sealed qualification may do that.
internal sealed class Did2RouteHistorySource
{
    internal const int Bytes = 96;
    private readonly byte[] exact;
    private Did2RouteHistorySource(byte[] exact, Did2MessagingArchiveReference reference)
    { this.exact = exact; Reference = reference; }
    internal ReadOnlyMemory<byte> Exact => exact;
    internal Did2MessagingArchiveReference Reference { get; }
    internal byte AtomIndex => exact[88];
    internal bool IsAbsent => Reference.IsAbsent;
    internal static Did2RouteHistorySource Decode(ReadOnlySpan<byte> raw, bool allowAbsent = true)
    {
        if (raw.Length != Bytes || raw[88] > 3 || !Zero(raw[89..])) throw Bad();
        var reference = Did2MessagingArchiveReference.Decode(raw[..88], allowAbsent);
        if (reference.IsAbsent ? !Zero(raw) : reference.Kind is not (1 or 2) || reference.Kind == 1 && raw[88] != 0)
            throw Bad();
        return new(raw.ToArray(), reference);
    }
    internal static Did2RouteHistorySource From(Did2MessagingArchiveReference reference, byte atomIndex)
    {
        var raw = new byte[Bytes]; reference.Exact.Span.CopyTo(raw); raw[88] = atomIndex;
        return Decode(raw, false);
    }
    internal static Did2RouteHistorySource Absent() => Decode(new byte[Bytes]);
}

internal sealed class Did2RouteHistoryDecision
{
    internal const int Bytes = 1024, IntervalBytes = 64;
    internal enum ActionKind : byte { Bootstrap = 1, Evidence = 2, Promotion = 3, Conflict = 4 }
    private readonly byte[] exact;
    private Did2RouteHistoryDecision(byte[] exact) => this.exact = exact;
    internal ReadOnlyMemory<byte> Exact => exact;
    internal ActionKind Action => (ActionKind)exact[1];
    internal byte Subject => exact[2];
    internal Did2MessagingArchiveReference PreviousDecision => Did2MessagingArchiveReference.Decode(exact.AsSpan(36, 88));
    internal Did2MessagingArchiveReference Selected => Did2MessagingArchiveReference.Decode(exact.AsSpan(124, 88), false);
    internal byte SelectedAtomIndex => exact[212];
    internal Did2RouteHistorySource C => Did2RouteHistorySource.Decode(exact.AsSpan(220, 96), false);
    internal Did2RouteHistorySource P => Did2RouteHistorySource.Decode(exact.AsSpan(316, 96), false);
    internal Did2MessagingArchiveReference L => Did2MessagingArchiveReference.Decode(exact.AsSpan(412, 88));
    internal Did2MessagingArchiveReference FirstFault => Did2MessagingArchiveReference.Decode(exact.AsSpan(500, 88));
    internal Did2MessagingArchiveReference Consent => Did2MessagingArchiveReference.Decode(exact.AsSpan(588, 88), false);
    internal ReadOnlySpan<byte> Interval => exact.AsSpan(676, 64);
    internal ReadOnlySpan<byte> EndpointHash => exact.AsSpan(740, 32);
    internal Did2RouteHistorySource Conflicting => Did2RouteHistorySource.Decode(exact.AsSpan(772, 96));

    internal static Did2RouteHistoryDecision Decode(ReadOnlySpan<byte> raw, Did2MessagingSessionScope scope)
    {
        if (raw.Length != Bytes || raw[0] != 1 || raw[1] is < 1 or > 4 || raw[2] is < 1 or > 2 || raw[3] != 0 ||
            !Fixed(raw.Slice(4, 32), scope.Hash) || raw[212] > 3 || !Zero(raw.Slice(213, 7)) || !Zero(raw[868..])) throw Bad();
        var previous = Did2MessagingArchiveReference.Decode(raw.Slice(36, 88));
        if (raw[1] == 1 ? !previous.IsAbsent : previous.Kind != 3) throw Bad();
        var selected = Did2MessagingArchiveReference.Decode(raw.Slice(124, 88), false);
        if (selected.Kind is not (1 or 2) || selected.Kind == 1 && raw[212] != 0) throw Bad();
        var c = Did2RouteHistorySource.Decode(raw.Slice(220, 96), false);
        var p = Did2RouteHistorySource.Decode(raw.Slice(316, 96), false);
        foreach (var reference in new[] { c.Reference, p.Reference, selected })
            if (reference.Kind == 2 ? reference.Direction != raw[2] : (raw[2] == 1) != scope.IsInitiator) throw Bad();
        var live = Did2MessagingArchiveReference.Decode(raw.Slice(412, 88));
        if (!live.IsAbsent && live.Kind is not (1 or 2)) throw Bad();
        if (!live.IsAbsent && (live.Kind == 2 ? live.Direction != raw[2] : (raw[2] == 1) != scope.IsInitiator)) throw Bad();
        var fault = Did2MessagingArchiveReference.Decode(raw.Slice(500, 88));
        if (!fault.IsAbsent && fault.Kind != 3 && (fault.Kind != 2 || fault.Direction != 2)) throw Bad();
        var consent = Did2MessagingArchiveReference.Decode(raw.Slice(588, 88), false);
        if (consent.Kind != 2 || consent.Direction != (scope.IsInitiator ? 2 : 1)) throw Bad();
        RequireInterval((ActionKind)raw[1], raw.Slice(676, IntervalBytes)); RequireHash(raw.Slice(740, 32));
        var related = Did2RouteHistorySource.Decode(raw.Slice(772, 96));
        if ((raw[1] == 4) == related.IsAbsent) throw Bad();
        if (!related.IsAbsent && (related.Reference.Kind == 2 ? related.Reference.Direction != raw[2] : (raw[2] == 1) != scope.IsInitiator)) throw Bad();
        return new(raw.ToArray());
    }

    internal static void RequireInterval(ActionKind action, ReadOnlySpan<byte> raw)
    {
        if (action is < ActionKind.Bootstrap or > ActionKind.Conflict || raw.Length != IntervalBytes ||
            raw[0] != (action == ActionKind.Promotion ? 1 : 3) || !Zero(raw.Slice(1, 7)) ||
            U64(raw, 8) == 0 || U64(raw, 16) < U64(raw, 8) || Zero(raw[32..])) throw Bad();
    }

    internal byte[] Operation(Did2MessagingSessionScope scope, Did2MessagingFloor predecessor)
    {
        _ = Decode(exact, scope); _ = Did2MessagingFloor.Decode(predecessor.Exact.Span, scope);
        if (predecessor.Phase != 1 || predecessor.Status != 1) throw Bad();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/route-history-decision"u8); hash.AppendData([0]); hash.AppendData(scope.Hash);
        hash.AppendData(predecessor.Exact.Span); hash.AppendData(SHA256.HashData(exact)); return hash.GetHashAndReset();
    }

    internal void RequireBefore(Did2MessagingFloor before)
    {
        if (before.Phase != 1 || before.Status != 1) throw Bad();
        foreach (var reference in new[] { PreviousDecision, Selected, C.Reference, P.Reference, L, FirstFault, Consent, Conflicting.Reference })
            reference.RequireAtBasis(before.Ordinal);
    }
}
