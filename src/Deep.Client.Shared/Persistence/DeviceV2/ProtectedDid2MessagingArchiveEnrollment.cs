using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Crash-consistency facts only. The enrollment owner must independently rejoin
// every protected guard and repeat the complete original-source audit on resume.
internal sealed class ProtectedDid2MessagingArchiveEnrollment
{
    internal const string Slot = "deep.store.v2.messaging-archive-enrollment";
    internal const int Bytes = 1120, HashCount = 8;
    internal enum PhaseKind : byte { SourceFrozen = 1, SchemaStaged = 2, Building = 3, FinalReady = 4 }
    internal enum GuardKind { Catalog, Registration, PeerBootstrap, OriginalSql, AuthoredSql, AuthoredRoot, Schema5, Schema6 }
    private readonly byte[] exact;
    private ProtectedDid2MessagingArchiveEnrollment(byte[] exact, Did2MessagingFloor source,
        Did2MessagingHistoryCheckpoint history, Did2MessagingFloor target)
    { this.exact = exact; SourceFloor = source; SourceHistory = history; TargetBasis = target; }
    internal ReadOnlyMemory<byte> Exact => exact;
    internal PhaseKind Phase => (PhaseKind)exact[1];
    internal ulong Revision => U64(exact, 8);
    internal Did2MessagingFloor SourceFloor { get; }
    internal Did2MessagingHistoryCheckpoint SourceHistory { get; }
    internal Did2MessagingFloor TargetBasis { get; }
    internal ulong Cursor => U64(exact, 984);
    internal ulong Count => U64(exact, 992);
    internal ReadOnlySpan<byte> ScopeHash => exact.AsSpan(16, 32);
    internal ReadOnlySpan<byte> PatriciaHash => exact.AsSpan(1000, 32);
    internal ReadOnlySpan<byte> ReducerHash => exact.AsSpan(1032, 32);
    internal ReadOnlySpan<byte> PreviousHash => exact.AsSpan(1064, 32);
    internal ReadOnlySpan<byte> Guard(GuardKind kind) => exact.AsSpan(540 + checked((int)kind * 32), 32);

    internal static ProtectedDid2MessagingArchiveEnrollment Decode(ReadOnlySpan<byte> raw, Did2MessagingSessionScope scope)
    {
        if (raw.Length != Bytes || raw[0] != 1 || raw[1] is < 1 or > 4 || !Zero(raw.Slice(2, 2)) ||
            BinaryPrimitives.ReadUInt32BigEndian(raw[4..]) != Bytes || U64(raw, 8) == 0 ||
            !Fixed(raw.Slice(16, 32), scope.Hash) || !Zero(raw[1096..])) throw Bad();
        var source = Did2MessagingFloor.Decode(raw.Slice(48, 188), scope);
        var history = Did2MessagingHistoryCheckpoint.Decode(raw.Slice(236, 304), scope);
        var target = Did2MessagingFloor.Decode(raw.Slice(796, 188), scope);
        if (source.Phase != 1 || target.Phase != 1 || !Fixed(target.Exact.Span, history.Basis.Exact.Span) ||
            source.Ordinal < target.Ordinal || source.RatchetGeneration < target.RatchetGeneration ||
            (U64(raw, 8) == 1) != Zero(raw.Slice(1064, 32))) throw Bad();
        for (var i = 0; i < HashCount; i++) if (Zero(raw.Slice(540 + i * 32, 32))) throw Bad();
        var cursor = U64(raw, 984); var count = U64(raw, 992);
        if (U64(raw, 8) < raw[1] || (raw[1] <= 2 && U64(raw, 8) != raw[1]) ||
            cursor > target.Ordinal || count > history.HistoryCount || (count == 0) != (cursor == 0) ||
            (count > 0 && (cursor < 3 || count > cursor - 2)) ||
            (raw[1] <= 2 && (cursor != 0 || count != 0)) ||
            (raw[1] == 4 && count != history.HistoryCount) ||
            Zero(raw.Slice(1000, 32)) || Zero(raw.Slice(1032, 32))) throw Bad();
        return new(raw.ToArray(), source, history, target);
    }

    internal static ProtectedDid2MessagingArchiveEnrollment Create(Did2MessagingSessionScope scope,
        Did2MessagingFloor floor, Did2MessagingHistoryCheckpoint history, IReadOnlyList<ReadOnlyMemory<byte>> guards,
        ReadOnlySpan<byte> patriciaHash, ReadOnlySpan<byte> reducerHash)
    {
        if (guards.Count != HashCount || guards.Any(static value => value.Length != 32) ||
            patriciaHash.Length != 32 || reducerHash.Length != 32) throw Bad();
        var raw = new byte[Bytes]; raw[0] = 1; raw[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(raw.AsSpan(4), Bytes); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), 1);
        scope.Hash.CopyTo(raw.AsSpan(16)); floor.Exact.Span.CopyTo(raw.AsSpan(48)); history.Exact.Span.CopyTo(raw.AsSpan(236));
        for (var i = 0; i < guards.Count; i++) guards[i].Span.CopyTo(raw.AsSpan(540 + i * 32));
        history.Basis.Exact.Span.CopyTo(raw.AsSpan(796)); patriciaHash.CopyTo(raw.AsSpan(1000)); reducerHash.CopyTo(raw.AsSpan(1032));
        return Decode(raw, scope);
    }

    internal ProtectedDid2MessagingArchiveEnrollment Advance(Did2MessagingSessionScope scope, PhaseKind phase,
        ulong cursor, ulong count, ReadOnlySpan<byte> patriciaHash, ReadOnlySpan<byte> reducerHash)
    {
        if (Phase == PhaseKind.FinalReady || phase < Phase || (phase == Phase && phase != PhaseKind.Building) ||
            (int)phase > (int)Phase + 1 || cursor < Cursor || count < Count ||
            patriciaHash.Length != 32 || reducerHash.Length != 32) throw Bad();
        var raw = exact.ToArray(); raw[1] = (byte)phase;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(8), checked(Revision + 1));
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(984), cursor); BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(992), count);
        patriciaHash.CopyTo(raw.AsSpan(1000)); reducerHash.CopyTo(raw.AsSpan(1032)); SHA256.HashData(exact, raw.AsSpan(1064, 32));
        return Decode(raw, scope);
    }

    internal Did2MessagingArchiveRoot FinalRoot(Did2MessagingSessionScope scope)
    {
        if (Phase != PhaseKind.FinalReady) throw Bad();
        return Did2MessagingArchiveRoot.Create(scope, 1, SourceHistory, TargetBasis, Count, PatriciaHash, ReducerHash);
    }
    private static ulong U64(ReadOnlySpan<byte> raw, int offset) => BinaryPrimitives.ReadUInt64BigEndian(raw[offset..]);
    private static bool Zero(ReadOnlySpan<byte> value) => Did2MessagingSessionScope.Zero(value);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => Did2MessagingSessionScope.Fixed(a, b);
    private static InvalidDataException Bad() => new("Messaging archive enrollment progress is absent, foreign or noncanonical.");
}
