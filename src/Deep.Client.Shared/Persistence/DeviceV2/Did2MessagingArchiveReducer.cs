using System.Buffers.Binary;
using static Deep.Client.Shared.Persistence.DeviceV2.Did2MessagingArchiveEncoding;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Closed semantic-fact framing; full source replay must independently establish every fact.</summary>
internal sealed class Did2MessagingArchiveReducer
{
    internal const int Bytes = 960, ReferenceCount = 7;
    internal enum ReferenceKind { Consent = 0, OwnHead = 1, OwnPrevious = 2, PeerHead = 3, PeerPrevious = 4, FirstFault = 5, MaximumPeerEpoch = 6 }
    private readonly byte[] exact, digest;
    private Did2MessagingArchiveReducer(byte[] exact, byte[] digest, Did2MessagingFloor basis)
    { this.exact = exact; this.digest = digest; Basis = basis; }
    internal ReadOnlyMemory<byte> Exact => exact;
    internal ReadOnlyMemory<byte> Digest => digest;
    internal Did2MessagingFloor Basis { get; }
    internal ReadOnlySpan<byte> InitialMetadataHash => exact.AsSpan(224, 32);
    internal ulong MaximumPeerEpoch => U64(exact, 872);
    internal ulong OwnHeadSequence => U64(exact, 880);
    internal ulong PeerHeadSequence => U64(exact, 888);
    internal uint HelloPolicy => BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(896));
    internal uint AcceptPolicy => BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(900));
    internal Did2MessagingArchiveReference Reference(ReferenceKind kind)
    {
        if ((int)kind is < 0 or >= ReferenceCount) throw new ArgumentOutOfRangeException(nameof(kind));
        return Did2MessagingArchiveReference.Decode(exact.AsSpan(256 + (int)kind * Did2MessagingArchiveReference.Bytes, Did2MessagingArchiveReference.Bytes));
    }

    internal static Did2MessagingArchiveReducer Decode(ReadOnlySpan<byte> raw, Did2MessagingSessionScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (raw.Length != Bytes || raw[0] != 1 || !Zero(raw.Slice(1, 3)) || !Fixed(raw.Slice(4, 32), scope.Hash) ||
            !Zero(raw[904..]) || (BinaryPrimitives.ReadUInt32BigEndian(raw[896..]) & ~3U) != 0 ||
            (BinaryPrimitives.ReadUInt32BigEndian(raw[900..]) & ~3U) != 0) throw Bad();
        var basis = RequireBasis(raw.Slice(36, Did2MessagingFloor.Bytes), scope);
        var references = new Did2MessagingArchiveReference[ReferenceCount];
        for (var index = 0; index < references.Length; index++)
        {
            references[index] = Did2MessagingArchiveReference.Decode(raw.Slice(256 + index * Did2MessagingArchiveReference.Bytes, Did2MessagingArchiveReference.Bytes));
            references[index].RequireAtBasis(basis.Ordinal);
        }
        if (basis.Ordinal == 0)
        { if (!Zero(raw[224..])) throw Bad(); }
        else
        {
            RequireHash(raw.Slice(224, 32));
            RequireEventDirection(references[0], 1, 2);
            RequireHead(references[1], 1); RequireHead(references[2], 1);
            RequireHead(references[3], 2); RequireHead(references[4], 2);
            RequireEventDirection(references[5], 2, 2); RequireEventDirection(references[6], 2, 2);
            RequirePrevious(references[1], references[2]); RequirePrevious(references[3], references[4]);
            foreach (var reference in references)
                if (reference.Kind == 1 && !Fixed(reference.MetadataHash, raw.Slice(224, 32))) throw Bad();
            if (!references[0].IsAbsent && references[0].Direction != (scope.IsInitiator ? 2 : 1) ||
                (references[1].Kind == 1 || references[2].Kind == 1) && !scope.IsInitiator ||
                (references[3].Kind == 1 || references[4].Kind == 1) && scope.IsInitiator ||
                references[1].Kind == 1 && U64(raw, 880) != 2 || references[3].Kind == 1 && U64(raw, 888) != 2) throw Bad();
            if (references[1].IsAbsent != (U64(raw, 880) == 0) || references[3].IsAbsent != (U64(raw, 888) == 0) ||
                references[6].IsAbsent && U64(raw, 872) != 0 ||
                references[0].IsAbsent && BinaryPrimitives.ReadUInt32BigEndian(raw[900..]) != 0) throw Bad();
        }
        return new(raw.ToArray(), ReducerHash(scope, raw), basis);
    }

    internal void RequireRoot(Did2MessagingArchiveRoot root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (!Fixed(root.Basis.Exact.Span, Basis.Exact.Span) || !Fixed(root.SummaryHash, digest) ||
            root.Source.Basis.Ordinal != 0 && !Fixed(root.Source.InitialHeaderHash, InitialMetadataHash)) throw Bad();
    }

    internal static Did2MessagingArchiveReducer Empty(Did2MessagingSessionScope scope)
    {
        var raw = new byte[Bytes]; raw[0] = 1; scope.Hash.CopyTo(raw.AsSpan(4));
        Did2MessagingFloor.Empty(scope).Exact.Span.CopyTo(raw.AsSpan(36)); return Decode(raw, scope);
    }

    // No semantic producer is exposed yet: caller supplied facts would not
    // establish the mandatory native/authored-source replay and ownership.
    private static void RequireEventDirection(Did2MessagingArchiveReference reference, byte minimum, byte maximum)
    { if (!reference.IsAbsent && (reference.Kind != 2 || reference.Direction < minimum || reference.Direction > maximum)) throw Bad(); }
    private static void RequireHead(Did2MessagingArchiveReference reference, byte direction)
    { if (!reference.IsAbsent && reference.Kind != 1 && (reference.Kind != 2 || reference.Direction != direction)) throw Bad(); }
    private static void RequirePrevious(Did2MessagingArchiveReference head, Did2MessagingArchiveReference previous)
    { if (!previous.IsAbsent && (head.IsAbsent || previous.Ordinal >= head.Ordinal)) throw Bad(); }
}
