using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>Exact protected metadata, not permission to mutate SQL or release a message.</summary>
internal sealed class Did2MessagingFloor
{
    internal const int Bytes = 188, PartBytes = 128 * 1024, MaximumParts = 18;
    internal const int MetadataBytes = 608;
    internal const int MaximumPendingBytes = MetadataBytes + 2097152 + 65536 + 33082 + 65536;
    private readonly byte[] exact;
    private Did2MessagingFloor(byte[] exact) => this.exact = exact;
    internal ReadOnlyMemory<byte> Exact => exact;
    internal byte Phase => exact[1];
    internal byte Status => exact[2];
    internal ulong Ordinal => U64(36);
    internal ulong RatchetGeneration => U64(76);
    internal ReadOnlySpan<byte> Head => exact.AsSpan(44, 32);
    internal ReadOnlySpan<byte> RatchetCommitment => exact.AsSpan(84, 32);
    internal ReadOnlySpan<byte> RatchetHash => exact.AsSpan(116, 32);
    internal ReadOnlySpan<byte> PendingHash => exact.AsSpan(148, 32);
    internal int PendingBytes => checked((int)BinaryPrimitives.ReadUInt32BigEndian(exact.AsSpan(180)));
    internal int PartCount => exact[184];
    private ulong U64(int offset) => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(offset));

    internal static Did2MessagingFloor Empty(Did2MessagingSessionScope scope)
    {
        var result = new byte[Bytes]; result[0] = 1; result[1] = 1; scope.Hash.CopyTo(result.AsSpan(4));
        return Decode(result, scope);
    }
    internal static Did2MessagingFloor Decode(ReadOnlySpan<byte> bytes, Did2MessagingSessionScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (bytes.Length != Bytes || bytes[0] != 1 || bytes[1] is not (1 or 2 or 3) || bytes[2] > 2 || bytes[3] != 0 ||
            !Did2MessagingSessionScope.Fixed(bytes.Slice(4, 32), scope.Hash) || !Did2MessagingSessionScope.Zero(bytes[185..]))
            throw new CryptographicException("DID2 messaging floor has a different closed shape or scope.");
        var ordinal = BinaryPrimitives.ReadUInt64BigEndian(bytes[36..]);
        var generation = BinaryPrimitives.ReadUInt64BigEndian(bytes[76..]);
        var headZero = Did2MessagingSessionScope.Zero(bytes.Slice(44, 32));
        var commitmentZero = Did2MessagingSessionScope.Zero(bytes.Slice(84, 32));
        var ratchetZero = Did2MessagingSessionScope.Zero(bytes.Slice(116, 32));
        var pendingZero = Did2MessagingSessionScope.Zero(bytes.Slice(148, 32));
        var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[180..]);
        if (ordinal == 0)
        {
            if (bytes[1] != 1 || bytes[2] != 0 || generation != 0 || !headZero || !commitmentZero || !ratchetZero)
                throw new InvalidDataException("DID2 messaging empty floor is not canonical.");
        }
        else if (generation == 0 || generation > ordinal || headZero ||
                 (bytes[2] == 2 ? !commitmentZero || !ratchetZero : commitmentZero || ratchetZero))
            throw new InvalidDataException("DID2 messaging floor state is inconsistent.");
        if (bytes[1] == 1 ? !pendingZero || length != 0 || bytes[184] != 0 :
            ordinal == 0 || pendingZero || length < MetadataBytes || length > MaximumPendingBytes ||
            bytes[184] != PartsFor(checked((int)length)))
            throw new InvalidDataException("DID2 messaging floor pending shape is inconsistent.");
        return new(bytes.ToArray());
    }
    // The successor fields are verified by the closed mutation owner. Encoding
    // bounded metadata is intentionally not a source-retirement capability.
    internal static Did2MessagingFloor Pending(Did2MessagingSessionScope scope, Did2MessagingFloor predecessor,
        byte status, ulong generation, ReadOnlySpan<byte> commitment, ReadOnlySpan<byte> ratchetHash,
        ReadOnlySpan<byte> metadataHeader, ReadOnlySpan<byte> payload)
    {
        _ = Decode(predecessor.Exact.Span, scope);
        if (predecessor.Phase != 1 || predecessor.Status == 2 || predecessor.Ordinal == ulong.MaxValue ||
            commitment.Length != 32 || ratchetHash.Length != 32 || metadataHeader.Length != MetadataBytes ||
            payload.Length < MetadataBytes || payload.Length > MaximumPendingBytes || !payload[..MetadataBytes].SequenceEqual(metadataHeader))
            throw new InvalidDataException("DID2 messaging pending mutation exceeds its closed bounds.");
        var result = predecessor.Exact.ToArray(); result[1] = 2; result[2] = status;
        var ordinal = predecessor.Ordinal + 1; BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(36), ordinal);
        JournalHead(scope, ordinal, predecessor.Head, metadataHeader).CopyTo(result.AsSpan(44));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(76), generation);
        commitment.CopyTo(result.AsSpan(84)); ratchetHash.CopyTo(result.AsSpan(116));
        SHA256.HashData(payload).CopyTo(result.AsSpan(148));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(180), checked((uint)payload.Length));
        result[184] = checked((byte)PartsFor(payload.Length));
        return Decode(result, scope);
    }
    internal Did2MessagingFloor Cleanup(Did2MessagingSessionScope scope)
    {
        if (Phase != 2) throw new InvalidDataException("Only pending messaging state can enter cleanup.");
        var result = exact.ToArray(); result[1] = 3; return Decode(result, scope);
    }
    internal Did2MessagingFloor Stable(Did2MessagingSessionScope scope)
    {
        if (Phase != 3) throw new InvalidDataException("Messaging state must complete cleanup before becoming stable.");
        var result = exact.ToArray(); result[1] = 1; result.AsSpan(148).Clear(); return Decode(result, scope);
    }
    internal static Did2MessagingFloor FromJournalMetadata(Did2MessagingSessionScope scope,
        Did2MessagingFloor predecessor, ReadOnlySpan<byte> header)
    {
        OwnedDid2MessagingMutation.ValidateMetadataTransition(header, scope, predecessor);
        if (predecessor.Ordinal == ulong.MaxValue) throw new InvalidDataException("DID2 journal ordinal cannot advance.");
        var bytes = new byte[Bytes]; bytes[0] = 1; bytes[1] = 1; bytes[2] = header[7]; scope.Hash.CopyTo(bytes.AsSpan(4));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(36), predecessor.Ordinal + 1);
        JournalHead(scope, predecessor.Ordinal + 1, predecessor.Head, header).CopyTo(bytes.AsSpan(44));
        header.Slice(196, 72).CopyTo(bytes.AsSpan(76)); // generation, commitment, exact TRS hash
        return Decode(bytes, scope);
    }
    internal static byte[] JournalHead(Did2MessagingSessionScope scope, ulong ordinal, ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> header)
    {
        if (ordinal == 0 || predecessor.Length != 32 || header.Length != MetadataBytes || (ordinal == 1) != Did2MessagingSessionScope.Zero(predecessor))
            throw new InvalidDataException("DID2 messaging journal edge is invalid.");
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-journal"u8); digest.AppendData([0]); digest.AppendData(scope.Hash);
        Span<byte> count = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(count, ordinal);
        digest.AppendData(count); digest.AppendData(predecessor); digest.AppendData(SHA256.HashData(header));
        return digest.GetHashAndReset();
    }
    internal static int PartsFor(int bytes)
    {
        if (bytes < MetadataBytes || bytes > MaximumPendingBytes) throw new InvalidDataException("DID2 messaging payload size is invalid.");
        return (bytes + PartBytes - 1) / PartBytes;
    }
}
