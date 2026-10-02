using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

/// <summary>DR-0027 bounded metadata. Restoring it grants no endpoint,
/// ratchet, source-retirement, dispatch or ACK authority.</summary>
internal sealed class Did2MessagingSessionScope
{
    internal const int Bytes = 404;
    private readonly byte[] exact, hash;
    private Did2MessagingSessionScope(byte[] exact)
    {
        this.exact = exact;
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/messaging-session-scope"u8);
        digest.AppendData([0]); digest.AppendData(exact);
        hash = digest.GetHashAndReset();
    }
    internal ReadOnlySpan<byte> Exact => exact;
    internal ReadOnlySpan<byte> Hash => hash;
    internal string FloorSlot => "deep.store.v2.messaging.floor." + Convert.ToHexStringLower(hash);
    internal bool IsInitiator => exact[1] == 1;
    internal ReadOnlySpan<byte> Network => exact.AsSpan(4, 16);
    internal ReadOnlySpan<byte> Instance => exact.AsSpan(20, 32);
    internal ReadOnlySpan<byte> LocalAccount => exact.AsSpan(52, 32);
    internal ReadOnlySpan<byte> LocalDevice => exact.AsSpan(92, 32);
    internal ulong LocalDeviceGeneration => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(124));
    internal ReadOnlySpan<byte> RemoteAccount => exact.AsSpan(132, 32);
    internal ReadOnlySpan<byte> RemoteDevice => exact.AsSpan(172, 32);
    internal ulong RemoteDeviceGeneration => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(204));
    internal ReadOnlySpan<byte> Session => exact.AsSpan(212, 32);
    internal ReadOnlySpan<byte> Conversation => exact.AsSpan(244, 32);
    internal ReadOnlySpan<byte> Relationship => exact.AsSpan(276, 32);
    internal ReadOnlySpan<byte> InitialBasis => exact.AsSpan(308, 32);
    internal ReadOnlySpan<byte> LocalDirectory => exact.AsSpan(340, 32);
    internal ReadOnlySpan<byte> RemoteDirectory => exact.AsSpan(372, 32);

    internal static Did2MessagingSessionScope FromSeed(OwnedInitialMessagingSeed seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        var record = seed.Initiation;
        var result = new byte[Bytes]; result[0] = 1; result[1] = seed.IsInitiator ? (byte)1 : (byte)2;
        seed.LocalDirectory.NetworkId.Span.CopyTo(result.AsSpan(4)); seed.Instance.CopyTo(result.AsSpan(20));
        seed.LocalDirectory.DeepAccountId.Span.CopyTo(result.AsSpan(52));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(84), seed.LocalDirectory.AccountGeneration);
        (seed.IsInitiator ? record.InitiatorDeviceId.Span : record.ResponderDeviceId.Span).CopyTo(result.AsSpan(92));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(124), seed.IsInitiator ? record.InitiatorDeviceGeneration : record.ResponderDeviceGeneration);
        seed.RemoteDirectory.DeepAccountId.Span.CopyTo(result.AsSpan(132));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(164), seed.RemoteDirectory.AccountGeneration);
        (seed.IsInitiator ? record.ResponderDeviceId.Span : record.InitiatorDeviceId.Span).CopyTo(result.AsSpan(172));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(204), seed.IsInitiator ? record.ResponderDeviceGeneration : record.InitiatorDeviceGeneration);
        record.SessionId.Span.CopyTo(result.AsSpan(212)); seed.ConversationId.Span.CopyTo(result.AsSpan(244));
        seed.RelationshipId.Span.CopyTo(result.AsSpan(276)); seed.InitialBasisHash.CopyTo(result.AsSpan(308));
        seed.LocalDirectory.RecordHash.Span.CopyTo(result.AsSpan(340)); seed.RemoteDirectory.RecordHash.Span.CopyTo(result.AsSpan(372));
        return RestoreMetadata(result);
    }

    internal static Did2MessagingSessionScope RestoreMetadata(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Bytes || bytes[0] != 1 || bytes[1] is not (1 or 2) || bytes[2] != 0 || bytes[3] != 0)
            throw new InvalidDataException("DID2 messaging scope has an unknown closed shape.");
        if (Zero(bytes.Slice(4, 16))) throw new InvalidDataException("DID2 messaging network is absent.");
        foreach (var offset in new[] { 20, 52, 92, 132, 172, 212, 244, 276, 308, 340, 372 })
            if (Zero(bytes.Slice(offset, 32))) throw new InvalidDataException("DID2 messaging scope has an absent field.");
        foreach (var offset in new[] { 84, 124, 164, 204 })
            if (BinaryPrimitives.ReadUInt64BigEndian(bytes[offset..]) == 0)
                throw new InvalidDataException("DID2 messaging scope generation is absent.");
        if (Fixed(bytes.Slice(52, 32), bytes.Slice(132, 32)) || Fixed(bytes.Slice(92, 32), bytes.Slice(172, 32)))
            throw new CryptographicException("DID2 messaging scope endpoints are not distinct.");
        return new(bytes.ToArray());
    }
    internal static bool Zero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    internal static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
