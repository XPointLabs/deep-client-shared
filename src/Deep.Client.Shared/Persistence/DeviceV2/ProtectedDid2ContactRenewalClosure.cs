using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Immutable protected data, never exported as a route or signing capability.
internal sealed class ProtectedDid2ContactRenewalClosure : IDisposable
{
    internal const int MaximumBytes = 41_753, OriginBytes = 184;
    private readonly byte[] exact;
    private readonly int oldLength;
    private ProtectedDid2ContactRenewalClosure(byte[] exact, int oldLength) { this.exact = exact; this.oldLength = oldLength; }
    internal ReadOnlySpan<byte> Exact => exact;
    internal ReadOnlyMemory<byte> PermanentIntent => exact.AsMemory(88,32);
    internal ReadOnlyMemory<byte> CompletedBaseEntryHash => exact.AsMemory(120,32);
    internal ReadOnlyMemory<byte> OldIntent => exact.AsMemory(152,32);
    internal ReadOnlyMemory<byte> NextIntent => exact.AsMemory(184,32);
    internal ReadOnlyMemory<byte> NextRequestHash => exact.AsMemory(216,32);
    internal ReadOnlyMemory<byte> ExactOldPhase1 => exact.AsMemory(252,oldLength);
    internal ReadOnlyMemory<byte> ExactRecordedResponse => exact.AsMemory(256+oldLength);
    internal static string ClosedSlot(ReadOnlySpan<byte> intent) => "deep.store.v2.contact-renewal-closed/" + Convert.ToHexStringLower(intent);
    internal static string OriginSlot(ReadOnlySpan<byte> hash) => "deep.store.v2.contact-renewal-origin/" + Convert.ToHexStringLower(hash);
    internal static byte[] DeriveNextIntent(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance,
        ReadOnlySpan<byte> permanent, ReadOnlySpan<byte> completedHash, ReadOnlySpan<byte> oldEntry, ReadOnlySpan<byte> response)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Client/DID2/contact-renewal-recorded-successor/v1"u8); hash.AppendData([0]);
        hash.AppendData(network); hash.AppendData(account); hash.AppendData(instance); hash.AppendData(permanent); hash.AppendData(completedHash);
        hash.AppendData(SHA256.HashData(oldEntry)); hash.AppendData(SHA256.HashData(response)); return hash.GetHashAndReset();
    }
    internal static ProtectedDid2ContactRenewalClosure Create(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance, ReadOnlySpan<byte> permanentIntent, ReadOnlySpan<byte> completedHash,
        ProtectedDid2ContactRouteJournal.Entry oldEntry, ProtectedDid2ContactRouteJournal.Entry nextEntry, ReadOnlySpan<byte> response)
    {
        if (oldEntry.Phase != 1 || nextEntry.Phase != 1) throw new InvalidDataException("Recorded closure requires two exact phase1 proposals.");
        var bytes = new byte[checked(256 + oldEntry.Exact.Length + response.Length)]; bytes[0] = 1; bytes[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), checked((uint)bytes.Length)); network.CopyTo(bytes.AsSpan(8)); account.CopyTo(bytes.AsSpan(24)); instance.CopyTo(bytes.AsSpan(56));
        permanentIntent.CopyTo(bytes.AsSpan(88)); completedHash.CopyTo(bytes.AsSpan(120)); oldEntry.Exact[..32].CopyTo(bytes.AsSpan(152)); nextEntry.Exact[..32].CopyTo(bytes.AsSpan(184));
        SHA256.HashData(nextEntry.Record(12).Span, bytes.AsSpan(216,32)); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(248), checked((uint)oldEntry.Exact.Length)); oldEntry.Exact.CopyTo(bytes.AsSpan(252));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(252+oldEntry.Exact.Length), checked((uint)response.Length)); response.CopyTo(bytes.AsSpan(256+oldEntry.Exact.Length));
        try { return Decode(bytes,network,account,instance); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static ProtectedDid2ContactRenewalClosure Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (bytes.Length is < 256 or > MaximumBytes || bytes[0] != 1 || bytes[1] != 1 || bytes[2] != 0 || bytes[3] != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]) != bytes.Length || !Fixed(bytes.Slice(8,16),network) || !Fixed(bytes.Slice(24,32),account) || !Fixed(bytes.Slice(56,32),instance))
            throw new InvalidDataException("Recorded closure has incompatible scope or framing.");
        for (var offset=88; offset<248; offset+=32) if (bytes.Slice(offset,32).IndexOfAnyExcept((byte)0)<0) throw new InvalidDataException("Recorded closure contains a zero identity.");
        var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[248..]);
        if (length > bytes.Length-256) throw new InvalidDataException("Recorded closure phase1 length is hostile.");
        using var old = ProtectedDid2ContactRouteJournal.Entry.Decode(bytes.Slice(252,checked((int)length)),network,account);
        if (old.Phase != 1 || old.Kind != 1 || !Fixed(old.Exact[..32],bytes.Slice(152,32)) ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[(252+checked((int)length))..]) != bytes.Length-256-length)
            throw new InvalidDataException("Recorded closure changed its exact original phase1.");
        var response=bytes[(256+checked((int)length))..];
        _=ContactRouteAuthorityWireCodec.DecodeResponse(ContactRouteAuthorityWireCodec.DecodeRequest(old.Record(12).Span),response);
        if (!Fixed(DeriveNextIntent(network,account,instance,bytes.Slice(88,32),bytes.Slice(120,32),old.Exact,response),bytes.Slice(184,32)))
            throw new CryptographicException("Recorded closure changed its derived successor intent.");
        return new(bytes.ToArray(),checked((int)length));
    }
    internal byte[] EncodeOrigin()
    {
        var bytes = new byte[OriginBytes]; bytes[0]=1; BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4),OriginBytes);
        exact.AsSpan(8,80).CopyTo(bytes.AsSpan(8)); NextRequestHash.Span.CopyTo(bytes.AsSpan(88)); OldIntent.Span.CopyTo(bytes.AsSpan(120)); SHA256.HashData(exact,bytes.AsSpan(152)); return bytes;
    }
    internal void RequireOrigin(ReadOnlySpan<byte> origin, ReadOnlySpan<byte> requestHash)
    {
        if(origin.Length!=OriginBytes || origin[0]!=1 || origin.Slice(1,3).IndexOfAnyExcept((byte)0)>=0 || BinaryPrimitives.ReadUInt32BigEndian(origin[4..])!=OriginBytes ||
            !Fixed(origin.Slice(8,80),exact.AsSpan(8,80)) || !Fixed(origin.Slice(88,32),requestHash) || !Fixed(requestHash,NextRequestHash.Span) ||
            !Fixed(origin.Slice(120,32),OldIntent.Span) || !Fixed(origin.Slice(152,32),SHA256.HashData(exact))) throw new CryptographicException("Recorded origin differs from its immutable exact closure.");
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(exact);
    private static bool Fixed(ReadOnlySpan<byte> a,ReadOnlySpan<byte>b)=>a.Length==b.Length&&CryptographicOperations.FixedTimeEquals(a,b);
}
