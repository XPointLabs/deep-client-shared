using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal static class ResponderInitialSessionCheckpoint
{
    internal const string Slot = "deep.store.v2.responder-initial-session-checkpoint";
    internal const int HeaderBytes = 192, MaximumSessions = 128;
    internal sealed class State(byte phase, ulong sequence, byte[] previous, byte[] hash, byte[] payload) : IDisposable
    {
        internal byte Phase => phase;
        internal ulong Sequence => sequence;
        internal byte[] Previous => previous;
        internal byte[] Hash => hash;
        internal byte[] Payload => payload;
        public void Dispose() => CryptographicOperations.ZeroMemory(payload);
    }
    internal static byte[] Stable(ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network,
        ulong sequence, ReadOnlySpan<byte> hash) => Encode(instance, account, network, 1, sequence, new byte[32], hash, []);
    internal static byte[] Pending(ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network,
        State stable, ReadOnlySpan<byte> payload)
    {
        if (stable.Phase != 1 || stable.Sequence >= MaximumSessions) throw new InvalidDataException("Responder checkpoint cannot advance.");
        var next = checked(stable.Sequence + 1);
        var metadataLength = DeepIdV2InitialContactSessionCommit.PendingMetadataLength(payload);
        return Encode(instance, account, network, 2, next, stable.Hash,
            RecordHash(instance, account, network, next, stable.Hash, payload[..metadataLength]), payload);
    }
    internal static State Decode(ReadOnlySpan<byte> exact, ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network)
    {
        RequireScope(instance, account, network);
        if (exact.Length < HeaderBytes || exact.Length > HeaderBytes + DeepIdV2InitialContactSessionCommit.MaximumPendingBytes ||
            exact[0] != 2 || exact[1] is not (1 or 2) || exact[2] != 0 || exact[3] != 0 ||
            !Fixed(exact.Slice(76, 32), instance) || !Fixed(exact.Slice(108, 32), account) || !Fixed(exact.Slice(140, 16), network))
            throw new CryptographicException("Responder checkpoint has a different closed shape or scope.");
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(4, 8));
        var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(156, 4));
        var previous = exact.Slice(12, 32); var hash = exact.Slice(44, 32);
        if (sequence > MaximumSessions || length > DeepIdV2InitialContactSessionCommit.MaximumPendingBytes ||
            exact.Length != (long)HeaderBytes + length || (sequence == 0) != IsZero(hash) ||
            exact[1] == 1 && (length != 0 || !IsZero(previous) || !IsZero(exact.Slice(160, 32))) ||
            exact[1] == 2 && (sequence == 0 || length < DeepIdV2InitialContactSessionCommit.HeaderBytes || (sequence == 1) != IsZero(previous)))
            throw new InvalidDataException("Responder checkpoint phase, size or tip is invalid.");
        if (exact[1] == 2)
        {
            var body = exact[HeaderBytes..];
            var metadataLength = DeepIdV2InitialContactSessionCommit.PendingMetadataLength(body);
            if (!Fixed(exact.Slice(160, 32), SHA256.HashData(body)) ||
                !Fixed(hash, RecordHash(instance, account, network, sequence, previous, body[..metadataLength])))
                throw new CryptographicException("Protected responder pending hash differs.");
        }
        return new(exact[1], sequence, previous.ToArray(), hash.ToArray(), exact[HeaderBytes..].ToArray());
    }
    private static byte[] Encode(ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network,
        byte phase, ulong sequence, ReadOnlySpan<byte> previous, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> payload)
    {
        RequireScope(instance, account, network);
        if (previous.Length != 32 || hash.Length != 32 || payload.Length > DeepIdV2InitialContactSessionCommit.MaximumPendingBytes)
            throw new InvalidDataException("Responder checkpoint fields exceed their bounds.");
        var result = new byte[HeaderBytes + payload.Length]; result[0] = 2; result[1] = phase;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(4, 8), sequence);
        previous.CopyTo(result.AsSpan(12)); hash.CopyTo(result.AsSpan(44)); instance.CopyTo(result.AsSpan(76));
        account.CopyTo(result.AsSpan(108)); network.CopyTo(result.AsSpan(140));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(156, 4), checked((uint)payload.Length)); payload.CopyTo(result.AsSpan(HeaderBytes));
        if (phase == 2) SHA256.HashData(payload).CopyTo(result.AsSpan(160));
        try { using var check = Decode(result, instance, account, network); return result; }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
    }
    internal static byte[] RecordHash(ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network,
        ulong sequence, ReadOnlySpan<byte> previous, ReadOnlySpan<byte> payload)
    {
        RequireScope(instance, account, network);
        if (sequence is 0 or > MaximumSessions || previous.Length != 32 || payload.Length < DeepIdV2InitialContactSessionCommit.HeaderBytes ||
            payload.Length > DeepIdV2InitialContactSessionCommit.MaximumPayloadBytes) throw new InvalidDataException("Responder record exceeds its closed bounds.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/responder-initial-metadata"u8); hash.AppendData([0]);
        hash.AppendData(instance); hash.AppendData(account); hash.AppendData(network);
        Span<byte> ordinal = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(ordinal, sequence); hash.AppendData(ordinal); hash.AppendData(previous);
        Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)payload.Length));
        hash.AppendData(length); hash.AppendData(payload); return hash.GetHashAndReset();
    }
    private static void RequireScope(ReadOnlySpan<byte> instance, ReadOnlySpan<byte> account, ReadOnlySpan<byte> network)
    {
        if (instance.Length != 32 || account.Length != 32 || network.Length != 16 || IsZero(instance) || IsZero(account) || IsZero(network))
            throw new ArgumentException("Nonzero responder instance/account/network scope is required.");
    }
    private static bool IsZero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => DeepIdV2InitialContactSessionCommit.Fixed(left, right);
}
