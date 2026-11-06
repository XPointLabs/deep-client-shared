using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Protected local selection only. Every issuer/time/native-source check belongs
// to the owner on read; this grammar cannot confer current XUR or route authority.
internal sealed class ProtectedContactRendezvousContinuation
{
    internal const int MaximumSuccessors = 59;
    private const int HeaderBytes = 196;
    internal List<ReadOnlyMemory<byte>> Successors { get; } = [];
    internal byte[] SourceOperation { get; } = new byte[32];
    internal byte[] SourceEventHash { get; } = new byte[32];
    internal byte[] FaultOperation { get; } = new byte[32];
    internal byte[] FaultEventHash { get; } = new byte[32];
    internal static string Slot(Did2MessagingSessionScope scope, byte subject) =>
        "deep.store.v2.contact-xur-continuation." + subject + "." + Convert.ToHexStringLower(scope.Hash);

    internal static ProtectedContactRendezvousContinuation Decode(ReadOnlySpan<byte> exact,
        Did2MessagingSessionScope scope, ReadOnlySpan<byte> original)
    {
        if (exact.Length < HeaderBytes || exact[0] != 1 || exact[1] != 0 ||
            !exact.Slice(4, 32).SequenceEqual(scope.Hash) ||
            !exact.Slice(36, 32).SequenceEqual(SHA256.HashData(original)))
            throw new InvalidDataException("Protected rendezvous continuation changed its native anchor.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        if (count > MaximumSuccessors || exact.Length != HeaderBytes + count * 538)
            throw new InvalidDataException("Protected rendezvous continuation exceeds its closed bound.");
        var value = new ProtectedContactRendezvousContinuation();
        exact.Slice(68, 32).CopyTo(value.SourceOperation); exact.Slice(100, 32).CopyTo(value.SourceEventHash);
        exact.Slice(132, 32).CopyTo(value.FaultOperation); exact.Slice(164, 32).CopyTo(value.FaultEventHash);
        if ((value.SourceOperation.AsSpan().IndexOfAnyExcept((byte)0) < 0) !=
            (value.SourceEventHash.AsSpan().IndexOfAnyExcept((byte)0) < 0) ||
            (value.FaultOperation.AsSpan().IndexOfAnyExcept((byte)0) < 0) !=
            (value.FaultEventHash.AsSpan().IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("Protected rendezvous continuation has an incomplete native source.");
        for (var i = 0; i < count; i++) value.Successors.Add(exact.Slice(HeaderBytes + i * 538, 538).ToArray());
        return value;
    }

    internal byte[] Encode(Did2MessagingSessionScope scope, ReadOnlySpan<byte> original)
    {
        if (Successors.Count > MaximumSuccessors || Successors.Any(value => value.Length != 538))
            throw new IOException("The protected rendezvous continuation is full.");
        var exact = new byte[HeaderBytes + Successors.Count * 538]; exact[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(exact.AsSpan(2), (ushort)Successors.Count);
        scope.Hash.CopyTo(exact.AsSpan(4)); SHA256.HashData(original, exact.AsSpan(36, 32));
        SourceOperation.CopyTo(exact, 68); SourceEventHash.CopyTo(exact, 100);
        FaultOperation.CopyTo(exact, 132); FaultEventHash.CopyTo(exact, 164);
        for (var i = 0; i < Successors.Count; i++) Successors[i].Span.CopyTo(exact.AsSpan(HeaderBytes + i * 538));
        return exact;
    }
}
