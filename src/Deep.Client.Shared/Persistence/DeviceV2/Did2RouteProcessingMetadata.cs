using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Parsed metadata is never authority to create a native mutation. The only
// producer is the actual account's sealed receive transition. The same closed
// grammar is checked by pending recovery, working SQL and protected history.
internal static class Did2RouteProcessingMetadata
{
    internal const int Offset = 608, Bytes = 64;

    internal static void RequireShape(ReadOnlySpan<byte> exact)
    {
        if (exact.Length != Bytes || exact[0] > 2 || exact.Slice(1, 7).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Native route processing has an unknown closed shape.");
        if (exact[0] == 0)
        {
            if (exact.IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Absent native route processing has nonzero fields.");
            return;
        }
        var lower = BinaryPrimitives.ReadUInt64BigEndian(exact[8..]);
        var upper = BinaryPrimitives.ReadUInt64BigEndian(exact[16..]);
        if (lower == 0 || lower > upper || exact[32..].IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Native route processing lacks its protected time interval.");
    }

    internal static void RequireReceivedEvent(ReadOnlySpan<byte> exact, ParsedDmc2 message)
    {
        RequireShape(exact);
        var route = message.ContentKind == Dmc2ContentKind.ContactRouteUpdate;
        if (route != (exact[0] != 0))
            throw new InvalidDataException("Native route processing differs from its authenticated control kind.");
        if (route && exact[0] == 1 &&
            (message.CreatedAtUnixMilliseconds > BinaryPrimitives.ReadUInt64BigEndian(exact[16..]) ||
             message.ExpiresAtUnixMilliseconds == 0 ||
             BinaryPrimitives.ReadUInt64BigEndian(exact[16..]) >= message.ExpiresAtUnixMilliseconds))
            throw new InvalidDataException("Accepted native route processing exceeds its original event interval.");
    }
}
