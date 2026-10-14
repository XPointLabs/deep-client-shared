using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

// The argument is a caller-owned defensive export, never borrowed record,
// database, history or native-custody memory.
internal static class OwnedByteExports
{
    internal static byte[] TakeArray(ReadOnlyMemory<byte> ownedExport)
    {
        if (MemoryMarshal.TryGetArray(ownedExport, out var segment) &&
            segment.Array is { } array && segment.Offset == 0 && segment.Count == array.Length)
            return array;
        try { return ownedExport.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(ownedExport).Span); }
    }

    internal static bool EqualAndErase(ReadOnlyMemory<byte> ownedExport, ReadOnlySpan<byte> expected)
    {
        try
        {
            return ownedExport.Length == expected.Length &&
                CryptographicOperations.FixedTimeEquals(ownedExport.Span, expected);
        }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(ownedExport).Span); }
    }
}
