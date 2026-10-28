using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Private archive framing only. These codecs grant no SQL, retirement, current
// authority or result-release permission and are not installed in the runtime.
internal static class Did2MessagingArchiveEncoding
{
    internal static byte[] Hash(ReadOnlySpan<byte> domain, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> exact = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain); hash.AppendData([0]); hash.AppendData(scope.Hash); hash.AppendData(exact);
        return hash.GetHashAndReset();
    }

    internal static byte[] EmptyHash(Did2MessagingSessionScope scope) => Hash("Deep/STORE-V2/archive-empty"u8, scope);
    internal static byte[] NodeHash(Did2MessagingSessionScope scope, ReadOnlySpan<byte> exact) =>
        Hash("Deep/STORE-V2/archive-node"u8, scope, exact);
    internal static byte[] ReducerHash(Did2MessagingSessionScope scope, ReadOnlySpan<byte> exact) =>
        Hash("Deep/STORE-V2/archive-reducer"u8, scope, exact);

    internal static bool Zero(ReadOnlySpan<byte> value) => Did2MessagingSessionScope.Zero(value);
    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => Did2MessagingSessionScope.Fixed(left, right);
    internal static ulong U64(ReadOnlySpan<byte> value, int offset) => BinaryPrimitives.ReadUInt64BigEndian(value[offset..]);
    internal static void RequireHash(ReadOnlySpan<byte> hash)
    { if (hash.Length != 32 || Zero(hash)) throw Bad(); }
    internal static InvalidDataException Bad() => new("Messaging archive record has a noncanonical closed shape.");

    internal static Did2MessagingFloor RequireBasis(ReadOnlySpan<byte> exact, Did2MessagingSessionScope scope)
    {
        var basis = Did2MessagingFloor.Decode(exact, scope);
        if (basis.Phase != 1 || basis.Ordinal > long.MaxValue ||
            (basis.Ordinal != 0 && (basis.Status != 1 || basis.Ordinal < 2))) throw Bad();
        return basis;
    }
}
