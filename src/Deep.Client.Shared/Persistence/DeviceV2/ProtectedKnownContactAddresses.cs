using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Services;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Address-book data only. Possessing this protected record grants no relationship,
// resolve, publication or Store authority; the native effect owner rejoins those.
internal static class ProtectedKnownContactAddresses
{
    internal const string Slot = "deep.store.v2.known-contact-addresses";
    private const int Header = 84, AddressBytes = 256;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static Dictionary<string, DeepPermanentIdV2> Decode(ReadOnlySpan<byte> exact,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (exact.Length < Header || exact.Length > Header + 128 * (34 + AddressBytes) ||
            exact[0] != 1 || exact[1] != 0 || !exact.Slice(4, 16).SequenceEqual(network) ||
            !exact.Slice(20, 32).SequenceEqual(account) || !exact.Slice(52, 32).SequenceEqual(instance))
            throw new InvalidDataException("Protected known-contact data has another scope or grammar.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(exact[2..]);
        if (count > DeepIdV2AccountService.MaximumKnownContactAddresses)
            throw new InvalidDataException("Protected known-contact data exceeds its bound.");
        var result = new Dictionary<string, DeepPermanentIdV2>(StringComparer.OrdinalIgnoreCase);
        var offset = Header; string? previous = null;
        for (var i = 0; i < count; i++)
        {
            if (exact.Length - offset < 34) throw new InvalidDataException("Truncated protected address.");
            var name = Convert.ToHexString(exact.Slice(offset, 32)); offset += 32;
            var length = BinaryPrimitives.ReadUInt16BigEndian(exact[offset..]); offset += 2;
            if (length is 0 or > AddressBytes || exact.Length - offset < length ||
                previous is not null && StringComparer.Ordinal.Compare(previous, name) >= 0)
                throw new InvalidDataException("Protected known-contact entries are noncanonical.");
            var address = DeepPermanentIdV2.ParseCanonical(Utf8.GetString(exact.Slice(offset, length)));
            result.Add(name, address); previous = name; offset += length;
        }
        if (offset != exact.Length) throw new InvalidDataException("Trailing protected known-contact data.");
        return result;
    }

    internal static byte[] Encode(IReadOnlyDictionary<string, DeepPermanentIdV2> addresses,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var owned = DeepIdV2AccountService.CopyKnownContactAddresses(addresses);
        if (network.Length != 16 || account.Length != 32 || instance.Length != 32)
            throw new ArgumentException("Exact protected address-book scope required.");
        using var stream = new MemoryStream();
        var header = new byte[Header]; header[0] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), checked((ushort)owned.Count));
        network.CopyTo(header.AsSpan(4)); account.CopyTo(header.AsSpan(20)); instance.CopyTo(header.AsSpan(52));
        stream.Write(header);
        foreach (var entry in owned.OrderBy(entry => entry.Key.ToUpperInvariant(), StringComparer.Ordinal))
        {
            var text = Utf8.GetBytes(entry.Value.CanonicalText);
            try
            {
                if (text.Length is 0 or > AddressBytes) throw new InvalidDataException("Address exceeds its bound.");
                stream.Write(Convert.FromHexString(entry.Key));
                var length = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)text.Length);
                stream.Write(length); stream.Write(text);
            }
            finally { CryptographicOperations.ZeroMemory(text); }
        }
        return stream.ToArray();
    }
}
