using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

/// <summary>Instance-local acknowledged managed I/O and crypto work. Includes
/// audit, enrollment, pending and recovery work; not device/cache-miss traffic.
/// A failed native operation may transfer bytes that its managed API does not report.</summary>
public readonly record struct DeepSecureStorageWorkSnapshot(
    long ManifestReads, long ManifestProtectedBytesRead, long ManifestPlaintextBytesDecoded,
    long ObjectReads, long ObjectCiphertextBytesRead, long ObjectPlaintextBytesDecrypted,
    long ManifestWrites, long ManifestProtectedBytesWritten, long ObjectWrites,
    long ObjectCiphertextBytesWritten, long CleanupTombstones, long UnprotectCalls, long ProtectCalls);

public sealed partial class JournaledDeepSecureStorage
{
    private const int ManifestHeaderBytes = 96;
    private const int MaximumManifestBytes = 704 * 1024;
    private const int MaximumProtectedManifestBytes = 2 * 1024 * 1024;
    private const int ObjectHeaderBytes = 96;
    private const int ObjectOverheadBytes = 112;

    private sealed class ValueDescriptor(string slot, byte[] id, ulong birth, int length, byte[] hash, byte[] key) : IDisposable
    {
        internal string Slot { get; } = slot;
        internal byte[] Id { get; } = id;
        internal string Name => Convert.ToHexStringLower(Id);
        internal ulong Birth { get; } = birth;
        internal int Length { get; } = length;
        internal int FileLength => checked(Length + ObjectOverheadBytes);
        internal byte[] Hash { get; } = hash;
        internal byte[] Key { get; } = key;
        internal ValueDescriptor Copy() => new(Slot, Id.ToArray(), Birth, Length, Hash.ToArray(), Key.ToArray());
        public void Dispose() { CryptographicOperations.ZeroMemory(Key); }
    }

    private sealed class Inventory(byte[] storeId, ulong revision, byte[] predecessor) : IDisposable
    {
        internal byte[] StoreId { get; } = storeId;
        internal ulong Revision { get; } = revision;
        internal byte[] Predecessor { get; } = predecessor;
        internal SortedDictionary<string, ValueDescriptor> Values { get; } = new(StringComparer.Ordinal);
        internal SortedSet<string> Cleanup { get; } = new(StringComparer.Ordinal);
        internal Inventory Successor(byte[] predecessor)
        {
            var result = new Inventory(StoreId.ToArray(), checked(Revision + 1), predecessor.ToArray());
            try
            {
                foreach (var item in Values) result.Values.Add(item.Key, item.Value.Copy());
                result.Cleanup.UnionWith(Cleanup); return result;
            }
            catch { result.Dispose(); throw; }
        }
        public void Dispose() { foreach (var item in Values.Values) item.Dispose(); Values.Clear(); }
    }

    private sealed class InventoryRead(byte[] exact, Inventory inventory) : IDisposable
    {
        internal byte[] Exact { get; } = exact;
        internal byte[] Hash { get; } = SHA256.HashData(exact);
        internal Inventory Inventory { get; } = inventory;
        public void Dispose() { Inventory.Dispose(); CryptographicOperations.ZeroMemory(Exact); }
    }

    // Only public cryptographic facts survive a protector callback, never keys.
    private sealed record ObjectFact(string Name, int FileLength, byte[] Hash);
    private sealed record EntryFact(string Slot, string Name, ulong Birth, int Length, byte[] Hash, byte[] KeyHash);
    private sealed record InventoryFact(byte[] StoreId, ulong Revision, byte[] Hash,
        Dictionary<string, EntryFact> Values, HashSet<string> Cleanup);

    private static InventoryFact Facts(InventoryRead read) => Facts(read.Inventory, read.Hash);

    private static InventoryFact Facts(Inventory inventory, byte[] hash) => new(inventory.StoreId.ToArray(), inventory.Revision,
        hash.ToArray(), inventory.Values.ToDictionary(p => p.Key,
            p => new EntryFact(p.Key, p.Value.Name, p.Value.Birth, p.Value.Length, p.Value.Hash.ToArray(), SHA256.HashData(p.Value.Key)),
            StringComparer.Ordinal), new HashSet<string>(inventory.Cleanup, StringComparer.Ordinal));

    private static byte[] EncodeManifest(Inventory inventory)
    {
        var logical = ValidateInventory(inventory);
        var length = checked(ManifestHeaderBytes + inventory.Cleanup.Count * 32 +
            inventory.Values.Sum(p => 114 + StrictUtf8.GetByteCount(p.Key)));
        if (length > MaximumManifestBytes) throw new InvalidOperationException("Protected manifest exceeds capacity.");
        var bytes = new byte[length];
        "DSS2"u8.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2);
        inventory.StoreId.CopyTo(bytes, 8); BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(40), inventory.Revision);
        inventory.Predecessor.CopyTo(bytes, 48);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(80), checked((uint)inventory.Values.Count));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(84), checked((uint)inventory.Cleanup.Count));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(88), checked((ulong)logical));
        var offset = ManifestHeaderBytes;
        foreach (var item in inventory.Values.Values)
        {
            var slot = StrictUtf8.GetBytes(item.Slot);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)slot.Length)); offset += 2;
            slot.CopyTo(bytes, offset); offset += slot.Length;
            item.Id.CopyTo(bytes, offset); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), item.Birth); offset += 8;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)item.Length)); offset += 4;
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)item.FileLength)); offset += 4;
            item.Hash.CopyTo(bytes, offset); offset += 32; item.Key.CopyTo(bytes, offset); offset += 32;
        }
        foreach (var name in inventory.Cleanup) { Convert.FromHexString(name).CopyTo(bytes, offset); offset += 32; }
        return bytes;
    }

    private static Inventory DecodeManifest(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < ManifestHeaderBytes or > MaximumManifestBytes || !bytes[..4].SequenceEqual("DSS2"u8) ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]) != 2 || BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]) != 0)
            throw new CryptographicException("Protected manifest framing is invalid; explicit enrollment may be required.");
        var count = BinaryPrimitives.ReadUInt32BigEndian(bytes[80..]);
        var cleanup = BinaryPrimitives.ReadUInt32BigEndian(bytes[84..]);
        if (count > MaximumEntries || cleanup > MaximumEntries)
            throw new CryptographicException("Protected manifest counts exceed capacity.");
        var inventory = new Inventory(bytes.Slice(8, 32).ToArray(), BinaryPrimitives.ReadUInt64BigEndian(bytes[40..]), bytes.Slice(48, 32).ToArray());
        try
        {
            var offset = ManifestHeaderBytes; string? previous = null;
            for (var index = 0U; index < count; index++)
            {
                if (bytes.Length - offset < 2) throw new CryptographicException("Protected manifest entry is truncated.");
                var slotLength = BinaryPrimitives.ReadUInt16BigEndian(bytes[offset..]); offset += 2;
                if (slotLength is < 1 or > MaximumSlotBytes || bytes.Length - offset < slotLength + 112)
                    throw new CryptographicException("Protected manifest entry is outside its bound.");
                var slot = StrictUtf8.GetString(bytes.Slice(offset, slotLength)); ValidateSlot(slot); offset += slotLength;
                if (previous is not null && StringComparer.Ordinal.Compare(previous, slot) >= 0)
                    throw new CryptographicException("Protected manifest names are not canonical.");
                previous = slot;
                var id = bytes.Slice(offset, 32).ToArray(); offset += 32;
                var birth = BinaryPrimitives.ReadUInt64BigEndian(bytes[offset..]); offset += 8;
                var length = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
                var fileLength = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
                if (length is < 1 || length > DeepSecureStorageRegistration.MaximumBytesForSlot(slot) || fileLength != length + ObjectOverheadBytes)
                    throw new CryptographicException("Protected manifest value size is invalid.");
                var hash = bytes.Slice(offset, 32).ToArray(); offset += 32;
                var key = bytes.Slice(offset, 32).ToArray(); offset += 32;
                inventory.Values.Add(slot, new(slot, id, birth, checked((int)length), hash, key));
            }
            previous = null;
            for (var index = 0U; index < cleanup; index++)
            {
                if (bytes.Length - offset < 32) throw new CryptographicException("Protected cleanup inventory is truncated.");
                var name = Convert.ToHexStringLower(bytes.Slice(offset, 32)); offset += 32;
                if (previous is not null && StringComparer.Ordinal.Compare(previous, name) >= 0)
                    throw new CryptographicException("Protected cleanup IDs are not canonical.");
                previous = name; inventory.Cleanup.Add(name);
            }
            if (offset != bytes.Length || checked((ulong)ValidateInventory(inventory)) != BinaryPrimitives.ReadUInt64BigEndian(bytes[88..]))
                throw new CryptographicException("Protected manifest accounting or EOF is invalid.");
            return inventory;
        }
        catch { inventory.Dispose(); throw; }
    }

    private static long ValidateInventory(Inventory inventory)
    {
        if (inventory.StoreId.Length != 32 || !Nonzero(inventory.StoreId) || inventory.Revision == 0 || inventory.Predecessor.Length != 32 ||
            (inventory.Revision > 1 && !Nonzero(inventory.Predecessor)) || inventory.Values.Count > MaximumEntries || inventory.Cleanup.Count > MaximumEntries)
            throw new CryptographicException("Protected manifest identity or capacity is invalid.");
        var ids = new HashSet<string>(StringComparer.Ordinal); long logical = 8;
        foreach (var item in inventory.Values.Values)
        {
            ValidateSlot(item.Slot);
            if (item.Id.Length != 32 || !Nonzero(item.Id) || !ids.Add(item.Name) || item.Key.Length != 32 || !Nonzero(item.Key) ||
                item.Hash.Length != 32 || !Nonzero(item.Hash) || item.Birth == 0 || item.Birth > inventory.Revision ||
                item.Length is < 1 || item.Length > DeepSecureStorageRegistration.MaximumBytesForSlot(item.Slot))
                throw new CryptographicException("Protected manifest descriptor is invalid.");
            logical = checked(logical + 6 + StrictUtf8.GetByteCount(item.Slot) + item.Length);
        }
        if (logical > MaximumPlaintextBytes) throw new CryptographicException("Protected logical inventory exceeds capacity.");
        foreach (var name in inventory.Cleanup)
            if (!ValidObjectName(name) || !Nonzero(Convert.FromHexString(name)) || ids.Contains(name))
                throw new CryptographicException("Protected cleanup inventory overlaps active objects.");
        return logical;
    }

    private static bool Nonzero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) >= 0;
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool ValidObjectName(string name) => name.Length == 64 && name.AsSpan().IndexOfAnyExcept("0123456789abcdef") < 0;
    private static byte[] Random32() { byte[] value; do { value = RandomNumberGenerator.GetBytes(32); } while (!Nonzero(value)); return value; }
}
