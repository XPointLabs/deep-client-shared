using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence;

/// <summary>Owned, bounded snapshot for the single atomic CAS-and-insert operation.</summary>
internal sealed class DeepSecureStorageRegistration : IDisposable
{
    internal const int MaximumEntries = 1024;
    internal const int MaximumValueBytes = 1024 * 1024;
    internal const int MaximumPlaintextBytes = 8 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    internal readonly string Slot;
    internal readonly byte[] Expected, Replacement;
    internal readonly Dictionary<string, byte[]> Insertions = new(StringComparer.Ordinal);

    internal DeepSecureStorageRegistration(string slot, ReadOnlyMemory<byte> expected,
        ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions)
    {
        ValidateSlot(slot); ArgumentNullException.ThrowIfNull(insertions);
        ValidateValue(expected); ValidateValue(replacement);
        if (insertions.Count is < 1 or >= MaximumEntries)
            throw new ArgumentException("Atomic secure registration has an invalid insertion count.", nameof(insertions));
        var insertionBytes = ValidateWrites(insertions);
        if (insertionBytes + 6L + Utf8.GetByteCount(slot) + replacement.Length > MaximumPlaintextBytes)
            throw new InvalidOperationException("Atomic secure registration exceeds protected inventory capacity.");
        Slot = slot; Expected = expected.ToArray(); Replacement = replacement.ToArray();
        try
        {
            foreach (var item in insertions)
            {
                ArgumentNullException.ThrowIfNull(item);
                ValidateSlot(item.Slot); ValidateValue(item.Value);
                if (item.Slot == slot || Insertions.ContainsKey(item.Slot))
                    throw new ArgumentException("Atomic secure registration repeats a slot.", nameof(insertions));
                Insertions.Add(item.Slot, item.Value.ToArray());
            }
            ValidateCapacity(new Dictionary<string, byte[]>(StringComparer.Ordinal) { [slot] = Expected });
        }
        catch { Dispose(); throw; }
    }

    internal void ValidateCapacity(IEnumerable<KeyValuePair<string, byte[]>> values)
    {
        var count = 0; long bytes = 8;
        foreach (var pair in values)
        {
            count++;
            bytes += 6L + Utf8.GetByteCount(pair.Key) + (pair.Key == Slot ? Replacement.Length : pair.Value.Length);
        }
        foreach (var pair in Insertions) bytes += 6L + Utf8.GetByteCount(pair.Key) + pair.Value.Length;
        if (count + Insertions.Count > MaximumEntries || bytes > MaximumPlaintextBytes)
            throw new InvalidOperationException("Atomic secure registration exceeds protected inventory capacity.");
    }

    internal Dictionary<string, byte[]> CopySuccessor()
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            result.Add(Slot, Replacement.ToArray());
            foreach (var item in Insertions) result.Add(item.Key, item.Value.ToArray());
            return result;
        }
        catch { foreach (var value in result.Values) CryptographicOperations.ZeroMemory(value); throw; }
    }

    internal static void ValidateSlot(string slot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slot);
        if (slot.Any(static c => char.IsControl(c) || char.IsSurrogate(c)) || Utf8.GetByteCount(slot) > 512)
            throw new ArgumentException("Secure-storage slot name is invalid.", nameof(slot));
    }
    internal static void ValidateInventory(IEnumerable<KeyValuePair<string, byte[]>> values)
    {
        var count = 0; long length = 8;
        foreach (var pair in values)
        {
            ValidateSlot(pair.Key); ValidateValue(pair.Value);
            count++; length += 6L + Utf8.GetByteCount(pair.Key) + pair.Value.Length;
            if (count > MaximumEntries || length > MaximumPlaintextBytes)
                throw new InvalidOperationException("Secure-storage aggregate exceeds its capacity.");
        }
    }
    internal static long ValidateWrites(IReadOnlyList<DeepSecureStorageWrite> writes)
    {
        ArgumentNullException.ThrowIfNull(writes);
        if (writes.Count is < 1 or > MaximumEntries)
            throw new ArgumentException("Secure-storage batch is empty or too large.", nameof(writes));
        var slots = new HashSet<string>(StringComparer.Ordinal); long bytes = 8;
        foreach (var item in writes)
        {
            ArgumentNullException.ThrowIfNull(item); ValidateSlot(item.Slot); ValidateValue(item.Value);
            if (!slots.Add(item.Slot)) throw new ArgumentException("Secure-storage batch repeats a slot.", nameof(writes));
            bytes += 6L + Utf8.GetByteCount(item.Slot) + item.Value.Length;
            if (bytes > MaximumPlaintextBytes)
                throw new InvalidOperationException("Secure-storage batch exceeds protected inventory capacity.");
        }
        return bytes;
    }
    private static void ValidateValue(ReadOnlyMemory<byte> value)
    {
        if (value.IsEmpty || value.Length > MaximumValueBytes)
            throw new ArgumentException("Secure-storage value is outside its byte bound.", nameof(value));
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Expected); CryptographicOperations.ZeroMemory(Replacement);
        foreach (var value in Insertions.Values) CryptographicOperations.ZeroMemory(value);
        Insertions.Clear();
    }
}
