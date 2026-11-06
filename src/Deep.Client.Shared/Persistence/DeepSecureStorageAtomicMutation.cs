using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

// One actual protected-inventory publication. There is deliberately no
// sequential fallback for providers that cannot atomically compare all roots.
internal interface IDeepSecureStorageAtomicMutation
{
    Task<bool> CompareExchangeBatchAsync(DeepSecureStorageAtomicMutation mutation, CancellationToken ct);
}

internal sealed class DeepSecureStorageAtomicMutation : IDisposable
{
    internal Dictionary<string, byte[]> Expected { get; } = new(StringComparer.Ordinal);
    internal Dictionary<string, byte[]> Writes { get; } = new(StringComparer.Ordinal);
    internal DeepSecureStorageAtomicMutation(IReadOnlyDictionary<string, byte[]> expected,
        IReadOnlyList<DeepSecureStorageWrite> writes)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (expected.Count is < 1 or > DeepSecureStorageRegistration.MaximumEntries)
            throw new ArgumentException("Atomic mutation has an invalid guard count.", nameof(expected));
        DeepSecureStorageRegistration.ValidateInventory(expected);
        _ = DeepSecureStorageRegistration.ValidateWrites(writes);
        try
        {
            foreach (var pair in expected)
            {
                DeepSecureStorageRegistration.ValidateSlot(pair.Key);
                if (pair.Value.Length is < 1 || pair.Value.Length > DeepSecureStorageRegistration.MaximumBytesForSlot(pair.Key))
                    throw new ArgumentException("Atomic mutation has an invalid predecessor.", nameof(expected));
                Expected.Add(pair.Key, pair.Value.ToArray());
            }
            foreach (var write in writes) Writes.Add(write.Slot, write.Value.ToArray());
        }
        catch { Dispose(); throw; }
    }
    internal Dictionary<string, byte[]> CopyWrites()
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try { foreach (var pair in Writes) result.Add(pair.Key, pair.Value.ToArray()); return result; }
        catch { foreach (var bytes in result.Values) CryptographicOperations.ZeroMemory(bytes); throw; }
    }
    public void Dispose()
    {
        foreach (var bytes in Expected.Values.Concat(Writes.Values)) CryptographicOperations.ZeroMemory(bytes);
    }
}

internal static class DeepSecureStorageAtomicMutationExtensions
{
    internal static async Task<bool> CompareExchangeBatchAsync(this IDeepSecureStorage storage,
        IReadOnlyDictionary<string, byte[]> expected, IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct)
    {
        using var mutation = new DeepSecureStorageAtomicMutation(expected, writes);
        if (storage is not IDeepSecureStorageAtomicMutation provider)
            throw new NotSupportedException("Secure storage does not support atomic local queue commits.");
        return await provider.CompareExchangeBatchAsync(mutation, ct).ConfigureAwait(false);
    }
}
