using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

// Deliberately internal: this proves a call-local dependency inventory, not
// currentness or permission to import/retire any secret.
internal interface IDeepSecureStorageGuardedRead
{
    Task<OwnedDeepSecretBatch> ReadOwnedGuardedBatchAsync(DeepSecureStorageGuardedRead request,
        CancellationToken cancellationToken);
}

internal static class DeepSecureStorageGuardedReadExtensions
{
    internal static async Task<OwnedDeepSecretBatch> ReadOwnedGuardedBatchAsync(this IDeepSecureStorage storage,
        IReadOnlyList<string> returnedSlots, IReadOnlyDictionary<string, byte[]?> guards,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(storage);
        using var request = new DeepSecureStorageGuardedRead(returnedSlots, guards);
        cancellationToken.ThrowIfCancellationRequested();
        if (storage is not IDeepSecureStorageGuardedRead provider)
            throw new NotSupportedException("Secure storage does not support atomic guarded reads.");
        return await provider.ReadOwnedGuardedBatchAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class DeepSecureStorageGuardedRead : IDisposable
{
    internal string[] ReturnedSlots { get; }
    internal IReadOnlyDictionary<string, byte[]?> Guards => guards;
    private readonly Dictionary<string, byte[]?> guards = new(StringComparer.Ordinal);

    internal DeepSecureStorageGuardedRead(IReadOnlyList<string> returnedSlots,
        IReadOnlyDictionary<string, byte[]?> expected)
    {
        ArgumentNullException.ThrowIfNull(returnedSlots);
        ArgumentNullException.ThrowIfNull(expected);
        var returnedCount = returnedSlots.Count;
        var guardCount = expected.Count;
        if (returnedCount is < 0 or > 32 || guardCount is < 1 or > 1024)
            throw new ArgumentException("Guarded read group is outside its bound.");
        ReturnedSlots = new string[returnedCount];
        var distinct = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            for (var index = 0; index < returnedCount; index++)
            {
                var slot = returnedSlots[index];
                DeepSecureStorageRegistration.ValidateSlot(slot);
                if (!distinct.Add(slot)) throw new ArgumentException("Guarded return group repeats a slot.");
                ReturnedSlots[index] = slot;
            }
            foreach (var pair in expected)
            {
                DeepSecureStorageRegistration.ValidateSlot(pair.Key);
                if (guards.Count >= guardCount || guards.ContainsKey(pair.Key) || pair.Value is { Length: not 32 })
                    throw new ArgumentException("Guarded dependency group is malformed.");
                guards.Add(pair.Key, pair.Value?.ToArray());
            }
            if (guards.Count != guardCount) throw new ArgumentException("Guarded dependency count changed.");
        }
        catch { Dispose(); throw; }
    }

    internal void Require(string slot, byte[]? plaintext)
    {
        if (!guards.TryGetValue(slot, out var expected)) return;
        if (expected is null)
        {
            if (plaintext is not null) throw new CryptographicException("Guarded dependency is unexpectedly present.");
            return;
        }
        if (plaintext is null) throw new CryptographicException("Guarded dependency is absent.");
        Span<byte> actual = stackalloc byte[32];
        try
        {
            SHA256.HashData(plaintext, actual);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                throw new CryptographicException("Guarded dependency changed.");
        }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    public void Dispose()
    {
        foreach (var hash in guards.Values) if (hash is not null) CryptographicOperations.ZeroMemory(hash);
    }
}
