using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed record DeepSecureStorageSlots(
    string DeviceSigningKey,
    string DeviceAgreementKey,
    string DeviceId,
    string DeviceRevocationHandle,
    string DevicePrekey,
    string PushKey,
    string MessageStoreInstanceId)
{
    internal static DeepSecureStorageSlots CreateForGeneration(ReadOnlySpan<byte> generationId)
    {
        if (generationId.Length != DeepAccountStoreContract.KeyMaterialSize
            || generationId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A nonzero 32-byte generation ID is required.", nameof(generationId));
        }

        var domain = "Deep/Store/V1/secure-slot-scope"u8;
        var input = new byte[domain.Length + generationId.Length];
        try
        {
            domain.CopyTo(input);
            generationId.CopyTo(input.AsSpan(domain.Length));
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(input, digest);
            var scope = Convert.ToHexStringLower(digest[..16]);
            CryptographicOperations.ZeroMemory(digest);
            return new DeepSecureStorageSlots(
                $"deep.store.v1.{scope}.device-signing",
                $"deep.store.v1.{scope}.device-agreement",
                $"deep.store.v1.{scope}.device-id",
                $"deep.store.v1.{scope}.device-revocation",
                $"deep.store.v1.{scope}.device-prekey",
                $"deep.store.v1.{scope}.push",
                $"deep.store.v1.{scope}.message-store-instance");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    internal static void Validate(DeepSecureStorageSlots slots)
    {
        ArgumentNullException.ThrowIfNull(slots);
        var accountValues = new[]
        {
            slots.DeviceSigningKey,
            slots.DeviceAgreementKey,
            slots.DeviceId,
            slots.DeviceRevocationHandle,
            slots.DevicePrekey,
            slots.PushKey,
            slots.MessageStoreInstanceId
        };
        const string prefix = "deep.store.v1.";
        var expectedSuffixes = new[]
        {
            ".device-signing", ".device-agreement", ".device-id",
            ".device-revocation", ".device-prekey", ".push",
            ".message-store-instance"
        };
        var scope = accountValues[0] is not null && accountValues[0].Length >= prefix.Length + 32
            ? accountValues[0].Substring(prefix.Length, 32)
            : string.Empty;
        if (scope.Length != 32
            || accountValues.Any(static value => value is null)
            || scope.AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0
            || accountValues.Distinct(StringComparer.Ordinal).Count() != accountValues.Length
            || accountValues.Where((value, index) => !string.Equals(
                value,
                prefix + scope + expectedSuffixes[index],
                StringComparison.Ordinal)).Any())
        {
            throw new LocalStateResetRequiredException(
                LocalStateResetRequiredReason.InvalidCurrentSchema,
                "Local secure-storage slot metadata is invalid and must be reset.");
        }
    }
}

public sealed record DeepSecureStorageWrite(string Slot, ReadOnlyMemory<byte> Value);

public delegate TResult DeepSecretReader<TResult>(ReadOnlySpan<byte> secret);

public delegate void DeepSecretAction(ReadOnlySpan<byte> secret);

/// <summary>
/// Owns one secure-storage read. The plaintext buffer is wiped deterministically
/// and cannot be accessed after disposal.
/// </summary>
public sealed class OwnedDeepSecret : IDisposable
{
    private readonly object gate = new();
    private byte[]? value;

    internal OwnedDeepSecret(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("A secure-storage value must not be empty.", nameof(value));
        }
        this.value = value.ToArray();
    }

    public int Length
    {
        get
        {
            lock (gate)
            {
                return GetValue().Length;
            }
        }
    }

    public TResult Use<TResult>(DeepSecretReader<TResult> reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        lock (gate)
        {
            return reader(GetValue());
        }
    }

    public void Use(DeepSecretAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        lock (gate)
        {
            action(GetValue());
        }
    }

    public void CopyTo(Span<byte> destination)
    {
        lock (gate)
        {
            var current = GetValue();
            if (destination.Length < current.Length)
            {
                throw new ArgumentException("The destination is shorter than the owned secret.", nameof(destination));
            }
            current.CopyTo(destination);
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            var current = value;
            value = null;
            if (current is not null)
            {
                CryptographicOperations.ZeroMemory(current);
            }
        }
    }

    private byte[] GetValue() => value
        ?? throw new ObjectDisposedException(nameof(OwnedDeepSecret));
}

public interface IDeepSecureStorage
{
    Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies the complete write set atomically. A platform adapter must journal the batch when
    /// its native keystore only exposes individual key operations.
    /// </summary>
    Task WriteBatchAsync(
        IReadOnlyList<DeepSecureStorageWrite> writes,
        CancellationToken cancellationToken = default);

    Task DeleteBatchAsync(
        IReadOnlyList<string> slots,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically and idempotently removes every value owned by STORE-V1. Implementations
    /// must identify the namespace without decoding any stored value. No value outside
    /// the exact <c>deep.store.v1.</c> prefix may be removed.
    /// </summary>
    Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default);
}

public sealed class InMemoryDeepSecureStorage : IDeepSecureStorage, IDisposable
{
    private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);
    private readonly object gate = new();
    private int disposed;

    public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(slot);
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ThrowIfDisposed();
            return Task.FromResult(values.TryGetValue(slot, out var value)
                ? new OwnedDeepSecret(value)
                : null);
        }
    }

    public Task WriteBatchAsync(
        IReadOnlyList<DeepSecureStorageWrite> writes,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(writes);
        cancellationToken.ThrowIfCancellationRequested();
        if (writes.Count == 0
            || writes.Select(static item => item.Slot).Distinct(StringComparer.Ordinal).Count() != writes.Count
            || writes.Any(static item => string.IsNullOrWhiteSpace(item.Slot) || item.Value.IsEmpty))
        {
            throw new ArgumentException("Secure-storage batch is empty or malformed.", nameof(writes));
        }

        var copies = writes.ToDictionary(
            static item => item.Slot,
            static item => item.Value.ToArray(),
            StringComparer.Ordinal);
        var committed = false;
        try
        {
            lock (gate)
            {
                ThrowIfDisposed();
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var slot in copies.Keys)
                {
                    if (values.ContainsKey(slot))
                    {
                        throw new InvalidOperationException("Secure-storage slot already exists.");
                    }
                }

                foreach (var item in copies)
                {
                    values[item.Key] = item.Value;
                }

                committed = true;
            }
        }
        finally
        {
            if (!committed)
            {
                foreach (var copy in copies.Values)
                {
                    CryptographicOperations.ZeroMemory(copy);
                }
            }
        }

        return Task.CompletedTask;
    }

    public Task DeleteBatchAsync(
        IReadOnlyList<string> slots,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(slots);
        cancellationToken.ThrowIfCancellationRequested();
        var validated = new HashSet<string>(StringComparer.Ordinal);
        foreach (var slot in slots)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(slot);
            if (!validated.Add(slot))
            {
                continue;
            }
        }
        lock (gate)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var slot in validated)
            {
                if (values.TryRemove(slot, out var value))
                {
                    CryptographicOperations.ZeroMemory(value);
                }
            }
        }

        return Task.CompletedTask;
    }

    public Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var slot in values.Keys.Where(
                         static slot => slot.StartsWith("deep.store.v1.", StringComparison.Ordinal)))
            {
                if (values.TryRemove(slot, out var value))
                {
                    CryptographicOperations.ZeroMemory(value);
                }
            }
        }

        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        lock (gate)
        {
            foreach (var value in values.Values)
            {
                CryptographicOperations.ZeroMemory(value);
            }

            values.Clear();
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
}
