using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    async Task<OwnedDeepSecretBatch> IDeepSecureStorageGuardedRead.ReadOwnedGuardedBatchAsync(
        DeepSecureStorageGuardedRead request, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            ThrowIfDisposed(); using var owned = await BeginOperationAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitReadAsync(cancellationToken).ConfigureAwait(false);
            var returned = request.ReturnedSlots.ToHashSet(StringComparer.Ordinal);
            foreach (var slot in request.Guards.Keys.Concat(request.ReturnedSlots).Distinct(StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte[]? plaintext = null;
                try
                {
                    if (current.Inventory.Values.TryGetValue(slot, out var descriptor))
                        plaintext = ReadObject(current.Inventory, descriptor);
                    request.Require(slot, plaintext);
                    if (plaintext is not null && returned.Contains(slot))
                    { values.Add(slot, plaintext); plaintext = null; }
                }
                finally { if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
            }
            // Even guard-only/all-absent reads join the actual final source and
            // cancellation before they can consume the cold audit marker.
            CheckFinalSource(current, cancellationToken);
            var result = OwnedDeepSecretBatch.CopyFrom(request.ReturnedSlots, values);
            auditRequired = 0; return result;
        }
        finally { ZeroValues(values); gate.Release(); }
    }
}
