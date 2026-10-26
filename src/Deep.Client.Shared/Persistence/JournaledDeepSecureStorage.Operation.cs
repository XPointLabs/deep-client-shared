using System.Diagnostics;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    // The gate and process lease own this object. It never outlives one public
    // operation, and its admission is destroyed before every external edge.
    private ClosedOperation? operation;

    private ClosedOperation BeginOperation()
    {
        if (operation is not null) throw new InvalidOperationException("Storage operation is already owned.");
        return operation = new ClosedOperation(this);
    }

    private sealed class ClosedOperation(JournaledDeepSecureStorage owner) : IDisposable
    {
        internal InventoryRead? Admission;
        internal ReplacementAuthority? Authority;
        internal bool FinalCleanup, Recovered;
        internal int HookInvalidations;
        private Stopwatch? retryTimer;

        internal void DropAdmission()
        {
            Admission?.Dispose(); Admission = null; Authority = null;
            owner.DropDirectories();
        }

        internal TimeSpan RemainingRetry()
        {
            retryTimer ??= Stopwatch.StartNew();
            var remaining = TimeSpan.FromSeconds(2) - retryTimer.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new IOException("Protected storage operation retry budget exhausted.");
            return remaining;
        }

        internal void BeforeHook()
        {
            _ = RemainingRetry();
            if (HookInvalidations >= 8) throw new IOException("Protected storage callback invalidation budget exhausted.");
            HookInvalidations++;
            DropAdmission();
        }

        public void Dispose()
        {
            DropAdmission(); owner.operation = null;
        }
    }

    private sealed class CleanupRestartException : Exception;

    private void BeforeProvider() => operation?.DropAdmission();

    private InventoryRead TakeAdmission(ReplacementAuthority authority, CancellationToken ct)
    {
        Revalidate(authority, ct);
        var result = operation!.Admission ?? throw new CryptographicException("Current storage admission is absent.");
        operation.Admission = null; operation.Authority = null;
        return result;
    }

    private void CheckFinalSource(InventoryRead current, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireExactSource(current.Hash);
        ct.ThrowIfCancellationRequested();
    }

    private void CheckGuard(InventoryRead current, Guard? guard)
    {
        if (guard is null) return;
        if (!current.Inventory.Values.TryGetValue(guard.Slot, out var descriptor))
            throw new CryptographicException("Protected mutation guard disappeared.");
        var value = ReadObject(current.Inventory, descriptor);
        try { if (!Fixed(value, guard.Expected)) throw new CryptographicException("Protected mutation guard changed."); }
        finally { CryptographicOperations.ZeroMemory(value); }
    }
}
