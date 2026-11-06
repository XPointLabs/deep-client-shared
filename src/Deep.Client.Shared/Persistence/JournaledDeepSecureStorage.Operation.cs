using System.Diagnostics;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    // The gate and process lease own this object. It never outlives one public
    // operation, and its admission is destroyed before every external edge.
    private ClosedOperation? operation;

    private async Task<ClosedOperation> BeginOperationAsync(CancellationToken ct)
    {
        if (operation is not null) throw new InvalidOperationException("Storage operation is already owned.");
        var owned = operation = new ClosedOperation(this);
        try { owned.ProcessLease = await AcquireProcessLeaseAsync(ct).ConfigureAwait(false); return owned; }
        catch { owned.Dispose(); throw; }
    }

    private sealed class ClosedOperation(JournaledDeepSecureStorage owner) : IDisposable
    {
        internal InventoryRead? Admission;
        internal FileStream? ProcessLease;
        internal ReplacementAuthority? Authority;
        internal InventoryFact? ClosedFacts;
        internal Inventory? ResultLoan;
        internal RecoveryPlan? Recovery;
        internal readonly HashSet<string> ReservedNames = new(StringComparer.Ordinal);
        internal bool FinalCleanup, FinalClosed, NoExternal;
        internal int HookInvalidations;
        private Stopwatch? retryTimer;

        internal void DropAdmission()
        {
            Admission?.Dispose(); Admission = null; Authority = null; ClosedFacts = null;
            ResultLoan?.Dispose(); ResultLoan = null;
            owner.DropDirectories();
        }

        internal TimeSpan RemainingRetry()
        {
            retryTimer ??= Stopwatch.StartNew();
            var remaining = TimeSpan.FromSeconds(2) - retryTimer.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new IOException("Protected storage operation retry budget exhausted.");
            return remaining;
        }

        internal void CheckRetry() { if (retryTimer is not null) _ = RemainingRetry(); }

        internal void BeforeHook()
        {
            _ = RemainingRetry();
            if (HookInvalidations >= 8) throw new IOException("Protected storage callback invalidation budget exhausted.");
            HookInvalidations++;
            DropAdmission();
        }

        public void Dispose()
        {
            DropAdmission(); ProcessLease?.Dispose(); ProcessLease = null; owner.operation = null;
        }
    }

    private sealed class CleanupRestartException : Exception;

    private void BeforeProvider()
    {
        if (operation?.FinalClosed == true || operation?.NoExternal == true)
            throw new InvalidOperationException("The final storage boundary is already closed.");
        operation?.DropAdmission();
    }

    private void CheckFinalSource(InventoryRead current, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireExactSource(current.Hash);
        ct.ThrowIfCancellationRequested();
    }

    private void CheckGuard(InventoryRead current, Guard? guard)
    {
        for (; guard is not null; guard = guard.Next)
        {
            if (!current.Inventory.Values.TryGetValue(guard.Slot, out var descriptor))
                throw new CryptographicException("Protected mutation guard disappeared.");
            var value = ReadObject(current.Inventory, descriptor);
            try { if (!Fixed(value, guard.Expected)) throw new CryptographicException("Protected mutation guard changed."); }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
    }
}
