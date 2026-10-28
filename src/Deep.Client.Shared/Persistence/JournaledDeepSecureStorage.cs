using System.Security.Cryptography;
using System.Text;

namespace Deep.Client.Shared.Persistence;

/// <summary>Platform-owned authenticated protection. Each call returns a fresh
/// array and rejects modified ciphertext; successful calls are not cached permission.</summary>
public interface IDeepSecretProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext);
    byte[] Unprotect(ReadOnlySpan<byte> protectedBytes);
}

/// <summary>One protected complete inventory and immutable authenticated value
/// objects. The constructor opens existing state; creation/enrollment are explicit.</summary>
public sealed partial class JournaledDeepSecureStorage : IDeepSecureStorage, IDisposable
{
    private const int MaximumEntries = DeepSecureStorageRegistration.MaximumEntries;
    private const int MaximumSlotBytes = 512;
    private const int MaximumPlaintextBytes = DeepSecureStorageRegistration.MaximumPlaintextBytes;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly string statePath, pendingPath, backupPath, leasePath, objectDirectory;
    private readonly IDeepSecretProtector protector;
    private readonly SemaphoreSlim gate = new(1, 1);
    private int disposed, auditRequired = 1;
    private long manifestReads, manifestProtectedRead, manifestPlaintext, objectReads, objectCiphertextRead, objectPlaintext;
    private long manifestWrites, manifestProtectedWritten, objectWrites, objectCiphertextWritten, cleanupTombstones, unprotectCalls, protectCalls;

    public JournaledDeepSecureStorage(string statePath, IDeepSecretProtector protector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        this.protector = protector ?? throw new ArgumentNullException(nameof(protector));
        this.statePath = Path.GetFullPath(statePath);
        if (string.IsNullOrWhiteSpace(Path.GetDirectoryName(this.statePath))) throw new ArgumentException("Storage path has no parent.", nameof(statePath));
        pendingPath = this.statePath + ".pending"; backupPath = this.statePath + ".backup";
        leasePath = this.statePath + ".lock"; objectDirectory = this.statePath + ".objects";
    }

    /// <summary>Cumulative closed scalars, including exceptional/recovery work.
    /// Safe after disposal; it grants no storage permission.</summary>
    public DeepSecureStorageWorkSnapshot ReadWorkSnapshot() => new(
        Interlocked.Read(ref manifestReads), Interlocked.Read(ref manifestProtectedRead), Interlocked.Read(ref manifestPlaintext),
        Interlocked.Read(ref objectReads), Interlocked.Read(ref objectCiphertextRead), Interlocked.Read(ref objectPlaintext),
        Interlocked.Read(ref manifestWrites), Interlocked.Read(ref manifestProtectedWritten), Interlocked.Read(ref objectWrites),
        Interlocked.Read(ref objectCiphertextWritten), Interlocked.Read(ref cleanupTombstones), Interlocked.Read(ref unprotectCalls), Interlocked.Read(ref protectCalls));

    public async Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken cancellationToken = default)
    {
        ValidateSlot(slot);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); using var owned = await BeginOperationAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitReadAsync(cancellationToken).ConfigureAwait(false);
            if (!current.Inventory.Values.TryGetValue(slot, out var descriptor))
            { CheckFinalSource(current, cancellationToken); auditRequired = 0; return null; }
            var value = ReadObject(current.Inventory, descriptor);
            try { CheckFinalSource(current, cancellationToken); var result = new OwnedDeepSecret(value); auditRequired = 0; return result; }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        finally { gate.Release(); }
    }

    public async Task<OwnedDeepSecretBatch> ReadOwnedBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default)
    {
        var captured = OwnedDeepSecretBatch.CaptureSlots(slots);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            ThrowIfDisposed(); using var owned = await BeginOperationAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitReadAsync(cancellationToken).ConfigureAwait(false);
            foreach (var slot in captured)
                if (current.Inventory.Values.TryGetValue(slot, out var item)) values.Add(slot, ReadObject(current.Inventory, item));
            CheckFinalSource(current, cancellationToken);
            var result = OwnedDeepSecretBatch.CopyFrom(captured, values); auditRequired = 0; return result;
        }
        finally { ZeroValues(values); gate.Release(); }
    }

    public async Task AuditAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); using var owned = await BeginOperationAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitReadAsync(cancellationToken, forceAudit: true).ConfigureAwait(false);
            CheckFinalSource(current, cancellationToken); auditRequired = 0;
        }
        finally { gate.Release(); }
    }

    public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken cancellationToken = default)
    {
        _ = DeepSecureStorageRegistration.ValidateWrites(writes);
        var captured = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            foreach (var write in writes) captured.Add(write.Slot, write.Value.ToArray());
            _ = await MutateAsync(MutationKind.Insert, null, null, captured, [], cancellationToken).ConfigureAwait(false);
        }
        finally { ZeroValues(captured); }
    }

    public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement,
        CancellationToken cancellationToken = default)
    {
        ValidateSlot(slot); var maximum = DeepSecureStorageRegistration.MaximumBytesForSlot(slot);
        if (expected.IsEmpty || replacement.IsEmpty || expected.Length > maximum || replacement.Length > maximum)
            throw new ArgumentException("Secure-storage replacement is outside its byte bound.");
        var before = expected.ToArray(); var after = replacement.ToArray();
        try { return await MutateAsync(MutationKind.Replace, slot, before, new Dictionary<string, byte[]>(StringComparer.Ordinal) { [slot] = after }, [], cancellationToken).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    public async Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement,
        IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken cancellationToken = default)
    {
        using var batch = new DeepSecureStorageRegistration(slot, expected, replacement, insertions);
        var writes = new Dictionary<string, byte[]>(batch.Insertions, StringComparer.Ordinal) { [batch.Slot] = batch.Replacement };
        return await MutateAsync(MutationKind.Register, batch.Slot, batch.Expected, writes, [], cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> CompareAndDeleteAsync(string guardSlot, ReadOnlyMemory<byte> expected, IReadOnlyList<string> slots,
        CancellationToken cancellationToken = default)
    {
        using var batch = new DeepSecureStorageGuardedDeletion(guardSlot, expected, slots);
        return await MutateAsync(MutationKind.GuardedDelete, batch.GuardSlot, batch.Expected, null, batch.Slots, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(slots);
        var captured = new HashSet<string>(StringComparer.Ordinal);
        foreach (var slot in slots) { ValidateSlot(slot); captured.Add(slot); }
        _ = await MutateAsync(MutationKind.Delete, null, null, null, captured.ToArray(), cancellationToken).ConfigureAwait(false);
    }
    public async Task PurgeStoreV1NamespaceAsync(CancellationToken cancellationToken = default) =>
        _ = await MutateAsync(MutationKind.PurgeV1, null, null, null, [], cancellationToken).ConfigureAwait(false);
    public async Task PurgeStoreV2NamespaceAsync(CancellationToken cancellationToken = default) =>
        _ = await MutateAsync(MutationKind.PurgeV2, null, null, null, [], cancellationToken).ConfigureAwait(false);

    private enum MutationKind { Insert, Replace, Register, GuardedDelete, Delete, PurgeV1, PurgeV2 }
    private sealed record Guard(string Slot, byte[] Expected);

    private async Task<bool> MutateAsync(MutationKind kind, string? slot, byte[]? expected,
        IReadOnlyDictionary<string, byte[]>? writes, string[] deletions, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); using var owned = await BeginOperationAsync(ct).ConfigureAwait(false);
            using var current = await AdmitMutationAsync(ct).ConfigureAwait(false);
            Guard? guard = null;
            if (slot is not null)
            {
                if (!current.Inventory.Values.TryGetValue(slot, out var descriptor)) { await CloseUnchangedMutationAsync(current, ct).ConfigureAwait(false); return false; }
                var value = ReadObject(current.Inventory, descriptor);
                bool matches;
                try { matches = Fixed(value, expected!); }
                finally { CryptographicOperations.ZeroMemory(value); }
                if (!matches) { await CloseUnchangedMutationAsync(current, ct).ConfigureAwait(false); return false; }
                guard = new(slot, expected!);
            }
            if (writes is not null && writes.Keys.Any(name => name != slot && current.Inventory.Values.ContainsKey(name)))
            {
                if (kind == MutationKind.Insert) throw new InvalidOperationException("Secure-storage slot already exists.");
                await CloseUnchangedMutationAsync(current, ct).ConfigureAwait(false); return false;
            }
            var remove = kind switch
            {
                MutationKind.PurgeV1 => current.Inventory.Values.Keys.Where(name => name.StartsWith("deep.store.v1.", StringComparison.Ordinal)).ToArray(),
                MutationKind.PurgeV2 => current.Inventory.Values.Keys.Where(name => name.StartsWith("deep.store.v2.", StringComparison.Ordinal)).ToArray(),
                _ => deletions
            };
            if ((writes is null || writes.Count == 0) && !remove.Any(current.Inventory.Values.ContainsKey)) { await CloseUnchangedMutationAsync(current, ct).ConfigureAwait(false); return true; }
            var lengths = current.Inventory.Values.ToDictionary(p => p.Key, p => p.Value.Length, StringComparer.Ordinal);
            foreach (var name in remove) lengths.Remove(name);
            if (writes is not null) foreach (var item in writes) lengths[item.Key] = item.Value.Length;
            DeepSecureStorageRegistration.ValidateInventoryLengths(lengths);
            await PublishMutationAsync(current, writes, remove, guard, ct).ConfigureAwait(false);
            auditRequired = 0;
            return true;
        }
        finally { gate.Release(); }
    }

    private InventoryRead ReadCurrent(CancellationToken ct)
    {
        var result = ReadForSelectedOperation(ct);
        try { CheckFinalSource(result, ct); return result; }
        catch { result.Dispose(); throw; }
    }

    // Only this dedicated read path defers its source join to the outer result
    // fence. Mutation/recovery still use ReadCurrent's immediate join.
    private InventoryRead ReadForSelectedOperation(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireObjectDirectory();
        var exact = ReadBoundedFile(statePath, MaximumProtectedManifestBytes, manifest: true);
        byte[]? plain = null; Inventory? inventory = null;
        try
        {
            BeforeProvider(); Interlocked.Increment(ref unprotectCalls); plain = protector.Unprotect(exact);
            if (ReferenceEquals(plain, exact)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plain.Length);
            inventory = DecodeManifest(plain); ct.ThrowIfCancellationRequested();
            return new InventoryRead(exact, inventory);
        }
        catch (Exception error) when (error is ArgumentException or OverflowException or InvalidDataException)
        { inventory?.Dispose(); CryptographicOperations.ZeroMemory(exact); throw new CryptographicException("Protected manifest authentication or decoding failed.", error); }
        catch { inventory?.Dispose(); CryptographicOperations.ZeroMemory(exact); throw; }
        finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private Task<InventoryRead> AdmitAsync(CancellationToken ct, bool forceAudit = false) => AdmitReadAsync(ct, forceAudit);

    private async Task<InventoryRead> AdmitReadAsync(CancellationToken ct, bool forceAudit = false)
    {
        var current = DiscoverRecovery(ReadForSelectedOperation(ct), ct);
        try
        {
            if (forceAudit || auditRequired != 0) AuditInventory(current, ct);
            if (operation!.Recovery is not null || current.Inventory.Cleanup.Count != 0)
                return await CloseReadRecoveryAsync(current, ct).ConfigureAwait(false);
            return current;
        }
        catch { current.Dispose(); throw; }
    }

    private Task<InventoryRead> AdmitMutationAsync(CancellationToken ct)
    {
        var current = DiscoverRecovery(ReadCurrent(ct), ct);
        try
        {
            if (auditRequired != 0) AuditInventory(current, ct);
            return Task.FromResult(current);
        }
        catch { current.Dispose(); throw; }
    }

    private void AuditInventory(InventoryRead current, CancellationToken ct)
    {
        foreach (var item in current.Inventory.Values.Values)
        {
            ct.ThrowIfCancellationRequested(); var value = ReadObject(current.Inventory, item);
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private async Task CloseUnchangedMutationAsync(InventoryRead current, CancellationToken ct)
    {
        if (operation!.Recovery is not null || current.Inventory.Cleanup.Count != 0)
        {
            using var complete = await CloseReadRecoveryAsync(current, ct).ConfigureAwait(false);
            CheckFinalSource(complete, ct);
        }
        else CheckFinalSource(current, ct);
    }
    private void RequireExactSource(byte[] expectedHash)
    {
        var actual = ReadBoundedFile(statePath, MaximumProtectedManifestBytes, manifest: true);
        try { if (!Fixed(SHA256.HashData(actual), expectedHash)) throw new CryptographicException("Protected inventory changed during admission."); }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    private byte[] ProtectManifest(byte[] plaintext)
    {
        try
        {
            BeforeProvider(); Interlocked.Increment(ref protectCalls); var result = protector.Protect(plaintext);
            if (ReferenceEquals(result, plaintext) || result.Length is < 1 or > MaximumProtectedManifestBytes)
            { CryptographicOperations.ZeroMemory(result); throw new CryptographicException("Platform protection returned an invalid manifest."); }
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void ValidateSlot(string slot)
    {
        DeepSecureStorageRegistration.ValidateSlot(slot);
    }
    private static void ZeroValues(IReadOnlyDictionary<string, byte[]>? values)
    { if (values is not null) foreach (var value in values.Values) CryptographicOperations.ZeroMemory(value); }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed != 0, this);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        gate.Wait(); gate.Release(); (protector as IDisposable)?.Dispose();
    }
}
