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
            ThrowIfDisposed(); using var process = await AcquireProcessLeaseAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitAsync(cancellationToken).ConfigureAwait(false);
            if (!current.Inventory.Values.TryGetValue(slot, out var descriptor)) return null;
            var value = ReadObject(current.Inventory, descriptor);
            try { cancellationToken.ThrowIfCancellationRequested(); RequireExactSource(current.Hash); return new OwnedDeepSecret(value); }
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
            ThrowIfDisposed(); using var process = await AcquireProcessLeaseAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitAsync(cancellationToken).ConfigureAwait(false);
            foreach (var slot in captured)
                if (current.Inventory.Values.TryGetValue(slot, out var item)) values.Add(slot, ReadObject(current.Inventory, item));
            cancellationToken.ThrowIfCancellationRequested(); RequireExactSource(current.Hash);
            return OwnedDeepSecretBatch.CopyFrom(captured, values);
        }
        finally { ZeroValues(values); gate.Release(); }
    }

    public async Task AuditAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed(); using var process = await AcquireProcessLeaseAsync(cancellationToken).ConfigureAwait(false);
            using var current = await AdmitAsync(cancellationToken, forceAudit: true).ConfigureAwait(false);
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
            ThrowIfDisposed(); using var process = await AcquireProcessLeaseAsync(ct).ConfigureAwait(false);
            using var current = await AdmitAsync(ct).ConfigureAwait(false);
            Guard? guard = null;
            if (slot is not null)
            {
                if (!current.Inventory.Values.TryGetValue(slot, out var descriptor)) return false;
                var value = ReadObject(current.Inventory, descriptor);
                try { if (!Fixed(value, expected!)) return false; }
                finally { CryptographicOperations.ZeroMemory(value); }
                guard = new(slot, expected!);
            }
            if (writes is not null && writes.Keys.Any(name => name != slot && current.Inventory.Values.ContainsKey(name)))
            {
                if (kind == MutationKind.Insert) throw new InvalidOperationException("Secure-storage slot already exists.");
                return false;
            }
            var remove = kind switch
            {
                MutationKind.PurgeV1 => current.Inventory.Values.Keys.Where(name => name.StartsWith("deep.store.v1.", StringComparison.Ordinal)).ToArray(),
                MutationKind.PurgeV2 => current.Inventory.Values.Keys.Where(name => name.StartsWith("deep.store.v2.", StringComparison.Ordinal)).ToArray(),
                _ => deletions
            };
            if ((writes is null || writes.Count == 0) && !remove.Any(current.Inventory.Values.ContainsKey)) return true;
            var lengths = current.Inventory.Values.ToDictionary(p => p.Key, p => p.Value.Length, StringComparer.Ordinal);
            foreach (var name in remove) lengths.Remove(name);
            if (writes is not null) foreach (var item in writes) lengths[item.Key] = item.Value.Length;
            DeepSecureStorageRegistration.ValidateInventoryLengths(lengths);
            var candidate = current.Inventory.Successor(current.Hash);
            var objects = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                foreach (var name in remove)
                    if (candidate.Values.Remove(name, out var old)) { candidate.Cleanup.Add(old.Name); old.Dispose(); }
                if (writes is not null) foreach (var item in writes)
                {
                    if (candidate.Values.Remove(item.Key, out var old)) { candidate.Cleanup.Add(old.Name); old.Dispose(); }
                    var (descriptor, file) = EncryptObject(candidate, item.Key, item.Value);
                    candidate.Values.Add(item.Key, descriptor); objects.Add(descriptor.Name, file);
                }
                await PublishAsync(current, candidate, objects, guard, RootKind.Current, ct).ConfigureAwait(false);
                using var complete = await AdmitAsync(ct).ConfigureAwait(false); // Includes durable retirement and cleanup-free metadata adoption.
                return true;
            }
            finally { candidate.Dispose(); ZeroValues(objects); }
        }
        finally { gate.Release(); }
    }

    private InventoryRead ReadCurrent(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); RequireObjectDirectory();
        var exact = ReadBoundedFile(statePath, MaximumProtectedManifestBytes, manifest: true);
        byte[]? plain = null; Inventory? inventory = null;
        try
        {
            Interlocked.Increment(ref unprotectCalls); plain = protector.Unprotect(exact);
            if (ReferenceEquals(plain, exact)) throw new CryptographicException("Protector did not return owned plaintext.");
            Interlocked.Add(ref manifestPlaintext, plain.Length);
            inventory = DecodeManifest(plain); ct.ThrowIfCancellationRequested();
            var result = new InventoryRead(exact, inventory);
            try { RequireExactSource(result.Hash); return result; }
            catch { result.Dispose(); throw; }
        }
        catch (Exception error) when (error is ArgumentException or OverflowException or InvalidDataException)
        { inventory?.Dispose(); CryptographicOperations.ZeroMemory(exact); throw new CryptographicException("Protected manifest authentication or decoding failed.", error); }
        catch { inventory?.Dispose(); CryptographicOperations.ZeroMemory(exact); throw; }
        finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private async Task<InventoryRead> AdmitAsync(CancellationToken ct, bool forceAudit = false)
    {
        for (var pass = 0; pass < 5; pass++)
        {
            var current = ReadCurrent(ct);
            try
            {
                if (File.Exists(pendingPath))
                { current.Dispose(); await RecoverPendingAsync(ct).ConfigureAwait(false); continue; }
                if (File.Exists(backupPath))
                {
                    var authority = new ReplacementAuthority(current.Hash.ToArray(), RootKind.Current, null);
                    current.Dispose(); await RetirePathAsync(backupPath, authority, null, ct, manifest: true).ConfigureAwait(false); continue;
                }
                if (current.Inventory.Cleanup.Count != 0)
                { await CompleteCleanupAsync(current, ct).ConfigureAwait(false); continue; }
                if (forceAudit || auditRequired != 0)
                {
                    foreach (var item in current.Inventory.Values.Values)
                    {
                        ct.ThrowIfCancellationRequested(); var value = ReadObject(current.Inventory, item);
                        CryptographicOperations.ZeroMemory(value);
                    }
                    ct.ThrowIfCancellationRequested(); RequireExactSource(current.Hash); auditRequired = 0;
                }
                return current;
            }
            catch { current.Dispose(); throw; }
        }
        throw new CryptographicException("Protected inventory recovery did not converge.");
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
            Interlocked.Increment(ref protectCalls); var result = protector.Protect(plaintext);
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
