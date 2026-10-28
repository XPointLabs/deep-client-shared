using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence;

public sealed partial class JournaledDeepSecureStorage
{
    private sealed class RecoveryPlan(string[] staged, byte[]? pendingHash, byte[]? backupHash)
    {
        internal string[] Staged { get; } = staged;
        internal byte[]? PendingHash { get; } = pendingHash;
        internal byte[]? BackupHash { get; } = backupHash;
        internal bool PendingWitness = pendingHash is not null, BackupWitness = backupHash is not null;
    }

    private sealed class PreparedRoot(byte[] bytes, InventoryFact facts) : IDisposable
    {
        internal byte[] Bytes { get; } = bytes;
        internal byte[] Hash => Facts.Hash;
        internal InventoryFact Facts { get; } = facts;
        public void Dispose() => CryptographicOperations.ZeroMemory(Bytes);
    }

    private PreparedRoot PrepareRoot(Inventory candidate, CancellationToken ct, out Inventory authenticated)
    {
        byte[] plaintext;
        try { plaintext = EncodeManifest(candidate); }
        finally { candidate.Dispose(); }
        byte[] plaintextHash, bytes;
        try { plaintextHash = SHA256.HashData(plaintext); bytes = ProtectManifest(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        byte[]? decoded = null; Inventory? verified = null;
        try
        {
            BeforeProvider(); Interlocked.Increment(ref unprotectCalls); decoded = protector.Unprotect(bytes);
            if (ReferenceEquals(decoded, bytes) || !Fixed(SHA256.HashData(decoded), plaintextHash))
                throw new CryptographicException("Prepared inventory differs from the intended successor.");
            Interlocked.Add(ref manifestPlaintext, decoded.Length);
            verified = DecodeManifest(decoded);
            ct.ThrowIfCancellationRequested();
            var facts = Facts(verified, SHA256.HashData(bytes));
            var result = new PreparedRoot(bytes, facts);
            // Transfer the decoded inventory, not an admitted permission. The
            // caller must destroy it before the next provider edge.
            authenticated = verified; verified = null;
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        finally { verified?.Dispose(); if (decoded is not null) CryptographicOperations.ZeroMemory(decoded); }
    }

    private static Inventory CopyInventory(Inventory source)
    {
        var result = new Inventory(source.StoreId.ToArray(), source.Revision, source.Predecessor.ToArray());
        try
        {
            foreach (var item in source.Values) result.Values.Add(item.Key, item.Value.Copy());
            result.Cleanup.UnionWith(source.Cleanup); return result;
        }
        catch { result.Dispose(); throw; }
    }

    private InventoryRead DiscoverRecovery(InventoryRead current, CancellationToken ct)
    {
        byte[]? pendingHash = null; string[] staged = [];
        try
        {
            if (File.Exists(pendingPath))
            {
                var facts = Facts(current);
                var bytes = ReadBoundedFile(pendingPath, MaximumProtectedManifestBytes, manifest: true, allowEmpty: true);
                byte[]? plaintext = null;
                try
                {
                    pendingHash = SHA256.HashData(bytes);
                    if (bytes.Length != 0)
                    {
                        current.Dispose();
                        BeforeProvider(); Interlocked.Increment(ref unprotectCalls); plaintext = protector.Unprotect(bytes);
                        if (ReferenceEquals(plaintext, bytes)) throw new CryptographicException("Protector did not return owned plaintext.");
                        Interlocked.Add(ref manifestPlaintext, plaintext.Length);
                        using (var pending = DecodeManifest(plaintext)) staged = ValidatePendingSuccessor(facts, pending);
                        CryptographicOperations.ZeroMemory(plaintext); plaintext = null;
                        current = ReadCurrent(ct);
                        if (!Fixed(current.Hash, facts.Hash)) throw new CryptographicException("Protected predecessor changed during recovery admission.");
                    }
                }
                finally { CryptographicOperations.ZeroMemory(bytes); if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
            }
            byte[]? backupHash = null;
            if (File.Exists(backupPath))
            {
                var backup = ReadBoundedFile(backupPath, MaximumPlaintextBytes * 2, manifest: true, allowEmpty: true);
                try { backupHash = SHA256.HashData(backup); }
                finally { CryptographicOperations.ZeroMemory(backup); }
            }
            operation!.Recovery = pendingHash is null && backupHash is null ? null : new RecoveryPlan(staged, pendingHash, backupHash);
            operation.ReservedNames.UnionWith(current.Inventory.Cleanup);
            operation.ReservedNames.UnionWith(staged);
            JoinRecoveryWitness(); return current;
        }
        catch { current.Dispose(); throw; }
    }

    private void JoinRecoveryWitness()
    {
        if (operation?.Recovery is not { } plan) return;
        if (plan.PendingWitness) RequireExactFile(pendingPath, plan.PendingHash!, MaximumProtectedManifestBytes, manifest: true, allowEmpty: true);
        if (plan.BackupWitness) RequireExactFile(backupPath, plan.BackupHash!, MaximumPlaintextBytes * 2, manifest: true, allowEmpty: true);
    }

    private async Task RetireRecoveryAsync(ReplacementAuthority authority, CancellationToken ct)
    {
        if (operation!.Recovery is not { } plan) return;
        JoinRecoveryWitness();
        foreach (var name in plan.Staged)
        {
            await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false).ConfigureAwait(false);
            await RetirePathAsync(ObjectPath(name, ".pending"), authority, name, ct, manifest: false).ConfigureAwait(false);
        }
        // The authenticated descriptor remains until all names it authorizes
        // are retired. Once it is removed, no external edge can restore them.
        JoinRecoveryWitness(); operation.NoExternal = true;
        if (plan.BackupWitness)
        {
            plan.BackupWitness = false;
            await RetirePathAsync(backupPath, authority, null, ct, manifest: true).ConfigureAwait(false);
        }
        if (plan.PendingWitness)
        {
            plan.PendingWitness = false;
            await RetirePathAsync(pendingPath, authority, null, ct, manifest: true).ConfigureAwait(false);
        }
    }

    private void UsePreparedRoot(PreparedRoot root)
    {
        var owned = operation!;
        owned.Admission?.Dispose(); owned.Admission = null;
        owned.ClosedFacts = root.Facts; owned.Authority = new(root.Hash, RootKind.Current, null);
    }

    private async Task AdoptPreparedAsync(PreparedRoot root, ReplacementAuthority authority, ObjectFact[] objects,
        CancellationToken ct, bool primary)
    {
        Revalidate(authority, ct);
        if (File.Exists(pendingPath)) RequireExactFile(pendingPath, root.Hash, MaximumProtectedManifestBytes, manifest: true);
        else { WriteBoundedFile(pendingPath, root.Bytes, manifest: true); FlushParent(pendingPath); }
        if (primary) Hit(JournaledDeepSecureStorageFailpoint.AfterPendingManifest);
        if (primary) Hit(JournaledDeepSecureStorageFailpoint.BeforeManifestReplace);
        else Hit(JournaledDeepSecureStorageFailpoint.BeforeCleanupManifest);
        await ReplaceDurablyAsync(pendingPath, statePath, authority, ct, replace: true,
            pendingHash: root.Hash, newObjects: objects).ConfigureAwait(false);
        UsePreparedRoot(root);
        if (primary) Hit(JournaledDeepSecureStorageFailpoint.AfterManifestReplace);
        RequireExactFile(statePath, root.Hash, MaximumProtectedManifestBytes, manifest: true);
    }

    private async Task<InventoryRead> CloseReadRecoveryAsync(InventoryRead current, CancellationToken ct)
    {
        var hash = current.Hash.ToArray(); PreparedRoot? clean = null;
        try
        {
            if (current.Inventory.Cleanup.Count != 0)
            {
                var candidate = current.Inventory.Successor(hash); candidate.Cleanup.Clear(); current.Dispose();
                clean = PrepareRoot(candidate, ct, out var verified); verified.Dispose();
            }
            else current.Dispose();
            var authority = new ReplacementAuthority(hash, RootKind.Current, null);
            while (true)
            {
                Revalidate(authority, ct); var owned = operation!;
                AuditInventory(owned.Admission!, ct);
                // Build the result from the final fresh actual admission. No
                // key-bearing result survives any provider/retry edge.
                Inventory? resultInventory = clean is null ? CopyInventory(owned.Admission!.Inventory) : owned.Admission!.Inventory.Successor(hash);
                if (clean is not null) resultInventory.Cleanup.Clear();
                owned.ResultLoan = resultInventory;
                owned.FinalCleanup = true;
                try
                {
                    await RetireRecoveryAsync(authority, ct).ConfigureAwait(false);
                    foreach (var name in owned.Admission!.Inventory.Cleanup.ToArray())
                        await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false).ConfigureAwait(false);
                    if (clean is not null) await AdoptPreparedAsync(clean, authority, [], ct, primary: false).ConfigureAwait(false);
                    var exact = clean?.Bytes.ToArray() ?? owned.Admission!.Exact.ToArray();
                    RequireExactFile(statePath, clean?.Hash ?? hash, MaximumProtectedManifestBytes, manifest: true);
                    ct.ThrowIfCancellationRequested(); owned.FinalClosed = true;
                    Hit(JournaledDeepSecureStorageFailpoint.AfterCleanupManifest);
                    var result = new InventoryRead(exact, resultInventory); resultInventory = null; owned.ResultLoan = null; return result;
                }
                catch (CleanupRestartException) { _ = owned.RemainingRetry(); }
                finally { owned.FinalCleanup = false; resultInventory?.Dispose(); owned.ResultLoan = null; }
            }
        }
        finally { clean?.Dispose(); }
    }

    private async Task PublishMutationAsync(InventoryRead current, IReadOnlyDictionary<string, byte[]>? writes, string[] remove,
        Guard? guard, CancellationToken ct)
    {
        var predecessor = current.Hash.ToArray(); var oldNames = current.Inventory.Cleanup.ToArray();
        var retired = remove.Concat(writes?.Keys ?? []).Distinct(StringComparer.Ordinal)
            .Where(current.Inventory.Values.ContainsKey).Select(name => current.Inventory.Values[name].Name).ToArray();
        var overflow = oldNames.Length + retired.Length > MaximumEntries;
        PreparedRoot? intermediate = null, primary = null, final = null;
        Inventory? candidate = null; var objects = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            if (overflow)
            {
                var cleared = current.Inventory.Successor(predecessor); cleared.Cleanup.Clear(); current.Dispose();
                intermediate = PrepareRoot(cleared, ct, out var decoded);
                try { candidate = decoded.Successor(intermediate.Hash); }
                finally { decoded.Dispose(); }
            }
            else { candidate = current.Inventory.Successor(predecessor); current.Dispose(); }
            foreach (var name in remove)
                if (candidate.Values.Remove(name, out var old)) { candidate.Cleanup.Add(old.Name); old.Dispose(); }
            if (writes is not null) foreach (var item in writes)
            {
                if (candidate.Values.Remove(item.Key, out var old)) { candidate.Cleanup.Add(old.Name); old.Dispose(); }
                var encrypted = EncryptObject(candidate, item.Key, item.Value);
                candidate.Values.Add(item.Key, encrypted.Descriptor); objects.Add(encrypted.Descriptor.Name, encrypted.File);
            }
            primary = PrepareRoot(candidate, ct, out var primaryInventory); candidate = null;
            try
            {
                if (primaryInventory.Cleanup.Count != 0)
                {
                    var cleared = primaryInventory.Successor(primary.Hash); cleared.Cleanup.Clear(); primaryInventory.Dispose();
                    final = PrepareRoot(cleared, ct, out var decoded); decoded.Dispose();
                }
            }
            finally { primaryInventory.Dispose(); }
            var objectFacts = objects.Keys.Select(name => primary.Facts.Values.Values.Single(item => item.Name == name))
                .Select(item => new ObjectFact(item.Name, checked(item.Length + ObjectOverheadBytes), item.Hash)).ToArray();
            var authority = new ReplacementAuthority(predecessor, RootKind.Current, guard);
            while (true)
            {
                Revalidate(authority, ct); var owned = operation!;
                if (auditRequired != 0) AuditInventory(owned.Admission!, ct);
                owned.FinalCleanup = true;
                try
                {
                    await RetireRecoveryAsync(authority, ct).ConfigureAwait(false);
                    if (intermediate is not null)
                    {
                        foreach (var name in oldNames)
                            await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false).ConfigureAwait(false);
                        await AdoptPreparedAsync(intermediate, authority, [], ct, primary: false).ConfigureAwait(false);
                        owned.NoExternal = true; authority = new(intermediate.Hash, RootKind.Current, guard);
                        owned.Authority = authority;
                    }
                    break;
                }
                catch (CleanupRestartException) { _ = owned.RemainingRetry(); }
                finally { owned.FinalCleanup = false; }
            }
            await PublishPreparedPrimaryAsync(primary, objects, objectFacts, authority, ct).ConfigureAwait(false);
            await FinishPreparedMutationCleanupAsync(primary, final, objectFacts, ct).ConfigureAwait(false);
        }
        finally { candidate?.Dispose(); current.Dispose(); intermediate?.Dispose(); primary?.Dispose(); final?.Dispose(); ZeroValues(objects); }
    }
    private async Task PublishPreparedPrimaryAsync(PreparedRoot primary, IReadOnlyDictionary<string, byte[]> objects,
        ObjectFact[] facts, ReplacementAuthority authority, CancellationToken ct)
    {
        Revalidate(authority, ct);
        if (File.Exists(pendingPath)) throw new CryptographicException("An unresolved protected pending inventory already exists.");
        WriteBoundedFile(pendingPath, primary.Bytes, manifest: true); FlushParent(pendingPath);
        Hit(JournaledDeepSecureStorageFailpoint.AfterPendingManifest);
        foreach (var item in objects)
        {
            Revalidate(authority, ct); RequireExactFile(pendingPath, primary.Hash, MaximumProtectedManifestBytes, manifest: true);
            WriteBoundedFile(ObjectPath(item.Key, ".pending"), item.Value, manifest: false);
            await ReplaceDurablyAsync(ObjectPath(item.Key, ".pending"), ObjectPath(item.Key), authority, ct, replace: false,
                pendingHash: primary.Hash, stagedObject: facts.Single(fact => fact.Name == item.Key)).ConfigureAwait(false);
            Hit(JournaledDeepSecureStorageFailpoint.AfterObjectStaged);
        }
        Hit(JournaledDeepSecureStorageFailpoint.BeforeManifestReplace);
        await ReplaceDurablyAsync(pendingPath, statePath, authority, ct, replace: true,
            pendingHash: primary.Hash, newObjects: facts).ConfigureAwait(false);
        UsePreparedRoot(primary);
        Hit(JournaledDeepSecureStorageFailpoint.AfterManifestReplace);
    }
    private async Task FinishPreparedMutationCleanupAsync(PreparedRoot primary, PreparedRoot? final, ObjectFact[] objects, CancellationToken ct)
    {
        var owned = operation!;
        if (final is not null)
        {
            var authority = new ReplacementAuthority(primary.Hash, RootKind.Current, null);
            while (true)
            {
                Revalidate(authority, ct); owned.FinalCleanup = true;
                try
                {
                    foreach (var name in primary.Facts.Cleanup.Order(StringComparer.Ordinal))
                        await RetirePathAsync(ObjectPath(name), authority, name, ct, manifest: false).ConfigureAwait(false);
                    await AdoptPreparedAsync(final, authority, [], ct, primary: false).ConfigureAwait(false);
                    break;
                }
                catch (CleanupRestartException) { _ = owned.RemainingRetry(); }
                finally { owned.FinalCleanup = false; }
            }
        }
        if (final is null) Revalidate(new(primary.Hash, RootKind.Current, null), ct);
        foreach (var item in objects) RequireExactFile(ObjectPath(item.Name), item.Hash, item.FileLength, manifest: false, exactLength: item.FileLength);
        RequireExactFile(statePath, final?.Hash ?? primary.Hash, MaximumProtectedManifestBytes, manifest: true);
        ct.ThrowIfCancellationRequested(); owned.FinalClosed = true;
        if (final is not null) Hit(JournaledDeepSecureStorageFailpoint.AfterCleanupManifest);
    }
}
