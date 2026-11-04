using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private const ulong NativeWorkingSoftLimit = 63;
    // Scheduling only: no key, SQL handle, source permission or successful read
    // is retained. Actual registration/instance checks remain in every opener.
    private string? auditedNativeOwner;
    private string? recoveredNativePrefixScope;
    private bool nativeAdmissionInProgress;
    private int nativeRuntimeClosed;

    internal void CloseNativeRuntime()
    {
        Interlocked.Exchange(ref nativeRuntimeClosed, 1);
        auditedNativeOwner = null;
        recoveredNativePrefixScope = null;
    }

    private async Task<OwnedDid2MessagingStorage> OpenNativeMessagingUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref nativeRuntimeClosed) != 0, this);
        held.RequireOwner(lease);
        if (nativeAdmissionInProgress)
            return await SqliteDeepIdV2AccountGeneration.OpenEstablishedNativeArchiveAuditUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
        _ = await EnsureNativeArchiveAdmissionUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(
            storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
        opened.RecoveredLocalCompaction = string.Equals(recoveredNativePrefixScope, Convert.ToHexString(scope.Hash), StringComparison.Ordinal);
        return opened;
    }

    private async Task<bool> EnsureNativeArchiveAdmissionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope requested, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref nativeRuntimeClosed) != 0, this);
        held.RequireOwner(lease);
        if (nativeAdmissionInProgress) throw new InvalidOperationException("Native cold admission cannot reenter.");
        nativeAdmissionInProgress = true;
        try { return await AuditNativeArchivesUnderLeaseAsync(current, requested, held, ct).ConfigureAwait(false); }
        finally { nativeAdmissionInProgress = false; }
    }

    private async Task<bool> AuditNativeArchivesUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope requested, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var identity = Convert.ToHexString(current.AccountId.Span) + Convert.ToHexString(requested.Instance);
        // Recovery uses only the existing lower FULL openers; it cannot recurse
        // into this admission or mistake a valid intermediate prefix for damage.
        var recovered = await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        if (string.Equals(auditedNativeOwner, identity, StringComparison.Ordinal)) return recovered;
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            if (!Did2MessagingSessionScope.Fixed(instance, requested.Instance))
                throw new CryptographicException("Native admission belongs to another account instance.");
            Did2MessagingSessionScope[] scopes; byte[] catalogHash;
            var catalogOwner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            using (var catalog = await catalogOwner.ReadAsync(ct).ConfigureAwait(false))
            {
                scopes = Enumerable.Range(0, catalog.Count).Where(index => catalog.Phase(index) == 2).Select(catalog.Scope).ToArray();
                catalogHash = SHA256.HashData(catalog.Exact.Span);
            }
            foreach (var scope in scopes)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (await SqliteDeepIdV2AccountGeneration.IsInitialOwnedNativeAuditUnderLeaseAsync(
                    storage, sqlStatePath, current, scope, ct).ConfigureAwait(false)) continue;
                using var opened = await SqliteDeepIdV2AccountGeneration.OpenEstablishedNativeArchiveAuditUnderLeaseAsync(
                    storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                var actualSql = await opened.WithSqlAsync(sql => sql.VerifyTip(), ct).ConfigureAwait(false);
                if (!Did2MessagingSessionScope.Fixed(floor.Exact.Span, actualSql.Exact.Span))
                    throw new CryptographicException("Cold native archive audit lost its independent floor.");
                var archive = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
                _ = await VerifyArchiveSemanticsUnderLeaseAsync(opened, archive, held, ct).ConfigureAwait(false);
            }
            using var readback = await catalogOwner.ReadAsync(ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(catalogHash, SHA256.HashData(readback.Exact.Span)))
                throw new CryptographicException("Native catalog changed during cold archive admission.");
            var finalInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
                storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            try
            {
                if (!Did2MessagingSessionScope.Fixed(instance, finalInstance))
                    throw new CryptographicException("Native account instance changed during cold archive admission.");
            }
            finally { CryptographicOperations.ZeroMemory(finalInstance); }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            ObjectDisposedException.ThrowIf(Volatile.Read(ref nativeRuntimeClosed) != 0, this);
            auditedNativeOwner = identity; Did2MessagingSqlJournal.NativeWork.Audit();
            return recovered;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private async Task<OwnedDid2MessagingStorage?> PrepareNativeMaintenanceForTransitionAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, OwnedDid2MessagingStorage opened,
        Did2MessagingFloor floor, HeldDeepIdV2AccountLease held, byte[] operation, byte[] exact, bool send,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, Deep.Protocol.DeepExtension.PrivacyRouting.OnionMonotonicReading first,
        CancellationToken ct)
    {
        if (opened.RecoveredLocalCompaction || string.Equals(recoveredNativePrefixScope, Convert.ToHexString(scope.Hash), StringComparison.Ordinal))
        {
            recoveredNativePrefixScope = null;
            return null; // Source/current-account recovery may have finished this exact batch before this opener.
        }
        var archive = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        if (floor.Ordinal < archive.Basis.Ordinal) throw new CryptographicException("Native maintenance hint rolled back its floor.");
        if (floor.Status != 1 || floor.Phase != 1 || floor.Ordinal - archive.Basis.Ordinal < NativeWorkingSoftLimit) return null;
        // Pure preparation has no authority/commit callback. Authenticate a
        // threshold-hit fresh input before staging maintenance, including bad
        // receive MACs. Drop ALL preview keys/outputs before the first await.
        var preview = await opened.WithSqlAsync(sql =>
        {
            var state = sql.ReadFreshMaintenancePreviewState(floor, operation, out var context);
            return (State: state, Context: context);
        }, ct).ConfigureAwait(false);
        using (var state = preview.State)
        {
            var context = preview.Context;
            if (send)
            {
                using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareSend(bytes, context, exact, scope.Network, operation));
            }
            else
            {
                using var prepared = state.Use(bytes => ExactDpe2DurableTransactionProducer.PrepareReceive(bytes, context, exact));
            }
        }
        opened.Dispose();
        await MaintainNativePrefixUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        recoveredNativePrefixScope = null; // This transition already paid its newly staged batch.
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        // Reopen actual registration/key/source/floor/history AFTER maintenance
        // and authority callbacks. Preview context/state is never reused.
        return await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
    }

    // Called once per ordinary authoring/encryption entry, BEFORE taking its
    // live SQL/ratchet loan. At most one existing bounded batch is staged; old
    // retained suffixes catch up gradually. A count is never deletion authority.
    private async Task MaintainNativePrefixUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        await EnsureNativeArchiveAdmissionUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
        if (floor.Phase != 1)
        {
            using var recovery = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
            floor = await recovery.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        }
        var archive = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        if (floor.Ordinal < archive.Basis.Ordinal) throw new CryptographicException("Native working suffix precedes its protected archive.");
        var working = floor.Ordinal - archive.Basis.Ordinal;
        Did2MessagingSqlJournal.NativeWork.Inventory(working, archive.ArchiveCount);
        if (floor.Status != 1 || working < NativeWorkingSoftLimit) return;
        using var selected = await PreparePrefixUnderLeaseAsync(current, scope, Did2CompactionPlan.MaximumRows, held, ct).ConfigureAwait(false);
        var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, scope.Instance);
        using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
        if (idle.Phase != 0) throw new InvalidOperationException("Existing native plan owns recovery.");
        await plans.StageAsync(idle, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        var after = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        Did2MessagingSqlJournal.NativeWork.Inventory(floor.Ordinal - after.Basis.Ordinal, after.ArchiveCount);
        // The caller opens a NEW journal after this method returns. No object
        // with the old captured history root is reused after root adoption.
    }
}
