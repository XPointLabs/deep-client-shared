using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Actual held read-only selection. The result is exact metadata, not a
    // durable or transferable deletion authority. No supplied roots/digests,
    // SQL path, terminal flag, clock replacement or mutation callback is used.
    internal async Task<Did2CompactionPlan.Preparation> PrepareOwnedMessagingPrefixCompactionAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, int prefixRows, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(requestedScope);
        if (prefixRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(prefixRows));
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var borrowed = held.BorrowFor(lease);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        return await PreparePrefixUnderLeaseAsync(current, scope, prefixRows, held, ct).ConfigureAwait(false);
    }
    private async Task<Did2CompactionPlan.Preparation> PreparePrefixUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, int prefixRows,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        if (archiveEnrollmentInProgress) return await PrepareOldEnrollmentPrefixUnderLeaseAsync(current, scope, prefixRows, held, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, instance);
            using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (idle.Phase != 0) throw new InvalidOperationException("An active compaction plan owns recovery; no new selection is permitted.");
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct, configureRouteHistory: configured => ConfigureRouteHistoryDecisionRecovery(configured, held)).ConfigureAwait(false);
            var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            byte[] catalogHash, registrationHash, peerHash;
            Did2MessagingHistoryCheckpoint history;
            Did2MessagingArchiveRoot archive;
            using (var inventory = await storage.ReadOwnedBatchAsync(PrefixRootSlots(scope), ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var sessions = (inventory[0] ?? throw new InvalidDataException("Compaction catalog is absent.")).Use(bytes =>
                    ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                var index = sessions.FindExact(scope);
                if (index < 0 || sessions.Phase(index) != 2 || !sessions.AllIndexed)
                    throw new InvalidDataException("Compaction requires the initialized indexed owned catalog.");
                catalogHash = SHA256.HashData(sessions.Exact.Span);
                var floor = (inventory[1] ?? throw new InvalidDataException("Compaction floor is absent.")).Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
                if (!Did2MessagingSessionScope.Fixed(floor.Exact.Span, stable.Exact.Span)) throw new CryptographicException("Compaction floor changed during selection.");
                var registration = inventory[2] ?? throw new InvalidDataException("Compaction registration is absent.");
                var registeredInstance = registration.Use(bytes => SqliteDeepIdV2AccountGeneration.ReadAccountInstanceFromRegistration(bytes, scope.Network, scope.LocalAccount));
                try { if (!Did2MessagingSessionScope.Fixed(registeredInstance, scope.Instance)) throw new CryptographicException("Compaction registration changed."); }
                finally { CryptographicOperations.ZeroMemory(registeredInstance); }
                registrationHash = registration.Use(bytes => SHA256.HashData(bytes));
                history = (inventory[3] ?? throw new InvalidDataException("Compaction history is absent.")).Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
                var peer = inventory[4] ?? throw new InvalidDataException("Compaction cannot orphan the registered peer bootstrap.");
                _ = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope)); peerHash = peer.Use(bytes => SHA256.HashData(bytes));
                archive = (inventory[5] ?? throw new InvalidDataException("Compaction archive root is absent.")).Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
                archive.RequireSource(history);
            }
            var effects = await CaptureArchivePrefixEffectsAsync(opened, stable, prefixRows, held, ct).ConfigureAwait(false);
            var roots = new Did2CompactionPlan.Root[]
            {
                Guard(Did2CompactionPlan.RootKind.SessionCatalog, ProtectedDid2MessagingSessionCatalog.Slot, catalogHash),
                Guard(Did2CompactionPlan.RootKind.MessagingFloor, scope.FloorSlot, SHA256.HashData(stable.Exact.Span)),
                Guard(Did2CompactionPlan.RootKind.AccountRegistration, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, registrationHash),
                Guard(Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, Did2MessagingHistoryCheckpoint.Slot(scope), SHA256.HashData(history.Exact.Span)),
                Guard(Did2CompactionPlan.RootKind.MessagingPeerBootstrap, ProtectedDid2MessagingPeerBootstrap.Slot(scope), peerHash),
                new(Did2CompactionPlan.RootKind.MessagingArchive, CompactionSlotSelector(Did2MessagingArchiveRoot.Slot(scope)),
                    SHA256.HashData(archive.Exact.Span), SHA256.HashData(effects.Successor.Exact.Span), false, effects.Successor.Exact)
            };
            var preparation = idle.Prepare(Did2CompactionPlan.SqlTarget.Messaging, RandomNumberGenerator.GetBytes(32),
                scope.Hash, effects.Before.Span, effects.After.Span, roots, effects.Rows);
            try { ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return preparation; }
            catch { preparation.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    private async Task<Did2CompactionPlan.Preparation> PrepareOldEnrollmentPrefixUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, int prefixRows,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (!archiveEnrollmentInProgress) throw new InvalidOperationException("Old prefix selection requires explicit enrollment.");
        var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, scope.Instance, oldEnrollment: true);
        using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
        if (idle.Phase != 0) throw new InvalidOperationException("An existing old plan owns recovery.");
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenArchiveEnrollmentMessagingUnderLeaseAsync(storage, sqlStatePath, networkId, current.AccountId, scope, ct).ConfigureAwait(false);
        var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        byte[] catalogHash, registrationHash, peerHash;
        Did2MessagingHistoryCheckpoint history;
        using (var inventory = await storage.ReadOwnedBatchAsync(PrefixRootSlots(scope, oldEnrollment: true), ct).ConfigureAwait(false))
        {
            using var catalog = inventory[0]!.Use(bytes => ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var selected = catalog.FindExact(scope);
            if (catalog.Version != 1 || selected < 0 || catalog.Phase(selected) != 2) throw new InvalidDataException("Old prefix requires the actual initialized V1 catalog entry.");
            catalogHash = SHA256.HashData(catalog.Exact.Span);
            var floor = inventory[1]!.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
            if (!Did2MessagingSessionScope.Fixed(floor.Exact.Span, stable.Exact.Span)) throw new CryptographicException("Old prefix floor changed before selection.");
            var registration = inventory[2] ?? throw new InvalidDataException("Old prefix registration is absent.");
            var instance = registration.Use(bytes => SqliteDeepIdV2AccountGeneration.ReadAccountInstanceFromRegistration(bytes, scope.Network, scope.LocalAccount));
            try { if (!Did2MessagingSessionScope.Fixed(instance, scope.Instance)) throw new CryptographicException("Old prefix account instance differs."); }
            finally { CryptographicOperations.ZeroMemory(instance); }
            registrationHash = registration.Use(bytes => SHA256.HashData(bytes));
            history = inventory[3]!.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
            var peer = inventory[4] ?? throw new InvalidDataException("Old prefix bootstrap is absent.");
            _ = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope)); peerHash = peer.Use(bytes => SHA256.HashData(bytes));
        }
        var effects = await opened.WithSqlAsync(sql => sql.CaptureHistoryPrefixEffects(stable, prefixRows), ct).ConfigureAwait(false);
        Did2CompactionPlan.Root[] roots =
        [Guard(Did2CompactionPlan.RootKind.SessionCatalog, ProtectedDid2MessagingSessionCatalog.Slot, catalogHash),
            Guard(Did2CompactionPlan.RootKind.MessagingFloor, scope.FloorSlot, SHA256.HashData(stable.Exact.Span)),
            Guard(Did2CompactionPlan.RootKind.AccountRegistration, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, registrationHash),
            new(Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, CompactionSlotSelector(Did2MessagingHistoryCheckpoint.Slot(scope)),
                SHA256.HashData(history.Exact.Span), SHA256.HashData(effects.Successor.Exact.Span), false, effects.Successor.Exact),
            Guard(Did2CompactionPlan.RootKind.MessagingPeerBootstrap, ProtectedDid2MessagingPeerBootstrap.Slot(scope), peerHash)];
        return idle.Prepare(Did2CompactionPlan.SqlTarget.Messaging, RandomNumberGenerator.GetBytes(32), scope.Hash,
            effects.Before.Span, effects.After.Span, roots, effects.Rows);
    }

    internal async Task CompactOwnedMessagingPrefixAsync(ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, int prefixRows, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(requestedScope);
        if (prefixRows is < 1 or > Did2CompactionPlan.MaximumRows) throw new ArgumentOutOfRangeException(nameof(prefixRows));
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var registered = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, registered.Account, registered.Instance);
            using var prior = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (prior.Phase != 0)
            {
                if (!Did2MessagingSessionScope.Fixed(prior.SqlSelector, scope.Hash)) throw new CryptographicException("Another stored batch owns local recovery.");
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false); return; // Never reselect in the same retry.
            }
            using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
            using var selected = await PreparePrefixUnderLeaseAsync(current, scope, prefixRows, held, ct).ConfigureAwait(false);
            await plans.StageAsync(prior, selected, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(registered.Account); CryptographicOperations.ZeroMemory(registered.Instance); }
    }

    // Completing an already-owned local transaction needs no new network/time
    // proof, signature or encryption. It grants no fresh account/network authority.
    internal async Task ResumeOwnedLocalCompactionAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
    }

    internal async Task AbandonUncommittedOwnedPrefixAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (plan.Phase != 1) throw new InvalidOperationException("Only an unchanged prepared prefix can be abandoned.");
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, owner.Account, owner.Instance).ReadAsync(ct).ConfigureAwait(false);
            var scope = ResolvePrefixScope(plan, catalog);
            catalog.Dispose();
            var successor = await ReadStoredArchiveSuccessorAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
            if ((await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false)).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Committed or changed SQL cannot be abandoned.");
            using var abandoning = plan.WithAbandoningBeforeSql();
            await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }

    private async Task<bool> ResumeLocalCompactionUnderLeaseAsync(HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var recovered = false;
        string? recoveredPrefix = null;
        Did2CompactionPlan? completedPrefix = null;
        Did2MessagingSessionScope? completedScope = null;
        Did2MessagingArchiveRoot? completedSuccessor = null;
        using var borrowed = held.BorrowFor(lease);
        using (var registration = await storage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ct).ConfigureAwait(false))
            if (registration is null)
            {
                using var orphan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot, ct).ConfigureAwait(false);
                using var pointer = await storage.ReadOwnedAsync(CurrentAccountSlot, ct).ConfigureAwait(false);
                if (orphan is not null || pointer is not null) throw new InvalidDataException("An existing account/plan lost its local registration.");
                return false; // No registered account yet, not a missing-plan initializer.
            }
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance, archiveEnrollmentInProgress);
            for (var iteration = 0; iteration < 8; iteration++)
            {
                if (iteration == 0) await ResumeInitialCancellationKeysUnderLeaseAsync(owner.Account, owner.Instance, held, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (plan.Phase == 0)
                {
                    await RequireNoPrefixPartsAsync(ct).ConfigureAwait(false);
                    if (completedPrefix is not null && completedScope is not null)
                    {
                        var finishedPlan = completedPrefix; var finishedScope = completedScope;
                        if (archiveEnrollmentInProgress)
                            await WithStoredPrefixSqlAsync(finishedPlan, finishedScope, held, (sql, floor, roots) =>
                            {
                                if (finishedPlan.Phase == 2) sql.VerifyCompletePrefixSuccessor(floor, finishedPlan);
                                else if (!Did2MessagingSessionScope.Fixed(sql.VerifyTip().Exact.Span, floor.Exact.Span))
                                    throw new CryptographicException("Completed old prefix floor changed after cleanup.");
                                if (finishedPlan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
                                    throw new CryptographicException("Completed old prefix dependencies changed after cleanup.");
                                return 0;
                            }, ct, expectedStoredPlan: plan).ConfigureAwait(false);
                        else
                        {
                            var finalSuccessor = completedSuccessor ?? throw new InvalidDataException("Completed archive prefix lost its in-memory successor.");
                            await WithQualifiedPrefixSqlAsync(finishedPlan, finishedScope, finalSuccessor, held,
                                (sql, floor, roots, authored) =>
                                {
                                    if (finishedPlan.ObserveReadback(sql.ReadArchivePrefixProjection(floor, finishedPlan, finalSuccessor, authored), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
                                        throw new CryptographicException("Completed archive prefix dependencies changed after cleanup.");
                                    return 0;
                                }, ct, plan).ConfigureAwait(false);
                        }
                    }
                    if (recoveredPrefix is not null)
                    { recoveredNativePrefixScope = recoveredPrefix; Did2MessagingSqlJournal.NativeWork.Maintenance(); }
                    return recovered;
                }
                recovered = true;
                if (IsStoppedControlPlan(plan))
                {
                    if (IsPreSessionControlPlan(plan)) await ResumePreSessionControlAuditStepUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                    else await ResumeControlAuditStepUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                    continue;
                }
                if (plan.ReadRow(plan.RowCount - 1).Action == Did2CompactionPlan.Disposition.RetainedPath)
                {
                    await ResumeRetainedPathStepUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                    continue;
                }
                if (plan.Target == Did2CompactionPlan.SqlTarget.ProtectedOnly)
                {
                    if (plan.ReadRow(0).Action is Did2CompactionPlan.Disposition.ContactAcceptPayload or Did2CompactionPlan.Disposition.InitialPayload)
                        await ResumeContactPayloadRetirementStepAsync(plans, plan, held, ct).ConfigureAwait(false);
                    else await ResumeMailboxRetirementStepUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                    continue;
                }
                using var catalog = await ReadMessagingCatalogForCompactionAsync(owner.Account, owner.Instance, ct).ConfigureAwait(false);
                if (plan.Target == Did2CompactionPlan.SqlTarget.Application)
                {
                    await ResumeOrdinaryOutboxStepUnderLeaseAsync(plans, plan, catalog, held, ct).ConfigureAwait(false);
                    continue;
                }
                var scope = ResolvePrefixScope(plan, catalog, archiveEnrollmentInProgress);
                catalog.Dispose();
                recoveredPrefix = Convert.ToHexString(scope.Hash);
                var finished = false;
                if (archiveEnrollmentInProgress)
                    finished = await ResumeOldEnrollmentPrefixStepAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
                else
                {
                    completedSuccessor = await ResumeArchivePrefixStepAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
                    finished = completedSuccessor is not null;
                }
                if (finished)
                {
                    completedPrefix?.Dispose(); completedScope = scope;
                    completedPrefix = archiveEnrollmentInProgress
                        ? Did2CompactionPlan.DecodeForOldEnrollment(plan.Exact.Span, scope.Network, scope.LocalAccount, scope.Instance)
                        : Did2CompactionPlan.Decode(plan.Exact.Span, scope.Network, scope.LocalAccount, scope.Instance);
                }
            }
            throw new InvalidOperationException("Prefix recovery exceeded its bounded handovers.");
        }
        finally { completedPrefix?.Dispose(); CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }

    // V1 is available only while the explicit enrollment entry has fenced
    // ordinary work. It drains the actual pre-existing history plan unchanged.
    private async Task<bool> ResumeOldEnrollmentPrefixStepAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (!archiveEnrollmentInProgress) throw new InvalidOperationException("Old prefix draining requires explicit enrollment.");
        var changedIndex = PrefixChangedRootIndex(plan, Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint);
        var observation = await WithStoredPrefixSqlAsync(plan, scope, held,
            (sql, _, roots) => plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots), ct).ConfigureAwait(false);
        if (observation.Step == Did2CompactionPlan.RecoveryStep.ClearPlan)
        {
            await WithStoredPrefixSqlAsync(plan, scope, held, (sql, floor, roots) =>
            {
                var digest = sql.ReadCompleteCompactionProjection();
                if (plan.Phase == 2) sql.VerifyCompletePrefixSuccessor(floor, plan);
                else if (plan.Phase != 3 || !Did2MessagingSessionScope.Fixed(sql.VerifyTip().Exact.Span, floor.Exact.Span))
                    throw new CryptographicException("Abandoning old prefix lost its exact predecessor.");
                _ = plan.ObserveReadback(digest, roots); return 0;
            }, ct).ConfigureAwait(false);
            await ValidateFinishingPrefixPartsAsync(plan, ct).ConfigureAwait(false);
            await storage.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)], ct).ConfigureAwait(false);
            await WithStoredPrefixSqlAsync(plan, scope, held, (sql, _, roots) =>
                plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots), ct).ConfigureAwait(false);
            using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false); return true;
        }
        using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
        using var raw = parts.Use(bytes => plan.OwnSuccessor(changedIndex, bytes));
        var successor = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
        parts.Dispose(); raw.Dispose();
        if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
        {
            await WithStoredPrefixSqlAsync(plan, scope, held, (sql, floor, roots) =>
            {
                if (plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                    throw new CryptographicException("Old prefix dependencies changed before SQL.");
                sql.ApplyOldEnrollmentPrefix(plan, floor, successor); return 0;
            }, ct).ConfigureAwait(false);
            observation = await WithStoredPrefixSqlAsync(plan, scope, held,
                (sql, _, roots) => plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots), ct).ConfigureAwait(false);
        }
        if (observation.Step == Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
        {
            await WithStoredPrefixSqlAsync(plan, scope, held, (sql, floor, roots) =>
            { sql.VerifyOldEnrollmentPrefixSuccessor(floor, plan, successor); return plan.ObserveReadback(plan.SqlAfter, roots); }, ct).ConfigureAwait(false);
            using var committed = plan.WithSqlCommitted(); await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false); return false;
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || observation.RootIndex != changedIndex)
            throw new InvalidDataException("Old prefix selected another recovery step.");
        var before = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        await WithStoredPrefixSqlAsync(plan, scope, held, (sql, floor, roots) =>
        {
            sql.VerifyOldEnrollmentPrefixSuccessor(floor, plan, successor);
            var current = plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots);
            if (current.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || current.RootIndex != changedIndex ||
                !Did2MessagingSessionScope.Fixed(SHA256.HashData(before.Exact.Span), plan.ReadRoot(changedIndex).Before.Span))
                throw new CryptographicException("Old prefix dependencies changed before adoption.");
            return 0;
        }, ct).ConfigureAwait(false);
        if (!await storage.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(scope), before.Exact, successor.Exact, ct).ConfigureAwait(false))
            throw new CryptographicException("Old prefix checkpoint adoption conflicted.");
        var readback = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(readback.Exact.Span, successor.Exact.Span)) throw new CryptographicException("Old prefix adoption read-back differs.");
        await WithStoredPrefixSqlAsync(plan, scope, held, (sql, floor, roots) =>
        { sql.VerifyCompletePrefixSuccessor(floor, plan); return plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots); }, ct).ConfigureAwait(false);
        return false;
    }

    private async Task<Did2MessagingArchiveRoot> ReadStoredArchiveSuccessorAsync(ProtectedDid2CompactionPlan plans,
        Did2CompactionPlan plan, Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var changedIndex = PrefixChangedRootIndex(plan, Did2CompactionPlan.RootKind.MessagingArchive);
        using (var parts = await ProtectedDid2CompactionPlan.ReadPartsAsync(storage, ct).ConfigureAwait(false))
        {
            if (parts[0] is not null)
            {
                using var all = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
                using var raw = all.Use(bytes => plan.OwnSuccessor(changedIndex, bytes));
                return raw.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
            }
        }
        if (plan.Phase == 2)
        {
            var adopted = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(adopted.Exact.Span), plan.ReadRoot(changedIndex).After.Span))
                throw new CryptographicException("Missing prefix parts have no exact adopted archive.");
            return adopted;
        }
        if (plan.Phase != 3) throw new InvalidDataException("Prepared archive prefix lost successor custody.");
        return await WithQualifiedPrefixSqlAsync(plan, scope, null, held,
            (sql, floor, roots, authored) =>
            {
                var effects = sql.CaptureArchivePrefixEffects(floor, plan.RowCount, authored);
                if (plan.ObserveReadback(effects.Before.Span, roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan ||
                    !Did2MessagingSessionScope.Fixed(effects.After.Span, plan.SqlAfter))
                    throw new CryptographicException("Abandoning prefix lost its exact virtual successor.");
                return effects.Successor;
            }, ct).ConfigureAwait(false);
    }

    private static int PrefixChangedRootIndex(Did2CompactionPlan plan, Did2CompactionPlan.RootKind kind)
    {
        for (var index = 0; index < plan.RootCount; index++)
            if (plan.ReadRoot(index).Kind == kind && !plan.ReadRoot(index).Guard) return index;
        throw new InvalidDataException("Prefix lost its exact changed root selector.");
    }

    private async Task<Did2CompactionPlan.RecoveryObservation> ObserveStoredArchivePrefixAsync(Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, Did2MessagingArchiveRoot successor, HeldDeepIdV2AccountLease held, CancellationToken ct) =>
        await WithQualifiedPrefixSqlAsync(plan, scope, successor, held, (sql, floor, roots, authored) =>
            plan.ObserveReadback(sql.ReadArchivePrefixProjection(floor, plan, successor, authored), roots), ct).ConfigureAwait(false);

    private async Task<Did2MessagingArchiveRoot?> ResumeArchivePrefixStepAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var successor = await ReadStoredArchiveSuccessorAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
        var changedIndex = PrefixChangedRootIndex(plan, Did2CompactionPlan.RootKind.MessagingArchive);
        var observation = await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false);
        if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
        {
            await WithQualifiedPrefixSqlAsync(plan, scope, successor, held, (sql, floor, roots, authored) =>
            {
                var digest = sql.ReadArchivePrefixProjection(floor, plan, successor, authored);
                if (plan.ObserveReadback(digest, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                    throw new CryptographicException("Archive prefix dependencies changed before SQL.");
                sql.ApplyArchivePrefix(plan, floor, successor, authored); return 0;
            }, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
            observation = await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false);
        }
        if (observation.Step == Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
        {
            using var committed = plan.WithSqlCommitted();
            await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
            return null;
        }
        if (observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            if (observation.RootIndex != changedIndex) throw new InvalidDataException("Prefix recovery selected another changed root.");
            var before = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            var adoption = await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false);
            if (adoption.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || adoption.RootIndex != changedIndex ||
                !Did2MessagingSessionScope.Fixed(SHA256.HashData(before.Exact.Span), plan.ReadRoot(changedIndex).Before.Span))
                throw new CryptographicException("Archive prefix dependencies changed before adoption.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (!await storage.CompareExchangeAsync(Did2MessagingArchiveRoot.Slot(scope), before.Exact, successor.Exact, ct).ConfigureAwait(false))
                throw new CryptographicException("Archive prefix adoption conflicted.");
            var readback = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            if (!Did2MessagingSessionScope.Fixed(readback.Exact.Span, successor.Exact.Span)) throw new CryptographicException("Archive prefix adoption read-back differs.");
            _ = await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
            return null;
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only a completed or abandoning archive prefix can clear.");
        await ValidateFinishingPrefixPartsAsync(plan, ct).ConfigureAwait(false);
        if ((await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false)).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Archive prefix dependencies changed before successor disposal.");
        await storage.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)], ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        if ((await ObserveStoredArchivePrefixAsync(plan, scope, successor, held, ct).ConfigureAwait(false)).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Archive prefix dependencies changed before clearing.");
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
        return successor;
    }

    private static Did2MessagingSessionScope ResolvePrefixScope(Did2CompactionPlan plan, ProtectedDid2MessagingSessionCatalog.Snapshot catalog, bool oldEnrollment = false)
    {
        if (plan.Target != Did2CompactionPlan.SqlTarget.Messaging || plan.RootCount != (oldEnrollment ? 5 : 6) || plan.SuccessorBytes != (oldEnrollment ? Did2MessagingHistoryCheckpoint.Bytes : Did2MessagingArchiveRoot.Bytes) || plan.PartCount != 1 ||
            (oldEnrollment ? catalog.Version != 1 : !catalog.AllIndexed))
            throw new InvalidDataException("No owned recovery is installed for this compaction profile.");
        for (var index = 0; index < catalog.Count; index++)
            if (catalog.Phase(index) == 2 && (oldEnrollment || catalog.ArchiveState(index) == 1) && Did2MessagingSessionScope.Fixed(catalog.Scope(index).Hash, plan.SqlSelector)) return catalog.Scope(index);
        throw new InvalidDataException("Stored prefix has no initialized owned SQL selector.");
    }

    private static string[] PrefixRootSlots(Did2MessagingSessionScope scope, bool oldEnrollment = false) => oldEnrollment
        ? [ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
            Did2MessagingHistoryCheckpoint.Slot(scope), ProtectedDid2MessagingPeerBootstrap.Slot(scope)]
        : [ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
            Did2MessagingHistoryCheckpoint.Slot(scope), ProtectedDid2MessagingPeerBootstrap.Slot(scope), Did2MessagingArchiveRoot.Slot(scope)];

    internal static async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadPrefixRootsUnderLeaseAsync(
        IDeepSecureStorage storage, Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        var slots = PrefixRootSlots(scope);
        using var inventory = await storage.ReadOwnedBatchAsync([.. slots, Did2CompactionPlan.Slot], ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        return DecodePrefixRoots(plan, scope, slots, inventory, oldEnrollment: false);
    }

    private static IReadOnlyList<Did2CompactionPlan.RootReadback> DecodePrefixRoots(Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, string[] slots, OwnedDeepSecretBatch inventory, bool oldEnrollment,
        Did2CompactionPlan? expectedStoredPlan = null)
    {
        var planRaw = inventory[slots.Length] ?? throw new InvalidDataException("Protected compaction registration is absent; explicit reset is required.");
        using var currentPlan = planRaw.Use(bytes => oldEnrollment
            ? Did2CompactionPlan.DecodeForOldEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance)
            : Did2CompactionPlan.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        if (expectedStoredPlan is not null)
        {
            if (plan.Phase is not (2 or 3) || expectedStoredPlan.Phase != 0) throw new InvalidDataException("Only exact completed prefix cleanup may verify an idle successor.");
            using var cleared = plan.Cleared();
            if (!Did2MessagingSessionScope.Fixed(cleared.Exact.Span, expectedStoredPlan.Exact.Span))
                throw new CryptographicException("Completed prefix has another idle successor.");
        }
        if (!Did2MessagingSessionScope.Fixed(currentPlan.Exact.Span, (expectedStoredPlan?.Exact ?? plan.Exact).Span))
            throw new CryptographicException("Stored prefix changed during recovery.");
        Did2CompactionPlan.RootKind[] kinds = oldEnrollment
            ? [Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.MessagingFloor,
                Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, Did2CompactionPlan.RootKind.MessagingPeerBootstrap]
            : [Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.MessagingFloor,
                Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint,
                Did2CompactionPlan.RootKind.MessagingPeerBootstrap, Did2CompactionPlan.RootKind.MessagingArchive];
        var changedKind = oldEnrollment ? Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint : Did2CompactionPlan.RootKind.MessagingArchive;
        if (plan.Target != Did2CompactionPlan.SqlTarget.Messaging || plan.RootCount != kinds.Length ||
            plan.SuccessorBytes != (oldEnrollment ? Did2MessagingHistoryCheckpoint.Bytes : Did2MessagingArchiveRoot.Bytes) || plan.PartCount != 1 ||
            !Did2MessagingSessionScope.Fixed(plan.SqlSelector, scope.Hash)) throw new InvalidDataException("Wrong closed prefix profile.");
        var result = new List<Did2CompactionPlan.RootReadback>(slots.Length);
        for (var index = 0; index < slots.Length; index++)
        {
            var expected = plan.ReadRoot(index); var selector = CompactionSlotSelector(slots[index]);
            if (expected.Kind != kinds[index] || expected.Guard != (expected.Kind != changedKind) || !Did2MessagingSessionScope.Fixed(expected.Selector.Span, selector))
                throw new InvalidDataException("Prefix changed its owned root mapping.");
            var raw = inventory[index] ?? throw new InvalidDataException("Prefix lost a mandatory dependency root.");
            switch (index)
            {
                case 0:
                    using (var catalog = raw.Use(bytes => oldEnrollment
                        ? ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance)
                        : ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance)))
                    {
                        var entry = catalog.FindExact(scope);
                        if (entry < 0 || catalog.Phase(entry) != 2 ||
                            (oldEnrollment ? catalog.Version != 1 : catalog.ArchiveState(entry) != 1 || !catalog.AllIndexed))
                            throw new InvalidDataException("Prefix catalog binding changed.");
                    }
                    break;
                case 1:
                    var floor = raw.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
                    if (floor.Phase != 1 || floor.Status != 1) throw new InvalidDataException("Prefix lost its stable active ratchet floor."); break;
                case 2:
                    var instance = raw.Use(bytes => SqliteDeepIdV2AccountGeneration.ReadAccountInstanceFromRegistration(bytes, scope.Network, scope.LocalAccount));
                    try { if (!Did2MessagingSessionScope.Fixed(instance, scope.Instance)) throw new CryptographicException("Prefix registration changed during read-back."); }
                    finally { CryptographicOperations.ZeroMemory(instance); }
                    break;
                case 3: _ = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope)); break;
                case 4: _ = raw.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope)); break;
                case 5:
                    raw.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope)).RequireSource(
                        inventory[3]!.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope))); break;
            }
            result.Add(new(kinds[index], selector, raw.Use(bytes => SHA256.HashData(bytes))));
        }
        return result;
    }

    // The exact durable plan, or this invocation's exact cleared successor,
    // selects this lower opener. An ordinary mirror error never selects it.
    // Every call closes its physical handle/key before
    // another protected provider edge or diagnostic callback can occur.
    private async Task<T> WithStoredPrefixSqlAsync<T>(Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, Func<Did2MessagingSqlJournal, Did2MessagingFloor,
            IReadOnlyList<Did2CompactionPlan.RootReadback>, T> operation, CancellationToken ct,
        Did2MessagingArchiveAuthoredRead? pairedRead = null, Did2CompactionPlan? expectedStoredPlan = null)
    {
        using var borrowed = held.BorrowFor(lease);
        var oldEnrollment = archiveEnrollmentInProgress;
        if (oldEnrollment && pairedRead is not null) throw new InvalidOperationException("Indexed paired reads cannot select old enrollment draining.");
        var slots = PrefixRootSlots(scope, oldEnrollment);
        var authoredSlots = pairedRead?.Roots.Keys.Order(StringComparer.Ordinal).ToArray() ?? [];
        string[] inventorySlots = pairedRead is null
            ? [.. slots, Did2CompactionPlan.Slot, ProtectedDid2MessagingArchiveEnrollment.Slot]
            : [.. slots, Did2CompactionPlan.Slot, ProtectedDid2MessagingArchiveEnrollment.Slot,
                SqliteDeepIdV2AccountGeneration.ApplicationStateSlot, .. authoredSlots];
        if (!oldEnrollment) inventorySlots = [.. inventorySlots, ProtectedInitialKeyRetirementJournal.Slot];
        using var inventory = await storage.ReadOwnedBatchAsync(inventorySlots, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        if (inventory[slots.Length + 1] is not null) throw new InvalidDataException("Archive enrollment progress owns this account.");
        var roots = DecodePrefixRoots(plan, scope, slots, inventory, oldEnrollment, expectedStoredPlan);
        using var catalog = inventory[0]!.Use(bytes => oldEnrollment
            ? ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance)
            : ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var floor = inventory[1]!.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
        var history = inventory[3]!.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
        var archive = oldEnrollment ? null : inventory[5]!.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
        var retirement = oldEnrollment ? null : (inventory[inventorySlots.Length - 1] ??
            throw new InvalidDataException("Stored archive prefix lost its established source retirement proof."))
            .Use(bytes => ProtectedInitialKeyRetirementJournal.CaptureEstablishedProof(bytes, scope));
        if (pairedRead is not null)
        {
            var registration = inventory[2]!.Use(bytes => bytes.ToArray());
            var application = (inventory[slots.Length + 2] ?? throw new InvalidDataException("Paired archive read lost application registration.")).Use(bytes => bytes.ToArray());
            var actualRoots = authoredSlots.Select((slot, index) => new KeyValuePair<string, byte[]?>(slot,
                inventory[slots.Length + 3 + index]?.Use(bytes => SHA256.HashData(bytes)))).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            inventory.Dispose(); // No protected/group source bytes enter application key acquisition.
            try
            {
                held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
                SqliteDeepIdV2AccountGeneration.VerifyPairedArchiveApplication(sqlStatePath, scope, registration,
                    application, actualRoots, pairedRead, ct);
            }
            finally { CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(application); }
        }
        using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
        catalog.Dispose(); inventory.Dispose();
        var sql = oldEnrollment ? Did2MessagingSqlJournal.ForArchiveEnrollment(connection, scope, history)
            : Did2MessagingSqlJournal.ForOrdinaryRuntime(connection, scope, history, archive!);
        // The exact stored plan permits its before/after mirror transition;
        // the operation below authenticates that complete projection. Its
        // immutable import still has the same fresh retirement requirement.
        if (retirement is not null) _ = sql.RequireEstablishedNativeImport(retirement);
        return operation(sql, floor, roots);
    }

    private async Task<T> WithQualifiedPrefixSqlAsync<T>(Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        Did2MessagingArchiveRoot? successor, HeldDeepIdV2AccountLease held,
        Func<Did2MessagingSqlJournal, Did2MessagingFloor, IReadOnlyList<Did2CompactionPlan.RootReadback>,
            IReadOnlyDictionary<ulong, ReadOnlyMemory<byte>>, T> operation, CancellationToken ct,
        Did2CompactionPlan? expectedStoredPlan = null)
    {
        var originals = await WithStoredPrefixSqlAsync(plan, scope, held,
            (sql, floor, _) => sql.ReadArchivePrefixAuthoredSources(floor, plan.RowCount, successor), ct,
            expectedStoredPlan: expectedStoredPlan).ConfigureAwait(false);
        try
        {
            using var authored = await QualifyArchiveAuthoredAsync(scope, originals, held, ct).ConfigureAwait(false);
            // One final actual inventory binds app and native inputs. Its
            // callback finishes before synchronous app read then native read;
            // no further provider edge can invalidate the selected app proof.
            return await WithStoredPrefixSqlAsync(plan, scope, held,
                (sql, floor, roots) => operation(sql, floor, roots, authored.Events), ct, authored.PairedRead, expectedStoredPlan).ConfigureAwait(false);
        }
        finally { foreach (var original in originals) original.Dispose(); }
    }

    private async Task ReplaceCompactionPlanAsync(Did2CompactionPlan before, Did2CompactionPlan after, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        if (!await storage.CompareExchangeAsync(Did2CompactionPlan.Slot, before.Exact, after.Exact, ct).ConfigureAwait(false))
            throw new CryptographicException("Compaction plan CAS conflicted.");
        using var readback = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId,
            after.Exact.Slice(32, 32), after.Exact.Slice(64, 32), ct, archiveEnrollmentInProgress).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(readback.Exact.Span, after.Exact.Span)) throw new CryptographicException("Compaction plan CAS read-back differs.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task ValidateFinishingPrefixPartsAsync(Did2CompactionPlan plan, CancellationToken ct)
    {
        using var parts = await ProtectedDid2CompactionPlan.ReadPartsAsync(storage, ct).ConfigureAwait(false);
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            ct.ThrowIfCancellationRequested();
            var part = parts[index];
            if (index == 0) { if (part is not null) part.Use(bytes => plan.ValidateSuccessors(bytes)); }
            else if (part is not null) throw new InvalidDataException("Prefix has an unexpected successor part.");
        }
    }
    private async Task RequireNoPrefixPartsAsync(CancellationToken ct)
    {
        using var parts = await ProtectedDid2CompactionPlan.ReadPartsAsync(storage, ct).ConfigureAwait(false);
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            ct.ThrowIfCancellationRequested();
            var part = parts[index];
            if (part is not null) throw new InvalidDataException("Idle prefix has orphan successor custody.");
        }
    }

    private static Did2CompactionPlan.Root Guard(Did2CompactionPlan.RootKind kind, string slot, byte[] hash) =>
        new(kind, CompactionSlotSelector(slot), hash, hash, true, ReadOnlyMemory<byte>.Empty);
    private static byte[] CompactionSlotSelector(string slot)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/STORE-V2/compaction-protected-slot"u8); hash.AppendData([0]); hash.AppendData(Encoding.UTF8.GetBytes(slot));
        return hash.GetHashAndReset();
    }
}
