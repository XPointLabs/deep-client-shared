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
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, instance);
            using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (idle.Phase != 0) throw new InvalidOperationException("An active compaction plan owns recovery; no new selection is permitted.");
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var stable = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var catalog = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            using var sessions = await catalog.ReadAsync(ct).ConfigureAwait(false);
            var index = sessions.FindExact(scope);
            if (index < 0 || sessions.Phase(index) != 2) throw new InvalidDataException("Compaction requires an initialized exact owned session.");
            using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using var peer = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false)
                ?? throw new InvalidDataException("Compaction cannot orphan the registered peer bootstrap.");
            _ = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var effects = opened.Sql.CaptureHistoryPrefixEffects(stable, prefixRows);
            var roots = new Did2CompactionPlan.Root[]
            {
                Guard(Did2CompactionPlan.RootKind.SessionCatalog, ProtectedDid2MessagingSessionCatalog.Slot, SHA256.HashData(sessions.Exact.Span)),
                Guard(Did2CompactionPlan.RootKind.MessagingFloor, scope.FloorSlot, SHA256.HashData(stable.Exact.Span)),
                Guard(Did2CompactionPlan.RootKind.AccountRegistration, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, registration.Use(bytes => SHA256.HashData(bytes))),
                new(Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, CompactionSlotSelector(Did2MessagingHistoryCheckpoint.Slot(scope)),
                    SHA256.HashData(history.Exact.Span), SHA256.HashData(effects.Successor.Exact.Span), false, effects.Successor.Exact),
                Guard(Did2CompactionPlan.RootKind.MessagingPeerBootstrap, ProtectedDid2MessagingPeerBootstrap.Slot(scope), peer.Use(bytes => SHA256.HashData(bytes)))
            };
            var preparation = idle.Prepare(Did2CompactionPlan.SqlTarget.Messaging, RandomNumberGenerator.GetBytes(32),
                scope.Hash, effects.Before.Span, effects.After.Span, roots, effects.Rows);
            try { ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return preparation; }
            catch { preparation.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
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
            var roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
            var sql = new Did2MessagingSqlJournal(connection, scope, history);
            var effects = sql.CaptureHistoryPrefixEffects(floor, plan.RowCount);
            if (!Did2MessagingSessionScope.Fixed(effects.Before.Span, plan.SqlBefore) ||
                plan.ObserveReadback(effects.Before.Span, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Committed or changed SQL cannot be abandoned.");
            using var abandoning = plan.WithAbandoningBeforeSql();
            await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }

    private async Task ResumeLocalCompactionUnderLeaseAsync(HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using (var registration = await storage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, ct).ConfigureAwait(false))
            if (registration is null)
            {
                using var orphan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot, ct).ConfigureAwait(false);
                using var pointer = await storage.ReadOwnedAsync(CurrentAccountSlot, ct).ConfigureAwait(false);
                if (orphan is not null || pointer is not null) throw new InvalidDataException("An existing account/plan lost its local registration.");
                return; // No registered account yet, not a missing-plan initializer.
            }
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            for (var iteration = 0; iteration < 8; iteration++)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (plan.Phase == 0) { await RequireNoPrefixPartsAsync(ct).ConfigureAwait(false); return; }
                if (plan.Target == Did2CompactionPlan.SqlTarget.ProtectedOnly)
                {
                    await ResumeMailboxRetirementStepUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                    continue;
                }
                using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, owner.Account, owner.Instance).ReadAsync(ct).ConfigureAwait(false);
                if (plan.Target == Did2CompactionPlan.SqlTarget.Application)
                {
                    await ResumeOrdinaryOutboxStepUnderLeaseAsync(plans, plan, catalog, held, ct).ConfigureAwait(false);
                    continue;
                }
                var scope = ResolvePrefixScope(plan, catalog);
                var roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
                var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
                using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
                var sql = new Did2MessagingSqlJournal(connection, scope, history);
                var digest = sql.ReadCompleteCompactionProjection();
                var observation = plan.ObserveReadback(digest, roots);
                if (plan.Phase == 1)
                {
                    using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
                    using var raw = parts.Use(bytes => plan.OwnSuccessor(3, bytes));
                    var successor = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
                    if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                    {
                        await sql.ApplyStoredPrefixAsync(storage, plan, floor, successor, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                    }
                    else if (observation.Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit) throw new InvalidDataException("Unexpected prepared prefix observation.");
                    var after = new Did2MessagingSqlJournal(connection, scope, successor);
                    after.VerifyCompletePrefixSuccessor(floor, plan);
                    roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                    _ = plan.ObserveReadback(plan.SqlAfter, roots);
                    using var committed = plan.WithSqlCommitted();
                    await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    continue;
                }
                if (observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
                {
                    if (observation.RootIndex != 3) throw new InvalidDataException("Prefix recovery has another changed root.");
                    using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
                    using var raw = parts.Use(bytes => plan.OwnSuccessor(3, bytes));
                    var successor = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
                    new Did2MessagingSqlJournal(connection, scope, successor).VerifyCompletePrefixSuccessor(floor, plan);
                    roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                    var adoption = plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots);
                    if (adoption.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || adoption.RootIndex != 3)
                        throw new CryptographicException("Prefix dependencies changed before checkpoint adoption.");
                    ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                    if (!await storage.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(scope), history.Exact, successor.Exact, ct).ConfigureAwait(false))
                        throw new CryptographicException("Prefix checkpoint adoption conflicted.");
                    var readback = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
                    if (!Did2MessagingSessionScope.Fixed(readback.Exact.Span, successor.Exact.Span)) throw new CryptographicException("Prefix checkpoint read-back differs.");
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                    continue;
                }
                if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan) throw new InvalidDataException("Unknown prefix recovery step.");
                if (plan.Phase == 2) sql.VerifyCompletePrefixSuccessor(floor, plan);
                else if (plan.Phase == 3)
                {
                    if (!Did2MessagingSessionScope.Fixed(floor.Exact.Span, sql.VerifyTip().Exact.Span) ||
                        !Did2MessagingSessionScope.Fixed(sql.ReadCompleteCompactionProjection(), plan.SqlBefore))
                        throw new CryptographicException("Abandoning prefix lost its unchanged SQL predecessor.");
                }
                else throw new InvalidDataException("Only complete or explicitly abandoning custody can clear.");
                // Missing parts are legal only in this verified final step:
                // all successor roots are already adopted, or durable abort
                // owns the unchanged predecessor. Never recreate them.
                await ValidateFinishingPrefixPartsAsync(plan, ct).ConfigureAwait(false);
                roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
                    throw new CryptographicException("Prefix dependencies changed before successor disposal.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                await storage.DeleteBatchAsync([ProtectedDid2CompactionPlan.PartSlot(0)], ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
                roots = await ReadPrefixRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                _ = plan.ObserveReadback(sql.ReadCompleteCompactionProjection(), roots);
                using var cleared = plan.Cleared();
                await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
            }
            throw new InvalidOperationException("Prefix recovery exceeded its bounded handovers.");
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }

    private static Did2MessagingSessionScope ResolvePrefixScope(Did2CompactionPlan plan, ProtectedDid2MessagingSessionCatalog.Snapshot catalog)
    {
        if (plan.Target != Did2CompactionPlan.SqlTarget.Messaging || plan.RootCount != 5 || plan.SuccessorBytes != Did2MessagingHistoryCheckpoint.Bytes || plan.PartCount != 1)
            throw new InvalidDataException("No owned recovery is installed for this compaction profile.");
        for (var index = 0; index < catalog.Count; index++)
            if (catalog.Phase(index) == 2 && Did2MessagingSessionScope.Fixed(catalog.Scope(index).Hash, plan.SqlSelector)) return catalog.Scope(index);
        throw new InvalidDataException("Stored prefix has no initialized owned SQL selector.");
    }

    internal static async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadPrefixRootsUnderLeaseAsync(
        IDeepSecureStorage storage, Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var currentPlan = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, scope.Network.ToArray(), scope.LocalAccount.ToArray(), scope.Instance.ToArray(), ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(currentPlan.Exact.Span, plan.Exact.Span)) throw new CryptographicException("Stored prefix changed during recovery.");
        var slots = new[] { ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
            SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot, Did2MessagingHistoryCheckpoint.Slot(scope), ProtectedDid2MessagingPeerBootstrap.Slot(scope) };
        var kinds = new[] { Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.MessagingFloor,
            Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, Did2CompactionPlan.RootKind.MessagingPeerBootstrap };
        if (plan.Target != Did2CompactionPlan.SqlTarget.Messaging || plan.RootCount != 5 || plan.SuccessorBytes != Did2MessagingHistoryCheckpoint.Bytes || plan.PartCount != 1 ||
            !Did2MessagingSessionScope.Fixed(plan.SqlSelector, scope.Hash)) throw new InvalidDataException("Wrong closed prefix profile.");
        var result = new List<Did2CompactionPlan.RootReadback>(5);
        for (var index = 0; index < slots.Length; index++)
        {
            var expected = plan.ReadRoot(index); var selector = CompactionSlotSelector(slots[index]);
            if (expected.Kind != kinds[index] || expected.Guard != (index != 3) || !Did2MessagingSessionScope.Fixed(expected.Selector.Span, selector))
                throw new InvalidDataException("Prefix changed its owned root mapping.");
            using var raw = await storage.ReadOwnedAsync(slots[index], ct).ConfigureAwait(false) ?? throw new InvalidDataException("Prefix lost a mandatory dependency root.");
            switch (index)
            {
                case 0:
                    using (var catalog = raw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance)))
                    { var entry = catalog.FindExact(scope); if (entry < 0 || catalog.Phase(entry) != 2) throw new InvalidDataException("Prefix catalog binding changed."); }
                    break;
                case 1:
                    var floor = raw.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
                    if (floor.Phase != 1 || floor.Status != 1) throw new InvalidDataException("Prefix lost its stable active ratchet floor."); break;
                case 2:
                    using (var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage, scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct).ConfigureAwait(false))
                        if (!Did2MessagingSessionScope.Fixed(raw.Use(bytes => SHA256.HashData(bytes)), registration.Use(bytes => SHA256.HashData(bytes))))
                            throw new CryptographicException("Prefix registration changed during read-back.");
                    break;
                case 3: _ = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope)); break;
                case 4: _ = raw.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope)); break;
            }
            result.Add(new(kinds[index], selector, raw.Use(bytes => SHA256.HashData(bytes))));
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
    }

    private async Task ReplaceCompactionPlanAsync(Did2CompactionPlan before, Did2CompactionPlan after, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        if (!await storage.CompareExchangeAsync(Did2CompactionPlan.Slot, before.Exact, after.Exact, ct).ConfigureAwait(false))
            throw new CryptographicException("Compaction plan CAS conflicted.");
        using var readback = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId,
            after.Exact.Slice(32, 32), after.Exact.Slice(64, 32), ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(readback.Exact.Span, after.Exact.Span)) throw new CryptographicException("Compaction plan CAS read-back differs.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task ValidateFinishingPrefixPartsAsync(Did2CompactionPlan plan, CancellationToken ct)
    {
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
            if (index == 0) { if (part is not null) part.Use(bytes => plan.ValidateSuccessors(bytes)); }
            else if (part is not null) throw new InvalidDataException("Prefix has an unexpected successor part.");
        }
    }
    private async Task RequireNoPrefixPartsAsync(CancellationToken ct)
    {
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
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
