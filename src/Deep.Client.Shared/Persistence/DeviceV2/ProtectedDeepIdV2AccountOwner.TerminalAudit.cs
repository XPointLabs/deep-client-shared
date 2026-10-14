using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Terminal audit membership never authorizes Store, dispatch or namespace retirement.
internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task ExpireOwnedTerminalAuditsAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope requestedScope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var scope = Did2MessagingSessionScope.RestoreMetadata(requestedScope.Exact);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        await ExpireTerminalAuditsUnderLeaseAsync(current, held, scope, own, source, ct).ConfigureAwait(false);
    }

    private async Task ExpireTerminalAuditsUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); RequireRetainedStoreOwnScope(scope, own);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            using var state = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            if (state.Pending is not null || state.TerminalAudits.Count == 0) return;
            var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            var lower = checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample);
            var selected = state.TerminalAudits.Values.Where(audit => lower >= checked(audit.TerminalAtUpper + SqliteDeepMailboxStore.StoppedAuditSeconds))
                .Take(Did2CompactionPlan.MaximumRows).ToArray();
            if (selected.Length == 0) return;
            using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Phase != 1 || floor.Status != 1) throw new CryptographicException("Audit expiry lost the actual guarded native owner.");
            using var app = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage,
                sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            var effects = await app.CaptureTerminalAuditExpiryAsync(scope, state, selected, ct).ConfigureAwait(false);
            try
            {
                var slots = OrdinaryOutboxSlots(scope); var roots = new List<Did2CompactionPlan.Root>();
                var rows = selected.Select(audit => new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ExpiredTerminalAudit,
                    audit.Operation.ToArray(), SHA256.HashData(audit.Exact))).ToArray();
                foreach (var audit in selected) { state.TerminalAudits.Remove(Convert.ToHexString(audit.Operation)); audit.Dispose(); }
                state.Revision = checked(state.Revision + 1);
                after = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                for (var index = 0; index < slots.Length; index++)
                {
                    using var actual = await storage.ReadOwnedAsync(slots[index], ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    var digest = actual.Use(bytes => SHA256.HashData(bytes));
                    if (index == 0 && !FixedRoute(digest, SHA256.HashData(before))) throw new CryptographicException("Terminal audit membership changed during selection.");
                    roots.Add(index == 0
                        ? new(OrdinaryOutboxRootKinds[index], CompactionSlotSelector(slots[index]), digest, SHA256.HashData(after), false, after)
                        : Guard(OrdinaryOutboxRootKinds[index], slots[index], digest));
                }
                var plans = new ProtectedDid2CompactionPlan(storage, lease, scope.Network, scope.LocalAccount, scope.Instance);
                using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (idle.Phase != 0) throw new InvalidDataException("Another held plan owns audit recovery.");
                using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.Application, RandomNumberGenerator.GetBytes(32), scope.Hash,
                    effects.Before, effects.After, roots, rows);
                var final = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                if (checked(own.Proof.TrustedLowerUnixSeconds + final.SampleSeconds - own.Proof.MonotonicSample) < lower)
                    throw new CryptographicException("Terminal audit expiry lost its proven lower time.");
                for (var index = 0; index < slots.Length; index++)
                {
                    using var actual = await storage.ReadOwnedAsync(slots[index], ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    if (!actual.Use(bytes => FixedRoute(SHA256.HashData(bytes), roots[index].Before.Span)))
                        throw new CryptographicException("Terminal audit dependency changed before staging.");
                }
                if (!FixedRoute(await app.ReadCompleteMailboxStateProjectionAsync(scope.Hash.ToArray(), ct).ConfigureAwait(false), effects.Before))
                    throw new CryptographicException("Terminal audit SQL changed before staging.");
                await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    private static ProtectedDid2DirectTextJournal.TerminalAudit[] SelectTerminalAuditPlan(Did2CompactionPlan plan,
        ProtectedDid2DirectTextJournal.State state)
    {
        var result = new ProtectedDid2DirectTextJournal.TerminalAudit[plan.RowCount];
        for (var index = 0; index < result.Length; index++)
        {
            var row = plan.ReadRow(index);
            if (row.Action != Did2CompactionPlan.Disposition.ExpiredTerminalAudit ||
                !state.TerminalAudits.TryGetValue(Convert.ToHexString(row.Selector.Span), out var audit) ||
                !FixedRoute(row.Commitment.Span, SHA256.HashData(audit.Exact)))
                throw new CryptographicException("Terminal audit plan lost its exact protected predecessor.");
            result[index] = audit;
        }
        return result;
    }

    private static void RequireTerminalAuditSuccessor(Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var state = ProtectedDid2DirectTextJournal.Decode(predecessor, scope.Network, scope.LocalAccount, scope.Instance);
        foreach (var audit in SelectTerminalAuditPlan(plan, state))
        { state.TerminalAudits.Remove(Convert.ToHexString(audit.Operation)); audit.Dispose(); }
        state.Revision = checked(state.Revision + 1);
        var expected = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Terminal audit successor changed unrelated custody."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private async Task ResumeTerminalAuditStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        ProtectedDid2MessagingSessionCatalog.Snapshot catalog, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var scope = ResolveOrdinaryOutboxScope(plan, catalog);
        var roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
        var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
        if (!FixedRoute(new Did2MessagingSqlJournal(connection, scope, history).VerifyTip().Exact.Span, floor.Exact.Span))
            throw new CryptographicException("Terminal audit recovery lost actual native custody.");
        using var app = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage,
            sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(await app.ReadCompleteMailboxStateProjectionAsync(scope.Hash.ToArray(), ct).ConfigureAwait(false), roots);
        if (observation.Step is Did2CompactionPlan.RecoveryStep.ApplySql or Did2CompactionPlan.RecoveryStep.RecordSqlCommit or Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray());
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            using var successor = parts.Use(bytes => plan.OwnSuccessor(0, bytes));
            var after = successor.Use(bytes => bytes.ToArray());
            try
            {
                RequireTerminalAuditSuccessor(plan, scope, before, after);
                if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                {
                    using var state = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                    await app.ApplyTerminalAuditExpiryAsync(storage, plan, scope, state, SelectTerminalAuditPlan(plan, state), held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                    return;
                }
                roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(await app.ReadCompleteMailboxStateProjectionAsync(scope.Hash.ToArray(), ct).ConfigureAwait(false), roots) != observation)
                    throw new CryptographicException("Terminal audit recovery changed before its transition.");
                if (observation.Step == Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                {
                    using var committed = plan.WithSqlCommitted(); await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    return;
                }
                if (observation.RootIndex != 0) throw new InvalidDataException("Terminal audit selected another root.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, before, after, ct).ConfigureAwait(false))
                    throw new CryptographicException("Terminal audit adoption changed before CAS.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, after, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                return;
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only adopted terminal audit expiry may finish.");
        using var adopted = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        if (plan.Phase == 2) adopted.Use(bytes => { plan.ValidateSuccessors(bytes); return true; });
        var remaining = 0;
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
            if (part is null) continue;
            var offset = index * Did2CompactionPlan.PartBytes;
            var copy = part.Use(bytes => bytes.ToArray());
            try
            {
                if (index >= plan.PartCount || copy.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset) ||
                    plan.Phase == 2 && !adopted.Use(current => FixedRoute(current.Slice(offset, copy.Length), copy)))
                    throw new CryptographicException("Terminal audit staging differs from its adopted successor.");
                remaining++;
            }
            finally { CryptographicOperations.ZeroMemory(copy); }
        }
        if (plan.Phase == 3 && remaining != 0)
        {
            if (remaining != plan.PartCount) throw new CryptographicException("Terminal audit abort lost partial staging.");
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            using var successor = parts.Use(bytes => plan.OwnSuccessor(0, bytes));
            var before = adopted.Use(bytes => bytes.ToArray()); var after = successor.Use(bytes => bytes.ToArray());
            try { RequireTerminalAuditSuccessor(plan, scope, before, after); }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        using var currentRoot = adopted.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        await app.ValidateCompleteStoppedAuditsAsync(currentRoot, ct).ConfigureAwait(false);
        roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(await app.ReadCompleteMailboxStateProjectionAsync(scope.Hash.ToArray(), ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Terminal audit guards changed before disposal.");
        await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(await app.ReadCompleteMailboxStateProjectionAsync(scope.Hash.ToArray(), ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Terminal audit guards changed before plan disposal.");
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
    }
}
