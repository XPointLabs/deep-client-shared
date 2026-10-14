using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Called only after the complete native/semantic/public-policy/MAU/quorum/
    // coordinator Store join. It records local first-success time, not a grant
    // or a deletion permission. First stop, success and expired audit are final.
    private async Task RetainContactStoreCompletionUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [];
        try
        {
            var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            var upper = checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
            if (scope.IsInitiator)
            {
                using var journal = ProtectedDid2ContactStartJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var entry = FindControlInitial(journal, scope, operation.Span) ?? throw new CryptographicException("Store completion lost its exact Initial command.");
                if (entry.WorkStopped || entry.SuccessfullyStored) return;
                var next = entry.WithVerifiedStore(upper, scope.Network, scope.LocalAccount);
                journal.Entries[Convert.ToHexString(entry.Intent)] = next; entry.Dispose(); journal.Revision = checked(journal.Revision + 1);
                after = ProtectedDid2ContactStartJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            }
            else
            {
                using var journal = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                var entry = journal.FindScope(scope) ?? throw new CryptographicException("Store completion lost its explicit acceptance command.");
                if (!FixedRoute(entry.Operation, operation.Span)) throw new CryptographicException("Store completion selected another acceptance command.");
                if (entry.WorkStopped || entry.SuccessfullyStored) return;
                var next = entry.WithVerifiedStore(upper);
                journal.Entries[Convert.ToHexString(entry.Operation)] = next; entry.Dispose(); journal.Revision = checked(journal.Revision + 1);
                after = ProtectedDid2ContactAcceptJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            }
            await RecheckRouteFreshnessAsync(current, source, own, held, reading, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            if (!await storage.CompareExchangeAsync(slot, before, after, ct).ConfigureAwait(false))
                throw new CryptographicException("Store completion changed its protected control predecessor.");
            await RequireExactProtectedMailboxRootAsync(slot, after, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    private static (byte[] After, byte[] Commitment, ulong StoppedAt) BuildControlAuditSuccessor(ReadOnlySpan<byte> before,
        Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation, bool expire)
    {
        if (scope.IsInitiator)
        {
            using var journal = ProtectedDid2ContactStartJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            var entry = FindControlInitial(journal, scope, operation) ?? throw new CryptographicException("Control audit lost its exact Initial winner.");
            if ((!entry.WorkStopped && !entry.SuccessfullyStored) || (expire ? !entry.PayloadRetired || entry.AuditDisposition != 1 : entry.PayloadRetired || entry.AuditDisposition != 0))
                throw new CryptographicException("Initial audit disposition differs from actual stop custody.");
            var commitment = SHA256.HashData(entry.Exact); var time = entry.TerminalAtUpper;
            var next = expire ? entry.WithoutStoppedAudit(scope.Network, scope.LocalAccount) : entry.WithoutWorkingPayload(scope.Network, scope.LocalAccount);
            journal.Entries[Convert.ToHexString(entry.Intent)] = next; entry.Dispose(); journal.Revision = checked(journal.Revision + 1);
            return (ProtectedDid2ContactStartJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance), commitment, time);
        }
        else
        {
            using var journal = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
            var entry = journal.FindScope(scope) ?? throw new CryptographicException("Control audit lost its exact acceptance winner.");
            if (!FixedRoute(entry.Operation, operation) || (!entry.WorkStopped && !entry.SuccessfullyStored) ||
                (expire ? !entry.PayloadRetired || entry.AuditDisposition != 1 : entry.PayloadRetired || entry.AuditDisposition != 0))
                throw new CryptographicException("Acceptance audit disposition differs from actual stop custody.");
            var commitment = SHA256.HashData(entry.Exact); var time = entry.TerminalAtUpper;
            var next = expire ? entry.WithoutStoppedAudit() : entry.WithoutWorkingPayload();
            journal.Entries[Convert.ToHexString(entry.Operation)] = next; entry.Dispose(); journal.Revision = checked(journal.Revision + 1);
            return (ProtectedDid2ContactAcceptJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance), commitment, time);
        }
    }

    private async Task MaintainStoppedControlUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease);
        for (var iteration = 0; iteration < 2; iteration++)
        {
            var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
            using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [], commitment = [];
            try
            {
                bool retired; byte audit; ulong stoppedAt;
                if (scope.IsInitiator)
                {
                    using var root = ProtectedDid2ContactStartJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                    var entry = FindControlInitial(root, scope, operation.Span) ?? throw new CryptographicException("Stopped Initial is absent.");
                    if (!entry.WorkStopped && !entry.SuccessfullyStored) return;
                    retired = entry.PayloadRetired; audit = entry.AuditDisposition; stoppedAt = entry.TerminalAtUpper;
                }
                else
                {
                    using var root = ProtectedDid2ContactAcceptJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                    var entry = root.FindScope(scope) ?? throw new CryptographicException("Stopped acceptance is absent.");
                    if (!FixedRoute(entry.Operation, operation.Span)) throw new CryptographicException("Stopped acceptance operation changed.");
                    if (!entry.WorkStopped && !entry.SuccessfullyStored) return;
                    retired = entry.PayloadRetired; audit = entry.AuditDisposition; stoppedAt = entry.TerminalAtUpper;
                }
                using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
                await application.ValidateCompleteStoppedAuditsAsync(ordinary, ct).ConfigureAwait(false);
                if (audit == 2) return;
                var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
                if (retired && checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample) <
                    checked(stoppedAt + SqliteDeepMailboxStore.StoppedAuditSeconds)) return;
                var expire = retired;
                var transformed = BuildControlAuditSuccessor(before, scope, operation.Span, expire);
                after = transformed.After; commitment = transformed.Commitment;
                var effects = await application.CaptureControlAuditEffectsAsync(scope, scope.IsInitiator ? (byte)1 : (byte)2, operation, expire, ordinary, ct).ConfigureAwait(false);
                try
                {
                    var profile = scope.IsInitiator ? MailboxCustodyProfile.StoppedInitial : MailboxCustodyProfile.StoppedAccept;
                    var guards = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct, profile).ConfigureAwait(false);
                    var payloadIndex = scope.IsInitiator ? 9 : 8;
                    if (!FixedRoute(guards[payloadIndex].Digest.Span, SHA256.HashData(before))) throw new CryptographicException("Control stop changed before selection.");
                    var roots = guards.Select((root, index) => new Did2CompactionPlan.Root(root.Kind, root.Selector, root.Digest,
                        index == payloadIndex ? SHA256.HashData(after) : root.Digest, index != payloadIndex,
                        index == payloadIndex ? after : ReadOnlyMemory<byte>.Empty)).ToArray();
                    var plans = new ProtectedDid2CompactionPlan(storage, lease, scope.Network, scope.LocalAccount, scope.Instance);
                    using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                    if (idle.Phase != 0) throw new InvalidDataException("Another exact plan owns control audit recovery.");
                    using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.Application, RandomNumberGenerator.GetBytes(32),
                        scope.Hash, effects.Before, effects.After, roots,
                        [new(expire ? Did2CompactionPlan.Disposition.ExpiredControlAudit : Did2CompactionPlan.Disposition.StoppedControlPayload, operation, commitment)]);
                    var latest = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct, profile).ConfigureAwait(false);
                    if (prepared.Plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), latest).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                        throw new CryptographicException("Control audit predecessor changed before staging.");
                    var final = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                    if (expire && checked(own.Proof.TrustedLowerUnixSeconds + final.SampleSeconds - own.Proof.MonotonicSample) <
                        checked(transformed.StoppedAt + SqliteDeepMailboxStore.StoppedAuditSeconds)) throw new IOException("Control audit deadline is not proven.");
                    await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                    await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); CryptographicOperations.ZeroMemory(commitment); }
        }
    }

    private async Task<Did2MessagingSessionScope> ResolveControlAuditScopeAsync(Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireContactPayloadRetirementProfile(plan); held.RequireOwner(lease);
        using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span).ReadAsync(ct).ConfigureAwait(false);
        Did2MessagingSessionScope? selected = null;
        for (var index = 0; index < catalog.Count; index++)
        {
            var scope = catalog.Scope(index);
            if (!FixedRoute(scope.Hash, plan.SqlSelector)) continue;
            if (selected is not null || catalog.Phase(index) != 2 || scope.IsInitiator != IsInitialControlPlan(plan))
                throw new CryptographicException("Control audit has ambiguous/incomplete native scope.");
            selected = scope;
        }
        return selected ?? throw new CryptographicException("Control audit lost its exact native scope.");
    }

    private async Task ResumeControlAuditStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var scope = await ResolveControlAuditScopeAsync(plan, held, ct).ConfigureAwait(false);
        var payloadIndex = scope.IsInitiator ? 9 : 8;
        var slot = scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var digest = await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false);
        var roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(digest, roots);
        if (observation.Step is Did2CompactionPlan.RecoveryStep.ApplySql or Did2CompactionPlan.RecoveryStep.RecordSqlCommit or Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            using var successor = parts.Use(bytes => plan.OwnSuccessor(payloadIndex, bytes));
            using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            var before = raw.Use(bytes => bytes.ToArray()); var after = successor.Use(bytes => bytes.ToArray());
            try
            {
                var transformed = BuildControlAuditSuccessor(before, scope, plan.ReadRow(0).Selector.Span,
                    plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredControlAudit);
                try
                {
                    if (!FixedRoute(transformed.After, after) || !FixedRoute(transformed.Commitment, plan.ReadRow(0).Commitment.Span))
                        throw new CryptographicException("Control audit changed unrelated commands or exact stop custody.");
                }
                finally { CryptographicOperations.ZeroMemory(transformed.After); CryptographicOperations.ZeroMemory(transformed.Commitment); }
                if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                {
                    using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    await application.ApplyControlAuditAsync(this, plan, scope, scope.IsInitiator ? (byte)1 : (byte)2,
                        plan.ReadRow(0).Selector, ordinary, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                    return;
                }
                roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                var latest = plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots);
                if (latest.Step != observation.Step || latest.RootIndex != observation.RootIndex) throw new CryptographicException("Control audit guards changed before adoption.");
                if (latest.Step == Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                {
                    using var committed = plan.WithSqlCommitted(); await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    return;
                }
                if (latest.RootIndex != payloadIndex) throw new InvalidDataException("Control audit selected an unrelated root.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Control audit adoption conflicted.");
                await RequireExactProtectedMailboxRootAsync(slot, after, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                return;
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only adopted or unchanged abandoning control audit may finish.");
        using var adopted = plan.Phase == 2 ? await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException() : null;
        if (adopted is not null) adopted.Use(bytes => { plan.ValidateSuccessors(bytes); return true; });
        var survivingParts = 0;
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
            if (part is null) continue;
            var offset = index * Did2CompactionPlan.PartBytes; var copy = part.Use(bytes => bytes.ToArray());
            try
            {
                if (index >= plan.PartCount || copy.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset) ||
                    adopted is not null && !adopted.Use(bytes => FixedRoute(bytes.Slice(offset, copy.Length), copy)))
                    throw new CryptographicException("Control audit staging differs from its exact successor.");
                survivingParts++;
            }
            finally { CryptographicOperations.ZeroMemory(copy); }
        }
        if (plan.Phase == 3 && survivingParts != 0)
        {
            if (survivingParts != plan.PartCount) throw new CryptographicException("Abandoning control audit lost successor custody.");
            await RequireUnadoptedControlAuditSuccessorAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
        }
        roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Control audit guards changed before staging disposal.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Control audit guards changed before plan disposal.");
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
    }

    private async Task RequireUnadoptedControlAuditSuccessorAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
        using var successor = parts.Use(bytes => plan.OwnSuccessor(scope.IsInitiator ? 9 : 8, bytes));
        using var raw = await storage.ReadOwnedAsync(scope.IsInitiator ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false)
            ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); var after = successor.Use(bytes => bytes.ToArray());
        try
        {
            var expected = BuildControlAuditSuccessor(before, scope, plan.ReadRow(0).Selector.Span,
                plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredControlAudit);
            try
            {
                if (!FixedRoute(expected.After, after) || !FixedRoute(expected.Commitment, plan.ReadRow(0).Commitment.Span))
                    throw new CryptographicException("Abandoning control audit changed its deterministic successor.");
            }
            finally { CryptographicOperations.ZeroMemory(expected.After); CryptographicOperations.ZeroMemory(expected.Commitment); }
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    internal async Task AbandonUncommittedControlAuditAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (plan.Phase != 1 || !IsStoppedControlPlan(plan)) throw new InvalidOperationException("Only an unchanged prepared control audit may abandon.");
            if (IsPreSessionControlPlan(plan))
            {
                await AbandonPreSessionControlAuditUnderLeaseAsync(plans, plan, held, ct).ConfigureAwait(false);
                return;
            }
            var scope = await ResolveControlAuditScopeAsync(plan, held, ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            using var ordinary = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var effects = await application.CaptureControlAuditEffectsAsync(scope, scope.IsInitiator ? (byte)1 : (byte)2,
                plan.ReadRow(0).Selector, plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredControlAudit, ordinary, ct).ConfigureAwait(false);
            try
            {
                if (!FixedRoute(effects.Before, plan.SqlBefore) || !FixedRoute(effects.After, plan.SqlAfter))
                    throw new CryptographicException("Changed or committed control audit SQL cannot abandon.");
                await RequireUnadoptedControlAuditSuccessorAsync(plans, plan, scope, held, ct).ConfigureAwait(false);
                var roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                    throw new CryptographicException("Changed or committed control audit predecessors cannot abandon.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var abandoning = plan.WithAbandoningBeforeSql(); await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterAbandonRecorded);
#endif
                await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }
}
