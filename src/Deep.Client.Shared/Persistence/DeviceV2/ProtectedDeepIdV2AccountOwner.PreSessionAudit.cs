using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static ProtectedDid2ContactStartJournal.Entry FindPreSessionInitial(ProtectedDid2ContactStartJournal.State state, ReadOnlySpan<byte> operation)
    {
        ProtectedDid2ContactStartJournal.Entry? selected = null;
        foreach (var entry in state.Entries.Values)
        {
            var op = InitialMailboxOperation(entry.Intent);
            try
            {
                if (!FixedRoute(op, operation)) continue;
                if (selected is not null) throw new CryptographicException("Pre-session Initial operation is ambiguous.");
                selected = entry;
            }
            finally { CryptographicOperations.ZeroMemory(op); }
        }
        if (selected is null || !selected.WorkStopped || selected.NativeStopMode != 2)
            throw new CryptographicException("Pre-session audit lost its exact stopped Initial owner.");
        return selected;
    }

    private static (byte[] After, byte[] Commitment, ulong StoppedAt) BuildPreSessionAuditSuccessor(ReadOnlySpan<byte> before,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance, ReadOnlySpan<byte> operation, bool expire)
    {
        using var state = ProtectedDid2ContactStartJournal.Decode(before, network, account, instance);
        var selected = FindPreSessionInitial(state, operation);
        if (expire ? !selected.PayloadRetired || selected.AuditDisposition != 1 : selected.PayloadRetired || selected.AuditDisposition != 0)
            throw new CryptographicException("Pre-session audit disposition differs from actual stop custody.");
        var commitment = SHA256.HashData(selected.Exact); var stoppedAt = selected.StoppedAtUpper;
        var next = expire ? selected.WithoutStoppedAudit(network, account) : selected.WithoutWorkingPayload(network, account);
        state.Entries[Convert.ToHexString(selected.Intent)] = next; selected.Dispose(); state.Revision = checked(state.Revision + 1);
        return (ProtectedDid2ContactStartJournal.Encode(state, network, account, instance), commitment, stoppedAt);
    }

    internal async Task RequireClosedPreSessionControlUnderLeaseAsync(ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> operation, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var drafts = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, account.Span, instance.Span));
        var draft = FindPreSessionInitial(drafts, operation.Span);
        var keys = await ProtectedInitialKeyRetirementJournal.ReadAsync(storage, networkId, account, ct).ConfigureAwait(false);
        var cancellation = keys.FindCancellation(draft.Intent);
        if (cancellation is null || cancellation.Phase != 2 || !FixedRoute(cancellation.ScopeHash, draft.CancellationBinding))
            throw new CryptographicException("Pre-session payload cleanup cannot precede its exact completed key destruction.");
        await SqliteDeepIdV2AccountGeneration.RequireCancellationNativeAbsenceUnderLeaseAsync(storage, sqlStatePath,
            networkId, account, instance, cancellation, held, lease, ct).ConfigureAwait(false);
        using var source = await SqliteDeepIdV2AccountGeneration.OpenExistingCancellationSourceUnderLeaseAsync(storage,
            sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        await source.RetireCancelledInitialUnderLeaseAsync(sqlStatePath, draft.Intent.ToArray(), held, lease, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    private async Task MaintainPreSessionControlUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        ReadOnlyMemory<byte> intent, ReadOnlyMemory<byte> instance, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var operation = InitialMailboxOperation(intent.Span);
        try
        {
            for (var iteration = 0; iteration < 2; iteration++)
            {
                await RequireClosedPreSessionControlUnderLeaseAsync(current.AccountId, instance, operation, held, ct).ConfigureAwait(false);
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                var before = raw.Use(bytes => bytes.ToArray()); byte[] after = [], commitment = [], selector = [];
                try
                {
                    using var drafts = ProtectedDid2ContactStartJournal.Decode(before, networkId, current.AccountId.Span, instance.Span);
                    var draft = FindPreSessionInitial(drafts, operation);
                    using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
                    using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
                        sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
                    await application.ValidateCompleteStoppedAuditsAsync(ordinary, ct).ConfigureAwait(false);
                    if (draft.AuditDisposition == 2) return;
                    var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
                    var expire = draft.PayloadRetired;
                    if (expire && checked(own.Proof.TrustedLowerUnixSeconds + first.SampleSeconds - own.Proof.MonotonicSample) <
                        checked(draft.StoppedAtUpper + SqliteDeepMailboxStore.StoppedAuditSeconds)) return;
                    var changed = BuildPreSessionAuditSuccessor(before, networkId, current.AccountId.Span, instance.Span, operation, expire);
                    after = changed.After; commitment = changed.Commitment; selector = application.PreSessionControlAuditSelector(operation);
                    var effects = await application.CapturePreSessionControlAuditEffectsAsync(operation, expire, ordinary, ct).ConfigureAwait(false);
                    try
                    {
                        var guards = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct, MailboxCustodyProfile.StoppedInitial).ConfigureAwait(false);
                        if (!FixedRoute(guards[9].Digest.Span, SHA256.HashData(before))) throw new CryptographicException("Pre-session draft changed before staging.");
                        var roots = guards.Select((root, index) => new Did2CompactionPlan.Root(root.Kind, root.Selector, root.Digest,
                            index == 9 ? SHA256.HashData(after) : root.Digest, index != 9, index == 9 ? after : ReadOnlyMemory<byte>.Empty)).ToArray();
                        var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, instance.Span);
                        using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                        if (idle.Phase != 0) throw new InvalidDataException("Another exact plan owns local cleanup.");
                        using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.Application, RandomNumberGenerator.GetBytes(32), selector,
                            effects.Before, effects.After, roots, [new(expire ? Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit :
                                Did2CompactionPlan.Disposition.PreSessionInitialPayload, operation, commitment)]);
                        await RequireClosedPreSessionControlUnderLeaseAsync(current.AccountId, instance, operation, held, ct).ConfigureAwait(false);
                        var latest = await CaptureCompletedContactSendGuardsUnderLeaseAsync(current, held, ct, MailboxCustodyProfile.StoppedInitial).ConfigureAwait(false);
                        if (prepared.Plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), latest).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                            throw new CryptographicException("Pre-session cleanup predecessor changed before publication.");
                        var final = await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
                        if (expire && checked(own.Proof.TrustedLowerUnixSeconds + final.SampleSeconds - own.Proof.MonotonicSample) <
                            checked(changed.StoppedAt + SqliteDeepMailboxStore.StoppedAuditSeconds)) throw new IOException("Pre-session audit deadline is not proven.");
                        await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                    }
                    finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
                }
                finally { foreach (var bytes in new[] { before, after, commitment, selector }) CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(operation); }
    }

    private async Task RequirePreSessionPlanSuccessorAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
        using var successor = parts.Use(bytes => plan.OwnSuccessor(9, bytes));
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var before = raw.Use(bytes => bytes.ToArray()); var after = successor.Use(bytes => bytes.ToArray());
        try
        {
            var expected = BuildPreSessionAuditSuccessor(before, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span,
                plan.ReadRow(0).Selector.Span, plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit);
            try
            {
                if (!FixedRoute(expected.After, after) || !FixedRoute(expected.Commitment, plan.ReadRow(0).Commitment.Span))
                    throw new CryptographicException("Pre-session cleanup changed unrelated commands or stop custody.");
            }
            finally { CryptographicOperations.ZeroMemory(expected.After); CryptographicOperations.ZeroMemory(expected.Commitment); }
        }
        finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
    }

    private async Task AbandonPreSessionControlAuditUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireContactPayloadRetirementProfile(plan);
        var account = plan.Exact.Slice(32, 32); var instance = plan.Exact.Slice(64, 32); var operation = plan.ReadRow(0).Selector;
        await RequireClosedPreSessionControlUnderLeaseAsync(account, instance, operation, held, ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
            sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var ordinary = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, account.Span, instance.Span));
        var selector = application.PreSessionControlAuditSelector(operation.Span);
        var effects = await application.CapturePreSessionControlAuditEffectsAsync(operation,
            plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit, ordinary, ct).ConfigureAwait(false);
        try
        {
            if (!FixedRoute(selector, plan.SqlSelector) || !FixedRoute(effects.Before, plan.SqlBefore) || !FixedRoute(effects.After, plan.SqlAfter))
                throw new CryptographicException("Changed or committed pre-session SQL cannot abandon.");
            await RequirePreSessionPlanSuccessorAsync(plans, plan, held, ct).ConfigureAwait(false);
            var roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Changed pre-session predecessors cannot abandon.");
            using var abandoning = plan.WithAbandoningBeforeSql(); await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterAbandonRecorded);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { foreach (var bytes in new[] { selector, effects.Before, effects.After }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task ResumePreSessionControlAuditStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireContactPayloadRetirementProfile(plan);
        if (!IsPreSessionControlPlan(plan)) throw new InvalidDataException("Only a pre-session Initial plan can select this recovery.");
        var account = plan.Exact.Slice(32, 32); var instance = plan.Exact.Slice(64, 32); var operation = plan.ReadRow(0).Selector;
        await RequireClosedPreSessionControlUnderLeaseAsync(account, instance, operation, held, ct).ConfigureAwait(false);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
            sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        var selector = application.PreSessionControlAuditSelector(operation.Span);
        try
        {
            if (!FixedRoute(selector, plan.SqlSelector)) throw new CryptographicException("Pre-session plan borrowed another account selection.");
            var roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            var observation = plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), roots);
            if (observation.Step is Did2CompactionPlan.RecoveryStep.ApplySql or Did2CompactionPlan.RecoveryStep.RecordSqlCommit or Did2CompactionPlan.RecoveryStep.AdoptRoot)
            {
                await RequirePreSessionPlanSuccessorAsync(plans, plan, held, ct).ConfigureAwait(false);
                if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                {
                    using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var ordinary = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    await application.ApplyPreSessionControlAuditAsync(this, plan, ordinary, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                    return;
                }
                roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                var latest = plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), roots);
                if (latest != observation) throw new CryptographicException("Pre-session recovery guards changed.");
                if (latest.Step == Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                {
                    using var committed = plan.WithSqlCommitted(); await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    return;
                }
                if (latest.RootIndex != 9) throw new InvalidDataException("Pre-session cleanup selected another root.");
                using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
                using var next = parts.Use(bytes => plan.OwnSuccessor(9, bytes));
                using var previous = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                var before = previous.Use(bytes => bytes.ToArray()); var after = next.Use(bytes => bytes.ToArray());
                try
                {
                    ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                    if (!await storage.CompareExchangeAsync(ProtectedDid2ContactStartJournal.Slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Pre-session payload adoption conflicted.");
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2ContactStartJournal.Slot, after, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                return;
            }
            if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3)) throw new InvalidDataException("Only adopted or unchanged aborting pre-session plan may finish.");
            using var adopted = plan.Phase == 2 ? await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException() : null;
            if (adopted is not null) adopted.Use(bytes => { plan.ValidateSuccessors(bytes); return true; });
            var count = 0;
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
                if (part is null) continue;
                var offset = index * Did2CompactionPlan.PartBytes; var copy = part.Use(bytes => bytes.ToArray());
                try
                {
                    if (index >= plan.PartCount || copy.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset) ||
                        adopted is not null && !adopted.Use(bytes => FixedRoute(bytes.Slice(offset, copy.Length), copy))) throw new CryptographicException("Pre-session staging differs from its exact successor.");
                    count++;
                }
                finally { CryptographicOperations.ZeroMemory(copy); }
            }
            if (plan.Phase == 3 && count != 0)
            {
                if (count != plan.PartCount) throw new CryptographicException("Pre-session abort lost partial staging.");
                await RequirePreSessionPlanSuccessorAsync(plans, plan, held, ct).ConfigureAwait(false);
            }
            roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
                throw new CryptographicException("Pre-session guards changed before staging disposal.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
            roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(await application.ReadCompleteMailboxStateProjectionAsync(selector, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
                throw new CryptographicException("Pre-session guards changed before plan disposal.");
            using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
        }
        finally { CryptographicOperations.ZeroMemory(selector); }
    }
}
