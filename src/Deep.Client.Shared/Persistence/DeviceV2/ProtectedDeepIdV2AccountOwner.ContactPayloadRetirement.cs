using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static byte[] RemoveCompletedInitialPayload(ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> scopeHash,
        ReadOnlySpan<byte> sendKey, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        using var state = ProtectedDid2ContactStartJournal.Decode(predecessor, network, account, instance);
        ProtectedDid2ContactStartJournal.Entry? selected = null;
        foreach (var entry in state.Entries.Values)
        {
            var operation = InitialMailboxOperation(entry.Intent); var key = ProtectedDid2MailboxSendJournal.Key(scopeHash, operation);
            try
            {
                if (!FixedRoute(key, sendKey)) continue;
                if (selected is not null) throw new CryptographicException("Initial payload selection is ambiguous.");
                selected = entry;
            }
            finally { CryptographicOperations.ZeroMemory(operation); CryptographicOperations.ZeroMemory(key); }
        }
        if (selected is null || selected.WorkStopped || !selected.SuccessfullyStored) throw new CryptographicException("Initial payload retirement lost its successful exact draft.");
        if (selected.PayloadRetired)
        {
            // The later exact send-cleanup plan still owns a real consent-root
            // transition; advance only its revision, never recreate audit/payload.
            state.Revision = checked(state.Revision + 1);
            return ProtectedDid2ContactStartJournal.Encode(state, network, account, instance);
        }
        var name = Convert.ToHexString(selected.Intent);
        state.Entries[name] = selected.WithoutWorkingPayload(network, account); selected.Dispose();
        state.Revision = checked(state.Revision + 1);
        return ProtectedDid2ContactStartJournal.Encode(state, network, account, instance);
    }

    private static byte[] RemoveCompletedContactAcceptPayload(ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> scopeHash,
        ReadOnlySpan<byte> sendKey, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        using var state = ProtectedDid2ContactAcceptJournal.Decode(predecessor, network, account, instance);
        var scopeCopy = scopeHash.ToArray(); var keyCopy = sendKey.ToArray();
        try
        {
            var command = state.Entries.Values.SingleOrDefault(entry => FixedRoute(entry.Scope.Hash, scopeCopy) &&
                FixedRoute(ProtectedDid2MailboxSendJournal.Key(entry.Scope.Hash, entry.Operation), keyCopy)) ??
                throw new CryptographicException("Contact payload retirement lost its exact explicit winner.");
            if (command.WorkStopped || !command.SuccessfullyStored) throw new CryptographicException("A stopped or unconfirmed payload cannot use successful-work retirement.");
            if (command.PayloadRetired)
            {
                state.Revision = checked(state.Revision + 1);
                return ProtectedDid2ContactAcceptJournal.Encode(state, network, account, instance);
            }
            var name = Convert.ToHexString(command.Operation);
            var marker = command.WithoutWorkingPayload();
            state.Entries[name] = marker; command.Dispose(); state.Revision = checked(state.Revision + 1);
            return ProtectedDid2ContactAcceptJournal.Encode(state, network, account, instance);
        }
        finally { CryptographicOperations.ZeroMemory(scopeCopy); CryptographicOperations.ZeroMemory(keyCopy); }
    }

    private static void RequireContactPayloadRetirementProfile(Did2CompactionPlan plan)
    {
        var stopped = IsStoppedControlPlan(plan);
        if (plan.Target != (stopped ? Did2CompactionPlan.SqlTarget.Application : Did2CompactionPlan.SqlTarget.ProtectedOnly) || plan.RowCount != 1 || plan.RootCount != 10 ||
            plan.ReadRow(0).Action is not (Did2CompactionPlan.Disposition.ContactAcceptPayload or Did2CompactionPlan.Disposition.InitialPayload or
                Did2CompactionPlan.Disposition.StoppedControlPayload or Did2CompactionPlan.Disposition.ExpiredControlAudit or
                Did2CompactionPlan.Disposition.PreSessionInitialPayload or Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit))
            throw new InvalidDataException("Contact payload retirement has an unknown closed profile.");
        for (var index = 0; index < 8; index++)
        {
            var root = plan.ReadRoot(index);
            if (root.Kind != ClosedAcquisitionRootKinds[index] || root.Guard != (stopped || index != 1) ||
                index < 7 && !FixedRoute(root.Selector.Span, CompactionSlotSelector(ClosedAcquisitionRootSlots[index])))
                throw new InvalidDataException("Contact payload retirement changed its exact root mapping.");
        }
        var initial = IsInitialControlPlan(plan);
        var guardIndex = initial ? 8 : 9; var payloadIndex = initial ? 9 : 8;
        if (plan.ReadRoot(guardIndex).Kind != Did2CompactionPlan.RootKind.MailboxContactCustody || !plan.ReadRoot(guardIndex).Guard ||
            plan.ReadRoot(payloadIndex).Kind != (initial ? Did2CompactionPlan.RootKind.ContactStart : Did2CompactionPlan.RootKind.ContactAccept) || plan.ReadRoot(payloadIndex).Guard ||
            !FixedRoute(plan.ReadRoot(payloadIndex).Selector.Span, CompactionSlotSelector(initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot)))
            throw new InvalidDataException("Contact payload retirement lost its independent guards or consent successor.");
    }

    internal async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadContactPayloadRetirementRootsAsync(
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireContactPayloadRetirementProfile(plan); held.RequireOwner(lease);
        using var actual = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId,
            plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), ct).ConfigureAwait(false);
        if (!FixedRoute(actual.Exact.Span, plan.Exact.Span)) throw new CryptographicException("Contact retirement plan changed.");
        var roots = await ReadMailboxProtectedRootsUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), held, ct).ConfigureAwait(false);
        roots.Add(await SqliteDeepIdV2AccountGeneration.ReadStoredPlanNativeFenceUnderLeaseAsync(storage, lease, sqlStatePath, plan, held, ct).ConfigureAwait(false));
        var initial = IsInitialControlPlan(plan); var stopped = IsStoppedControlPlan(plan);
        var slot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        if (initial) roots.Add(stopped
            ? await ReadStoppedControlCustodyUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), held, true, ct).ConfigureAwait(false)
            : await ReadMailboxInitialCustodyUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), held, ct).ConfigureAwait(false));
        using var consent = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Contact retirement lost its mandatory consent root.");
        if (initial)
        { using var decoded = consent.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span)); }
        else
        { using var decoded = consent.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span)); }
        roots.Add(new(initial ? Did2CompactionPlan.RootKind.ContactStart : Did2CompactionPlan.RootKind.ContactAccept, CompactionSlotSelector(slot),
            consent.Use(bytes => SHA256.HashData(bytes))));
        if (!initial) roots.Add(stopped
            ? await ReadStoppedControlCustodyUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), held, false, ct).ConfigureAwait(false)
            : await ReadMailboxContactCustodyUnderLeaseAsync(plan.Exact.Slice(32, 32), plan.Exact.Slice(64, 32), held, ct).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return roots;
    }

    private static bool IsStoppedControlPlan(Did2CompactionPlan plan) => plan.RowCount == 1 &&
        plan.ReadRow(0).Action is Did2CompactionPlan.Disposition.StoppedControlPayload or Did2CompactionPlan.Disposition.ExpiredControlAudit or
            Did2CompactionPlan.Disposition.PreSessionInitialPayload or Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit;

    private static bool IsPreSessionControlPlan(Did2CompactionPlan plan) => plan.RowCount == 1 &&
        plan.ReadRow(0).Action is Did2CompactionPlan.Disposition.PreSessionInitialPayload or Did2CompactionPlan.Disposition.ExpiredPreSessionInitialAudit;

    private static bool IsInitialControlPlan(Did2CompactionPlan plan) =>
        plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.InitialPayload ||
        IsStoppedControlPlan(plan) && plan.ReadRoot(9).Kind == Did2CompactionPlan.RootKind.ContactStart;

    private static void RequireContactConsentSuccessor(Did2CompactionPlan plan, ReadOnlySpan<byte> before, ReadOnlySpan<byte> after)
    {
        var expected = plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.InitialPayload
            ? RemoveCompletedInitialPayload(before, plan.SqlSelector, plan.ReadRow(0).Selector.Span,
                plan.Exact.Slice(16, 16).Span, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span)
            : RemoveCompletedContactAcceptPayload(before, plan.SqlSelector, plan.ReadRow(0).Selector.Span,
            plan.Exact.Slice(16, 16).Span, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        try { if (!FixedRoute(expected, after)) throw new CryptographicException("Consent successor changed unrelated commands or exact consent facts."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private async Task RequireUnadoptedContactPayloadSuccessorsAsync(Did2CompactionPlan plan, OwnedDeepSecret successors,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireContactPayloadRetirementProfile(plan); held.RequireOwner(lease);
        if (plan.Phase is not (1 or 3)) throw new InvalidDataException("Only unchanged contact predecessors may abandon.");
        using var sendBefore = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        var initial = plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.InitialPayload;
        using var consentBefore = await storage.ReadOwnedAsync(initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var sendAfter = successors.Use(bytes => plan.OwnSuccessor(1, bytes));
        using var consentAfter = successors.Use(bytes => plan.OwnSuccessor(initial ? 9 : 8, bytes));
        var originalSend = sendBefore.Use(bytes => bytes.ToArray()); var nextSend = sendAfter.Use(bytes => bytes.ToArray());
        var originalConsent = consentBefore.Use(bytes => bytes.ToArray()); var nextConsent = consentAfter.Use(bytes => bytes.ToArray());
        try
        {
            RequireCompletedContactSendSuccessor(plan, originalSend, nextSend);
            RequireContactConsentSuccessor(plan, originalConsent, nextConsent);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally
        {
            foreach (var bytes in new[] { originalSend, nextSend, originalConsent, nextConsent }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private async Task ValidateAbandoningContactPayloadPartsAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var count = 0;
        for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
            if (part is null) continue;
            var offset = index * Did2CompactionPlan.PartBytes;
            if (index >= plan.PartCount || part.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset))
                throw new InvalidDataException("Abandoning contact retirement has an unexpected successor part.");
            count++;
        }
        if (count == 0) return; // Atomic batch disposal may already have completed before the reply was lost.
        if (count != plan.PartCount) throw new InvalidDataException("Abandoning contact retirement lost successor custody.");
        using var successors = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
        await RequireUnadoptedContactPayloadSuccessorsAsync(plan, successors, held, ct).ConfigureAwait(false);
    }

    private async Task ResumeContactPayloadRetirementStepAsync(ProtectedDid2CompactionPlan plans,
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(new byte[32], roots);
        var initial = plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.InitialPayload;
        var payloadIndex = initial ? 9 : 8;
        var payloadSlot = initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot;
        if (plan.Phase == 1 || observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            using var sendAfter = parts.Use(bytes => plan.OwnSuccessor(1, bytes));
            using var consentAfter = parts.Use(bytes => plan.OwnSuccessor(payloadIndex, bytes));
            var index = plan.Phase == 1 ? 1 : observation.RootIndex;
            if (index != 1 && index != payloadIndex) throw new InvalidDataException("Contact retirement selected an unrelated root.");
            var slot = index == 1 ? ProtectedDid2MailboxSendJournal.Slot : payloadSlot;
            using var predecessor = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Contact retirement predecessor is absent.");
            var before = predecessor.Use(bytes => bytes.ToArray());
            var after = (index == 1 ? sendAfter : consentAfter).Use(bytes => bytes.ToArray());
            try
            {
                if (index == 1) RequireCompletedContactSendSuccessor(plan, before, after);
                else RequireContactConsentSuccessor(plan, before, after);
                if (plan.Phase == 1)
                {
                    using var consentBefore = await storage.ReadOwnedAsync(payloadSlot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    var original = consentBefore.Use(bytes => bytes.ToArray()); var expected = consentAfter.Use(bytes => bytes.ToArray());
                    try { RequireContactConsentSuccessor(plan, original, expected); }
                    finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(expected); }
                }
                roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
                var latest = plan.ObserveReadback(new byte[32], roots);
                if (plan.Phase == 1)
                {
                    if (latest.Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit) throw new CryptographicException("Contact retirement guards changed before commit.");
                    using var committed = plan.WithSqlCommitted(); await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    return;
                }
                if (latest.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || latest.RootIndex != index)
                    throw new CryptographicException("Contact retirement guards changed before adoption.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(slot, before, after, ct).ConfigureAwait(false)) throw new CryptographicException("Contact root adoption conflicted.");
                using var read = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                if (!read.Use(bytes => FixedRoute(bytes, after))) throw new CryptographicException("Contact root readback differs.");
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                return;
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only adopted or unchanged abandoning contact retirement can clear.");
        using var send = plan.Phase == 2 ? await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException() : null;
        using var consent = plan.Phase == 2 ? await storage.ReadOwnedAsync(payloadSlot, ct).ConfigureAwait(false) ?? throw new InvalidDataException() : null;
        var aggregate = plan.Phase == 2 ? new byte[checked(send!.Length + consent!.Length)] : [];
        try
        {
            if (plan.Phase == 2)
            {
                send!.CopyTo(aggregate); consent!.CopyTo(aggregate.AsSpan(send.Length)); plan.ValidateSuccessors(aggregate);
                for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
                {
                    using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
                    if (part is null) continue;
                    var offset = index * Did2CompactionPlan.PartBytes;
                    if (index >= plan.PartCount || part.Length != Math.Min(Did2CompactionPlan.PartBytes, aggregate.Length - offset) ||
                        !part.Use(bytes => FixedRoute(bytes, aggregate.AsSpan(offset, bytes.Length))))
                        throw new CryptographicException("Contact retirement staging differs from its adopted successors.");
                }
            }
            else await ValidateAbandoningContactPayloadPartsAsync(plans, plan, held, ct).ConfigureAwait(false);
            roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(new byte[32], roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan) throw new CryptographicException("Contact retirement guards changed before disposal.");
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
            roots = await ReadContactPayloadRetirementRootsAsync(plan, held, ct).ConfigureAwait(false);
            _ = plan.ObserveReadback(new byte[32], roots);
            using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
        }
        finally { CryptographicOperations.ZeroMemory(aggregate); }
    }
}
