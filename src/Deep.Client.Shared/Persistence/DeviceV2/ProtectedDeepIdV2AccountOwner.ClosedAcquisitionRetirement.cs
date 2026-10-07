using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // A held owner producer, not a consumer of exported snapshot flags.
        // Known outcomes, linked acquisitions and retained paths remain pinned.
        internal async Task RetireUnusedClosedDepositAcquisitionAsync(CancellationToken ct = default)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                var dependencies = await RetirementDependencies.CaptureUnderGateAsync(this, ct).ConfigureAwait(false);
                if (dependencies.Dependencies != RetirementDependency.None)
                    throw new IOException("Outstanding mailbox dependencies pin this acquisition; retirement is unavailable.");
                using var state = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var scope = RequireUnusedClosedDeposit(state, acquisition);
                var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                var selected = state.Entries[Convert.ToHexString(acquisition)];
                var row = new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope, acquisition.ToArray(), SHA256.HashData(selected));
                var successor = RemoveUnusedClosedDeposit(state, acquisition, owner.networkId, current.AccountId.Span, instance);
                try
                {
                    var roots = dependencies.Guards.Select(guard => new Did2CompactionPlan.Root(guard.Kind, guard.Selector,
                        guard.Digest, guard.Kind == Did2CompactionPlan.RootKind.Grant ? SHA256.HashData(successor) : guard.Digest,
                        guard.Kind != Did2CompactionPlan.RootKind.Grant,
                        guard.Kind == Did2CompactionPlan.RootKind.Grant ? successor : ReadOnlyMemory<byte>.Empty)).ToArray();
                    using var preparation = idle.Prepare(Did2CompactionPlan.SqlTarget.ProtectedOnly, RandomNumberGenerator.GetBytes(32),
                        scope, new byte[32], new byte[32], roots, [row]);
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    await dependencies.RequireExactGuardsUnderGateAsync(ct).ConfigureAwait(false);
                    await plans.StageAsync(idle, preparation, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                    // The committed plan now owns recovery. The transient
                    // exclusion is not re-minted after original custody retires.
                    await owner.ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(successor); CryptographicOperations.ZeroMemory(scope); }
            }
            finally { gate.Release(); }
        }
    }

    private static byte[] RequireUnusedClosedDeposit(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition)
    {
        var name = Convert.ToHexString(acquisition);
        if (!state.Entries.TryGetValue(name, out var entry) || !ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry) ||
            ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0] != (byte)MailboxCapabilityDomain.Deposit)
            throw new IOException("Only a closed unused deposit acquisition is eligible for this retirement profile.");
        var scope = entry.AsSpan(0, 32).ToArray(); var scopeName = Convert.ToHexString(scope);
        if (!state.Selections.TryGetValue(scopeName, out var selection) || selection.Current is not null || selection.Pending is not null ||
            selection.RetainedTail != name || state.Entries.Values.Count(value => value.AsSpan(0, 32).SequenceEqual(scope)) != 1)
            throw new IOException("Linked or selected mailbox custody cannot be retired by this profile.");
        return scope;
    }

    private static byte[] RemoveUnusedClosedDeposit(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> acquisition,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var scope = RequireUnusedClosedDeposit(state, acquisition);
        try
        {
            var name = Convert.ToHexString(acquisition); var entry = state.Entries[name];
            state.Entries.Remove(name); state.Selections.Remove(Convert.ToHexString(scope));
            CryptographicOperations.ZeroMemory(entry); state.Revision = checked(state.Revision + 1);
            return ProtectedDid2MailboxGrantJournal.Encode(state, network, account, instance);
        }
        finally { CryptographicOperations.ZeroMemory(scope); }
    }

    private static readonly Did2CompactionPlan.RootKind[] ClosedAcquisitionRootKinds =
        [Did2CompactionPlan.RootKind.Ordinary, Did2CompactionPlan.RootKind.Send, Did2CompactionPlan.RootKind.Grant,
         Did2CompactionPlan.RootKind.Read, Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.Attachment,
         Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.NativeFence];
    private static readonly string[] ClosedAcquisitionRootSlots =
        [ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot,
         ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2AttachmentJournal.Slot,
         SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot];

    private static void RequireClosedAcquisitionProfile(Did2CompactionPlan plan)
    {
        if (plan.Target != Did2CompactionPlan.SqlTarget.ProtectedOnly || plan.RootCount != 8 || plan.RowCount != 1 ||
            plan.ReadRow(0).Action != Did2CompactionPlan.Disposition.ReplayScope)
            throw new InvalidDataException("No owned recovery is installed for this protected retirement profile.");
        for (var index = 0; index < 8; index++)
        {
            var root = plan.ReadRoot(index);
            if (root.Kind != ClosedAcquisitionRootKinds[index] || root.Guard != (index != 2) ||
                index < 7 && !FixedRoute(root.Selector.Span, CompactionSlotSelector(ClosedAcquisitionRootSlots[index])))
                throw new InvalidDataException("Stored retirement changed its closed root mapping.");
        }
    }

    private async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadClosedAcquisitionRootsUnderLeaseAsync(
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireClosedAcquisitionProfile(plan); held.RequireOwner(lease);
        var exact = plan.Exact; var account = exact.Slice(32, 32); var instance = exact.Slice(64, 32);
        using var actualPlan = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId, account, instance, ct).ConfigureAwait(false);
        if (!FixedRoute(actualPlan.Exact.Span, exact.Span)) throw new CryptographicException("Retirement plan changed during readback.");
        var result = new List<Did2CompactionPlan.RootReadback>(8);
        for (var index = 0; index < 7; index++)
        {
            using var raw = await storage.ReadOwnedAsync(ClosedAcquisitionRootSlots[index], ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Retirement lost a mandatory dependency root.");
            switch (index)
            {
                case 0: using (var state = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 1: using (var state = raw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 2: using (var state = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 3: using (var state = raw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 4: using (var state = raw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 5: using (var state = raw.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, account.Span, instance.Span))) { } break;
                case 6:
                    using (var actual = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage, networkId, account, ct).ConfigureAwait(false))
                        if (!FixedRoute(actual.Use(bytes => SHA256.HashData(bytes)), raw.Use(bytes => SHA256.HashData(bytes))))
                            throw new CryptographicException("Retirement registration changed during readback.");
                    break;
            }
            result.Add(new(ClosedAcquisitionRootKinds[index], CompactionSlotSelector(ClosedAcquisitionRootSlots[index]), raw.Use(bytes => SHA256.HashData(bytes))));
        }
        result.Add(await SqliteDeepIdV2AccountGeneration.ReadStoredPlanNativeFenceUnderLeaseAsync(storage, lease, sqlStatePath, plan, held, ct).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
    }

    private void RequireClosedAcquisitionSuccessor(Did2CompactionPlan plan, ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var state = ProtectedDid2MailboxGrantJournal.Decode(predecessor, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
        var row = plan.ReadRow(0); var scope = RequireUnusedClosedDeposit(state, row.Selector.Span);
        try
        {
            if (!FixedRoute(scope, plan.SqlSelector) || !FixedRoute(SHA256.HashData(state.Entries[Convert.ToHexString(row.Selector.Span)]), row.Commitment.Span))
                throw new CryptographicException("Retirement selected a different original acquisition.");
            var expected = RemoveUnusedClosedDeposit(state, row.Selector.Span, networkId, plan.Exact.Slice(32, 32).Span, plan.Exact.Slice(64, 32).Span);
            try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Retirement successor changed unrelated work."); }
            finally { CryptographicOperations.ZeroMemory(expected); }
        }
        finally { CryptographicOperations.ZeroMemory(scope); }
    }

    private async Task ResumeClosedAcquisitionStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans,
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var roots = await ReadClosedAcquisitionRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(new byte[32], roots);
        if (plan.Phase == 1 || observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            using var successor = parts.Use(bytes => plan.OwnSuccessor(2, bytes));
            using var predecessor = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Retirement lost original grant custody before adoption.");
            var before = predecessor.Use(bytes => bytes.ToArray()); var after = successor.Use(bytes => bytes.ToArray());
            try
            {
                RequireClosedAcquisitionSuccessor(plan, before, after);
                roots = await ReadClosedAcquisitionRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
                var latest = plan.ObserveReadback(new byte[32], roots);
                if (plan.Phase == 1)
                {
                    if (latest.Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                        throw new CryptographicException("Protected-only retirement changed before its commit boundary.");
                    using var committed = plan.WithSqlCommitted(); // No SQL mutation in this profile.
                    await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                    return;
                }
                if (latest.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || latest.RootIndex != 2)
                    throw new CryptographicException("Retirement dependencies changed before grant adoption.");
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, before, after, ct).ConfigureAwait(false))
                    throw new CryptographicException("Retirement grant adoption conflicted.");
                using var actual = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Retired grant root disappeared.");
                if (!actual.Use(bytes => FixedRoute(bytes, after))) throw new CryptographicException("Retirement grant adoption readback differs.");
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
                return;
            }
            finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only completed or unchanged abandoning retirement can clear.");
        await ValidateFinishingClosedAcquisitionPartsAsync(plan, ct).ConfigureAwait(false);
        roots = await ReadClosedAcquisitionRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(new byte[32], roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Retirement dependencies changed before staging disposal.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        roots = await ReadClosedAcquisitionRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        _ = plan.ObserveReadback(new byte[32], roots);
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
    }

    private async Task ValidateFinishingClosedAcquisitionPartsAsync(Did2CompactionPlan plan, CancellationToken ct)
    {
        using var adopted = plan.Phase == 2 ? await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Retirement successor is absent.") : null;
        if (adopted is not null) adopted.Use(bytes => { plan.ValidateSuccessors(bytes); return true; });
        var parts = new List<OwnedDeepSecret>();
        try
        {
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
                if (part is null) continue; parts.Add(part);
                var offset = index * Did2CompactionPlan.PartBytes;
                if (index >= plan.PartCount || part.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset))
                    throw new InvalidDataException("Retirement has an unexpected successor part.");
                if (adopted is not null)
                {
                    var value = part.Use(bytes => bytes.ToArray());
                    try { if (!adopted.Use(bytes => FixedRoute(bytes.Slice(offset, part.Length), value))) throw new CryptographicException("Retirement staging differs from its adopted root."); }
                    finally { CryptographicOperations.ZeroMemory(value); }
                }
            }
            if (plan.Phase == 3 && parts.Count != 0)
            {
                if (parts.Count != plan.PartCount) throw new InvalidDataException("Abandoning retirement lost successor parts.");
                var bytes = new byte[plan.SuccessorBytes];
                try { var offset = 0; foreach (var part in parts) { part.CopyTo(bytes.AsSpan(offset)); offset += part.Length; } plan.ValidateSuccessors(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally { foreach (var part in parts) part.Dispose(); }
    }

    internal async Task AbandonUncommittedClosedAcquisitionRetirementAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (plan.Phase != 1) throw new InvalidOperationException("Only a prepared protected retirement can be abandoned.");
            var roots = await ReadClosedAcquisitionRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(new byte[32], roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                throw new CryptographicException("Only the exact unchanged retirement predecessor can be abandoned.");
            using var abandoning = plan.WithAbandoningBeforeSql(); await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }
}
