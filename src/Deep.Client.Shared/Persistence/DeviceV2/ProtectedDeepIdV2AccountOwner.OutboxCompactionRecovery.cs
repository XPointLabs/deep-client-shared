using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal static bool IsStoppedOutboxPlan(Did2CompactionPlan plan) =>
        plan.RowCount > 0 && plan.ReadRow(0).Action is Did2CompactionPlan.Disposition.StoppedOutboxPayload or Did2CompactionPlan.Disposition.ExpiredTerminalAudit;
    private static readonly Did2CompactionPlan.RootKind[] OrdinaryOutboxRootKinds =
    [
        Did2CompactionPlan.RootKind.Ordinary, Did2CompactionPlan.RootKind.Send, Did2CompactionPlan.RootKind.Grant,
        Did2CompactionPlan.RootKind.Read, Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.MessagingFloor,
        Did2CompactionPlan.RootKind.Attachment, Did2CompactionPlan.RootKind.AccountRegistration,
        Did2CompactionPlan.RootKind.MessagingHistoryCheckpoint, Did2CompactionPlan.RootKind.MessagingPeerBootstrap
    ];
    private static string[] OrdinaryOutboxSlots(Did2MessagingSessionScope scope) =>
    [
        ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot,
        ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot,
        ProtectedDid2AttachmentJournal.Slot, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
        Did2MessagingHistoryCheckpoint.Slot(scope), ProtectedDid2MessagingPeerBootstrap.Slot(scope)
    ];

    private static Did2MessagingSessionScope ResolveOrdinaryOutboxScope(Did2CompactionPlan plan,
        ProtectedDid2MessagingSessionCatalog.Snapshot catalog)
    {
        if (plan.Target != Did2CompactionPlan.SqlTarget.Application || plan.RootCount != OrdinaryOutboxRootKinds.Length ||
            plan.SuccessorBytes < ProtectedDid2DirectTextJournal.HeaderBytes + (IsStoppedOutboxPlan(plan) ? 0 : ProtectedDid2MailboxSendJournal.HeaderBytes) ||
            plan.SuccessorBytes > ProtectedDid2DirectTextJournal.MaximumBytes + ProtectedDid2MailboxSendJournal.MaximumBytes)
            throw new InvalidDataException("No owned recovery is installed for this application compaction profile.");
        for (var index = 0; index < plan.RowCount; index++)
            if (plan.ReadRow(index).Action != (IsStoppedOutboxPlan(plan)
                ? plan.ReadRow(0).Action : Did2CompactionPlan.Disposition.OutboxPayload))
                throw new InvalidDataException("Ordinary recovery cannot consume another disposition.");
        for (var index = 0; index < catalog.Count; index++)
            if (catalog.Phase(index) == 2 && FixedRoute(catalog.Scope(index).Hash, plan.SqlSelector)) return catalog.Scope(index);
        throw new InvalidDataException("Stored ordinary batch has no initialized SQL selector.");
    }

    internal static async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadOrdinaryOutboxRootsUnderLeaseAsync(
        IDeepSecureStorage storage, Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        HeldDeepIdV2AccountLease held, DeepIdV2AccountFileLease lease, CancellationToken ct)
    {
        using var borrowed = held.BorrowFor(lease);
        using var current = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, scope.Network.ToArray(),
            scope.LocalAccount.ToArray(), scope.Instance.ToArray(), ct).ConfigureAwait(false);
        if (!FixedRoute(current.Exact.Span, plan.Exact.Span)) throw new CryptographicException("Stored ordinary plan changed during recovery.");
        using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, scope.Network, scope.LocalAccount, scope.Instance).ReadAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(ResolveOrdinaryOutboxScope(plan, catalog).Exact, scope.Exact)) throw new InvalidDataException("Wrong ordinary SQL scope.");
        var slots = OrdinaryOutboxSlots(scope); var result = new List<Did2CompactionPlan.RootReadback>(slots.Length);
        for (var index = 0; index < slots.Length; index++)
        {
            var expected = plan.ReadRoot(index); var selector = CompactionSlotSelector(slots[index]);
            if (expected.Kind != OrdinaryOutboxRootKinds[index] || expected.Guard != (index >= (IsStoppedOutboxPlan(plan) ? 1 : 2)) || !FixedRoute(expected.Selector.Span, selector))
                throw new InvalidDataException("Ordinary batch changed its closed root mapping.");
            using var raw = await storage.ReadOwnedAsync(slots[index], ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Ordinary batch lost a mandatory dependency root.");
            switch (index)
            {
                case 0: using (raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance))) { } break;
                case 1: using (raw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance))) { } break;
                case 2: using (raw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance))) { } break;
                case 3: using (raw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance))) { } break;
                case 4:
                    if (!raw.Use(bytes => FixedRoute(bytes, catalog.Exact.Span))) throw new CryptographicException("Ordinary catalog changed during recovery."); break;
                case 5:
                    var floor = raw.Use(bytes => Did2MessagingFloor.Decode(bytes, scope));
                    if (floor.Phase != 1 || floor.Status != 1) throw new InvalidDataException("Ordinary recovery lost its stable active native floor."); break;
                case 6: using (raw.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance))) { } break;
                case 7:
                    using (var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(storage,
                        scope.Network.ToArray(), scope.LocalAccount.ToArray(), ct).ConfigureAwait(false))
                        if (!registration.Use(bytes => FixedRoute(bytes.Slice(56, 32), scope.Instance)) ||
                            !registration.Use(bytes => FixedRoute(SHA256.HashData(bytes), raw.Use(value => SHA256.HashData(value)))))
                            throw new CryptographicException("Ordinary account registration changed during recovery.");
                    break;
                case 8: _ = raw.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope)); break;
                case 9: _ = raw.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope)); break;
            }
            result.Add(new(OrdinaryOutboxRootKinds[index], selector, raw.Use(bytes => SHA256.HashData(bytes))));
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
    }

    private static ProtectedDid2DirectTextJournal.Entry[] RequireOrdinaryPlanSelection(
        Did2CompactionPlan plan, Did2MessagingSessionScope scope, ProtectedDid2DirectTextJournal.State predecessor)
    {
        var candidates = predecessor.Entries.Values.Where(entry => FixedRoute(entry.Scope.Exact, scope.Exact)).OrderBy(entry => entry.Sequence);
        var selected = (IsStoppedOutboxPlan(plan)
            ? candidates.Where(entry => entry.WorkStopped)
            : candidates.TakeWhile(entry => entry.Stored && !entry.WorkStopped)).Take(plan.RowCount).ToArray();
        if (selected.Length != plan.RowCount) throw new CryptographicException("Stored ordinary prefix differs from actual predecessor custody.");
        var ordered = selected.OrderBy(entry => Convert.ToHexString(entry.Operation), StringComparer.Ordinal).ToArray();
        for (var index = 0; index < ordered.Length; index++)
        {
            var row = plan.ReadRow(index);
            if (row.Action != (IsStoppedOutboxPlan(plan) ? plan.ReadRow(0).Action : Did2CompactionPlan.Disposition.OutboxPayload) || !FixedRoute(row.Selector.Span, ordered[index].Operation) ||
                !FixedRoute(row.Commitment.Span, SHA256.HashData(ordered[index].Exact)))
                throw new CryptographicException("Stored ordinary rows differ from the exact settled prefix.");
        }
        return selected;
    }

    private static void RequireOrdinarySuccessor(Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var state = ProtectedDid2DirectTextJournal.Decode(predecessor, scope.Network, scope.LocalAccount, scope.Instance);
        var selected = RequireOrdinaryPlanSelection(plan, scope, state);
        if (IsStoppedOutboxPlan(plan))
            foreach (var entry in selected)
                state.RetireWorkingPayload(Convert.ToHexString(entry.Operation));
        else
        {
            state.RetireSuccessfulCommands(selected);
        }
        var expected = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Ordinary successor changed retained work or independent floors."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private static byte[] RemoveSelectedOrdinarySendCommitments(ProtectedDid2MailboxSendJournal.State sends,
        Did2MessagingSessionScope scope, IReadOnlyList<Did2CompactionPlan.Row> rows)
    {
        var revision = checked(sends.Revision + 1);
        var selected = new List<ProtectedDid2MailboxSendJournal.Entry>();
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (row.Action != Did2CompactionPlan.Disposition.OutboxPayload)
                throw new CryptographicException("Selected ordinary work lost its exact prepared send commitment.");
            foreach (var send in sends.RequirePreparedChain(scope.Hash, row.Selector.Span))
            {
                if (!unique.Add(send.Name)) throw new CryptographicException("An ordinary batch cannot select a send chain twice.");
                selected.Add(send);
            }
        }
        foreach (var send in selected) { sends.Entries.Remove(send.Name); send.Dispose(); }
        // All independent floors and unrelated/pending sends remain exact.
        sends.Revision = revision;
        return ProtectedDid2MailboxSendJournal.Encode(sends, scope.Network, scope.LocalAccount, scope.Instance);
    }

    private static void RequireOrdinarySendSuccessor(Did2CompactionPlan plan, Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> predecessor, ReadOnlySpan<byte> successor)
    {
        using var sends = ProtectedDid2MailboxSendJournal.Decode(predecessor, scope.Network, scope.LocalAccount, scope.Instance);
        var rows = Enumerable.Range(0, plan.RowCount).Select(plan.ReadRow).ToArray();
        var expected = RemoveSelectedOrdinarySendCommitments(sends, scope, rows);
        try { if (!FixedRoute(expected, successor)) throw new CryptographicException("Send successor changed unrelated requests or replay floors."); }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    // A local stored plan resumes without freshness acquisition. It cannot
    // remove native events/history/Store receipts or mint new request authority.
    private async Task ResumeOrdinaryOutboxStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        ProtectedDid2MessagingSessionCatalog.Snapshot catalog, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredTerminalAudit)
        {
            await ResumeTerminalAuditStepUnderLeaseAsync(plans, plan, catalog, held, ct).ConfigureAwait(false);
            return;
        }
        var scope = ResolveOrdinaryOutboxScope(plan, catalog);
        var roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(ct).ConfigureAwait(false);
        var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
        using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
        var native = new Did2MessagingSqlJournal(connection, scope, history);
        if (!FixedRoute(native.VerifyTip().Exact.Span, floor.Exact.Span)) throw new CryptographicException("Ordinary recovery lost its independent native tip.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        using var authoredRoot = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Ordinary recovery lost authored membership.");
        using var authored = authoredRoot.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        using var sendRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Ordinary recovery lost its guarded send custody.");
        using var sends = sendRoot.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        async Task RequireNativeSelectionAsync(ProtectedDid2DirectTextJournal.Entry entry)
        {
            using var committed = native.ReadVerifiedOperation(floor, entry.Operation);
            if (committed is null)
            {
                if (!IsStoppedOutboxPlan(plan)) throw new CryptographicException("Ordinary Store recovery lost its committed event.");
                await RequireUnencryptedCancelledDraftAsync(scope, entry, application, sends, ct).ConfigureAwait(false);
            }
            else if (committed.Direction != 1 || !FixedRoute(committed.EventHash, entry.EventHash))
                throw new CryptographicException("Ordinary recovery selected a received or changed native event.");
        }
        var ordinaryAdopted = FixedRoute(roots[0].Digest.Span, plan.ReadRoot(0).After.Span);
        for (var index = 0; index < plan.RowCount; index++)
        {
            if (IsStoppedOutboxPlan(plan))
            {
                // A stopped successor removes the complete working entry.
                // After its exact protected adoption, unchanged native/send
                // guards plus exact SQL/root observation own disposal; never
                // reconstruct its event commitment from the key-free audit.
                if (ordinaryAdopted) continue;
                if (!authored.Entries.TryGetValue(Convert.ToHexString(plan.ReadRow(index).Selector.Span), out var entry))
                    throw new CryptographicException("Stopped recovery lost its exact selected authored command.");
                await RequireNativeSelectionAsync(entry).ConfigureAwait(false);
            }
            else
            {
                // Normal Store-prefix adoption removes these working entries;
                // the independently retained native event remains mandatory.
                using var committed = native.ReadVerifiedOperation(floor, plan.ReadRow(index).Selector.Span) ??
                    throw new CryptographicException("Ordinary recovery lost a retained committed event.");
                if (committed.Direction != 1) throw new CryptographicException("Ordinary recovery selected a received event.");
            }
        }
        var digest = await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(digest, roots);
        if (plan.Phase == 1 || observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            var changedIndex = plan.Phase == 1 ? 0 : observation.RootIndex;
            if (changedIndex is not (0 or 1) || IsStoppedOutboxPlan(plan) && changedIndex != 0)
                throw new InvalidDataException("Ordinary recovery has another changed root.");
            var changedSlot = OrdinaryOutboxSlots(scope)[changedIndex];
            using var successor = parts.Use(bytes => plan.OwnSuccessor(changedIndex, bytes));
            using var predecessor = await storage.ReadOwnedAsync(changedSlot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Ordinary recovery lost its predecessor.");
            var predecessorBytes = predecessor.Use(bytes => bytes.ToArray());
            try
            {
                successor.Use(after =>
                {
                    if (changedIndex == 0) RequireOrdinarySuccessor(plan, scope, predecessorBytes, after);
                    else RequireOrdinarySendSuccessor(plan, scope, predecessorBytes, after);
                    return true;
                });
                if (plan.Phase == 1 && !IsStoppedOutboxPlan(plan))
                {
                    using var sendBefore = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Prepared ordinary batch lost send custody.");
                    using var sendAfter = parts.Use(bytes => plan.OwnSuccessor(1, bytes));
                    var original = sendBefore.Use(bytes => bytes.ToArray());
                    try { sendAfter.Use(bytes => { RequireOrdinarySendSuccessor(plan, scope, original, bytes); return true; }); }
                    finally { CryptographicOperations.ZeroMemory(original); }
                }
            }
            finally { CryptographicOperations.ZeroMemory(predecessorBytes); }
            if (plan.Phase == 1)
            {
                if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                {
                    using var state = predecessor.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    var selected = RequireOrdinaryPlanSelection(plan, scope, state);
                    foreach (var entry in selected)
                        await RequireNativeSelectionAsync(entry).ConfigureAwait(false);
                    await application.ApplyStoredOrdinaryOutboxAsync(storage, plan, scope, selected, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                }
                else if (observation.Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit) throw new InvalidDataException("Unexpected prepared ordinary observation.");
                roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                    throw new CryptographicException("Ordinary SQL successor changed before commit marker.");
                using var committedPlan = plan.WithSqlCommitted();
                await ReplaceCompactionPlanAsync(plan, committedPlan, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                return;
            }
            roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
            var latest = plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots);
            if (latest.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || latest.RootIndex != changedIndex)
                throw new CryptographicException("Ordinary dependencies changed before root adoption.");
            var beforeBytes = predecessor.Use(bytes => bytes.ToArray()); var afterBytes = successor.Use(bytes => bytes.ToArray());
            try
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(changedSlot, beforeBytes, afterBytes, ct).ConfigureAwait(false))
                    throw new CryptographicException("Ordinary root adoption conflicted.");
                using var readback = await storage.ReadOwnedAsync(changedSlot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Adopted ordinary root disappeared.");
                if (!readback.Use(bytes => FixedRoute(bytes, afterBytes))) throw new CryptographicException("Ordinary root adoption read-back differs.");
            }
            finally { CryptographicOperations.ZeroMemory(beforeBytes); CryptographicOperations.ZeroMemory(afterBytes); }
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
            return;
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only a completed or unchanged abandoning ordinary batch can clear.");
        await ValidateFinishingOrdinaryPartsAsync(plan, ct).ConfigureAwait(false);
        roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Ordinary dependencies changed before staging disposal.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
        _ = plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots);
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
    }

    private async Task ValidateFinishingOrdinaryPartsAsync(Did2CompactionPlan plan, CancellationToken ct)
    {
        using var ordinary = plan.Phase == 2 ? await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Ordinary successor is absent.") : null;
        using var send = plan.Phase == 2 ? await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Send successor is absent.") : null;
        using var adopted = ordinary is not null && send is not null
            ? IsStoppedOutboxPlan(plan) ? ordinary.Use(bytes => new OwnedDeepSecret(bytes)) : OwnOrdinarySuccessors(ordinary, send) : null;
        if (adopted is not null) adopted.Use(bytes => { plan.ValidateSuccessors(bytes); return true; });
        var remaining = new List<OwnedDeepSecret>();
        try
        {
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
                if (part is null) continue;
                remaining.Add(part);
                var offset = index * Did2CompactionPlan.PartBytes;
                if (index >= plan.PartCount || part.Length != Math.Min(Did2CompactionPlan.PartBytes, plan.SuccessorBytes - offset))
                    throw new InvalidDataException("Ordinary staging has an unexpected successor part.");
                if (adopted is not null)
                {
                    var value = part.Use(bytes => bytes.ToArray());
                    try
                    {
                        if (!adopted.Use(bytes => FixedRoute(bytes.Slice(offset, part.Length), value)))
                            throw new CryptographicException("Ordinary staging differs from the adopted successor.");
                    }
                    finally { CryptographicOperations.ZeroMemory(value); }
                }
            }
            // A pre-SQL abort must retain all parts or have completed their
            // atomic disposal. Partial disappearance is not repairable.
            if (plan.Phase == 3 && remaining.Count != 0)
            {
                if (remaining.Count != plan.PartCount) throw new InvalidDataException("Abandoning ordinary staging has missing parts.");
                var bytes = new byte[plan.SuccessorBytes];
                try
                {
                    var offset = 0; foreach (var part in remaining) { part.CopyTo(bytes.AsSpan(offset)); offset += part.Length; }
                    plan.ValidateSuccessors(bytes);
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally { foreach (var part in remaining) part.Dispose(); }
    }

    private static OwnedDeepSecret OwnOrdinarySuccessors(OwnedDeepSecret ordinary, OwnedDeepSecret send)
    {
        var bytes = new byte[checked(ordinary.Length + send.Length)];
        try { ordinary.CopyTo(bytes); send.CopyTo(bytes.AsSpan(ordinary.Length)); return new OwnedDeepSecret(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal async Task AbandonUncommittedOwnedOrdinaryOutboxAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (plan.Phase != 1) throw new InvalidOperationException("Only a prepared ordinary batch can be abandoned.");
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, owner.Account, owner.Instance).ReadAsync(ct).ConfigureAwait(false);
            var scope = ResolveOrdinaryOutboxScope(plan, catalog);
            var roots = await ReadOrdinaryOutboxRootsUnderLeaseAsync(storage, plan, scope, held, lease, ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, ct).ConfigureAwait(false), roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Committed ordinary SQL cannot be abandoned.");
            if (plan.ReadRow(0).Action == Did2CompactionPlan.Disposition.ExpiredTerminalAudit)
            {
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                var before = raw.Use(bytes => bytes.ToArray());
                using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
                using var next = parts.Use(bytes => plan.OwnSuccessor(0, bytes));
                var after = next.Use(bytes => bytes.ToArray());
                try
                {
                    RequireTerminalAuditSuccessor(plan, scope, before, after);
                    using var state = ProtectedDid2DirectTextJournal.Decode(before, scope.Network, scope.LocalAccount, scope.Instance);
                    var effects = await application.CaptureTerminalAuditExpiryAsync(scope, state, SelectTerminalAuditPlan(plan, state), ct).ConfigureAwait(false);
                    try
                    {
                        if (!FixedRoute(effects.Before, plan.SqlBefore) || !FixedRoute(effects.After, plan.SqlAfter))
                            throw new CryptographicException("Successful audit abort changed its exact SQL effects.");
                    }
                    finally { CryptographicOperations.ZeroMemory(effects.Before); CryptographicOperations.ZeroMemory(effects.After); }
                }
                finally { CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after); }
            }
            using var abandoning = plan.WithAbandoningBeforeSql(); await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterAbandonRecorded);
#endif
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }
}
