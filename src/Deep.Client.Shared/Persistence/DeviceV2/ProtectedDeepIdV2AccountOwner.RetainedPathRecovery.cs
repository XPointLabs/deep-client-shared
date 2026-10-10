using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private static string RetainedPathRootSlot(int index) => index switch
    {
        2 => ProtectedDid2MailboxGrantJournal.Slot,
        3 => ProtectedDid2MailboxReadJournal.Slot,
        8 => ProtectedDid2ContactRouteJournal.Slot,
        _ => throw new InvalidDataException("Retained-path recovery cannot mutate another root.")
    };

    private async Task ResumeRetainedPathStepUnderLeaseAsync(ProtectedDid2CompactionPlan plans, Did2CompactionPlan plan,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        RequireRetainedPathProfile(plan);
        var account = plan.Exact.Slice(32, 32); var instance = plan.Exact.Slice(64, 32);
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
            storage, sqlStatePath, networkId, account, instance, held, lease, ct).ConfigureAwait(false);
        var sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
        var roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        var observation = plan.ObserveReadback(sql, roots);
        if (plan.Phase == 1 || observation.Step == Did2CompactionPlan.RecoveryStep.AdoptRoot)
        {
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.Phase == 1)
            {
                // Before ANY SQL or root mutation validate all three owned
                // successors against actual predecessor custody, not hashes alone.
                foreach (var index in new[] { 2, 3, 8 })
                {
                    using var successor = parts.Use(bytes => plan.OwnSuccessor(index, bytes));
                    await RequireRetainedPathSuccessorUnderLeaseAsync(plan, index, successor, held, ct).ConfigureAwait(false);
                }
                if (observation.Step == Did2CompactionPlan.RecoveryStep.ApplySql)
                {
                    using var grantRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var grants = grantRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    var selected = RequireArchivedPathGrants(grants, plan.SqlSelector);
                    var exact = selected.Select(entry => ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8)).ToArray();
                    using var publicationRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var publications = publicationRaw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    var route = ContactRouteClosureCodec.Decode(RequireArchivedPath(publications, plan.SqlSelector).Value.Record(6).Span);
                    var scope = ArchivedPathReadScope(route);
                    using var readRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                    using var read = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    if (read.Phase != 0 || read.Active is not null || !read.Traversals.TryGetValue(Convert.ToHexString(scope.Value), out var traversal))
                        throw new CryptographicException("Retained-path SQL recovery lost its original idle protected traversal.");
                    await application.ApplyStoredRetainedPathAsync(this, plan, route, scope, traversal, exact, held, lease, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSql);
#endif
                }
                else if (observation.Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                    throw new InvalidDataException("Retained-path prepared SQL has a third outcome.");
                sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
                roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
                if (plan.ObserveReadback(sql, roots).Step != Did2CompactionPlan.RecoveryStep.RecordSqlCommit)
                    throw new CryptographicException("Retained-path SQL commit differs from the stored complete successor.");
                using var committed = plan.WithSqlCommitted();
                await ReplaceCompactionPlanAsync(plan, committed, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterSqlRecorded);
#endif
                return;
            }
            var changing = observation.RootIndex;
            using var after = parts.Use(bytes => plan.OwnSuccessor(changing, bytes));
            await RequireRetainedPathSuccessorUnderLeaseAsync(plan, changing, after, held, ct).ConfigureAwait(false);
            using var before = await storage.ReadOwnedAsync(RetainedPathRootSlot(changing), ct).ConfigureAwait(false) ?? throw new InvalidDataException();
            sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
            roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
            var latest = plan.ObserveReadback(sql, roots);
            if (latest.Step != Did2CompactionPlan.RecoveryStep.AdoptRoot || latest.RootIndex != changing ||
                !before.Use(bytes => FixedRoute(SHA256.HashData(bytes), plan.ReadRoot(changing).Before.Span)))
                throw new CryptographicException("Retained-path dependencies changed before root adoption.");
            var expected = before.Use(bytes => bytes.ToArray()); var next = after.Use(bytes => bytes.ToArray());
            try
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareExchangeAsync(RetainedPathRootSlot(changing), expected, next, ct).ConfigureAwait(false))
                    throw new CryptographicException("Retained-path root adoption conflicted.");
                using var actual = await storage.ReadOwnedAsync(RetainedPathRootSlot(changing), ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                if (!actual.Use(bytes => FixedRoute(bytes, next))) throw new CryptographicException("Retained-path root CAS readback differs.");
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterHistoryAdopted);
#endif
            }
            finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(next); }
            return;
        }
        if (observation.Step != Did2CompactionPlan.RecoveryStep.ClearPlan || plan.Phase is not (2 or 3))
            throw new InvalidDataException("Only a fully adopted or unchanged abandoning retained-path plan can clear.");
        await ValidateFinishingRetainedPathPartsAsync(plan, held, ct).ConfigureAwait(false);
        sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
        roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        if (plan.ObserveReadback(sql, roots).Step != Did2CompactionPlan.RecoveryStep.ClearPlan)
            throw new CryptographicException("Retained-path custody changed before staging disposal.");
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        await storage.DeleteBatchAsync(Enumerable.Range(0, plan.PartCount).Select(ProtectedDid2CompactionPlan.PartSlot).ToArray(), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPartsDeleted);
#endif
        sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
        roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
        _ = plan.ObserveReadback(sql, roots);
        using var cleared = plan.Cleared(); await ReplaceCompactionPlanAsync(plan, cleared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPlanCleared);
#endif
    }

    private async Task RequireRetainedPathSuccessorUnderLeaseAsync(Did2CompactionPlan plan, int index,
        OwnedDeepSecret successor, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var expected = await DeriveRetainedPathSuccessorUnderLeaseAsync(plan, index, ct).ConfigureAwait(false);
        try
        {
            if (!successor.Use(bytes => FixedRoute(bytes, expected)))
                throw new CryptographicException("Retained-path successor changed unrelated custody.");
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private async Task<byte[]> DeriveRetainedPathSuccessorUnderLeaseAsync(Did2CompactionPlan plan, int index, CancellationToken ct)
    {
        var account = plan.Exact.Slice(32, 32); var instance = plan.Exact.Slice(64, 32);
        var rows = Enumerable.Range(0, plan.RowCount).Select(plan.ReadRow).ToArray();
        using var original = await storage.ReadOwnedAsync(RetainedPathRootSlot(index), ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        if (!original.Use(bytes => FixedRoute(SHA256.HashData(bytes), plan.ReadRoot(index).Before.Span)))
            throw new CryptographicException("Retained-path source is not the stored exact predecessor.");
        if (index == 2)
        {
            using var grants = original.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, account.Span, instance.Span));
            return RemoveArchivedPathGrants(grants, plan.SqlSelector, rows, networkId, account.Span, instance.Span);
        }
        if (index == 8)
        {
            using var publications = original.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
            return RemoveArchivedPublication(publications, rows[^1], networkId, account.Span, instance.Span);
        }
        using var publicationRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        if (!publicationRaw.Use(bytes => FixedRoute(SHA256.HashData(bytes), plan.ReadRoot(8).Before.Span)))
            throw new CryptographicException("Read adoption lost its original publication predecessor.");
        using var archive = publicationRaw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
        var entry = RequireArchivedPath(archive, plan.SqlSelector).Value;
        if (!FixedRoute(SHA256.HashData(entry.Exact), rows[^1].Commitment.Span)) throw new CryptographicException("Read adoption changed the original archive.");
        var route = ContactRouteClosureCodec.Decode(entry.Record(6).Span);
        using var read = original.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, account.Span, instance.Span));
        return RemoveArchivedPathRead(read, route, rows, networkId, account.Span, instance.Span);
    }

    private async Task ValidateFinishingRetainedPathPartsAsync(Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var stream = new MemoryStream();
        foreach (var index in new[] { 2, 3, 8 })
        {
            if (plan.Phase == 3)
            {
                var bytes = await DeriveRetainedPathSuccessorUnderLeaseAsync(plan, index, ct).ConfigureAwait(false);
                try { stream.Write(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            else
            {
                using var raw = await storage.ReadOwnedAsync(RetainedPathRootSlot(index), ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                raw.Use(bytes => { stream.Write(bytes); return true; });
            }
        }
        var exact = stream.ToArray();
        try
        {
            plan.ValidateSuccessors(exact);
            for (var index = 0; index < Did2CompactionPlan.MaximumSuccessorBytes / Did2CompactionPlan.PartBytes; index++)
            {
                using var part = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index), ct).ConfigureAwait(false);
                if (part is null) continue; // Only this exact fully-after/before-abort observation permits absence.
                var offset = index * Did2CompactionPlan.PartBytes;
                if (index >= plan.PartCount || part.Length != Math.Min(Did2CompactionPlan.PartBytes, exact.Length - offset) ||
                    !part.Use(bytes => FixedRoute(bytes, exact.AsSpan(offset, part.Length))))
                    throw new CryptographicException("Retained-path finishing parts differ from actual owned successors.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
            if (stream.TryGetBuffer(out var buffer)) CryptographicOperations.ZeroMemory(buffer.AsSpan());
        }
    }

    internal async Task AbandonUncommittedRetainedPathAsync(CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false); using var borrowed = held.BorrowFor(lease);
        var owner = await SqliteDeepIdV2AccountGeneration.ReadCompactionOwnerScopeUnderLeaseAsync(storage, networkId, ct).ConfigureAwait(false);
        try
        {
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, owner.Account, owner.Instance);
            using var plan = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            RequireRetainedPathProfile(plan);
            if (plan.Phase != 1) throw new InvalidOperationException("Only an unchanged prepared retained path can be abandoned.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                storage, sqlStatePath, networkId, owner.Account, owner.Instance, held, lease, ct).ConfigureAwait(false);
            var sql = await application.ReadCompleteMailboxStateProjectionAsync(plan.SqlSelector.ToArray(), ct).ConfigureAwait(false);
            var roots = await ReadRetainedPathRootsUnderLeaseAsync(plan, held, ct).ConfigureAwait(false);
            if (plan.ObserveReadback(sql, roots).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                throw new CryptographicException("Committed or changed SQL cannot be abandoned.");
            using var parts = await plans.ReadSuccessorsAsync(plan, held, ct).ConfigureAwait(false);
            foreach (var index in new[] { 2, 3, 8 })
            {
                using var successor = parts.Use(bytes => plan.OwnSuccessor(index, bytes));
                await RequireRetainedPathSuccessorUnderLeaseAsync(plan, index, successor, held, ct).ConfigureAwait(false);
            }
            using var abandoning = plan.WithAbandoningBeforeSql();
            await ReplaceCompactionPlanAsync(plan, abandoning, held, ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owner.Account); CryptographicOperations.ZeroMemory(owner.Instance); }
    }
}
