using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task EnrollMessagingArchiveAsync(ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct, explicitArchiveEnrollment: true).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            var owner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance);
            using (var before = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false))
            {
                var oldCatalog = before.Version == 1;
                var oldScopes = Enumerable.Range(0, before.Count).Select(before.Scope).ToArray();
                before.Dispose();
                if (oldCatalog)
                {
                    archiveEnrollmentInProgress = true;
                    try
                    {
                        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                        foreach (var scope in oldScopes)
                        {
                            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedArchiveEnrollmentUnderLeaseAsync(
                                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
                            _ = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                            await DrainOldArchiveEnrollmentPrefixAsync(current, scope, held, ct).ConfigureAwait(false);
                        }
                        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                        var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, instance, oldEnrollment: true);
                        using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                        if (idle.Phase != 0) throw new InvalidOperationException("Old archive enrollment still has a live plan.");
                        using var parts = await ProtectedDid2CompactionPlan.ReadPartsAsync(storage, ct).ConfigureAwait(false);
                        if (Enumerable.Range(0, parts.Count).Any(index => parts[index] is not null))
                            throw new CryptographicException("Old archive enrollment still has protected successor parts.");
                        parts.Dispose();
                        using var drained = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false);
                        var replacement = drained.WithEnrollmentRequired();
                        try
                        {
                            if (!await storage.CompareExchangeAsync(ProtectedDid2MessagingSessionCatalog.Slot, drained.Exact, replacement, ct).ConfigureAwait(false))
                                throw new CryptographicException("Explicit archive enrollment catalog conversion conflicted.");
                        }
                        finally { CryptographicOperations.ZeroMemory(replacement); }
                    }
                    finally { archiveEnrollmentInProgress = false; }
                }
            }
            while (true)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                using var selection = await storage.ReadOwnedBatchAsync([ProtectedDid2MessagingSessionCatalog.Slot, ProtectedDid2MessagingArchiveEnrollment.Slot], ct).ConfigureAwait(false);
                using var catalog = (selection[0] ?? throw new InvalidDataException("Enrollment selection catalog is absent.")).Use(bytes =>
                    ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, networkId, current.AccountId.Span, instance));
                if (catalog.Version != 2) throw new InvalidDataException("Explicit archive enrollment requires its actual V2 conversion.");
                var progressRaw = selection[1]?.Use(bytes => bytes.ToArray());
                var catalogHash = SHA256.HashData(catalog.Exact.Span);
                var selected = -1;
                if (progressRaw is not null)
                {
                    for (var i = 0; i < catalog.Count; i++)
                        if (progressRaw.Length == ProtectedDid2MessagingArchiveEnrollment.Bytes &&
                            Did2MessagingSessionScope.Fixed(progressRaw.AsSpan(16, 32), catalog.Scope(i).Hash)) { selected = i; break; }
                    if (selected < 0) throw new CryptographicException("Live archive enrollment does not resolve an exact catalog entry.");
                }
                else selected = Enumerable.Range(0, catalog.Count).FirstOrDefault(i => catalog.ArchiveState(i) == 0, -1);
                if (selected < 0)
                {
                    catalog.Dispose(); selection.Dispose();
                    await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                    using var ordinary = await owner.ReadAsync(ct).ConfigureAwait(false);
                    var scopes = Enumerable.Range(0, ordinary.Count).Where(index => ordinary.Phase(index) == 2).Select(ordinary.Scope).ToArray();
                    ordinary.Dispose();
                    foreach (var registeredScope in scopes)
                    {
                        using var audit = await SqliteDeepIdV2AccountGeneration.OpenMessagingArchiveAuditUnderLeaseAsync(
                            storage, sqlStatePath, current, registeredScope, ct).ConfigureAwait(false);
                        var root = await Did2MessagingArchiveRoot.ReadRegisteredAsync(storage, registeredScope, ct).ConfigureAwait(false);
                        _ = await VerifyArchiveSemanticsUnderLeaseAsync(audit, root, held, ct).ConfigureAwait(false);
                    }
                    return;
                }
                var scope = catalog.Scope(selected);
                catalog.Dispose(); selection.Dispose();
                ProtectedDid2MessagingArchiveEnrollment progress;
                if (progressRaw is null)
                {
                    using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedArchiveEnrollmentSelectionUnderLeaseAsync(
                        storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
                    var floor = await opened.Custody.ReadCurrentFloorAsync(ct).ConfigureAwait(false);
                    var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
                    var bootstrap = await opened.WithSqlAsync(sql => sql.CaptureArchiveEnrollmentBootstrap(), ct).ConfigureAwait(false);
                    var guards = await CaptureArchiveEnrollmentGuardsAsync(current, scope, held, opened, catalogHash, ct).ConfigureAwait(false);
                    await AuditUnindexedEnrollmentSourceAsync(opened, scope, floor, history, guards, held, ct).ConfigureAwait(false);
                    progress = ProtectedDid2MessagingArchiveEnrollment.Create(scope, floor, history, guards, bootstrap.Tree.PatriciaHash.Span, bootstrap.Reducer.Digest.Span);
                    using (var finalCatalog = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false))
                    {
                        if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(finalCatalog.Exact.Span), catalogHash) ||
                            !await storage.CompareExchangeAndInsertAsync(ProtectedDid2MessagingSessionCatalog.Slot, finalCatalog.Exact, finalCatalog.Exact,
                                [new(ProtectedDid2MessagingArchiveEnrollment.Slot, progress.Exact)], ct).ConfigureAwait(false))
                            throw new CryptographicException("Archive enrollment source selection conflicted.");
                    }
#if DEEP_TEST_INTERNALS
                    Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterSourceFrozen);
#endif
                }
                else progress = ProtectedDid2MessagingArchiveEnrollment.Decode(progressRaw, scope);
                await ResumeArchiveEnrollmentSessionAsync(current, scope, progress, held, ct).ConfigureAwait(false);
            }
        }
        finally { archiveEnrollmentInProgress = false; CryptographicOperations.ZeroMemory(instance); }
    }

    private async Task<IReadOnlyList<ReadOnlyMemory<byte>>> CaptureArchiveEnrollmentGuardsAsync(
        VerifiedDeepIdV2CurrentAccount current, Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> catalogHash, CancellationToken ct)
    {
        var source = await opened.WithSqlAsync(sql => sql.CaptureArchiveEnrollmentSource(), ct).ConfigureAwait(false);
        var authored = await CaptureArchiveAuthoredSourceAsync(current, scope, held, ct).ConfigureAwait(false);
        using var actual = await storage.ReadOwnedBatchAsync([SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
            ProtectedDid2MessagingPeerBootstrap.Slot(scope)], ct).ConfigureAwait(false);
        return [catalogHash, (actual[0] ?? throw new InvalidDataException("Enrollment registration is absent.")).Use(bytes => SHA256.HashData(bytes)),
            (actual[1] ?? throw new InvalidDataException("Enrollment peer bootstrap is absent.")).Use(bytes => SHA256.HashData(bytes)),
            source, authored.SqlHash, authored.DirectRootHash, Did2MessagingSqlJournal.ArchiveSchemaHash(5), Did2MessagingSqlJournal.ArchiveSchemaHash(6)];
    }

    private async Task AuditUnindexedEnrollmentSourceAsync(OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        Did2MessagingFloor floor, Did2MessagingHistoryCheckpoint history, IReadOnlyList<ReadOnlyMemory<byte>> guards,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var reducer = Did2MessagingArchiveReducer.Empty(scope); ulong cursor = 0, count = 0;
        while (true)
        {
            var originals = await opened.WithSqlAsync(sql => sql.ReadEnrollmentSourceAuthoredSources(reducer, cursor), ct).ConfigureAwait(false);
            try
            {
                using var authored = await QualifyArchiveAuthoredAsync(scope, originals, held, ct).ConfigureAwait(false);
                var paired = authored.PairedRead.WithFullSourceHash(guards[(int)ProtectedDid2MessagingArchiveEnrollment.GuardKind.AuthoredSql].Span);
                var step = await opened.WithPairedSqlAsync(paired, sql =>
                {
                    if (!Did2MessagingSessionScope.Fixed(sql.ReadOpenedFloor().Exact.Span, floor.Exact.Span) ||
                        !Did2MessagingSessionScope.Fixed(sql.CaptureArchiveEnrollmentSource(), guards[(int)ProtectedDid2MessagingArchiveEnrollment.GuardKind.OriginalSql].Span))
                        throw new CryptographicException("Unindexed enrollment audit changed its actual frozen native source.");
                    return sql.VerifyEnrollmentSourceReplayBatch(reducer, cursor, count, authored.Events);
                }, ct).ConfigureAwait(false);
                reducer = step.Reducer; cursor = step.Cursor; count = step.Count;
                if (step.Complete)
                {
                    if (count != history.HistoryCount || !Did2MessagingSessionScope.Fixed(reducer.Basis.Exact.Span, history.Basis.Exact.Span))
                        throw new CryptographicException("Unindexed enrollment full replay changed its actual history basis/count.");
                    return;
                }
            }
            finally { foreach (var row in originals) row.Dispose(); }
        }
    }

    private async Task RequireArchiveEnrollmentSourcesAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, ProtectedDid2MessagingArchiveEnrollment progress,
        OwnedDid2MessagingStorage opened, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var source = await opened.WithSqlAsync(sql => sql.CaptureArchiveEnrollmentSource(), ct).ConfigureAwait(false);
        var authored = await CaptureArchiveAuthoredSourceAsync(current, scope, held, ct).ConfigureAwait(false);
        if (!Did2MessagingSessionScope.Fixed(source, progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.OriginalSql)) ||
            !Did2MessagingSessionScope.Fixed(authored.SqlHash, progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.AuthoredSql)) ||
            !Did2MessagingSessionScope.Fixed(authored.DirectRootHash, progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.AuthoredRoot)) ||
            !Did2MessagingSessionScope.Fixed(Did2MessagingSqlJournal.ArchiveSchemaHash(5), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Schema5)) ||
            !Did2MessagingSessionScope.Fixed(Did2MessagingSqlJournal.ArchiveSchemaHash(6), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Schema6)))
            throw new CryptographicException("Enrollment original SQL/authored source changed after its frozen selection.");
        _ = await opened.Custody.ReadCurrentFloorAsync(ct).ConfigureAwait(false);
        if (progress.Phase != ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SourceFrozen)
            await opened.WithSqlAsync(sql => sql.RequireStagedArchiveProgress(progress), ct).ConfigureAwait(false);
    }

    private async Task ResumeArchiveEnrollmentSessionAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, ProtectedDid2MessagingArchiveEnrollment progress,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedArchiveEnrollmentUnderLeaseAsync(
            storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        await RequireArchiveEnrollmentSourcesAsync(current, scope, progress, opened, held, ct).ConfigureAwait(false);
        if (progress.Phase == ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SourceFrozen)
        {
            var bootstrap = await opened.WithSqlAsync(sql => sql.CaptureArchiveEnrollmentBootstrap(), ct).ConfigureAwait(false);
            await opened.WithSqlAsync(sql => sql.StageArchiveSchema(progress, bootstrap.Tree, bootstrap.Reducer), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterSchemaSql);
#endif
            await opened.WithSqlAsync(sql => sql.RequireStagedArchive(bootstrap.Tree, bootstrap.Reducer), ct).ConfigureAwait(false);
            var next = progress.Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged, 0, 0, progress.PatriciaHash, progress.ReducerHash);
            await ReplaceArchiveEnrollmentProgressAsync(progress, next, ct).ConfigureAwait(false); progress = next;
#if DEEP_TEST_INTERNALS
            Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterSchemaStaged);
#endif
        }
        while (progress.Phase is ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged or ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building)
        {
            var rows = await opened.WithSqlAsync(sql => sql.ReadArchiveEnrollmentBatch(progress), ct).ConfigureAwait(false);
            try
            {
                if (rows.Count == 0) break;
                var reducer = await opened.WithSqlAsync(sql => sql.ReadEnrollmentReducer(progress), ct).ConfigureAwait(false);
                var candidates = new List<Did2MessagingArchiveOriginal>(rows.Where(row => row.Reference.Direction == 1));
                var borrowed = new List<Did2MessagingArchiveOriginal>();
                try
                {
                    foreach (var kind in new[] { Did2MessagingArchiveReducer.ReferenceKind.Consent, Did2MessagingArchiveReducer.ReferenceKind.OwnHead, Did2MessagingArchiveReducer.ReferenceKind.OwnPrevious })
                    {
                        var reference = reducer.Reference(kind);
                        if (reference.Kind != 2 || reference.Direction != 1 || candidates.Any(row => row.Reference.Ordinal == reference.Ordinal)) continue;
                        var row = await opened.WithSqlAsync(sql => sql.ReadArchiveOriginal(reference), ct).ConfigureAwait(false); borrowed.Add(row); candidates.Add(row);
                    }
                    using var authored = await QualifyArchiveAuthoredAsync(scope, candidates, held, ct).ConfigureAwait(false);
                    var batch = await opened.WithPairedSqlAsync(authored.PairedRead, sql => sql.InsertArchiveEnrollmentBatch(progress, rows.Select(row => row.Reference).ToArray(), authored.Events), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterBatchSql);
#endif
                    await RequireArchiveAuthoredCurrentAsync(authored, scope, held, ct).ConfigureAwait(false);
                    _ = await opened.WithPairedSqlAsync(authored.PairedRead, sql =>
                    {
                        var readback = sql.InsertArchiveEnrollmentBatch(progress, rows.Select(row => row.Reference).ToArray(), authored.Events);
                        sql.RequireStagedArchive(batch.Tree, batch.Reducer);
                        if (!Did2MessagingSessionScope.Fixed(batch.Tree.PatriciaHash.Span, readback.Tree.PatriciaHash.Span) ||
                            !Did2MessagingSessionScope.Fixed(batch.Reducer.Exact.Span, readback.Reducer.Exact.Span))
                            throw new CryptographicException("Enrollment batch changed across its paired physical readback.");
                        return 0;
                    }, ct).ConfigureAwait(false);
                    var next = progress.Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building, batch.Cursor, batch.Count, batch.Tree.PatriciaHash.Span, batch.Reducer.Digest.Span);
                    await ReplaceArchiveEnrollmentProgressAsync(progress, next, ct).ConfigureAwait(false); progress = next;
#if DEEP_TEST_INTERNALS
                    Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterBatchProgress);
#endif
                }
                finally { foreach (var row in borrowed) row.Dispose(); }
            }
            finally { foreach (var row in rows) row.Dispose(); }
        }
        var candidate = Did2MessagingArchiveRoot.Create(scope, 1, progress.SourceHistory, progress.TargetBasis,
            progress.SourceHistory.HistoryCount, progress.PatriciaHash, progress.ReducerHash);
        var summary = await VerifyArchiveSemanticsUnderLeaseAsync(opened, candidate, held, ct).ConfigureAwait(false);
        await RequireArchiveEnrollmentSourcesAsync(current, scope, progress, opened, held, ct).ConfigureAwait(false);
        if (progress.Phase != ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady)
        {
            await opened.WithSqlAsync(sql => sql.WriteEnrollmentArchiveMirror(candidate, summary), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterFinalSql);
#endif
            _ = await VerifyArchiveSemanticsUnderLeaseAsync(opened, candidate, held, ct).ConfigureAwait(false);
            await opened.WithSqlAsync(sql => sql.RequireCandidateArchiveMirror(candidate), ct).ConfigureAwait(false);
            var next = progress.Advance(scope, ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady, progress.Cursor,
                progress.Count, progress.PatriciaHash, progress.ReducerHash);
            await ReplaceArchiveEnrollmentProgressAsync(progress, next, ct).ConfigureAwait(false); progress = next;
#if DEEP_TEST_INTERNALS
            Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterFinalReady);
#endif
        }
        await RequireArchiveEnrollmentSourcesAsync(current, scope, progress, opened, held, ct).ConfigureAwait(false);
        await opened.WithSqlAsync(sql => sql.RequireCandidateArchiveMirror(candidate), ct).ConfigureAwait(false);
        await RequireFinalEnrollmentPairAsync(opened, scope, progress, candidate, held, ct).ConfigureAwait(false);
        var owner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, scope.Instance);
        using (var actual = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false))
        {
            var index = actual.FindExact(scope); if (index < 0) throw new CryptographicException("Enrollment adoption lost its actual catalog entry.");
            if (actual.ArchiveState(index) == 0)
            {
                if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(actual.Exact.Span), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Catalog)))
                    throw new CryptographicException("Enrollment adoption catalog changed.");
                var next = actual.WithIndexed(index);
                try
                {
                    if (!await storage.CompareExchangeAndInsertAsync(ProtectedDid2MessagingSessionCatalog.Slot, actual.Exact, next,
                        [new(Did2MessagingArchiveRoot.Slot(scope), candidate.Exact)], ct).ConfigureAwait(false))
                        throw new CryptographicException("Enrollment root/catalog adoption conflicted.");
                }
                finally { CryptographicOperations.ZeroMemory(next); }
#if DEEP_TEST_INTERNALS
                Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterCatalogAndRoot);
#endif
            }
        }
        // The restricted opener independently resolves FinalReady's actual
        // already-adopted root; a missing root can never reach this readback.
        _ = await VerifyArchiveSemanticsUnderLeaseAsync(opened, candidate, held, ct).ConfigureAwait(false);
        await RequireArchiveEnrollmentSourcesAsync(current, scope, progress, opened, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterAdoptionReadback);
#endif
        await RequireFinalEnrollmentPairAsync(opened, scope, progress, candidate, held, ct).ConfigureAwait(false);
        if (!await storage.CompareAndDeleteAsync(ProtectedDid2MessagingArchiveEnrollment.Slot, progress.Exact,
            [ProtectedDid2MessagingArchiveEnrollment.Slot], ct).ConfigureAwait(false))
            throw new CryptographicException("Enrollment cleanup conflicted with actual progress.");
#if DEEP_TEST_INTERNALS
        Did2MessagingArchiveEnrollmentTestHooks.Hit(Did2MessagingArchiveEnrollmentFailpoint.AfterCleanup);
#endif
        var cleanupSlots = new[] { ProtectedDid2MessagingSessionCatalog.Slot, Did2MessagingArchiveRoot.Slot(scope),
            ProtectedDid2MessagingArchiveEnrollment.Slot, SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot,
            SqliteDeepIdV2AccountGeneration.ApplicationStateSlot, scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope),
            ProtectedDid2MessagingPeerBootstrap.Slot(scope) }.Concat(ArchiveAuthoredSlots.Order(StringComparer.Ordinal)).ToArray();
        using var readback = await storage.ReadOwnedBatchAsync(cleanupSlots, ct).ConfigureAwait(false);
        if (readback[2] is not null) throw new CryptographicException("Enrollment cleanup retained its account fence.");
        using var catalog = (readback[0] ?? throw new InvalidDataException("Enrollment cleanup lost catalog.")).Use(bytes =>
            ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        var selected = catalog.FindExact(scope);
        var actualRoot = (readback[1] ?? throw new InvalidDataException("Enrollment cleanup lost its adopted root.")).Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
        if (selected < 0 || catalog.ArchiveState(selected) != 1 || !Did2MessagingSessionScope.Fixed(actualRoot.Exact.Span, candidate.Exact.Span))
            throw new CryptographicException("Enrollment cleanup adopted readback differs.");
        var comparison = catalog.BeforeIndexedComparison(selected);
        try { if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(comparison), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Catalog))) throw new CryptographicException("Enrollment cleanup changed unrelated catalog custody."); }
        finally { CryptographicOperations.ZeroMemory(comparison); }
        byte[] registration = [], applicationRegistration = [];
        try
        {
            registration = (readback[3] ?? throw new InvalidDataException("Enrollment cleanup lost actual key registration.")).Use(bytes => bytes.ToArray());
            applicationRegistration = (readback[4] ?? throw new InvalidDataException("Enrollment cleanup lost application registration.")).Use(bytes => bytes.ToArray());
            var actualAuthored = Enumerable.Range(8, cleanupSlots.Length - 8).ToDictionary(index => cleanupSlots[index],
                index => readback[index]?.Use(bytes => SHA256.HashData(bytes)), StringComparer.Ordinal);
            using var fullSourcePrefix = SqliteDeepIdV2AccountGeneration.CreateArchiveAuthoredPrefix(scope, cleanupSlots, readback, 8);
            if (!Did2MessagingSessionScope.Fixed(SHA256.HashData(registration), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.Registration)) ||
                !(readback[5]?.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, progress.SourceFloor.Exact.Span)) ?? false) ||
                !(readback[6]?.Use(bytes => Did2MessagingSessionScope.Fixed(bytes, progress.SourceHistory.Exact.Span)) ?? false) ||
                !(readback[7]?.Use(bytes => Did2MessagingSessionScope.Fixed(SHA256.HashData(bytes), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.PeerBootstrap))) ?? false))
                throw new CryptographicException("Enrollment cleanup changed its actual protected source guards.");
            readback.Dispose();
            var paired = new Did2MessagingArchiveAuthoredRead(actualAuthored, static _ => { }, hasSources: false,
                progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.AuthoredSql).ToArray());
            SqliteDeepIdV2AccountGeneration.VerifyPairedArchiveApplication(sqlStatePath, scope, registration, applicationRegistration,
                actualAuthored, paired, ct, fullSourcePrefix);
        }
        finally { CryptographicOperations.ZeroMemory(registration); CryptographicOperations.ZeroMemory(applicationRegistration); }
        using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(sqlStatePath, catalog, scope, held, lease);
        var finalSql = Did2MessagingSqlJournal.ForArchiveEnrollment(connection, scope, progress.SourceHistory, progress);
        finalSql.BindArchiveRoot(candidate); finalSql.RequireArchiveMirror();
        if (!Did2MessagingSessionScope.Fixed(finalSql.CaptureArchiveEnrollmentSource(), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.OriginalSql)))
            throw new CryptographicException("Enrollment cleanup changed the original source.");
    }

    private async Task ReplaceArchiveEnrollmentProgressAsync(ProtectedDid2MessagingArchiveEnrollment before,
        ProtectedDid2MessagingArchiveEnrollment after, CancellationToken ct)
    {
        if (!await storage.CompareExchangeAsync(ProtectedDid2MessagingArchiveEnrollment.Slot, before.Exact, after.Exact, ct).ConfigureAwait(false))
            throw new CryptographicException("Enrollment progress CAS conflicted.");
    }

    private async Task RequireFinalEnrollmentPairAsync(OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ProtectedDid2MessagingArchiveEnrollment progress, Did2MessagingArchiveRoot candidate,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        using var authored = await QualifyArchiveAuthoredAsync(scope, [], held, ct).ConfigureAwait(false);
        var paired = authored.PairedRead.WithFullSourceHash(progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.AuthoredSql));
        _ = await opened.WithPairedSqlAsync(paired, sql =>
        {
            sql.RequireOpenedEnrollmentProgress(progress);
            if (!Did2MessagingSessionScope.Fixed(sql.ReadOpenedFloor().Exact.Span, progress.SourceFloor.Exact.Span) ||
                !Did2MessagingSessionScope.Fixed(sql.CaptureArchiveEnrollmentSource(), progress.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.OriginalSql)))
                throw new CryptographicException("Final paired enrollment read changed its frozen actual native source/floor.");
            sql.RequireStagedArchiveProgress(progress); sql.RequireCandidateArchiveMirror(candidate); return 0;
        }, ct).ConfigureAwait(false);
    }

    private async Task DrainOldArchiveEnrollmentPrefixAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (!archiveEnrollmentInProgress) throw new InvalidOperationException("Old prefix draining belongs only to explicit enrollment.");
        while (true)
        {
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedArchiveEnrollmentUnderLeaseAsync(
                storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, ct).ConfigureAwait(false);
            if (floor.Ordinal < history.Basis.Ordinal) throw new CryptographicException("Old enrollment suffix rolled back its actual source checkpoint.");
            var count = floor.Ordinal - history.Basis.Ordinal;
            if (floor.Status != 1 || count <= 63) return;
            using var prepared = await PreparePrefixUnderLeaseAsync(current, scope, checked((int)Math.Min(32UL, count - 63)), held, ct).ConfigureAwait(false);
            var plans = new ProtectedDid2CompactionPlan(storage, lease, networkId, current.AccountId.Span, scope.Instance, oldEnrollment: true);
            using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
            if (idle.Phase != 0) throw new InvalidOperationException("Old enrollment prefix already has a live plan.");
            await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
            await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        }
    }

    private async Task<Did2MessagingArchiveReducer> VerifyArchiveSemanticsUnderLeaseAsync(OwnedDid2MessagingStorage opened,
        Did2MessagingArchiveRoot root, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var tree = await opened.WithSqlAsync(sql => sql.VerifyCompleteArchiveTree(root), ct).ConfigureAwait(false);
        var reducer = Did2MessagingArchiveReducer.Empty(opened.Scope); ulong cursor = 0, count = 0; var families = new ulong[6];
        while (true)
        {
            var originals = await opened.WithSqlAsync(sql => sql.ReadArchiveReplayAuthoredSources(root, reducer, cursor), ct).ConfigureAwait(false);
            try
            {
                using var authored = await QualifyArchiveAuthoredAsync(opened.Scope, originals, held, ct).ConfigureAwait(false);
                var step = await opened.WithPairedSqlAsync(authored.PairedRead, sql => sql.VerifyArchiveReplayBatch(root, reducer, cursor, count, authored.Events), ct).ConfigureAwait(false);
                await RequireArchiveAuthoredCurrentAsync(authored, opened.Scope, held, ct).ConfigureAwait(false);
                step = await opened.WithPairedSqlAsync(authored.PairedRead, sql => sql.VerifyArchiveReplayBatch(root, reducer, cursor, count, authored.Events), ct).ConfigureAwait(false);
                reducer = step.Reducer; cursor = step.Cursor; count = step.Count;
                for (var i = 0; i < families.Length; i++) families[i] = checked(families[i] + step.Families[i]);
                if (step.Complete) break;
            }
            finally { foreach (var original in originals) original.Dispose(); }
        }
        await opened.WithSqlAsync(sql => sql.RequireFinalArchiveAudit(root, reducer, count, families, tree), ct).ConfigureAwait(false);
        return reducer;
    }
    // Set only inside the explicit leased enrollment entry. It permits the
    // existing old-plan owner to drain V1 before the single V2/all0 catalog CAS;
    // it never grants an ordinary opener or V2 state0 fallback.
    private bool archiveEnrollmentInProgress;

    private async Task<ProtectedDid2MessagingSessionCatalog.Snapshot> ReadMessagingCatalogForCompactionAsync(
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct)
    {
        var owner = new ProtectedDid2MessagingSessionCatalog(storage, networkId, account.Span, instance.Span);
        if (!archiveEnrollmentInProgress) return await owner.ReadAsync(ct).ConfigureAwait(false);
        var result = await owner.ReadForEnrollmentAsync(ct).ConfigureAwait(false);
        if (result.Version != 1)
        {
            result.Dispose();
            throw new CryptographicException("Only the actual old catalog may enter explicit legacy-plan draining.");
        }
        return result;
    }
}
