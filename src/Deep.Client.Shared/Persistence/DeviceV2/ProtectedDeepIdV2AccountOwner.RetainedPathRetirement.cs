using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal sealed partial class MailboxEpochExclusion
    {
        // Retire an archived original path, never the current permanent route.
        // Unknown acquisition chains and unsettled work must be reconciled by
        // their existing owners first; exclusion alone is not permission.
        internal async Task RetireArchivedReadPathAsync(CancellationToken ct = default)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                using var grants = ProtectedDid2MailboxGrantJournal.Decode(root, owner.networkId, current.AccountId.Span, instance);
                var original = grants.Entries[Convert.ToHexString(acquisition)];
                var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(original).Span);
                using var publication = await owner.OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct, route.ExactHash).ConfigureAwait(false);
                using var publicationRaw = await owner.storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Archived publication is absent.");
                using var publications = publicationRaw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, owner.networkId, current.AccountId.Span, instance));
                var permanent = owner.CreatePermanentContactPlan(current, instance);
                var main = Convert.ToHexString(permanent.Intent.Span);
                if (!publications.Entries.TryGetValue(main, out var active) || active.Phase != 7 || active.Kind != 1 ||
                    FixedRoute(ContactRouteClosureCodec.Decode(active.Record(6).Span).ExactHash.Span, route.ExactHash.Span))
                    throw new IOException("The last current permanent route cannot be retired.");
                var archive = RequireArchivedPath(publications, route.ExactHash.Span);
                if (archive.Key == main) throw new IOException("Current publication cannot be selected as an archive.");
                owner.RequireRetainedPermanentIntent(archive.Key, archive.Value, permanent, current.AccountId.Span, instance);
                if (publications.Entries.Values.Any(entry => entry.Phase != 7))
                    throw new IOException("Pending publication work pins retained-path retirement.");
                var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                // Every original Store grant is bounded by XRA1 expiry. Object
                // retention is measured from its last possible admission, NOT
                // the lifetime of this owner's short Retrieve grant.
                var objectHorizon = checked(BinaryPrimitives.ReadUInt64BigEndian(route.Authorization.Field(13).Span) +
                    (ulong)MailboxClientLimits.MaximumTtlSeconds);
                var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(reading.SampleSeconds - fresh.Proof.MonotonicSample));
                if (lower < objectHorizon) throw new IOException("Original accepted-object retention still pins this read path.");
                var selected = RequireArchivedPathGrants(grants, route.ExactHash.Span);
                foreach (var entry in selected)
                {
                    var originalRoute = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                    await RequireExclusionAsync(entry, originalRoute, authority, fresh, reading,
                        BinaryPrimitives.ReadUInt64BigEndian(originalRoute.Projection.Field(6).Span), ct).ConfigureAwait(false);
                    var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
                    if (!FixedRoute(request.Field(3).Span, publication.Locator.Span) || !FixedRoute(request.Field(4).Span, publication.Capability.Span))
                        throw new CryptographicException("An original holder differs from its owned archived capability.");
                }
                await owner.RequireIdleArchivedPathWorkUnderLeaseAsync(current.AccountId, instance, route.ExactHash, held, ct).ConfigureAwait(false);
                using var readRaw = await owner.storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Read custody is absent.");
                using var read = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, owner.networkId, current.AccountId.Span, instance));
                var scope = ArchivedPathReadScope(route);
                if (read.Phase != 0 || read.Active is not null || !read.Traversals.TryGetValue(Convert.ToHexString(scope.Value), out var traversal))
                    throw new IOException("Original completed traversal is required; absence is not settlement.");
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                    owner.storage, owner.sqlStatePath, owner.networkId, current.AccountId, instance, held, owner.lease, ct).ConfigureAwait(false);
                RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), traversal);
                var exactGrants = selected.Select(entry => ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8)).ToArray();
                foreach (var grant in exactGrants)
                {
                    if (!read.Counters.TryGetValue(Convert.ToHexString(SHA256.HashData(grant.Span)), out var counter) || counter == 0)
                        throw new IOException("Original read replay floor is absent.");
                    await application.RequireSettledGrantReadCoverageAsync(grant, scope, traversal,
                        new BlindedMailboxId(route.Reachability.Field(2).Span), new BlindedPlacementId(route.Reachability.Field(10).Span), ct).ConfigureAwait(false);
                }
                var plans = new ProtectedDid2CompactionPlan(owner.storage, owner.lease, owner.networkId, current.AccountId.Span, instance);
                using var idle = await plans.ReadAsync(held, ct).ConfigureAwait(false);
                if (idle.Phase != 0) throw new InvalidOperationException("An active local plan owns recovery.");
                var rows = selected.Select(entry => new Did2CompactionPlan.Row(Did2CompactionPlan.Disposition.ReplayScope,
                    SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span), SHA256.HashData(entry)))
                    .OrderBy(row => Convert.ToHexString(row.Selector.Span), StringComparer.Ordinal).ToList();
                rows.Add(new(Did2CompactionPlan.Disposition.RetainedPath, route.ExactHash.ToArray(), SHA256.HashData(archive.Value.Exact)));
                var grantAfter = RemoveArchivedPathGrants(grants, route.ExactHash.Span, rows, owner.networkId, current.AccountId.Span, instance);
                var readAfter = RemoveArchivedPathRead(read, route, rows, owner.networkId, current.AccountId.Span, instance);
                var publicationAfter = RemoveArchivedPublication(publications, rows[^1], owner.networkId, current.AccountId.Span, instance);
                try
                {
                    var before = await owner.ReadMailboxProtectedRootsUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false);
                    before.Add(await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(owner.storage, owner.lease, owner.sqlStatePath, current, held, ct).ConfigureAwait(false));
                    before.Add(new(Did2CompactionPlan.RootKind.ContactPublication, CompactionSlotSelector(ProtectedDid2ContactRouteJournal.Slot), publicationRaw.Use(bytes => SHA256.HashData(bytes))));
                    before.Add(await owner.ReadMailboxLocalCustodyUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false));
                    var changed = new Dictionary<int, byte[]> { [2] = grantAfter, [3] = readAfter, [8] = publicationAfter };
                    var roots = before.Select((item, index) => changed.TryGetValue(index, out var next)
                        ? new Did2CompactionPlan.Root(item.Kind, item.Selector, item.Digest, SHA256.HashData(next), false, next)
                        : new Did2CompactionPlan.Root(item.Kind, item.Selector, item.Digest, item.Digest, true, default)).ToArray();
                    var effects = await application.CaptureRetainedPathEffectsAsync(route, scope, traversal, exactGrants, ct).ConfigureAwait(false);
                    using var prepared = idle.Prepare(Did2CompactionPlan.SqlTarget.Application, RandomNumberGenerator.GetBytes(32),
                        route.ExactHash.Span, effects.Before, effects.After, roots, rows);
                    await publication.RecheckAsync(ct).ConfigureAwait(false);
                    await RecheckUnderGateAsync(ct).ConfigureAwait(false);
                    var actual = await owner.ReadRetainedPathRootsUnderLeaseAsync(prepared.Plan, held, ct, current).ConfigureAwait(false);
                    var sql = await application.ReadCompleteMailboxStateProjectionAsync(route.ExactHash, ct).ConfigureAwait(false);
                    if (prepared.Plan.ObserveReadback(sql, actual).Step != Did2CompactionPlan.RecoveryStep.ApplySql)
                        throw new CryptographicException("Retained-path predecessor changed before staging.");
                    await plans.StageAsync(idle, prepared, held, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterStage);
#endif
                    await owner.ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(grantAfter); CryptographicOperations.ZeroMemory(readAfter);
                    CryptographicOperations.ZeroMemory(publicationAfter);
                }
            }
            finally { gate.Release(); }
        }
    }

    private static readonly Did2CompactionPlan.RootKind[] RetainedPathKinds =
    [Did2CompactionPlan.RootKind.Ordinary, Did2CompactionPlan.RootKind.Send, Did2CompactionPlan.RootKind.Grant,
        Did2CompactionPlan.RootKind.Read, Did2CompactionPlan.RootKind.SessionCatalog, Did2CompactionPlan.RootKind.Attachment,
        Did2CompactionPlan.RootKind.AccountRegistration, Did2CompactionPlan.RootKind.NativeFence,
        Did2CompactionPlan.RootKind.ContactPublication, Did2CompactionPlan.RootKind.MailboxLocalCustody];

    private static void RequireRetainedPathProfile(Did2CompactionPlan plan)
    {
        if (plan.Target != Did2CompactionPlan.SqlTarget.Application || plan.RootCount != RetainedPathKinds.Length ||
            plan.RowCount is < 2 or > Did2CompactionPlan.MaximumRows ||
            plan.ReadRow(plan.RowCount - 1).Action != Did2CompactionPlan.Disposition.RetainedPath ||
            !FixedRoute(plan.ReadRow(plan.RowCount - 1).Selector.Span, plan.SqlSelector))
            throw new InvalidDataException("No recovery is installed for this retained-path profile.");
        for (var i = 0; i < plan.RootCount; i++)
        {
            var root = plan.ReadRoot(i);
            if (root.Kind != RetainedPathKinds[i] || root.Guard != (i is not (2 or 3 or 8)))
                throw new InvalidDataException("Retained-path root profile changed.");
        }
        for (var i = 0; i < plan.RowCount - 1; i++)
            if (plan.ReadRow(i).Action != Did2CompactionPlan.Disposition.ReplayScope) throw new InvalidDataException("Retained-path grant selection changed.");
    }

    internal async Task<IReadOnlyList<Did2CompactionPlan.RootReadback>> ReadRetainedPathRootsUnderLeaseAsync(
        Did2CompactionPlan plan, HeldDeepIdV2AccountLease held, CancellationToken ct, VerifiedDeepIdV2CurrentAccount? selecting = null)
    {
        RequireRetainedPathProfile(plan); held.RequireOwner(lease);
        var account = plan.Exact.Slice(32, 32); var instance = plan.Exact.Slice(64, 32);
        if (selecting is null)
        {
            using var actual = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId, account, instance, ct).ConfigureAwait(false);
            if (!FixedRoute(actual.Exact.Span, plan.Exact.Span)) throw new CryptographicException("Retained-path plan changed during recovery.");
        }
        var result = await ReadMailboxProtectedRootsUnderLeaseAsync(account, instance, held, ct).ConfigureAwait(false);
        result.Add(selecting is null
            ? await SqliteDeepIdV2AccountGeneration.ReadStoredPlanNativeFenceUnderLeaseAsync(storage, lease, sqlStatePath, plan, held, ct).ConfigureAwait(false)
            : await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(storage, lease, sqlStatePath, selecting, held, ct).ConfigureAwait(false));
        using var publication = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Retained-path publication root is absent.");
        using var decoded = publication.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
        result.Add(new(Did2CompactionPlan.RootKind.ContactPublication, CompactionSlotSelector(ProtectedDid2ContactRouteJournal.Slot), publication.Use(bytes => SHA256.HashData(bytes))));
        result.Add(await ReadMailboxLocalCustodyUnderLeaseAsync(account, instance, held, ct).ConfigureAwait(false));
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
    }

    private async Task RequireIdleArchivedPathWorkUnderLeaseAsync(ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> route, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, account.Span, instance.Span));
        using var assetRaw = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var assets = assetRaw.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, account.Span, instance.Span));
        using var sendRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var sends = sendRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, account.Span, instance.Span));
        if (ordinary.Entries.Count != 0 || assets.Entries.Count != 0 || sends.Entries.Values.Any(entry => FixedRoute(entry.RouteHash, route.Span)))
            throw new IOException("Ordinary, attachment or original send work pins archived-path retirement.");
    }

    private static KeyValuePair<string, ProtectedDid2ContactRouteJournal.Entry> RequireArchivedPath(
        ProtectedDid2ContactRouteJournal.State publications, ReadOnlySpan<byte> route)
    {
        var selected = new List<KeyValuePair<string, ProtectedDid2ContactRouteJournal.Entry>>();
        foreach (var pair in publications.Entries)
            if (pair.Value.Phase == 7 && pair.Value.Kind == 1 && FixedRoute(ContactRouteClosureCodec.Decode(pair.Value.Record(6).Span).ExactHash.Span, route)) selected.Add(pair);
        if (selected.Count != 1) throw new CryptographicException("Archived-path publication selection is absent or ambiguous.");
        return selected[0];
    }

    private static List<byte[]> RequireArchivedPathGrants(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> route)
    {
        var selected = new List<byte[]>();
        foreach (var pair in state.Entries)
        {
            var entry = pair.Value;
            if (!FixedRoute(ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash.Span, route)) continue;
            var scope = Convert.ToHexString(entry.AsSpan(0, 32));
            if (!ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(entry) || !state.Selections.TryGetValue(scope, out var selection) || selection.Pending is not null ||
                selection.Current != pair.Key || selection.RetainedTail != pair.Key ||
                state.Entries.Values.Count(value => FixedRoute(value.AsSpan(0, 32), entry.AsSpan(0, 32))) != 1 ||
                ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0] != (byte)MailboxCapabilityDomain.Retrieve)
                throw new IOException("A pending, unused, linked or Store acquisition pins the archived path.");
            selected.Add(entry);
        }
        if (selected.Count is < 1 or >= Did2CompactionPlan.MaximumRows) throw new IOException("Archived-path holder selection is absent or exceeds the existing batch bound.");
        return selected;
    }

    private static ClientMailboxScope ArchivedPathReadScope(ParsedContactRouteClosure route) => ClientMailboxScope.Derive(
        route.ExactHash.Span, new BlindedMailboxId(route.Reachability.Field(2).Span), BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span));

    private static byte[] RemoveArchivedPathGrants(ProtectedDid2MailboxGrantJournal.State state, ReadOnlySpan<byte> route,
        IReadOnlyList<Did2CompactionPlan.Row> rows, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var selected = RequireArchivedPathGrants(state, route);
        if (selected.Count != rows.Count - 1) throw new CryptographicException("Archived-path grant count changed.");
        foreach (var entry in selected)
        {
            var digest = SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
            var matching = rows.Where(row => row.Action == Did2CompactionPlan.Disposition.ReplayScope && FixedRoute(row.Selector.Span, digest)).ToArray();
            if (matching.Length != 1 || !FixedRoute(matching[0].Commitment.Span, SHA256.HashData(entry))) throw new CryptographicException("Archived-path grant changed exact custody.");
            state.Selections.Remove(Convert.ToHexString(entry.AsSpan(0, 32)));
            state.Entries.Remove(ProtectedDid2MailboxGrantJournal.Acquisition(entry)); CryptographicOperations.ZeroMemory(entry);
        }
        state.Revision = checked(state.Revision + 1);
        return ProtectedDid2MailboxGrantJournal.Encode(state, network, account, instance);
    }

    private static byte[] RemoveArchivedPathRead(ProtectedDid2MailboxReadJournal.State state, ParsedContactRouteClosure route,
        IReadOnlyList<Did2CompactionPlan.Row> rows, ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        if (state.Phase != 0 || state.Active is not null) throw new IOException("An active original read/ACK pins retirement.");
        foreach (var row in rows.Where(row => row.Action == Did2CompactionPlan.Disposition.ReplayScope))
            if (!state.Counters.Remove(Convert.ToHexString(row.Selector.Span))) throw new CryptographicException("Archived-path replay counter is absent.");
        if (!state.Traversals.Remove(Convert.ToHexString(ArchivedPathReadScope(route).Value))) throw new CryptographicException("Archived-path traversal is absent.");
        state.Revision = checked(state.Revision + 1);
        return ProtectedDid2MailboxReadJournal.Encode(state, network, account, instance);
    }

    private static byte[] RemoveArchivedPublication(ProtectedDid2ContactRouteJournal.State state, Did2CompactionPlan.Row row,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> account, ReadOnlySpan<byte> instance)
    {
        var archive = RequireArchivedPath(state, row.Selector.Span);
        if (row.Action != Did2CompactionPlan.Disposition.RetainedPath || !FixedRoute(SHA256.HashData(archive.Value.Exact), row.Commitment.Span) || state.Entries.Count < 2)
            throw new CryptographicException("Archived-path publication changed or is the final route.");
        state.Entries.Remove(archive.Key); archive.Value.Dispose();
        return ProtectedDid2ContactRouteJournal.Encode(state, network, account, instance);
    }
}
