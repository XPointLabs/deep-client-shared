using System.Buffers.Binary;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // One locally retained control per invocation. Repeated maintenance can
    // drain further pages; absence or an unusable candidate never spins.
    internal async Task<bool> ContinueRouteHistoryAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        using (var initial = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2, Did2RouteHistorySelection.Initial(), held, ct).ConfigureAwait(false))
            if (initial.Snapshot.PreviousDecision is null || !initial.Snapshot.FirstFault.IsAbsent) return false;
        var cursor = await ReadAdoptedRouteHistoryCursorUnderLeaseAsync(opened, 2, held, ct).ConfigureAwait(false);
        var c = BinaryPrimitives.ReadUInt64BigEndian(cursor); var p = BinaryPrimitives.ReadUInt64BigEndian(cursor.AsSpan(40));
        var selectors = new List<Did2RouteHistoryFactSelector>();
        if (c < ulong.MaxValue) selectors.Add(HistorySelector(2, 1, c + 1));
        if (p < ulong.MaxValue) selectors.Add(HistorySelector(2, 2, p + 1));
        var endpoint = new byte[42]; endpoint[0] = 1; endpoint[1] = 2; cursor.AsSpan(0, 40).CopyTo(endpoint.AsSpan(2));
        selectors.Add(new(Did2MessagingArchiveFamily.RouteControl, endpoint));
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 2, Did2RouteHistorySelection.Initial(selectors), held, ct).ConfigureAwait(false);
        var candidates = new List<(Did2MessagingArchiveReference Reference, ulong Sequence)>();
        foreach (var fact in read.Snapshot.Facts)
        {
            if (fact.Value is not { } value) continue;
            if (fact.Selector.Family == Did2MessagingArchiveFamily.RouteHistory)
            {
                var candidate = Did2RouteHistorySource.Decode(value.Span.Slice(120, 96));
                if (!candidate.IsAbsent) candidates.Add((candidate.Reference, BinaryPrimitives.ReadUInt64BigEndian(value.Span[216..])));
            }
            else
            {
                var candidate = Did2MessagingArchiveReference.Decode(value.Span[..88], false);
                if (!FixedRoute(candidate.Exact.Span, read.Snapshot.L.Exact.Span))
                    candidates.Add((candidate, BinaryPrimitives.ReadUInt64BigEndian(value.Span[88..])));
            }
        }
        var selected = candidates.Where(value => value.Reference.Kind == 2 && value.Reference.Direction == 2)
            .OrderByDescending(value => value.Sequence).ThenBy(value => value.Reference.Ordinal).FirstOrDefault();
        if (selected.Reference is null) return false;
        var before = read.Snapshot.Before.Ordinal;
        var operation = selected.Reference.Operation.ToArray();
        await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
        await opened.WithPairedSqlAsync(read.Authored.PairedRead,
            sql => { sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true; }, ct).ConfigureAwait(false);
        await ProcessRouteHistoryControlUnderLeaseAsync(current, opened, operation, false, own, peer, source, held, ct).ConfigureAwait(false);
        return (await opened.Custody.ReadCurrentFloorAsync(ct).ConfigureAwait(false)).Ordinal > before;
    }
}
