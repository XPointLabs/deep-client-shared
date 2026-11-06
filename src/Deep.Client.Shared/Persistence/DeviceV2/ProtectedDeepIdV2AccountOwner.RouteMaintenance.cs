using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Scheduling only: null means no runnable advertisement; empty means a new
    // owner-authored update is needed;32 bytes select exact existing work. The
    // actual author/encryption/Store owners independently recheck every effect.
    internal async Task<byte[]?> SelectOwnRouteMaintenanceAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var selected = await SelectOwnRouteMaintenanceCandidateAsync(seconds, verifier, scope, own, peer, source, ct).ConfigureAwait(false);
        try
        {
            if (selected is { Length: 32 } &&
                await ReadMessagingWorkPreflightAsync(seconds, verifier, scope, selected, own, source, ct).ConfigureAwait(false) ==
                    MessagingWorkPreflightResult.ExpiredOriginalStopCompleted)
            {
                // No Store success and no replacement are inferred. The next
                // normal receive/request phase decides whether work is needed.
                CryptographicOperations.ZeroMemory(selected);
                return null;
            }
            return selected;
        }
        catch { if (selected is not null) CryptographicOperations.ZeroMemory(selected); throw; }
    }

    private async Task<byte[]?> SelectOwnRouteMaintenanceCandidateAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        await ResumeLocalCompactionUnderLeaseAsync(held, ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(seconds, verifier, ct).ConfigureAwait(false);
        var first = await RequireMessagingFreshnessAsync(current, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Route maintenance lost mandatory authored custody.");
        using var journal = raw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        if (journal.Pending is { } pending && (pending.Kind != Dmc2ContentKind.ContactRouteUpdate || !FixedRoute(pending.Scope.Exact, scope.Exact)))
            throw new InvalidOperationException("Resume the existing authored command before route maintenance.");
        using var opened = await OpenNativeMessagingUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status != 1) throw new CryptographicException("Inactive messaging cannot maintain a route.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var retained = journal.Entries.Values.Where(item => item.Kind == Dmc2ContentKind.ContactRouteUpdate &&
            FixedRoute(item.Scope.Exact, scope.Exact) && !item.Stored && !item.WorkStopped).OrderBy(item => item.Sequence).FirstOrDefault();
        byte[]? result; byte[] proactiveRoot = []; OwnNativeRouteHead? proactiveHead = null;
        if (retained is not null)
        {
            // No new operation, payload or publication is substituted for an
            // interrupted control. Its ordinary owner will reconcile actual SQL.
            result = retained.Operation.ToArray();
        }
        else
        {
            var head = await ReadOwnNativeRouteHeadUnderLeaseAsync(current, held, opened, application, journal, own, peer, source, ct).ConfigureAwait(false);
            using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, own, ct).ConfigureAwait(false);
            result = FixedRoute(head.ExactRoute.Span, publication.Route.ExactRouteClosure.Span) ? null : [];
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            if (result is null && !head.Announcement.IsEmpty)
            {
                // Settled history is immutable. A fresh uncorrelated announcement
                // can advertise the same endpoint when its last count8 envelope
                // no longer covers this interval; active originals above always win.
                var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
                var message = ApplicationCoreCodec.DecodeDmc2(head.Announcement.Span);
                var upper = checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
                if (message.CreatedAtUnixMilliseconds > checked(upper * 1000) ||
                    message.ExpiresAtUnixMilliseconds == 0 || checked(upper * 1000) >= message.ExpiresAtUnixMilliseconds)
                    result = [];
                else if (upper >= ProactiveRefreshAt(message.CreatedAtUnixMilliseconds / 1000,
                    message.ExpiresAtUnixMilliseconds / 1000))
                {
                    // Scheduling only. The unchanged limiting signed artifact
                    // cannot be worked around by minting another control.
                    proactiveRoot = raw.Use(bytes => SHA256.HashData(bytes)); proactiveHead = head;
                    try
                    {
                        var expiry = await ApplicationCoreCodec.ReadVerifiedContactRouteHistoryAnnouncementExpiryAsync(
                            head.PagedFacts ?? throw new CryptographicException("Announcement lost its verified count8 endpoint."),
                            publication.Route.Recipient, own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                        await publication.RecheckAsync(ct).ConfigureAwait(false);
                        if (expiry > message.ExpiresAtUnixMilliseconds) result = [];
                    }
                    catch { CryptographicOperations.ZeroMemory(proactiveRoot); throw; }
                }
            }
            if (result is null && await OwnRendezvousMaintenanceDueUnderLeaseAsync(current, opened,
                head.Announcement, own, peer, source, held, ct).ConfigureAwait(false)) result = [];
        }
        try
        {
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            if (proactiveHead is not null)
            {
                var finalHead = await ReadOwnNativeRouteHeadUnderLeaseAsync(current, held, opened, application,
                    journal, own, peer, source, ct, proactiveRoot).ConfigureAwait(false);
                if (!FixedRoute(finalHead.NativeFloor.Span, proactiveHead.NativeFloor.Span) ||
                    !FixedRoute(finalHead.EventHash.Span, proactiveHead.EventHash.Span) ||
                    !FixedRoute(finalHead.Announcement.Span, proactiveHead.Announcement.Span))
                    throw new CryptographicException("Announcement maintenance changed its actual native source.");
            }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
        }
        catch { if (result is not null) CryptographicOperations.ZeroMemory(result); throw; }
        finally { CryptographicOperations.ZeroMemory(proactiveRoot); }
    }
}
