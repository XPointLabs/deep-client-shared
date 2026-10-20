using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Scheduling only: null means no changed advertisement; empty means a new
    // owner-authored update is needed;32 bytes select exact existing work. The
    // actual author/encryption/Store owners independently recheck every effect.
    internal async Task<byte[]?> SelectOwnRouteMaintenanceAsync(ulong seconds, IDeepMlDsa65Verifier verifier,
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
        using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status != 1) throw new CryptographicException("Inactive messaging cannot maintain a route.");
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        var retained = journal.Entries.Values.Where(item => item.Kind == Dmc2ContentKind.ContactRouteUpdate &&
            FixedRoute(item.Scope.Exact, scope.Exact) && !item.Stored && !item.WorkStopped).OrderBy(item => item.Sequence).FirstOrDefault();
        byte[]? result;
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
        }
        try
        {
            await RequireFinalMessagingFreshnessAsync(current, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return result;
        }
        catch { if (result is not null) CryptographicOperations.ZeroMemory(result); throw; }
    }
}
