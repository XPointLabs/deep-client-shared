using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal Task<byte[]> ReadVerifiedPeerRouteControlCommitUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount account, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct) =>
        ReadPeerRouteProcessingCommitUnderLeaseAsync(account, held, opened, operation, own, peer, source, 1, ct);

    // No semantic handoff or ACK capability is exported for a rejection. Both
    // receive and ACK reconstruct the original native result independently.
    private async Task RequireRejectedPeerRouteControlCommitUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount account, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var exact = await ReadPeerRouteProcessingCommitUnderLeaseAsync(account, held, opened,
            operation, own, peer, source, 2, ct).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(exact);
    }

    private async Task<byte[]> ReadPeerRouteProcessingCommitUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount account, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source,
        byte expectedOutcome, CancellationToken ct)
    {
        held.RequireOwner(lease); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var scope = opened.Scope;
        if (!FixedRoute(account.AccountId.Span, scope.LocalAccount))
            throw new CryptographicException("Peer route history belongs to another account owner.");
        var first = await RequireMessagingFreshnessAsync(account, own, peer, source, held, ct).ConfigureAwait(false);
        OwnedInitialMessagingSeed.RequireFreshScope(scope, own.Proof, peer, first);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
            throw new CryptographicException("Peer route control has no actual native receive commit.");
        if (native.Direction != 2 || native.RouteProcessing[0] != expectedOutcome)
            throw new CryptographicException("Peer route control differs from its original native processing outcome.");
        using var plain = native.OwnAuthenticatedDmc2();
        var exact = plain.Use(bytes => bytes.ToArray());
        try
        {
            if (exact.Length is < 4497 or > 23649)
                throw new CryptographicException("Native peer route control has a different closed size.");
            var message = ApplicationCoreCodec.DecodeDmc2(exact);
            if (message.ContentKind != Dmc2ContentKind.ContactRouteUpdate ||
                !FixedRoute(message.NetworkId.Span, scope.Network) ||
                !FixedRoute(message.SenderAccountId.Span, scope.RemoteAccount) ||
                !FixedRoute(message.SenderDeviceId.Span, scope.RemoteDevice))
                throw new CryptographicException("Native peer route processing differs from its authenticated endpoint.");
            Did2RouteProcessingMetadata.RequireReceivedEvent(native.RouteProcessing, message);
            // Every accepted native member is independently checked for
            // history, scope and consent. Later faults cannot erase an earlier
            // positive materialization; no current-route capability is needed.
            var history = await ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(account, opened,
                own, peer, source, held, ct).ConfigureAwait(false);
            await AuthenticatedInitialDmc2Batch.RequireRetainedMailboxRouteFactsAsync(history.Original,
                peer, own, source, held, ct).ConfigureAwait(false);
            if (expectedOutcome == 2 && !history.Faulted)
                throw new CryptographicException("Rejected native route processing lost its retained fault fence.");
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(history.NativeFloor.Span, floor.Exact.Span) || !FixedRoute(final.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Peer route processing changed during historical reconstruction.");
            await RequireFinalMessagingFreshnessAsync(account, scope, own, peer, source, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var result = exact; exact = []; return result;
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
