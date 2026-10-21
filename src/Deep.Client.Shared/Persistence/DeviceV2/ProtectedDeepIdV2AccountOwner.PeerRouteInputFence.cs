using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Owned by this one held Store only, never serialized, shared across leases
    // or substituted for endpoint/time/native verification. Native VerifyTip
    // reauthenticates ALL SQL rows and the protected historical prefix, not just
    // a latest SQL ordinal. These additional exact digests cover the two inputs
    // to original consent reconstruction that are outside that native tip.
    private sealed record PeerRouteInputFence(byte[] Scope, byte[] AcceptanceRoot, byte[] AcceptanceProjection);

    private async Task<PeerRouteInputFence?> ReadPeerRouteInputFenceUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); var scope = opened.Scope;
        using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Held route lost its mandatory consent root.");
        if (!scope.IsInitiator)
        {
            using var consent = root.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                scope.Network, scope.LocalAccount, scope.Instance));
            // First acceptance legitimately commits its own Store marker. Such
            // unsettled consent, including pre-acceptance braid work, retains
            // complete semantic reconstruction at every boundary instead.
            if (consent.FindScope(scope)?.SuccessfullyStored != true) return null;
        }
        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(
            storage, sqlStatePath, scope, held, lease, ct).ConfigureAwait(false);
        var accepted = await application.ReadContactAcceptAsync(current.AccountId,
            BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope.Conversation.ToArray(),
            (scope.IsInitiator ? scope.RemoteAccount : scope.LocalAccount).ToArray(),
            (scope.IsInitiator ? scope.RemoteDevice : scope.LocalDevice).ToArray(), ct).ConfigureAwait(false);
        if (accepted is null) return null; // No new prerequisite for a full route read.
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(scope.Hash.ToArray(), root.Use(static bytes => SHA256.HashData(bytes)), SHA256.HashData(accepted));
        }
        finally { CryptographicOperations.ZeroMemory(accepted); }
    }

    private static void RequireSamePeerRouteInputs(PeerRouteInputFence expected, PeerRouteInputFence actual)
    {
        if (!FixedRoute(expected.Scope, actual.Scope) || !FixedRoute(expected.AcceptanceRoot, actual.AcceptanceRoot) ||
            !FixedRoute(expected.AcceptanceProjection, actual.AcceptanceProjection))
            throw new CryptographicException("Actual consent inputs changed during the held peer-route verification.");
    }

    private async Task RecheckPeerMailboxRouteUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        OwnedDid2MessagingStorage opened, OwnedPeerMailboxRoute route,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var expected = route.Inputs;
        if (expected is null)
        {
            var verified = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
            if (!FixedRoute(verified.HeadEventHash.Span, route.HeadEventHash.Span) ||
                !FixedRoute(verified.NativeFloor.Span, route.NativeFloor.Span) ||
                !FixedRoute(verified.Route.ExactRouteClosure.Span, route.Route.ExactRouteClosure.Span))
                throw new CryptographicException("Actual peer route changed during full current reconstruction.");
            return;
        }
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(floor.Exact.Span, route.NativeFloor.Span))
            throw new CryptographicException("Actual native peer route history changed during this exact dispatch.");
        var actual = await ReadPeerRouteInputFenceUnderLeaseAsync(current, opened, held, ct).ConfigureAwait(false);
        if (actual is null) throw new CryptographicException("Held route lost its stable consent inputs.");
        RequireSamePeerRouteInputs(expected, actual);
        await route.Route.EnsureCurrentAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }
}
