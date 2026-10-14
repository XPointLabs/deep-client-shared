using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Fresh encryption and its actual native commit both use this check. A
    // structurally valid caller control, an authored SQL row or a current route
    // alone is insufficient. Exact committed replay must not reopen/remint the
    // latest publication; its historical consumer is a separate obligation.
    private async Task RequireOwnRouteControlAdmissionUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> exact,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested(); var scope = opened.Scope;
        RequireRequestedAuthoredKind(exact.Span, null, true, scope);
        using var owner = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Route-control admission lost mandatory authored custody.");
        var root = owner.Use(bytes => bytes.ToArray());
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(root, scope.Network, scope.LocalAccount, scope.Instance);
            if (journal.Pending is not null ||
                !journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command) ||
                command.Pending || command.Kind != Dmc2ContentKind.ContactRouteUpdate ||
                !FixedRoute(command.Scope.Exact, scope.Exact))
                throw new CryptographicException("Fresh route-control encryption requires its exact stable owned command.");
            command.RequireEvent(exact.Span);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            using var row = await application.ReconcileOwnedTextOutboxAsync(journal, current.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope, operation, ct,
                requireStableReadOnly: true).ConfigureAwait(false) ??
                throw new CryptographicException("Fresh route-control encryption lost actual stable SQL custody.");
            if (!OwnedByteExports.EqualAndErase(row.ExactDmc2, exact.Span))
                throw new CryptographicException("Fresh route-control encryption differs from its owned command.");
            var head = await ReadOwnNativeRouteHeadUnderLeaseAsync(current, held, opened, application,
                journal, own, peer, source, ct).ConfigureAwait(false);
            using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, own, ct).ConfigureAwait(false);
            var route = await DeepIdV2ContactRouteUpdateVerifier.VerifyCurrentSuccessorAsync(head.Original,
                own.Proof, own.Network, own.Authority, source.RendezvousTrustedTime, head.ExactRoute,
                head.EventHash, scope.Relationship.ToArray(), scope.Conversation.ToArray(), exact, ct).ConfigureAwait(false);
            if (!FixedRoute(route.ExactRouteClosure.Span, publication.Route.ExactRouteClosure.Span))
                throw new CryptographicException("Fresh route control is not this account's actual adopted publication.");
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            await route.EnsureCurrentAsync(ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(floor.Exact.Span, head.NativeFloor.Span))
                throw new CryptographicException("Route-control native predecessor changed during admission.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, root, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
        }
        finally { CryptographicOperations.ZeroMemory(root); }
    }
}
