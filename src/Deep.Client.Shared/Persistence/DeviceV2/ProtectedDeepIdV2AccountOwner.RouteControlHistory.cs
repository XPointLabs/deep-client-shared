using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Key-free bytes only for the closed historical handoff. Fresh native send
    // uses the separate current/adopted publication admission, not this reader.
    internal async Task<byte[]> ReadVerifiedOwnRouteControlCommitUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount account, HeldDeepIdV2AccountLease held,
        OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        ct.ThrowIfCancellationRequested(); var scope = opened.Scope;
        RequireRetainedStoreOwnScope(scope, own);
        if (!FixedRoute(account.AccountId.Span, scope.LocalAccount))
            throw new CryptographicException("Own route-control history belongs to another registered account.");
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Own route-control history lost mandatory authored custody.");
        var root = raw.Use(bytes => bytes.ToArray()); byte[] exact = [];
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(root, scope.Network, scope.LocalAccount, scope.Instance);
            if (journal.Pending is not null) throw new CryptographicException("Own route-control history has unresolved authored work.");
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            using var native = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ??
                throw new CryptographicException("Own route control has no actual native commit.");
            if (native.Direction != 1) throw new CryptographicException("Own route control cannot originate from an incoming event.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, account, held, ct).ConfigureAwait(false);
            using var row = await application.ReconcileOwnedTextOutboxAsync(journal, account.AccountId,
                BinaryPrimitives.ReadUInt64BigEndian(scope.Exact[84..]), scope,
                journal.Entries.ContainsKey(Convert.ToHexString(operation.Span)) ? operation : ReadOnlyMemory<byte>.Empty,
                ct, requireStableReadOnly: true).ConfigureAwait(false);
            if (journal.Entries.TryGetValue(Convert.ToHexString(operation.Span), out var command))
            {
                if (command.Pending || command.Kind != Dmc2ContentKind.ContactRouteUpdate ||
                    !FixedRoute(command.Scope.Exact, scope.Exact) || row is null)
                    throw new CryptographicException("Own route control lost its exact stable authored command.");
                exact = OwnedByteExports.TakeArray(row!.ExactDmc2);
                command.RequireEvent(exact);
            }
            else exact = await application.ReadRetainedAuthoredEventAsync(scope, native.EventHash.ToArray(), ct).ConfigureAwait(false) ??
                throw new CryptographicException("Compacted own route control lost independent local history.");
            RequireRequestedAuthoredKind(exact, null, true, scope);
            var parsed = ApplicationCoreCodec.DecodeDmc2(exact);
            if (!FixedRoute(SHA256.HashData(exact), native.EventHash) || parsed.SenderClientSequence >= journal.NextSequence(scope))
                throw new CryptographicException("Own route control differs from actual native event and authored floor.");
            // This independently authenticates every actual outgoing control,
            // including the selected earlier member, and actual native consent.
            // It grants no authority from the latest route or publication.
            var head = await ReadOwnNativeRouteHeadUnderLeaseAsync(account, held, opened, application,
                journal, own, peer, source, ct).ConfigureAwait(false);
            var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (!FixedRoute(head.NativeFloor.Span, floor.Exact.Span) || !FixedRoute(final.Exact.Span, floor.Exact.Span))
                throw new CryptographicException("Own route-control native history changed during reconstruction.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, root, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var released = exact; exact = []; return released;
        }
        finally { CryptographicOperations.ZeroMemory(root); CryptographicOperations.ZeroMemory(exact); }
    }
}
