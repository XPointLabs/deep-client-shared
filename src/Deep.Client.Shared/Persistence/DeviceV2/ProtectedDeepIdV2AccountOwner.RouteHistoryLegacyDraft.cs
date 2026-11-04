using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Only the first own bootstrap uses this ordering barrier. New code cannot
    // author legacy6/7 after bootstrap. Native-committed uncertainty remains
    // retryable; an uncommitted stop must finish its existing cleanup first.
    private async Task<byte[]> RequireRetainedLegacyRouteDraftsDrainedUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease); var scope = opened.Scope;
        using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
            storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Own history bootstrap lost its retained authored work.");
        var exactRoot = raw.Use(bytes => bytes.ToArray()); raw.Dispose();
        try
        {
            using var journal = ProtectedDid2DirectTextJournal.Decode(exactRoot, scope.Network, scope.LocalAccount, scope.Instance);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            var blocked = false;
            foreach (var command in journal.Entries.Values.Where(entry => entry.Kind == Dmc2ContentKind.ContactRouteUpdate &&
                FixedRoute(entry.Scope.Exact, scope.Exact)))
            {
                var op = command.Operation.ToArray();
                using var native = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, op), ct).ConfigureAwait(false);
                if (native is not null)
                {
                    if (native.Direction != 1 || !FixedRoute(native.EventHash, command.EventHash))
                        throw new CryptographicException("Retained route work differs from its actual native commit.");
                    continue;
                }
                if (command.Stored) throw new CryptographicException("Stored route work lost its actual native commit.");
                var exact = await ReadOwnedHistoryCommandUnderLeaseAsync(current, application, journal, scope, command, ct).ConfigureAwait(false);
                try { blocked |= ApplicationCoreCodec.DecodeDmc2(exact).ParsedPayload is ContactRouteUpdateDmc2Payload; }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2DirectTextJournal.Slot, exactRoot, ct).ConfigureAwait(false);
            if (blocked) throw new RouteHistoryWorkNotRequiredException("Finish the exact retained legacy route work before new history work.");
            return SHA256.HashData(exactRoot);
        }
        finally { CryptographicOperations.ZeroMemory(exactRoot); }
    }
}
