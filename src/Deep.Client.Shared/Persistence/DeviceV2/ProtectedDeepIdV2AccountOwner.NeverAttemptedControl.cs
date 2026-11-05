using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<bool> TryStopNeverAttemptedRouteControlUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ProtectedDid2DirectTextJournal.State authored,
        ProtectedDid2DirectTextJournal.Entry command, byte[] sendSnapshot,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        if (command.Kind != Dmc2ContentKind.ContactRouteUpdate) return false;
        if (command.Pending || command.Stored || command.WorkStopped || !FixedRoute(command.Scope.Exact, scope.Exact))
            throw new CryptographicException("Never-attempted stop requires exact stable active owned control custody.");
        using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        using (var native = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, command.Operation), ct).ConfigureAwait(false))
        {
            if (native is null) return false; // No expiry inference for an uncommitted draft.
            if (native.Direction != 1 || !FixedRoute(native.EventHash, command.EventHash))
                throw new CryptographicException("Never-attempted stop lost its actual native outgoing identity.");
        }
        using var read = await ReadRouteHistorySourcesUnderLeaseAsync(opened, 1,
            Did2RouteHistorySelection.Custody(command.Operation), held, ct).ConfigureAwait(false);
        var selected = read.Snapshot.SelectedOriginal;
        if (selected.Reference.Direction != 1 || !FixedRoute(selected.Reference.Operation, command.Operation) ||
            !FixedRoute(selected.Metadata.AsSpan(300, 32), command.EventHash))
            throw new CryptographicException("Never-attempted stop selected another native control.");
        var exact = read.Original(selected.Reference);
        var message = ApplicationCoreCodec.DecodeDmc2(exact.Span); command.RequireEvent(exact.Span);
        if (message.ParsedPayload is not ContactRouteHistoryDmc2Payload) return false; // Retained6/7 keeps its owner.
        if (message.ExpiresAtUnixMilliseconds == 0)
            throw new CryptographicException("Never-attempted control has no canonical expiry.");
        using var qualifiedOrdinary = ProtectedDid2DirectTextJournal.Decode(read.Authored.OrdinaryExact,
            scope.Network, scope.LocalAccount, scope.Instance);
        var expectedOrdinary = ProtectedDid2DirectTextJournal.Encode(authored, scope.Network, scope.LocalAccount, scope.Instance);
        var roots = read.Authored.Roots.ToDictionary(pair => pair.Key, pair => pair.Value?.ToArray(), StringComparer.Ordinal);
        byte[] logical = [], next = [];
        try
        {
            if (!FixedRoute(expectedOrdinary, read.Authored.OrdinaryExact))
                throw new CryptographicException("Never-attempted stop changed the authoritative authored predecessor.");
            using (var inventory = await storage.ReadOwnedBatchAsync(
                [ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2MailboxGrantJournal.Slot], ct).ConfigureAwait(false))
            {
                var sendsRaw = inventory[0] ?? throw new InvalidDataException("Never-attempted stop lost send custody.");
                var grantsRaw = inventory[1] ?? throw new InvalidDataException("Never-attempted stop lost grant custody.");
                sendsRaw.Use(bytes =>
                {
                    if (!FixedRoute(bytes, sendSnapshot)) throw new CryptographicException("Never-attempted stop changed actual send custody.");
                    using var sends = ProtectedDid2MailboxSendJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance);
                    if (sends.Entries.Values.Any(value => FixedRoute(value.ScopeHash, scope.Hash) && FixedRoute(value.Operation, command.Operation)))
                        throw new CryptographicException("Never-attempted stop has an owned send attempt.");
                    roots.Add(ProtectedDid2MailboxSendJournal.Slot, SHA256.HashData(bytes)); return true;
                });
                grantsRaw.Use(bytes =>
                {
                    using var grants = ProtectedDid2MailboxGrantJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance);
                    roots.Add(ProtectedDid2MailboxGrantJournal.Slot, SHA256.HashData(bytes)); return true;
                });
            }
            var reading = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
            var lower = checked(own.Proof.TrustedLowerUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample);
            if (lower < Did2ControlWorkStop.ProvenExpirySecond(message.ExpiresAtUnixMilliseconds)) return false;
            logical = MailboxSendOperation(scope, command.Operation, selected.Envelope);
            var paired = new Did2MessagingArchiveAuthoredRead(roots, connection =>
            {
                read.Authored.PairedRead.Verify(connection);
                using var ordinary = ProtectedDid2DirectTextJournal.Decode(read.Authored.OrdinaryExact,
                    scope.Network, scope.LocalAccount, scope.Instance);
                var actual = ordinary.Entries[Convert.ToHexString(command.Operation)];
                SqliteDeepMailboxStore.RequireNeverAttemptedControl(connection, actual, logical);
            });
            Task<bool> Rejoin() => opened.WithPairedSqlAsync(paired, sql =>
            {
                sql.RequireRouteHistorySnapshot(read.Snapshot, read.Authored.Events); return true;
            }, ct);
            await Rejoin().ConfigureAwait(false);
            qualifiedOrdinary.StopWork(Convert.ToHexString(command.Operation), ProtectedDid2DirectTextJournal.WorkStopReason.RetryExpired,
                checked(own.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - own.Proof.MonotonicSample));
            next = ProtectedDid2DirectTextJournal.Encode(qualifiedOrdinary, scope.Network, scope.LocalAccount, scope.Instance);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeWorkStopRoot);
#endif
            if (!await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, expectedOrdinary, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Never-attempted stop changed its exact authored predecessor.");
#if DEEP_TEST_INTERNALS
            Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterWorkStopRoot);
#endif
            CryptographicOperations.ZeroMemory(roots[ProtectedDid2DirectTextJournal.Slot]!);
            roots[ProtectedDid2DirectTextJournal.Slot] = SHA256.HashData(next);
            CryptographicOperations.ZeroMemory(read.Authored.OrdinaryExact); read.Authored.OrdinaryExact = next.ToArray();
            // This is a single-root CAS, not a multi-root transaction. A failed
            // post-CAS proof leaves only the denial-only stop; no cleanup or
            // successful scheduling result may escape this call.
            await Rejoin().ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return true;
        }
        finally
        {
            foreach (var digest in roots.Values) if (digest is not null) CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(expectedOrdinary); CryptographicOperations.ZeroMemory(logical); CryptographicOperations.ZeroMemory(next);
        }
    }
}
