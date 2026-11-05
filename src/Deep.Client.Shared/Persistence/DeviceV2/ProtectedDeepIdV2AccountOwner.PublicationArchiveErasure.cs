using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task RequireNoSealedAcquisitionForPathAsync(ProtectedDid2MailboxGrantJournal.State grants,
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, ReadOnlyMemory<byte> route,
        HeldDeepIdV2AccountLease held, CancellationToken ct, Dictionary<string, byte[]?>? guards = null)
    {
        held.RequireOwner(lease);
        foreach (var pair in grants.Retained)
        {
            var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(pair.Key));
            using var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false);
            if (guards is not null) guards.Add(slot, raw?.Use(bytes => SHA256.HashData(bytes)));
            if (raw is null)
            {
                if (pair.Value.Phase != 3) throw new CryptographicException("Publication erasure lost sealed acquisition custody.");
                continue; // Its existing owner already authorized and completed erasure.
            }
            using var retained = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(grants, pair.Key,
                bytes, networkId, account.Span, instance.Span));
            var original = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(retained.Entries[pair.Key]).Span);
            if (FixedRoute(original.ExactHash.Span, route.Span))
                throw new IOException("A sealed acquisition still pins the original publication path.");
        }
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }

    // Only a durable erasure tombstone produced by the original joint SQL and
    // protected-root retirement can enter this owner. No time or new authority
    // is inferred here. The existing compaction owner calls this only while idle.
    private async Task DrainPublicationArchiveErasuresUnderLeaseAsync(ReadOnlyMemory<byte> account,
        ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireOwner(lease);
        for (var iteration = 0; iteration < ProtectedDid2ContactRouteJournal.MaximumIntents; iteration++)
        {
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Publication erasure root is absent.");
            // V10 remains accessible only through explicit enrollment. Before
            // enrollment no V11 erasure tombstone can exist.
            if (raw.Length < 92) throw new InvalidDataException("Publication erasure root is truncated.");
            if (raw.Use(bytes => bytes[0]) == 10) return;
            if (!raw.Use(bytes =>
            {
                registrationGrammar.Validate(RegistrationGrammarKind.ContactRoutes, bytes, networkId, account.Span, instance.Span);
                return ProtectedDid2ContactRouteJournal.HasErasureAfterGrammarValidation(bytes);
            })) return;
            using var state = raw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes, networkId, account.Span, instance.Span));
            var selected = state.Archived.FirstOrDefault(pair => pair.Value.Retiring);
            if (selected.Value is null) return;
            using var idle = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, networkId, account, instance, ct).ConfigureAwait(false);
            if (idle.Phase != 0) throw new CryptographicException("Active compaction owns publication erasure recovery.");
            var slot = ProtectedDid2ContactRouteJournal.ArchiveSlot(instance.Span, selected.Key);
            var expected = raw.Use(bytes => bytes.ToArray());
            byte[] replacement = [];
            var guards = new Dictionary<string, byte[]?> { [ProtectedDid2ContactRouteJournal.Slot] = SHA256.HashData(expected) };
            try
            {
                using var grantsRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var grants = grantsRaw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, account.Span, instance.Span));
                if (grants.Entries.Values.Any(entry => FixedRoute(ContactRouteClosureCodec.Decode(
                    ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash.Span, selected.Value.Route)))
                    throw new CryptographicException("Retired publication still has a working acquisition dependency.");
                guards.Add(ProtectedDid2MailboxGrantJournal.Slot, grantsRaw.Use(bytes => SHA256.HashData(bytes)));
                await RequireNoSealedAcquisitionForPathAsync(grants, account, instance, selected.Value.Route, held, ct, guards).ConfigureAwait(false);
                await RequireIdleArchivedPathWorkUnderLeaseAsync(account, instance, selected.Value.Route, held, ct).ConfigureAwait(false);
                using var readRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var reads = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, account.Span, instance.Span));
                guards.Add(ProtectedDid2MailboxReadJournal.Slot, readRaw.Use(bytes => SHA256.HashData(bytes)));
                if (reads.Traversals.ContainsKey(Convert.ToHexString(selected.Value.ReadScope!)))
                    throw new CryptographicException("Retired publication still has its original traversal dependency.");
                if (reads.Active is { } active && FixedRoute(active.Route, selected.Value.Route) ||
                    reads.Closed.Values.Any(closed => FixedRoute(closed.Route, selected.Value.Route)))
                    throw new CryptographicException("Retired publication still has an original read/ACK dependency.");
                using var original = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false);
                if (original is not null)
                {
                    using var entry = original.Use(bytes => ProtectedDid2ContactRouteJournal.Entry.Decode(bytes, networkId, account.Span));
                    ProtectedDid2ContactRouteJournal.RequireArchiveEntry(selected.Key, selected.Value, entry);
                    var route = ContactRouteClosureCodec.Decode(entry.Record(6).Span);
                    if (!FixedRoute(ArchivedPathReadScope(route).Value, selected.Value.ReadScope!))
                        throw new CryptographicException("Publication erasure tombstone changed its exact original read scope.");
                }
                guards.Add(slot, original is null ? null : selected.Value.Hash.ToArray());
                var workSlots = new[] { ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2DirectTextJournal.Slot, ProtectedDid2AttachmentJournal.Slot };
                using (var work = await storage.ReadOwnedBatchAsync(workSlots, ct).ConfigureAwait(false))
                {
                    for (var index = 0; index < workSlots.Length; index++)
                        guards.Add(workSlots[index], (work[index] ?? throw new InvalidDataException("Publication erasure work custody is absent.")).Use(bytes => SHA256.HashData(bytes)));
                    using var sends = work[0]!.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    using var ordinary = work[1]!.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    using var assets = work[2]!.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, account.Span, instance.Span));
                    if (ordinary.Entries.Count != 0 || assets.Entries.Count != 0 ||
                        sends.Entries.Values.Any(send => FixedRoute(send.RouteHash, selected.Value.Route)))
                        throw new IOException("Original transport work still pins publication archive erasure.");
                }
                // The predecessor tombstone is retained across the irreversible
                // erasure. Missing is accepted only here, after that durable proof.
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.BeforePublicationArchiveDelete);
#endif
                using (var checkedDependencies = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false)) { }
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                if (!await storage.CompareAndDeleteAsync(ProtectedDid2ContactRouteJournal.Slot, expected, [slot], ct).ConfigureAwait(false))
                    throw new CryptographicException("Publication archive erasure changed its exact protected guard.");
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPublicationArchiveDelete);
#endif
                guards[slot] = null;
                using (var checkedAbsenceAndDependencies = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false)) { }
                state.Archived.Remove(selected.Key); selected.Value.Dispose();
                replacement = ProtectedDid2ContactRouteJournal.Encode(state, networkId, account.Span, instance.Span);
                if (!await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, expected, replacement, ct).ConfigureAwait(false))
                    throw new CryptographicException("Publication erasure tombstone cleanup changed its exact predecessor.");
                using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                if (!readback.Use(bytes => FixedRoute(bytes, replacement)))
                    throw new CryptographicException("Publication erasure cleanup readback changed its exact successor.");
#if DEEP_TEST_INTERNALS
                Did2CompactionTestHooks.Hit(Did2CompactionFailpoint.AfterPublicationArchiveReferenceRemoved);
#endif
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(replacement);
                foreach (var digest in guards.Values) if (digest is not null) CryptographicOperations.ZeroMemory(digest);
            }
        }
        throw new InvalidDataException("Publication erasure cleanup exceeded its bounded inventory.");
    }
}
