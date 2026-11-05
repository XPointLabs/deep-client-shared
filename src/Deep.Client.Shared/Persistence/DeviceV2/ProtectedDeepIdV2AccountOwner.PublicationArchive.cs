using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<DeepIdV2PublicationArchiveStatus> EnrollPublicationArchiveAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct,
            explicitPublicationEnrollment: true).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[] expected = [], next = [];
        IReadOnlyList<DeepSecureStorageWrite> copies = [];
        try
        {
            await DrainPublicationArchiveErasuresUnderLeaseAsync(current.AccountId, instance, held, ct).ConfigureAwait(false);
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Publication enrollment source is absent.");
            expected = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.DecodeForEnrollment(expected, networkId, current.AccountId.Span, instance);
            var plan = CreatePermanentContactPlan(current, instance);
            var pinned = Convert.ToHexString(plan.Intent.Span);
            if (state.PinnedIntent.AsSpan().IndexOfAnyExcept((byte)0) >= 0 && !FixedRoute(state.PinnedIntent, plan.Intent.Span))
                throw new CryptographicException("Publication enrollment cannot replace its working owner.");
            if (state.Archived.ContainsKey(pinned)) throw new CryptographicException("Publication enrollment cannot adopt archived current custody.");
            if (state.Entries.Values.Any(entry => entry.Kind == 1) && !state.Entries.ContainsKey(pinned))
                throw new CryptographicException("Publication enrollment lost its owned permanent current intent.");
            state.PinnedIntent = plan.Intent.ToArray();
            copies = ProtectedDid2ContactRouteJournal.StageArchive(state, instance, all: true);
            next = ProtectedDid2ContactRouteJournal.Encode(state, networkId, current.AccountId.Span, instance);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var applied = copies.Count == 0
                ? await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, expected, next, ct).ConfigureAwait(false)
                : await storage.CompareExchangeAndInsertAsync(ProtectedDid2ContactRouteJournal.Slot, expected, next, copies, ct).ConfigureAwait(false);
            if (!applied) throw new CryptographicException("Publication enrollment source or archive custody conflicted.");
            using var adopted = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Publication enrollment winner is absent.");
            if (!adopted.Use(bytes => FixedRoute(bytes, next))) throw new CryptographicException("Publication enrollment readback changed its winner.");
            await ProtectedDid2ContactRouteJournal.RequireArchiveCustodyAsync(storage, adopted, networkId, current.AccountId, instance, ct).ConfigureAwait(false);
            var reserved = ProtectedDid2ContactRouteJournal.ReservedBytes(state);
            var count = ProtectedDid2ContactRouteJournal.WorkingCount(state);
            return new(count, state.Archived.Count, next.Length, reserved, ProtectedDid2ContactRouteJournal.ArchivedBytes(state),
                count + state.Archived.Count < ProtectedDid2ContactRouteJournal.MaximumIntents &&
                checked(reserved + 4 + ProtectedDid2ContactRouteJournal.MaximumEntryBytes) <= ProtectedDid2ContactRouteJournal.MaximumBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance); CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(next);
            foreach (var copy in copies) CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsMemory(copy.Value).Span);
        }
    }

    private async Task HydratePublicationArchiveAsync(ProtectedDid2ContactRouteJournal.State state, OwnedDeepSecret root,
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, CancellationToken ct,
        string? selectedIntent = null, ReadOnlyMemory<byte> selectedRoute = default)
    {
        var exact = root.Use(bytes => bytes.ToArray());
        try { await ProtectedDid2ContactRouteJournal.HydrateAsync(storage, state, exact, networkId, account, instance, ct, selectedIntent, selectedRoute).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
