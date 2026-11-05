using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Exact local provenance only. Callers must independently authenticate the
    // original Store, or current admission before installing/signing anything.
    private sealed class OriginalDepositAcquisition(IDeepSecureStorage storage, DeepIdV2AccountFileLease owner,
        HeldDeepIdV2AccountLease held, byte[] entry, Dictionary<string, byte[]?> guards) : IDisposable
    {
        private bool disposed;
        internal byte[] Entry => !disposed ? entry : throw new ObjectDisposedException(nameof(OriginalDepositAcquisition));
        internal async Task RecheckAsync(CancellationToken ct)
        {
            ObjectDisposedException.ThrowIf(disposed, this); held.RequireOwner(owner);
            using var actual = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(owner);
        }
        internal void AddGuards(Dictionary<string, byte[]?> destination)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            foreach (var pair in guards)
                if (destination.TryGetValue(pair.Key, out var prior))
                {
                    if ((prior is null) != (pair.Value is null) || prior is not null && !FixedRoute(prior, pair.Value!))
                        throw new CryptographicException("Original Deposit acquisition changed a captured dependency.");
                }
                else destination.Add(pair.Key, pair.Value?.ToArray());
        }
        public void Dispose()
        {
            if (disposed) return; disposed = true; CryptographicOperations.ZeroMemory(entry);
            foreach (var digest in guards.Values) if (digest is not null) CryptographicOperations.ZeroMemory(digest);
            guards.Clear();
        }
    }

    private async Task<OriginalDepositAcquisition> ReadOriginalDepositAcquisitionUnderLeaseAsync(
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance,
        ReadOnlyMemory<byte> exactGrantRoot, ReadOnlyMemory<byte> grantHash, CancellationToken ct, string? expectedScope = null)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        if (grantHash.Length != 32 || grantHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("Original Deposit acquisition requires its exact grant commitment.");
        using var state = ProtectedDid2MailboxGrantJournal.Decode(exactGrantRoot.Span, networkId, account.Span, instance.Span);
        var guards = new Dictionary<string, byte[]?> { [ProtectedDid2MailboxGrantJournal.Slot] = SHA256.HashData(exactGrantRoot.Span) };
        byte[] selected = [];
        OriginalDepositAcquisition? result = null;
        try
        {
            var ownedHash = grantHash.ToArray();
            try
            {
                var working = state.Entries.Where(pair => ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(pair.Value) &&
                    FixedRoute(SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(pair.Value).Span).Field(8).Span), ownedHash)).ToArray();
                var archived = state.Retained.Where(pair => FixedRoute(pair.Value.GrantHash, ownedHash)).ToArray();
                if (working.Length > 1 || archived.Length > 1 || working.Length == 0 && archived.Length == 0)
                    throw new CryptographicException("Original Deposit acquisition is absent or ambiguous.");
                if (archived.Length != 0)
                {
                    var reference = archived[0];
                    if (reference.Value.Phase is not (1 or 2) ||
                        reference.Value.Phase == 1 && working.Length != 0 ||
                        reference.Value.Phase == 2 && (working.Length != 1 || working[0].Key != reference.Key))
                        throw new CryptographicException("Original Deposit acquisition has another retained disposition.");
                    var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(reference.Key));
                    using var read = await storage.ReadOwnedGuardedBatchAsync([slot], guards, ct).ConfigureAwait(false);
                    var raw = read[0] ?? throw new CryptographicException("Original Deposit acquisition lost its mandatory exact archive.");
                    using var retained = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(state, reference.Key,
                        bytes, networkId, account.Span, instance.Span));
                    selected = retained.Entries[reference.Key].ToArray();
                    if (working.Length != 0 && !FixedRoute(working[0].Value, selected))
                        throw new CryptographicException("Restored Deposit acquisition differs from its exact archive.");
                    guards.Add(slot, raw.Use(bytes => SHA256.HashData(bytes)));
                }
                else selected = working[0].Value.ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(ownedHash); }
            var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(selected).Span);
            var grant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(selected).Span).Field(8);
            if (!ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(selected) ||
                request.Field(6).Span[0] != (byte)MailboxCapabilityDomain.Deposit ||
                !FixedRoute(SHA256.HashData(grant.Span), grantHash.Span) ||
                expectedScope is not null && Convert.ToHexString(selected.AsSpan(0, 32)) != expectedScope)
                throw new CryptographicException("Original Deposit acquisition changed its exact role, scope or grant.");
            result = new(storage, lease, held, selected, guards); selected = [];
            await result.RecheckAsync(ct).ConfigureAwait(false);
            var returned = result; result = null; return returned;
        }
        catch
        {
            result?.Dispose(); CryptographicOperations.ZeroMemory(selected);
            foreach (var digest in guards.Values) if (digest is not null) CryptographicOperations.ZeroMemory(digest);
            throw;
        }
    }
    private async Task GuardRetainedAcquisitionCustodyUnderLeaseAsync(ReadOnlyMemory<byte> account,
        ReadOnlyMemory<byte> instance, HeldDeepIdV2AccountLease held, Dictionary<string, byte[]?> guards, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Mailbox custody lost its registered acquisition root.");
        using var state = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, account.Span, instance.Span));
        guards.Add(ProtectedDid2MailboxGrantJournal.Slot, raw.Use(bytes => SHA256.HashData(bytes)));
        var rootGuard = new Dictionary<string, byte[]?> { [ProtectedDid2MailboxGrantJournal.Slot] = guards[ProtectedDid2MailboxGrantJournal.Slot] };
        foreach (var batch in state.Retained.Chunk(32))
        {
            var slots = batch.Select(pair => ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(pair.Key))).ToArray();
            using var actual = await storage.ReadOwnedGuardedBatchAsync(slots, rootGuard, ct).ConfigureAwait(false);
            for (var index = 0; index < batch.Length; index++)
            {
                var pair = batch[index]; var slot = slots[index];
                if (actual[index] is not { } copy)
                {
                    if (pair.Value.Phase != 3) throw new CryptographicException("Mailbox custody lost a mandatory retained acquisition.");
                    guards.Add(slot, null); continue;
                }
                using var decoded = copy.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(state, pair.Key,
                    bytes, networkId, account.Span, instance.Span));
                guards.Add(slot, copy.Use(bytes => SHA256.HashData(bytes)));
            }
        }
        using var final = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false);
    }

}
