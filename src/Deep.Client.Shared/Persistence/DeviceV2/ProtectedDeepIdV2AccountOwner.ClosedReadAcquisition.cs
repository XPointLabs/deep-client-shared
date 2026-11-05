using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Exact historical inputs for already closed reads only. No current holder
    // selection, installation, signing, dispatch, restoration or deletion API.
    private sealed class ClosedReadAcquisitions : IDisposable
    {
        internal readonly Dictionary<string, byte[]> Entries = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, byte[]> Working = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, byte[]?> Guards = new(StringComparer.Ordinal);
        public void Dispose()
        {
            foreach (var entry in Entries.Values) CryptographicOperations.ZeroMemory(entry);
            foreach (var hash in Guards.Values) if (hash is not null) CryptographicOperations.ZeroMemory(hash);
        }
        internal byte[] Require(ProtectedDid2MailboxReadJournal.ClosedAttempt closed)
            => Entries.TryGetValue(Convert.ToHexString(closed.Grant), out var entry)
                ? entry : Working.TryGetValue(Convert.ToHexString(closed.Grant), out entry)
                    ? entry : throw new CryptographicException("Closed Retrieve lost its captured unique original acquisition.");
    }

    private async Task<ClosedReadAcquisitions> ReadClosedReadAcquisitionsUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, byte[] instance,
        ProtectedDid2MailboxGrantJournal.State grants, ProtectedDid2MailboxReadJournal.State reads,
        byte[] grantRoot, byte[] readRoot, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var result = new ClosedReadAcquisitions();
        try
        {
            // Decode/hash each bounded working winner once. A restored reference
            // must never be hidden by finding its working copy first.
            foreach (var entry in grants.Entries.Values)
                if (ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(entry) &&
                    !result.Working.TryAdd(Convert.ToHexString(SHA256.HashData(ContactCodec.Decode("XMC2",
                        ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span)), entry))
                    throw new CryptographicException("Closed Retrieve has ambiguous working acquisitions.");
            var retained = grants.Retained.ToDictionary(pair => Convert.ToHexString(pair.Value.GrantHash),
                pair => pair, StringComparer.Ordinal);
            foreach (var closed in reads.Closed.Values)
            {
                var name = Convert.ToHexString(closed.Grant);
                if (!retained.TryGetValue(name, out var selected))
                {
                    if (!result.Working.ContainsKey(name))
                        throw new CryptographicException("Closed Retrieve lost its unique original acquisition.");
                    continue;
                }
                if (selected.Value.Phase != 1 || result.Working.ContainsKey(name))
                    throw new CryptographicException("Closed Retrieve lost its exact sealed acquisition reference.");
                var slot = ProtectedDid2MailboxGrantJournal.RetainedSlot(Convert.FromHexString(selected.Key));
                using var batch = await storage.ReadOwnedGuardedBatchAsync([slot], new Dictionary<string, byte[]?>
                {
                    [ProtectedDid2MailboxGrantJournal.Slot] = SHA256.HashData(grantRoot),
                    [ProtectedDid2MailboxReadJournal.Slot] = SHA256.HashData(readRoot)
                }, ct).ConfigureAwait(false);
                var raw = batch[0] ?? throw new CryptographicException("Closed Retrieve lost its mandatory sealed original.");
                using var original = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.DecodeRetained(grants,
                    selected.Key, bytes, networkId, current.AccountId.Span, instance));
                var entry = original.Entries[selected.Key];
                if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry) ||
                    !reads.Counters.TryGetValue(Convert.ToHexString(closed.Grant), out var counter) || counter == 0 || counter < closed.Counter ||
                    reads.Active is { } active && (FixedRoute(active.Grant, closed.Grant) || FixedRoute(active.AckGrant, closed.Grant)) ||
                    ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0] != (byte)MailboxCapabilityDomain.Retrieve ||
                    !FixedRoute(SHA256.HashData(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span), closed.Route))
                    throw new CryptographicException("Closed Retrieve sealed source changed its exact purpose or original route.");
                result.Entries.Add(name, entry.ToArray());
                result.Guards.Add(slot, raw.Use(bytes => SHA256.HashData(bytes)));
            }
#if DEEP_TEST_INTERNALS
            if (result.Guards.Count != 0) Did2AcquisitionRetentionTestHooks.Hit(Did2AcquisitionRetentionFailpoint.AfterClosedSourceCapture);
#endif
            return result;
        }
        catch { result.Dispose(); throw; }
    }

    private async Task RequireClosedReadSourcesAsync(ClosedReadAcquisitions sources, byte[] grantRoot,
        byte[] readRoot, byte[] registrationHash, byte[] applicationHash, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (sources.Guards.Count == 0) return;
        held.RequireOwner(lease);
        var guards = new Dictionary<string, byte[]?>(sources.Guards, StringComparer.Ordinal)
        {
            [ProtectedDid2MailboxGrantJournal.Slot] = SHA256.HashData(grantRoot),
            [ProtectedDid2MailboxReadJournal.Slot] = SHA256.HashData(readRoot),
            ["deep.store.v2.sql-generation"] = registrationHash,
            [SqliteDeepIdV2AccountGeneration.ApplicationStateSlot] = applicationHash
        };
        using var rejoin = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
    }
}
