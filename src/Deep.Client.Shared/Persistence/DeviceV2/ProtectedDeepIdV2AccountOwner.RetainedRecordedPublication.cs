using System.Security.Cryptography;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Non-destructive retained reading only. The retirement planner deliberately
    // keeps its direct-only predicate until its stored recovery plan can bind
    // these additional protected dependencies independently.
    private async Task RequireRetainedReadPermanentIntentAsync(string name, ProtectedDid2ContactRouteJournal.Entry entry,
        ProtectedDid2ContactRouteJournal.State state, Did2OwnedPermanentContactPlan plan,
        ReadOnlyMemory<byte> account, ReadOnlyMemory<byte> instance, Dictionary<string, byte[]?> guards, CancellationToken ct)
    {
        byte[] cursor, baseHash;
        using (var predecessor = entry.RebindCommittedIntent(plan.Intent.Span, networkId, account.Span))
        {
            cursor = DeriveContactRenewalIntent(networkId, account.Span, instance.Span, plan.Intent.Span, predecessor.Exact);
            baseHash = SHA256.HashData(predecessor.Exact);
        }
        byte[]? expectedRequestHash = null;
        try
        {
            if (name == Convert.ToHexString(cursor)) return;
            for (var count = 0; count < 3; count++)
            {
                // After promotion only the exact terminal archive locator may
                // remain. A live intermediate proposal cannot be skipped.
                if (state.Entries.ContainsKey(Convert.ToHexString(cursor)) || state.Archived.ContainsKey(Convert.ToHexString(cursor)))
                    throw new CryptographicException("Retained recorded publication crosses a live intermediate intent.");
                var slot = ProtectedDid2ContactRenewalClosure.ClosedSlot(cursor);
                byte[] next, requestHash;
                using (var raw = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Retained recorded publication lost its protected closure."))
                {
                    (next, requestHash) = raw.Use(bytes =>
                    {
                        using var closure = ProtectedDid2ContactRenewalClosure.Decode(bytes, networkId, account.Span, instance.Span);
                        if (!FixedRoute(closure.OldIntent.Span, cursor) ||
                            !FixedRoute(closure.PermanentIntent.Span, plan.Intent.Span) ||
                            !FixedRoute(closure.CompletedBaseEntryHash.Span, baseHash))
                            throw new CryptographicException("Retained recorded publication changed its exact completed anchor.");
                        if (expectedRequestHash is not null)
                        {
                            using var old = ProtectedDid2ContactRouteJournal.Entry.Decode(closure.ExactOldPhase1.Span, networkId, account.Span);
                            if (!FixedRoute(expectedRequestHash, SHA256.HashData(old.Record(12).Span)))
                                throw new CryptographicException("Retained recorded publication changed its exact proposal adjacency.");
                        }
                        var digest = SHA256.HashData(bytes);
                        if (guards.TryGetValue(slot, out var prior))
                        {
                            try
                            {
                                if (prior is null || !FixedRoute(prior, digest))
                                    throw new CryptographicException("Retained recorded publication closure changed during capture.");
                            }
                            finally { CryptographicOperations.ZeroMemory(digest); }
                        }
                        else guards.Add(slot, digest);
                        return (closure.NextIntent.ToArray(), closure.NextRequestHash.ToArray());
                    });
                }
                // Only detached hashes/locators survive the next provider edge;
                // no decoded private phase1 custody or owned batch does.
                CryptographicOperations.ZeroMemory(cursor); cursor = next;
                if (expectedRequestHash is not null) CryptographicOperations.ZeroMemory(expectedRequestHash);
                expectedRequestHash = requestHash;
                if (name == Convert.ToHexString(cursor)) return;
            }
            throw new IOException("Retained recorded publication exceeds its existing three-link bound.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cursor); CryptographicOperations.ZeroMemory(baseHash);
            if (expectedRequestHash is not null) CryptographicOperations.ZeroMemory(expectedRequestHash);
        }
    }

    private static void ClearRetainedPublicationGuards(IReadOnlyDictionary<string, byte[]?> guards)
    {
        foreach (var digest in guards.Values) if (digest is not null) CryptographicOperations.ZeroMemory(digest);
    }
}
