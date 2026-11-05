using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Selection only. The caller still authenticates the exact native event,
    // original route/policy, signed MAU, replicas and coordinator, then repeats
    // that verification under unchanged protected roots before adopting Store.
    private sealed class RetainedStoreAttemptCandidate(byte[] attempt, Did2StorePublicEvidence evidence,
        List<OriginalDepositAcquisition> originals) : IDisposable
    {
        internal ReadOnlyMemory<byte> Attempt => attempt;
        internal Did2StorePublicEvidence Evidence => evidence;
        internal async Task RecheckAsync(CancellationToken ct)
        { foreach (var original in originals) await original.RecheckAsync(ct).ConfigureAwait(false); }
        public void Dispose() { CryptographicOperations.ZeroMemory(attempt); foreach (var original in originals) original.Dispose(); originals.Clear(); }
    }

    private async Task<RetainedStoreAttemptCandidate?> ReadRetainedStoreAttemptCandidateUnderLeaseAsync(
        HeldDeepIdV2AccountLease held, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> nativeOperation,
        ReadOnlyMemory<byte> actualEnvelope, SqliteDeepMailboxStore application,
        ProtectedDid2MailboxSendJournal.State sends, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        ProtectedDph2PreClaimJournal.RequireIntent(nativeOperation.Span);
        var owned = sends.Entries.Values.Where(entry =>
            FixedRoute(entry.ScopeHash, scope.Hash) && FixedRoute(entry.Operation, nativeOperation.Span))
            .OrderBy(entry => entry.Ordinal).ToArray();
        if (owned.Length != 0 && sends.Current(scope.Hash, nativeOperation.Span) is null)
            throw new CryptographicException("Retained attempts lost their original protected chain.");
        var candidates = new List<byte[]>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        RetainedStoreAttemptCandidate? selected = null;
        byte[][] indexed = [];
        var originals = new List<OriginalDepositAcquisition>();
        var acquisitions = new Dictionary<string, OriginalDepositAcquisition>(StringComparer.Ordinal);
        byte[] grantRoot = [];
        try
        {
            if (owned.Length != 0)
            {
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Retained Store lost mandatory original acquisition custody.");
                grantRoot = raw.Use(bytes => bytes.ToArray());
                foreach (var grant in owned.GroupBy(entry => Convert.ToHexString(entry.GrantHash), StringComparer.Ordinal))
                {
                    var original = await ReadOriginalDepositAcquisitionUnderLeaseAsync(held, scope.LocalAccount.ToArray(), scope.Instance.ToArray(),
                        grantRoot, grant.First().GrantHash.ToArray(), ct).ConfigureAwait(false);
                    originals.Add(original); acquisitions.Add(grant.Key, original);
                }
            }
            // Protected ordinal determines a stable preference, not outcome.
            // Include the original identity even when its public row is absent:
            // actual attempted/Durable SQL cannot disappear with that row.
            Add(nativeOperation.Span);
            foreach (var entry in owned) Add(entry.Attempt);
            indexed = await application.ReadStoreAttemptCandidatesAsync(scope, nativeOperation, ct).ConfigureAwait(false);
            foreach (var candidate in indexed)
            {
                if (owned.Length != 0 && (!sends.Entries.TryGetValue(Convert.ToHexString(
                        ProtectedDid2MailboxSendJournal.Key(scope.Hash, candidate)), out var entry) ||
                    !FixedRoute(entry.ScopeHash, scope.Hash) || !FixedRoute(entry.Operation, nativeOperation.Span)))
                    throw new CryptographicException("SQL cannot append an unowned attempt to a protected send chain.");
                Add(candidate);
            }
            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
                var logical = MailboxSendOperation(scope, candidate, actualEnvelope.Span);
                try
                {
                    var evidence = await application.ReadDurableStorePublicEvidenceAsync(scope, nativeOperation,
                        candidate, logical, ct).ConfigureAwait(false);
                    if (evidence is not null)
                        await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, nativeOperation, candidate,
                            evidence, ct).ConfigureAwait(false);
                    if (evidence is not null && owned.Length != 0)
                    {
                        var original = owned.Single(entry => FixedRoute(entry.Attempt, candidate));
                        var acquisition = acquisitions[Convert.ToHexString(original.GrantHash)].Entry;
                        if (!FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition).Span, evidence.ExactPma.Span) ||
                            !FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(acquisition).Span, evidence.OriginalRoute.Span) ||
                            !FixedRoute(original.RouteHash, SHA256.HashData(evidence.OriginalRoute.Span)))
                            throw new CryptographicException("Cached Store route differs from its actual protected attempt.");
                        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                            ProtectedDid2MailboxGrantJournal.Response(acquisition).Span).Field(8).Span);
                        sends.RequireGrant(grant);
                        if (!original.Prepared || sends.MinimumCounter(original.GrantHash) <= original.Counter)
                            throw new CryptographicException("Cached Store lost its exact prepared independent counter.");
                        var actual = await application.ReadTransportOutboxAsync(OutboxAccountScope.FromBytes(evidence.AccountScope.Span),
                            OutboxLogicalId.FromBytes(original.MailboxOperation), ct).ConfigureAwait(false);
                        if (actual is not { Result: TransportOutboxReadResult.Found, Item: not null })
                            throw new CryptographicException("Cached Store lost its exact original request.");
                        var request = actual.Item.GetCiphertextBundleCopy();
                        try { RequireOriginalAttemptRequest(original, grant,
                            ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(acquisition).Span), scope,
                            MailboxAuthenticatedClientRequestCodec.Decode(request), request, actualEnvelope.Span, actual.Item); }
                        finally { CryptographicOperations.ZeroMemory(request); }

                    }
                    // Check ALL candidates, even after a terminal one is found.
                    // A late predecessor result cannot hide lost evidence for
                    // another possibly forwarded successor.
                    await application.RequireAttemptedStoreEvidenceAsync(scope, nativeOperation, candidate,
                        logical, ct).ConfigureAwait(false);
                    if (evidence is not null && selected is null)
                        selected = new(candidate.ToArray(), evidence, originals);
                }
                finally { CryptographicOperations.ZeroMemory(logical); }
            }
            foreach (var original in originals) await original.RecheckAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            var result = selected; selected = null;
            if (result is not null) originals = [];
            return result;
        }
        finally
        {
            selected?.Dispose();
            foreach (var original in originals) original.Dispose();
            CryptographicOperations.ZeroMemory(grantRoot);
            foreach (var bytes in candidates.Concat(indexed)) CryptographicOperations.ZeroMemory(bytes);
        }

        void Add(ReadOnlySpan<byte> attempt)
        {
            if (!names.Add(Convert.ToHexString(attempt))) return;
            if (candidates.Count >= ProtectedDid2MailboxSendJournal.MaximumEntries)
                throw new InvalidDataException("Retained attempts exceed the existing bounded chain.");
            candidates.Add(attempt.ToArray());
        }
    }
}
