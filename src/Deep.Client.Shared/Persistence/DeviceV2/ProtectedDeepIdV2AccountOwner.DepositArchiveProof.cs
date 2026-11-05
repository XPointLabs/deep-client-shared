using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private sealed class DepositSendArchiveProof(byte[] digest, Dictionary<string, byte[]?> guards) : IDisposable
    {
        internal byte[] Digest => digest;
        internal void AddGuards(Dictionary<string, byte[]?> destination)
        {
            foreach (var pair in guards)
                if (destination.TryGetValue(pair.Key, out var prior))
                {
                    if (prior is null || pair.Value is null || !FixedRoute(prior, pair.Value))
                        throw new CryptographicException("Deposit archival source guards changed during qualification.");
                }
                else destination.Add(pair.Key, pair.Value?.ToArray());
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(digest);
            foreach (var value in guards.Values) if (value is not null) CryptographicOperations.ZeroMemory(value);
            guards.Clear();
        }
    }

    // Authenticate every still-retained reference before moving its holder.
    // This also runs on independently reopened SQL/archive custody after CAS.
    // No receipt outcome, signing, expiry extension or retirement is inferred.
    private async Task<DepositSendArchiveProof> ProveDepositArchiveSendsUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> instance,
        byte[] acquisition, ProtectedDid2MailboxSendJournal.State sends,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        CancellationToken ct)
    {
        held.RequireOwner(lease);
        var grantBytes = Deep.Protocol.ContactV1.ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(acquisition).Span).Field(8);
        var grantHash = SHA256.HashData(grantBytes.Span);
        var references = sends.Entries.Values.Where(send => FixedRoute(send.GrantHash, grantHash)).OrderBy(send => send.Name, StringComparer.Ordinal).ToArray();
        var guards = new Dictionary<string, byte[]?>(StringComparer.Ordinal);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/STORE-V2/deposit-archive-send-proof\0"u8);
        digest.AppendData(networkId); digest.AppendData(current.AccountId.Span); digest.AppendData(instance.Span); digest.AppendData(acquisition);
        try
        {
            if (references.Length == 0 || references.Any(send => !send.Prepared || send.Counter == 0))
                throw new IOException("Pending or absent exact Store requests pin Deposit holder custody.");
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance.Span).ReadAsync(ct).ConfigureAwait(false);
            guards.Add(ProtectedDid2MessagingSessionCatalog.Slot, SHA256.HashData(catalog.Exact.Span));
            using var draftsRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactStartJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Deposit archival lost Initial draft custody.");
            using var drafts = draftsRaw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
            guards.Add(ProtectedDid2ContactStartJournal.Slot, draftsRaw.Use(bytes => SHA256.HashData(bytes)));
            foreach (var group in references.GroupBy(send => Convert.ToHexString(send.ScopeHash), StringComparer.Ordinal))
            {
                var indexes = Enumerable.Range(0, catalog.Count).Where(index => Convert.ToHexString(catalog.Scope(index).Hash) == group.Key).ToArray();
                if (indexes.Length != 1 || catalog.Phase(indexes[0]) != 2)
                    throw new CryptographicException("Retained Store reference lost its unique initialized native scope.");
                var scope = catalog.Scope(indexes[0]);
                using var opened = await OpenLocalHistoryUnderLeaseAsync(current, scope, held, ct).ConfigureAwait(false);
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (floor.Status != 1) throw new CryptographicException("Inactive native custody cannot archive a referenced Deposit.");
                guards.Add(scope.FloorSlot, SHA256.HashData(floor.Exact.Span));
                using var peer = await storage.ReadOwnedAsync(ProtectedDid2MessagingPeerBootstrap.Slot(scope), ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Deposit archival lost its protected original peer.");
                guards.Add(ProtectedDid2MessagingPeerBootstrap.Slot(scope), peer.Use(bytes => SHA256.HashData(bytes)));

                digest.AppendData(scope.Hash); digest.AppendData(floor.Exact.Span);
                foreach (var send in group)
                {
                    _ = sends.Chain(scope.Hash, send.Operation);
                    var (grant, route) = await RequireOriginalAttemptGrantAsync(send, acquisition, fresh, source, scope, ct).ConfigureAwait(false);
                    sends.RequireGrant(grant);
                    if (sends.MinimumCounter(grantHash) <= send.Counter)
                        throw new CryptographicException("Deposit archival lost an independently reserved original counter.");
                    var initial = drafts.Entries.Values.Where(draft => FixedRoute(draft.Conversation, scope.Conversation) &&
                        FixedRoute(draft.LocalDevice, scope.LocalDevice) && FixedRoute(draft.Exact.Slice(64, 32), scope.RemoteAccount) &&
                        FixedRoute(InitialMailboxOperation(draft.Intent), send.Operation)).ToArray();
                    if (initial.Length > 1) throw new CryptographicException("Deposit archival has ambiguous Initial custody.");
                    var intent = initial.Length == 1 ? initial[0].Intent.ToArray() : [];
                    byte[] envelope = [], exact = [];
                    try
                    {
                        envelope = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, send.Operation.ToArray(), intent, ct).ConfigureAwait(false);
                        // No application key is retained across the trusted
                        // namespace/time callbacks above. One selected send's
                        // actual SQL and native recipient join owns this scope.
                        using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                            storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
                        if (intent.Length == 0)
                            _ = await ReadAttemptStorePeerRouteAsync(current, held, opened, application, send.Operation.ToArray(),
                                send.Attempt.ToArray(), route, fresh, source, ct).ConfigureAwait(false);
                        else
                        {
                            var metadata = await application.ReadStorePublicEvidenceIfPresentAsync(scope, send.Operation.ToArray(),
                                send.Attempt.ToArray(), ct).ConfigureAwait(false);
                            if (metadata is null)
                            {
                                await application.RequireAttemptedStoreEvidenceAsync(scope, send.Operation.ToArray(), send.Attempt.ToArray(),
                                    send.MailboxOperation.ToArray(), ct).ConfigureAwait(false);
                                throw new IOException("Uncaptured original recipient evidence pins this prepared Deposit.");
                            }
                            await RequireStoreEvidenceCommitmentUnderLeaseAsync(held, scope, send.Operation.ToArray(), send.Attempt.ToArray(), metadata, ct).ConfigureAwait(false);
                            await RequireRetainedInitialContactFactsUnderLeaseAsync(current, held, opened, intent, metadata, envelope, ct).ConfigureAwait(false);
                            var pinned = peer.Use(bytes => ProtectedDid2MessagingPeerBootstrap.Restore(bytes, scope));
                            var originalRoute = DeepIdV2OriginalContactStoreVerifier.Verify(fresh.Authority, pinned,
                                metadata.OriginalPeerAdp.Span, metadata.OriginalDcr.Span, metadata.OriginalRoute.Span,
                                send.Created, deploymentProfileId, 2, verifier);
                            if (!FixedRoute(originalRoute.ExactBytes.Span, route.ExactBytes.Span) ||
                                !FixedRoute(metadata.ExactPma.Span, ProtectedDid2MailboxGrantJournal.OriginalPolicy(acquisition).Span))
                                throw new CryptographicException("Deposit archival changed the original independently authenticated recipient.");
                            var records = metadata.CopyRecords();
                            try { foreach (var record in records) digest.AppendData(SHA256.HashData(record)); }
                            finally { foreach (var record in records) CryptographicOperations.ZeroMemory(record); }
                        }
                        var request = await application.ReadTransportOutboxAsync(VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                            OutboxLogicalId.FromBytes(send.MailboxOperation), ct).ConfigureAwait(false);
                        if (request is not { Result: TransportOutboxReadResult.Found, Item: not null })
                            throw new CryptographicException("Deposit archival cannot reconstruct a missing original Store request.");
                        exact = request.Item.GetCiphertextBundleCopy();
                        RequireOriginalAttemptRequest(send, grant, route, scope,
                            MailboxAuthenticatedClientRequestCodec.Decode(exact), exact, envelope, request.Item);
                        digest.AppendData(send.Exact); digest.AppendData(SHA256.HashData(exact)); digest.AppendData([(byte)request.Item.State]);
                    }
                    finally { CryptographicOperations.ZeroMemory(intent); CryptographicOperations.ZeroMemory(envelope); CryptographicOperations.ZeroMemory(exact); }
                }
                var final = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (!FixedRoute(final.Exact.Span, floor.Exact.Span)) throw new CryptographicException("Deposit archival native source changed during qualification.");
            }
            using (var actual = await storage.ReadOwnedGuardedBatchAsync([], guards, ct).ConfigureAwait(false)) { }
            ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            return new(digest.GetHashAndReset(), guards);
        }
        catch
        {
            foreach (var value in guards.Values) if (value is not null) CryptographicOperations.ZeroMemory(value);
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(grantHash); }
    }
}
