using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<byte[]> ReauthorizeCapturedFinalAckUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ProtectedDid2MailboxReadJournal.State state, byte[] originalRoot, byte[] instance,
        IDid2MailboxGrantTransport transport, CancellationToken ct)
    {
        var snapshot = originalRoot.ToArray(); byte[] grantsRoot = [], oldAck = [], previousGrant = [];
        try
        {
            var cycle = state.Active ?? throw new CryptographicException("Current ACK lost captured page custody.");
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException())
                grantsRoot = raw.Use(bytes => bytes.ToArray());
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantsRoot, networkId, current.AccountId.Span, instance);
            var retained = OriginalReadAcquisition(grants, cycle.AckGrantHash);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                ProtectedDid2MailboxGrantJournal.Response(retained).Span).Field(8).Span);
            var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
            var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(reading.SampleSeconds - fresh.Proof.MonotonicSample));
            if (lower < grant.ExpiresAtUnixSeconds) return snapshot.ToArray();
            using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct, cycle.Route).ConfigureAwait(false);
            if (cycle.ReadPage().HasMore || cycle.AckReply.Length != 0 || state.Phase is not (4 or 6 or 8 or 9) ||
                state.Phase == 4 && (cycle.AckBody.Length != 0 || cycle.AckCounter != 0 || cycle.AckGrant.Length != 0))
                throw new CryptographicException("Expired prepared ACK or pagination needs original outcome recovery; exact custody retained.");
            _ = await RequireOriginalReadFactsUnderLeaseAsync(current, held, source, fresh, publication.Host, retained,
                cycle.AckGrantHash.ToArray(), cycle.Route, cycle.Scope, cycle.RetrieveBody, ct).ConfigureAwait(false);
            previousGrant = cycle.AckGrantHash.ToArray();
            if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(retained))
                throw new CryptographicException("ACK closure lost its original holder reservation.");
            var fence = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
            if (state.Phase is 6 or 8 or 9)
            {
                using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                    storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
                var body = MailboxAuthenticatedRequestTranscript.DecodeAckBody(cycle.AckBody);
                var stored = await application.ReadTransportOutboxAsync(
                    VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                    OutboxLogicalId.FromBytes(body.OperationId.Span), ct).ConfigureAwait(false);
                if (stored.Result != TransportOutboxReadResult.Found || stored.Item is null)
                    throw new CryptographicException("ACK closure cannot reconstruct a missing original SQL request.");
                oldAck = stored.Item.GetCiphertextBundleCopy();
                RequirePreparedMailboxRead(cycle, oldAck, MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant), ack: true);
                RequireUncapturedReadSql(stored, 3, oldAck, cycle.RetrieveBody, previousGrant, cycle.AckCounter, cycle.AckMauHash);
                var name = ProtectedDid2MailboxReadJournal.Name(previousGrant);
                if (state.Phase == 9)
                {
                    if (!state.Closed.TryGetValue(name, out var closed) || closed.Phase != 3 ||
                        !FixedRoute(closed.ExactMau, oldAck) || closed.ClosedAtLower > lower)
                        throw new CryptographicException("Closed ACK lost its exact independent original custody.");
                }
                else
                {
                    if (state.Closed.Count >= ProtectedDid2MailboxReadJournal.MaximumFloors || state.Closed.ContainsKey(name) ||
                        snapshot.Length > ProtectedDid2MailboxReadJournal.MaximumBytes - oldAck.Length - cycle.RetrieveBody.Length - 256)
                        throw new IOException("Closed ACK capacity is exhausted; original requests cannot be evicted.");
                    var closed = ProtectedDid2MailboxReadJournal.ClosedAttempt.CaptureAck(cycle, grant.ExpiresAtUnixSeconds, lower, oldAck);
                    state.Closed.Add(name, closed);
                    if (cycle.AckGrant.Length == 0) cycle.AckGrant = previousGrant.ToArray();
                    state.Phase = 9;
#if DEEP_TEST_INTERNALS
                    Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeAckClosure);
#endif
                    await Save().ConfigureAwait(false); // Exact old request protected BEFORE successor issuer callback.
#if DEEP_TEST_INTERNALS
                    Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterAckClosure);
#endif
                }
            }
            await Guard().ConfigureAwait(false);
            // Reserve the complete new binding/body/response/counter before an
            // issuer callback. A prepared ACK never enters this producer.
            if (snapshot.Length > ProtectedDid2MailboxReadJournal.MaximumBytes -
                (32 + 5_000 + ProtectedDid2MailboxReadJournal.MaximumAckReplyBytes + 40))
                throw new IOException("Captured ACK continuation cannot fit bounded protected custody.");
            var winner = await AcquireRetainedMailboxReadUnderLeaseAsync(current, held, publication, source, fresh,
                transport, ct, expectedNewReadRoot: snapshot, renewForCapturedFinalAck: true).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(grantsRoot);
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException())
                grantsRoot = raw.Use(bytes => bytes.ToArray());
            using var next = ProtectedDid2MailboxGrantJournal.Decode(grantsRoot, networkId, current.AccountId.Span, instance);
            var hash = SHA256.HashData(winner.ExactGrant.Span);
            if (FixedRoute(hash, cycle.Grant) || FixedRoute(hash, previousGrant) || state.Closed.ContainsKey(ProtectedDid2MailboxReadJournal.Name(hash)))
                throw new CryptographicException("An expired original grant cannot authorize a new ACK.");
            var entry = OriginalReadAcquisition(next, hash);
            if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry))
            {
                ProtectedDid2MailboxGrantJournal.ReserveReadIntent(next, entry);
                var saved = await SaveMailboxGrantJournalAsync(next, grantsRoot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(grantsRoot); grantsRoot = saved;
            }
            var page = cycle.ReadPage();
            CryptographicOperations.ZeroMemory(cycle.AckGrant); cycle.AckGrant = hash;
            CryptographicOperations.ZeroMemory(cycle.AckBody); CryptographicOperations.ZeroMemory(cycle.AckMauHash);
            cycle.AckCounter = 0; cycle.AckMauHash = new byte[32];
            var original = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(cycle.RetrieveBody);
            cycle.AckBody = MailboxAuthenticatedRequestTranscript.ForAck(page.Epoch, cycle.AckOperation(),
                original.MailboxId, original.PlacementId, true, [], page.Items.Select(value => value.ToAcknowledgement()).ToArray()).CanonicalRequest.ToArray();
            state.Phase = 7; await Save().ConfigureAwait(false);
            return snapshot.ToArray();

            async Task Guard()
            {
                var now = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                if (checked(fresh.Proof.TrustedLowerUnixSeconds + checked(now.SampleSeconds - fresh.Proof.MonotonicSample)) < lower)
                    throw new CryptographicException("ACK closure crossed authenticated lower-time rollback.");
                await publication.RecheckAsync(ct).ConfigureAwait(false);
                var actual = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                    storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
                if (fence.Kind != actual.Kind || !FixedRoute(fence.Selector.Span, actual.Selector.Span) || !FixedRoute(fence.Digest.Span, actual.Digest.Span))
                    throw new CryptographicException("ACK closure crossed native SQL fence replacement.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, snapshot, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantsRoot, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
            async Task Save()
            {
                await Guard().ConfigureAwait(false); state.Revision = checked(state.Revision + 1);
                var saved = await SaveMailboxReadJournalAsync(state, snapshot, current, instance, held, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = saved;
            }
        }
        finally { foreach (var bytes in new[] { snapshot, grantsRoot, oldAck, previousGrant }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
