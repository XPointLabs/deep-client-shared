using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // DR-0137: local-only historical result completion. This method has no
    // credential installation, signer, transport, current-grant or ACK authority.
    private async Task<OwnedDid2MailboxReadPage> ResumeCapturedFinalPageUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ProtectedDid2MailboxReadJournal.State state, byte[] originalRoot, byte[] grantRoot, byte[] retained,
        byte[] instance, CancellationToken ct)
    {
        var snapshot = originalRoot.ToArray(); byte[] exact = [];
        try
        {
            var cycle = state.Active ?? throw new CryptographicException("Captured page custody is absent.");
            var page = cycle.ReadPage();
            if (state.Phase < 3 || page.HasMore) throw new CryptographicException("Expired non-final page needs independent pagination recovery; original custody retained.");
            var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(fresh.Network, fresh.Authority,
                fresh.MailboxAuthority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var grant = await RequireOriginalReadFactsUnderLeaseAsync(current, held, source, fresh, host,
                retained, cycle.Grant, cycle.Route, cycle.Scope, cycle.RetrieveBody, ct).ConfigureAwait(false);
            if (cycle.CapturedAt < grant.NotBeforeUnixSeconds || cycle.CapturedAt >= grant.ExpiresAtUnixSeconds)
                throw new CryptographicException("Captured response lies outside its original authority interval.");
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
            var account = VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span);
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(cycle.RetrieveBody);
            var logical = OutboxLogicalId.FromBytes(request.OperationId.Span);
            var scope = ClientMailboxScope.Derive(cycle.Route, request.MailboxId, request.Epoch);
            if (!FixedRoute(scope.Value, cycle.Scope)) throw new CryptographicException("Captured result changed original SQL scope.");
            var stored = await ReadExact().ConfigureAwait(false);
            exact = stored.GetCiphertextBundleCopy();
            RequirePreparedMailboxRead(cycle, exact, MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant), ack: false);
            if (!FixedRoute(stored.DedupMaterial.Value, MailboxAuthenticatedClientRequestCodec.Decode(exact).Binding.RequestDigest.Span))
                throw new CryptographicException("Captured request changed its native SQL dedup binding.");
            var before = new ClientMailboxTraversal(request.AfterCursor, request.ContinuationToken.Span, cycle.PollGeneration);
            var after = new ClientMailboxTraversal(0, [], checked(cycle.PollGeneration + 1));
            var actual = await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false);
            await Guard().ConfigureAwait(false);
            if (state.Phase == 3 && actual.PollGeneration == before.PollGeneration)
            {
                RequireReadTraversal(actual, before);
                if (stored.State != TransportOutboxState.Attempted)
                    throw new CryptographicException("Uncommitted captured page has contradictory SQL outcome.");
                _ = await application.CommitRetrievePageAsync(scope, before, page, ct).ConfigureAwait(false);
            }
            RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), after);
            var inbox = await application.ReadDurableInboxAsync(scope, ct).ConfigureAwait(false);
            foreach (var item in page.Items)
            {
                var row = inbox.SingleOrDefault(value => value.Cursor == item.Cursor);
                // An ACK recovery may already have committed inbox tombstones.
                if (row is null && state.Phase is 6 or 8 && cycle.AckReply.Length != 0) continue;
                if (row is null || !FixedRoute(MailboxClientCodec.EncodeEncryptedEnvelope(row.Envelope),
                        MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope)))
                    throw new CryptographicException("Captured response has no exact native inbox custody.");
            }
            var evidence = ClientMailboxRetrieveOutcomeSummary.Encode(request, page, cycle.Page);
            if (stored.State == TransportOutboxState.Attempted)
            {
                if (stored.Attempts.Count == 0 || stored.Attempts.Any(value => value.State != TransportOutboxAttemptState.Attempted || value.GetEvidenceCopy().Length != 0))
                    throw new CryptographicException("Captured result lost its original transport attempt.");
                var at = DateTimeOffset.FromUnixTimeSeconds(checked((long)cycle.CapturedAt));
                if (at < stored.TransitionedAt || at >= stored.ExpiresAt)
                    throw new CryptographicException("Historical result time contradicts native attempt custody.");
                await Guard().ConfigureAwait(false);
                await Apply(TransportOutboxTransition.Accepted(account, logical, stored.Revision, stored.Attempts[^1].AttemptId,
                    OutboxTransitionSource.Recovery, OutboxTransitionReason.CrashReconciled, at, at, evidence)).ConfigureAwait(false);
                stored = await ReadExact().ConfigureAwait(false);
            }
            if (stored.State is not (TransportOutboxState.Accepted or TransportOutboxState.Durable))
                throw new CryptographicException("Captured response has contradictory native completion.");
            var completed = stored.Attempts.Single(value => value.State == (stored.State == TransportOutboxState.Accepted
                ? TransportOutboxAttemptState.Accepted : TransportOutboxAttemptState.Durable));
            if (!FixedRoute(completed.GetEvidenceCopy(), evidence)) throw new CryptographicException("Historical result differs from exact native evidence.");
            if (stored.State == TransportOutboxState.Accepted)
            {
                await Guard().ConfigureAwait(false);
                await Apply(TransportOutboxTransition.Durable(account, logical, stored.Revision, completed.AttemptId,
                    OutboxTransitionSource.Recovery, OutboxTransitionReason.CrashReconciled, stored.TransitionedAt, evidence)).ConfigureAwait(false);
                stored = await ReadExact().ConfigureAwait(false);
            }
            if (stored.State != TransportOutboxState.Durable) throw new CryptographicException("Historical result is not durably read back.");
            if (state.Phase == 3)
            {
                state.Traversals[Convert.ToHexString(cycle.Scope)] = after; state.Phase = 4;
                await Save().ConfigureAwait(false);
            }
            var result = new OwnedDid2MailboxReadPage(cycle.Grant, cycle.Scope, cycle.RetrieveMauHash, cycle.Page, cycle.CapturedAt);
            if (page.Items.Count == 0)
            { state.Active = null; state.Phase = 0; cycle.Dispose(); await Save().ConfigureAwait(false); }
            try { await Guard().ConfigureAwait(false); return result; }
            catch { result.Dispose(); throw; }

            async Task<TransportOutboxItemSnapshot> ReadExact()
            {
                var read = await application.ReadTransportOutboxAsync(account, logical, ct).ConfigureAwait(false);
                if (read.Result != TransportOutboxReadResult.Found || read.Item is null ||
                    exact.Length != 0 && !FixedRoute(read.Item.GetCiphertextBundleCopy(), exact))
                    throw new CryptographicException("Captured result lost exact original native request.");
                return read.Item;
            }
            async Task Apply(TransportOutboxTransition transition)
            {
                if (await application.ApplyTransportOutboxTransitionAsync(transition, ct).ConfigureAwait(false) is not (TransportOutboxCommitResult.Applied or TransportOutboxCommitResult.Idempotent))
                    throw new CryptographicException("Historical captured result conflicted with native state.");
            }
            async Task Guard()
            {
                _ = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                await host.EnsureCurrentAsync(ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, snapshot, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
            async Task Save()
            {
                await Guard().ConfigureAwait(false); state.Revision = checked(state.Revision + 1);
                var next = await SaveMailboxReadJournalAsync(state, snapshot, current, instance, held, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = next;
            }
        }
        finally { CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(exact); }
    }
}
