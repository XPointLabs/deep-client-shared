using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<byte[]?> RestartExpiredIdleTraversalUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        OwnRetainedPublication publication, ProtectedDid2MailboxReadJournal.State read, byte[] snapshot,
        byte[] instance, CancellationToken ct)
    {
        if (read.Phase != 0 || read.Active is not null) throw new CryptographicException("Active read cannot restart pagination.");
        var route = publication.Route;
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span);
        var mailbox = new BlindedMailboxId(route.Reachability.Field(2).Span);
        var placement = new BlindedPlacementId(route.Reachability.Field(10).Span);
        var scope = ClientMailboxScope.Derive(route.ExactHash.Span, mailbox, epoch);
        var scopeName = Convert.ToHexString(scope.Value);
        if (!read.Traversals.TryGetValue(scopeName, out var old)) return null;
        byte[] grantRoot = [], registrationHash = [], applicationHash = [], nextRoot = [];
        try
        {
            using (var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException())
                grantRoot = raw.Use(bytes => bytes.ToArray());
            using (var registrations = await storage.ReadOwnedBatchAsync(["deep.store.v2.sql-generation", SqliteDeepIdV2AccountGeneration.ApplicationStateSlot], ct).ConfigureAwait(false))
            {
                registrationHash = (registrations[0] ?? throw new InvalidDataException()).Use(bytes => SHA256.HashData(bytes));
                applicationHash = (registrations[1] ?? throw new InvalidDataException()).Use(bytes => SHA256.HashData(bytes));
            }
            if (old.AfterCursor == 0)
            {
                using var idleApplication = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                    storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
                RequireReadTraversal(await idleApplication.ReadTraversalAsync(scope, ct).ConfigureAwait(false), old);
                await publication.RecheckAsync(ct).ConfigureAwait(false);
                using (var roots = await storage.ReadOwnedBatchAsync(["deep.store.v2.sql-generation", SqliteDeepIdV2AccountGeneration.ApplicationStateSlot,
                    ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2MailboxReadJournal.Slot], ct).ConfigureAwait(false))
                    if (roots[0] is null || roots[1] is null || roots[2] is null || roots[3] is null ||
                        !roots[0]!.Use(bytes => FixedRoute(SHA256.HashData(bytes), registrationHash)) ||
                        !roots[1]!.Use(bytes => FixedRoute(SHA256.HashData(bytes), applicationHash)) ||
                        !roots[2]!.Use(bytes => FixedRoute(bytes, grantRoot)) || !roots[3]!.Use(bytes => FixedRoute(bytes, snapshot)))
                        throw new CryptographicException("Idle traversal lost its exact protected custody.");
                RequireReadTraversal(await idleApplication.ReadTraversalAsync(scope, ct).ConfigureAwait(false), old);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease); return null;
            }
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantRoot, networkId, current.AccountId.Span, instance);
            using var closedSources = await ReadClosedReadAcquisitionsUnderLeaseAsync(current, held, instance,
                grants, read, grantRoot, snapshot, ct).ConfigureAwait(false);
            var grantScope = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(route.ExactHash.Span,
                publication.Locator.Span, (byte)MailboxCapabilityDomain.Retrieve));
            var selected = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants, grantScope) ??
                throw new CryptographicException("Idle continuation lost its selected original holder.");
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                ProtectedDid2MailboxGrantJournal.Response(selected).Span).Field(8).Span);
            var operation = ClientMailboxAdapter.RetrieveOperationId(epoch, mailbox, placement, old);
            var body = MailboxAuthenticatedRequestTranscript.ForRetrieve(epoch, operation, mailbox, placement,
                old.AfterCursor, ProtectedDid2MailboxReadJournal.NewPageMaximumItems, old.ContinuationToken).CanonicalRequest;
            var expiry = ProtectedDid2MailboxReadJournal.BoundContinuationExpiry(body.Span, grant) ?? throw new CryptographicException();
            var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
            var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(first.SampleSeconds - fresh.Proof.MonotonicSample));
            if (lower < expiry) return null;
            var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(fresh.Network, fresh.Authority,
                fresh.MailboxAuthority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            _ = await RequireOriginalReadFactsUnderLeaseAsync(current, held, source, fresh, host, selected,
                SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)), route.ExactHash, scope.ToArray(), body, ct).ConfigureAwait(false);
            var fence = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
            var next = new ClientMailboxTraversal(0, [], checked(old.PollGeneration + 1));
            await Guard().ConfigureAwait(false);
            await RequireOriginalOperations().ConfigureAwait(false);
            var actual = await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false);
            RequireOldOrNext(actual);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeTraversalRestart);
#endif
            await RequireClosedReadSourcesAsync(closedSources, grantRoot, snapshot, registrationHash, applicationHash, held, ct).ConfigureAwait(false);
            _ = await application.RestartExpiredContinuationAsync(scope, old, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterTraversalRestart);
#endif
            await Guard().ConfigureAwait(false);
            await RequireOriginalOperations().ConfigureAwait(false);
            RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), next);
            read.Traversals[scopeName] = next; read.Revision = checked(read.Revision + 1);
            nextRoot = await SaveMailboxReadJournalAsync(read, snapshot, current, instance, held, ct).ConfigureAwait(false);
            await Guard().ConfigureAwait(false);
            await RequireOriginalOperations().ConfigureAwait(false);
            RequireReadTraversal(await application.ReadTraversalAsync(scope, ct).ConfigureAwait(false), next);
            return nextRoot.ToArray();

            void RequireOldOrNext(ClientMailboxTraversal value)
            {
                if (value.PollGeneration == old.PollGeneration) RequireReadTraversal(value, old);
                else RequireReadTraversal(value, next);
            }
            async Task RequireOriginalOperations()
            {
                await RequireClosedReadSourcesAsync(closedSources, grantRoot,
                    nextRoot.Length == 0 ? snapshot : nextRoot, registrationHash, applicationHash, held, ct).ConfigureAwait(false);
                foreach (var entry in grants.Entries.Values.Concat(closedSources.Entries.Values))
                {
                    if (!ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(entry) ||
                        !FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span, route.ExactBytes.Span)) continue;
                    var original = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
                        ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
                    if (original.Domain != MailboxCapabilityDomain.Retrieve) continue;
                    var stored = await application.ReadTransportOutboxAsync(VerifiedCurrentMailboxGrant.AccountScopeForHolder(original.HolderPublicKey.Span),
                        OutboxLogicalId.FromBytes(operation), ct).ConfigureAwait(false);
                    if (read.Closed.TryGetValue(Convert.ToHexString(SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(original))), out var closed) &&
                        closed.Phase != 3 && closed.PollGeneration == old.PollGeneration && FixedRoute(closed.Scope, scope.Value) &&
                        FixedRoute(closed.Route, route.ExactHash.Span) &&
                        FixedRoute(MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(closed.RetrieveBody).OperationId.Span, operation))
                        RequireUncapturedReadSql(stored, closed.Phase, closed.ExactMau, closed.RetrieveBody, closed.Grant, closed.Counter, closed.MauHash);
                    else if (stored.Result != TransportOutboxReadResult.Missing || stored.Item is not null)
                        throw new CryptographicException("Idle traversal has an unclosed prepared or captured query.");
                }
                await RequireClosedReadSourcesAsync(closedSources, grantRoot,
                    nextRoot.Length == 0 ? snapshot : nextRoot, registrationHash, applicationHash, held, ct).ConfigureAwait(false);
            }
            async Task Guard()
            {
                var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                if (checked(fresh.Proof.TrustedLowerUnixSeconds + checked(reading.SampleSeconds - fresh.Proof.MonotonicSample)) < lower)
                    throw new CryptographicException("Pagination restart crossed protected time rollback.");
                await publication.RecheckAsync(ct).ConfigureAwait(false);
                var after = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
                if (after.Kind != fence.Kind || !FixedRoute(after.Selector.Span, fence.Selector.Span) || !FixedRoute(after.Digest.Span, fence.Digest.Span))
                    throw new CryptographicException("Pagination restart changed its native fence.");
                using var roots = await storage.ReadOwnedBatchAsync(["deep.store.v2.sql-generation", SqliteDeepIdV2AccountGeneration.ApplicationStateSlot,
                    ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2MailboxReadJournal.Slot], ct).ConfigureAwait(false);
                if (roots[0] is null || roots[1] is null || roots[2] is null || roots[3] is null ||
                    !roots[0]!.Use(bytes => FixedRoute(SHA256.HashData(bytes), registrationHash)) ||
                    !roots[1]!.Use(bytes => FixedRoute(SHA256.HashData(bytes), applicationHash)) ||
                    !roots[2]!.Use(bytes => FixedRoute(bytes, grantRoot)) || !roots[3]!.Use(bytes => FixedRoute(bytes, nextRoot.Length == 0 ? snapshot : nextRoot)))
                    throw new CryptographicException("Pagination restart lost its exact account/read/grant custody.");
                await RequireClosedReadSourcesAsync(closedSources, grantRoot,
                    nextRoot.Length == 0 ? snapshot : nextRoot, registrationHash, applicationHash, held, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
        }
        finally { foreach (var bytes in new[] { grantRoot, registrationHash, applicationHash, nextRoot }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
