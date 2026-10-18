using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed record Did2MailboxSemanticEndpoints(Did2MessagingSessionScope Scope,
    DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority Pair);

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<ClientMailboxAckResult> AcknowledgeOwnMailboxAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        OwnedDid2MailboxReadPage descriptor, IReadOnlyList<Did2MailboxSemanticEndpoints> endpoints,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        IDid2MailboxGrantTransport grantTransport, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct)
    {
        byte[] instance = [], snapshot = [], grantRoot = [], exact = [];
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Protected mailbox read custody disappeared."))
                snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxReadJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var cycle = state.Active ?? throw new CryptographicException("No active protected page can authorize ACK.");
            using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct,
                cycle.Route).ConfigureAwait(false);
            if (state.Phase < 4 || !FixedRoute(cycle.Grant, descriptor.Grant) || !FixedRoute(cycle.Scope, descriptor.Scope) ||
                !FixedRoute(cycle.RetrieveMauHash, descriptor.RetrieveMauHash) || !FixedRoute(cycle.Page, descriptor.ExactPage) ||
                cycle.CapturedAt != descriptor.CapturedAt || !FixedRoute(cycle.Route, publication.Route.ExactHash.Span))
                throw new CryptographicException("ACK descriptor differs from the actual protected committed page.");
            var page = cycle.ReadPage(); if (page.Items.Count == 0) throw new CryptographicException("An empty page cannot mint an ACK.");
            var renewed = await ReauthorizeCapturedFinalAckUnderLeaseAsync(current, held, source, fresh,
                state, snapshot, instance, grantTransport, ct).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(snapshot); snapshot = renewed;
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Protected holder custody disappeared."))
                grantRoot = root.Use(bytes => bytes.ToArray());
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantRoot, networkId, current.AccountId.Span, instance);
            var grantName = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(cycle.Route, publication.Locator.Span, (byte)MailboxCapabilityDomain.Retrieve));
            var originalRetained = ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(grants, grantName, cycle.Grant);
            if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(originalRetained))
                throw new CryptographicException("ACK lost its original read-intent reservation; repair is forbidden.");
            var retained = ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(grants, grantName, cycle.AckGrantHash);
            var winner = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                ProtectedDid2MailboxGrantJournal.Request(retained), ProtectedDid2MailboxGrantJournal.Response(retained), ct).ConfigureAwait(false);
            if (!FixedRoute(SHA256.HashData(winner.ExactGrant.Span), cycle.AckGrantHash)) throw new CryptographicException("ACK changed its retained grant.");
            if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(retained))
                throw new CryptographicException("ACK lost its original read-intent reservation; repair is forbidden.");
            // Independently reconstruct semantic handoffs from actual verified
            // ratchet rows, not descriptor/callback flags. Do this before starting
            // the bounded signing loan; the ordinary receive already committed.
            await MaterializeMailboxPageUnderLeaseAsync(current, held, page, endpoints, source, fresh, ct).ConfigureAwait(false);
            using var loan = await OpenRetainedMailboxWinnerUnderLeaseAsync(current, held, publication, winner,
                retained, source, fresh, ct).ConfigureAwait(false);
            var scope = ClientMailboxScope.Derive(loan.Selector.IssuerContext.Span, loan.Route.MailboxId, loan.Route.Epoch);
            if (!FixedRoute(scope.ToArray(), cycle.Scope)) throw new CryptographicException("ACK differs from the actual installed scope.");
            RequireReadTraversal(await loan.Store.ReadTraversalAsync(scope, ct).ConfigureAwait(false), state.Traversals[Convert.ToHexString(cycle.Scope)]);
            _ = MailboxClientCodec.DecodeRetrievePage(cycle.Page, new OwnedMailboxDecodePolicy(loan.Grant, loan.Authority).GetCurrent());
            var acknowledgements = page.Items.Select(item => item.ToAcknowledgement()).ToArray();
            if (state.Phase == 4)
            {
                cycle.AckBody = MailboxAuthenticatedRequestTranscript.ForAck(page.Epoch, cycle.AckOperation(),
                    loan.Route.MailboxId, loan.Route.PlacementId, !page.HasMore,
                    page.HasMore ? page.ContinuationToken.Span : [], acknowledgements).CanonicalRequest.ToArray();
                state.Phase = 5; await Save(ct).ConfigureAwait(false);
            }
            var body = MailboxAuthenticatedRequestTranscript.DecodeAckBody(cycle.AckBody);
            var stored = await loan.Store.ReadTransportOutboxAsync(loan.Selector.AccountScope, OutboxLogicalId.FromBytes(body.OperationId.Span), ct).ConfigureAwait(false);
            MailboxAuthenticatedRequestFrame prepared;
            if (state.Phase is 6 or 8)
            {
                if (stored.Item is null || stored.Result != TransportOutboxReadResult.Found) throw new CryptographicException("Protected ACK has no SQL request; regeneration is forbidden.");
                exact = stored.Item.GetCiphertextBundleCopy(); prepared = new(MailboxAuthenticatedOperation.Ack, exact);
                RequirePreparedMailboxRead(cycle, exact, winner, ack: true);
            }
            else
            {
                if (stored.Item is { State: not TransportOutboxState.Prepared }) throw new CryptographicException("Pending protected ACK cannot already be dispatched.");
                loan.MinimumCounter = state.MinimumCounter(cycle.AckGrantHash);
                prepared = await new MailboxAuthenticatedRequestFactory(loan.Store, loan.Authority).CreateAckAsync(loan.Selector.AccountScope,
                    loan.Selector, loan.Signer, body.OperationId, body.IsFinalPage, body.ContinuationToken, body.Acknowledgements, ct).ConfigureAwait(false);
                exact = prepared.GetCanonicalMau3Copy(); cycle.AdoptPrepared(exact, ack: true);
                if (cycle.AckCounter < loan.MinimumCounter) throw new CryptographicException("SQL ACK replay counter rolled back behind protected custody.");
                state.Counters[Convert.ToHexString(cycle.AckGrantHash)] = cycle.AckCounter;
                state.Phase = cycle.AckGrant.Length == 0 ? (byte)6 : (byte)8; await Save(ct).ConfigureAwait(false);
            }
            var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease, sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
            var pma = fresh.MailboxAuthority;
            using var policy = await OpenRetainedInstallationPolicyAsync(current, held, publication, winner, source, fresh, ct).ConfigureAwait(false);
            var authority = new VerifiedOfficialMailboxAuthority(pma.NetworkId, pma.MinimumGrantGeneration,
                [pma.ResolveIssuer(MailboxCapabilityDomain.Retrieve)], false, static () => true, policy, policy.Clock);
            var decoder = new OwnedMailboxDecodePolicy(loan.Grant, authority);
            var context = new Did2OwnedMailboxTransportContext(source, custody, current, fresh, held, publication.Route.ExactBytes, winner);
            var pinned = new ClientMailboxPinnedRoute(loan.Route.PlacementId, loan.Route.MembershipCommitment.Span,
                loan.Route.Replicas.FirstId.Span, loan.Route.Replicas.FirstSigningKey.Span, loan.Route.Replicas.SecondId.Span, loan.Route.Replicas.SecondSigningKey.Span);
            var receiptVerifier = new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto());
            void VerifyQuorums(ReadOnlyMemory<byte> response)
            {
                var aggregate = MailboxAggregateAckCodec.DecodeMqr3(response.Span);
                if (aggregate.Epoch != body.Epoch || !FixedRoute(aggregate.OperationId.Span, body.OperationId.Span) || aggregate.TombstoneQuorums.Count != page.Items.Count)
                    throw new CryptographicException("Durable ACK outcome differs from the exact captured page.");
                for (var i = 0; i < page.Items.Count; i++)
                    _ = receiptVerifier.VerifyDurable(aggregate.TombstoneQuorums[i].Span, new()
                    {
                        Epoch = body.Epoch, OperationId = body.OperationId, MailboxId = body.MailboxId, Route = pinned,
                        EnvelopeDigest = page.Items[i].Envelope.DeduplicationDigest, ExpiresAtUnixSeconds = page.Items[i].Envelope.ExpiresAtUnixSeconds,
                        AllowedDispositions = new HashSet<MailboxReplicaDisposition> { MailboxReplicaDisposition.Tombstone }, Cursor = page.Items[i].Cursor
                    });
            }
            async Task Guard(CancellationToken token)
            {
                policy.ValidateFreshness(); await context.RequireCurrentAsync(token).ConfigureAwait(false);
                await publication.RecheckCustodyAsync(token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, snapshot, token).ConfigureAwait(false);
                await MaterializeMailboxPageUnderLeaseAsync(current, held, page, endpoints, source, fresh, token).ConfigureAwait(false);
                policy.ValidateFreshness(); held.RequireActive();
            }
            async Task Capture(ReadOnlyMemory<byte> response, CancellationToken token)
            {
                VerifyQuorums(response);
                if (cycle.AckReply.Length != 0) throw new CryptographicException("Protected ACK quorum winner cannot be replaced.");
                cycle.AckReply = response.ToArray(); await Save(token).ConfigureAwait(false);
            }
            using var ingress = new OwnedAckIngress(transport.Create(context, decoder) ?? throw new InvalidOperationException("Owned ACK transport is unavailable."),
                exact, loan.Route, Guard, Capture, () => cycle.AckReply.Length == 0 ? ReadOnlyMemory<byte>.Empty : cycle.AckReply.ToArray());
            var adapter = new ClientMailboxAdapter(ClientFeatureFlags.ReleaseDefaults with { ClientMailboxAdapterEnabled = true },
                new(true, loan.Selector.IssuerContext.Span, true), ingress, loan.Store, loan.Store, loan.Store, loan.Store,
                new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()), new MailboxAuthenticatedRequestFactory(loan.Store, authority), decoder, authority.TimeProvider);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            // The interceptor performs the complete pre-callback fence. Do not
            // repeat its SQL/semantic reconstruction immediately before adapter
            // bookkeeping; a cached result still crosses the final full fence.
            policy.ValidateFreshness(); held.RequireActive();
            try
            {
                var result = await adapter.DispatchPreparedAcknowledgementAsync(loan.Selector.AccountScope, loan.Selector, prepared, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                var completed = await loan.Store.ReadTransportOutboxAsync(loan.Selector.AccountScope, OutboxLogicalId.FromBytes(body.OperationId.Span), deadline.Token).ConfigureAwait(false);
                if (completed.Item is not { State: TransportOutboxState.Durable } || result.DurableTombstones != page.Items.Count)
                    throw new CryptographicException("ACK has no exact durable SQL quorum outcome.");
                // Do not treat a cached Durable bit as quorum evidence: reverify
                // retained exact quorums independently before releasing custody.
                var evidence = completed.Item.Attempts.Single(value => value.State == TransportOutboxAttemptState.Durable).GetEvidenceCopy();
                if (cycle.AckReply.Length == 0 || evidence.Length != 40 || !evidence.AsSpan(0, 4).SequenceEqual("MCO1"u8) ||
                    evidence.AsSpan(4, 4).IndexOfAnyExcept((byte)0) >= 0 || !FixedRoute(evidence.AsSpan(8), SHA256.HashData(cycle.AckReply)))
                    throw new CryptographicException("SQL ACK outcome digest does not bind its protected exact quorum response.");
                VerifyQuorums(cycle.AckReply);
                RequireReadTraversal(await loan.Store.ReadTraversalAsync(scope, deadline.Token).ConfigureAwait(false), state.Traversals[Convert.ToHexString(cycle.Scope)]);
                await Guard(deadline.Token).ConfigureAwait(false);
                state.Active = null; state.Phase = 0; cycle.Dispose(); await Save(deadline.Token).ConfigureAwait(false);
                policy.ValidateFreshness(); return result;
            }
            catch (Exception error) when (ingress.Attempted && error is not ClientMailboxDispatchOutcomeUnknownException &&
                error is CryptographicException or IOException or InvalidOperationException or OperationCanceledException)
            { throw new ClientMailboxDispatchOutcomeUnknownException("Owned ACK cannot confirm completion; retain the exact cycle.", error); }
            async Task Save(CancellationToken token)
            {
                state.Revision = checked(state.Revision + 1);
                var next = await SaveMailboxReadJournalAsync(state, snapshot, current, instance, held, token).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = next;
            }
        }
        finally { foreach (var bytes in new[] { instance, snapshot, grantRoot, exact }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task MaterializeMailboxPageUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        MailboxRetrievePage page, IReadOnlyList<Did2MailboxSemanticEndpoints> endpoints, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        if (endpoints.Count > ProtectedDid2MailboxReadJournal.MaximumItems) throw new CryptographicException("Semantic endpoint set exceeds owned page bounds.");
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        // One actual native snapshot per scope while the account lease remains
        // held. This is neither a cross-operation cache nor caller authority.
        var sessions = new Dictionary<string, (Did2MessagingSessionScope Scope, Did2MailboxSemanticEndpoints Endpoint,
            OwnedDid2MessagingStorage Opened, Did2MessagingFloor Floor, OnionMonotonicReading First)>(StringComparer.Ordinal);
        GroupRoot? groups = null; SqliteDeepMailboxStore? application = null;
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            foreach (var item in page.Items)
            {
                if (item.Envelope.Ciphertext.Span.StartsWith("DPH2"u8))
                {
                    await MaterializeMailboxInitialUnderLeaseAsync(current, held, Dph2Codec.Decode(item.Envelope.Ciphertext.Span),
                        endpoints, catalog, source, fresh, ct).ConfigureAwait(false);
                    continue;
                }
                if (item.Envelope.Ciphertext.Span.StartsWith("DBR2"u8))
                {
                    var control = Dbr2Codec.Decode(item.Envelope.Ciphertext.Span);
                    var controlScope = catalog.FindIncoming(control.NetworkId.Span, control.SessionId.Span,
                        control.SenderDeviceId.Span, control.RecipientDeviceId.Span) ??
                        throw new CryptographicException("Unknown Braid session cannot authorize tombstone.");
                    var endpoint = endpoints.SingleOrDefault(value => FixedRoute(value.Scope.Hash, controlScope.Hash)) ??
                        throw new CryptographicException("Braid tombstone lost its refreshed owned endpoint pair.");
                    var reading = await RequireMessagingFreshnessAsync(current, endpoint.Pair.Own, endpoint.Pair.Peer, source, held, ct).ConfigureAwait(false);
                    OwnedInitialMessagingSeed.RequireFreshScope(controlScope, endpoint.Pair.Own.Proof, endpoint.Pair.Peer, reading);
                    using var controlStorage = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, controlScope, ct).ConfigureAwait(false);
                    var controlFloor = await controlStorage.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                    if (ClassifyBraidMailboxCustodyUnderLease(controlStorage, controlScope, controlFloor, control, held, ct) == BraidMailboxCustody.NotCommitted)
                        throw new CryptographicException("Braid tombstone has neither authenticated receive nor obsolete-purpose custody.");
                    await RequireFinalMessagingFreshnessAsync(current, controlScope, endpoint.Pair.Own, endpoint.Pair.Peer, source, held, reading, ct).ConfigureAwait(false);
                    continue; // No DMC2 materialization, receipt obligation or AppAck for controls.
                }
                var incoming = Dpe2Codec.Decode(item.Envelope.Ciphertext.Span);
                var scope = catalog.FindIncoming(incoming.NetworkId.Span, incoming.SessionId.Span, incoming.SenderDeviceId.Span, incoming.RecipientDeviceId.Span) ??
                    throw new CryptographicException("Unknown mailbox session cannot authorize ACK.");
                var name = Convert.ToHexString(scope.Hash);
                if (!sessions.TryGetValue(name, out var session))
                {
                    var endpoint = endpoints.SingleOrDefault(value => FixedRoute(value.Scope.Hash, scope.Hash)) ??
                        throw new CryptographicException("Mailbox ACK has no independently refreshed owned endpoint pair.");
                    var reading = await RequireMessagingFreshnessAsync(current, endpoint.Pair.Own, endpoint.Pair.Peer, source, held, ct).ConfigureAwait(false);
                    OwnedInitialMessagingSeed.RequireFreshScope(scope, endpoint.Pair.Own.Proof, endpoint.Pair.Peer, reading);
                    var owned = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
                    try { session = (scope, endpoint, owned, await owned.Custody.ReconcileAsync(ct).ConfigureAwait(false), reading); sessions.Add(name, session); }
                    catch { owned.Dispose(); throw; }
                }
                var selected = session.Endpoint; var opened = session.Opened; var stable = session.Floor;
                using var retained = opened.Sql.ReadVerifiedOperation(stable, incoming.OperationId.Span) ?? throw new CryptographicException("ACK has no actual committed receive row.");
                if (retained.Direction != 2 || !FixedRoute(retained.ExactEnvelope, item.Envelope.Ciphertext.Span))
                    throw new CryptographicException("ACK differs from the actual authenticated receive.");
                using var plaintext = retained.OwnAuthenticatedDmc2();
                var parsed = plaintext.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
                try
                {
                    if (ProtectedDid2GroupJournal.IsKind(parsed.ContentKind))
                    {
                        groups ??= await OpenGroupsUnderLeaseAsync(current, ct).ConfigureAwait(false);
                        await MaterializeGroupNativeUnderLeaseAsync(current, held, scope, retained, selected.Pair.Own,
                            selected.Pair.Peer, source, ct, groups).ConfigureAwait(false);
                        continue;
                    }
                    application ??= await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                    if (parsed.ContentKind is Dmc2ContentKind.MessageCreate or Dmc2ContentKind.AttachmentOffer)
                    {
                        using var handoff = AuthenticatedDirectDmc2.FromOwnedDid2Commit(opened, stable, incoming.OperationId.Span, []);
                        RequireApplicationDisposition(await application.MaterializeDirectDmc2Async(handoff, ct).ConfigureAwait(false));
                    }
                    else if (parsed.ContentKind == Dmc2ContentKind.ContactAccept)
                    {
                        using var handoff = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened, incoming.OperationId, ReadOnlyMemory<byte>.Empty,
                            storage, selected.Pair.Own, selected.Pair.Peer, source, held, ct).ConfigureAwait(false);
                        RequireApplicationDisposition(await application.MaterializeContactAcceptAsync(handoff, ct).ConfigureAwait(false));
                    }
                    else if (parsed.ContentKind == Dmc2ContentKind.ContactRouteUpdate)
                    {
                        if (retained.RouteProcessing[0] == 2)
                            await RequireRejectedPeerRouteControlCommitUnderLeaseAsync(current, held, opened,
                                incoming.OperationId, selected.Pair.Own, selected.Pair.Peer, source, ct).ConfigureAwait(false);
                        else
                        {
                            using var handoff = await AuthenticatedPeerRouteUpdateDmc2.FromOwnedCommitAsync(this, current,
                                held, opened, incoming.OperationId, selected.Pair.Own, selected.Pair.Peer, source, ct).ConfigureAwait(false);
                            RequireApplicationDisposition(await application.MaterializePeerRouteUpdateAsync(handoff, ct).ConfigureAwait(false));
                        }
                    }
                    else throw new NotSupportedException("This mailbox event has no actual composed semantic ACK consumer; retain it.");
                }
                finally { if (parsed.ParsedPayload is AttachmentOfferDmc2Payload attachment) attachment.Manifest.Dispose(); }
            }
            foreach (var session in sessions.Values)
            {
                var final = await session.Opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                if (!FixedRoute(final.Exact.Span, session.Floor.Exact.Span)) throw new CryptographicException("ACK native custody changed during bounded page materialization.");
                await RequireFinalMessagingFreshnessAsync(current, session.Scope, session.Endpoint.Pair.Own,
                    session.Endpoint.Pair.Peer, source, held, session.First, ct).ConfigureAwait(false);
            }
            if (groups is not null)
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2GroupJournal.Slot, groups.Exact, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
        }
        finally
        {
            application?.Dispose(); groups?.Dispose(); foreach (var session in sessions.Values) session.Opened.Dispose();
            CryptographicOperations.ZeroMemory(instance);
        }
    }

    private sealed class OwnedAckIngress(IClientMailboxBinaryIngress target, byte[] exact, ScopedMailboxResolvedRoute installed,
        Func<CancellationToken, Task> guard, Func<ReadOnlyMemory<byte>, CancellationToken, Task> capture,
        Func<ReadOnlyMemory<byte>> readCaptured) : IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress, IDisposable
    {
        private readonly byte[] expected = exact.ToArray(); private bool disposed;
        internal bool Attempted { get; private set; }
        public async Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!FixedRoute(request.Span, expected) || route.Epoch != installed.Epoch || !FixedRoute(route.MailboxId.Bytes.Span, installed.MailboxId.Bytes.Span) ||
                !FixedRoute(route.PlacementCommitment.Span, installed.PlacementCommitment.Span) || !FixedRoute(route.MembershipCommitment.Span, installed.MembershipCommitment.Span))
                throw new CryptographicException("Owned ACK changed its exact request or route.");
            await guard(ct).ConfigureAwait(false);
            var saved = readCaptured(); if (!saved.IsEmpty) return saved;
            var owned = expected.ToArray();
            try
            {
                ct.ThrowIfCancellationRequested(); Attempted = true;
                var response = target is IRouteBoundClientMailboxBinaryIngress bound ? await bound.AcknowledgeOnRouteAsync(owned, route, ct).ConfigureAwait(false) : await target.AcknowledgeAsync(owned, ct).ConfigureAwait(false);
                if (response.IsEmpty || response.Length > ProtectedDid2MailboxReadJournal.MaximumAckReplyBytes) throw new InvalidDataException("ACK reply exceeds its closed aggregate bound.");
                var copied = response.ToArray();
                // Full post-callback fence precedes protected quorum capture.
                // Capture itself CAS/read-backs the updated root; the owner
                // performs the full final fence after SQL outcome read-back.
                try { await guard(ct).ConfigureAwait(false); await capture(copied, ct).ConfigureAwait(false); return copied; }
                catch { CryptographicOperations.ZeroMemory(copied); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(owned); }
        }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        public Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        private static Task<ReadOnlyMemory<byte>> Reject() => Task.FromException<ReadOnlyMemory<byte>>(new CryptographicException("Owned ACK loan permits only exact route-bound ACK."));
        public void Dispose() { disposed = true; CryptographicOperations.ZeroMemory(expected); }
    }
}
