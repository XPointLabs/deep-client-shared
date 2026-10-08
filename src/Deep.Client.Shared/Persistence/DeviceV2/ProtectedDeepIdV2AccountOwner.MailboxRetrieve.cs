using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<OwnedDid2MailboxReadPage> RetrieveOwnMailboxAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct)
    {
        byte[] instance = [], snapshot = [], grantRoot = [], exact = [];
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected mailbox read custody is absent; explicit reset is required."))
                snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxReadJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var routeHash = publication.Route.ExactHash.ToArray();
            if (state.Active is { } old && !FixedRoute(old.Route, routeHash))
                throw new CryptographicException("Resume the original protected mailbox read; silent rerouting is forbidden.");
            // Only a new cycle may acquire the selected winner. An interrupted
            // cycle must retain its original grant even after selection changes.
            var winner = state.Active is null
                ? await AcquireRetainedMailboxReadUnderLeaseAsync(current, held, publication, source, fresh, grants, ct).ConfigureAwait(false)
                : null;
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected mailbox grant custody disappeared.")) grantRoot = root.Use(bytes => bytes.ToArray());
            using var grantState = ProtectedDid2MailboxGrantJournal.Decode(grantRoot, networkId, current.AccountId.Span, instance);
            var grantName = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(routeHash, publication.Locator.Span, (byte)MailboxCapabilityDomain.Retrieve));
            var retained = state.Active is { } retainedCycle
                ? ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(grantState, grantName, retainedCycle.Grant)
                : ProtectedDid2MailboxGrantJournal.CurrentWinner(grantState, grantName) ??
                    throw new CryptographicException("Mailbox read has no selected protected Retrieve winner.");
            if (winner is not null && !FixedRoute(ProtectedDid2MailboxGrantJournal.Response(retained).Span, winner.ExactXmc2.Span))
                throw new CryptographicException("Mailbox read changed its acquired winner.");
            winner ??= await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                ProtectedDid2MailboxGrantJournal.Request(retained), ProtectedDid2MailboxGrantJournal.Response(retained),
                ct).ConfigureAwait(false);
            var grantHash = SHA256.HashData(winner.ExactGrant.Span);
            using var loan = await OpenRetainedMailboxWinnerUnderLeaseAsync(current, held, publication, winner,
                retained, source, fresh, ct).ConfigureAwait(false);
            var scope = ClientMailboxScope.Derive(loan.Selector.IssuerContext.Span, loan.Route.MailboxId, loan.Route.Epoch);
            var scopeHash = scope.ToArray(); var scopeName = Convert.ToHexString(scopeHash);
            var traversal = await loan.Store.ReadTraversalAsync(scope, ct).ConfigureAwait(false);
            if (state.Phase == 0)
            {
                if (!state.Traversals.TryGetValue(scopeName, out var floor))
                {
                    if (state.Traversals.Count >= ProtectedDid2MailboxReadJournal.MaximumFloors || traversal.PollGeneration != 0 ||
                        traversal.AfterCursor != 0 || !traversal.ContinuationToken.IsEmpty) throw new CryptographicException("New mailbox scope has no empty owned traversal.");
                    state.Traversals.Add(scopeName, traversal);
                }
                else RequireReadTraversal(traversal, floor);
                if (!state.Counters.ContainsKey(Convert.ToHexString(grantHash)) && state.Counters.Count >= ProtectedDid2MailboxReadJournal.MaximumFloors)
                    throw new IOException("Protected Retrieve-holder counter floors are full.");
                var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(loan.Route.Epoch,
                    ClientMailboxAdapter.RetrieveOperationId(loan.Route, traversal), loan.Route.MailboxId, loan.Route.PlacementId,
                    traversal.AfterCursor, ProtectedDid2MailboxReadJournal.MaximumItems, traversal.ContinuationToken);
                state.Active = ProtectedDid2MailboxReadJournal.Cycle.Begin(grantHash, scopeHash, routeHash, traversal.PollGeneration, binding.CanonicalRequest.Span);
                state.Phase = 1; await Save().ConfigureAwait(false);
            }
            var cycle = state.Active!;
            if (!FixedRoute(cycle.Scope, scopeHash)) throw new CryptographicException("Protected read belongs to another installed mailbox scope.");
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(cycle.RetrieveBody);
            var original = new ClientMailboxTraversal(request.AfterCursor, request.ContinuationToken.Span, cycle.PollGeneration);
            if (state.Phase is 1 or 2) RequireReadTraversal(traversal, original);
            else if (state.Phase >= 4) RequireReadTraversal(traversal, state.Traversals[scopeName]);
            var stored = await loan.Store.ReadTransportOutboxAsync(loan.Selector.AccountScope, OutboxLogicalId.FromBytes(request.OperationId.Span), ct).ConfigureAwait(false);
            MailboxAuthenticatedRequestFrame prepared;
            if (state.Phase >= 2)
            {
                if (stored.Item is null || stored.Result != TransportOutboxReadResult.Found)
                    throw new CryptographicException("Protected prepared Retrieve has no SQL request; regeneration is forbidden.");
                exact = stored.Item.GetCiphertextBundleCopy(); prepared = new(MailboxAuthenticatedOperation.Retrieve, exact);
                RequirePreparedMailboxRead(cycle, exact, winner, ack: false);
            }
            else
            {
                if (stored.Item is { State: not TransportOutboxState.Prepared })
                    throw new CryptographicException("Pending protected Retrieve cannot already be dispatched.");
                loan.MinimumCounter = state.MinimumCounter(grantHash);
                prepared = await new MailboxAuthenticatedRequestFactory(loan.Store, loan.Authority).CreateRetrieveAsync(
                    loan.Selector.AccountScope, loan.Selector, loan.Signer, loan.Route, request.OperationId, request.AfterCursor,
                    request.MaximumItems, request.ContinuationToken, ct).ConfigureAwait(false);
                exact = prepared.GetCanonicalMau3Copy(); cycle.AdoptPrepared(exact, ack: false);
                if (cycle.RetrieveCounter < loan.MinimumCounter) throw new CryptographicException("SQL read replay counter rolled back behind protected custody.");
                state.Counters[Convert.ToHexString(grantHash)] = cycle.RetrieveCounter; state.Phase = 2;
                await Save().ConfigureAwait(false);
            }
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease, sqlStatePath,
                current, source.AccountOwner, held, ct).ConfigureAwait(false);
            var pma = fresh.MailboxAuthority;
            using var policy = await OpenRetainedInstallationPolicyAsync(current, held, publication, winner, source, fresh, ct).ConfigureAwait(false);
            var authority = new VerifiedOfficialMailboxAuthority(pma.NetworkId, pma.MinimumGrantGeneration,
                [pma.ResolveIssuer(MailboxCapabilityDomain.Retrieve)], false, static () => true, policy, policy.Clock);
            var decoder = new OwnedMailboxDecodePolicy(loan.Grant, authority);
            var context = new Did2OwnedMailboxTransportContext(source, custody, current, fresh, held, publication.Route.ExactBytes, winner);
            async Task Guard(CancellationToken token)
            {
                policy.ValidateFreshness(); await context.RequireCurrentAsync(token).ConfigureAwait(false);
                await publication.RecheckCustodyAsync(token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, snapshot, token).ConfigureAwait(false);
                policy.ValidateFreshness(); held.RequireActive();
            }
            async Task Capture(ReadOnlyMemory<byte> response, CancellationToken token)
            {
                var decode = decoder.GetCurrent(); cycle.Capture(response.Span, decode.NowUnixSeconds, decode);
                state.Phase = 3; await Save(token).ConfigureAwait(false);
            }
            using var ingress = new OwnedRetrieveIngress(transport.Create(context, decoder) ?? throw new InvalidOperationException("Owned Retrieve transport is unavailable."), exact, loan.Route, Guard, Capture,
                () => cycle.Page.Length == 0 ? ReadOnlyMemory<byte>.Empty : cycle.Page.ToArray());
            var adapter = new ClientMailboxAdapter(ClientFeatureFlags.ReleaseDefaults with { ClientMailboxAdapterEnabled = true },
                new(true, loan.Selector.IssuerContext.Span, true), ingress, loan.Store, loan.Store, loan.Store, loan.Store,
                new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()),
                new MailboxAuthenticatedRequestFactory(loan.Store, authority), decoder, authority.TimeProvider);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            await Guard(deadline.Token).ConfigureAwait(false);
            try
            {
                if (state.Phase >= 5) { /* ACK recovery validates its retained SQL/tombstones separately. */ }
                else if (state.Phase >= 3 && traversal.PollGeneration == checked(original.PollGeneration + 1))
                    _ = await adapter.ResumeCapturedRetrieveAsync(loan.Selector.AccountScope, loan.Selector, prepared, cycle.Page, original, deadline.Token).ConfigureAwait(false);
                else
                    _ = await adapter.DispatchPreparedRetrieveAsync(loan.Selector.AccountScope, loan.Selector, prepared, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                if (state.Phase < 3) throw new CryptographicException("A SQL Retrieve result has no protected captured page.");
                var page = cycle.ReadPage(); var next = new ClientMailboxTraversal(page.HasMore ? page.NextCursor : 0,
                    page.HasMore ? page.ContinuationToken.Span : [], checked(original.PollGeneration + 1));
                RequireReadTraversal(await loan.Store.ReadTraversalAsync(scope, deadline.Token).ConfigureAwait(false), next);
                var completed = await loan.Store.ReadTransportOutboxAsync(loan.Selector.AccountScope, OutboxLogicalId.FromBytes(request.OperationId.Span), deadline.Token).ConfigureAwait(false);
                if (completed.Item is not { State: TransportOutboxState.Durable }) throw new CryptographicException("Captured page has no durable SQL outcome.");
                var evidence = completed.Item.Attempts.Single(value => value.State == TransportOutboxAttemptState.Durable).GetEvidenceCopy();
                if (!FixedRoute(evidence, ClientMailboxRetrieveOutcomeSummary.Encode(request, page, cycle.Page)))
                    throw new CryptographicException("Captured response differs from independently read SQL outcome.");
                await Guard(deadline.Token).ConfigureAwait(false);
                if (state.Phase == 3)
                { state.Traversals[scopeName] = next; state.Phase = 4; await Save(deadline.Token).ConfigureAwait(false); }
                var result = new OwnedDid2MailboxReadPage(cycle.Grant, cycle.Scope, cycle.RetrieveMauHash, cycle.Page, cycle.CapturedAt);
                if (page.Items.Count == 0)
                { state.Active = null; state.Phase = 0; cycle.Dispose(); await Save(deadline.Token).ConfigureAwait(false); }
                try { await Guard(deadline.Token).ConfigureAwait(false); return result; }
                catch { result.Dispose(); throw; }
            }
            catch (Exception error) when (ingress.Attempted && error is not ClientMailboxDispatchOutcomeUnknownException &&
                error is CryptographicException or IOException or InvalidOperationException or OperationCanceledException)
            { throw new ClientMailboxDispatchOutcomeUnknownException("Owned Retrieve cannot confirm its outcome; retain exact custody.", error); }

            async Task Save(CancellationToken? token = null)
            {
                state.Revision = checked(state.Revision + 1);
                var next = await SaveMailboxReadJournalAsync(state, snapshot, current, instance, held, token ?? ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = next;
            }
        }
        finally { foreach (var bytes in new[] { instance, snapshot, grantRoot, exact }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void RequireReadTraversal(ClientMailboxTraversal actual, ClientMailboxTraversal expected)
    {
        if (actual.PollGeneration != expected.PollGeneration || actual.AfterCursor != expected.AfterCursor ||
            !FixedRoute(actual.ContinuationToken, expected.ContinuationToken)) throw new CryptographicException("Mailbox SQL traversal differs from protected custody.");
    }

    private static void RequirePreparedMailboxRead(ProtectedDid2MailboxReadJournal.Cycle cycle, ReadOnlySpan<byte> exact,
        VerifiedMailboxRetainedReadGrantV2 winner, bool ack)
    {
        var request = MailboxAuthenticatedClientRequestCodec.Decode(exact);
        if (request.Binding.Operation != (ack ? MailboxAuthenticatedOperation.Ack : MailboxAuthenticatedOperation.Retrieve) ||
            !FixedRoute(request.Binding.CanonicalRequest.Span, ack ? cycle.AckBody : cycle.RetrieveBody) ||
            request.Presentation.ReplayCounter != (ack ? cycle.AckCounter : cycle.RetrieveCounter) ||
            !FixedRoute(SHA256.HashData(exact), ack ? cycle.AckMauHash : cycle.RetrieveMauHash) ||
            !FixedRoute(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), winner.ExactGrant.Span) ||
            !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation), request.Presentation.Grant.HolderPublicKey.ToArray()))
            throw new CryptographicException("Prepared read/ACK differs from exact protected custody.");
    }

    private async Task<byte[]> SaveMailboxReadJournalAsync(ProtectedDid2MailboxReadJournal.State state, byte[] expected,
        VerifiedDeepIdV2CurrentAccount current, byte[] instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var next = ProtectedDid2MailboxReadJournal.Encode(state, networkId, current.AccountId.Span, instance);
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            if (!await storage.CompareExchangeAsync(ProtectedDid2MailboxReadJournal.Slot, expected, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Mailbox read custody changed under its actual owner lease.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, next, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return next.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }

    private sealed class OwnedRetrieveIngress(IClientMailboxBinaryIngress target, byte[] exact, ScopedMailboxResolvedRoute installed,
        Func<CancellationToken, Task> guard, Func<ReadOnlyMemory<byte>, CancellationToken, Task> capture,
        Func<ReadOnlyMemory<byte>> readCaptured) : IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress, IDisposable
    {
        private readonly byte[] expected = exact.ToArray(); private bool disposed;
        internal bool Attempted { get; private set; }
        public async Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (!FixedRoute(request.Span, expected) || route.Epoch != installed.Epoch ||
                !FixedRoute(route.MailboxId.Bytes.Span, installed.MailboxId.Bytes.Span) ||
                !FixedRoute(route.PlacementCommitment.Span, installed.PlacementCommitment.Span) ||
                !FixedRoute(route.MembershipCommitment.Span, installed.MembershipCommitment.Span)) throw new CryptographicException("Owned Retrieve changed request or route.");
            await guard(ct).ConfigureAwait(false);
            var saved = readCaptured(); if (!saved.IsEmpty) return saved;
            var owned = expected.ToArray();
            try
            {
                ct.ThrowIfCancellationRequested(); Attempted = true;
                var response = target is IRouteBoundClientMailboxBinaryIngress bound ?
                    await bound.RetrieveOnRouteAsync(owned, route, ct).ConfigureAwait(false) : await target.RetrieveAsync(owned, ct).ConfigureAwait(false);
                if (response.Length is < 48 or > ProtectedDid2MailboxReadJournal.MaximumPageBytes) throw new InvalidDataException("Owned Retrieve reply exceeds its closed bound.");
                var copied = response.ToArray();
                try { await guard(ct).ConfigureAwait(false); await capture(copied, ct).ConfigureAwait(false); await guard(ct).ConfigureAwait(false); return copied; }
                catch { CryptographicOperations.ZeroMemory(copied); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(owned); }
        }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        public Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        private static Task<ReadOnlyMemory<byte>> Reject() => Task.FromException<ReadOnlyMemory<byte>>(new CryptographicException("Owned read loan permits only exact route-bound Retrieve."));
        public void Dispose() { disposed = true; CryptographicOperations.ZeroMemory(expected); }
    }
}

// Internal key-free encrypted page descriptor. It is never an ACK capability;
// continuation must independently re-read this exact actual protected cycle.
internal sealed class OwnedDid2MailboxReadPage : IDisposable
{
    internal OwnedDid2MailboxReadPage(ReadOnlySpan<byte> grant, ReadOnlySpan<byte> scope, ReadOnlySpan<byte> mau, ReadOnlySpan<byte> page, ulong capturedAt)
    { Grant = grant.ToArray(); Scope = scope.ToArray(); RetrieveMauHash = mau.ToArray(); ExactPage = page.ToArray(); CapturedAt = capturedAt; }
    internal byte[] Grant { get; }
    internal byte[] Scope { get; }
    internal byte[] RetrieveMauHash { get; }
    internal byte[] ExactPage { get; }
    internal ulong CapturedAt { get; }
    internal MailboxRetrievePage ReadPage()
    {
        if (ExactPage.Length is < 48 or > ProtectedDid2MailboxReadJournal.MaximumPageBytes || CapturedAt == 0)
            throw new InvalidDataException("Owned page descriptor is not bounded captured metadata.");
        return MailboxClientCodec.DecodeRetrievePage(ExactPage, new()
        {
            NowUnixSeconds = CapturedAt,
            EpochWindow = new() { CurrentEpoch = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(ExactPage.AsSpan(8)),
                CurrentNotBeforeUnixSeconds = 1, CurrentExpiresAtUnixSeconds = ulong.MaxValue,
                NextEpoch = 0, NextNotBeforeUnixSeconds = 0, NextExpiresAtUnixSeconds = 0 },
            CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }, AllowLegacyMirrorOverlap = false
        });
    }
    public void Dispose() { foreach (var bytes in new[] { Grant, Scope, RetrieveMauHash, ExactPage }) CryptographicOperations.ZeroMemory(bytes); }
}
