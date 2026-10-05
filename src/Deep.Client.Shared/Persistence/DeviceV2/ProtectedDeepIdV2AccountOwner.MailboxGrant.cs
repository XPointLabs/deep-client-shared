using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // Only the actual completed own publication supplies private reply metadata.
    // No public descriptor secret, retrieve capability or holder escapes.
    internal async Task<ParsedDeepIdV2ContactMailboxRoute> ReadOwnPrivateContactMailboxRouteAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
        var package = DeepIdV2ContactMailboxRouteCodec.Decode(DeepIdV2ContactMailboxRouteCodec.Encode(publication.Route));
        await publication.RecheckAsync(ct).ConfigureAwait(false);
        return package;
    }

    internal async Task<VerifiedDeepIdV2MailboxGrant> AcquirePermanentContactDepositGrantAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        IDid2MailboxGrantTransport transport, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(transport);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var contact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        var route = contact.Contact.Route;
        var locator = contact.Contact.Candidate.Request.LocatorHash;
        return await AcquireMailboxGrantUnderLeaseAsync(current, held, source, resolved.Own, route,
            locator, route.Route.Reachability.Field(10), MailboxCapabilityDomain.Deposit, async token =>
            { await RequireClaimContactTimeAsync(current, source, resolved, held, contact.Contact, contact.Time, token).ConfigureAwait(false); },
            transport, ct).ConfigureAwait(false);
    }

    internal async Task<VerifiedDeepIdV2MailboxGrant> AcquireOwnPermanentContactRetrieveGrantAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        IDid2MailboxGrantTransport transport, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(transport);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var publication = await OpenOwnPermanentMailboxPublicationUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
        return await AcquireMailboxGrantUnderLeaseAsync(current, held, source, fresh, publication.Route,
            publication.Locator, publication.Capability, MailboxCapabilityDomain.Retrieve,
            publication.RecheckAsync, transport, ct).ConfigureAwait(false);
    }

    // One private derivation for grant acquisition and the recipient polling
    // continuation. No secret, route trust marker or callback leaves the owner.
    private async Task<OwnPermanentMailboxPublication> OpenOwnPermanentMailboxPublicationUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        CancellationToken ct)
    {
        held.RequireActive();
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? routeSnapshot = null, resolverCapability = null, ownerCapability = null;
        try
        {
            var plan = CreatePermanentContactPlan(current, instance);
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected owner publication custody is absent; explicit local reset is required.");
            routeSnapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(routeSnapshot, networkId, current.AccountId.Span, instance);
            if (!state.Entries.TryGetValue(Convert.ToHexString(plan.Intent.Span), out var entry) || entry.Phase != 7 ||
                !entry.Matches(Did2OwnedPermanentContactPlan.Configuration()))
                throw new CryptographicException("Owner retrieval requires the exact committed permanent publication.");
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(entry.Record(0).Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, first.BootId.Span, first.SampleSeconds);
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var permanent = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, current.AccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.DeepId, ct).ConfigureAwait(false);
            resolverCapability = permanent.ResolverReadCapability.ToArray();
            var contact = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, entry.Record(7), entry.Record(8), resolverCapability, ct).ConfigureAwait(false);
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            var publication = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
            _ = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact, request,
                publication.ExactXpu1, entry.Record(11), ct).ConfigureAwait(false);
            // Exact-body/commit verification binds this secret to XPU1 tag 27.
            // It is never obtained from a public resolve or caller argument.
            ownerCapability = request.OwnerRetrieveCapability.ToArray();
            var locator = Xpu1Codec.Decode(publication.ExactXpu1.Span).LocatorHash;
            var retainedSnapshot = routeSnapshot;
            async Task RecheckCustody(CancellationToken token)
            {
                held.RequireActive();
                using var retained = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, token).ConfigureAwait(false) ??
                    throw new CryptographicException("Protected owner publication disappeared during retrieval.");
                if (!retained.Use(bytes => FixedRoute(bytes, retainedSnapshot)))
                    throw new CryptographicException("Protected owner publication changed during retrieval.");
                token.ThrowIfCancellationRequested(); held.RequireActive();
            }
            async Task Recheck(CancellationToken token)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, token).ConfigureAwait(false);
                await RecheckCustody(token).ConfigureAwait(false);
            }
            await Recheck(ct).ConfigureAwait(false);
            var owned = new OwnPermanentMailboxPublication(route, contact.Closure, locator.Span, ownerCapability, retainedSnapshot, Recheck, RecheckCustody);
            // Transfer only after closed verification and final protected read-back.
            // The loan's disposal owns both sensitive buffers from this point.
            ownerCapability = null; routeSnapshot = null;
            return owned;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (routeSnapshot is not null) CryptographicOperations.ZeroMemory(routeSnapshot);
            if (resolverCapability is not null) CryptographicOperations.ZeroMemory(resolverCapability);
            if (ownerCapability is not null) CryptographicOperations.ZeroMemory(ownerCapability);
        }
    }

    private sealed class OwnPermanentMailboxPublication : IDisposable
    {
        private readonly byte[] locator, capability, snapshot;
        private readonly Func<CancellationToken, Task> recheck;
        private readonly Func<CancellationToken, Task> recheckCustody;
        private bool disposed;
        internal OwnPermanentMailboxPublication(VerifiedDeepIdV2ContactRouteClosure route, ParsedDcr1V2 contact,
            ReadOnlySpan<byte> locator, byte[] capability, byte[] snapshot, Func<CancellationToken, Task> recheck,
            Func<CancellationToken, Task> recheckCustody)
        { Route = route; Contact = contact; this.locator = locator.ToArray(); this.capability = capability; this.snapshot = snapshot; this.recheck = recheck; this.recheckCustody = recheckCustody; }
        internal VerifiedDeepIdV2ContactRouteClosure Route { get; }
        internal ParsedDcr1V2 Contact { get; }
        internal ReadOnlyMemory<byte> Locator { get { RequireActive(); return locator; } }
        internal ReadOnlyMemory<byte> Capability { get { RequireActive(); return capability; } }
        internal Task RecheckAsync(CancellationToken ct) { RequireActive(); return recheck(ct); }
        // The dispatch context independently rechecks the same actual own
        // directory/network floors. Do not reopen both SQL stores twice in one
        // fence; this private continuation adds the publication's exact root.
        internal Task RecheckCustodyAsync(CancellationToken ct) { RequireActive(); return recheckCustody(ct); }
        private void RequireActive() => ObjectDisposedException.ThrowIf(disposed, this);
        public void Dispose()
        {
            if (disposed) return; disposed = true;
            CryptographicOperations.ZeroMemory(locator); CryptographicOperations.ZeroMemory(capability); CryptographicOperations.ZeroMemory(snapshot);
        }
    }

    // Both directions enter through the closed wrappers above. The recheck
    // delegate is constructed here inside the actual owner's held lease, never
    // supplied by a public caller or used as a caller-mintable trust flag.
    private async Task<VerifiedDeepIdV2MailboxGrant> AcquireMailboxGrantUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locator, ReadOnlyMemory<byte> capability,
        MailboxCapabilityDomain domain, Func<CancellationToken, Task> recheck,
        IDid2MailboxGrantTransport transport, CancellationToken ct)
    {
        held.RequireActive();
        await RequireMailboxIssuerCurrentAsync(route, fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
        var routeHash = SHA256.HashData(route.ExactRouteClosure.Span);
        var scope = ProtectedDid2MailboxGrantJournal.Scope(routeHash, locator.Span, (byte)domain);
        var name = Convert.ToHexString(scope);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null;
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected mailbox holder custody is absent; explicit local reset is required.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var entry = ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(state, name);
            if (entry is null)
            {
                if (state.Entries.Count >= ProtectedDid2MailboxGrantJournal.MaximumEntries)
                    throw new IOException("Protected mailbox holder custody is full.");
                var seed = NewRouteRandom32();
                try
                {
                    using var signer = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                        capability, domain, seed);
                    var request = domain == MailboxCapabilityDomain.Deposit ?
                        await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, signer, ct).ConfigureAwait(false) :
                        await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route, locator, capability, signer, ct).ConfigureAwait(false);
                    await recheck(ct).ConfigureAwait(false);
                    await RequireMailboxIssuerCurrentAsync(route, fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
                    entry = ProtectedDid2MailboxGrantJournal.Pending(seed, routeHash, request, networkId);
                    ProtectedDid2MailboxGrantJournal.AddPending(state, entry);
                    state.Revision = checked(state.Revision + 1);
                    var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally { CryptographicOperations.ZeroMemory(seed); }
            }
            if (!ProtectedDid2MailboxGrantJournal.HasWinner(entry))
            {
                using var signer = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                    capability, domain,
                    ProtectedDid2MailboxGrantJournal.Seed(entry));
                var request = domain == MailboxCapabilityDomain.Deposit ?
                    await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(route, locator,
                        signer.Ed25519PublicKey, ProtectedDid2MailboxGrantJournal.Request(entry), ct).ConfigureAwait(false) :
                    await DeepIdV2MailboxGrantRequestAuthor.RestoreRetrieveAsync(route, locator, capability,
                        signer.Ed25519PublicKey, ProtectedDid2MailboxGrantJournal.Request(entry), ct).ConfigureAwait(false);
                await recheck(ct).ConfigureAwait(false);
                await RequireMailboxIssuerCurrentAsync(route, fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, deadline.Token).ConfigureAwait(false);
                var dispatch = new Did2OwnedContactTransportContext(custody, fresh.Network, held);
                var returned = await transport.AcquireAsync(request, route, dispatch, deadline.Token).AsTask()
                    .WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length != 510) throw new InvalidDataException("Mailbox success exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, request,
                        response, fresh.MailboxAuthority.ExactPma2, deadline.Token).ConfigureAwait(false);
                    await recheck(deadline.Token).ConfigureAwait(false);
                    var next = ProtectedDid2MailboxGrantJournal.WithWinner(entry, verified.ExactXmc2.Span, networkId);
                    state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(entry)] = next;
                    CryptographicOperations.ZeroMemory(entry); entry = next;
                    state.Revision = checked(state.Revision + 1);
                    var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, deadline.Token).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            // Read the protected winner again, not the callback or the mutable
            // in-memory transition. No expired acquisition envelope is retried.
            using var winnerRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Adopted mailbox custody disappeared.");
            using var winnerState = winnerRoot.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(
                bytes, networkId, current.AccountId.Span, instance));
            var winner = ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(winnerState, name);
            if (winner is null || !ProtectedDid2MailboxGrantJournal.HasWinner(winner) ||
                !FixedRoute(winner, entry)) throw new CryptographicException("Mailbox winner differs from protected read-back.");
            var result = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                ProtectedDid2MailboxGrantJournal.Request(winner), ProtectedDid2MailboxGrantJournal.Response(winner),
                fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
            // A received initial winner remains the pending candidate until its actual
            // verification and protected read-back. Cold reopen adopts that exact
            // candidate without another issuer call; selection is never inferred.
            if (winnerState.Selections[name].Current is null)
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeSelection);
#endif
                await recheck(ct).ConfigureAwait(false);
                ProtectedDid2MailboxGrantJournal.PromoteWinner(winnerState, name);
                winnerState.Revision = checked(winnerState.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(winnerState, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
            }
            await InstallMailboxWinnerUnderLeaseAsync(current, held, route, result, locator, capability,
                winner, source, fresh, recheck, ct).ConfigureAwait(false);
            using var installedRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Protected mailbox winner disappeared during SQL installation.");
            if (!installedRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Protected mailbox custody changed during SQL installation.");
            await recheck(ct).ConfigureAwait(false);
            await result.EnsureCurrentAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
        }
    }

    private static async Task RequireMailboxIssuerCurrentAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ReadOnlyMemory<byte> exactPma2, CancellationToken ct)
    {
        var time = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var policy = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, exactPma2.Span,
            time.LowerUnixSeconds, time.UpperUnixSeconds);
        if (!policy.BindsProjection(route.Route.Projection.CanonicalBytes.Span))
            throw new CryptographicException("Owned mailbox acquisition has no current root-authorized issuer policy.");
        ct.ThrowIfCancellationRequested();
    }

    private async Task<byte[]> SaveMailboxGrantJournalAsync(ProtectedDid2MailboxGrantJournal.State state,
        byte[] expected, ReadOnlyMemory<byte> account, byte[] instance, CancellationToken ct)
    {
        var next = ProtectedDid2MailboxGrantJournal.Encode(state, networkId, account.Span, instance);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, expected, next, ct).ConfigureAwait(false))
                throw new IOException("Mailbox custody changed during account-owned adoption.");
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Adopted mailbox custody is absent.");
            if (!readback.Use(bytes => FixedRoute(bytes, next))) throw new CryptographicException("Mailbox custody read-back differs.");
            ct.ThrowIfCancellationRequested(); return next.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }
}
