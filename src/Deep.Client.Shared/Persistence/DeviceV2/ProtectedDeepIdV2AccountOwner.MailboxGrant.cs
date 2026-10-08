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

    internal async Task<VerifiedMailboxRetainedReadGrantV2> AcquireOwnPermanentContactRetrieveGrantAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        IDid2RetainedMailboxReadGrantTransport transport, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(transport);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
        return await AcquireRetainedMailboxReadUnderLeaseAsync(current, held, publication, source, fresh, transport, ct).ConfigureAwait(false);
    }

    internal async Task<VerifiedMailboxRetainedReadGrantV2> AcceptOwnPermanentContactRetrieveGrantResultAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
        return await AcceptRetainedMailboxReadResultUnderLeaseAsync(current, held, publication, source, fresh, exactXmc2, ct).ConfigureAwait(false);
    }

    internal async Task<VerifiedDeepIdV2MailboxGrant> AcceptPermanentContactDepositGrantResultAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var contact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        var route = contact.Contact.Route;
        return await AcceptMailboxGrantResultUnderLeaseAsync(current, held, source, resolved.Own, route,
            contact.Contact.Candidate.Request.LocatorHash, route.Route.Reachability.Field(10),
            MailboxCapabilityDomain.Deposit, async token =>
            { await RequireClaimContactTimeAsync(current, source, resolved, held, contact.Contact, contact.Time, token).ConfigureAwait(false); },
            exactXmc2, ct).ConfigureAwait(false);
    }

    // The packet is untrusted input, never a caller-supplied outcome or authority.
    // All route/capability/proof continuations originate in this actual owner.
    private async Task<VerifiedDeepIdV2MailboxGrant> AcceptMailboxGrantResultUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> locator, ReadOnlyMemory<byte> capability,
        MailboxCapabilityDomain domain, Func<CancellationToken, Task> recheck,
        ReadOnlyMemory<byte> exactXmc2, CancellationToken ct)
    {
        held.RequireActive(); ct.ThrowIfCancellationRequested();
        if (domain != MailboxCapabilityDomain.Deposit)
            throw new CryptographicException("Current-route settlement is Deposit-only.");
        if (exactXmc2.Length is not (0 or 510)) throw new InvalidDataException("Late mailbox result exceeds its exact bound.");
        var routeHash = SHA256.HashData(route.ExactRouteClosure.Span);
        var scope = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(routeHash, locator.Span, (byte)domain));
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null;
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Original mailbox acquisition custody is absent.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            ContactRecord response;
            if (exactXmc2.IsEmpty)
            {
                // Explicit recovery selects only an actual retained late result;
                // no packet is reconstructed and no issuer callback is involved.
                var candidate = ProtectedDid2MailboxGrantJournal.RequireLateResultForResume(state, scope);
                response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(candidate).Span);
            }
            else response = ContactCodec.Decode("XMC2", exactXmc2.Span);
            var acquisition = Convert.ToHexString(response.Field(5).Span);
            if (!state.Entries.TryGetValue(acquisition, out var entry) ||
                !FixedRoute(entry.AsSpan(0, 32), Convert.FromHexString(scope)) ||
                !FixedRoute(entry.AsSpan(64, 32), routeHash))
                throw new CryptographicException("Late mailbox result has no exact owned acquisition in this route and role.");
            var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
            if (!FixedRoute(request.Field(4).Span, capability.Span))
                throw new CryptographicException("Late mailbox result differs from the actual private capability.");
            if (!ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry) && !ProtectedDid2MailboxGrantJournal.HasWinner(entry))
                throw new InvalidDataException("Pending acquisition must close under authenticated time before late settlement.");
            if (ProtectedDid2MailboxGrantJournal.HasWinner(entry) &&
                !FixedRoute(ProtectedDid2MailboxGrantJournal.Response(entry).Span, response.CanonicalBytes.Span))
                throw new CryptographicException("A mailbox winner is immutable; a different late result cannot replace it.");
            var verified = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                ProtectedDid2MailboxGrantJournal.Request(entry), response.CanonicalBytes,
                fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
            await recheck(ct).ConfigureAwait(false);
            if (ProtectedDid2MailboxGrantJournal.IsClosedUnresolved(entry))
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeLateResult);
#endif
                var next = ProtectedDid2MailboxGrantJournal.WithLateWinner(entry, verified.ExactXmc2.Span, networkId);
                state.Entries[acquisition] = next; CryptographicOperations.ZeroMemory(entry); entry = next;
                state.Revision = checked(state.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterLateResult);
#endif
            }
            using var receivedRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Late mailbox result disappeared before adoption.");
            if (!receivedRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Late mailbox custody changed before adoption.");
            using var received = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var winner = received.Entries[acquisition];
            verified = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                ProtectedDid2MailboxGrantJournal.Request(winner), ProtectedDid2MailboxGrantJournal.Response(winner),
                fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
            await recheck(ct).ConfigureAwait(false);
            if (ProtectedDid2MailboxGrantJournal.IsLateCandidate(winner))
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeLateAdoption);
#endif
                ProtectedDid2MailboxGrantJournal.AdoptLateWinner(received, acquisition);
                received.Revision = checked(received.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(received, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterLateAdoption);
#endif
            }
            // Ordinary received winners are still pending, not late adopted work.
            if (!ProtectedDid2MailboxGrantJournal.IsLateAdopted(winner) &&
                received.Selections[scope].Pending == acquisition)
                throw new InvalidDataException("Ordinary pending winner requires its original selection continuation.");
            await recheck(ct).ConfigureAwait(false); await verified.EnsureCurrentAsync(ct).ConfigureAwait(false);
            using var selectedRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Late mailbox selection disappeared.");
            if (!selectedRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Late mailbox selection changed before SQL installation.");
            await InstallMailboxWinnerUnderLeaseAsync(current, held, route, verified, locator, capability,
                winner, source, fresh, recheck, ct).ConfigureAwait(false);
            await recheck(ct).ConfigureAwait(false); await verified.EnsureCurrentAsync(ct).ConfigureAwait(false);
            using var finalRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Late mailbox custody disappeared during installation.");
            if (!finalRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Late mailbox custody changed during installation.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
        }
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

    // Deposit enters through its closed wrapper above. The recheck
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
        if (domain != MailboxCapabilityDomain.Deposit)
            throw new CryptographicException("Current-route acquisition is Deposit-only.");
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
                    var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, locator, signer, ct).ConfigureAwait(false);
                    await recheck(ct).ConfigureAwait(false);
                    var originalPolicy = await RequireMailboxIssuerCurrentAsync(route, fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
                    entry = ProtectedDid2MailboxGrantJournal.Pending(seed, route, request, originalPolicy, networkId);
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
                var request = await DeepIdV2MailboxGrantRequestAuthor.RestoreDepositAsync(route, locator,
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
                    // The request was current before dispatch; a delayed exact
                    // reply may outlive that envelope, never the actual grant.
                    var verified = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route, request.ExactXmg2,
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

    private static async Task<VerifiedMailboxAuthorityV2> RequireMailboxIssuerCurrentAsync(VerifiedDeepIdV2ContactRouteClosure route,
        ReadOnlyMemory<byte> exactPma2, CancellationToken ct)
    {
        var time = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var policy = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, exactPma2.Span,
            time.LowerUnixSeconds, time.UpperUnixSeconds);
        if (!policy.BindsProjection(route.Route.Projection.CanonicalBytes.Span))
            throw new CryptographicException("Owned mailbox acquisition has no current root-authorized issuer policy.");
        ct.ThrowIfCancellationRequested(); return policy;
    }

    // Independent current own proof/time: this never restores an expired XMG
    // or requires the old route/issuer to be current just to close uncertainty.
    internal async Task<int> CloseExpiredMailboxAcquisitionsAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(first.SampleSeconds - fresh.Proof.MonotonicSample));
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null, adopted = null;
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Original acquisition custody is absent; no settlement repair is permitted.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var count = 0;
            foreach (var pair in state.Selections.ToArray())
            {
                if (pair.Value.Pending is not { } name) continue;
                var pending = state.Entries[name];
                if (ProtectedDid2MailboxGrantJournal.HasWinner(pending) || lower < ProtectedDid2MailboxGrantJournal.RequestExpiry(pending)) continue;
                var closed = ProtectedDid2MailboxGrantJournal.WithClosedUnresolved(pending, lower, networkId);
                state.Entries[name] = closed; CryptographicOperations.ZeroMemory(pending);
                ProtectedDid2MailboxGrantJournal.ClosePending(state, pair.Key); count++;
            }
            if (count == 0) { ct.ThrowIfCancellationRequested(); return 0; }
            state.Revision = checked(state.Revision + 1);
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeClosure);
#endif
            adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterClosure);
#endif
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            using var finalRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Closed mailbox acquisition custody disappeared.");
            if (!finalRoot.Use(bytes => FixedRoute(bytes, adopted)))
                throw new CryptographicException("Closed mailbox acquisition custody changed after read-back.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return count;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
            if (adopted is not null) CryptographicOperations.ZeroMemory(adopted);
        }
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
