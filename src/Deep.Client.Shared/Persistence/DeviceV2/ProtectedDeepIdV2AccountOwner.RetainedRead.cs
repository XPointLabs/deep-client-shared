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
    private async Task<VerifiedMailboxRetainedReadGrantV2> AcquireRetainedMailboxReadUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnRetainedPublication publication,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        IDid2RetainedMailboxReadGrantTransport transport, CancellationToken ct)
    {
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null;
        try
        {
            using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected retained-read holder custody is absent; no repair is permitted.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var scope = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(publication.Route.ExactHash.Span,
                publication.Locator.Span, (byte)MailboxCapabilityDomain.Retrieve));
            var entry = ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(state, scope);
            if (entry is null)
            {
                if (state.Entries.Count >= ProtectedDid2MailboxGrantJournal.MaximumEntries)
                    throw new IOException("Protected retained-read holder custody is full.");
                var seed = NewRouteRandom32();
                try
                {
                    using var signer = ReachabilityMailboxHolderAuthority.OpenRetainedRead(publication.Route, networkId,
                        publication.Locator, publication.Capability, seed, publication.RecheckAsync);
                    var request = await publication.Host.AuthorRetainedReadRequestAsync(publication.Route.ExactBytes,
                        publication.Locator, publication.Capability, signer, ct).ConfigureAwait(false);
                    await publication.RecheckAsync(ct).ConfigureAwait(false);
                    entry = ProtectedDid2MailboxGrantJournal.PendingRetainedRead(seed, publication.Route,
                        request, fresh.MailboxAuthority, networkId);
                    ProtectedDid2MailboxGrantJournal.AddPending(state, entry);
                    state.Revision = checked(state.Revision + 1);
                    var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                finally { CryptographicOperations.ZeroMemory(seed); }
            }
            var ownedRequest = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
            if (!FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span, publication.Route.ExactBytes.Span) ||
                !FixedRoute(ownedRequest.Field(4).Span, publication.Capability.Span))
                throw new CryptographicException("Retained acquisition differs from this publication's exact private custody.");
            if (!ProtectedDid2MailboxGrantJournal.HasWinner(entry))
            {
                using var signer = ReachabilityMailboxHolderAuthority.OpenRetainedRead(publication.Route, networkId,
                    publication.Locator, publication.Capability, ProtectedDid2MailboxGrantJournal.Seed(entry), publication.RecheckAsync);
                var request = await publication.Host.RestoreRetainedReadRequestAsync(publication.Route.ExactBytes,
                    publication.Locator, publication.Capability, signer.Ed25519PublicKey,
                    ProtectedDid2MailboxGrantJournal.Request(entry), ct).ConfigureAwait(false);
                await publication.RecheckAsync(ct).ConfigureAwait(false);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, deadline.Token).ConfigureAwait(false);
                var dispatch = new Did2OwnedContactTransportContext(custody, fresh.Network, held);
                var response = await transport.AcquireRetainedReadAsync(request, dispatch, deadline.Token).AsTask()
                    .WaitAsync(deadline.Token).ConfigureAwait(false);
                if (response.Length != 510) throw new InvalidDataException("Retained-read result exceeds its exact bound.");
                var verified = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                    request.ExactXmg2, response, deadline.Token).ConfigureAwait(false);
                await publication.RecheckAsync(deadline.Token).ConfigureAwait(false);
                var next = ProtectedDid2MailboxGrantJournal.WithWinner(entry, verified.ExactXmc2.Span, networkId);
                state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(entry)] = next;
                CryptographicOperations.ZeroMemory(entry); entry = next;
                state.Revision = checked(state.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(state, snapshot, current.AccountId, instance, deadline.Token).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
            }
            using var receivedRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Retained-read winner disappeared before read-back.");
            if (!receivedRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Retained-read custody changed before read-back.");
            using var received = ProtectedDid2MailboxGrantJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var winner = ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(received, scope);
            if (winner is null || !ProtectedDid2MailboxGrantJournal.HasWinner(winner) || !FixedRoute(winner, entry))
                throw new CryptographicException("Retained-read winner differs from its protected original acquisition.");
            var result = await publication.Host.VerifyRetainedReadSuccessAsync(publication.Route.ExactBytes,
                ProtectedDid2MailboxGrantJournal.Request(winner), ProtectedDid2MailboxGrantJournal.Response(winner), ct).ConfigureAwait(false);
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            if (received.Selections[scope].Current is null)
            {
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeSelection);
#endif
                ProtectedDid2MailboxGrantJournal.PromoteWinner(received, scope);
                received.Revision = checked(received.Revision + 1);
                var adopted = await SaveMailboxGrantJournalAsync(received, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
            }
            await publication.RecheckAsync(ct).ConfigureAwait(false);
            await result.EnsureCurrentAsync(ct).ConfigureAwait(false);
            using var installed = await OpenRetainedMailboxWinnerUnderLeaseAsync(current, held, publication,
                result, winner, source, fresh, ct).ConfigureAwait(false);
            using var finalRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Retained-read selection disappeared.");
            if (!finalRoot.Use(bytes => FixedRoute(bytes, snapshot)))
                throw new CryptographicException("Retained-read selection changed after verification.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
        }
    }

    // The only provenance of these original facts is the actual private phase7
    // journal, bound to the current account instance and permanent intent.
    // Decoding old signatures never makes them current admission authority.
    private async Task<OwnRetainedPublication> OpenOwnRetainedPublicationUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        CancellationToken ct)
    {
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(fresh.Network, fresh.Authority,
            fresh.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null, capability = null;
        try
        {
            var plan = CreatePermanentContactPlan(current, instance);
            using var root = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Original publication custody is absent; retained reading cannot repair it.");
            snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            if (!state.Entries.TryGetValue(Convert.ToHexString(plan.Intent.Span), out var entry) ||
                entry.Phase != 7 || entry.Kind != 1 || !entry.Matches(Did2OwnedPermanentContactPlan.Configuration()))
                throw new CryptographicException("Retained reading requires this account's exact completed permanent publication.");
            var contact = DeepIdV2ResolverClosureCodec.Decode(entry.Record(7).Span);
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Decode(entry.Record(0).Span);
            if (!FixedRoute(contact.Bundle.Field(23).Span, checkpoint.Binding.DeepId.CanonicalBytes.Span) ||
                !checkpoint.Binding.Identity.ActiveDevices.Any(device =>
                    FixedRoute(device.Certificate.DeviceId.Span, dca.PublisherDeviceId.Span)))
                throw new CryptographicException("Original publication is not owned by the current exact account/device.");
            var permanent = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, current.AccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.DeepId, ct).ConfigureAwait(false);
            var resolver = permanent.ResolverReadCapability.ToArray();
            try
            {
                if (!checkpoint.Binding.DeepId.MatchesResolverReadCapability(resolver))
                    throw new CryptographicException("Original resolver capability is not in this account's protected custody.");
            }
            finally { CryptographicOperations.ZeroMemory(resolver); }
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            var publication = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
            var original = ContactRouteClosureCodec.Decode(entry.Record(6).Span);
            var xpu = Xpu1Codec.Decode(publication.ExactXpu1.Span);
            capability = request.OwnerRetrieveCapability.ToArray();
            if (FixedRoute(capability, original.Reachability.Field(10).Span))
                throw new CryptographicException("Public Deposit capability cannot become retained owner custody.");
            var captured = snapshot;
            async Task RecheckCustody(CancellationToken token)
            {
                held.RequireActive(); token.ThrowIfCancellationRequested();
                using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, token).ConfigureAwait(false) ??
                    throw new CryptographicException("Original publication disappeared during retained reading.");
                if (!readback.Use(bytes => FixedRoute(bytes, captured)))
                    throw new CryptographicException("Original publication changed during retained reading.");
                token.ThrowIfCancellationRequested(); held.RequireActive();
            }
            async Task Recheck(CancellationToken token)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, token).ConfigureAwait(false);
                await host.EnsureCurrentAsync(token).ConfigureAwait(false);
                await RecheckCustody(token).ConfigureAwait(false);
            }
            await Recheck(ct).ConfigureAwait(false);
            var result = new OwnRetainedPublication(original, host, xpu.LocatorHash.ToArray(), capability, captured, Recheck, RecheckCustody);
            snapshot = null; capability = null; return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
            if (capability is not null) CryptographicOperations.ZeroMemory(capability);
        }
    }

    private sealed class OwnRetainedPublication : IDisposable
    {
        private readonly byte[] locator, capability, root;
        private readonly Func<CancellationToken, Task> recheck;
        private readonly Func<CancellationToken, Task> recheckCustody;
        private bool disposed;
        internal OwnRetainedPublication(ParsedContactRouteClosure route, VerifiedMailboxHostAuthorityV2 host,
            byte[] locator, byte[] capability, byte[] root, Func<CancellationToken, Task> recheck,
            Func<CancellationToken, Task> recheckCustody)
        { Route = route; Host = host; this.locator = locator; this.capability = capability; this.root = root; this.recheck = recheck; this.recheckCustody = recheckCustody; }
        internal ParsedContactRouteClosure Route { get; }
        internal VerifiedMailboxHostAuthorityV2 Host { get; }
        internal ReadOnlyMemory<byte> Locator { get { RequireActive(); return locator; } }
        internal ReadOnlyMemory<byte> Capability { get { RequireActive(); return capability; } }
        internal Task RecheckAsync(CancellationToken ct) { RequireActive(); return recheck(ct); }
        internal Task RecheckCustodyAsync(CancellationToken ct) { RequireActive(); return recheckCustody(ct); }
        private void RequireActive() => ObjectDisposedException.ThrowIf(disposed, this);
        public void Dispose()
        {
            if (disposed) return; disposed = true;
            CryptographicOperations.ZeroMemory(locator); CryptographicOperations.ZeroMemory(capability); CryptographicOperations.ZeroMemory(root);
        }
    }
}
