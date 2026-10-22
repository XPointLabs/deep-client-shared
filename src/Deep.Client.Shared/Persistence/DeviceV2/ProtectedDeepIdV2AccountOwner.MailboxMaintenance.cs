using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    // New business work only, under its actual account lease. Selection is a
    // hint; every effect uses the existing dependency-closed owned producer.
    // No nested lease, new worker, repaired floor or generic exception swallowing.
    private async Task MaintainMailboxNamespacesUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            // An exact active read/ACK bypasses all new-work maintenance,
            // including pending-acquisition disposition. A lost issuer reply
            // with no active read can close only under fresh authenticated lower
            // time; this preserves uncertainty, not non-issuance or reissue.
            using (var readRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Namespace maintenance lost mandatory read custody."))
            using (var reads = readRoot.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, current.AccountId.Span, instance)))
                if (reads.Active is not null || reads.Phase != 0) return;
            _ = await CloseExpiredMailboxAcquisitionsUnderLeaseAsync(current, held, source, fresh, ct).ConfigureAwait(false);
            await MaintainRetainedMailboxAcquisitionsUnderLeaseAsync(current, held, instance, source, fresh, ct).ConfigureAwait(false);
            await SealInactiveMailboxAcquisitionsUnderLeaseAsync(current, held, instance, source, fresh, ct).ConfigureAwait(false);

            // One dependency-closed namespace pair per business call, not32
            // separate plans borrowing the same short directory freshness.
            // Subsequent calls resume ordinary bounded maintenance.
            for (var batch = 0; batch < 1; batch++)
            {
                using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                    throw new InvalidDataException("Namespace maintenance lost mandatory grant custody.");
                using var grants = raw.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
                if (grants.Entries.Count == 0) return;
                var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(fresh.Network, fresh.Authority,
                    fresh.MailboxAuthority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                if (grants.Entries.Values.All(entry => BinaryPrimitives.ReadUInt64BigEndian(
                    ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).Projection.Field(6).Span) >= host.SelectionEpoch)) return;
                var elapsed = checked(reading.SampleSeconds - fresh.Proof.MonotonicSample);
                var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + elapsed);
                var upper = checked(fresh.Proof.TrustedUpperUnixSeconds + elapsed);
                using var sendsRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var sends = sendsRaw.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
                using var readRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
                using var reads = readRaw.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
                if (reads.Active is not null || reads.Phase != 0) return; // Exact active read/ACK is never a maintenance entry.
                if (await MaintainArchivedMailboxPathUnderLeaseAsync(current, held, instance, source, fresh,
                    grants, sends, reads, host.SelectionEpoch, lower, ct).ConfigureAwait(false)) continue;
                var progressed = false;
                foreach (var pair in grants.Entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
                {
                    ct.ThrowIfCancellationRequested();
                    var entry = pair.Value;
                    var route = ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span);
                    if (BinaryPrimitives.ReadUInt64BigEndian(route.Projection.Field(6).Span) >= host.SelectionEpoch ||
                        lower < ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry)) continue;
                    var domain = (MailboxCapabilityDomain)ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span).Field(6).Span[0];
                    var acquisition = Convert.FromHexString(pair.Key);
                    try
                    {
                        var known = entry[96] is 2 or 5 && ProtectedDid2MailboxGrantJournal.HasWinner(entry);
                        // Structural eligibility, not authorization. Pending,
                        // unresolved/intervening chains and current Retrieve stay pinned.
                        try
                        {
                            if (known && domain == MailboxCapabilityDomain.Deposit)
                                ProtectedDid2MailboxGrantJournal.RequireOldestAdoptedDeposit(grants, acquisition);
                            else if (known && domain == MailboxCapabilityDomain.Retrieve)
                                ProtectedDid2MailboxGrantJournal.RequireSupersededRetrieve(grants, acquisition);
                            else if (domain == MailboxCapabilityDomain.Deposit)
                            { var scope = RequireUnusedClosedDeposit(grants, acquisition); CryptographicOperations.ZeroMemory(scope); }
                            else if (domain == MailboxCapabilityDomain.Retrieve)
                            { var scope = RequireUnusedClosedRetrieve(grants, acquisition); CryptographicOperations.ZeroMemory(scope); }
                            else continue;
                        }
                        catch (IOException) { continue; } // Only the pure structural selector can return pinned.
                        if (known && domain == MailboxCapabilityDomain.Retrieve)
                        {
                            var replacement = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants,
                                Convert.ToHexString(entry.AsSpan(0, 32)))!;
                            var replacementGrant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                                ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(replacement).Span).Field(8).Span);
                            var issuer = fresh.MailboxAuthority.ResolveIssuer(MailboxCapabilityDomain.Retrieve);
                            // Eligibility only, NEVER retirement authority.
                            // An expired/old-policy replacement stays pinned
                            // while normal new-read renewal can proceed if
                            // capacity permits. No floor or holder effect here.
                            if (replacementGrant.Lifecycle != MailboxCapabilityLifecycle.Active ||
                                replacementGrant.Generation < fresh.MailboxAuthority.MinimumGrantGeneration ||
                                !FixedRoute(replacementGrant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
                                replacementGrant.NotBeforeUnixSeconds < issuer.ValidFromUnixSeconds ||
                                lower < replacementGrant.NotBeforeUnixSeconds ||
                                upper >= Math.Min(replacementGrant.ExpiresAtUnixSeconds,
                                    Math.Min(fresh.MailboxAuthority.ExpiresAtUnixSeconds, fresh.Network.MaximumRecordExpiryUnixSeconds)))
                                continue;
                        }
                        using var exclusion = await MailboxEpochExclusion.OpenUnderLeaseAsync(this, current, held,
                            source, fresh, acquisition, ct).ConfigureAwait(false);
                        var dependencies = await exclusion.CaptureRetirementDependenciesAsync(ct).ConfigureAwait(false);
                        const MailboxEpochExclusion.RetirementDependency depositAllowed =
                            MailboxEpochExclusion.RetirementDependency.AcquisitionChain |
                            MailboxEpochExclusion.RetirementDependency.SendFloor |
                            MailboxEpochExclusion.RetirementDependency.UnresolvedReceiptOrObject;
                        const MailboxEpochExclusion.RetirementDependency retrieveAllowed =
                            MailboxEpochExclusion.RetirementDependency.AcquisitionChain |
                            MailboxEpochExclusion.RetirementDependency.ReadFloor |
                            MailboxEpochExclusion.RetirementDependency.ReadTraversal |
                            MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath |
                            MailboxEpochExclusion.RetirementDependency.UnresolvedReceiptOrObject;
                        var unusedRetrieveAllowed = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants,
                            Convert.ToHexString(entry.AsSpan(0, 32))) is null
                            ? MailboxEpochExclusion.RetirementDependency.RetainedRetrievePath
                            : retrieveAllowed & ~MailboxEpochExclusion.RetirementDependency.ReadFloor;
                        var allowed = known ? domain == MailboxCapabilityDomain.Deposit ? depositAllowed : retrieveAllowed :
                            domain == MailboxCapabilityDomain.Deposit ? MailboxEpochExclusion.RetirementDependency.None : unusedRetrieveAllowed;
                        if ((dependencies.Dependencies & ~allowed) != MailboxEpochExclusion.RetirementDependency.None) continue;
                        if (!known)
                        {
                            if (domain == MailboxCapabilityDomain.Deposit)
                                await exclusion.RetireUnusedClosedDepositAcquisitionAsync(ct).ConfigureAwait(false);
                            else await exclusion.RetireUnusedClosedRetrieveAcquisitionAsync(ct).ConfigureAwait(false);
                        }
                        else
                        {
                            var exactGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8);
                            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
                                sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
                            if (domain == MailboxCapabilityDomain.Retrieve)
                            {
                                var replacement = ProtectedDid2MailboxGrantJournal.CurrentWinner(grants,
                                    Convert.ToHexString(entry.AsSpan(0, 32)))!;
                                var replacementGrant = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(replacement).Span).Field(8);
                                // Both used and never-used old holders retain
                                // their path until a real replacement read completes.
                                if (!await application.HasOriginalGrantTransportWorkForMaintenanceAsync(replacementGrant, ct).ConfigureAwait(false)) continue;
                            }
                            if (!await application.HasOriginalGrantTransportWorkForMaintenanceAsync(exactGrant, ct).ConfigureAwait(false))
                            {
                                // Do not retire a counter first: a genuine
                                // unused winner has none. Missing SQL for used
                                // native work must reject before any plan effect.
                                if (domain == MailboxCapabilityDomain.Deposit)
                                    await exclusion.RetireUnusedAdoptedDepositAcquisitionAsync(verifier, ct).ConfigureAwait(false);
                                else await exclusion.RetireUnusedAdoptedRetrieveAcquisitionAsync(verifier, ct).ConfigureAwait(false);
                                progressed = true; break;
                            }
                            if (domain == MailboxCapabilityDomain.Retrieve && !ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(entry))
                                throw new CryptographicException("Original SQL read lost its protected read-intent custody before counter retirement.");
                            var hash = SHA256.HashData(exactGrant.Span);
                            try
                            {
                                var hasFloor = domain == MailboxCapabilityDomain.Deposit
                                    ? sends.Floors.Values.Any(floor => FixedRoute(floor.GrantHash, hash))
                                    : reads.Counters.ContainsKey(Convert.ToHexString(hash));
                                if (hasFloor) await exclusion.RetireIdleMailboxCounterFloorAsync(ct).ConfigureAwait(false);
                            }
                            finally { CryptographicOperations.ZeroMemory(hash); }
                            // No catch after selection or a plan effect. IO,
                            // corruption, cancellation and fault injection stop
                            // new authoring; any staged plan owns cold recovery.
                            if (domain == MailboxCapabilityDomain.Deposit)
                                await exclusion.RetireUsedDepositAcquisitionAsync(verifier, ct).ConfigureAwait(false);
                            else await exclusion.RetireSupersededRetrieveAcquisitionAsync(verifier, ct).ConfigureAwait(false);
                        }
                        progressed = true; break; // Read all actual roots again after one ordered transition.
                    }
                    finally { CryptographicOperations.ZeroMemory(acquisition); }
                }
                if (!progressed) return;
            }
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    // Candidate selection only. The joint owner independently reopens the
    // original publication, every holder, completed read/ACK and actual native
    // exclusion before staging its existing three-root/application-SQL plan.
    private async Task<bool> MaintainArchivedMailboxPathUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> instance,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ProtectedDid2MailboxGrantJournal.State grants, ProtectedDid2MailboxSendJournal.State sends,
        ProtectedDid2MailboxReadJournal.State reads, ulong epoch, ulong lower, CancellationToken ct)
    {
        held.RequireOwner(lease);
        using var publicationRaw = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Archived-path maintenance lost publication custody.");
        using var publications = publicationRaw.Use(bytes => ProtectedDid2ContactRouteJournal.Decode(bytes,
            networkId, current.AccountId.Span, instance.Span));
        var main = Convert.ToHexString(CreatePermanentContactPlan(current, instance.Span).Intent.Span);
        if (!publications.Entries.TryGetValue(main, out var active) || active.Phase != 7 || active.Kind != 1 ||
            publications.Entries.Values.Any(entry => entry.Phase != 7)) return false;
        using var ordinaryRaw = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var ordinary = ordinaryRaw.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
        using var assetRaw = await storage.ReadOwnedAsync(ProtectedDid2AttachmentJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException();
        using var assets = assetRaw.Use(bytes => ProtectedDid2AttachmentJournal.Decode(bytes, networkId, current.AccountId.Span, instance.Span));
        if (ordinary.Entries.Count != 0 || assets.Entries.Count != 0) return false;
        foreach (var pair in publications.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (pair.Key == main || pair.Value.Kind != 1) continue;
            var route = ContactRouteClosureCodec.Decode(pair.Value.Record(6).Span);
            if (BinaryPrimitives.ReadUInt64BigEndian(route.Projection.Field(6).Span) >= epoch ||
                lower < checked(BinaryPrimitives.ReadUInt64BigEndian(route.Authorization.Field(13).Span) +
                    (ulong)MailboxClientLimits.MaximumTtlSeconds) ||
                sends.Entries.Values.Any(entry => FixedRoute(entry.RouteHash, route.ExactHash.Span)) ||
                reads.Closed.Values.Any(closed => FixedRoute(closed.Route, route.ExactHash.Span))) continue;
            List<byte[]> selected;
            try { selected = RequireArchivedPathGrants(grants, route.ExactHash.Span); }
            catch (IOException) { continue; } // Pure structural pins only, never an effect failure.
            if (selected.Any(entry => lower < ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry)) ||
                !reads.Traversals.ContainsKey(Convert.ToHexString(ArchivedPathReadScope(route).Value))) continue;
            var exactGrants = selected.Select(entry => ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8)).ToArray();
            if (exactGrants.Any(grant => !reads.Counters.TryGetValue(Convert.ToHexString(SHA256.HashData(grant.Span)), out var counter) || counter == 0)) continue;
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(storage,
                sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
            var hasCoverage = true;
            foreach (var grant in exactGrants)
                if (!await application.HasOriginalGrantTransportWorkForMaintenanceAsync(grant, ct).ConfigureAwait(false)) { hasCoverage = false; break; }
            if (!hasCoverage) continue; // No SQL is not settlement or deletion permission.
            var acquisition = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(selected[0]));
            try
            {
                using var exclusion = await MailboxEpochExclusion.OpenUnderLeaseAsync(this, current, held,
                    source, fresh, acquisition, ct).ConfigureAwait(false);
                await exclusion.RetireArchivedReadPathAsync(ct).ConfigureAwait(false);
                return true; // Caller reopens all actual roots before another selection.
            }
            finally { CryptographicOperations.ZeroMemory(acquisition); }
        }
        return false;
    }
}
