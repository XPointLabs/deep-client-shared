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
    // DR-0133: historical local closure only. Captured page/ACK never enters
    // this producer. No issuer, signer, ingress, delete or original replay here.
    private async Task ReconcileExpiredUncapturedReadUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        byte[] instance, CancellationToken ct)
    {
        held.RequireOwner(lease); ct.ThrowIfCancellationRequested();
        using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Read recovery lost mandatory protected custody.");
        var snapshot = raw.Use(bytes => bytes.ToArray());
        byte[] grantsSnapshot = [], originalMau = [];
        try
        {
            using var read = ProtectedDid2MailboxReadJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            if (read.Closed.Count == 0 && (read.Active is null || read.Phase >= 3)) return;
            await RequireMailboxReadIntentCustodyUnderLeaseAsync(read, current, instance, held, ct).ConfigureAwait(false);
            using var grantsRaw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Read recovery lost original grant custody.");
            grantsSnapshot = grantsRaw.Use(bytes => bytes.ToArray());
            using var grants = ProtectedDid2MailboxGrantJournal.Decode(grantsSnapshot, networkId, current.AccountId.Span, instance);
            var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
            var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(first.SampleSeconds - fresh.Proof.MonotonicSample));
            var active = read.Phase is 1 or 2 ? read.Active : null;
            var activeEntry = active is null ? null : OriginalReadAcquisition(grants, active.Grant);
            var activeGrant = activeEntry is null ? null : MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(activeEntry).Span).Field(8).Span);
            var close = activeGrant is not null && lower >= activeGrant.ExpiresAtUnixSeconds;
            if (!close && read.Closed.Count == 0) return;
            if (close && (read.Closed.Count >= ProtectedDid2MailboxReadJournal.MaximumFloors ||
                read.Closed.ContainsKey(ProtectedDid2MailboxReadJournal.Name(active!.Grant))))
                throw new IOException("Closed Retrieve custody is full or contradicts active work; no eviction is permitted.");

            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(fresh.Network, fresh.Authority,
                fresh.MailboxAuthority.ExactPma2, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var fence = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForOwnerUnderLeaseAsync(
                storage, sqlStatePath, networkId, current.AccountId, instance, held, lease, ct).ConfigureAwait(false);
            foreach (var prior in read.Closed.Values)
            {
                if (lower < prior.ClosedAtLower) throw new CryptographicException("Closed Retrieve crossed protected time rollback.");
                var entry = OriginalReadAcquisition(grants, prior.Grant);
                var grant = await RequireOriginalReadFactsUnderLeaseAsync(current, held, source, fresh, host,
                    entry, prior.Grant, prior.Route, prior.Scope, prior.RetrieveBody, ct).ConfigureAwait(false);
                if (grant.ExpiresAtUnixSeconds != prior.GrantExpiry)
                    throw new CryptographicException("Closed Retrieve changed its original expiry.");
                var stored = await application.ReadTransportOutboxAsync(
                    VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                    OutboxLogicalId.FromBytes(prior.Phase == 3
                        ? MailboxAuthenticatedRequestTranscript.DecodeAckBody(MailboxAuthenticatedClientRequestCodec.Decode(prior.ExactMau).Binding.CanonicalRequest.Span).OperationId.Span
                        : MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(prior.RetrieveBody).OperationId.Span), ct).ConfigureAwait(false);
                RequireUncapturedReadSql(stored, prior.Phase, prior.ExactMau, prior.RetrieveBody,
                    prior.Grant, prior.Counter, prior.MauHash);
            }
            if (close)
            {
                var cycle = active!;
                var grant = await RequireOriginalReadFactsUnderLeaseAsync(current, held, source, fresh, host,
                    activeEntry!, cycle.Grant, cycle.Route, cycle.Scope, cycle.RetrieveBody, ct).ConfigureAwait(false);
                var stored = await application.ReadTransportOutboxAsync(
                    VerifiedCurrentMailboxGrant.AccountScopeForHolder(grant.HolderPublicKey.Span),
                    OutboxLogicalId.FromBytes(MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(cycle.RetrieveBody).OperationId.Span), ct).ConfigureAwait(false);
                if (stored.Item is not null)
                {
                    if (!ProtectedDid2MailboxGrantJournal.HasReservedReadIntent(activeEntry!))
                        throw new CryptographicException("Prepared original Retrieve lost its protected holder reservation.");
                    originalMau = stored.Item.GetCiphertextBundleCopy();
                    RequireUncapturedReadSql(stored, read.Phase, originalMau, cycle.RetrieveBody,
                        cycle.Grant, cycle.RetrieveCounter, cycle.RetrieveMauHash);
                    if (read.Phase == 1)
                    {
                        var frame = MailboxAuthenticatedClientRequestCodec.Decode(originalMau);
                        if (frame.Presentation.ReplayCounter != read.MinimumCounter(cycle.Grant))
                            throw new CryptographicException("Original SQL preparation does not advance its exact protected counter.");
                        cycle.AdoptPrepared(originalMau, ack: false);
                        read.Counters[ProtectedDid2MailboxReadJournal.Name(cycle.Grant)] = cycle.RetrieveCounter;
                        read.Phase = 2;
                        await RequireRecoveryGuards().ConfigureAwait(false);
                        await Save().ConfigureAwait(false); // Original local preparation, no signing or dispatch.
                    }
                }
                else RequireUncapturedReadSql(stored, read.Phase, [], cycle.RetrieveBody,
                    cycle.Grant, cycle.RetrieveCounter, cycle.RetrieveMauHash);
                var closed = ProtectedDid2MailboxReadJournal.ClosedAttempt.Capture(cycle, read.Phase,
                    grant.ExpiresAtUnixSeconds, lower, originalMau);
                read.Closed.Add(ProtectedDid2MailboxReadJournal.Name(closed.Grant), closed);
                read.Active = null; read.Phase = 0; cycle.Dispose();
                // Verify remaining capacity before closure can enable new issuance.
                var revision = read.Revision;
                byte[] candidate = [];
                try
                {
                    read.Revision = checked(revision + 1);
                    candidate = ProtectedDid2MailboxReadJournal.Encode(read, networkId, current.AccountId.Span, instance);
                    ProtectedDid2MailboxReadJournal.RequireRoomForNewCycle(candidate.Length);
                }
                finally { read.Revision = revision; CryptographicOperations.ZeroMemory(candidate); }
                await RequireRecoveryGuards().ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeReadClosure);
#endif
                await Save().ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterReadClosure);
#endif
            }
            await RequireRecoveryGuards().ConfigureAwait(false);

            async Task Save()
            {
                read.Revision = checked(read.Revision + 1);
                var next = await SaveMailboxReadJournalAsync(read, snapshot, current, instance, held, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = next;
            }
            async Task RequireRecoveryGuards()
            {
                var final = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                var currentLower = checked(fresh.Proof.TrustedLowerUnixSeconds + checked(final.SampleSeconds - fresh.Proof.MonotonicSample));
                if (currentLower < lower) throw new CryptographicException("Read recovery crossed protected time rollback.");
                var after = await SqliteDeepIdV2AccountGeneration.ReadNativeReplayFenceUnderLeaseAsync(
                    storage, lease, sqlStatePath, current, held, ct).ConfigureAwait(false);
                if (fence.Kind != after.Kind || !FixedRoute(fence.Selector.Span, after.Selector.Span) || !FixedRoute(fence.Digest.Span, after.Digest.Span))
                    throw new CryptographicException("Read recovery changed its native SQL fence.");
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantsSnapshot, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxReadJournal.Slot, snapshot, ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
        }
        finally
        {
            foreach (var bytes in new[] { snapshot, grantsSnapshot, originalMau }) CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static byte[] OriginalReadAcquisition(ProtectedDid2MailboxGrantJournal.State grants, ReadOnlySpan<byte> grantHash)
    {
        var hash = grantHash.ToArray();
        try
        {
            return grants.Entries.Values.SingleOrDefault(entry => ProtectedDid2MailboxGrantJournal.IsAdoptedWinner(entry) &&
                FixedRoute(SHA256.HashData(ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span), hash)) ??
                throw new CryptographicException("Original Retrieve lost its unique adopted grant.");
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    private async Task<MailboxAuthenticatedGrant> RequireOriginalReadFactsUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        VerifiedMailboxHostAuthorityV2 host, byte[] entry, ReadOnlyMemory<byte> grantHash,
        ReadOnlyMemory<byte> routeHash, ReadOnlyMemory<byte> scopeHash, ReadOnlyMemory<byte> body, CancellationToken ct)
    {
        using var publication = await OpenOwnRetainedPublicationUnderLeaseAsync(current, held, source, fresh, ct, routeHash).ConfigureAwait(false);
        var request = ContactCodec.Decode("XMG2", ProtectedDid2MailboxGrantJournal.Request(entry).Span);
        var route = publication.Route;
        var read = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(body.Span);
        var scope = ClientMailboxScope.Derive(route.ExactHash.Span, new(route.Reachability.Field(2).Span),
            BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span));
        if (!FixedRoute(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span, route.ExactBytes.Span) ||
            !FixedRoute(request.Field(3).Span, publication.Locator.Span) || !FixedRoute(request.Field(4).Span, publication.Capability.Span) ||
            !FixedRoute(route.ExactHash.Span, routeHash.Span) || !FixedRoute(scope.Value, scopeHash.Span) ||
            read.Epoch != BinaryPrimitives.ReadUInt64BigEndian(route.Selection.Field(4).Span) ||
            !FixedRoute(read.MailboxId.Bytes.Span, route.Reachability.Field(2).Span) ||
            !FixedRoute(read.PlacementId.Bytes.Span, route.Reachability.Field(10).Span))
            throw new CryptographicException("Original Retrieve lost actual private publication/body custody.");
        using var signer = ReachabilityMailboxHolderAuthority.OpenRetainedRead(route, networkId, publication.Locator,
            publication.Capability, ProtectedDid2MailboxGrantJournal.Seed(entry), publication.RecheckAsync);
        if (!FixedRoute(signer.Ed25519PublicKey.Span, request.Field(5).Span))
            throw new CryptographicException("Original Retrieve lost actual holder seed custody.");
        await host.RequireOriginalRetainedReadGrantAsync(ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry),
            route.ExactBytes, request.CanonicalBytes, ProtectedDid2MailboxGrantJournal.Response(entry), ct).ConfigureAwait(false);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2",
            ProtectedDid2MailboxGrantJournal.Response(entry).Span).Field(8).Span);
        if (!FixedRoute(SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)), grantHash.Span))
            throw new CryptographicException("Original Retrieve changed its protected grant hash.");
        await publication.RecheckAsync(ct).ConfigureAwait(false); return grant;
    }

    private static void RequireUncapturedReadSql(TransportOutboxReadSnapshot stored, byte phase,
        ReadOnlySpan<byte> exactMau, ReadOnlySpan<byte> body, ReadOnlySpan<byte> grant, ulong counter, ReadOnlySpan<byte> mauHash)
    {
        if (stored.Result == TransportOutboxReadResult.Corrupt ||
            stored.Item is { State: TransportOutboxState.Durable or TransportOutboxState.Delivered })
            throw new CryptographicException("Original Retrieve has a captured/contradictory SQL outcome; ordinary reconciliation is required.");
        if (stored.Item is null)
        {
            if (stored.Result != TransportOutboxReadResult.Missing || phase != 1 || !exactMau.IsEmpty || counter != 0)
                throw new CryptographicException("Original prepared Retrieve lost its native SQL request.");
            return;
        }
        var actual = stored.Item.GetCiphertextBundleCopy();
        try
        {
            var frame = MailboxAuthenticatedClientRequestCodec.Decode(actual);
            if (stored.Result != TransportOutboxReadResult.Found || !FixedRoute(actual, exactMau) ||
                frame.Binding.Operation != (phase == 3 ? MailboxAuthenticatedOperation.Ack : MailboxAuthenticatedOperation.Retrieve) ||
                !FixedRoute(frame.Binding.CanonicalRequest.Span, phase == 3 ? MailboxAuthenticatedClientRequestCodec.Decode(exactMau).Binding.CanonicalRequest.Span : body) ||
                !FixedRoute(SHA256.HashData(MailboxAuthenticatedCapabilityCodec.EncodeGrant(frame.Presentation.Grant)), grant) ||
                !FixedRoute(stored.Item.DedupMaterial.Value, frame.Binding.RequestDigest.Span) ||
                phase >= 2 && (frame.Presentation.ReplayCounter != counter || !FixedRoute(SHA256.HashData(actual), mauHash)) ||
                !Sodium.PublicKeyAuth.VerifyDetached(frame.Presentation.HolderSignature.ToArray(),
                    MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(frame.Presentation), frame.Presentation.Grant.HolderPublicKey.ToArray()))
                throw new CryptographicException("Original Retrieve SQL differs from protected holder/body/counter custody.");
        }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }
}
