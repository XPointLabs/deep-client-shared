using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal Task<ClientMailboxStoreResult> DeliverMessagingAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct) =>
        DeliverOwnedMailboxAsync(unixSeconds, verifier, scope, operation, ReadOnlyMemory<byte>.Empty,
            source, null, own, peer, grants, transport, ct);

    internal async Task<Did2MessagingSessionScope> FindOutgoingInitialMessagingScopeAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var source = await SqliteDeepIdV2AccountGeneration.OpenExistingMessagingSenderSourceUnderLeaseAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
        using var retained = await source.ReadMessagingSourceByIntentUnderLeaseAsync(intent, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        try
        {
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, networkId, current.AccountId.Span, instance).ReadAsync(ct).ConfigureAwait(false);
            var scope = catalog.FindSource(retained.SessionId.Span, SHA256.HashData(retained.CanonicalSpan)) ??
                throw new CryptographicException("Initial dispatch requires the actual initialized sender catalog.");
            var index = catalog.FindExact(scope);
            if (index < 0 || catalog.Phase(index) != 2 || retained.HasInitialState)
                throw new CryptographicException("Initial dispatch cannot precede completed source transfer/retirement.");
            Did2MessagingSourceScope.RequireSender(scope, retained);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
            if (floor.Status != 1) throw new CryptographicException("Initial dispatch requires active mutable custody.");
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return scope;
        }
        finally { CryptographicOperations.ZeroMemory(instance); }
    }

    internal Task<ClientMailboxStoreResult> DeliverInitialAsync(ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        Did2MessagingSessionScope scope, ReadOnlyMemory<byte> intent, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent.Span);
        return DeliverOwnedMailboxAsync(unixSeconds, verifier, scope, InitialMailboxOperation(intent.Span), intent,
            source, resolved, null, null, grants, transport, ct);
    }

    internal static byte[] InitialMailboxOperation(ReadOnlySpan<byte> intent)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(intent);
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        digest.AppendData("Deep/Local/DID2/InitialMailboxIntent/1"u8); digest.AppendData([0]); digest.AppendData(intent);
        return digest.GetHashAndReset();
    }

    private async Task<byte[]> ReadOwnedMailboxEnvelopeUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        Did2MessagingSessionScope scope, OwnedDid2MessagingStorage opened, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> initialIntent, CancellationToken ct)
    {
        var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
        if (floor.Status != 1) throw new CryptographicException("Mailbox Store requires stable active messaging custody.");
        if (!initialIntent.IsEmpty)
        {
            using var source = await SqliteDeepIdV2AccountGeneration.OpenExistingMessagingSenderSourceUnderLeaseAsync(storage, sqlStatePath, current, ct).ConfigureAwait(false);
            using var retained = await source.ReadMessagingSourceByIntentUnderLeaseAsync(initialIntent, ct).ConfigureAwait(false);
            Did2MessagingSourceScope.RequireSender(scope, retained);
            if (retained.HasInitialState || !FixedRoute(InitialMailboxOperation(initialIntent.Span), operation.Span))
                throw new CryptographicException("Initial Store differs from the actual retired sender intent.");
            return retained.ExactDph2.ToArray();
        }
        using var sent = opened.Sql.ReadVerifiedOperation(floor, operation.Span) ?? throw new CryptographicException("Only an actual committed owned message can be dispatched.");
        if (sent.Direction != 1) throw new CryptographicException("A receive row cannot authorize mailbox Store.");
        return sent.ExactEnvelope.ToArray();
    }

    private async Task<ClientMailboxStoreResult> DeliverOwnedMailboxAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        ReadOnlyMemory<byte> initialIntent, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority? resolved,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority? ordinaryOwn,
        VerifiedDeepIdV2DirectoryFreshness? ordinaryPeer,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var op = operation.ToArray(); byte[] snapshot = [], grantRoot = [], instance = [], exactMau = [], envelopeBytes = [];
        try
        {
            using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
            using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
            var contact = resolved is not null
                ? await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false) : default;
            var fresh = resolved?.Own ?? ordinaryOwn ?? throw new CryptographicException("Ordinary dispatch has no current owned endpoint.");
            var peer = resolved is not null ? contact.Contact.Authorization.Freshness : ordinaryPeer ??
                throw new CryptographicException("Ordinary dispatch has no independently current session peer.");
            var first = await RequireMessagingFreshnessAsync(current, fresh, peer, source, held, ct).ConfigureAwait(false);
            OwnedInitialMessagingSeed.RequireFreshScope(scope, fresh.Proof, peer, first);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, sqlStatePath, current, scope, ct).ConfigureAwait(false);
            var privateContact = resolved is null
                ? await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, fresh, peer, source, held, ct).ConfigureAwait(false) : null;
            var route = privateContact?.Route ?? contact.Contact.Route;
            envelopeBytes = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, initialIntent, ct).ConfigureAwait(false);
            var locator = privateContact?.LocatorHash ?? contact.Contact.Candidate.Request.LocatorHash;
            var capability = route.Route.Reachability.Field(10);
            // Acquiring a grant persists holder custody and can cause remote
            // issuance. Reject absent/full or changed attempt custody first.
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            var routeHash = SHA256.HashData(route.ExactRouteClosure.Span);
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Protected send custody is absent; explicit reset is required."))
                snapshot = root.Use(bytes => bytes.ToArray());
            using var sends = ProtectedDid2MailboxSendJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, op));
            sends.Entries.TryGetValue(name, out var entry);
            if (entry is null && sends.Entries.Count >= ProtectedDid2MailboxSendJournal.MaximumEntries)
                throw new IOException("Resume the pending protected mailbox request or perform verified rollover.");
            if (entry is not null && (!FixedRoute(entry.RouteHash, routeHash) ||
                !FixedRoute(entry.EnvelopeHash, SHA256.HashData(envelopeBytes))))
                throw new CryptographicException("An exact owned send cannot acquire a replacement route or ciphertext.");
            await RequireMailboxSendFloorCapacityUnderLeaseAsync(sends, routeHash, locator,
                entry is null ? null : entry.GrantHash.ToArray(), current, instance, held, ct).ConfigureAwait(false);
            async Task Recheck(CancellationToken token)
            {
                await RequireFinalMessagingFreshnessAsync(current, scope, fresh, peer, source, held, first, token).ConfigureAwait(false);
                if (resolved is not null)
                    await RequireClaimContactTimeAsync(current, source, resolved, held, contact.Contact, contact.Time, token).ConfigureAwait(false);
                else
                {
                    var retainedRoute = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, fresh, peer, source, held, token).ConfigureAwait(false);
                    if (!FixedRoute(retainedRoute.Package.ExactBytes.Span, privateContact!.Package.ExactBytes.Span))
                        throw new CryptographicException("The authenticated peer mailbox route changed during this exact dispatch.");
                }
                var retained = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, initialIntent, token).ConfigureAwait(false);
                try
                {
                    if (!FixedRoute(retained, envelopeBytes)) throw new CryptographicException("The committed send changed during dispatch.");
                }
                finally { CryptographicOperations.ZeroMemory(retained); }
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, token).ConfigureAwait(false);
            }
            var winner = entry is null
                ? await AcquireMailboxGrantUnderLeaseAsync(current, held, source, fresh, route, locator,
                    capability, MailboxCapabilityDomain.Deposit, Recheck, grants, ct).ConfigureAwait(false)
                : null;
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Protected grant custody disappeared."))
                grantRoot = root.Use(bytes => bytes.ToArray());
            using var grantState = ProtectedDid2MailboxGrantJournal.Decode(grantRoot, networkId, current.AccountId.Span, instance);
            var grantName = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(routeHash, locator.Span, (byte)MailboxCapabilityDomain.Deposit));
            var retainedGrant = entry is not null
                ? ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(grantState, grantName, entry.GrantHash)
                : ProtectedDid2MailboxGrantJournal.CurrentWinner(grantState, grantName) ??
                    throw new CryptographicException("Dispatch has no selected protected grant winner.");
            if (winner is not null && !FixedRoute(ProtectedDid2MailboxGrantJournal.Response(retainedGrant).Span, winner.ExactXmc2.Span))
                throw new CryptographicException("Dispatch changed its acquired winner.");
            winner ??= await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route,
                ProtectedDid2MailboxGrantJournal.Request(retainedGrant), ProtectedDid2MailboxGrantJournal.Response(retainedGrant),
                fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
            var grantHash = SHA256.HashData(winner.ExactGrant.Span);
            using var loan = await OpenMailboxWinnerUnderLeaseAsync(current, held, route, winner, locator, capability,
                retainedGrant, source, fresh, Recheck, ct).ConfigureAwait(false);
            if (entry is null && sends.Entries.Values.Any(value => !value.Prepared && FixedRoute(value.GrantHash, grantHash)))
                throw new IOException("Resume the pending protected mailbox request or perform verified rollover.");
            var created = entry?.Created ?? loan.Authority.NowUnixSeconds;
            var expiry = entry?.Expires ?? Math.Min(loan.Grant.ExpiresAtUnixSeconds, checked(created + MailboxClientLimits.MaximumTtlSeconds));
            var ciphertext = envelopeBytes.ToArray();
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = loan.Grant.Epoch,
                MailboxId = loan.Route.MailboxId,
                PlacementId = loan.Route.PlacementId,
                OperationId = MailboxSendOperation(scope, op, envelopeBytes),
                DeduplicationDigest = SHA256.HashData(envelopeBytes),
                CreatedAtUnixSeconds = created,
                ExpiresAtUnixSeconds = expiry,
                Ciphertext = ciphertext
            };
            try
            {
                using var candidate = ProtectedDid2MailboxSendJournal.Entry.Pending(scope, op, grantHash, routeHash, envelope);
                if (entry is null)
                {
                    sends.EnrollGrant(loan.Grant);
                    entry = ProtectedDid2MailboxSendJournal.Entry.Decode(candidate.Exact); sends.Entries.Add(name, entry);
                    sends.Revision = checked(sends.Revision + 1);
                    var adopted = await SaveMailboxSendJournalAsync(sends, snapshot, current, instance, held, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
                }
                else if (!FixedRoute(entry.Exact[..256], candidate.Exact[..256]))
                    throw new CryptographicException("Mailbox retry changed its protected message, grant, route or original lifetime.");
                sends.RequireGrant(loan.Grant);
                loan.MinimumCounter = sends.MinimumCounter(grantHash);
                var existing = await loan.Store.ReadTransportOutboxAsync(loan.Selector.AccountScope,
                    OutboxLogicalId.FromBytes(envelope.OperationId.Span), ct).ConfigureAwait(false);
                if (entry.Prepared && existing is not { Result: TransportOutboxReadResult.Found, Item: not null })
                    throw new CryptographicException("Prepared protected MAU3 has no SQL request; regeneration is forbidden.");
                if (!entry.Prepared && existing.Item is { State: not TransportOutboxState.Prepared })
                    throw new CryptographicException("An uncommitted protected request cannot have a dispatched SQL attempt.");
                var factory = new MailboxAuthenticatedRequestFactory(loan.Store, loan.Authority);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeSql);
#endif
                var prepared = await factory.CreateStoreAsync(loan.Selector.AccountScope, loan.Selector, loan.Signer, envelope, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterSql);
#endif
                exactMau = prepared.GetCanonicalMau3Copy();
                var parsed = MailboxAuthenticatedClientRequestCodec.Decode(exactMau);
                RequireMailboxPreparedSend(entry, parsed, exactMau, winner);
                if (!entry.Prepared)
                {
                    if (parsed.Presentation.ReplayCounter < loan.MinimumCounter)
                        throw new CryptographicException("Mailbox SQL replay counter rolled back behind protected custody.");
                    var next = entry.WithPrepared(exactMau, parsed.Presentation.ReplayCounter);
                    sends.AdvanceCounter(grantHash, parsed.Presentation.ReplayCounter);
                    sends.Entries[name] = next; entry.Dispose(); entry = next; sends.Revision = checked(sends.Revision + 1);
#if DEEP_TEST_INTERNALS
                    Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforePreparedRoot);
#endif
                    var adopted = await SaveMailboxSendJournalAsync(sends, snapshot, current, instance, held, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                    Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterPreparedRoot);
#endif
                }
                await Recheck(ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, ct).ConfigureAwait(false);
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
                // Signing preparation is not renewed. This new dispatch-only
                // scope has no signer and cannot alter the original request.
                var dispatchStarted = Stopwatch.GetTimestamp();
                var dispatchTime = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                var dispatchPma = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, winner.ExactPma2.Span,
                    dispatchTime.LowerUnixSeconds, dispatchTime.UpperUnixSeconds);
                if (!dispatchPma.BindsProjection(route.Route.Projection.CanonicalBytes.Span))
                    throw new CryptographicException("Owned Store lost its current dispatch projection.");
                using var dispatchPolicy = new MailboxInstallationPolicy(held, route, dispatchPma, loan.Grant, dispatchTime, dispatchStarted);
                var dispatchAuthority = new VerifiedOfficialMailboxAuthority(dispatchPma.NetworkId, dispatchPma.MinimumGrantGeneration,
                    [dispatchPma.ResolveIssuer(loan.Grant.Domain)], false, static () => true, dispatchPolicy, dispatchPolicy.Clock);
                var dispatchFactory = new MailboxAuthenticatedRequestFactory(loan.Store, dispatchAuthority);
                var context = new Did2OwnedMailboxTransportContext(source, custody, current, fresh, held, route, winner);
                var decoder = new OwnedMailboxDecodePolicy(loan.Grant, dispatchAuthority);
                async Task Guard(CancellationToken token)
                {
                    dispatchPolicy.ValidateFreshness();
                    await context.RequireCurrentAsync(token).ConfigureAwait(false);
                    await Recheck(token).ConfigureAwait(false);
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, token).ConfigureAwait(false);
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, token).ConfigureAwait(false);
                    dispatchPolicy.ValidateFreshness(); held.RequireActive();
                }
                using var ingress = new OwnedStoreIngress(
                    transport.Create(context, decoder) ?? throw new InvalidOperationException("Owned mailbox transport is unavailable."),
                    exactMau, loan.Route, Guard);
                var adapter = new ClientMailboxAdapter(ClientFeatureFlags.ReleaseDefaults with { ClientMailboxAdapterEnabled = true },
                    new(true, loan.Selector.IssuerContext.Span, true), ingress, loan.Store, loan.Store, loan.Store, loan.Store,
                    new PinnedClientMailboxReceiptVerifier(new SodiumMailboxPeerReplicationCrypto()), dispatchFactory, decoder, dispatchAuthority.TimeProvider);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
                await Guard(deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeDispatch);
#endif
                try
                {
                    var result = await adapter.DispatchPreparedStoreAsync(loan.Selector.AccountScope, loan.Selector, prepared, deadline.Token)
                        .WaitAsync(deadline.Token).ConfigureAwait(false);
                    await Guard(deadline.Token).ConfigureAwait(false);
                    if (result.Cursor is null || result.Disposition is not (MailboxReplicaDisposition.Stored or MailboxReplicaDisposition.Duplicate))
                        throw new CryptographicException("Owned Store did not retain a verified durable storage result.");
                    if (initialIntent.IsEmpty)
                    {
#if DEEP_TEST_INTERNALS
                        Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeOrdinaryCompletion);
#endif
                        await RetainOrdinaryStoreCompletionUnderLeaseAsync(current, held, opened, scope, op, deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterOrdinaryCompletion);
#endif
                    }
                    return result;
                }
                catch (Exception error) when (ingress.Attempted && error is not ClientMailboxDispatchOutcomeUnknownException &&
                    error is CryptographicException or IOException or InvalidOperationException or OperationCanceledException)
                {
                    throw new ClientMailboxDispatchOutcomeUnknownException("Owned Store cannot confirm its outcome after dispatch; retain the exact request.", error);
                }
            }
            finally { CryptographicOperations.ZeroMemory(ciphertext); }
        }
        finally { foreach (var value in new[] { op, snapshot, grantRoot, instance, exactMau, envelopeBytes }) CryptographicOperations.ZeroMemory(value); }
    }

    // Capacity is checked before grant acquisition can enroll a holder or call
    // the issuer. A structural protected winner is only a capacity hint here;
    // the normal acquisition, signature, freshness and exact-grant checks still
    // run independently. A reader cannot enroll/repair an absent counter floor.
    private async Task RequireMailboxSendFloorCapacityUnderLeaseAsync(ProtectedDid2MailboxSendJournal.State sends,
        byte[] routeHash, ReadOnlyMemory<byte> locator, byte[]? originalGrant, VerifiedDeepIdV2CurrentAccount current,
        byte[] instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        if (sends.Floors.Count < ProtectedDid2MailboxSendJournal.MaximumFloors) return;
        held.RequireActive();
        using var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected grant custody is absent during replay-floor preflight.");
        using var state = root.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes, networkId, current.AccountId.Span, instance));
        var name = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(routeHash, locator.Span, (byte)MailboxCapabilityDomain.Deposit));
        var winner = originalGrant is not null
            ? ProtectedDid2MailboxGrantJournal.RequireRetainedWinner(state, name, originalGrant)
            : ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(state, name);
        if (winner is null || !ProtectedDid2MailboxGrantJournal.HasWinner(winner))
            throw new IOException("Protected mailbox replay floors are full; issuance cannot start.");
        var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(winner).Span);
        sends.RequireGrant(MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span));
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }

    private async Task<VerifiedDeepIdV2ContactMailboxRoute> ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive(); var scope = opened.Scope;
        using var pending = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
        var hello = pending.FirstApplicationDmc2; byte[]? accepted = null;
        try
        {
            ParsedDeepIdV2ContactMailboxRoute package;
            if (!scope.IsInitiator)
                package = ((ContactHelloDmc2Payload)ApplicationCoreCodec.DecodeDmc2(hello).ParsedPayload).MailboxRoute;
            else
            {
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                accepted = await application.ReadContactAcceptAsync(current.AccountId, pending.LocalAccountGeneration,
                    scope.Conversation.ToArray(), scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(), ct).ConfigureAwait(false) ??
                    throw new InvalidOperationException("The peer has not supplied an authenticated private acceptance route; retain the pending send.");
                var floor = await opened.Custody.ReconcileAsync(ct).ConfigureAwait(false);
                using var received = opened.Sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(accepted)) ??
                    throw new CryptographicException("The peer route has no actual authenticated receive custody.");
                using var plain = received.OwnAuthenticatedDmc2();
                if (!plain.Use(bytes => FixedRoute(bytes, accepted)))
                    throw new CryptographicException("The peer acceptance projection differs from its authenticated event.");
                var response = ApplicationCoreCodec.DecodeDmc2(accepted);
                await ApplicationCoreVerifier.RequireContactAcceptEndpointBindingsAsync(response, ApplicationCoreCodec.DecodeDmc2(hello),
                    own.Proof, peer, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                package = ((ContactAcceptDmc2Payload)response.ParsedPayload).MailboxRoute;
            }
            return await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(package, peer, own.Network, own.Authority,
                source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hello);
            if (accepted is not null) CryptographicOperations.ZeroMemory(accepted);
        }
    }

    private static byte[] MailboxSendOperation(Did2MessagingSessionScope scope, ReadOnlySpan<byte> operation, ReadOnlySpan<byte> dpe)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Local/DID2/MailboxStoreOperation/1"u8); hash.AppendData([0]);
        hash.AppendData(scope.Network); hash.AppendData(scope.LocalAccount); hash.AppendData(scope.Hash);
        hash.AppendData(operation); hash.AppendData(SHA256.HashData(dpe)); return hash.GetHashAndReset()[..16];
    }

    private static void RequireMailboxPreparedSend(ProtectedDid2MailboxSendJournal.Entry entry,
        MailboxAuthenticatedClientRequest request, ReadOnlySpan<byte> exact, VerifiedDeepIdV2MailboxGrant winner)
    {
        var signing = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation);
        if (request.Binding.Operation != MailboxAuthenticatedOperation.Store ||
            !FixedRoute(request.Binding.OperationId.Span, entry.MailboxOperation) ||
            !FixedRoute(SHA256.HashData(request.Binding.CanonicalRequest.Span), entry.BodyHash) ||
            !FixedRoute(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), winner.ExactGrant.Span) ||
            !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(), signing, request.Presentation.Grant.HolderPublicKey.ToArray()) ||
            entry.Prepared && (request.Presentation.ReplayCounter != entry.Counter || !FixedRoute(SHA256.HashData(exact), entry.MauHash)))
            throw new CryptographicException("Prepared MAU3 differs from the exact protected message/grant/counter.");
    }

    private async Task<byte[]> SaveMailboxSendJournalAsync(ProtectedDid2MailboxSendJournal.State state, byte[] expected,
        VerifiedDeepIdV2CurrentAccount current, byte[] instance, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var next = ProtectedDid2MailboxSendJournal.Encode(state, networkId, current.AccountId.Span, instance);
        try
        {
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            if (!await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, expected, next, ct).ConfigureAwait(false))
                throw new CryptographicException("Protected mailbox send custody changed under its owner lease.");
            await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, next, ct).ConfigureAwait(false);
            return next.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }

    private async Task RequireExactProtectedMailboxRootAsync(string slot, byte[] exact, CancellationToken ct)
    {
        using var root = await storage.ReadOwnedAsync(slot, ct).ConfigureAwait(false) ?? throw new CryptographicException("Protected mailbox custody disappeared.");
        if (!root.Use(bytes => FixedRoute(bytes, exact))) throw new CryptographicException("Protected mailbox custody changed during its owned operation.");
    }

    private sealed class OwnedMailboxDecodePolicy(MailboxAuthenticatedGrant grant, VerifiedOfficialMailboxAuthority authority) : IMailboxClientDecodePolicyProvider
    {
        public MailboxClientDecodePolicy GetCurrent() => new()
        {
            NowUnixSeconds = authority.NowUnixSeconds,
            EpochWindow = new()
            {
                CurrentEpoch = grant.Epoch,
                CurrentNotBeforeUnixSeconds = grant.NotBeforeUnixSeconds,
                CurrentExpiresAtUnixSeconds = grant.ExpiresAtUnixSeconds,
                NextEpoch = 0,
                NextNotBeforeUnixSeconds = 0,
                NextExpiresAtUnixSeconds = 0
            },
            CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = authority.MinimumGeneration },
            AllowLegacyMirrorOverlap = false
        };
    }

    // The transport cannot replace the prepared bytes or bypass the final
    // owner/floor/journal fence. It receives no holder, SQL or issuer authority.
    private sealed class OwnedStoreIngress(IClientMailboxBinaryIngress target, byte[] exact,
        ScopedMailboxResolvedRoute installed, Func<CancellationToken, Task> guard) :
        IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress, IDisposable
    {
        private readonly byte[] expected = exact.ToArray();
        private bool disposed;
        internal bool Attempted { get; private set; }
        public async Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request,
            ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (request.Length != expected.Length || !FixedRoute(request.Span, expected) ||
                route.Epoch != installed.Epoch || !FixedRoute(route.MailboxId.Bytes.Span, installed.MailboxId.Bytes.Span) ||
                !FixedRoute(route.PlacementCommitment.Span, installed.PlacementCommitment.Span) ||
                !FixedRoute(route.MembershipCommitment.Span, installed.MembershipCommitment.Span))
                throw new CryptographicException("Owned Store transport changed its prepared request or route.");
            await guard(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
            var owned = expected.ToArray();
            try
            {
                Attempted = true;
                var response = target is IRouteBoundClientMailboxBinaryIngress bound
                    ? await bound.StoreOnRouteAsync(owned, route, ct).ConfigureAwait(false)
                    : await target.StoreAsync(owned, ct).ConfigureAwait(false);
                if (response.IsEmpty || response.Length > MailboxReceiptV3Limits.MaximumQuorumLength)
                    throw new InvalidDataException("Owned Store reply exceeds its closed quorum bound.");
                // Do not retain callback-owned bytes across the asynchronous fence.
                var receipt = response.ToArray();
                try { await guard(ct).ConfigureAwait(false); return receipt; }
                catch { CryptographicOperations.ZeroMemory(receipt); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(owned); }
        }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => Reject();
        public Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        public Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => Reject();
        private static Task<ReadOnlyMemory<byte>> Reject() => Task.FromException<ReadOnlyMemory<byte>>(
            new CryptographicException("This owned loan authorizes only exact route-bound Store."));
        public void Dispose() { disposed = true; CryptographicOperations.ZeroMemory(expected); }
    }
}
