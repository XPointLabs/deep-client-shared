using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
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
    private enum OwnedMailboxPayloadKind { Application, BraidControl }

    internal Task<ClientMailboxStoreResult> DeliverMessagingAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer,
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport, CancellationToken ct) =>
        DeliverOwnedMailboxAsync(unixSeconds, verifier, scope, operation, ReadOnlyMemory<byte>.Empty,
            source, null, own, peer, grants, transport, OwnedMailboxPayloadKind.Application, ct);

    internal Task<ClientMailboxStoreResult> DeliverBraidControlAsync(ulong unixSeconds,
        IDeepMlDsa65Verifier verifier, Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, IDid2MailboxGrantTransport grants,
        IDid2OwnedMailboxTransportFactory transport, CancellationToken ct) =>
        DeliverOwnedMailboxAsync(unixSeconds, verifier, scope, operation, ReadOnlyMemory<byte>.Empty,
            source, null, own, peer, grants, transport, OwnedMailboxPayloadKind.BraidControl, ct);

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
            source, resolved, null, null, grants, transport, OwnedMailboxPayloadKind.Application, ct);
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
        // The class comes from authenticated native history, never a transport
        // flag. Ordinary semantic readers remain data-only.
        if (opened.Sql.ReadVerifiedNativeEventDirection(floor, operation.Span) == 3)
        {
            using var control = opened.Sql.ReadVerifiedBraidControl(floor, operation.Span) ??
                throw new CryptographicException("Control Store lost its actual committed send.");
            return control.ExactControl.ToArray();
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
        IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport,
        OwnedMailboxPayloadKind payloadKind, CancellationToken ct)
    {
        ProtectedDph2PreClaimJournal.RequireIntent(operation.Span);
        var op = operation.ToArray(); byte[] snapshot = [], grantRoot = [], instance = [], exactMau = [], envelopeBytes = [], attemptId = [];
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
            if (resolved is null && initialIntent.IsEmpty)
            {
                var cached = payloadKind == OwnedMailboxPayloadKind.BraidControl
                    ? await TryReadRetainedBraidStoreUnderLeaseAsync(current, held, opened, scope, op, fresh, source, ct).ConfigureAwait(false)
                    : await TryReadRetainedMessagingStoreUnderLeaseAsync(current, held, opened, scope, op, fresh, source, ct).ConfigureAwait(false);
                if (cached is not null) return cached; // Historical outcome only; no renewed dispatch.
            }
            envelopeBytes = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, initialIntent, ct).ConfigureAwait(false);
            var controlPayload = envelopeBytes.AsSpan().StartsWith("DBR2"u8);
            if (controlPayload != (payloadKind == OwnedMailboxPayloadKind.BraidControl))
                throw new CryptographicException("Mailbox dispatch selected a different native payload class.");
            if (controlPayload)
                await RequireBraidStorePurposeUnderLeaseAsync(opened, scope, op, envelopeBytes, held, ct).ConfigureAwait(false);
            else if (initialIntent.IsEmpty)
                await RequireOrdinaryWorkNotStoppedUnderLeaseAsync(scope, op, held, ct).ConfigureAwait(false);
            // A control has no DMC2/application lifetime. Its original signed
            // transport interval still limits every attempt and successor.
            var applicationRetryUntil = controlPayload ? ulong.MaxValue :
                await ReadMailboxApplicationRetryDeadlineUnderLeaseAsync(current, held, opened,
                    scope, op, initialIntent, ct).ConfigureAwait(false);
            // Acquiring a grant persists holder custody and can cause remote
            // issuance. Reject absent/full or changed attempt custody first.
            instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
            using (var root = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ?? throw new InvalidDataException("Protected send custody is absent; explicit reset is required."))
                snapshot = root.Use(bytes => bytes.ToArray());
            using var sends = ProtectedDid2MailboxSendJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var entry = sends.Current(scope.Hash, op);
            if (entry is not null && entry.RetryUntil != Math.Min(entry.Expires, applicationRetryUntil))
                throw new CryptographicException("Original attempt lost its effective authenticated application retry deadline.");
            var closedRoot = await CloseExpiredMailboxAttemptUnderLeaseAsync(current, held, opened, scope, op,
                initialIntent, envelopeBytes, sends, snapshot, instance, source, fresh, ct).ConfigureAwait(false);
            if (closedRoot is not null) { CryptographicOperations.ZeroMemory(snapshot); snapshot = closedRoot; }
            entry = sends.Current(scope.Hash, op);
            if (!controlPayload && initialIntent.IsEmpty && entry is not null)
            {
                var expiryTime = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
                var lower = checked(fresh.Proof.TrustedLowerUnixSeconds + expiryTime.SampleSeconds - fresh.Proof.MonotonicSample);
                if (lower >= entry.RetryUntil)
                {
                    await StopExpiredOrdinaryWorkUnderLeaseAsync(current, held, opened, scope, op, fresh, source, ct).ConfigureAwait(false);
                    throw new IOException("The original logical retry deadline permanently stops sender work.");
                }
            }
            // Expiry may close original uncertainty, never authorize replacement.
            await RequireMailboxRetryTimeUnderLeaseAsync(current, source, fresh, held,
                Math.Min(applicationRetryUntil, entry?.RetryUntil ?? ulong.MaxValue), ct).ConfigureAwait(false);
            var predecessor = entry?.Closed == true ? entry : null;
            if (predecessor is not null)
            {
                await RequireClosedMailboxChainForSuccessorUnderLeaseAsync(current, held, opened, scope, op,
                    initialIntent, resolved is null ? null : contact.Contact, verifier,
                    envelopeBytes, sends, snapshot, instance, source, fresh, ct).ConfigureAwait(false);
                entry = null;
            }
            var privateContact = resolved is null
                ? await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, fresh, peer, source, held, ct).ConfigureAwait(false) : null;
            var route = privateContact?.Route ?? contact.Contact.Route;
            var locator = privateContact?.LocatorHash ?? contact.Contact.Candidate.Request.LocatorHash;
            var capability = route.Route.Reachability.Field(10);
            var routeHash = SHA256.HashData(route.ExactRouteClosure.Span);
            if (!initialIntent.IsEmpty)
                await RequireRetainedInitialDraftAndRecipientUnderLeaseAsync(current, held, opened, initialIntent,
                    contact.Contact.Contact.CanonicalBytes, envelopeBytes, ct).ConfigureAwait(false);
            // Ordinary successors now join every original attempt to actual
            // qualified native peer history above, while this new route has
            // its own independently current delivery verification. Initial
            // contact still requires its original invitation-bound recipient.
            if (predecessor is not null && !initialIntent.IsEmpty && !FixedRoute(predecessor.RouteHash, routeHash))
                throw new CryptographicException("A replacement recipient route requires authenticated session-update custody.");
            if (entry is null && sends.Entries.Count >= ProtectedDid2MailboxSendJournal.MaximumEntries)
                throw new IOException("Resume the pending protected mailbox request or perform verified rollover.");
            if (entry is not null && (!FixedRoute(entry.RouteHash, routeHash) ||
                !FixedRoute(entry.EnvelopeHash, SHA256.HashData(envelopeBytes))))
                throw new CryptographicException("An exact owned send cannot acquire a replacement route or ciphertext.");
            await RequireMailboxSendFloorCapacityUnderLeaseAsync(sends, routeHash, locator,
                entry is null ? null : entry.GrantHash.ToArray(), current, instance, held, source, fresh, ct).ConfigureAwait(false);
            async Task Recheck(CancellationToken token)
            {
                await RequireFinalMessagingFreshnessAsync(current, scope, fresh, peer, source, held, first, token).ConfigureAwait(false);
                await RequireMailboxRetryTimeUnderLeaseAsync(current, source, fresh, held,
                    Math.Min(applicationRetryUntil, sends.Current(scope.Hash, op)?.RetryUntil ?? ulong.MaxValue), token).ConfigureAwait(false);
                if (resolved is not null)
                {
                    await RequireClaimContactTimeAsync(current, source, resolved, held, contact.Contact, contact.Time, token).ConfigureAwait(false);
                    await RequireRetainedInitialDraftAndRecipientUnderLeaseAsync(current, held, opened, initialIntent,
                        contact.Contact.Contact.CanonicalBytes, envelopeBytes, token).ConfigureAwait(false);
                }
                else
                {
                    var retainedRoute = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, fresh, peer, source, held, token).ConfigureAwait(false);
                    if (!FixedRoute(retainedRoute.HeadEventHash.Span, privateContact!.HeadEventHash.Span) ||
                        !FixedRoute(retainedRoute.NativeFloor.Span, privateContact.NativeFloor.Span) ||
                        !FixedRoute(retainedRoute.Route.ExactRouteClosure.Span, privateContact.Route.ExactRouteClosure.Span))
                        throw new CryptographicException("The authenticated peer mailbox route changed during this exact dispatch.");
                }
                var retained = await ReadOwnedMailboxEnvelopeUnderLeaseAsync(current, scope, opened, op, initialIntent, token).ConfigureAwait(false);
                try
                {
                    if (!FixedRoute(retained, envelopeBytes)) throw new CryptographicException("The committed send changed during dispatch.");
                }
                finally { CryptographicOperations.ZeroMemory(retained); }
                if (controlPayload)
                    await RequireBraidStorePurposeUnderLeaseAsync(opened, scope, op, envelopeBytes, held, token).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, token).ConfigureAwait(false);
                if (sends.Current(scope.Hash, op) is { Closed: true } || entry?.HasPredecessor == true)
                    await RequireClosedMailboxChainForSuccessorUnderLeaseAsync(current, held, opened, scope, op,
                        initialIntent, resolved is null ? null : contact.Contact, verifier,
                        envelopeBytes, sends, snapshot, instance, source, fresh, token).ConfigureAwait(false);
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
            if (predecessor is not null && FixedRoute(predecessor.GrantHash, grantHash))
                throw new CryptographicException("A closed attempt cannot reuse its original grant.");
            using var loan = await OpenMailboxWinnerUnderLeaseAsync(current, held, route, winner, locator, capability,
                retainedGrant, source, fresh, Recheck, ct).ConfigureAwait(false);
            if (entry is null && sends.Entries.Values.Any(value => !value.Prepared && FixedRoute(value.GrantHash, grantHash)))
                throw new IOException("Resume the pending protected mailbox request or perform verified rollover.");
            var created = entry?.Created ?? loan.Authority.NowUnixSeconds;
            // The short grant permits this attempt, not the accepted object's
            // retention. Exact retry retains the original signed body expiry.
            var expiry = entry?.Expires ?? predecessor?.Expires ?? checked(created + MailboxClientLimits.MaximumTtlSeconds);
            attemptId = entry is not null ? entry.Attempt.ToArray() : predecessor is not null ? NewRouteRandom32() : op.ToArray();
            var name = Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, attemptId));
            var ciphertext = envelopeBytes.ToArray();
            var mailboxOperation = MailboxSendOperation(scope, attemptId, envelopeBytes);
            var transportDigest = MailboxAttemptEnvelopeDigest(mailboxOperation, envelopeBytes);
            if (entry is not null)
            {
                // Replay the authenticated original body, never regenerate a
                // captured request from a producer derivation or a new grant.
                using var existingApplication = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
                var read = await existingApplication.ReadTransportOutboxAsync(
                    VerifiedCurrentMailboxGrant.AccountScopeForHolder(loan.Grant.HolderPublicKey.Span),
                    OutboxLogicalId.FromBytes(entry.MailboxOperation), ct).ConfigureAwait(false);
                if (read.Result == TransportOutboxReadResult.Corrupt || entry.Prepared && read.Item is null)
                    throw new CryptographicException("Retry lost its original SQL request.");
                if (read.Item is not null)
                {
                    var original = read.Item.GetCiphertextBundleCopy();
                    try
                    {
                        var mau = MailboxAuthenticatedClientRequestCodec.Decode(original);
                        if (!FixedRoute(SHA256.HashData(mau.Binding.CanonicalRequest.Span), entry.BodyHash) ||
                            entry.Prepared && !FixedRoute(SHA256.HashData(original), entry.MauHash))
                            throw new CryptographicException("Retry changed its protected original body.");
                        transportDigest = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                            mau.Binding.CanonicalRequest.Span).DeduplicationDigest.ToArray();
                    }
                    finally { CryptographicOperations.ZeroMemory(original); }
                }
            }
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = loan.Grant.Epoch,
                MailboxId = loan.Route.MailboxId,
                PlacementId = loan.Route.PlacementId,
                OperationId = mailboxOperation,
                DeduplicationDigest = transportDigest,
                CreatedAtUnixSeconds = created,
                ExpiresAtUnixSeconds = expiry,
                Ciphertext = ciphertext
            };
            try
            {
                var body = MailboxAuthenticatedRequestTranscript.ForStore(envelope).CanonicalRequest;
                if (entry is not null && (!FixedRoute(entry.MailboxOperation, envelope.OperationId.Span) ||
                    !FixedRoute(entry.GrantHash, grantHash) || !FixedRoute(entry.BodyHash, SHA256.HashData(body.Span))))
                    throw new CryptographicException("Mailbox retry changed its exact attempt body or selected grant.");
                using var candidate = predecessor is not null
                    ? ProtectedDid2MailboxSendJournal.Entry.SuccessorOf(predecessor, attemptId, grantHash, routeHash, envelope,
                        Math.Min(loan.Grant.ExpiresAtUnixSeconds, predecessor.RetryUntil))
                    : entry is not null ? ProtectedDid2MailboxSendJournal.Entry.Decode(entry.Exact)
                    : NewOriginalMailboxSend(scope, op, grantHash, routeHash, envelope, loan.Grant.ExpiresAtUnixSeconds,
                        Math.Min(applicationRetryUntil, expiry));
                if (entry is null)
                {
                    sends.EnrollGrant(loan.Grant);
                    if (predecessor is not null) sends.LinkSuccessor(predecessor, candidate);
                    else
                    {
                        sends.Entries.Add(name, ProtectedDid2MailboxSendJournal.Entry.Decode(candidate.Exact));
                        sends.Revision = checked(sends.Revision + 1);
                    }
#if DEEP_TEST_INTERNALS
                    if (predecessor is not null) Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeSuccessorRoot);
#endif
                    var adopted = await SaveMailboxSendJournalAsync(sends, snapshot, current, instance, held, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                    if (predecessor is not null) Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterSuccessorRoot);
#endif
                    entry = sends.Entries[name];
                }
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
                var preparedUpperStarted = Stopwatch.GetTimestamp();
                var minimumPreparedUpper = loan.Authority.NowUnixSeconds;
                Did2StorePublicEvidence publicEvidence;
                // Evidence/CAS preparation is not the network attempt. Keep its
                // own bounded scope before minting the signer-free dispatch
                // policy/context, so durable local writes cannot consume that
                // policy's unchanged30-second transport/return fence.
                using (var preparation = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    preparation.CancelAfter(TimeSpan.FromSeconds(30));
                    var token = preparation.Token;
                    var publicReplicas = await MailboxStoreReplicaEvidenceVerifier.CaptureAsync(route, token).ConfigureAwait(false);
                    publicEvidence = new Did2StorePublicEvidence(loan.Selector.AccountScope.ToArray(), envelope.OperationId,
                        ProtectedDid2MailboxGrantJournal.OriginalPolicy(retainedGrant), publicReplicas,
                        resolved is null ? default : contact.Contact.Contact.CanonicalBytes,
                        route.ExactRouteClosure,
                        resolved is null ? default : contact.Contact.Authorization.Freshness.ExactAdp1V2);
                    publicEvidence = await BindStoreEvidenceUnderLeaseAsync(current, held, opened, scope, op,
                        entry.Attempt.ToArray(), initialIntent, publicEvidence, fresh, token).ConfigureAwait(false);
                    if (controlPayload)
                        await RetainBraidStoreEvidenceBeforeDispatchUnderLeaseAsync(current, held, opened, scope, op,
                            publicEvidence, token).ConfigureAwait(false);
                    else if (initialIntent.IsEmpty)
                        await RetainMessageStoreEvidenceBeforeDispatchUnderLeaseAsync(current, held, opened, scope, op,
                            publicEvidence, token).ConfigureAwait(false);
                    else publicEvidence = await RetainInitialStoreEvidenceUnderLeaseAsync(current, held, opened, scope, op, initialIntent,
                        envelopeBytes, publicEvidence, fresh, verifier, envelope.CreatedAtUnixSeconds,
                        requireExisting: false, token).ConfigureAwait(false);
                    await Recheck(token).ConfigureAwait(false);
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot, grantRoot, token).ConfigureAwait(false);
                    await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, token).ConfigureAwait(false);
                }
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
                // Signing preparation is not renewed. This new dispatch-only
                // scope has no signer and cannot alter the original request.
                minimumPreparedUpper = checked(minimumPreparedUpper + (ulong)Math.Ceiling(
                    Stopwatch.GetElapsedTime(preparedUpperStarted).TotalSeconds));
                var dispatchStarted = Stopwatch.GetTimestamp();
                var dispatchTime = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
                var dispatchPma = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, winner.ExactPma2.Span,
                    dispatchTime.LowerUnixSeconds, dispatchTime.UpperUnixSeconds);
                RequireMailboxPolicyProjection(route, dispatchPma, fresh);
                using var dispatchPolicy = new MailboxInstallationPolicy(held, route, dispatchPma, loan.Grant, dispatchTime, dispatchStarted,
                    minimumPreparedUpper);
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
                // The ingress performs the full pre-callback fence. Avoid an
                // identical reconstruction immediately before adapter SQL
                // bookkeeping; cached outcomes still cross the final fence.
                dispatchPolicy.ValidateFreshness(); held.RequireActive();
#if DEEP_TEST_INTERNALS
                Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeDispatch);
#endif
                var dispatchValidated = false;
                try
                {
                    var result = await adapter.DispatchPreparedStoreAsync(loan.Selector.AccountScope, loan.Selector, prepared, deadline.Token)
                        .WaitAsync(deadline.Token).ConfigureAwait(false);
                    await Guard(deadline.Token).ConfigureAwait(false);
                    if (result.Cursor is null || result.Disposition is not (MailboxReplicaDisposition.Stored or MailboxReplicaDisposition.Duplicate))
                        throw new CryptographicException("Owned Store did not retain a verified durable storage result.");
                    dispatchValidated = true;
                    if (controlPayload)
                    {
                        _ = await TryReadRetainedBraidStoreUnderLeaseAsync(current, held, opened, scope, op,
                            fresh, source, deadline.Token).ConfigureAwait(false) ??
                            throw new CryptographicException("Control Store lost its original authenticated durable outcome.");
                    }
                    else if (initialIntent.IsEmpty)
                    {
#if DEEP_TEST_INTERNALS
                        Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeOrdinaryCompletion);
#endif
                        await RetainOrdinaryStoreCompletionUnderLeaseAsync(current, held, opened, scope, op, entry.Attempt.ToArray(), publicEvidence, fresh, source, deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.AfterOrdinaryCompletion);
#endif
                    }
                    else
                    {
#if DEEP_TEST_INTERNALS
                        Did2MailboxSendTestHooks.Hit(Did2MailboxSendFailpoint.BeforeOrdinaryCompletion);
#endif
                        await RetainInitialStoreEvidenceUnderLeaseAsync(current, held, opened, scope, op, initialIntent,
                            envelopeBytes, publicEvidence, fresh, verifier, envelope.CreatedAtUnixSeconds,
                            requireExisting: true, deadline.Token).ConfigureAwait(false);
                        _ = await TryReadRetainedInitialStoreUnderLeaseAsync(current, held, opened, scope, initialIntent,
                            null, fresh, source, verifier, deadline.Token).ConfigureAwait(false) ??
                            throw new CryptographicException("Initial completion lost its independently verified original Store.");
                    }
                    // Local SQL/protected completion can await platform IO.
                    // Its durable fact survives expiry or cancellation, but
                    // that does not authorize a stale successful UI return.
                    await Guard(deadline.Token).ConfigureAwait(false);
                    return result;
                }
                catch (Exception error) when (ingress.Attempted &&
                    error is CryptographicException or IOException or InvalidOperationException or OperationCanceledException)
                {
                    // A returned bounded response is untrusted input, not a fresh
                    // dispatch capability. Authenticate original custody under this
                    // SAME owner lease; never re-sign or re-dispatch an expired grant.
                    if (!dispatchValidated && !ingress.OriginalReply.IsEmpty)
                        return await AdoptOriginalMailboxStoreReplyUnderLeaseAsync(current, held, opened, verifier,
                            scope, op, entry.Attempt.ToArray(), initialIntent, ingress.OriginalReply, fresh, source, ct)
                            .ConfigureAwait(false);
                    if (error is ClientMailboxDispatchOutcomeUnknownException) throw;
                    throw new ClientMailboxDispatchOutcomeUnknownException("Owned Store cannot confirm its outcome after dispatch; retain the exact request.", error);
                }
            }
            finally { CryptographicOperations.ZeroMemory(ciphertext); }
        }
        finally { foreach (var value in new[] { op, snapshot, grantRoot, instance, exactMau, envelopeBytes, attemptId }) CryptographicOperations.ZeroMemory(value); }
    }

    // Denial-only preflight for a new ordinary command / ratchet transition.
    // It neither reserves a slot nor grants signing/dispatch authority. Every
    // actual transport writer still performs its own existing capacity checks.
    private async Task RequireNewMailboxWorkCapacityUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, OwnedDid2MessagingStorage opened, Did2MessagingSessionScope scope,
        ReadOnlyMemory<byte> operation, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        VerifiedDeepIdV2DirectoryFreshness peer, DeepIdV2ContactPathAuthoritySource source, IDeepMlDsa65Verifier verifier, CancellationToken ct)
    {
        held.RequireActive(); ct.ThrowIfCancellationRequested();
        await RequireNoRetainedPeerRouteFaultUnderLeaseAsync(opened, held, ct).ConfigureAwait(false);
        await MaintainMailboxNamespacesUnderLeaseAsync(current, held, verifier, own, source, ct).ConfigureAwait(false);
        using var sendRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected send custody is absent before new authored work.");
        using var sends = sendRoot.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        var name = Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, operation.Span));
        // A transport commitment requires its original committed ciphertext.
        // An absent native ratchet operation cannot reconstruct that source.
        if (sends.Entries.ContainsKey(name))
            throw new CryptographicException("Protected transport work has lost its original committed operation.");
        if (sends.Entries.Count >= ProtectedDid2MailboxSendJournal.MaximumEntries)
            throw new IOException("Protected mailbox send capacity is exhausted before new authored work.");
        using var grantRoot = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot, ct).ConfigureAwait(false) ??
            throw new InvalidDataException("Protected grant custody is absent before new authored work.");
        using var grants = grantRoot.Use(bytes => ProtectedDid2MailboxGrantJournal.Decode(bytes,
            scope.Network, scope.LocalAccount, scope.Instance));
        if (sends.Floors.Count >= ProtectedDid2MailboxSendJournal.MaximumFloors ||
            grants.Entries.Count >= ProtectedDid2MailboxGrantJournal.MaximumEntries)
        {
            // Only when a bound is exhausted is a retained route/winner needed
            // to distinguish reusable custody from issuance of another scope.
            // Structural winner metadata is a capacity hint, never authority.
            var route = await ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(current, opened, own, peer,
                source, held, ct).ConfigureAwait(false);
            var routeHash = SHA256.HashData(route.Route.ExactRouteClosure.Span);
            var grantScope = Convert.ToHexString(ProtectedDid2MailboxGrantJournal.Scope(routeHash,
                route.LocatorHash.Span, (byte)MailboxCapabilityDomain.Deposit));
            var candidate = ProtectedDid2MailboxGrantJournal.AcquisitionForNewWork(grants, grantScope);
            if (candidate is null && grants.Entries.Count >= ProtectedDid2MailboxGrantJournal.MaximumEntries)
                throw new IOException("Protected mailbox acquisition capacity is exhausted before new authored work.");
            if (candidate is not null)
            {
                var renewalRoot = grantRoot.Use(bytes => bytes.ToArray());
                try
                {
                    var renewal = await SelectNewWorkMailboxGrantRenewalUnderLeaseAsync(current, held, grants,
                        grantScope, renewalRoot, source, own, ct).ConfigureAwait(false);
                    if (!renewal.IsEmpty)
                    {
                        var continuation = ProtectedDid2MailboxGrantJournal.AcquisitionForRenewal(grants,
                            grantScope, renewal.Span, MailboxCapabilityDomain.Deposit);
                        if (sends.Floors.Count >= ProtectedDid2MailboxSendJournal.MaximumFloors ||
                            continuation is null && grants.Entries.Count >= ProtectedDid2MailboxGrantJournal.MaximumEntries)
                            throw new IOException("A new grant or replay scope cannot fit before new authored work.");
                    }
                }
                finally { CryptographicOperations.ZeroMemory(renewalRoot); }
            }
            if (sends.Floors.Count >= ProtectedDid2MailboxSendJournal.MaximumFloors)
            {
                if (candidate is null || !ProtectedDid2MailboxGrantJournal.HasWinner(candidate))
                    throw new IOException("Protected mailbox replay floors are full before new authored work.");
                var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(candidate).Span);
                sends.RequireGrant(MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span));
            }
            var exactSend = sendRoot.Use(bytes => bytes.ToArray());
            var exactGrant = grantRoot.Use(bytes => bytes.ToArray());
            try
            {
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxSendJournal.Slot,
                    exactSend, ct).ConfigureAwait(false);
                await RequireExactProtectedMailboxRootAsync(ProtectedDid2MailboxGrantJournal.Slot,
                    exactGrant, ct).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(exactSend); CryptographicOperations.ZeroMemory(exactGrant); }
        }
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }

    // Capacity is checked before grant acquisition can enroll a holder or call
    // the issuer. A structural protected winner is only a capacity hint here;
    // the normal acquisition, signature, freshness and exact-grant checks still
    // run independently. A reader cannot enroll/repair an absent counter floor.
    private async Task RequireMailboxSendFloorCapacityUnderLeaseAsync(ProtectedDid2MailboxSendJournal.State sends,
        byte[] routeHash, ReadOnlyMemory<byte> locator, byte[]? originalGrant, VerifiedDeepIdV2CurrentAccount current,
        byte[] instance, HeldDeepIdV2AccountLease held, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
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
        if (originalGrant is null)
        {
            var exact = root.Use(bytes => bytes.ToArray());
            try
            {
                // A due successor needs a distinct enrolled replay scope; the old
                // winner cannot conceal exhausted floors before issuer callback.
                var renewal = await SelectNewWorkMailboxGrantRenewalUnderLeaseAsync(current, held, state,
                    name, exact, source, fresh, ct).ConfigureAwait(false);
                if (!renewal.IsEmpty) throw new IOException("Protected mailbox replay floors cannot fit a grant successor.");
            }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        var response = ContactCodec.Decode("XMC2", ProtectedDid2MailboxGrantJournal.Response(winner).Span);
        sends.RequireGrant(MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span));
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }

    private async Task<OwnedPeerMailboxRoute> ReadAuthenticatedPeerMailboxRouteUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var history = await ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(current, opened, own, peer, source, held, ct).ConfigureAwait(false);
        return await RequireCurrentPeerRouteUnderLeaseAsync(opened, history, own, peer, source, held, ct).ConfigureAwait(false);
    }

    private async Task<OwnedPeerRouteHistory> ReadAuthenticatedPeerRouteHistoryUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, OwnedDid2MessagingStorage opened,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, VerifiedDeepIdV2DirectoryFreshness peer,
        DeepIdV2ContactPathAuthoritySource source, HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        held.RequireActive(); var scope = opened.Scope;
        using var pending = await AuthenticatedInitialDmc2Batch.FromOwnedDid2Async(opened, own, peer, source, held, ct).ConfigureAwait(false);
        var hello = pending.FirstApplicationDmc2; byte[]? accepted = null;
        try
        {
            var greeting = ApplicationCoreCodec.DecodeDmc2(hello);
            if (greeting.ParsedPayload is not ContactHelloDmc2Payload helloPayload)
                throw new CryptographicException("Private route has no actual native Hello custody.");
            ParsedDeepIdV2ContactMailboxRoute package;
            var policy = helloPayload.Policy;
            ReadOnlyMemory<byte> originalEvent = greeting.CanonicalBytes;
            ulong originalOrdinal = 1;
            if (!scope.IsInitiator)
                package = helloPayload.MailboxRoute;
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
                using var verifiedAccept = await AuthenticatedContactAcceptDmc2.FromOwnedCommitAsync(opened,
                    Deep.Protocol.MessagingWire.Dpe2Codec.Decode(received.ExactEnvelope).OperationId,
                    ReadOnlyMemory<byte>.Empty, storage, own, peer, source, held, ct).ConfigureAwait(false);
                package = ((ContactAcceptDmc2Payload)response.ParsedPayload).MailboxRoute;
                policy &= ((ContactAcceptDmc2Payload)response.ParsedPayload).Policy;
                originalEvent = response.CanonicalBytes;
                originalOrdinal = received.Ordinal;
            }
            var localAccountGeneration = pending.LocalAccountGeneration;
            async Task<bool> HasUpdateConsent(ulong updateOrdinal, CancellationToken token)
            {
                if ((policy & ContactPolicy.AllowRouteUpdates) == 0)
                    return false;
                if (updateOrdinal <= originalOrdinal)
                    return false;
                if (scope.IsInitiator) return true; // Both native Hello/Accept policies were checked above.
                using var application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                    storage, sqlStatePath, current, held, token).ConfigureAwait(false);
                await RequireRetainedAcceptanceForTextAsync(opened, application, own, peer, source, held, token).ConfigureAwait(false);
                var localAccept = await application.ReadContactAcceptAsync(current.AccountId, localAccountGeneration,
                    scope.Conversation.ToArray(), scope.LocalAccount.ToArray(), scope.LocalDevice.ToArray(), token).ConfigureAwait(false) ??
                    throw new CryptographicException("Private route update lost its native local acceptance.");
                try
                {
                    if (ApplicationCoreCodec.DecodeDmc2(localAccept).ParsedPayload is not ContactAcceptDmc2Payload local)
                        throw new CryptographicException("Native local acceptance has a different canonical kind.");
                    using var raw = await storage.ReadOwnedAsync(ProtectedDid2ContactAcceptJournal.Slot, token).ConfigureAwait(false) ??
                        throw new CryptographicException("Private route update lost protected local acceptance.");
                    using var commands = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes,
                        scope.Network, scope.LocalAccount, scope.Instance));
                    var command = commands.FindScope(scope) ??
                        throw new CryptographicException("Private route update lost its local acceptance winner.");
                    var floor = await opened.Custody.ReconcileAsync(token).ConfigureAwait(false);
                    using var native = opened.Sql.ReadVerifiedOperation(floor, command.Operation) ??
                        throw new CryptographicException("Private route update lost actual native local acceptance.");
                    if (native.Direction != 1 || !FixedRoute(native.EventHash, SHA256.HashData(localAccept)))
                        throw new CryptographicException("Private route update local consent differs from native custody.");
                    return native.Ordinal < updateOrdinal && (local.Policy & ContactPolicy.AllowRouteUpdates) != 0;
                }
                finally { CryptographicOperations.ZeroMemory(localAccept); }
            }
            return await ReadNativePeerRouteHistoryUnderLeaseAsync(opened, package, originalEvent,
                own, peer, source, held, HasUpdateConsent, ct).ConfigureAwait(false);
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

    private static byte[] MailboxAttemptEnvelopeDigest(ReadOnlySpan<byte> operation, ReadOnlySpan<byte> ciphertext)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(System.Text.Encoding.UTF8.GetBytes(MailboxDomainSeparation.EnvelopeDigest));
        hash.AppendData([0]); hash.AppendData(operation); hash.AppendData(ciphertext);
        return hash.GetHashAndReset();
    }

    private static void RequireMailboxPreparedSend(ProtectedDid2MailboxSendJournal.Entry entry,
        MailboxAuthenticatedClientRequest request, ReadOnlySpan<byte> exact, VerifiedDeepIdV2MailboxGrant winner)
    {
        var signing = MailboxAuthenticatedCapabilityCodec.GetPresentationSigningBytes(request.Presentation);
        if (request.Binding.Operation != MailboxAuthenticatedOperation.Store ||
            entry.Closed || entry.HasSuccessor ||
            entry.AdmissionUntil != Math.Min(request.Presentation.Grant.ExpiresAtUnixSeconds, entry.RetryUntil) ||
            !FixedRoute(request.Binding.OperationId.Span, entry.MailboxOperation) ||
            !FixedRoute(SHA256.HashData(request.Binding.CanonicalRequest.Span), entry.BodyHash) ||
            !FixedRoute(MailboxAuthenticatedCapabilityCodec.EncodeGrant(request.Presentation.Grant), winner.ExactGrant.Span) ||
            !PublicKeyAuth.VerifyDetached(request.Presentation.HolderSignature.ToArray(), signing, request.Presentation.Grant.HolderPublicKey.ToArray()) ||
            entry.Prepared && (request.Presentation.ReplayCounter != entry.Counter || !FixedRoute(SHA256.HashData(exact), entry.MauHash)))
            throw new CryptographicException("Prepared MAU3 differs from the exact protected message/grant/counter.");
    }

    private static ProtectedDid2MailboxSendJournal.Entry NewOriginalMailboxSend(Did2MessagingSessionScope scope,
        ReadOnlySpan<byte> operation, ReadOnlySpan<byte> grantHash, ReadOnlySpan<byte> routeHash,
        MailboxEncryptedEnvelope envelope, ulong grantExpiry, ulong retryUntil)
    {
        using var pending = ProtectedDid2MailboxSendJournal.Entry.Pending(scope, operation, grantHash, routeHash, envelope, retryUntil);
        return pending.WithAdmissionCeiling(Math.Min(grantExpiry, retryUntil));
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
        private readonly object replyGate = new();
        private byte[] originalReply = [];
        private bool disposed;
        internal bool Attempted { get; private set; }
        internal ReadOnlyMemory<byte> OriginalReply => originalReply;
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
                try
                {
                    lock (replyGate)
                    {
                        ObjectDisposedException.ThrowIf(disposed, this);
                        if (receipt.Length == MailboxReceiptV3Limits.QuorumFixedHeaderLength +
                            2 * MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength + 64)
                        {
                            CryptographicOperations.ZeroMemory(originalReply);
                            originalReply = receipt.ToArray();
                        }
                    }
                    await guard(ct).ConfigureAwait(false); return receipt;
                }
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
        public void Dispose()
        {
            lock (replyGate)
            { disposed = true; CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(originalReply); }
        }
    }
}
