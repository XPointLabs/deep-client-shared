using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal const int MaximumRenewalThresholdVerificationAttempts = 3;
    private static readonly TimeSpan RenewalThresholdAcquisitionBudget = TimeSpan.FromSeconds(30);
    // The complete current/pending transition owns one actual account lease.
    // A null result means normal genesis/current restoration, never a fallback
    // after failed successor authentication or an abandoned unknown outcome.
    internal async Task<VerifiedDeepIdV2PublicationCommit?> TryRenewPermanentContactAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, Did2OwnedPermanentContactPlan plan,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        StagedDeepIdV2PreKeyPublication staged, IDid2ContactRouteThresholdSource thresholdSource,
        IDid2ContactPublicationSource publicationSource, IDid2ContactReplicaPublicationTransport transport, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(
            storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null, capability = null, pendingIntent = null;
        try
        {
            RequirePermanentContactPlan(plan, current, instance, plan.Intent.Span);
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected route custody is absent; explicit local reset is required.");
            snapshot = owned.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var currentName = Convert.ToHexString(plan.Intent.Span);
            if (!state.Entries.TryGetValue(currentName, out var prior) || prior.Phase != 7) return null;
            var configuration = Did2OwnedPermanentContactPlan.Configuration();
            if (prior.Kind != 1 || !prior.Matches(configuration) || !FixedRoute(prior.Record(0).Span, staged.ExactDca1.Span))
                throw new CryptographicException("Permanent-contact renewal changed protected configuration or delegation.");
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(prior.Record(0).Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, first.BootId.Span, first.SampleSeconds);
            var priorRoute = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(authorization, fresh.Network,
                fresh.Authority, prior.Record(5), prior.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var permanent = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, current.AccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.DeepId, ct).ConfigureAwait(false);
            capability = permanent.ResolverReadCapability.ToArray();
            var priorObject = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(authorization, fresh.Network,
                fresh.Authority, priorRoute, prior.Record(7), prior.Record(8), capability, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (!FixedRoute(priorObject.Closure.Bundle.Field(15).Span, System.Text.Encoding.UTF8.GetBytes(plan.Profile)) ||
                priorObject.Closure.Bundle.Field(12).Length != 357)
                throw new CryptographicException("Permanent-contact renewal changed its protected profile or device set.");
            var serviceChanged = !FixedRoute(priorObject.Closure.Bundle.Field(12).Span[5..], staged.ExactXps1.Span);
            ParsedXps1V2[] serviceHistory = [];
            if (serviceChanged)
            {
                serviceHistory = await SqliteDeepIdV2AccountGeneration.ReadCommittedOwnPreKeyServiceHistoryAsync(storage, sqlStatePath,
                    current, staged, priorObject.Closure.Bundle.Field(12).Slice(5), fresh.Network, ct).ConfigureAwait(false);
                DeepIdV2PreKeyLineageVerifier.VerifyServiceHistory(DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span),
                    DeepIdV2PreKeyServiceCodec.Decode(priorObject.Closure.Bundle.Field(12).Span[5..]),
                    serviceHistory,
                    checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceEd25519PublicKey.Span);
                var checkedTime = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, checkedTime.BootId.Span, checkedTime.SampleSeconds);
                DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId, staged.ExactXps1.Span,
                    authorization, DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span), checkedTime.BootId.Span, checkedTime.SampleSeconds);
            }
            var priorRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(prior.Record(9).Span);
            var priorWinner = ContactPublicationAuthorityWireCodec.DecodeResponse(priorRequest, prior.Record(10).Span);
            var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(authorization, fresh.Network,
                fresh.Authority, priorObject, priorRequest, priorWinner.ExactXpu1, prior.Record(11),
                source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            pendingIntent = DeriveContactRenewalIntent(networkId, current.AccountId.Span, instance, plan.Intent.Span, prior.Exact);
            var resolvedIntent = await ResolveRenewalIntentAsync(state, pendingIntent, current.AccountId, instance, ct).ConfigureAwait(false);
            var followedRecordedClosure = !FixedRoute(pendingIntent, resolvedIntent);
            CryptographicOperations.ZeroMemory(pendingIntent); pendingIntent = resolvedIntent;
            var pendingName = Convert.ToHexString(pendingIntent);
            if (!state.Entries.TryGetValue(pendingName, out var entry))
            {
                // Derive the decision only from authenticated signed expiry and
                // independently current time. Corruption is not expiry recovery.
                var now = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, now.BootId.Span, now.SampleSeconds);
                var advertisement = ContactCodec.Decode("XRA1", prior.Record(1).Span);
                var refreshAt = Math.Min(ProactiveRefreshAt(
                        BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(12).Span),
                        BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(13).Span)),
                    ProactiveRefreshAt(
                        BinaryPrimitives.ReadUInt64BigEndian(priorObject.Closure.Bundle.Field(17).Span),
                        BinaryPrimitives.ReadUInt64BigEndian(priorObject.Closure.Bundle.Field(18).Span)));
                // The threshold may shorten selection/live/successor windows
                // below the subject's XRA or object lifetime. All these exact
                // records were independently authenticated above; expiry is
                // never inferred from a parse failure or extended on retry.
                var authenticatedRoute = ContactRouteClosureCodec.Decode(priorRoute.ExactRouteClosure.Span);
                foreach (var (record, issuedTag, expiryTag) in new[] {
                    (authenticatedRoute.Selection, 8, 9), (authenticatedRoute.Route, 17, 18),
                    (authenticatedRoute.Successor, 10, 11), (authenticatedRoute.Reachability, 16, 17) })
                    refreshAt = Math.Min(refreshAt, ProactiveRefreshAt(
                        BinaryPrimitives.ReadUInt64BigEndian(record.Field(issuedTag).Span),
                        BinaryPrimitives.ReadUInt64BigEndian(record.Field(expiryTag).Span)));
                if (!serviceChanged && authorization.TrustedUpperUnixSeconds < refreshAt) return null;
                var scalar = NewRouteRandom32(); var keyId = NewRouteRandom32(); var nonce = NewRouteRandom32();
                try
                {
                    var minimumExpiry = checked(BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(13).Span) + 1);
                    var ceiling = Math.Min(fresh.Authority.ExpiresAt, Math.Min(dca.Record.ExpiresAtUnixSeconds,
                        current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds));
                    var nextExpiry = Math.Min(Math.Max(checked(authorization.TrustedLowerUnixSeconds + 86_400), minimumExpiry), ceiling);
                    if (nextExpiry < minimumExpiry)
                        throw new CryptographicException("Current authority cannot extend the exact reachability predecessor.");
                    var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(authorization, fresh.Network,
                        fresh.Authority, current.Verified.DeviceSecrets, prior.Record(1), configuration.AntiSpamHash, keyId,
                        Deep.Protocol.Identity.DeepIdentityCrypto.DeriveX25519PublicKey(scalar), nextExpiry,
                        source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                    entry = ProtectedDid2ContactRouteJournal.Entry.Proposal(pendingIntent, configuration, scalar, keyId, nonce,
                        staged.ExactDca1, xra, new ContactRouteAuthorityWireRequest(networkId, nonce,
                            authorization.Freshness.QueriedDirectoryLeafKey.Span, authorization.Freshness.NextProtectedLkg.LogGeneration,
                            authorization.Freshness.NextProtectedLkg.CoreHash.Span, staged.ExactDca1.Span, xra.CanonicalBytes.Span,
                            priorRoute.ExactXir1V2.Span, priorRoute.ExactRouteClosure.Span), networkId, current.AccountId.Span);
                    state.Entries.Add(pendingName, entry);
                    await SaveAsync(ct).ConfigureAwait(false); // Includes full capacity reservation and independent readback.
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterProposal);
#endif
                }
                finally { CryptographicOperations.ZeroMemory(scalar); CryptographicOperations.ZeroMemory(keyId); CryptographicOperations.ZeroMemory(nonce); }
            }
            if (entry.Phase == 7 || !entry.Matches(configuration) || !FixedRoute(entry.Record(0).Span, prior.Record(0).Span))
                throw new CryptographicException("Pending renewal differs from its exact protected predecessor configuration.");
            var recordedHistory = await ReadRecordedRenewalHistoryAsync(entry, authorization, fresh, source, ct).ConfigureAwait(false);
            if (followedRecordedClosure && recordedHistory is null)
                throw new InvalidDataException("Recorded renewal forward custody lost its protected origin history.");
            var routeRequest = ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span);
            if (entry.Phase == 1 && authorization.TrustedLowerUnixSeconds >= BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1",entry.Record(1).Span).Field(13).Span))
            {
                using var recoveryDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                recoveryDeadline.CancelAfter(RenewalThresholdAcquisitionBudget);
                var recoveryToken = recoveryDeadline.Token;
                if (thresholdSource is not IDid2ContactRouteRecoverySource recoverySource)
                    throw new CryptographicException("The owned route recovery transport is unavailable.");
                await DeepIdV2ContactRouteVerifier.VerifyExpiredAdvertisementForRecoveryAsync(authorization, fresh.Network, fresh.Authority,
                    priorRoute, entry.Record(1), source.RendezvousTrustedTime, recoveryToken, recordedHistory).AsTask().WaitAsync(recoveryToken).ConfigureAwait(false);
                if (recordedHistory?.Pairs.Count == 3) throw new IOException("Recorded renewal history capacity is exhausted.");
                var readRequest = await DeepIdV2ContactRouteAuthor.AuthorRecoveryRequestAsync(authorization, fresh.Network, fresh.Authority,
                    current.Verified.DeviceSecrets, DeepIdV2ContactRouteRecoveryMode.ReadRecordedWinner, routeRequest,
                    recordedHistory?.Pairs ?? [], source.RendezvousTrustedTime, recoveryToken).AsTask().WaitAsync(recoveryToken).ConfigureAwait(false);
                var readDispatch = await DispatchAsync(recoveryToken).WaitAsync(recoveryToken).ConfigureAwait(false);
                var recordedResponse = await recoverySource.RecoverAsync(readRequest,readDispatch,recoveryToken).AsTask().WaitAsync(recoveryToken).ConfigureAwait(false);
                var exactResponse = ContactRouteAuthorityWireCodec.EncodeResponse(routeRequest,recordedResponse);
                try
                {
                    var pairs = (recordedHistory?.Pairs ?? []).Append(new DeepIdV2ContactRouteRecordedPair(entry.Record(12).Span,exactResponse)).ToArray();
                    recordedHistory = await DeepIdV2ContactRouteVerifier.VerifyRecordedHistoryAsync(authorization, fresh.Network, fresh.Authority,
                        priorRoute,pairs,source.RendezvousTrustedTime,recoveryToken).AsTask().WaitAsync(recoveryToken).ConfigureAwait(false);
                    var scalar=NewRouteRandom32(); var keyId=NewRouteRandom32(); var nonce=NewRouteRandom32();
                    try
                    {
                        var expiryFloor=checked(BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1",entry.Record(1).Span).Field(13).Span)+1);
                        var expiry=Math.Min(Math.Max(checked(authorization.TrustedLowerUnixSeconds+86_400),expiryFloor),
                            Math.Min(fresh.Authority.ExpiresAt,Math.Min(dca.Record.ExpiresAtUnixSeconds,current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds)));
                        var xra=await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAfterRecordedHistoryAsync(authorization,fresh.Network,fresh.Authority,
                            current.Verified.DeviceSecrets,recordedHistory,configuration.AntiSpamHash,keyId,
                            Deep.Protocol.Identity.DeepIdentityCrypto.DeriveX25519PublicKey(scalar),expiry,source.RendezvousTrustedTime,recoveryToken).AsTask().WaitAsync(recoveryToken).ConfigureAwait(false);
                        var nextRequest=new ContactRouteAuthorityWireRequest(networkId,nonce,authorization.Freshness.QueriedDirectoryLeafKey.Span,
                            authorization.Freshness.NextProtectedLkg.LogGeneration,authorization.Freshness.NextProtectedLkg.CoreHash.Span,staged.ExactDca1.Span,xra.CanonicalBytes.Span,
                            priorRoute.ExactXir1V2.Span,priorRoute.ExactRouteClosure.Span);
                        var baseHash=SHA256.HashData(prior.Exact);
                        var nextIntent=ProtectedDid2ContactRenewalClosure.DeriveNextIntent(networkId,current.AccountId.Span,instance,plan.Intent.Span,baseHash,entry.Exact,exactResponse);
                        using var next=ProtectedDid2ContactRouteJournal.Entry.Proposal(nextIntent,configuration,scalar,keyId,nonce,staged.ExactDca1,xra,nextRequest,networkId,current.AccountId.Span);
                        using var closure=ProtectedDid2ContactRenewalClosure.Create(networkId,current.AccountId.Span,instance,plan.Intent.Span,baseHash,entry,next,exactResponse);
                        var origin=closure.EncodeOrigin(); var closureBytes=closure.Exact.ToArray();
                        var adopted=ProtectedDid2ContactRouteJournal.Entry.Decode(next.Exact,networkId,current.AccountId.Span);
                        var oldEntry=entry; var nextName=Convert.ToHexString(nextIntent);
                        byte[]? replacement = null;
                        var adoptedAdded = false;
                        try
                        {
                            state.Entries.Remove(pendingName); state.Entries.Add(nextName,adopted); adoptedAdded = true;
                            replacement=ProtectedDid2ContactRouteJournal.Encode(state,networkId,current.AccountId.Span,instance);
                            await RequireThresholdAdoptionGuardsAsync(recoveryToken).WaitAsync(recoveryToken).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                            Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.BeforeRecordedClosure);
#endif
                            var closedSlot=ProtectedDid2ContactRenewalClosure.ClosedSlot(pendingIntent);
                            var originSlot=ProtectedDid2ContactRenewalClosure.OriginSlot(SHA256.HashData(next.Record(12).Span));
                            if(!await storage.CompareExchangeAndInsertAsync(ProtectedDid2ContactRouteJournal.Slot,snapshot!,replacement,
                                [new(closedSlot,closureBytes),new(originSlot,origin)],recoveryToken).ConfigureAwait(false))throw new IOException("Recorded renewal closure lost its exact protected journal comparison.");
#if DEEP_TEST_INTERNALS
                            Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRecordedClosure);
#endif
                            using var readback=await storage.ReadOwnedBatchAsync([ProtectedDid2ContactRouteJournal.Slot,closedSlot,originSlot],recoveryToken).ConfigureAwait(false);
                            if(readback[0] is null || readback[1] is null || readback[2] is null || !readback[0]!.Use(bytes=>FixedRoute(bytes,replacement)) ||
                                !readback[1]!.Use(bytes=>FixedRoute(bytes,closureBytes)) || !readback[2]!.Use(bytes=>FixedRoute(bytes,origin)))throw new CryptographicException("Recorded renewal closure independent readback differs.");
                            CryptographicOperations.ZeroMemory(snapshot!);snapshot=replacement.ToArray();
                            CryptographicOperations.ZeroMemory(pendingIntent);pendingIntent=nextIntent.ToArray();pendingName=nextName;entry=adopted;
                            routeRequest=nextRequest;
#if DEEP_TEST_INTERNALS
                            Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRecordedClosureReadback);
#endif
                        }
                        finally{oldEntry.Dispose();if(!adoptedAdded)adopted.Dispose();if(replacement is not null)CryptographicOperations.ZeroMemory(replacement);CryptographicOperations.ZeroMemory(closureBytes);CryptographicOperations.ZeroMemory(origin);CryptographicOperations.ZeroMemory(nextIntent);CryptographicOperations.ZeroMemory(baseHash);}
                    }
                    finally{CryptographicOperations.ZeroMemory(scalar);CryptographicOperations.ZeroMemory(keyId);CryptographicOperations.ZeroMemory(nonce);}
                }
                finally{CryptographicOperations.ZeroMemory(exactResponse);}
            }
            if (!routeRequest.HasPredecessor || !FixedRoute(routeRequest.ExactPredecessorXir1V2.Span, prior.Record(5).Span) ||
                !FixedRoute(routeRequest.ExactPredecessorRouteClosure.Span, prior.Record(6).Span))
                throw new CryptographicException("Pending renewal substituted its committed predecessor.");
            Did2ContactRouteRequestCustody.RequireCurrent(routeRequest, authorization, fresh.Network);
            if(recordedHistory is null)
                await DeepIdV2ContactRouteVerifier.VerifyAdvertisementSuccessorAsync(authorization, fresh.Network,
                    fresh.Authority, priorRoute, entry.Record(1), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            else
                await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAfterRecordedHistoryAsync(authorization,fresh.Network,fresh.Authority,
                    recordedHistory,entry.Record(1),source.RendezvousTrustedTime,ct).ConfigureAwait(false);
            if (entry.Phase == 1)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var acquisitionStarted = Stopwatch.GetTimestamp();
                deadline.CancelAfter(RenewalThresholdAcquisitionBudget);
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                ContactRouteAuthorityWireResponse response;
                if(recordedHistory is null)
                    response=await thresholdSource.FetchAsync(routeRequest,authorization,fresh.Network,fresh.Authority,source.RendezvousTrustedTime,dispatch,deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
                else
                {
                    var recovery=thresholdSource as IDid2ContactRouteRecoverySource ?? throw new CryptographicException("The owned route recovery transport is unavailable.");
                    var outer=await DeepIdV2ContactRouteAuthor.AuthorRecoveryRequestAsync(authorization,fresh.Network,fresh.Authority,current.Verified.DeviceSecrets,
                        DeepIdV2ContactRouteRecoveryMode.IssueAfterRecordedHistory,routeRequest,recordedHistory.Pairs,source.RendezvousTrustedTime,deadline.Token).ConfigureAwait(false);
                    response=await recovery.RecoverAsync(outer,dispatch,deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
                }
                if(response is null)throw new CryptographicException("The route successor threshold response is absent.");
                _ = ContactRouteAuthorityWireCodec.EncodeResponse(routeRequest, response);
                // Own the exact response once. A future-start hint schedules
                // only this response; it is never adoption/signing authority.
                var threshold = new ParsedDeepIdV2RouteThreshold(response.ExactPms2.Span, response.ExactXrc1.Span, response.ExactXss1.Span);
                var issuanceHead = response.ExactIssuanceAdh1;
                VerifiedDeepIdV2ContactRouteIssuance verified;
                for (var attempt = 1; ; attempt++)
                {
                    await RequireThresholdAdoptionGuardsAsync(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                    try
                    {
                        verified = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(authorization, fresh.Network,
                            fresh.Authority, routeRequest, threshold, issuanceHead,
                            source.RendezvousTrustedTime, deadline.Token, recordedHistory).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
                        break;
                    }
                    catch (DeepIdV2RouteNotBeforeException future) when (
                        attempt < MaximumRenewalThresholdVerificationAttempts && future.RequiredDelaySeconds > 0 &&
                        future.RequiredDelaySeconds < 30 &&
                        Stopwatch.GetElapsedTime(acquisitionStarted) + TimeSpan.FromSeconds(future.RequiredDelaySeconds) < RenewalThresholdAcquisitionBudget)
                    {
                        // No TRS/transition loan or verified admission survives
                        // this wait. The existing account operation remains held;
                        // all actual guards are reacquired on the next iteration.
#if DEEP_TEST_INTERNALS
                        Did2ContactThresholdWaitTestHooks.Hit(Did2ContactThresholdWaitFailpoint.BeforeWait);
#endif
                        await Task.Delay(TimeSpan.FromSeconds(future.RequiredDelaySeconds), deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                        Did2ContactThresholdWaitTestHooks.Hit(Did2ContactThresholdWaitFailpoint.AfterWait);
#endif
                    }
                }
                await RequireThresholdAdoptionGuardsAsync(deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                await AdoptAsync(entry.WithThreshold(verified, networkId, current.AccountId.Span), deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterThreshold);
#endif
            }
            var issuance = await VerifyRetainedRouteIssuanceAsync(entry, authorization, fresh, source, ct).ConfigureAwait(false);
            if (entry.Phase == 2)
            {
                var completed = await DeepIdV2ContactRouteAuthor.CompleteRetainedSuccessorAsync(authorization, fresh.Network,
                    fresh.Authority, current.Verified.DeviceSecrets, priorRoute, issuance, configuration.MinimumReader,
                    source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                await AdoptAsync(entry.WithCompletion(completed, networkId, current.AccountId.Span), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterComplete);
#endif
            }
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct, issuance.RecordedHistory).ConfigureAwait(false);
            if (entry.Phase == 3)
            {
                var contactCandidate = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(route, issuance,
                    priorObject, current.Verified.DeviceSecrets, [DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span)],
                    plan.Profile, capability, ct, serviceHistory).ConfigureAwait(false);
                await AdoptAsync(entry.WithContactObject(contactCandidate, networkId, current.AccountId.Span), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterContactObject);
#endif
            }
            var contact = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, entry.Record(7), entry.Record(8), capability, ct).ConfigureAwait(false);
            if (entry.Phase == 4)
            {
                var nonce = NewRouteRandom32(); var operationId = NewRouteRandom32();
                try
                {
                    var candidate = await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(route, contact,
                        current.Verified.DeviceSecrets, priorPublication, nonce, operationId, ct).ConfigureAwait(false);
                    await AdoptAsync(entry.WithPublicationRequest(candidate.WireRequest, networkId, current.AccountId.Span), ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRenewalRequest);
#endif
                }
                finally { CryptographicOperations.ZeroMemory(nonce); CryptographicOperations.ZeroMemory(operationId); }
            }
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
            VerifiedXpa1PublicationAuthorization? mutationLease = null;
            if (entry.Phase == 5)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                mutationLease = await AcquireCurrentPublicationAsync(route, contact, request,
                    current.Verified.DeviceSecrets, publicationSource, dispatch, deadline.Token).ConfigureAwait(false);
                var response = ContactPublicationAuthorityWireCodec.EncodeResponse(request,
                    new(request.NetworkId.Span, request.RequestNonce.Span, mutationLease.ExactOriginalXpu1.Span));
                try
                {
                    await mutationLease.EnsureCurrentAsync(deadline.Token).ConfigureAwait(false);
                    deadline.Token.ThrowIfCancellationRequested();
                    await AdoptAsync(entry.WithPublicationResponse(response, networkId, current.AccountId.Span), deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRenewalResponse);
#endif
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                mutationLease ??= await AcquireCurrentPublicationAsync(route, contact, request,
                    current.Verified.DeviceSecrets, publicationSource, dispatch, deadline.Token).ConfigureAwait(false);
                if (!CryptographicOperations.FixedTimeEquals(mutationLease.ExactOriginalXpu1.Span, winner.ExactXpu1.Span))
                    throw new CryptographicException("Current successor publication replaced the exact persisted original winner.");
                await mutationLease.EnsureCurrentAsync(deadline.Token).ConfigureAwait(false);
                var returned = await transport.PublishAsync(mutationLease.ExactDispatchRequest, dispatch, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length is < 256 or > DeepIdV2PublicationCommitVerifier.MaximumResultBytes)
                    throw new InvalidDataException("Publication successor commit exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var committed = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact, request,
                        winner.ExactXpu1, response, deadline.Token).ConfigureAwait(false);
                    await mutationLease.EnsureCurrentAsync(deadline.Token).ConfigureAwait(false);
                    using var completed = entry.WithPublicationCommit(committed, networkId, current.AccountId.Span);
                    var replacement = completed.RebindCommittedIntent(plan.Intent.Span, networkId, current.AccountId.Span);
                    // Promotion changes the discoverable publication, not the
                    // lifetime of objects or exact reads on its predecessor.
                    // Reuse the already reserved pending slot for private old
                    // publication custody; no signed bytes/capability change.
                    var retained = prior.RebindCommittedIntent(pendingIntent, networkId, current.AccountId.Span);
                    state.Entries[currentName] = replacement; state.Entries[pendingName] = retained;
                    prior.Dispose(); entry.Dispose(); entry = replacement;
                    deadline.Token.ThrowIfCancellationRequested();
                    await SaveAsync(deadline.Token).ConfigureAwait(false); // Atomic promotion and retention, then readback.
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRenewalPromotion);
#endif
                    var persistedRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(entry.Record(9).Span);
                    var persistedWinner = ContactPublicationAuthorityWireCodec.DecodeResponse(persistedRequest, entry.Record(10).Span);
                    var result = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact, persistedRequest,
                        persistedWinner.ExactXpu1, entry.Record(11), ct).ConfigureAwait(false);
                    await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested(); held.RequireActive(); return result;
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }

            async Task SaveAsync(CancellationToken token)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, token).ConfigureAwait(false);
                var adopted = await SaveRouteJournalAsync(state, snapshot!, current.AccountId, instance, token).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot!); snapshot = adopted;
            }
            async Task RequireThresholdAdoptionGuardsAsync(CancellationToken token)
            {
                // Existing account-owned material is not cached permission.
                // Rejoin the actual key/account, protected source/revocation,
                // same-boot clock, resolver capability and exact proposal.
                using var actual = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, token).ConfigureAwait(false);
                RequirePermanentContactPlan(plan, actual, instance, plan.Intent.Span);
                if (!FixedRoute(actual.AccountId.Span, current.AccountId.Span))
                    throw new CryptographicException("Renewal owner changed during threshold admission.");
                await RecheckRouteFreshnessAsync(actual, source, fresh, held, first, token).ConfigureAwait(false);
                var resolver = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, actual.AccountId.Span)
                    .ReadVerifiedAsync(fresh.Proof.CurrentCheckpoint!.Binding.DeepId, token).ConfigureAwait(false);
                if (!FixedRoute(resolver.ResolverReadCapability.Span, capability))
                    throw new CryptographicException("Renewal resolver custody changed during threshold admission.");
                using var journal = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, token).ConfigureAwait(false) ??
                    throw new InvalidDataException("Renewal proposal disappeared during threshold admission.");
                if (!journal.Use(bytes => FixedRoute(bytes, snapshot!)))
                    throw new CryptographicException("Renewal proposal changed during threshold admission.");
                token.ThrowIfCancellationRequested(); held.RequireOwner(lease);
            }
            async Task AdoptAsync(ProtectedDid2ContactRouteJournal.Entry candidate, CancellationToken token)
            {
                state.Entries[pendingName] = candidate; entry.Dispose(); entry = candidate;
                await SaveAsync(token).ConfigureAwait(false);
            }
            async Task<Did2OwnedContactTransportContext> DispatchAsync(CancellationToken cancellation)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, cancellation).ConfigureAwait(false);
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, cancellation).ConfigureAwait(false);
                return new(custody, fresh.Network, fresh.Authority, held);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
            if (capability is not null) CryptographicOperations.ZeroMemory(capability);
            if (pendingIntent is not null) CryptographicOperations.ZeroMemory(pendingIntent);
        }
    }

    // CONTACT-RESOLVER and TRANSPORT-NEUTRAL-MESSAGING own their proactive margins.
    // Call only after authenticating
    // the original signed interval; this arithmetic is not currentness authority.
    // Round the margin upward, without floating point or multiplying a u64 lifetime.
    internal static ulong ProactiveRefreshAt(ulong issuedAt, ulong expiresAt)
    {
        if (issuedAt == 0 || expiresAt <= issuedAt)
            throw new CryptographicException("Owned authority has no valid signed refresh interval.");
        var lifetime = expiresAt - issuedAt;
        var margin = lifetime / 5 + (lifetime % 5 == 0 ? 0UL : 1UL);
        return expiresAt - margin;
    }

    private static byte[] DeriveContactRenewalIntent(ReadOnlySpan<byte> network, ReadOnlySpan<byte> account,
        ReadOnlySpan<byte> instance, ReadOnlySpan<byte> intent, ReadOnlySpan<byte> committed)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Client/DID2/contact-renewal/v1"u8); hash.AppendData([0]);
        hash.AppendData(network); hash.AppendData(account); hash.AppendData(instance); hash.AppendData(intent);
        var exactHash = SHA256.HashData(committed);
        try { hash.AppendData(exactHash); return hash.GetHashAndReset(); }
        finally { CryptographicOperations.ZeroMemory(exactHash); }
    }
}
