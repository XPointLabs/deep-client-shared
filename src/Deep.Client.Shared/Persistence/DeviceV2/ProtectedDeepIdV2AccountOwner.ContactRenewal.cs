using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
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
                priorObject.Closure.Bundle.Field(12).Length != 357 ||
                !FixedRoute(priorObject.Closure.Bundle.Field(12).Span[5..], staged.ExactXps1.Span))
                throw new CryptographicException("Permanent-contact renewal requires separately authorized profile/service rollover.");
            var priorRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(prior.Record(9).Span);
            var priorWinner = ContactPublicationAuthorityWireCodec.DecodeResponse(priorRequest, prior.Record(10).Span);
            var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(authorization, fresh.Network,
                fresh.Authority, priorObject, priorRequest, priorWinner.ExactXpu1, prior.Record(11),
                source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            pendingIntent = DeriveContactRenewalIntent(networkId, current.AccountId.Span, instance, plan.Intent.Span, prior.Exact);
            var pendingName = Convert.ToHexString(pendingIntent);
            if (!state.Entries.TryGetValue(pendingName, out var entry))
            {
                // Derive the decision only from authenticated signed expiry and
                // independently current time. Corruption is not expiry recovery.
                var now = await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, now.BootId.Span, now.SampleSeconds);
                var expiry = Math.Min(BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1", prior.Record(1).Span).Field(13).Span),
                    BinaryPrimitives.ReadUInt64BigEndian(priorObject.Closure.Bundle.Field(18).Span));
                if (authorization.TrustedUpperUnixSeconds < expiry) return null;
                var scalar = NewRouteRandom32(); var keyId = NewRouteRandom32(); var nonce = NewRouteRandom32();
                try
                {
                    var nextExpiry = Math.Min(checked(authorization.TrustedLowerUnixSeconds + 86_400),
                        Math.Min(fresh.Network.MaximumRecordExpiryUnixSeconds, Math.Min(dca.Record.ExpiresAtUnixSeconds,
                            current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds)));
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
            var routeRequest = ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span);
            if (!routeRequest.HasPredecessor || !FixedRoute(routeRequest.ExactPredecessorXir1V2.Span, prior.Record(5).Span) ||
                !FixedRoute(routeRequest.ExactPredecessorRouteClosure.Span, prior.Record(6).Span))
                throw new CryptographicException("Pending renewal substituted its committed predecessor.");
            Did2ContactRouteRequestCustody.RequireCurrent(routeRequest, authorization, fresh.Network);
            await DeepIdV2ContactRouteVerifier.VerifyAdvertisementSuccessorAsync(authorization, fresh.Network,
                fresh.Authority, priorRoute, entry.Record(1), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (entry.Phase == 1)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                var response = await thresholdSource.FetchAsync(routeRequest, authorization, fresh.Network, fresh.Authority,
                    source.RendezvousTrustedTime, dispatch, deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false) ??
                    throw new CryptographicException("The route successor threshold response is absent.");
                _ = ContactRouteAuthorityWireCodec.EncodeResponse(routeRequest, response);
                var verified = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(authorization, fresh.Network,
                    fresh.Authority, routeRequest, new(response.ExactPms2.Span, response.ExactXrc1.Span, response.ExactXss1.Span),
                    response.ExactIssuanceAdh1, source.RendezvousTrustedTime, deadline.Token).ConfigureAwait(false);
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
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            if (entry.Phase == 3)
            {
                var contactCandidate = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(route, issuance,
                    priorObject, current.Verified.DeviceSecrets, [DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span)],
                    plan.Profile, capability, ct).ConfigureAwait(false);
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
            await DeepIdV2PublicationAuthorityAuthor.VerifySuccessorRequestAsync(route, request, priorPublication, ct).ConfigureAwait(false);
            if (entry.Phase == 5)
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                var returned = await publicationSource.FetchAsync(request, dispatch, deadline.Token).AsTask().WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length is < ContactPublicationAuthorityWireCodec.MinimumResponseBytes or > ContactPublicationAuthorityWireCodec.MaximumResponseBytes)
                    throw new InvalidDataException("Publication successor response exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var candidate = ContactPublicationAuthorityWireCodec.DecodeResponse(request, response);
                    _ = await DeepIdV2PublicationAuthorityAuthor.VerifySuccessorResponseAsync(route, request, priorPublication,
                        candidate.ExactXpu1, deadline.Token).ConfigureAwait(false);
                    deadline.Token.ThrowIfCancellationRequested();
                    await AdoptAsync(entry.WithPublicationResponse(response, networkId, current.AccountId.Span), deadline.Token).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterRenewalResponse);
#endif
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(request, entry.Record(10).Span);
            _ = await DeepIdV2PublicationAuthorityAuthor.VerifySuccessorResponseAsync(route, request, priorPublication, winner.ExactXpu1, ct).ConfigureAwait(false);
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(30));
                var dispatch = await DispatchAsync(deadline.Token).ConfigureAwait(false);
                var returned = await transport.PublishAsync(winner.ExactXpu1, dispatch, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
                if (returned.Length is < 256 or > DeepIdV2PublicationCommitVerifier.MaximumResultBytes)
                    throw new InvalidDataException("Publication successor commit exceeds its exact bound.");
                var response = returned.ToArray();
                try
                {
                    var committed = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(route, contact, request,
                        winner.ExactXpu1, response, deadline.Token).ConfigureAwait(false);
                    _ = await DeepIdV2PublicationAuthorityAuthor.VerifySuccessorResponseAsync(route, request, priorPublication,
                        winner.ExactXpu1, deadline.Token).ConfigureAwait(false);
                    using var completed = entry.WithPublicationCommit(committed, networkId, current.AccountId.Span);
                    var replacement = completed.RebindCommittedIntent(plan.Intent.Span, networkId, current.AccountId.Span);
                    state.Entries[currentName] = replacement; state.Entries.Remove(pendingName);
                    prior.Dispose(); entry.Dispose(); entry = replacement;
                    deadline.Token.ThrowIfCancellationRequested();
                    await SaveAsync(deadline.Token).ConfigureAwait(false); // Atomic replacement, then independent readback.
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
                return new(custody, fresh.Network, held);
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
