using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<AuthoredDeepIdV2ContactObject> EnsureContactObjectAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        StagedDeepIdV2PreKeyPublication staged, Did2ContactRouteConfiguration configuration, string profileName, CancellationToken ct,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage, networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null; byte[]? capability = null;
        try
        {
            RequirePermanentContactPlan(bootstrap, current, instance, intent.Span);
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected route custody is absent; explicit local reset is required.");
            snapshot = owned.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(intent.Span);
            if (!state.Entries.TryGetValue(name, out var entry) || entry.Phase < 3 || !entry.Matches(configuration) ||
                !FixedRoute(entry.Record(0).Span, staged.ExactDca1.Span))
                throw new CryptographicException("Contact object requires the exact retained completed route.");
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(entry.Record(0).Span), checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, first.BootId.Span, first.SampleSeconds);
            var issuance = await VerifyRetainedRouteIssuanceAsync(entry, authorization, fresh, source, ct).ConfigureAwait(false);
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            var permanent = await new ProtectedDeepIdV2ResolverCapabilityStore(storage, networkId, current.AccountId.Span)
                .ReadVerifiedAsync(checkpoint.Binding.DeepId, ct).ConfigureAwait(false);
            capability = permanent.ResolverReadCapability.ToArray();
            if (entry.Phase == 3)
            {
                var service = DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span);
                var candidate = await DeepIdV2ContactObjectAuthor.AuthorRetainedGenesisAsync(route, issuance, current.Verified.DeviceSecrets,
                    [service], profileName, capability, ct).ConfigureAwait(false);
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                var nextEntry = entry.WithContactObject(candidate, networkId, current.AccountId.Span);
                state.Entries[name] = nextEntry; entry.Dispose(); entry = nextEntry;
                var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterContactObject);
#endif
            }
            var result = await DeepIdV2ContactObjectAuthor.RestoreAsync(route, entry.Record(7), entry.Record(8), capability, ct).ConfigureAwait(false);
            // Signed profile and service are fixed under the logical intent.
            var expectedName = System.Text.Encoding.UTF8.GetBytes(profileName);
            var serviceList = result.Closure.Bundle.Field(12).Span;
            if (!FixedRoute(result.Closure.Bundle.Field(15).Span, expectedName) || serviceList.Length != 357 ||
                !FixedRoute(serviceList[5..], staged.ExactXps1.Span))
                throw new CryptographicException("A retained contact object cannot change profile or prekey descriptor.");
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive(); return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(instance);
            if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot);
            if (capability is not null) CryptographicOperations.ZeroMemory(capability);
        }
    }

    internal async Task<VerifiedDeepIdV2ContactRouteClosure> EnsureContactRouteAsync(
        ulong trustedUnixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        ReadOnlyMemory<byte> exactDca, Did2ContactRouteConfiguration configuration,
        IDid2ContactRouteThresholdSource thresholdSource, CancellationToken ct,
        Did2OwnedPermanentContactPlan? bootstrap = null)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(trustedUnixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
            networkId, current.AccountId, ct).ConfigureAwait(false);
        byte[]? snapshot = null;
        try
        {
            RequirePermanentContactPlan(bootstrap, current, instance, intent.Span);
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new InvalidDataException("Protected route custody is absent; explicit local reset is required.");
            snapshot = owned.Use(value => value.ToArray());
            using var state = ProtectedDid2ContactRouteJournal.Decode(snapshot, networkId, current.AccountId.Span, instance);
            var name = Convert.ToHexString(intent.Span);
            var checkpoint = fresh.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(exactDca.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, dca, first.BootId.Span, first.SampleSeconds);
            if (!state.Entries.TryGetValue(name, out var entry))
            {
                if (state.Entries.Count >= ProtectedDid2ContactRouteJournal.MaximumIntents)
                    throw new IOException("Protected route capacity is exhausted.");
                var scalar = NewRouteRandom32(); var keyId = NewRouteRandom32(); var nonce = NewRouteRandom32();
                try
                {
                    var expiry = Math.Min(checked(authorization.TrustedLowerUnixSeconds + 86_400),
                        Math.Min(fresh.Network.MaximumRecordExpiryUnixSeconds, Math.Min(dca.Record.ExpiresAtUnixSeconds,
                            current.Verified.PublicEvidence.Binding.Identity.ActiveDevices.Single().Certificate.ExpiresAtUnixSeconds)));
                    var xra = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(authorization, fresh.Network, fresh.Authority,
                        current.Verified.DeviceSecrets, configuration.Quota, configuration.AntiSpamHash, keyId,
                        DeepIdentityCrypto.DeriveX25519PublicKey(scalar), authorization.TrustedLowerUnixSeconds, expiry,
                        source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                    entry = ProtectedDid2ContactRouteJournal.Entry.Proposal(intent.Span, configuration, scalar, keyId, nonce,
                        exactDca, xra, new ContactRouteAuthorityWireRequest(networkId, nonce,
                            authorization.Freshness.QueriedDirectoryLeafKey.Span,
                            authorization.Freshness.NextProtectedLkg.LogGeneration,
                            authorization.Freshness.NextProtectedLkg.CoreHash.Span, exactDca.Span, xra.CanonicalBytes.Span),
                        networkId, current.AccountId.Span);
                    state.Entries.Add(name, entry);
                    await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                    var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                    CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                    Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterProposal);
#endif
                }
                finally { CryptographicOperations.ZeroMemory(scalar); CryptographicOperations.ZeroMemory(keyId); CryptographicOperations.ZeroMemory(nonce); }
            }
            if (!entry.Matches(configuration) || !FixedRoute(entry.Record(0).Span, exactDca.Span))
                throw new CryptographicException("A retained route intent cannot change configuration or delegation.");
            var pendingRequest = ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span);
            Did2ContactRouteRequestCustody.RequireCurrent(pendingRequest, authorization, fresh.Network);
            if (entry.Phase == 1)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(authorization, fresh.Network, fresh.Authority,
                    entry.Record(1), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                // Response is untrusted; only independent Protocol completion
                // below can release authority. Never pass the metadata scalar.
                using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
                budget.CancelAfter(TimeSpan.FromSeconds(30));
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage, lease,
                    sqlStatePath, current, source.AccountOwner, held, budget.Token).ConfigureAwait(false);
                var dispatch = new Did2OwnedContactTransportContext(custody, fresh.Network, held);
                var response = await thresholdSource.FetchAsync(pendingRequest,
                    authorization, fresh.Network, fresh.Authority, source.RendezvousTrustedTime, dispatch, budget.Token).AsTask()
                    .WaitAsync(budget.Token).ConfigureAwait(false) ?? throw new CryptographicException("The route threshold response is absent.");
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                // Bind response nonce/network before treating parsed records as
                // candidates. Only the closed Protocol verifier authenticates.
                _ = ContactRouteAuthorityWireCodec.EncodeResponse(pendingRequest, response);
                var verified = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(authorization,
                    fresh.Network, fresh.Authority, pendingRequest,
                    new(response.ExactPms2.Span, response.ExactXrc1.Span, response.ExactXss1.Span),
                    response.ExactIssuanceAdh1, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                var candidate = entry.WithThreshold(verified, networkId, current.AccountId.Span);
                state.Entries[name] = candidate; entry.Dispose(); entry = candidate;
                var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterThreshold);
#endif
            }
            var issuance = await VerifyRetainedRouteIssuanceAsync(entry, authorization, fresh, source, ct).ConfigureAwait(false);
            if (entry.Phase == 2)
            {
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                var completed = await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(authorization, fresh.Network, fresh.Authority,
                    current.Verified.DeviceSecrets, issuance, configuration.MinimumReader,
                    source.RendezvousTrustedTime, ct).ConfigureAwait(false);
                await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
                var candidate = entry.WithCompletion(completed, networkId, current.AccountId.Span);
                state.Entries[name] = candidate; entry.Dispose(); entry = candidate;
                var adopted = await SaveRouteJournalAsync(state, snapshot, current.AccountId, instance, ct).ConfigureAwait(false);
                CryptographicOperations.ZeroMemory(snapshot); snapshot = adopted;
#if DEEP_TEST_INTERNALS
                Did2ContactRouteTestHooks.Hit(Did2ContactRouteFailpoint.AfterComplete);
#endif
            }
            var result = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                entry.Record(5), entry.Record(6), source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            await RecheckRouteFreshnessAsync(current, source, fresh, held, first, ct).ConfigureAwait(false);
            await result.EnsureCurrentAsync(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested(); held.RequireActive();
            return result;
        }
        finally { CryptographicOperations.ZeroMemory(instance); if (snapshot is not null) CryptographicOperations.ZeroMemory(snapshot); }
    }

    private static ValueTask<VerifiedDeepIdV2ContactRouteIssuance> VerifyRetainedRouteIssuanceAsync(
        ProtectedDid2ContactRouteJournal.Entry entry, DeepIdV2CurrentContactAuthorization authorization,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        DeepIdV2ContactPathAuthoritySource source, CancellationToken ct)
    {
        var request = ContactRouteAuthorityWireCodec.DecodeRequest(entry.Record(12).Span);
        Did2ContactRouteRequestCustody.RequireCurrent(request, authorization, fresh.Network);
        return DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(authorization, fresh.Network,
            fresh.Authority, request, new(entry.Record(2).Span, entry.Record(3).Span, entry.Record(4).Span),
            entry.Record(13), source.RendezvousTrustedTime, ct);
    }

    private static async Task<OnionMonotonicReading> RecheckRouteFreshnessAsync(VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        HeldDeepIdV2AccountLease held, OnionMonotonicReading? first, CancellationToken ct)
    {
        // Single owned endpoint uses the existing held-lease pair reader with
        // the same proof twice; no synthetic peer identity/proof is created.
        var reading = await source.RecheckEndpointPairUnderLeaseAsync(fresh, fresh.Proof, held, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(current, fresh.Proof, reading.BootId.Span, reading.SampleSeconds);
        if (first is not null && (reading.SampleSeconds < first.SampleSeconds || !FixedRoute(reading.BootId.Span, first.BootId.Span)))
            throw new CryptographicException("Owned route custody crossed a protected clock discontinuity.");
        ct.ThrowIfCancellationRequested(); held.RequireActive(); return reading;
    }

    private async Task<byte[]> SaveRouteJournalAsync(ProtectedDid2ContactRouteJournal.State state, byte[] expected,
        ReadOnlyMemory<byte> account, byte[] instance, CancellationToken ct)
    {
        var next = ProtectedDid2ContactRouteJournal.Encode(state, networkId, account.Span, instance);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!await storage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, expected, next, ct).ConfigureAwait(false))
                throw new IOException("Protected route custody changed during account-owned adoption.");
            using var readback = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, ct).ConfigureAwait(false) ??
                throw new CryptographicException("Adopted route custody is absent.");
            if (!readback.Use(bytes => FixedRoute(bytes, next)))
                throw new CryptographicException("Adopted route custody differs from its exact winner.");
            ct.ThrowIfCancellationRequested(); return next.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(next); }
    }
    private static bool FixedRoute(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static byte[] NewRouteRandom32()
    { var bytes = new byte[32]; do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0); return bytes; }
}
