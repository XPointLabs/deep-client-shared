using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<(Xiq1Request Query, ExactContactResolveOnionResponse Response)> ReadPermanentContactAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepPermanentIdV2 address,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own,
        IExactContactResolveOnionTransport? transport, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(own.Proof,
            current.Verified.PublicEvidence.Authorization, first.BootId.Span, first.SampleSeconds);
        var request = await DeepIdV2PermanentContactResolveRequestAuthor.AuthorAsync(address, authorization,
            own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(
            storage, lease, sqlStatePath, current, source.AccountOwner, held, budget.Token).ConfigureAwait(false);
        transport ??= new DeepIdV2PublicationOnionTransport(source, custody);
        if (transport is not IDid2OwnedExactContactResolveOnionTransport owned)
            throw new NotSupportedException("Owned permanent read requires an explicit owned ONION transport.");
        var operation = new Did2OwnedContactTransportContext(custody, own.Network, own.Authority, held);
        var canonical = ContactResolveCanonicalPathRequest.Decode(request.CanonicalBytes.Span);
        var placement = ContactServicePlacementFactory.Create(own.Network, ContactServiceRequestKind.ResolveInvite, request.LocatorHash);
        // One bounded read, not an automatic retry or a mutation.
        var response = await owned.SendOwnedExactAsync(canonical, placement.RankedReplicaNodeIds[0], operation,
            budget.Token).AsTask().WaitAsync(budget.Token).ConfigureAwait(false);
        await RecheckRouteFreshnessAsync(current, source, own, held, first, budget.Token).ConfigureAwait(false);
        budget.Token.ThrowIfCancellationRequested(); held.RequireActive(); return (request, response);
    }

    internal async Task<VerifiedDeepIdV2PermanentContactResolveClosure> RecheckPermanentContactAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var result = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        return result.Contact;
    }

    private static async Task<(VerifiedDeepIdV2PermanentContactResolveClosure Contact, DeepIdV2ContactRouteTimeWindow Time)>
        RecheckPermanentContactUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        HeldDeepIdV2AccountLease held, CancellationToken ct)
    {
        var peer = resolved.Contact.Authorization.Freshness;
        var first = await RequireMessagingFreshnessAsync(current, resolved.Own, peer, source, held, ct).ConfigureAwait(false);
        var result = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(resolved.Contact.Candidate,
            peer, resolved.Own.Network, resolved.Own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        var final = await RequireMessagingFreshnessAsync(current, resolved.Own, peer, source, held, ct).ConfigureAwait(false);
        if (final.SampleSeconds < first.SampleSeconds || !FixedRoute(first.BootId.Span, final.BootId.Span))
            throw new CryptographicException("Permanent contact resolution crossed a protected clock discontinuity.");
        var routeTime = await result.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        if (routeTime.MonotonicSample < final.SampleSeconds || !FixedRoute(routeTime.BootId.Span, final.BootId.Span))
            throw new CryptographicException("Permanent contact route clock reversed after the protected floor recheck.");
        ct.ThrowIfCancellationRequested(); held.RequireActive(); return (result, routeTime);
    }

    internal async Task<ParsedXpk1V2> PreparePermanentContactClaimAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var prepared = await PreparePermanentContactClaimUnderLeaseAsync(current, held, intent, source,
            resolved, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        return prepared.Request;
    }

    // Preparation and this single dispatch share the real owner lease. The
    // existing borrowed custody/transport loan prevents recursive acquisition
    // or a second network-floor advancement halfway through the exact claim.
    internal async Task<(ParsedXpk1V2 Request, VerifiedXpc1V2ReplicaSignatures Result)> ClaimPermanentContactAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        int maximumMessagesWithoutPqInjection, IExactContactResolveOnionTransport? onion, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        using var prepared = await PreparePermanentContactClaimUnderLeaseAsync(current, held, intent, source,
            resolved, maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(30));
        var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedClaimRequestCustodyAsync(
            storage, lease, sqlStatePath, current, held, budget.Token).ConfigureAwait(false);
        var transportCustody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(
            storage, lease, sqlStatePath, current, source.AccountOwner, held, budget.Token).ConfigureAwait(false);
        onion ??= new DeepIdV2PublicationOnionTransport(source, transportCustody);
        var operation = new Did2OwnedContactTransportContext(transportCustody, resolved.Own.Network, resolved.Own.Authority, held);
        var result = await new DeepIdV2PreKeyClaimTransport(source, onion, custody)
            .ClaimOwnedExactAsync(prepared.Request.CanonicalBytes, operation, budget.Token).ConfigureAwait(false);
        var final = await RequireClaimContactTimeAsync(current, source, resolved, held,
            prepared.Contact, prepared.Time, budget.Token).ConfigureAwait(false);
        var own = DeepIdV2CurrentContactAuthorizationVerifier.Verify(resolved.Own.Proof,
            current.Verified.PublicEvidence.Authorization, final.BootId.Span, final.MonotonicSample);
        SqliteDeepIdV2AccountGeneration.RequireResolvedContactClaimCurrent(prepared.Request, prepared.Started,
            prepared.Contact, resolved.Own.Network, final, own);
        await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, prepared.Contact,
            held, intent, budget.Token).ConfigureAwait(false);
        budget.Token.ThrowIfCancellationRequested(); held.RequireActive();
        return (prepared.Request, result);
    }

    private async Task<PreparedPermanentContactClaim> PreparePermanentContactClaimUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> intent,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved,
        int maximumMessagesWithoutPqInjection, CancellationToken ct)
    {
        held.RequireOwner(lease);
        var checkedContact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, checkedContact.Contact, held, intent, ct).ConfigureAwait(false);
        using (var completed = await SqliteDeepIdV2AccountGeneration.OpenCurrentDeviceStateStoreAsync(
            storage, sqlStatePath, current, ct).ConfigureAwait(false))
            if (await completed.HasCompletedInitialSessionAsync(intent, ct).ConfigureAwait(false))
                throw new InvalidOperationException("This intent is completed; recover exact session custody instead of reclaiming.");
        var started = await SqliteDeepIdV2AccountGeneration.BeginOrRestorePreClaimUnderLeaseAsync(
            storage, current, intent, resolved.Own.Proof, checkedContact.Time.BootId,
            checkedContact.Time.MonotonicSample, source.RendezvousTrustedTime,
            maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
        try
        {
            var beforeStorage = await RequireClaimContactTimeAsync(current, source, resolved, held,
                checkedContact.Contact, checkedContact.Time, ct).ConfigureAwait(false);
            var own = DeepIdV2CurrentContactAuthorizationVerifier.Verify(resolved.Own.Proof,
                current.Verified.PublicEvidence.Authorization, beforeStorage.BootId.Span, beforeStorage.MonotonicSample);
            var request = await SqliteDeepIdV2AccountGeneration.ReserveResolvedContactClaimUnderLeaseAsync(
                storage, lease, sqlStatePath, current, started, checkedContact.Contact, resolved.Own.Network,
                beforeStorage, own, held, ct).ConfigureAwait(false);
            var final = await RequireClaimContactTimeAsync(current, source, resolved, held,
                checkedContact.Contact, beforeStorage, ct).ConfigureAwait(false);
            own = DeepIdV2CurrentContactAuthorizationVerifier.Verify(resolved.Own.Proof,
                current.Verified.PublicEvidence.Authorization, final.BootId.Span, final.MonotonicSample);
            SqliteDeepIdV2AccountGeneration.RequireResolvedContactClaimCurrent(request, started,
                checkedContact.Contact, resolved.Own.Network, final, own);
            await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, checkedContact.Contact, held, intent, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); held.RequireActive();
            return new(started, request, checkedContact.Contact, final);
        }
        catch { started.Dispose(); throw; }
    }

    private sealed class PreparedPermanentContactClaim(InitiatorDph2PreKeyClaim started, ParsedXpk1V2 request,
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactRouteTimeWindow time) : IDisposable
    {
        internal InitiatorDph2PreKeyClaim Started { get; } = started;
        internal ParsedXpk1V2 Request { get; } = request;
        internal VerifiedDeepIdV2PermanentContactResolveClosure Contact { get; } = contact;
        internal DeepIdV2ContactRouteTimeWindow Time { get; } = time;
        public void Dispose() => Started.Dispose();
    }

    private static async Task<DeepIdV2ContactRouteTimeWindow> RequireClaimContactTimeAsync(
        VerifiedDeepIdV2CurrentAccount current, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.PermanentContactAuthority resolved, HeldDeepIdV2AccountLease held,
        VerifiedDeepIdV2PermanentContactResolveClosure contact, DeepIdV2ContactRouteTimeWindow prior, CancellationToken ct)
    {
        var reading = await RequireMessagingFreshnessAsync(current, resolved.Own,
            contact.Authorization.Freshness, source, held, ct).ConfigureAwait(false);
        if (reading.SampleSeconds < prior.MonotonicSample || !FixedRoute(reading.BootId.Span, prior.BootId.Span))
            throw new CryptographicException("Owned claim preparation crossed protected clock continuity.");
        var time = await contact.Route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        RequireCurrentClaimRead(time.MonotonicSample, time.BootId.Span, reading.SampleSeconds, reading.BootId.Span,
            contact.Candidate.Request.IssuedAtUnixSeconds, contact.Candidate.Request.ExpiresAtUnixSeconds,
            time.LowerUnixSeconds, time.UpperUnixSeconds);
        return time;
    }

    // Same predicates and order as the former combined guard. Labels contain
    // no clock values; they distinguish failure without changing authority.
    internal static void RequireCurrentClaimRead(ulong routeSample, ReadOnlySpan<byte> routeBoot,
        ulong freshnessSample, ReadOnlySpan<byte> freshnessBoot, ulong issued, ulong expires,
        ulong lower, ulong upper)
    {
        if (routeSample < freshnessSample)
            throw new CryptographicException("Owned claim route clock precedes the protected freshness reading.");
        if (!FixedRoute(routeBoot, freshnessBoot))
            throw new CryptographicException("Owned claim route clock changed its protected boot.");
        if (issued > lower)
            throw new CryptographicException("Owned claim read issuance exceeds trusted lower time.");
        if (expires <= upper)
            throw new CryptographicException("Owned claim read expiry does not cover trusted upper time.");
    }
}
