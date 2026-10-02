using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Identity;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    internal async Task<Xiq1Request> AuthorPermanentContactQueryAsync(
        ulong unixSeconds, IDeepMlDsa65Verifier verifier, DeepPermanentIdV2 address,
        DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority own, CancellationToken ct)
    {
        using var held = await lease.AcquireAsync(ct).ConfigureAwait(false);
        using var current = await RequireCurrentUnderLeaseAsync(unixSeconds, verifier, ct).ConfigureAwait(false);
        var first = await RecheckRouteFreshnessAsync(current, source, own, held, null, ct).ConfigureAwait(false);
        var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(own.Proof,
            current.Verified.PublicEvidence.Authorization, first.BootId.Span, first.SampleSeconds);
        var request = await DeepIdV2PermanentContactResolveRequestAuthor.AuthorAsync(address, authorization,
            own.Network, own.Authority, source.RendezvousTrustedTime, ct).ConfigureAwait(false);
        await RecheckRouteFreshnessAsync(current, source, own, held, first, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested(); held.RequireActive(); return request;
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
        var checkedContact = await RecheckPermanentContactUnderLeaseAsync(current, source, resolved, held, ct).ConfigureAwait(false);
        await RequireInitialContactDraftForClaimUnderLeaseAsync(current, source, resolved, checkedContact.Contact, held, intent, ct).ConfigureAwait(false);
        using (var completed = await SqliteDeepIdV2AccountGeneration.OpenCurrentDeviceStateStoreAsync(
            storage, sqlStatePath, current, ct).ConfigureAwait(false))
            if (await completed.HasCompletedInitialSessionAsync(intent, ct).ConfigureAwait(false))
                throw new InvalidOperationException("This intent is completed; recover exact session custody instead of reclaiming.");
        using var started = await SqliteDeepIdV2AccountGeneration.BeginOrRestorePreClaimUnderLeaseAsync(
            storage, current, intent, resolved.Own.Proof, checkedContact.Time.BootId,
            checkedContact.Time.MonotonicSample, source.RendezvousTrustedTime,
            maximumMessagesWithoutPqInjection, ct).ConfigureAwait(false);
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
        ct.ThrowIfCancellationRequested(); held.RequireActive(); return request;
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
        if (time.MonotonicSample < reading.SampleSeconds || !FixedRoute(time.BootId.Span, reading.BootId.Span) ||
            contact.Candidate.Request.IssuedAtUnixSeconds > time.LowerUnixSeconds ||
            contact.Candidate.Request.ExpiresAtUnixSeconds <= time.UpperUnixSeconds)
            throw new CryptographicException("Owned claim preparation no longer has a current contact read.");
        return time;
    }
}
