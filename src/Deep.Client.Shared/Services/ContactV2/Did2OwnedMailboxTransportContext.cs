using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Services.ContactV2;

// Closed internal account-operation loan, not a fresh-proof fetch or grant
// installation factory. Only the owner composes this from its held read-back.
internal sealed class Did2OwnedMailboxTransportContext : IMailboxPrivacyNetworkAuthoritySource
{
    private readonly VerifiedDeepIdV2CurrentAccount account;
    private readonly DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh;
    private readonly HeldDeepIdV2AccountLease held;
    private readonly VerifiedDeepIdV2ContactRouteClosure? route;
    private readonly VerifiedDeepIdV2MailboxGrant? grant;
    private readonly VerifiedMailboxRetainedReadGrantV2? retainedRead;
    private readonly byte[]? originalRoute;
    private readonly long started = Stopwatch.GetTimestamp();

    internal Did2OwnedMailboxTransportContext(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody, VerifiedDeepIdV2CurrentAccount account,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        HeldDeepIdV2AccountLease held, VerifiedDeepIdV2ContactRouteClosure route,
        VerifiedDeepIdV2MailboxGrant grant)
    {
        Source = source; Custody = custody; this.account = account; this.fresh = fresh;
        this.held = held; this.route = route; this.grant = grant;
        source.RequireAccountOwner(custody.Owner); held.RequireActive();
        if (!ReferenceEquals(route.Network, fresh.Network))
            throw new CryptographicException("Held mailbox transport differs from the actual owned network.");
    }

    internal Did2OwnedMailboxTransportContext(DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2OnionClientCustody custody, VerifiedDeepIdV2CurrentAccount account,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        HeldDeepIdV2AccountLease held, ReadOnlyMemory<byte> exactOriginalRoute,
        VerifiedMailboxRetainedReadGrantV2 retainedRead)
    {
        Source = source; Custody = custody; this.account = account; this.fresh = fresh;
        this.held = held; this.retainedRead = retainedRead;
        originalRoute = ContactRouteClosureCodec.Decode(exactOriginalRoute.Span).ExactBytes.ToArray();
        source.RequireAccountOwner(custody.Owner); held.RequireActive();
        var request = ContactCodec.Decode("XMG2", retainedRead.ExactXmg2.Span);
        if (retainedRead.Domain != MailboxCapabilityDomain.Retrieve ||
            !CryptographicOperations.FixedTimeEquals(request.Field(1).Span, fresh.Network.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(request.Field(11).Span, SHA256.HashData(originalRoute)))
            throw new CryptographicException("Retained transport differs from its held original selection.");
    }

    internal DeepIdV2ContactPathAuthoritySource Source { get; }
    internal DeepIdV2OnionClientCustody Custody { get; }

    internal async ValueTask RequireCurrentAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); held.RequireActive();
        var elapsed = Stopwatch.GetElapsedTime(started);
        if (elapsed < TimeSpan.Zero || elapsed >= TimeSpan.FromSeconds(30))
            throw new CryptographicException("Held mailbox transport exceeded its one-attempt loan.");
        // These are source-owned readonly existing-floor readers, not the fetch
        // gate or account APIs which would reacquire the lock already held here.
        var reading = await Source.RecheckEndpointPairUnderLeaseAsync(fresh, fresh.Proof, held, ct).ConfigureAwait(false);
        _ = DeepIdV2AccountService.RequireOwnCurrentDirectory(account, fresh.Proof, reading.BootId.Span, reading.SampleSeconds);
        if (retainedRead is not null)
        {
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(fresh.Network, fresh.Authority,
                fresh.MailboxAuthority.ExactPma2, Source.RendezvousTrustedTime, ct).ConfigureAwait(false);
            _ = await host.VerifyRetainedReadSuccessAsync(originalRoute!, retainedRead.ExactXmg2,
                retainedRead.ExactXmc2, ct).ConfigureAwait(false);
            await retainedRead.EnsureCurrentAsync(ct).ConfigureAwait(false);
        }
        else
        {
            _ = await DeepIdV2MailboxGrantResultVerifier.VerifyRetainedSuccessAsync(route!,
                grant!.ExactXmg2, grant.ExactXmc2, fresh.MailboxAuthority.ExactPma2, ct).ConfigureAwait(false);
            await grant.EnsureCurrentAsync(ct).ConfigureAwait(false);
        }
        if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(30))
            throw new CryptographicException("Held mailbox transport expired during its authority check.");
        ct.ThrowIfCancellationRequested(); held.RequireActive();
    }

    public async ValueTask<VerifiedOnionNetworkContext> GetCurrentForMailboxAsync(
        ReadOnlyMemory<byte> placementCommitment, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (placementCommitment.Length != 32)
            throw new CryptographicException("Held mailbox path requires its exact placement commitment.");
        var exact = placementCommitment.ToArray();
        try
        {
            var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant((retainedRead?.ExactGrant ?? grant!.ExactGrant).Span);
            if (!CryptographicOperations.FixedTimeEquals(exact, decoded.PlacementCommitment.Span))
                throw new CryptographicException("Held mailbox path changed its installed placement.");
            await RequireCurrentAsync(ct).ConfigureAwait(false); return fresh.Network;
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }
}
