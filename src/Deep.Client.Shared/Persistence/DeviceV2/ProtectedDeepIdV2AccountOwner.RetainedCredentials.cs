using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task<MailboxCredentialLoan> OpenRetainedMailboxWinnerUnderLeaseAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnRetainedPublication publication,
        VerifiedMailboxRetainedReadGrantV2 winner, byte[] protectedWinner, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        await publication.RecheckAsync(ct).ConfigureAwait(false);
        await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(winner.ExactGrant.Span);
        var request = ContactCodec.Decode("XMG2", winner.ExactXmg2.Span);
        if (grant.Domain != MailboxCapabilityDomain.Retrieve ||
            !FixedRoute(ProtectedDid2MailboxGrantJournal.Request(protectedWinner).Span, winner.ExactXmg2.Span) ||
            !FixedRoute(ProtectedDid2MailboxGrantJournal.Response(protectedWinner).Span, winner.ExactXmc2.Span) ||
            !FixedRoute(request.Field(3).Span, publication.Locator.Span) ||
            !FixedRoute(request.Field(4).Span, publication.Capability.Span))
            throw new CryptographicException("Retained credential installation differs from original publication/holder custody.");
        var replicas = await publication.Host.GetSelectedRetainedReadReplicasAsync(winner.ExactGrant, ct).ConfigureAwait(false);
        var ids = publication.Route.Selection.Field(6);
        if (replicas.Count != 2 || ids.Length != 64 ||
            !FixedRoute(replicas[0].NodeId.Span, ids.Span[..32]) ||
            !FixedRoute(replicas[1].NodeId.Span, ids.Span[32..]))
            throw new CryptographicException("Retained installation cannot rerank or replace original selected replicas.");
        var localPolicy = await OpenRetainedInstallationPolicyAsync(current, held, publication, winner, source, fresh, ct).ConfigureAwait(false);
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner? holder = null;
        SqliteDeepMailboxStore? application = null;
        try
        {
            var policy = fresh.MailboxAuthority;
            var authority = new VerifiedOfficialMailboxAuthority(policy.NetworkId, policy.MinimumGrantGeneration,
                [policy.ResolveIssuer(MailboxCapabilityDomain.Retrieve)], false, static () => true, localPolicy, localPolicy.Clock);
            var credential = new VerifiedCurrentMailboxGrant(request, ContactCodec.Decode("XMC2", winner.ExactXmc2.Span),
                grant, publication.Route, replicas.Select(replica =>
                    new VerifiedCurrentMailboxReplica(replica.NodeId.Span, replica.SigningPublicKey.Span)).ToArray(), authority);
            holder = ReachabilityMailboxHolderAuthority.OpenRetainedRead(publication.Route, networkId, publication.Locator,
                publication.Capability, ProtectedDid2MailboxGrantJournal.Seed(protectedWinner), publication.RecheckAsync);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeSql);
#endif
            application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            var selector = await credential.InstallForHolderAsync(application, MailboxCredentialScopeKind.Self, holder, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterSql);
#endif
            var read = await application.RevalidateScopedMailboxDispatchAsync(selector, MailboxAuthenticatedOperation.Retrieve,
                authority, ct).ConfigureAwait(false);
            if (read.Epoch != grant.Epoch || read.ExpiresAtUnixSeconds != grant.ExpiresAtUnixSeconds ||
                !FixedRoute(read.MailboxId.Bytes.Span, credential.MailboxId.Bytes.Span) ||
                !FixedRoute(read.PlacementId.Bytes.Span, credential.PlacementId.Bytes.Span) ||
                !FixedRoute(read.MembershipCommitment.Span, winner.MembershipCommitment.Span) ||
                !FixedRoute(read.Replicas.FirstId.Span, replicas[0].NodeId.Span) ||
                !FixedRoute(read.Replicas.SecondId.Span, replicas[1].NodeId.Span) ||
                !FixedRoute(read.Replicas.FirstSigningKey.Span, replicas[0].SigningPublicKey.Span) ||
                !FixedRoute(read.Replicas.SecondSigningKey.Span, replicas[1].SigningPublicKey.Span))
                throw new CryptographicException("Retained installation differs from independent exact SQL read-back.");
            await publication.RecheckAsync(ct).ConfigureAwait(false); await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
            if (Did2MailboxInstallationTestHooks.HasHeldPathCheck)
            {
                var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage,
                    lease, sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
                await Did2MailboxInstallationTestHooks.CheckHeldPathAsync(new(source, custody, current,
                    fresh, held, publication.Route.ExactBytes, winner), read, ct).ConfigureAwait(false);
            }
#endif
            localPolicy.ValidateFreshness(); held.RequireActive(); ct.ThrowIfCancellationRequested();
            return new(application, holder, localPolicy, authority, selector, read, grant);
        }
        catch { application?.Dispose(); holder?.Dispose(); localPolicy.Dispose(); throw; }
    }

    private static async Task<RetainedMailboxInstallationPolicy> OpenRetainedInstallationPolicyAsync(
        VerifiedDeepIdV2CurrentAccount current, HeldDeepIdV2AccountLease held, OwnRetainedPublication publication,
        VerifiedMailboxRetainedReadGrantV2 winner, DeepIdV2ContactPathAuthoritySource source,
        DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, CancellationToken ct)
    {
        var started = Stopwatch.GetTimestamp();
        await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
        var reading = await RecheckRouteFreshnessAsync(current, source, fresh, held, null, ct).ConfigureAwait(false);
        await publication.Host.EnsureCurrentAsync(ct).ConfigureAwait(false);
        if (!FixedRoute(winner.ExactPma2.Span, fresh.MailboxAuthority.ExactPma2.Span))
            throw new CryptographicException("Retained installation lost the actual current role issuer policy.");
        return new(held, fresh, MailboxAuthenticatedCapabilityCodec.DecodeGrant(winner.ExactGrant.Span), reading, started);
    }

    // An exact local winner policy, NOT a global revocation source or native
    // admission permission. Actual node MGR1/replay owners remain mandatory.
    private sealed class RetainedMailboxInstallationPolicy : IOwnedMailboxInstallationPolicy
    {
        private readonly HeldDeepIdV2AccountLease held;
        private readonly DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh;
        private readonly MailboxAuthenticatedGrant grant;
        private readonly ulong lower, upper, sample;
        private readonly long started;
        private bool disposed;
        internal RetainedMailboxInstallationPolicy(HeldDeepIdV2AccountLease held,
            DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh, MailboxAuthenticatedGrant grant,
            OnionMonotonicReading reading, long started)
        {
            this.held = held; this.fresh = fresh; this.grant = grant; this.started = started;
            var elapsed = checked(reading.SampleSeconds - fresh.Proof.MonotonicSample);
            lower = checked(fresh.Proof.TrustedLowerUnixSeconds + elapsed);
            upper = checked(fresh.Proof.TrustedUpperUnixSeconds + elapsed); sample = reading.SampleSeconds;
            Clock = new InstallationClock(this); ValidateFreshness();
        }
        public TimeProvider Clock { get; }
        private ulong CurrentUpper()
        {
            ObjectDisposedException.ThrowIf(disposed, this); held.RequireActive(); fresh.Network.EnsureCurrent();
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (elapsed < TimeSpan.Zero || elapsed >= TimeSpan.FromSeconds(30))
                throw new CryptographicException("Retained installation exceeded its bounded authenticated loan.");
            var seconds = checked((ulong)Math.Ceiling(elapsed.TotalSeconds));
            var now = checked(upper + seconds);
            var policy = fresh.MailboxAuthority;
            if (grant.Domain != MailboxCapabilityDomain.Retrieve || lower > upper ||
                lower < grant.NotBeforeUnixSeconds || lower < policy.NotBeforeUnixSeconds ||
                checked(sample + seconds) >= fresh.Proof.FreshnessDeadlineMonotonicSeconds ||
                now >= Math.Min(grant.ExpiresAtUnixSeconds,
                    Math.Min(policy.ExpiresAtUnixSeconds, fresh.Network.MaximumRecordExpiryUnixSeconds)))
                throw new CryptographicException("Retained installation lost its complete current authority interval.");
            return now;
        }
        public void ValidateFreshness() => _ = CurrentUpper();
        public bool IsRevoked(MailboxCapabilityRevocationQuery query)
        {
            ArgumentNullException.ThrowIfNull(query); ValidateFreshness();
            return query.Domain != grant.Domain || query.Generation != grant.Generation || query.Epoch != grant.Epoch ||
                !FixedRoute(query.IssuerPublicKey.Span, grant.IssuerPublicKey.Span) ||
                !FixedRoute(query.Serial.Span, grant.Serial.Span) ||
                !FixedRoute(query.MembershipCommitment.Span, grant.MembershipCommitment.Span);
        }
        public void Dispose() => disposed = true;
        private sealed class InstallationClock(RetainedMailboxInstallationPolicy owner) : TimeProvider
        { public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(checked((long)owner.CurrentUpper())); }
    }
}
