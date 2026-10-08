using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class ProtectedDeepIdV2AccountOwner
{
    private async Task InstallMailboxWinnerUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, VerifiedDeepIdV2ContactRouteClosure route,
        VerifiedDeepIdV2MailboxGrant winner, ReadOnlyMemory<byte> locator,
        ReadOnlyMemory<byte> capability, byte[] protectedWinner,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Func<CancellationToken, Task> recheck, CancellationToken ct)
    {
        using var installed = await OpenMailboxWinnerUnderLeaseAsync(current, held, route, winner,
            locator, capability, protectedWinner, source, fresh, recheck, ct).ConfigureAwait(false);
    }

    private async Task<MailboxCredentialLoan> OpenMailboxWinnerUnderLeaseAsync(VerifiedDeepIdV2CurrentAccount current,
        HeldDeepIdV2AccountLease held, VerifiedDeepIdV2ContactRouteClosure route,
        VerifiedDeepIdV2MailboxGrant winner, ReadOnlyMemory<byte> locator,
        ReadOnlyMemory<byte> capability, byte[] protectedWinner,
        DeepIdV2ContactPathAuthoritySource source, DeepIdV2ContactPathAuthoritySource.OwnPreKeyAuthoringAuthority fresh,
        Func<CancellationToken, Task> recheck, CancellationToken ct)
    {
        held.RequireActive(); await recheck(ct).ConfigureAwait(false);
        await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
        // Start before the asynchronous authenticated sample: subsequent synchronous
        // SQL checks may overestimate elapsed time, never underestimate it.
        var started = Stopwatch.GetTimestamp();
        var time = await route.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
        var policy = MailboxAuthorityV2Verifier.Verify(route.NetworkAuthority, winner.ExactPma2.Span,
            time.LowerUnixSeconds, time.UpperUnixSeconds);
        if (!policy.BindsProjection(route.Route.Projection.CanonicalBytes.Span))
            throw new CryptographicException("Owned mailbox installation lost its exact current issuer projection.");
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(winner.ExactGrant.Span);
        var localPolicy = new MailboxInstallationPolicy(held, route, policy, grant, time, started);
        ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner? holder = null;
        SqliteDeepMailboxStore? application = null;
        try
        {
            var authority = new VerifiedOfficialMailboxAuthority(policy.NetworkId, policy.MinimumGrantGeneration,
                [policy.ResolveIssuer(grant.Domain)], requiresManagedEntitlement: false,
                static () => true, localPolicy, localPolicy.Clock);
            // PMS names mailbox replicas, not the two ResolveInvite stores which
            // attested private capability lookup for issuance.
            var ids = route.Route.Selection.Field(6);
            if (ids.Length != 64)
                throw new CryptographicException("Owned mailbox installation has no exact replica pair.");
            var first = ids[..32]; var second = ids.Slice(32, 32);
            var verified = new VerifiedCurrentMailboxGrant(
                ContactCodec.Decode("XMG2", winner.ExactXmg2.Span),
                ContactCodec.Decode("XMC2", winner.ExactXmc2.Span), grant, route.Route,
                [new(first.Span, route.Network.ResolveNodeIdentityPublicKey(first).Span),
             new(second.Span, route.Network.ResolveNodeIdentityPublicKey(second).Span)], authority);
            holder = ReachabilityMailboxHolderAuthority.OpenRetained(route, locator,
                capability, grant.Domain, ProtectedDid2MailboxGrantJournal.Seed(protectedWinner));
#if DEEP_TEST_INTERNALS
        Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.BeforeSql);
#endif
            application = await SqliteDeepIdV2AccountGeneration.OpenApplicationUnderLeaseAsync(
                storage, sqlStatePath, current, held, ct).ConfigureAwait(false);
            var selector = await verified.InstallForHolderAsync(application,
                grant.Domain == MailboxCapabilityDomain.Retrieve ? MailboxCredentialScopeKind.Self : MailboxCredentialScopeKind.Peer,
                holder, ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        Did2MailboxInstallationTestHooks.Hit(Did2MailboxInstallationFailpoint.AfterSql);
#endif
            var operation = grant.Domain == MailboxCapabilityDomain.Retrieve ?
                MailboxAuthenticatedOperation.Retrieve : MailboxAuthenticatedOperation.Store;
            // Reopen through the actual SQL resolver/issuer checks; Install success
            // alone is not read-back evidence or dispatch permission.
            var read = await application.RevalidateScopedMailboxDispatchAsync(selector, operation, authority, ct).ConfigureAwait(false);
            if (read.Epoch != grant.Epoch || read.ExpiresAtUnixSeconds != grant.ExpiresAtUnixSeconds ||
                !FixedRoute(read.MailboxId.Bytes.Span, verified.MailboxId.Bytes.Span) ||
                !FixedRoute(read.PlacementId.Bytes.Span, verified.PlacementId.Bytes.Span) ||
                !FixedRoute(read.MembershipCommitment.Span, winner.MembershipCommitment.Span) ||
                !FixedRoute(read.Replicas.FirstId.Span, first.Span) ||
                !FixedRoute(read.Replicas.SecondId.Span, second.Span) ||
                !FixedRoute(read.Replicas.FirstSigningKey.Span, route.Network.ResolveNodeIdentityPublicKey(first).Span) ||
                !FixedRoute(read.Replicas.SecondSigningKey.Span, route.Network.ResolveNodeIdentityPublicKey(second).Span))
                throw new CryptographicException("Owned mailbox credential differs from independent SQL read-back.");
            await recheck(ct).ConfigureAwait(false); await winner.EnsureCurrentAsync(ct).ConfigureAwait(false);
#if DEEP_TEST_INTERNALS
        if (Did2MailboxInstallationTestHooks.HasHeldPathCheck)
        {
            var custody = await SqliteDeepIdV2AccountGeneration.OpenBorrowedOnionCustodyAsync(storage,
                lease, sqlStatePath, current, source.AccountOwner, held, ct).ConfigureAwait(false);
            await Did2MailboxInstallationTestHooks.CheckHeldPathAsync(new(source, custody, current,
                fresh, held, route, winner), read, ct).ConfigureAwait(false);
        }
#endif
            localPolicy.ValidateFreshness(); ct.ThrowIfCancellationRequested(); held.RequireActive();
            return new(application, holder, localPolicy, authority, selector, read, grant);
        }
        catch { application?.Dispose(); holder?.Dispose(); localPolicy.Dispose(); throw; }
    }

    // The loan type is private to the account owner. Neither a signer nor an
    // authority is returned by an application/service/transport API.
    private sealed class MailboxCredentialLoan : IDisposable
    {
        private readonly ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder;
        private readonly IOwnedMailboxInstallationPolicy policy;
        internal MailboxCredentialLoan(SqliteDeepMailboxStore store,
            ReachabilityMailboxHolderAuthority.ReachabilityMailboxHolderSigner holder,
            IOwnedMailboxInstallationPolicy policy, VerifiedOfficialMailboxAuthority authority,
            MailboxCredentialSelector selector, ScopedMailboxResolvedRoute route, MailboxAuthenticatedGrant grant)
        {
            Store = store; this.holder = holder; this.policy = policy; Authority = authority;
            Selector = selector; Route = route; Grant = grant; Signer = new ExactGrantSigner(this);
        }
        internal SqliteDeepMailboxStore Store { get; }
        internal VerifiedOfficialMailboxAuthority Authority { get; }
        internal MailboxCredentialSelector Selector { get; }
        internal ScopedMailboxResolvedRoute Route { get; }
        internal MailboxAuthenticatedGrant Grant { get; }
        internal IMailboxOperationSigner Signer { get; }
        internal ulong MinimumCounter { get; set; } = 1;
        public void Dispose() { policy.Dispose(); holder.Dispose(); Store.Dispose(); }
        private sealed class ExactGrantSigner(MailboxCredentialLoan owner) : IMailboxOperationSigner
        {
            public byte[] GetEd25519PublicKey() { owner.policy.ValidateFreshness(); return owner.holder.GetEd25519PublicKey(); }
            public byte[] SignMailboxPresentation(MailboxAuthenticatedOperation operation, ReadOnlySpan<byte> input)
            {
                owner.policy.ValidateFreshness();
                const int tag = 16;
                var exact = MailboxAuthenticatedCapabilityCodec.EncodeGrant(owner.Grant);
                try
                {
                    if (input.Length != tag + MailboxAuthenticatedCapabilityLimits.PresentationLength -
                        MailboxAuthenticatedCapabilityLimits.SignatureLength ||
                        !FixedRoute(input.Slice(tag + 72, MailboxAuthenticatedCapabilityLimits.GrantLength), exact) ||
                        BinaryPrimitives.ReadUInt64BigEndian(input.Slice(tag + 24)) < owner.MinimumCounter)
                        throw new CryptographicException("Owned MCP3 signing differs from the protected exact grant/counter floor.");
                    return owner.holder.SignMailboxPresentation(operation, input);
                }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
        }
    }

    // Owner-private, single-installation lifetime. This does not invent an empty
    // global revocation list: every foreign serial/role/epoch is denied, while
    // current PMA2 minimum generation and independently verified closure bind
    // the one exact winner. No factory/authority escapes this held operation.
    private interface IOwnedMailboxInstallationPolicy : IFreshMailboxCapabilityRevocationSource, IDisposable
    {
        TimeProvider Clock { get; }
    }

    private sealed class MailboxInstallationPolicy : IOwnedMailboxInstallationPolicy
    {
        private readonly HeldDeepIdV2AccountLease held;
        private readonly VerifiedDeepIdV2ContactRouteClosure route;
        private readonly VerifiedMailboxAuthorityV2 policy;
        private readonly MailboxAuthenticatedGrant grant;
        private readonly DeepIdV2ContactRouteTimeWindow sample;
        private readonly long started;
        private bool disposed;

        internal MailboxInstallationPolicy(HeldDeepIdV2AccountLease held,
            VerifiedDeepIdV2ContactRouteClosure route, VerifiedMailboxAuthorityV2 policy,
            MailboxAuthenticatedGrant grant, DeepIdV2ContactRouteTimeWindow sample, long started)
        {
            this.held = held; this.route = route; this.policy = policy; this.grant = grant;
            this.sample = sample; this.started = started; Clock = new InstallationClock(this);
            ValidateFreshness();
        }

        public TimeProvider Clock { get; }

        private ulong CurrentUpper()
        {
            ObjectDisposedException.ThrowIf(disposed, this); held.RequireActive(); route.Network.EnsureCurrent();
            var elapsed = Stopwatch.GetElapsedTime(started);
            if (elapsed < TimeSpan.Zero || elapsed >= TimeSpan.FromSeconds(30))
                throw new CryptographicException("Owned mailbox installation exceeded its bounded authenticated scope.");
            var upper = checked(sample.UpperUnixSeconds + (ulong)Math.Ceiling(elapsed.TotalSeconds));
            var expiry = new[] { grant.ExpiresAtUnixSeconds, policy.ExpiresAtUnixSeconds,
                route.Network.MaximumRecordExpiryUnixSeconds,
                U64(route.Route.Reachability.Field(17).Span), U64(route.Route.Authorization.Field(13).Span),
                U64(route.Route.Route.Field(18).Span), U64(route.Route.Successor.Field(11).Span),
                U64(route.Route.Projection.Field(12).Span), U64(route.Route.Selection.Field(9).Span) }.Min();
            if (sample.LowerUnixSeconds > sample.UpperUnixSeconds ||
                sample.LowerUnixSeconds < grant.NotBeforeUnixSeconds ||
                sample.LowerUnixSeconds < policy.NotBeforeUnixSeconds || upper >= expiry)
                throw new CryptographicException("Owned mailbox installation does not cover its full authenticated interval.");
            return upper;
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
        private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);
        private sealed class InstallationClock(MailboxInstallationPolicy owner) : TimeProvider
        {
            public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(checked((long)owner.CurrentUpper()));
        }
    }
}
