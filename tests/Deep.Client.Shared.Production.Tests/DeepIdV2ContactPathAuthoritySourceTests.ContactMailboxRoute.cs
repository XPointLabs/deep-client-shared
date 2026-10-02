using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PrivateReplyRoute_ActualOwnPublicationCurrentPeerAndExactReopen()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckPrivateReplyRouteAsync();
    }

    private sealed partial class Fixture
    {
        private async Task<ParsedDeepIdV2ContactMailboxRoute> EnsurePrivateReplyPublicationAsync(Deep.Client.Shared.Services.DeepIdV2AccountService account)
        {
            var source = Source(account); var plan = await account.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await account.EnsureOwnContactRouteAsync(plan.Intent, source, Did2OwnedPermanentContactPlan.Configuration(), threshold);
            var publication = new OwnedPublicationSource(this, route); var replicas = new OwnedPublicationReplica(this, route);
            _ = await account.EnsureOwnPermanentContactPublishedAsync(source, threshold, publication, replicas);
            return await account.ReadOwnPrivateContactMailboxRouteAsync(source);
        }

        internal async Task CheckPrivateReplyRouteAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            // A signed route candidate alone cannot export actual published
            // reply metadata from the owner, even with a current proof.
            await Assert.ThrowsAsync<CryptographicException>(() => accounts.ReadOwnPrivateContactMailboxRouteAsync(Source()));
            var publication = new OwnedPublicationSource(this, route);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, publication, replicas);
            var package = await accounts.ReadOwnPrivateContactMailboxRouteAsync(Source());
            Assert.Equal(DeepIdV2ContactMailboxRouteCodec.Encode(route), package.ExactBytes.ToArray());
            var fresh = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var verified = await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(package, fresh.Proof, fresh.Network,
                fresh.Authority, Source().RendezvousTrustedTime);
            Assert.Equal(Xpu1Codec.Decode(replicas.ExactPublication.Span).LocatorHash.ToArray(), verified.LocatorHash.ToArray());
            Assert.Equal(route.ExactRouteClosure.ToArray(), verified.Route.ExactRouteClosure.ToArray());
            var copy = verified.LocatorHash.ToArray(); copy[0] ^= 1;
            Assert.NotEqual(copy, verified.LocatorHash.ToArray());
            var reopened = ReopenAccount();
            Assert.Equal(package.ExactBytes.ToArray(), (await reopened.ReadOwnPrivateContactMailboxRouteAsync(Source(reopened))).ExactBytes.ToArray());
            var other = await Source(peerAccounts!).VerifyForOwnPreKeyAuthoringAsync(peerAccounts!, default);
            await RequireRouteRejectionAsync(async () => await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(package, other.Proof,
                other.Network, other.Authority, Source(peerAccounts!).RendezvousTrustedTime));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(package,
                fresh.Proof, fresh.Network, fresh.Authority, Source().RendezvousTrustedTime, cancelled.Token));
            // Expire the actual captured proof, not an assumed fixture TTL.
            Sample = fresh.Proof.FreshnessDeadlineMonotonicSeconds;
            await RequireRouteRejectionAsync(async () => await DeepIdV2ContactMailboxRouteVerifier.VerifyAsync(package,
                fresh.Proof, fresh.Network, fresh.Authority, Source().RendezvousTrustedTime));
        }
    }
}
