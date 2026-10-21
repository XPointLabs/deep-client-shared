using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2NewWorkGrantCeiling_CurrentSignedNetworkCapColdReusesExactDepositWithoutIssuer()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckCurrentNetworkGrantCeilingAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckCurrentNetworkGrantCeilingAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var originalRoute = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, originalRoute);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, originalRoute), replicas);
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            var routeEnd = new[] { (originalRoute.Route.Reachability, 17), (originalRoute.Route.Authorization, 13),
                (originalRoute.Route.Route, 18), (originalRoute.Route.Successor, 11), (originalRoute.Route.Selection, 9) }
                .Min(part => BinaryPrimitives.ReadUInt64BigEndian(part.Item1.Field(part.Item2).Span));
            // A genuine signed successor, not a mocked grant expiry: current
            // carriage/policy now ends before the older original exact route.
            // Leave room for the fixture's complete 30-second signed DTT
            // response window even after entering the proactive grant margin.
            const ulong networkEnd = 1_400;
            Assert.True(routeEnd > networkEnd);
            await AdvanceNetworkAsync(expiry: networkEnd);
            var firstIssuer = new OwnedGrantTransport(this);
            var first = await Acquire(firstIssuer);
            Assert.Equal(1, firstIssuer.Calls);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(first.ExactGrant.Span);
            Assert.Equal(networkEnd, grant.ExpiresAtUnixSeconds);
            Assert.True(grant.ExpiresAtUnixSeconds < routeEnd);
            var refreshAt = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            var center = checked(refreshAt - 5);
            Assert.True(center > CurrentProofTime);
            var delta = center - CurrentProofTime; ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            Assert.True(checked(CurrentProofTime + 5) < grant.ExpiresAtUnixSeconds);
            // The old selector would renew here: due, still live, and expiry
            // strictly below routeEnd. A new holder cannot extend this cap.
            Assert.True(ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(
                grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds, grant.Domain, checked(CurrentProofTime + 5)));
            byte[] before;
            using (var root = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot))
                before = root!.Use(bytes => bytes.ToArray());
            try
            {
                for (var cold = 0; cold < 2; cold++)
                {
                    var unusedIssuer = new OwnedGrantTransport(this);
                    var reused = await Acquire(unusedIssuer);
                    Assert.Equal(first.ExactXmg2.ToArray(), reused.ExactXmg2.ToArray());
                    Assert.Equal(first.ExactXmc2.ToArray(), reused.ExactXmc2.ToArray());
                    Assert.Equal(0, unusedIssuer.Calls);
                    using var root = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot);
                    Assert.True(root!.Use(bytes => bytes.SequenceEqual(before)));
                    using var state = await ReadPeerGrantsAsync();
                    Assert.Single(state.Entries);
                    var selection = Assert.Single(state.Selections).Value;
                    Assert.Null(selection.Pending);
                    Assert.Equal(Convert.ToHexString(SHA256.HashData(first.ExactXmg2.Span)), selection.Current);
                }
            }
            finally { CryptographicOperations.ZeroMemory(before); }

            async Task<VerifiedDeepIdV2MailboxGrant> Acquire(OwnedGrantTransport issuer)
            {
                var reopened = ReopenGrantReader(); var source = GrantReaderSource(reopened);
                var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(reopened, default);
                Assert.Equal(networkEnd, fresh.Network.MaximumRecordExpiryUnixSeconds);
                Assert.Equal(networkEnd, fresh.MailboxAuthority.ExpiresAtUnixSeconds);
                var resolved = await reopened.ResolvePermanentContactAsync(address, source,
                    new SyntheticPermanentRead(this, source, replicas.ExactPublication));
                return await reopened.AcquirePermanentContactDepositGrantAsync(resolved, source, issuer);
            }
        }
    }
}
