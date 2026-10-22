using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2NewWorkGrantCeiling_CurrentSignedNetworkCapColdReusesExactDepositWithoutIssuer()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckCurrentNetworkGrantCeilingAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2NewWorkGrantCeiling_TightenedSignedCeilingRenewsBeforeMarginAndColdKeepsOriginal(bool loseReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        await fixture.CheckCurrentNetworkGrantCeilingAsync(tightened: true, loseReply);
    }

    [Theory]
    [InlineData("unchanged")]
    [InlineData("issuer")]
    [InlineData("floor")]
    [InlineData("issuer-window")]
    [InlineData("max-lifetime")]
    [InlineData("lifecycle")]
    public async Task Did2NewWorkGrantCeiling_CurrentSignedPolicyChangeCannotSuppressUsefulReplacement(string change)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGrantCeilingPolicyEligibilityAsync(change);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckGrantCeilingPolicyEligibilityAsync(string change)
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), Did2OwnedPermanentContactPlan.Configuration(), threshold, reopen: false);
            var replicas = new OwnedPublicationReplica(this, route);
            _ = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold,
                new OwnedPublicationSource(this, route), replicas);
            var reader = ReopenGrantReader(); var source = GrantReaderSource(reader);
            var resolved = await reader.ResolvePermanentContactAsync((await accounts.GetCurrentAsync())!.PermanentId,
                source, new SyntheticPermanentRead(this, source, replicas.ExactPublication));
            var first = await reader.AcquirePermanentContactDepositGrantAsync(resolved, source, new OwnedGrantTransport(this));
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(first.ExactGrant.Span);
            // A real canonical, issued winner. Only the PMA policy metadata
            // changes below; this component test does not install a new PMT.
            Assert.True(ProtectedDeepIdV2AccountOwner.IsDepositGrantStructurallyEligibleForCurrentPolicy(grant,
                (await source.VerifyForOwnPreKeyAuthoringAsync(reader, default)).MailboxAuthority));
            Sample = checked(Sample + 2); ProofTime = checked(ProofTime + 2);
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(reader, default);
            var exact = fresh.MailboxAuthority.ExactPma2.ToArray();
            switch (change)
            {
                case "issuer": PublicKey(0x35).CopyTo(exact, FieldOffset(exact, 5)); break;
                case "floor": BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 7)), checked(grant.Generation + 1)); break;
                case "issuer-window": BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 11)), checked(grant.NotBeforeUnixSeconds + 1)); break;
                case "max-lifetime": BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(FieldOffset(exact, 8)),
                    checked((uint)(grant.ExpiresAtUnixSeconds - grant.NotBeforeUnixSeconds - 1))); break;
                case "lifecycle":
                    var overlap = grant with { Lifecycle = MailboxCapabilityLifecycle.Overlap,
                        OverlapUntilUnixSeconds = grant.ExpiresAtUnixSeconds, IssuerSignature = new byte[64] };
                    var signature = await new FixtureMailboxIssuer(0x31).SignAsync(MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(overlap), default);
                    grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(MailboxAuthenticatedCapabilityCodec.EncodeGrant(overlap with { IssuerSignature = signature }));
                    break;
                case "unchanged": break;
                default: throw new ArgumentOutOfRangeException(nameof(change));
            }
            if (change is not ("unchanged" or "lifecycle"))
            {
                var oldGeneration = BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 2)));
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 2)), checked(oldGeneration + 1));
                fresh.MailboxAuthority.CoreHash.Span.CopyTo(exact.AsSpan(FieldOffset(exact, 3), 32));
                var candidate = ContactCodec.Decode("PMA2", exact);
                var rows = candidate.Field(16).ToArray();
                for (var offset = 0; offset < rows.Length; offset += 96)
                {
                    Assert.Equal(root.RootKeyId.ToArray(), rows.AsSpan(offset, 32).ToArray());
                    root.SignCommit(candidate.SignatureInput).CopyTo(rows, offset + 32);
                }
                rows.CopyTo(exact, FieldOffset(exact, 16));
            }
            var policy = MailboxAuthorityV2Verifier.Verify(fresh.Authority, exact,
                fresh.Proof.TrustedLowerUnixSeconds, fresh.Proof.TrustedUpperUnixSeconds);
            var eligible = ProtectedDeepIdV2AccountOwner.IsDepositGrantStructurallyEligibleForCurrentPolicy(grant, policy);
            Assert.Equal(change == "unchanged", eligible);
            var due = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            Assert.True(ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(
                grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds, grant.Domain, due));
            // Reflect the closed selector: only eligible current policy can
            // supply its fixed-ceiling skip; changes retain normal renewal.
            Assert.Equal(change != "unchanged", ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(
                grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds, grant.Domain, due,
                eligible ? grant.ExpiresAtUnixSeconds : null));
        }

        internal async Task CheckCurrentNetworkGrantCeilingAsync(bool tightened = false, bool loseReply = false)
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
            ulong networkEnd = tightened ? 1_500UL : 1_400UL;
            Assert.True(routeEnd >= networkEnd);
            if (!tightened) await AdvanceNetworkAsync(expiry: networkEnd);
            var firstIssuer = new OwnedGrantTransport(this);
            var first = await Acquire(firstIssuer);
            Assert.Equal(1, firstIssuer.Calls);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(first.ExactGrant.Span);
            Assert.Equal(networkEnd, grant.ExpiresAtUnixSeconds);
            Assert.True(grant.ExpiresAtUnixSeconds < routeEnd);
            var refreshAt = ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(grant.NotBeforeUnixSeconds, grant.ExpiresAtUnixSeconds);
            if (tightened)
            {
                byte[] original;
                using (var state = await ReadPeerGrantsAsync()) original = Assert.Single(state.Entries).Value.ToArray();
                try
                {
                    networkEnd = 1_350;
                    await AdvanceNetworkAsync(expiry: networkEnd);
                    Assert.True(checked(CurrentProofTime + 5) < refreshAt);
                    var issuer = new OwnedGrantTransport(this) { LoseResponse = loseReply };
                    if (loseReply)
                    {
                        await Assert.ThrowsAsync<IOException>(async () => _ = await Acquire(issuer));
                        Assert.Equal(1, issuer.Calls);
                        issuer.LoseResponse = false;
                    }
                    var successor = await Acquire(issuer);
                    Assert.Equal(networkEnd, MailboxAuthenticatedCapabilityCodec.DecodeGrant(successor.ExactGrant.Span).ExpiresAtUnixSeconds);
                    Assert.NotEqual(first.ExactXmg2.ToArray(), successor.ExactXmg2.ToArray());
                    Assert.Equal(loseReply ? 2 : 1, issuer.Calls);
                    Assert.True(issuer.ExactRetry);
                    using (var state = await ReadPeerGrantsAsync())
                    {
                        Assert.Equal(2, state.Entries.Count);
                        Assert.Equal(original, state.Entries[ProtectedDid2MailboxGrantJournal.Acquisition(original)]);
                        Assert.Null(Assert.Single(state.Selections).Value.Pending);
                    }
                    var unused = new OwnedGrantTransport(this);
                    Assert.Equal(successor.ExactXmc2.ToArray(), (await Acquire(unused)).ExactXmc2.ToArray());
                    Assert.Equal(0, unused.Calls);
                    return;
                }
                finally { CryptographicOperations.ZeroMemory(original); }
            }
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
