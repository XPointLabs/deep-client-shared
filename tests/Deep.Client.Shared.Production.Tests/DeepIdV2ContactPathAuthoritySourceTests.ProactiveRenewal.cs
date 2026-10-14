using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2OwnedRenewal_SignedMarginStartsBeforeExpiryAndColdResumesPending()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        await fixture.CheckProactivePermanentRenewalAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckProactivePermanentRenewalAsync()
        {
            await SeedShortPermanentProposalAsync(validitySeconds: 200);
            var backend = new RenewalBackend(this);
            var originalCommit = await Ensure();
            Assert.Equal(0UL, originalCommit.Generation);
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var name = Convert.ToHexString(plan.Intent.Span);
            var address = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            byte[] original, root;
            ulong refreshAt, expiry;
            using (var state = await RouteState())
            {
                var entry = state.Entries[name]; original = entry.Exact.ToArray();
                var advertisement = ContactCodec.Decode("XRA1", entry.Record(1).Span);
                var bundle = DeepIdV2ResolverClosureCodec.Decode(entry.Record(7).Span).Bundle;
                var advertisementExpiry = BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(13).Span);
                var bundleExpiry = BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(18).Span);
                expiry = Math.Min(advertisementExpiry, bundleExpiry);
                refreshAt = Math.Min(ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
                        BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(12).Span), advertisementExpiry),
                    ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(
                        BinaryPrimitives.ReadUInt64BigEndian(bundle.Field(17).Span), bundleExpiry));
            }
            root = await RouteSnapshot();
            try
            {
                // The fixture signs a +/-5-second interval, independently of
                // local UTC. Just before the margin, restoration is callback-free.
                AdvanceTo(checked(refreshAt - 6));
                var calls = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
                var beforeMargin = await Ensure();
                Assert.Equal(originalCommit.ExactXpo1.ToArray(), beforeMargin.ExactXpo1.ToArray());
                Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                var unchanged = await RouteSnapshot();
                try { Assert.Equal(root, unchanged); }
                finally { CryptographicOperations.ZeroMemory(unchanged); }

                // Exactly at the authenticated upper boundary, stage a successor
                // while the old publication is still unexpired. Do not replace it
                // merely because a proposal was saved; cold reopen owns its retry.
                AdvanceTo(checked(refreshAt - 5));
                Assert.True(checked(CurrentProofTime + 5) < expiry);
                var hit = false;
                using (Did2ContactRouteTestHooks.Push(point =>
                    {
                        if (point != Did2ContactRouteFailpoint.AfterProposal) return;
                        hit = true; throw new IOException("Interrupted proactive successor after protected proposal.");
                    }))
                    await Assert.ThrowsAsync<IOException>(async () => _ = await Ensure());
                Assert.True(hit);
                Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                using (var staged = await RouteState())
                {
                    Assert.Equal(original, staged.Entries[name].Exact.ToArray());
                    Assert.Equal((byte)1, Assert.Single(staged.Entries, pair => pair.Key != name).Value.Phase);
                }
                var successor = await Ensure();
                Assert.Equal(1UL, successor.Generation);
                Assert.Equal(2, backend.RouteSignings); Assert.Equal(2, backend.PublicationSignings);
                using (var promoted = await RouteState())
                {
                    Assert.Equal(2, promoted.Entries.Count);
                    Assert.Equal((byte)7, promoted.Entries[name].Phase);
                    var retained = Assert.Single(promoted.Entries, pair => pair.Key != name).Value;
                    Assert.Equal((byte)7, retained.Phase);
                    Assert.Equal(original.AsSpan(32).ToArray(), retained.Exact[32..].ToArray());
                }
                calls = (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls);
                Assert.Equal(successor.ExactXpo1.ToArray(), (await Ensure()).ExactXpo1.ToArray());
                Assert.Equal(calls, (backend.RouteCalls, backend.PublicationCalls, backend.ReplicaCalls));
                Assert.Equal(address, (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText);
                Assert.True(plan.Matches(await accounts.ReadOwnPermanentContactPlanAsync()));
            }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(root); }

            Task<VerifiedDeepIdV2PublicationCommit> Ensure()
            {
                var reopened = ReopenAccount();
                return reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), backend, backend, backend);
            }
            void AdvanceTo(ulong proofTime)
            {
                Assert.True(proofTime > CurrentProofTime);
                var delta = proofTime - CurrentProofTime;
                ProofTime = checked(ProofTime + delta); Sample = checked(Sample + delta);
            }
        }
    }
}

public sealed class OwnedPermanentContactRefreshTests
{
    [Theory]
    [InlineData(100UL, 200UL, 180UL)]
    [InlineData(100UL, 101UL, 100UL)]
    [InlineData(100UL, 104UL, 103UL)]
    [InlineData(100UL, 105UL, 104UL)]
    [InlineData(100UL, 106UL, 104UL)]
    [InlineData(ulong.MaxValue - 5, ulong.MaxValue, ulong.MaxValue - 1)]
    public void SignedLifetimeMarginIsConservativeAndDoesNotOverflow(ulong issued, ulong expiry, ulong expected)
        => Assert.Equal(expected, ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(issued, expiry));

    [Theory]
    [InlineData(0UL, 1UL)]
    [InlineData(1UL, 1UL)]
    [InlineData(2UL, 1UL)]
    public void InvalidSignedIntervalsCannotBecomeRefreshAuthority(ulong issued, ulong expiry)
        => Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.ProactiveRefreshAt(issued, expiry));
}
