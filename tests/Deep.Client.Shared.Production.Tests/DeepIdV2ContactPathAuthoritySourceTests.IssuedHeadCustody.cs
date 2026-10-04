using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2IssuedHead_ProposalOneWinnerTwoResumeThreeCommitsAndReopens(bool adopted)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckIssuedHeadCustodyAsync(adopted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2IssuedHead_BadResponseCannotAdvanceProposal(bool wrongNonce)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckBadIssuedHeadAsync(wrongNonce);
    }

    private sealed partial class Fixture
    {
        private async Task AdvanceIssuedHeadAsync()
        {
            retainedIssuanceHistory ??= new() { [0] = genesis.ProtectedHead };
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                new(head.ExactAllTransitions, [checkpoint], [], 990, 1_500, 2), witnesses);
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
        }

        internal async Task CheckIssuedHeadCustodyAsync(bool adopted)
        {
            var intent = Bytes(32, 0xc4); var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            var identity = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            using var threshold = new OwnedRouteThreshold(this);
            using (Did2ContactRouteTestHooks.Push(point =>
                { if (point == Did2ContactRouteFailpoint.AfterProposal) throw new IOException("Retain original proposal."); }))
                await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, config, threshold));
            byte[] original;
            using (var state = await RouteState()) original = Assert.Single(state.Entries).Value.Record(12).ToArray();
            Assert.Equal(1UL, ContactRouteAuthorityWireCodec.DecodeRequest(original).MinimumAdh1Generation);
            await AdvanceIssuedHeadAsync();
            threshold.LoseNextResponse = !adopted;
            using (Did2ContactRouteTestHooks.Push(point =>
                { if (adopted && point == Did2ContactRouteFailpoint.AfterThreshold) throw new IOException("Retain adopted winner."); }))
                await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, config, threshold, reopen: true));
            using (var state = await RouteState()) Assert.Equal(adopted ? (byte)2 : (byte)1, Assert.Single(state.Entries).Value.Phase);
            Assert.Equal(2UL, AccountDirectoryAdh1Codec.Decode(threshold.WinnerHead.Span).LogGeneration);
            await AdvanceIssuedHeadAsync();
            var route = await EnsureRoute(intent, config, threshold, reopen: true);
            Assert.Equal(3UL, route.Recipient.Freshness.NextProtectedLkg.LogGeneration);
            Assert.All(threshold.Requests, value => Assert.Equal(original, value));
            Assert.Equal(adopted ? 1 : 2, threshold.Calls);
            var account = ReopenAccount();
            var contact = await account.EnsureOwnContactObjectAsync(intent, Source(account), config, threshold, "DID2 contact QA");
            Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(contact.Closure.Bundle.Field(21).Span));
            var publication = new OwnedPublicationSource(this, route);
            var replica = new OwnedPublicationReplica(this, route);
            async Task<VerifiedDeepIdV2PublicationCommit> Commit()
            {
                var reopened = ReopenAccount();
                return await reopened.EnsureOwnContactPublicationCommitAsync(intent, Source(reopened), config,
                    threshold, "DID2 contact QA", publication, replica);
            }
            var committed = await Commit();
            Assert.Equal(committed.ExactXpo1.ToArray(), (await Commit()).ExactXpo1.ToArray());
            Assert.Equal(1, publication.Calls); Assert.Equal(1, replica.Calls);
            using (var state = await RouteState())
            {
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal((byte)7, entry.Phase);
                Assert.Equal(original, entry.Record(12).ToArray());
                Assert.Equal(threshold.WinnerHead.ToArray(), entry.Record(13).ToArray());
            }
            Assert.Equal(identity, (await ReopenAccount().GetCurrentAsync())!.PermanentId.CanonicalText);
            // Even terminal state must authenticate retained evidence before
            // returning a capability or invoking coordination/replica callbacks.
            // Record14 is the current empty secret slot for this reusable entry.
            // Corrupt the actual retained issuance signature, not that LP32 trailer.
            var good = await RouteSnapshot(); var damaged = good.ToArray(); damaged[^5] ^= 1;
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, damaged));
                await RequireRouteRejectionAsync(async () => await Commit());
                Assert.Equal(1, publication.Calls); Assert.Equal(1, replica.Calls);
                var persisted = await RouteSnapshot();
                try { Assert.Equal(damaged, persisted); }
                finally { CryptographicOperations.ZeroMemory(persisted); }
            }
            finally
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, good));
                CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(damaged);
            }
        }

        internal async Task CheckBadIssuedHeadAsync(bool wrongNonce)
        {
            var intent = Bytes(32, 0xc4); var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this)
            { WrongResponseNonce = wrongNonce, CorruptIssuanceHead = !wrongNonce };
            await RequireRouteRejectionAsync(async () => await EnsureRoute(intent, config, threshold));
            using (var state = await RouteState())
            {
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal((byte)1, entry.Phase); Assert.Empty(entry.Record(13).ToArray());
            }
            threshold.WrongResponseNonce = false; threshold.CorruptIssuanceHead = false;
            await (await EnsureRoute(intent, config, threshold, reopen: true)).EnsureCurrentAsync();
            Assert.Equal(2, threshold.Calls); Assert.True(threshold.StableRequest);
        }
    }
}
