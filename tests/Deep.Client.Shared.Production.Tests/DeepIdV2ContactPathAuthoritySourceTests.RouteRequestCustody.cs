using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2OwnedRoute_RetainsExactRequestAcrossRealDirectoryHeadAdvance(bool loseResponse)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckExactRouteRequestAsync(loseResponse);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task Did2OwnedRoute_CorruptPendingRequestRejectsBeforeThreshold(int mode)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckCorruptRouteRequestAsync(mode);
    }

    private sealed partial class Fixture
    {
        private AuthoredAccountDirectoryHeadMutation? routeRequestPriorHead;
        private AccountDirectoryProtectedLkg[] RouteRequestHistoryHeads() => routeRequestPriorHead is null
            ? [genesis.ProtectedHead, head.ProtectedHead]
            : [genesis.ProtectedHead, routeRequestPriorHead.ProtectedHead, head.ProtectedHead];

        internal async Task CheckExactRouteRequestAsync(bool loseResponse)
        {
            var intent = Bytes(32, 0xc4); var configuration = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            var accountBefore = (await accounts.GetCurrentAsync())!.PermanentId.CanonicalText;
            using var remote = new OwnedRouteThreshold(this) { LoseNextResponse = loseResponse, ProbeHeldCustody = true };
            if (loseResponse)
                await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, configuration, remote, reopen: true));
            else
            {
                using var hook = Did2ContactRouteTestHooks.Push(point =>
                { if (point == Did2ContactRouteFailpoint.AfterProposal) throw new IOException("Stop after exact request custody before dispatch."); });
                await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, configuration, remote, reopen: true));
            }
            byte[] pending;
            using (var state = await RouteState())
            {
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal((byte)1, entry.Phase); pending = entry.Record(12).ToArray();
            }
            var saved = ContactRouteAuthorityWireCodec.DecodeRequest(pending);
            Assert.Equal(1UL, saved.MinimumAdh1Generation);
            Assert.Equal(head.CoreHash.ToArray(), saved.MinimumAdh1CoreHash.ToArray());
            // Genuine witness-signed head-only renewal. The account, device,
            // network view and PMT remain exact; no fake floor/current proof.
            routeRequestPriorHead = head;
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority, head.ProtectedHead,
                new(head.ExactAllTransitions, [checkpoint], [], 990, 1_500, 2), witnesses);
            Assert.Equal(2UL, head.ProtectedHead.LogGeneration);
            try
            {
                if (loseResponse)
                {
                    // DR42 still disallows completing old-head threshold
                    // issuance. Do not waive it just because nonce replay is
                    // now exact; connected retained issuance is a separate gate.
                    var rejected = await Assert.ThrowsAsync<CryptographicException>(() =>
                        EnsureRoute(intent, configuration, remote, reopen: true));
                    Assert.Equal("The threshold route has stale or substituted current directory/network references.", rejected.Message);
                }
                else
                {
                    var completed = await EnsureRoute(intent, configuration, remote, reopen: true);
                    await completed.EnsureCurrentAsync();
                }
                Assert.True(remote.StableRequest); Assert.True(remote.StableProposal); Assert.True(remote.StableNonce);
                Assert.Equal(loseResponse ? 2 : 1, remote.Calls);
                Assert.All(remote.Requests, exact => Assert.Equal(pending, exact));
                Assert.Equal(2UL, remote.CurrentHeadGenerations[^1]);
                if (loseResponse) Assert.Equal(1UL, remote.CurrentHeadGenerations[0]);
                using var after = await RouteState();
                Assert.Equal(loseResponse ? (byte)1 : (byte)3, Assert.Single(after.Entries).Value.Phase);
                Assert.Equal(pending, Assert.Single(after.Entries).Value.Record(12).ToArray());
                Assert.Equal(accountBefore, (await ReopenAccount().GetCurrentAsync())!.PermanentId.CanonicalText);
                var calls = remote.Calls;
                if (loseResponse)
                {
                    await Assert.ThrowsAsync<CryptographicException>(() => EnsureRoute(intent, configuration, remote, reopen: true));
                    Assert.Equal(calls + 1, remote.Calls);
                    Assert.True(remote.StableRequest);
                }
                else
                {
                    await EnsureRoute(intent, configuration, remote, reopen: true);
                    Assert.Equal(calls, remote.Calls);
                }
            }
            finally { CryptographicOperations.ZeroMemory(pending); }
        }

        internal async Task CheckCorruptRouteRequestAsync(int mode)
        {
            var intent = Bytes(32, 0xc4); var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var remote = new OwnedRouteThreshold(this);
            using (Did2ContactRouteTestHooks.Push(point =>
                { if (point == Did2ContactRouteFailpoint.AfterProposal) throw new IOException("Stop before request dispatch."); }))
                await Assert.ThrowsAsync<IOException>(() => EnsureRoute(intent, config, remote));
            var good = await RouteSnapshot(); var damaged = good.ToArray();
            var offset = ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + ProtectedDid2ContactRouteJournal.PrefixBytes;
            for (var index = 0; index < 12; index++) offset += 4 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(damaged.AsSpan(offset)));
            var body = offset + 4;
            if (mode == 0) damaged[body + 56] ^= 1; // changed queried leaf
            if (mode == 1) damaged[body + 24] ^= 1; // changed nonce
            if (mode == 2) damaged[body + 601 + 549] ^= 1; // changed exact proposal
            if (mode == 3) BinaryPrimitives.WriteUInt64BigEndian(damaged.AsSpan(body + 88), 2); // future minimum
            if (mode == 4) damaged[body + 96] ^= 1; // same-generation fork
            if (mode == 5) BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(offset), ContactRouteAuthorityWireCodec.RequestBytes + 1);
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, good, damaged));
                if (mode == 5)
                    await Assert.ThrowsAsync<InvalidDataException>(() => EnsureRoute(intent, config, remote, reopen: true));
                else
                    await Assert.ThrowsAsync<CryptographicException>(() => EnsureRoute(intent, config, remote, reopen: true));
                Assert.Equal(0, remote.Calls);
                var retained = await RouteSnapshot();
                try { Assert.Equal(damaged, retained); }
                finally { CryptographicOperations.ZeroMemory(retained); }
            }
            finally
            {
                // Fixture-only cleanup, never runtime repair/migration.
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, good));
                CryptographicOperations.ZeroMemory(good); CryptographicOperations.ZeroMemory(damaged);
            }
            var recovered = await EnsureRoute(intent, config, remote, reopen: true);
            await recovered.EnsureCurrentAsync(); Assert.Equal(1, remote.Calls);
        }
    }
}
