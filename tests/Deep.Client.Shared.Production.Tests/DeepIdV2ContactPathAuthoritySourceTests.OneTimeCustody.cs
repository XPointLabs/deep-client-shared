using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2OwnedOneTime_CapacityReservesBeforeThresholdAndIndependentIntentsDoNotAlias()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOneTimeCapacityAsync();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task Did2OwnedOneTime_ReadbackFailureCannotReturnSecretOrRemint(int phase)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOneTimeReadbackAsync(phase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2OwnedOneTime_AllPhasesReopenExactSecretAndTwoReceiptCommit(bool advanceHead)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckOneTimeCustodyAsync(advanceHead);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckOneTimeCapacityAsync()
        {
            var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var firstThreshold = new OwnedRouteThreshold(this);
            using var secondThreshold = new OwnedRouteThreshold(this);
            using var blockedThreshold = new OwnedRouteThreshold(this);
            using var first = await accounts.EnsureOwnOneTimeContactObjectAsync(Bytes(32, 0xc1), Source(accounts),
                config, firstThreshold, "one-time capacity QA");
            using var second = await accounts.EnsureOwnOneTimeContactObjectAsync(Bytes(32, 0xc2), Source(accounts),
                config, secondThreshold, "one-time capacity QA");
            Assert.False(first.LocatorHash.Span.SequenceEqual(second.LocatorHash.Span));
            var before = await RouteSnapshot();
            try
            {
                await Assert.ThrowsAsync<IOException>(async () =>
                {
                    using var rejected = await accounts.EnsureOwnOneTimeContactObjectAsync(Bytes(32, 0xc3), Source(accounts),
                        config, blockedThreshold, "one-time capacity QA");
                });
                Assert.Equal(0, blockedThreshold.Calls);
                var after = await RouteSnapshot();
                try { Assert.True(CryptographicOperations.FixedTimeEquals(before, after)); }
                finally { CryptographicOperations.ZeroMemory(after); }
                using var state = await RouteState(); Assert.Equal(2, state.Entries.Count);
            }
            finally { CryptographicOperations.ZeroMemory(before); }
        }

        internal async Task CheckOneTimeReadbackAsync(int phase)
        {
            var intent = Bytes(32, 0xcf); var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this);
            storage.FailRouteReadbackPhase = (byte)phase;
            await Assert.ThrowsAsync<IOException>(async () =>
            {
                using var rejected = await accounts.EnsureOwnOneTimeContactObjectAsync(intent, Source(accounts), config,
                    threshold, "one-time readback QA");
            });
            using var before = await RouteState();
            var retained = Assert.Single(before.Entries).Value;
            Assert.Equal((byte)phase, retained.Phase); Assert.Equal(phase == 1 ? 0 : 1, threshold.Calls);
            var secret = phase == 4 ? retained.CopyOneTimeInvitation() : Array.Empty<byte>();
            try
            {
                var reopened = ReopenAccount();
                using var recovered = await reopened.EnsureOwnOneTimeContactObjectAsync(intent, Source(reopened), config,
                    threshold, "one-time readback QA");
                var exported = recovered.ExactInvitation;
                try { if (phase == 4) Assert.True(CryptographicOperations.FixedTimeEquals(secret, exported.Span)); }
                finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exported).Span); }
                Assert.Equal(1, threshold.Calls);
                using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                {
                    using var rejected = await reopened.EnsureOwnOneTimeContactObjectAsync(intent, Source(reopened), config,
                        threshold, "one-time readback QA", cancelled.Token);
                });
                Assert.Equal(1, threshold.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(secret); }
        }

        internal async Task CheckOneTimeCustodyAsync(bool advanceHead)
        {
            var intent = Bytes(32, 0xcf);
            var configuration = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd1));
            using var threshold = new OwnedRouteThreshold(this);
            const string profile = "DID2 one-time QA";
            async Task<AuthoredDeepIdV2OneTimeContactObject> Object()
            {
                var reopened = ReopenAccount();
                return await reopened.EnsureOwnOneTimeContactObjectAsync(intent, Source(reopened),
                    configuration, threshold, profile);
            }
            foreach (var (point, phase) in new[] {
                (Did2ContactRouteFailpoint.AfterProposal, 1), (Did2ContactRouteFailpoint.AfterThreshold, 2),
                (Did2ContactRouteFailpoint.AfterComplete, 3), (Did2ContactRouteFailpoint.AfterContactObject, 4) })
            {
                var hit = false;
                using (Did2ContactRouteTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected owned one-time phase interruption."); } }))
                    await Assert.ThrowsAsync<IOException>(async () => { using var result = await Object(); });
                Assert.True(hit);
                using var state = await RouteState();
                var entry = Assert.Single(state.Entries).Value;
                Assert.Equal((byte)phase, entry.Phase); Assert.Equal((byte)2, entry.Kind);
                Assert.Equal(phase >= 4 ? 225 : 0, entry.InvitationLength);
                Assert.Equal(phase == 1 ? 0 : 1, threshold.Calls);
                if (advanceHead && phase == 2) await AdvanceIssuedHeadAsync();
            }
            using var authored = await Object();
            var invitation = authored.ExactInvitation;
            var ciphertext = authored.ProtectedDcr1;
            try
            {
                using var restored = await Object();
                var restoredInvitation = restored.ExactInvitation;
                try { Assert.True(CryptographicOperations.FixedTimeEquals(invitation.Span, restoredInvitation.Span)); }
                finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(restoredInvitation).Span); }
                Assert.True(ciphertext.Span.SequenceEqual(restored.ProtectedDcr1.Span));
                Assert.Equal(1, threshold.Calls);

                var account = ReopenAccount(); var source = Source(account);
                var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(account, default);
                using var retained = await RouteState();
                var entry = Assert.Single(retained.Entries).Value;
                var checkpointNow = fresh.Proof.CurrentCheckpoint!;
                var delegation = DeepIdV2ContactAuthorizationCodec.Verify(
                    DeepIdV2ContactAuthorizationCodec.Decode(entry.Record(0).Span), checkpointNow.Binding, checkpointNow.Directory);
                var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh.Proof, delegation, Boot, Sample);
                var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(authorization, fresh.Network, fresh.Authority,
                    entry.Record(5), entry.Record(6), source.RendezvousTrustedTime);
                var publication = new OwnedPublicationSource(this, route) { CorruptResponse = true };
                var replica = new OwnedPublicationReplica(this, route);
                async Task<VerifiedDeepIdV2PublicationCommit> Commit()
                {
                    var reopened = ReopenAccount();
                    return await reopened.EnsureOwnOneTimeContactPublicationCommitAsync(intent, Source(reopened),
                        configuration, threshold, profile, publication, replica);
                }
                await RequireRouteRejectionAsync(async () => await Commit());
                using (var pending = await RouteState()) Assert.Equal((byte)5, Assert.Single(pending.Entries).Value.Phase);
                Assert.Equal(1, publication.Calls); Assert.Equal(0, replica.Calls);
                publication.CorruptResponse = false; replica.LoseResponse = true;
                await Assert.ThrowsAsync<IOException>(() => Commit());
                using (var pending = await RouteState()) Assert.Equal((byte)6, Assert.Single(pending.Entries).Value.Phase);
                replica.LoseResponse = false; replica.CorruptReceipt = true;
                await Assert.ThrowsAsync<CryptographicException>(() => Commit());
                replica.CorruptReceipt = false;
                var committed = await Commit();
                var publications = publication.Calls; var dispatches = replica.Calls;
                var before = await RouteSnapshot();
                try
                {
                    var reopenedCommit = await Commit();
                    Assert.True(committed.ExactXpo1.Span.SequenceEqual(reopenedCommit.ExactXpo1.Span));
                    var after = await RouteSnapshot();
                    try { Assert.True(CryptographicOperations.FixedTimeEquals(before, after)); }
                    finally { CryptographicOperations.ZeroMemory(after); }
                    Assert.Equal(publications, publication.Calls); Assert.Equal(dispatches, replica.Calls);
                    Assert.True(publication.StableRequest); Assert.True(replica.StableRequest);
                    using (var winner = await RouteState())
                    {
                        var won = Assert.Single(winner.Entries).Value;
                        Assert.Equal((byte)7, won.Phase);
                        var secret = won.CopyOneTimeInvitation();
                        try { Assert.True(CryptographicOperations.FixedTimeEquals(invitation.Span, secret)); }
                        finally { CryptographicOperations.ZeroMemory(secret); }
                    }
                    // Authenticated storage can be corrupted: neither cached success nor
                    // regeneration is permitted; callbacks stay untouched after rejection.
                    for (var mode = 0; mode < 7; mode++)
                    {
                        var damaged = before.ToArray();
                        var start = ProtectedDid2ContactRouteJournal.HeaderBytes + 4;
                        var offset = start + ProtectedDid2ContactRouteJournal.PrefixBytes;
                        var record = 0;
                        while (record++ < (mode == 0 ? 8 : 14))
                            offset += 4 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(damaged.AsSpan(offset)));
                        if (mode == 0) damaged[offset + 4 + 24] ^= 1; // Actual AEAD body.
                        if (mode == 1) damaged[offset + 4 + 127] ^= 1; // DIA1 decryption-key bytes.
                        if (mode == 2) damaged[start + 33] = 1; // Mixed kind/secret/policy.
                        if (mode == 3) damaged[start + 33] = 3; // Unknown kind.
                        if (mode == 4) damaged[0] = 9; // No old-format reader.
                        if (mode == 5) BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(offset), 224);
                        if (mode == 6) damaged[start + 34] = 1;
                        try
                        {
                            Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, before, damaged));
                            if (mode < 2) await Assert.ThrowsAsync<CryptographicException>(() => Commit());
                            else await Assert.ThrowsAsync<InvalidDataException>(() => Commit());
                            Assert.Equal(publications, publication.Calls); Assert.Equal(dispatches, replica.Calls);
                            var persisted = await RouteSnapshot();
                            try { Assert.True(CryptographicOperations.FixedTimeEquals(damaged, persisted)); }
                            finally { CryptographicOperations.ZeroMemory(persisted); }
                        }
                        finally
                        {
                            Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2ContactRouteJournal.Slot, damaged, before));
                            CryptographicOperations.ZeroMemory(damaged);
                        }
                    }
                }
                finally { CryptographicOperations.ZeroMemory(before); }
                await Assert.ThrowsAsync<CryptographicException>(() => accounts.EnsureOwnContactObjectAsync(
                    intent, Source(accounts), configuration, threshold, profile));
                await Assert.ThrowsAsync<CryptographicException>(async () =>
                {
                    using var changed = await accounts.EnsureOwnOneTimeContactObjectAsync(intent, Source(accounts),
                        configuration, threshold, profile + " changed");
                });
                Assert.Equal(1, threshold.Calls);
            }
            finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(invitation).Span); }
        }
    }
}
