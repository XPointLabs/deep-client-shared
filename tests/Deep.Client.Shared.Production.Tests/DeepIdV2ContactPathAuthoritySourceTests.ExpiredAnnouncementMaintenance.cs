using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ConnectedMaintenance_ExpiredPeerAnnouncementUsesVerifiedKnownPeerForExactNativeOriginalOnly()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.CheckExpiredAnnouncementMaintenanceAsync();
    }

    private sealed partial class Fixture
    {
        internal async Task CheckExpiredAnnouncementMaintenanceAsync()
        {
            var (sender, receiver) = await PrepareRouteHistoryPair();
            using var peerAnnouncement = await CreateOwnedRouteUpdate(receiver);
            var oldPeerMessage = ApplicationCoreCodec.DecodeDmc2(peerAnnouncement.ExactDmc2.Span);
            using (var peerNative = await SendOwnedRouteUpdate(receiver, peerAnnouncement.OperationId))
            using (await ReceiveOwnedMessage(sender, peerNative.ExactEnvelope.ToArray())) { }
            await RequireCurrentNativeRoute(sender);
            AdvanceControlClock(oldPeerMessage.ExpiresAtUnixMilliseconds, past: true);
            var account = ReopenAccount(); var source = Source(account); var conversation = new DeepIdV2Conversation(sender);
            var health = await account.ReadContactRouteHealthAsync(conversation, source);
            Assert.True(health.AdvertisementIntervalCoversNow); Assert.False(health.RouteFaultRetained);
            await Assert.ThrowsAsync<CryptographicException>(() => account.RequireCurrentContactRouteAsync(conversation, source));

            // This is the control already committed by the old maintenance
            // ordering before it discovered the expired remote announcement.
            using var original = await CreateOwnedRouteUpdate(sender);
            var operation = original.OperationId.ToArray(); var exactDmc = original.ExactDmc2.ToArray(); byte[] ciphertext;
            using (var native = await SendOwnedRouteUpdate(sender, operation)) ciphertext = native.ExactEnvelope.ToArray();
            var current = (await source.VerifyForOwnMessagingAsync(account, sender, default)).Own.Proof;
            Assert.True(checked(current.TrustedUpperUnixSeconds * 1000) <
                ApplicationCoreCodec.DecodeDmc2(exactDmc).ExpiresAtUnixMilliseconds);
            var floor = (await ReadMessagingFloor(sender)).Exact.ToArray();
            var authoredHash = await ReadAuthoredRootDigestAsync();
            using var authored = await ReadAuthoredTextJournalAsync(sender);
            var grants = new OwnedGrantTransport(this, ownerOnPrimary: true);
            var terminal = new OwnedStoreFixture(this, sender, operation, ciphertext);
            var read = new SyntheticPermanentRead(this, source, nativeMessagingPublication);
            var address = nativeMessagingContact!.Candidate.Address;

            var missing = await account.MaintainPublishedContactRouteAsync(conversation, null, source,
                default, read, grants, terminal);
            Assert.Equal(0, missing.Completed); Assert.True(missing.Deferred); Assert.False(missing.Reintroduced);
            Assert.Equal(0, read.Calls); Assert.Equal(0, grants.Calls); Assert.Equal(0, terminal.Calls);
            Assert.Equal(authoredHash, await ReadAuthoredRootDigestAsync());
            Assert.Equal(floor, (await ReadMessagingFloor(sender)).Exact.ToArray());

            read.CorruptReceipt = true;
            try
            {
                await Assert.ThrowsAsync<CryptographicException>(() => account.MaintainPublishedContactRouteAsync(
                    conversation, address, source, default, read, grants, terminal));
            }
            finally { read.CorruptReceipt = false; }
            Assert.True(read.Calls > 0); Assert.Equal(0, grants.Calls); Assert.Equal(0, terminal.Calls);
            Assert.Equal(authoredHash, await ReadAuthoredRootDigestAsync());
            Assert.Equal(floor, (await ReadMessagingFloor(sender)).Exact.ToArray());

            var completed = await account.MaintainPublishedContactRouteAsync(conversation, address, source,
                default, read, grants, terminal);
            Assert.Equal(1, completed.Completed); Assert.True(completed.Reintroduced); Assert.True(completed.Deferred);
            Assert.Equal(1, grants.Calls); Assert.Equal(1, terminal.Calls);
            Assert.Equal(ciphertext, terminal.StoredEnvelope!.Ciphertext.ToArray());
            Assert.Equal(floor, (await ReadMessagingFloor(sender)).Exact.ToArray());
            using (var after = await ReadAuthoredTextJournalAsync(sender))
            {
                Assert.Equal(authored.NextSequence(sender), after.NextSequence(sender));
                Assert.Equal(authored.Entries.Count, after.Entries.Count);
                Assert.Equal(authored.Entries[Convert.ToHexString(operation)].EventHash,
                    after.Entries[Convert.ToHexString(operation)].EventHash);
            }
            // Store of our update does not promote the independently expired
            // peer L, and never turns this result into current-route permission.
            await Assert.ThrowsAsync<CryptographicException>(() => account.RequireCurrentContactRouteAsync(conversation, source));
            ColdReopenCompactionStorage();
            using (var retry = await RetryOwnedRouteUpdate(sender, operation)) Assert.Equal(exactDmc, retry.ExactDmc2.ToArray());
            using (var retry = await SendOwnedRouteUpdate(sender, operation)) Assert.Equal(ciphertext, retry.ExactEnvelope.ToArray());
            var replay = new OwnedStoreFixture(this, sender, operation, ciphertext);
            _ = await DeliverNativeMessage(sender, operation, new OwnedGrantTransport(this, ownerOnPrimary: true), replay);
            Assert.Equal(0, replay.Calls);
            Assert.Equal(floor, (await ReadMessagingFloor(sender)).Exact.ToArray());
            foreach (var bytes in new[] { operation, exactDmc, ciphertext, floor }) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
