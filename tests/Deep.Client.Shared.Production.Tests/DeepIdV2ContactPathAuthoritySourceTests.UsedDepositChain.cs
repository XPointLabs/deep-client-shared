using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2UsedDepositChain_RealStoresRetireOldestAndUnknownSuccessorPins(bool loseReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        await fixture.CheckUsedDepositChainAsync(loseReply);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckUsedDepositChainAsync(bool loseReply)
        {
            var contact = await PrepareCompletedContactSendCase(isInitial: false);
            var firstResult = await DeliverCompletedCaseWithExactRetry(contact);
            var firstDispatches = contact.Transport.Calls;
            byte[] oldest;
            using (var grants = await ReadPeerGrantsAsync())
                oldest = Convert.FromHexString(Assert.Single(grants.Entries).Key);

            // Genuine signed successor and three durable selection transitions
            // through the existing controlled producer fixture. This is owned
            // retirement/consumer evidence, not runtime renewal qualification.
            await StageVerifiedGrantSuccessorAsync(contact.Grants, own: false);
            byte[] newest, successorSeed, successorRequest, successorResponse, successorPolicy, successorRoute;
            using (var grants = await ReadPeerGrantsAsync())
            {
                var selection = Assert.Single(grants.Selections).Value;
                newest = Convert.FromHexString(selection.Current!);
                var entry = grants.Entries[selection.Current!];
                Assert.Equal(2, grants.Entries.Count); Assert.NotEqual(oldest, newest); Assert.Null(selection.Pending);
                successorSeed = ProtectedDid2MailboxGrantJournal.Seed(entry).ToArray();
                successorRequest = ProtectedDid2MailboxGrantJournal.Request(entry).ToArray();
                successorResponse = ProtectedDid2MailboxGrantJournal.Response(entry).ToArray();
                successorPolicy = ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry).ToArray();
                successorRoute = ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).ToArray();
            }
            var operation = Bytes(32, 0xd1); byte[] plaintext, cipher;
            using (var text = await PrepareOwnedText(contact.Scope, operation, "second original Store under successor"))
            {
                plaintext = text.ExactDmc2.ToArray();
                using var sent = await SendOwnedMessage(contact.Scope, operation, ApplicationCoreCodec.DecodeDmc2(plaintext));
                cipher = sent.ExactEnvelope.ToArray();
            }
            var second = new OwnedStoreFixture(this, contact.Scope, operation, cipher, ownerOnPrimary: false)
                { Cursor = 2, LoseReply = loseReply };
            ClientMailboxStoreResult? secondResult = null;
            if (loseReply)
                await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
                    DeliverNativeMessage(contact.Scope, operation, contact.Grants, second));
            else
                secondResult = await DeliverCompletedCaseWithExactRetry(new(contact.Scope, operation, [], contact.Grants, second,
                    () => DeliverNativeMessage(contact.Scope, operation, contact.Grants, second)));
            Assert.NotNull(second.ExactRequest); Assert.Equal(1, contact.Grants.Calls);
            var secondDispatches = second.Calls;
            await AdvanceOriginalStoreEpochForTestAsync(2_100);
            await RetireCompletedContactSend(contact);
            var account = ReopenGrantReader();
            using (var exclusion = await account.OpenMailboxEpochExclusionAsync(oldest, GrantReaderSource(account)))
                await exclusion.RetireIdleMailboxCounterFloorAsync();

            if (loseReply)
            {
                using var grantBefore = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                using var sendBefore = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                using var planBefore = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                var sqlBefore = await ReadCompleteOrdinaryApplicationProjection(contact.Scope);
                var nativeBefore = (await ReadMessagingFloor(contact.Scope)).Exact.ToArray();
                await Assert.ThrowsAsync<IOException>(() => account.RetireUsedDepositAcquisitionAsync(oldest, GrantReaderSource(account)));
                using var grantAfter = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
                using var sendAfter = await peerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
                using var planAfter = await peerStorage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                Assert.Equal(grantBefore.Use(bytes => bytes.ToArray()), grantAfter.Use(bytes => bytes.ToArray()));
                Assert.Equal(sendBefore.Use(bytes => bytes.ToArray()), sendAfter.Use(bytes => bytes.ToArray()));
                Assert.Equal(planBefore.Use(bytes => bytes.ToArray()), planAfter.Use(bytes => bytes.ToArray()));
                Assert.Equal(sqlBefore, await ReadCompleteOrdinaryApplicationProjection(contact.Scope));
                Assert.Equal(nativeBefore, (await ReadMessagingFloor(contact.Scope)).Exact.ToArray());
                using var working = await ReadMailboxSends(own: false);
                var pending = Assert.Single(working.Entries).Value;
                Assert.Equal(operation, pending.Operation.ToArray()); Assert.True(pending.Prepared);
            }
            else
            {
                // The real ordinary producer removes only completed working
                // state; original SQL/body/history/receipt custody remains.
                await CompactNativeOrdinaryOutbox(contact.Scope, default);
                account = ReopenGrantReader();
                using (var exclusion = await account.OpenMailboxEpochExclusionAsync(newest, GrantReaderSource(account)))
                    await exclusion.RetireIdleMailboxCounterFloorAsync();
                var sql = await ReadCompleteOrdinaryApplicationProjection(contact.Scope);
                var native = (await ReadMessagingFloor(contact.Scope)).Exact.ToArray();
                var sourceSql = await ReadCompletedContactSendSourceProjection(contact.Scope);
                var heldRoots = await ReadUsedDepositRetainedRoots(contact.Scope);
                var wrongOrder = await Assert.ThrowsAsync<IOException>(() =>
                    account.RetireUsedDepositAcquisitionAsync(newest, GrantReaderSource(account)));
                Assert.Contains("oldest first", wrongOrder.Message);
                using (Did2CompactionTestHooks.Push(point =>
                {
                    if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Injected real used-chain handover.");
                }))
                    await Assert.ThrowsAsync<IOException>(() => account.RetireUsedDepositAcquisitionAsync(oldest, GrantReaderSource(account)));
                ColdReopenReceiverStoreStorage(); await PeerRetirementOwner().ResumeOwnedLocalCompactionAsync(default);
                using (var remaining = await ReadPeerGrantsAsync())
                {
                    var selection = Assert.Single(remaining.Selections).Value;
                    Assert.Equal(Convert.ToHexString(newest), selection.Current); Assert.Equal(selection.Current, selection.RetainedTail);
                    var entry = Assert.Single(remaining.Entries).Value;
                    Assert.Equal(successorSeed, ProtectedDid2MailboxGrantJournal.Seed(entry).ToArray());
                    Assert.Equal(successorRequest, ProtectedDid2MailboxGrantJournal.Request(entry).ToArray());
                    Assert.Equal(successorResponse, ProtectedDid2MailboxGrantJournal.Response(entry).ToArray());
                    Assert.Equal(successorPolicy, ProtectedDid2MailboxGrantJournal.OriginalPolicy(entry).ToArray());
                    Assert.Equal(successorRoute, ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).ToArray());
                }
                account = ReopenGrantReader();
                await account.RetireUsedDepositAcquisitionAsync(newest, GrantReaderSource(account));
                using (var empty = await ReadPeerGrantsAsync()) { Assert.Empty(empty.Entries); Assert.Empty(empty.Selections); }
                Assert.Equal(sql, await ReadCompleteOrdinaryApplicationProjection(contact.Scope));
                Assert.Equal(native, (await ReadMessagingFloor(contact.Scope)).Exact.ToArray());
                Assert.Equal(sourceSql, await ReadCompletedContactSendSourceProjection(contact.Scope));
                Assert.Equal(heldRoots, await ReadUsedDepositRetainedRoots(contact.Scope));
                var firstCached = await contact.Deliver();
                var secondCached = await DeliverNativeMessage(contact.Scope, operation, contact.Grants, second);
                Assert.False(firstCached.IngressDispatched); Assert.Equal(firstResult.Cursor, firstCached.Cursor);
                Assert.False(secondCached.IngressDispatched); Assert.Equal(secondResult!.Cursor, secondCached.Cursor);
                using (var replay = await SendOwnedMessage(contact.Scope, operation, ApplicationCoreCodec.DecodeDmc2(plaintext)))
                    Assert.Equal(cipher, replay.ExactEnvelope.ToArray());
                Assert.Equal("second original Store under successor", Assert.Single(await ListOwnedMessages(contact.Scope)).Text);
                Assert.Equal(sql, await ReadCompleteOrdinaryApplicationProjection(contact.Scope));
                Assert.Equal(native, (await ReadMessagingFloor(contact.Scope)).Exact.ToArray());
                Assert.True(contact.Transport.StoredEnvelope!.ExpiresAtUnixSeconds > 2_100);
                Assert.True(second.StoredEnvelope!.ExpiresAtUnixSeconds > 2_100);
            }
            Assert.Equal(firstDispatches, contact.Transport.Calls); Assert.Equal(secondDispatches, second.Calls);
            Assert.Equal(1, contact.Grants.Calls);
            foreach (var bytes in new[] { oldest, newest, successorSeed, successorRequest, successorResponse,
                successorPolicy, successorRoute, operation, plaintext, cipher }) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
