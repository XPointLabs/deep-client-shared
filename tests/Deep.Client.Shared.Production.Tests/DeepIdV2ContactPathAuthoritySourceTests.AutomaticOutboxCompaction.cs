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
    public async Task Did2AutomaticOutboxCompaction_PublicSendColdRecoversEveryHandoverAndPinsUnknownPrefix()
    {
        // Genuine committed commands/ratchet/SQLCipher/receipts, not manufactured
        // occupancy; synthetic signed services, NOT sockets, device or512/128 soak.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using (var reply = await fixture.CreateOwnedText(receiver, "receipt obligation survives automatic cleanup"))
        using (var sent = await fixture.SendOwnedMessage(receiver, reply.OperationId.ToArray(), ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var receipt = Assert.Single(await fixture.ListOwnedReceiptObligations(sender)).EventHash.ToArray();
        var delivered = 0;
        var feedback = 0;
        async Task DeliverAndAdvanceBraid(OwnedStoreFixture transport)
        {
            using (var received = await fixture.ReceiveOwnedMessage(receiver,
                transport.StoredEnvelope!.Ciphertext.ToArray())) { }
            delivered++;
            // Real peer receive/reply drives the pinned native Braid. Merely
            // storing32 unanswered envelopes cannot create fresh PQ output.
            if (delivered % 4 != 0) return;
            using var reply = await fixture.CreateOwnedText(receiver, "native Braid feedback " + feedback);
            var replyOperation = reply.OperationId.ToArray();
            using var sent = await fixture.SendOwnedMessage(receiver, replyOperation, ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span));
            using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            feedback++;
        }
        async Task AssertRetainedReceipts()
        {
            var retained = await fixture.ListOwnedReceiptObligations(sender);
            Assert.Equal(1 + feedback, retained.Count);
            Assert.Single(retained, item => item.EventHash.Span.SequenceEqual(receipt));
        }
        var handle = await fixture.ReadAutomaticMaintenanceConversation(sender);
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        OwnedStoreFixture? firstTransport = null;
        byte[]? originalOperation = null;
        for (var index = 0; index < Did2CompactionPlan.MaximumRows; index++)
        {
            var operation = await fixture.QueueAutomaticMaintenanceText(handle, "cohort " + index);
            var transport = new OwnedStoreFixture(fixture, sender, operation, null);
            _ = await fixture.SendAutomaticMaintenanceText(handle, operation, "cohort " + index, grants, transport);
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            Assert.Equal(1, transport.Calls);
            firstTransport ??= transport;
            originalOperation ??= operation.ToArray();
            await DeliverAndAdvanceBraid(transport);
        }
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Equal(32, sends.Entries.Count); Assert.Equal(32UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        Assert.Equal(8, feedback);
        await fixture.AssertAutomaticMaintenanceHistory(sender, outgoing: 32, incoming: 1 + feedback);
        var beforeFloor = await fixture.ReadAutomaticMaintenanceFloorDigest(sender);
        var beforeGrantCalls = grants.Calls;
        // One real32-row batch crosses all fault boundaries without restoring
        // snapshots or calling an explicit compaction API between public retries.
        // A valid ordinary batch commits; AfterAbandonRecorded belongs to the
        // separately tested rejected-plan recovery, not this success handover.
        foreach (var point in new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSql,
            Did2CompactionFailpoint.AfterSqlRecorded, Did2CompactionFailpoint.AfterHistoryAdopted,
            Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared })
        {
            var hit = false;
            using (Did2CompactionTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Interrupted automatic ordinary maintenance."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.QueueAutomaticMaintenanceText(handle, "after cleanup"));
            Assert.True(hit, "The actual ordinary handover must reach its selected fault boundary.");
            Assert.Equal(beforeGrantCalls, grants.Calls);
            Assert.Equal(beforeFloor, await fixture.ReadAutomaticMaintenanceFloorDigest(sender));
            fixture.ColdReopenCompactionStorage();
        }
        var nextOperation = await fixture.QueueAutomaticMaintenanceText(handle, "after cleanup");
        var nextTransport = new OwnedStoreFixture(fixture, sender, nextOperation, null);
        _ = await fixture.SendAutomaticMaintenanceText(handle, nextOperation, "after cleanup", grants, nextTransport);
        fixture.AdvanceSyntheticMailboxClockPast(nextTransport.DurableTimeForFixture);
        await DeliverAndAdvanceBraid(nextTransport);
        Assert.Equal(1, nextTransport.Calls); Assert.Equal(beforeGrantCalls, grants.Calls);
        await fixture.AssertSenderCompactionIdle(sender);
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Single(sends.Entries); Assert.Equal(33UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        await fixture.AssertAutomaticMaintenanceHistory(sender, outgoing: 33, incoming: 1 + feedback);
        await AssertRetainedReceipts();
        var afterFloor = await fixture.ReadAutomaticMaintenanceFloorDigest(sender);
        var cached = await fixture.SendAutomaticMaintenanceText(handle, originalOperation!, "cohort 0", grants, firstTransport!);
        Assert.False(cached.IngressDispatched); Assert.Equal(1, firstTransport!.Calls);
        Assert.Equal(afterFloor, await fixture.ReadAutomaticMaintenanceFloorDigest(sender));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendAutomaticMaintenanceText(handle,
            originalOperation!, "changed compacted text", grants, firstTransport));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendAutomaticMaintenanceText(handle,
            nextOperation, "changed retained text", grants, nextTransport));
        Assert.Equal(afterFloor, await fixture.ReadAutomaticMaintenanceFloorDigest(sender));
        Assert.Equal(1, firstTransport.Calls); Assert.Equal(1, nextTransport.Calls);
        using (var received = await fixture.ReceiveOwnedMessage(receiver, firstTransport.StoredEnvelope!.Ciphertext.ToArray())) { }
        await fixture.AssertAutomaticMaintenanceHistory(receiver, outgoing: 1 + feedback, incoming: 33); // Exact replay, no new semantic effect.

        var unknownOperation = await fixture.QueueAutomaticMaintenanceText(handle, "unknown cannot be evicted");
        var unknown = new OwnedStoreFixture(fixture, sender, unknownOperation, null) { LoseReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SendAutomaticMaintenanceText(
            handle, unknownOperation, "unknown cannot be evicted", grants, unknown));
        await DeliverAndAdvanceBraid(unknown); // Lost Store reply is not evidence of non-delivery.
        // Grow beyond the maintenance batch with an unsettled earliest command.
        // A later settled suffix cannot be selected past that pinned position.
        for (var index = 0; index < Did2CompactionPlan.MaximumRows; index++)
        {
            var operation = await fixture.QueueAutomaticMaintenanceText(handle, "after unknown " + index);
            var transport = new OwnedStoreFixture(fixture, sender, operation, null);
            _ = await fixture.SendAutomaticMaintenanceText(handle, operation, "after unknown " + index, grants, transport);
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            await DeliverAndAdvanceBraid(transport);
        }
        using (var sends = await fixture.ReadMailboxSends())
        {
            Assert.Equal(33, sends.Entries.Count);
            Assert.Contains(sends.Entries.Values, entry => CryptographicOperations.FixedTimeEquals(entry.Operation, unknownOperation));
            Assert.Equal(66UL, Assert.Single(sends.Floors).Value.HighestCounter);
        }
        Assert.Equal(16, feedback);
        await fixture.AssertAutomaticMaintenanceHistory(sender, outgoing: 66, incoming: 1 + feedback);
        await fixture.AssertAutomaticMaintenanceHistory(receiver, outgoing: 1 + feedback, incoming: 66);
        await AssertRetainedReceipts();
        unknown.LoseReply = false; fixture.Sample += 40; fixture.ProofTime += 40;
        _ = await fixture.SendAutomaticMaintenanceText(handle, unknownOperation, "unknown cannot be evicted", grants, unknown);
        Assert.Equal(2, unknown.Calls);
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Equal(33, sends.Entries.Count); Assert.Equal(66UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        await fixture.AssertAutomaticMaintenanceHistory(sender, outgoing: 66, incoming: 1 + feedback); // Exact retry, no second logical effect.
        await AssertRetainedReceipts();
        foreach (var bytes in new[] { receipt, beforeFloor, afterFloor }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertAutomaticMaintenanceHistory(Did2MessagingSessionScope scope, int outgoing, int incoming)
        {
            var history = await ListOwnedMessages(scope);
            Assert.Equal(outgoing + incoming, history.Count);
            Assert.Equal(outgoing, history.Count(message => message.IsLocalAuthor));
            Assert.Equal(incoming, history.Count(message => !message.IsLocalAuthor));
        }

        internal async Task<DeepIdV2Conversation> ReadAutomaticMaintenanceConversation(Did2MessagingSessionScope scope)
            => (await ReadApplicationConversation(scope)).Handle;

        internal Task<ClientMailboxStoreResult> SendAutomaticMaintenanceText(DeepIdV2Conversation conversation,
            byte[] operation, string text, OwnedGrantTransport grants, OwnedStoreFixture transport)
        {
            var account = ReopenAccount();
            return account.RetryTextAsync(conversation, operation, text, Source(account), grants, transport);
        }
        internal async Task<byte[]> QueueAutomaticMaintenanceText(DeepIdV2Conversation conversation, string text)
        {
            var account = ReopenAccount();
            return (await account.QueueTextAsync(conversation, text, Source(account))).ToArray();
        }

        internal async Task<byte[]> ReadAutomaticMaintenanceFloorDigest(Did2MessagingSessionScope scope)
        {
            using var root = await storage.ReadOwnedAsync(scope.FloorSlot) ?? throw new InvalidDataException();
            return root.Use(bytes => SHA256.HashData(bytes));
        }
    }
}
