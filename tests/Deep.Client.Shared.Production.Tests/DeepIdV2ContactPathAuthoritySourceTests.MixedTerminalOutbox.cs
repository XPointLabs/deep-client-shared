using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MixedTerminalOutbox_CancelledDraftCannotPinSuccessfulPublicSendPrefix()
    {
        // Real account owner, native crypto, SQLCipher and signed in-process
        // services. Controlled fixture time, not physical or elapsed-time E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true,
            encryptedStorage: true, longMailboxWindow: true);
        static byte[] Operation(string purpose, int index) =>
            SHA256.HashData(Encoding.UTF8.GetBytes("S04/mixed-terminal/" + purpose + "/" + index));
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Operation("hello", 0));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Operation("accept", 0)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(),
            ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }

        byte[] cancelled;
        using (var draft = await fixture.CreateOwnedText(sender, "cancelled before encryption"))
            cancelled = draft.OperationId.ToArray();
        var beforeCancel = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        await fixture.CancelNativeMessagingWork(sender, cancelled);
        Assert.Equal(beforeCancel, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        var handle = await fixture.ReadAutomaticMaintenanceConversation(sender);
        var feedback = 0;
        for (var index = 0; index <= Did2CompactionPlan.MaximumRows; index++)
        {
            var operation = await fixture.QueueAutomaticMaintenanceText(handle, "mixed text " + index);
            var transport = new OwnedStoreFixture(fixture, sender, operation, null);
            var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
            _ = await fixture.SendAutomaticMaintenanceText(handle, operation, "mixed text " + index, grants, transport);
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            Assert.Equal(1, transport.Calls);
            using (var received = await fixture.ReceiveOwnedMessage(receiver,
                transport.StoredEnvelope!.Ciphertext.ToArray())) { }
            if ((index + 1) % 4 != 0) continue;
            using var reply = await fixture.CreateOwnedText(receiver, "mixed feedback " + feedback);
            var replyOperation = reply.OperationId.ToArray();
            using var sent = await fixture.SendOwnedMessage(receiver, replyOperation,
                ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span));
            using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            feedback++;
        }
        fixture.ColdReopenCompactionStorage();
        await fixture.AssertSenderCompactionIdle(sender);
        using (var sends = await fixture.ReadMailboxSends())
            Assert.InRange(sends.Entries.Count, 1, Did2CompactionPlan.MaximumRows);
        var beforeRetry = await fixture.ReadAutomaticMaintenanceFloorDigest(sender);
        await Assert.ThrowsAsync<IOException>(() => fixture.RetryOwnedText(sender,
            cancelled, "cancelled before encryption"));
        Assert.Equal(beforeRetry, await fixture.ReadAutomaticMaintenanceFloorDigest(sender));
        await fixture.AssertAutomaticMaintenanceHistory(sender,
            outgoing: Did2CompactionPlan.MaximumRows + 1, incoming: feedback);
        await fixture.AssertAutomaticMaintenanceHistory(receiver,
            outgoing: feedback, incoming: Did2CompactionPlan.MaximumRows + 1);
        foreach (var bytes in new[] { beforeCancel, beforeRetry }) CryptographicOperations.ZeroMemory(bytes);
    }
}
