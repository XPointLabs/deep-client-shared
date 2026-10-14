using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("BeforeSql")]
    [InlineData("AfterSql")]
    [InlineData("AfterPreparedRoot")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ExpiredAttempt_ClosesOriginalUnknownAndColdPreservesAnySqlReservedCounter(string preparationFault)
    {
        // Real two-account PQ/SQLCipher; synthetic signed control plane. This
        // tests closure, not successor dispatch, remote denial or device E2E.
        var interruption = Enum.Parse<Did2MailboxSendFailpoint>(preparationFault);
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x81));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x82)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using var text = await fixture.CreateOwnedText(sender, "closed admission does not prove non-delivery");
        var operation = text.OperationId.ToArray();
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        var interrupted = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != interruption) return;
            interrupted = true; throw new IOException("Interrupted original request preparation.");
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.True(interrupted); Assert.Equal(1, grants.Calls); Assert.Equal(0, transport.Calls);
        byte[] original;
        using (var sends = await fixture.ReadMailboxSends()) original = Assert.Single(sends.Entries).Value.Exact.ToArray();
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenCompactionStorage();
        var nativeFloor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var authored = await fixture.ReadAuthoredRootDigestAsync();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        try
        {
            foreach (var point in new[] { Did2MailboxSendFailpoint.BeforeClosureRoot, Did2MailboxSendFailpoint.AfterClosureRoot })
            {
                var hit = false;
                using (Did2MailboxSendTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Interrupted original admission closure."); } }))
                    await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
                Assert.True(hit); Assert.Equal(1, grants.Calls); Assert.Equal(0, transport.Calls);
                using (var sends = await fixture.ReadMailboxSends())
                {
                    var entry = Assert.Single(sends.Entries).Value;
                    Assert.Equal(original[..256], entry.Exact[..256].ToArray());
                    Assert.Equal(point == Did2MailboxSendFailpoint.AfterClosureRoot, entry.Closed);
                    if (entry.Closed)
                    {
                        Assert.True(entry.ClosedAtLower >= entry.AdmissionUntil);
                        Assert.Equal(interruption != Did2MailboxSendFailpoint.BeforeSql, entry.Prepared);
                        Assert.Equal(interruption == Did2MailboxSendFailpoint.BeforeSql ? 0UL : 1UL, entry.Counter);
                        Assert.Equal(entry.Counter, Assert.Single(sends.Floors).Value.HighestCounter);
                        Assert.False(entry.HasSuccessor);
                    }
                }
                fixture.ColdReopenCompactionStorage();
            }
            byte[] closed;
            using (var sends = await fixture.ReadMailboxSends()) closed = Assert.Single(sends.Entries).Value.Exact.ToArray();
            try
            {
                // The retained native recipient route belongs to the old epoch;
                // closure alone cannot make it a current replacement route.
                await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
                using var sends = await fixture.ReadMailboxSends();
                Assert.Equal(closed, Assert.Single(sends.Entries).Value.Exact.ToArray());
            }
            finally { CryptographicOperations.ZeroMemory(closed); }
            Assert.Equal(nativeFloor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(authored, await fixture.ReadAuthoredRootDigestAsync());
            Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
            Assert.Single(await fixture.ListOwnedMessages(sender));
            Assert.Equal(1, grants.Calls); Assert.Equal(0, transport.Calls);
        }
        finally { foreach (var bytes in new[] { original, nativeFloor, authored, application }) CryptographicOperations.ZeroMemory(bytes); }
    }
}
