using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(true, false)] [InlineData(false, false)]
    [InlineData(true, true)] [InlineData(false, true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactControlStop_UnknownWorkCannotDispatchAfterStopAndColdReplyLoss(bool initial, bool loseStopReply)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(initial);
        test.Transport.LoseReply = true;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(test.Deliver);
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope);
        var source = await fixture.ReadCompletedContactSendSourceProjection(test.Scope);
        var secure = fixture.CompletedContactSendStorage(initial);
        using var send = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        var sends = send.Use(bytes => bytes.ToArray());
        if (loseStopReply)
        {
            using (Did2MailboxSendTestHooks.Push(point =>
                { if (point == Did2MailboxSendFailpoint.AfterWorkStopRoot) throw new IOException("Lost committed control stop reply."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(test.Scope, test.Operation));
        }
        else await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        if (initial) fixture.ColdReopenCompactionStorage(); else fixture.ColdReopenReceiverStoreStorage();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled);
        fixture.RejectContactRetryRecipient(initial);
        var grantCalls = test.Grants.Calls; var transportCalls = test.Transport.Calls;
        for (var retry = 0; retry < 2; retry++) await Assert.ThrowsAsync<IOException>(test.Deliver);
        Assert.Equal(grantCalls, test.Grants.Calls); Assert.Equal(transportCalls, test.Transport.Calls);
        Assert.Equal(0, fixture.RejectedContactRetryProofCalls); Assert.Equal(0, fixture.RejectedContactRetryReadCalls);
        using var sendAfter = await secure.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
        Assert.True(sendAfter.Use(bytes => bytes.SequenceEqual(sends)));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        var expiredVirtual = await fixture.CaptureStoppedControlAudit(test, expire: true);
        Assert.Equal(expiredVirtual.Before, await fixture.ReadCompleteOrdinaryApplicationProjection(test.Scope));
        Assert.Equal(application, expiredVirtual.After); // Only the content-free audit row changed.
        Assert.Equal(source, await fixture.ReadCompletedContactSendSourceProjection(test.Scope));
        foreach (var bytes in new[] { native, application, source, sends, expiredVirtual.Before, expiredVirtual.After }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactControlStop_UnencryptedAcceptanceCannotReauthorOrFirstEncryptAfterCancel()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var test = await fixture.PrepareCompletedContactSendCase(false, encryptAcceptance: false);
        byte[] accepted;
        using (var draft = await fixture.PrepareOwnedContactAccept(test.Scope, test.Operation)) accepted = draft.ExactDmc2.ToArray();
        var native = (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray();
        await fixture.CancelNativeMessagingWork(test.Scope, test.Operation);
        fixture.ColdReopenReceiverStoreStorage();
        await fixture.AssertControlStopMetadata(test, ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled);
        await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedContactAccept(test.Scope, test.Operation));
        await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedMessage(test.Scope, test.Operation, ApplicationCoreCodec.DecodeDmc2(accepted)));
        Assert.Equal(native, (await fixture.ReadMessagingFloor(test.Scope)).Exact.ToArray());
        Assert.Equal(0, test.Grants.Calls); Assert.Equal(0, test.Transport.Calls);
        Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await fixture.ReadOwnedContactState(test.Scope));
        CryptographicOperations.ZeroMemory(accepted); CryptographicOperations.ZeroMemory(native);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertControlStopMetadata(CompletedContactSendCase test, ProtectedDid2DirectTextJournal.WorkStopReason reason, bool retired = true)
        {
            var initial = test.Scope.IsInitiator;
            using var raw = await CompletedContactSendStorage(initial).ReadOwnedAsync(initial ? ProtectedDid2ContactStartJournal.Slot : ProtectedDid2ContactAcceptJournal.Slot) ?? throw new InvalidDataException();
            if (initial)
            {
                using var journal = raw.Use(bytes => ProtectedDid2ContactStartJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = journal.Entries[Convert.ToHexString(test.Intent)];
                Assert.Equal(reason, entry.StopReason); Assert.True(entry.WorkStopped); Assert.True(entry.StoppedAtUpper > 0);
                Assert.Equal(retired, entry.PayloadRetired); Assert.Equal(retired ? 1 : 0, entry.AuditDisposition);
            }
            else
            {
                using var journal = raw.Use(bytes => ProtectedDid2ContactAcceptJournal.Decode(bytes, test.Scope.Network, test.Scope.LocalAccount, test.Scope.Instance));
                var entry = journal.FindScope(test.Scope) ?? throw new InvalidDataException();
                Assert.Equal(reason, entry.StopReason); Assert.True(entry.WorkStopped); Assert.True(entry.StoppedAtUpper > 0);
                Assert.Equal(retired, entry.PayloadRetired); Assert.Equal(retired ? 1 : 0, entry.AuditDisposition);
            }
        }
    }
}
