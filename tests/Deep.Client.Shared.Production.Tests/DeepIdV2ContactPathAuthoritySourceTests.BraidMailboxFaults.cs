using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_NewControlCapacityAndTransportNamespaceRejectBeforeNativeMutation(int fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, _) = await PrepareRouteFaultPair(fixture); var operation = Bytes(32, 200);
        var before = (await fixture.ReadMessagingFloor(alice)).Exact.ToArray();
        // Adversarial structurally valid protected custody only, NOT genuine
        // sustained delivery/grants or a fake authenticated control/frame.
        var rootHash = await fixture.StageRejectedMailboxSend(alice, operation, Bytes(64, 0x83), fault);
        if (fault == 0)
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedBraid(alice, operation));
        else await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedBraid(alice, operation));
        Assert.Equal(before, (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
        using var root = await fixture.ReadMailboxSends(own: true);
        Assert.Equal(fault == 0 ? ProtectedDid2MailboxSendJournal.MaximumEntries : 1, root.Entries.Count);
        Assert.Equal(rootHash, await fixture.HashMailboxSendRootForBraidTest());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_ControlStorePreparationLateSettlementAndRetirementRecoverEveryHandover(bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture); var operation = Bytes(32, 200);
        using var authored = await fixture.SendOwnedBraid(alice, operation);
        var exact = authored.ExactControl.ToArray();
        var floor = (await fixture.ReadMessagingFloor(alice)).Exact.ToArray();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, alice, operation, exact) { LoseReply = true };
        byte[] originalMau = [], reply = [];
        try
        {
            foreach (var target in new[] { Did2MailboxSendFailpoint.BeforeSql, Did2MailboxSendFailpoint.AfterSql,
                         Did2MailboxSendFailpoint.BeforePreparedRoot, Did2MailboxSendFailpoint.AfterPreparedRoot,
                         Did2MailboxSendFailpoint.BeforeDispatch })
            {
                using var interrupted = new CancellationTokenSource(); var hit = false;
                using (Did2MailboxSendTestHooks.Push(point =>
                    { if (point == target) { hit = true; Interrupt(interrupted); } }))
                    await RequireInterrupted(() => fixture.DeliverBraidWithCancellation(alice, operation, grants, transport, interrupted.Token));
                Assert.True(hit); Assert.Equal(0, transport.Calls);
                Assert.Equal(floor, (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
                using (var sends = await fixture.ReadMailboxSends(own: true))
                {
                    var send = sends.Current(alice.Hash, operation)!; Assert.NotNull(send);
                    var prepared = target is Did2MailboxSendFailpoint.AfterPreparedRoot or Did2MailboxSendFailpoint.BeforeDispatch;
                    Assert.Equal(prepared, send.Prepared); Assert.Equal(prepared ? 1UL : 0UL, Assert.Single(sends.Floors).Value.HighestCounter);
                    Assert.Equal(SHA256.HashData(exact), send.EnvelopeHash.ToArray());
                }
                fixture.ColdReopenBraidStorage(alice);
            }
            fixture.Sample += 40; fixture.ProofTime += 40;
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeBraid(alice, operation, grants, transport));
            Assert.Equal(1, transport.Calls); originalMau = transport.ExactRequest!.ToArray();
            reply = transport.CopyOriginalQuorumForFixture();
            var grant = MailboxAuthenticatedClientRequestCodec.Decode(originalMau).Presentation.Grant;
            fixture.AdvanceStoreSettlementClock(checked(grant.ExpiresAtUnixSeconds + 5));
            foreach (var target in new[] { Did2MailboxSendFailpoint.BeforeSettlementSql, Did2MailboxSendFailpoint.AfterSettlementSql })
            {
                using var interrupted = new CancellationTokenSource(); var hit = false;
                using (Did2MailboxSendTestHooks.Push(point =>
                    { if (point == target) { hit = true; Interrupt(interrupted); } }))
                    await RequireInterrupted(() => fixture.AdoptBraidStoreReply(alice, operation, reply, interrupted.Token));
                Assert.True(hit); Assert.Equal(1, transport.Calls);
                Assert.Equal(floor, (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
                fixture.ColdReopenBraidStorage(alice);
            }
            var stored = await fixture.AdoptBraidStoreReply(alice, operation, reply, default);
            Assert.False(stored.IngressDispatched); Assert.Equal(1UL, stored.Cursor);
            using (var sends = await fixture.ReadMailboxSends(own: true))
            {
                var send = sends.Current(alice.Hash, operation)!; Assert.True(send.Prepared);
                Assert.Equal(SHA256.HashData(originalMau), send.MauHash.ToArray());
            }
            // Protected-only Audit has no SQL mutation/AfterSql handover.
            // Interrupt ALL five real stages of this one original staged plan.
            foreach (var target in new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSqlRecorded,
                         Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterPartsDeleted,
                         Did2CompactionFailpoint.AfterPlanCleared })
            {
                using var interrupted = new CancellationTokenSource(); var hit = false;
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == target) { hit = true; Interrupt(interrupted); } }))
                    await RequireInterrupted(() => fixture.DeliverBraidWithCancellation(alice, operation, grants, transport, interrupted.Token));
                Assert.True(hit); Assert.Equal(1, transport.Calls);
                fixture.ColdReopenBraidStorage(alice);
                Assert.Equal(floor, (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
            }
            var recovered = await fixture.DeliverNativeBraid(alice, operation, grants, transport);
            Assert.False(recovered.IngressDispatched); Assert.Equal(stored.Cursor, recovered.Cursor);
            Assert.Equal(1, transport.Calls); Assert.Equal(originalMau, transport.ExactRequest);
            using (var sends = await fixture.ReadMailboxSends(own: true))
            {
                Assert.Null(sends.Current(alice.Hash, operation));
                Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter);
            }
            using (var retry = await fixture.SendOwnedBraid(alice, operation)) Assert.True(exact.AsSpan().SequenceEqual(retry.ExactControl));
            Assert.Equal(floor, (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
            // Original Stored object's active native purpose is still receivable;
            // retiring redundant send custody never fabricates native progress.
            var retrieval = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
            var terminal = new OwnedReadTerminal(fixture, exact) { RetainedEnvelope = transport.StoredEnvelope, LoseAckReply = true };
            var receiverBefore = (await fixture.ReadMessagingFloor(bob)).Exact.ToArray(); var hitPage = false;
            using (ClientMailboxRetrieveTestHooks.Push(point =>
                { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) { hitPage = true; throw new IOException("Interrupted captured control page."); } }))
                await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(retrieval, terminal));
            Assert.True(hitPage); Assert.Equal(0, terminal.AckCalls);
            Assert.Equal(receiverBefore, (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
            var hitReceive = false;
            using (Did2MessagingCommitTestHooks.Push(point =>
                { if (point == Did2MessagingCommitFailpoint.AfterSql) { hitReceive = true; throw new IOException("Interrupted actual control receive after SQL."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(retrieval, terminal));
            Assert.True(hitReceive); Assert.Equal(0, terminal.AckCalls);
            fixture.ColdReopenBraidStorage(bob);
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(retrieval, terminal));
            var receiverAfter = (await fixture.ReadMessagingFloor(bob)).Exact.ToArray();
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.PollBraidWithCancellation(bob, retrieval, terminal, cancelled.Token));
            }
            Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
            fixture.ColdReopenBraidStorage(bob); fixture.Sample += 40; fixture.ProofTime += 40; terminal.LoseAckReply = false;
            Assert.Equal(1, (await fixture.SynchronizeNativeReceiver(retrieval, terminal)).DurableTombstones);
            Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls);
            Assert.Equal(receiverAfter, (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
            Assert.Empty(await fixture.ListOwnedReceiptObligations(bob));
        }
        finally { foreach (var bytes in new[] { exact, floor, originalMau, reply }) CryptographicOperations.ZeroMemory(bytes); }

        void Interrupt(CancellationTokenSource interrupted)
        { if (cancel) interrupted.Cancel(); else throw new IOException("Interrupted original control transport handover."); }
        async Task RequireInterrupted(Func<Task> action)
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(action);
            else await Assert.ThrowsAsync<IOException>(action);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> HashMailboxSendRootForBraidTest()
        {
            using var raw = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ??
                throw new InvalidDataException("Fixture send root absent.");
            return raw.Use(bytes => SHA256.HashData(bytes));
        }
        internal Task<ClientMailboxStoreResult> DeliverBraidWithCancellation(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory terminal, CancellationToken ct)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.DeliverOwnBraidControlAsync(scope, operation, source, grants, terminal, ct);
        }
        internal Task<ClientMailboxStoreResult> AdoptBraidStoreReply(Did2MessagingSessionScope scope,
            ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> reply, CancellationToken ct)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.AdoptOwnOriginalMailboxStoreReplyAsync(scope, operation, operation, ReadOnlyMemory<byte>.Empty, reply, source, ct);
        }
        internal Task<DeepIdV2MailboxSynchronizationResult> PollBraidWithCancellation(Did2MessagingSessionScope scope,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory terminal, CancellationToken ct)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.SynchronizeOwnMailboxAsync(source, grants, terminal, ct);
        }
    }
}
