using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteProcessing_ActualMailboxAckRetainsFirstAcceptedOrExpiredOutcome(bool expiredBeforeReceive)
    {
        // Real native account/session/counter/receive and protected page/ACK.
        // Witnesses and terminal remain in-process signed fixtures, not devices.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x71));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x72)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        fixture.TrackMailboxDispatchClock();
        // Actual threshold-signed successor with a shorter route window than
        // the still-current independent directory/network authority.
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray();
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation)) ciphertext = sent.ExactEnvelope.ToArray();
        if (expiredBeforeReceive) fixture.AdvanceRouteProcessingPast(message.ExpiresAtUnixMilliseconds);
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var terminal = new OwnedReadTerminal(fixture, ciphertext) { LoseAckReply = true };
        var before = await fixture.ReadMessagingFloor(receiver);
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
        byte[] processing;
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
        {
            processing = replay.RouteProcessing.ToArray();
            Assert.Equal(expiredBeforeReceive ? 2 : 1, processing[0]);
        }
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(1, committed.Status); // Rejected route does not erase/latch live TRS.
        Assert.Equal(before.Ordinal + 1, committed.Ordinal);
        Assert.Equal(before.RatchetGeneration + 1, committed.RatchetGeneration);
        // Actual protected-prefix compaction must retain both the positive
        // outcome and rejected fault; cold ACK/replay cannot reclassify either.
        await fixture.CompactHistoricalPeerRoutePrefix(receiver);
        fixture.ColdReopenReceiverStoreStorage();
        fixture.AdvanceRouteProcessingPast(message.ExpiresAtUnixMilliseconds);
        // Respect the actual persisted outcome-unknown retry lease. For the
        // already-expired case the previous call need not advance the clock.
        fixture.AdvanceRouteProcessingRetryClock();
        terminal.LoseAckReply = false;
        var completed = await fixture.SynchronizeNativeReceiver(grants, terminal);
        Assert.Equal(1, completed.ProcessedEnvelopes); Assert.Equal(1, completed.DurableTombstones);
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls); Assert.Equal(1, grants.Calls);
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
            Assert.Equal(processing, replay.RouteProcessing.ToArray());
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Empty(await fixture.ListOwnedMessages(receiver));
        Assert.Empty(await fixture.ListOwnedReceiptObligations(receiver));
        if (expiredBeforeReceive)
        {
            var blockedGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
            var blockedTransport = new RejectInitialDispatchFactory();
            var error = await Assert.ThrowsAsync<CryptographicException>(() => fixture.QueueNativeText(receiver,
                "must not dispatch across a retained route fault"));
            Assert.Contains("Retained authenticated route fault", error.Message, StringComparison.Ordinal);
            Assert.Equal(0, blockedGrants.Calls); Assert.Equal(0, blockedTransport.Calls);
        }
    }

    [Theory]
    [InlineData("AfterPending", false)] [InlineData("AfterSql", false)] [InlineData("AfterStable", false)]
    [InlineData("AfterPending", true)] [InlineData("AfterSql", true)] [InlineData("AfterStable", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteProcessing_ActualOwnedControlCommitsFirstOutcomeAndColdExactReplay(string fault, bool cancellation)
    {
        // Two real owned PQ accounts, adopted witness-signed publication,
        // protected authored command, native ratchet and SQLCipher. In-process
        // signed services are not socket, device or shipping evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x61));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x62)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        using var command = await fixture.CreateOwnedRouteUpdate(sender);
        var operation = command.OperationId.ToArray();
        var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
        Assert.Equal(Dmc2ContentKind.ContactRouteUpdate, message.ContentKind);
        // Raw control emission still cannot enter the generic ordinary facade.
        await Assert.ThrowsAsync<NotSupportedException>(() => fixture.SendOwnedMessage(sender, operation, message));
        byte[] ciphertext;
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, operation))
        {
            ciphertext = sent.ExactEnvelope.ToArray();
            Assert.Equal(SHA256.HashData(command.ExactDmc2.Span), sent.EventHash.ToArray());
            Assert.Equal(new byte[64], sent.RouteProcessing.ToArray());
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        var interrupted = false; var failpoint = Enum.Parse<Did2MessagingCommitFailpoint>(fault);
        using var cancel = new CancellationTokenSource();
        using (Did2MessagingCommitTestHooks.Push(point =>
        {
            if (point != failpoint) return;
            interrupted = true;
            if (cancellation) cancel.Cancel();
            else throw new IOException("Injected route-processing commit interruption.");
        }))
        {
            if (cancellation) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.ReceiveOwnedMessage(receiver, ciphertext, cancel.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.ReceiveOwnedMessage(receiver, ciphertext));
        }
        Assert.True(interrupted);
        var pending = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(failpoint == Did2MessagingCommitFailpoint.AfterStable ? 1 : 2, pending.Phase);
        Assert.Equal(before.Ordinal + 1, pending.Ordinal);
        var firstProcessing = pending.Phase == 2 ? await fixture.ReadPendingRouteProcessing(receiver, pending) :
            await fixture.ReadStableRouteProcessing(receiver, operation, pending);
        Assert.Equal(1, firstProcessing[0]);
        fixture.ColdReopenReceiverStoreStorage();
        fixture.AdvanceRouteProcessingPast(message.ExpiresAtUnixMilliseconds);
        byte[] processing;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
        {
            processing = received.RouteProcessing.ToArray();
            Assert.Equal(1, processing[0]);
            Assert.Equal(firstProcessing, processing); // No fresh/retrospective classification after recovery.
            Assert.Equal(SHA256.HashData(command.ExactDmc2.Span), received.EventHash.ToArray());
            using var exact = received.OwnAuthenticatedDmc2();
            Assert.True(exact.Use(bytes => bytes.SequenceEqual(command.ExactDmc2.Span)));
        }
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(before.Ordinal + 1, committed.Ordinal);
        Assert.Equal(before.RatchetGeneration + 1, committed.RatchetGeneration);
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, ciphertext))
            Assert.Equal(processing, replay.RouteProcessing.ToArray());
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        using (var replay = await fixture.SendOwnedRouteUpdate(sender, operation))
            Assert.Equal(ciphertext, replay.ExactEnvelope.ToArray());
        Assert.Empty(await fixture.ListOwnedMessages(receiver));
        Assert.Empty(await fixture.ListOwnedReceiptObligations(receiver));
        // The independent semantic history has exactly the original control;
        // it is not projected as user text or application receipt work.
        Assert.False(AuthenticatedDirectDmc2.IsDirectKind(message.ContentKind));
    }

    private sealed partial class Fixture
    {
        internal void AdvanceRouteProcessingClock() { Sample++; ProofTime++; }
        internal void AdvanceRouteProcessingRetryClock() { Sample += 40; ProofTime += 40; }
        internal void AdvanceRouteProcessingPast(ulong expiresMilliseconds)
        {
            var next = checked(expiresMilliseconds / 1000 + 10);
            if (CurrentProofTime >= next) return;
            var elapsed = next - CurrentProofTime;
            Sample = checked(Sample + elapsed); ProofTime = checked(ProofTime + elapsed);
        }
        internal async Task<byte[]> ReadPendingRouteProcessing(Did2MessagingSessionScope scope, Did2MessagingFloor pending)
        {
            var checkpoint = new Did2MessagingProtectedCheckpoint(scope.IsInitiator ? (Deep.Client.Shared.Persistence.IDeepSecureStorage)storage : peerStorage, scope);
            using var raw = await checkpoint.ReadPendingAsync(pending, default);
            return raw.Use(bytes => bytes.Slice(Did2RouteProcessingMetadata.Offset, Did2RouteProcessingMetadata.Bytes).ToArray());
        }
        internal async Task<byte[]> ReadStableRouteProcessing(Did2MessagingSessionScope scope, byte[] operation, Did2MessagingFloor floor)
        {
            var stateDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (Deep.Client.Shared.Persistence.IDeepSecureStorage)storage : peerStorage;
            var lease = new DeepIdV2AccountFileLease(Path.Combine(stateDirectory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(secure, Network, scope.LocalAccount, scope.Instance).ReadAsync(default);
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                Path.Combine(stateDirectory, "deep-store-v2-account.dsv2"), catalog, scope, held, lease);
            using var rawHistory = await secure.ReadOwnedAsync(Did2MessagingHistoryCheckpoint.Slot(scope)) ?? throw new InvalidDataException("Actual protected history absent.");
            var history = rawHistory.Use(bytes => Did2MessagingHistoryCheckpoint.Decode(bytes, scope));
            var sql = new Did2MessagingSqlJournal(connection, scope, history);
            using var native = sql.ReadVerifiedOperation(floor, operation) ?? throw new InvalidDataException("Actual native control absent.");
            return native.RouteProcessing.ToArray();
        }
    }
}
