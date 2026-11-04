using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_ActualGapStagesThenLatePredecessorAndRetainedContinuationPromote()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        using var controls = await fixture.PrepareFreshPagedHistoryGap(sender);
        var before = await fixture.ReadMessagingFloor(receiver);
        byte[] staged, finalEventHash;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, controls.Final))
        {
            staged = received.RouteProcessing.ToArray(); Assert.Equal(3, staged[0]);
            Assert.True(received.RouteHistoryCatchupRequired);
            finalEventHash = received.EventHash.ToArray();
        }
        var gap = await fixture.ReadMessagingFloor(receiver);
        await fixture.RequireActualGapRequestAlreadyCommitted(receiver, before, gap, controls.Final, finalEventHash);
        Assert.Equal(before.RatchetGeneration + 2, gap.RatchetGeneration);
        Assert.True(fixture.CurrentProofTime * 1_000 < controls.FinalExpiry,
            "The actual final announcement expired before the missing history was supplied.");
        Assert.DoesNotContain(await fixture.ReadPagedNativeDecisionRows(receiver),
            row => row.Body.Action == Did2RouteHistoryDecision.ActionKind.Promotion);
        // Mode3 supplies retained signed history. Only the separate actual
        // current final announcement can authorize promotion of L.
        foreach (var prefix in controls.Prefixes)
            using (var late = await fixture.ReceiveOwnedMessage(receiver, prefix)) Assert.Equal(3, late.RouteProcessing[0]);
        Assert.True(fixture.CurrentProofTime * 1_000 < controls.FinalExpiry,
            "Continuation must qualify the retained final announcement while it is actually current.");
        _ = await fixture.ContinuePagedHistory(receiver);
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(1, committed.Status);
        Assert.True(committed.Ordinal > before.Ordinal + checked((ulong)controls.Prefixes.Count) + 1);
        Assert.Equal(gap.RatchetGeneration + checked((ulong)controls.Prefixes.Count), committed.RatchetGeneration);
        Assert.Equal(controls.FinalRouteHash, (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body.EndpointHash.ToArray());
        await fixture.CompactHistoricalPeerRoutePrefix(receiver); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, controls.Final)) Assert.Equal(staged, replay.RouteProcessing.ToArray());
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await fixture.AssertNoPagedRouteFault(receiver);
        CryptographicOperations.ZeroMemory(staged); CryptographicOperations.ZeroMemory(finalEventHash);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_FreshAnnouncementOfSamePublicEndpointDoesNotCreatePrivateChainFault()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        // Alternate sender clone of this DISPOSABLE local fixture only. Both
        // branches use actual registered PQ/owned/native producers. Receiver
        // custody is never restored, forged or assigned a parsed trust flag.
        using var branch = fixture.CaptureDisposableRouteSenderBranch();
        byte[] first, firstProcessing;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId)) first = sent.ExactEnvelope.ToArray();
        using (var received = await fixture.ReceiveOwnedMessage(receiver, first))
        { firstProcessing = received.RouteProcessing.ToArray(); Assert.Equal(3, firstProcessing[0]); }
        fixture.RestoreDisposableRouteSenderBranch(branch);
        // Advance the clone's real native counter without advertising a route.
        // Do not deliver this branch's earlier text envelope to the receiver.
        using (var text = await fixture.CreateOwnedText(sender, "withheld sender-fork branch"))
        using (var sent = await fixture.SendOwnedMessage(sender, text.OperationId, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span))) { }
        byte[] fork; ulong forkSequence;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span); forkSequence = message.SenderClientSequence;
            Assert.Equal(1UL, System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(
                Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload).RightCursor.Span));
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); fork = sent.ExactEnvelope.ToArray();
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        byte[] rejected;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, fork))
        { rejected = received.RouteProcessing.ToArray(); Assert.Equal(3, rejected[0]); }
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(1, committed.Status); Assert.True(committed.Ordinal > before.Ordinal + 1);
        Assert.Equal(before.RatchetGeneration + 1, committed.RatchetGeneration);
        await AssertExactReplay(fork, rejected, committed, "warm newer original");
        await AssertExactReplay(first, firstProcessing, committed, "warm older original");
        await fixture.CompactHistoricalPeerRoutePrefix(receiver); fixture.ColdReopenReceiverStoreStorage();
        await AssertExactReplay(fork, rejected, committed, "cold newer original");
        await AssertExactReplay(first, firstProcessing, committed, "cold older original");
        var priorDecision = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
        byte[] newest, newestProcessing;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
            Assert.True(message.SenderClientSequence > forkSequence);
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload);
            Assert.Equal(DeepIdV2ContactRouteHistoryMode.Announcement, page.Mode);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); newest = sent.ExactEnvelope.ToArray();
        }
        using (var received = await fixture.ReceiveOwnedMessage(receiver, newest))
        { newestProcessing = received.RouteProcessing.ToArray(); Assert.Equal(3, newestProcessing[0]); }
        var promoted = await fixture.ReadMessagingFloor(receiver);
        var promotion = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
        Assert.Equal(committed.Ordinal + 2, promoted.Ordinal); // One actual receive and one current promotion.
        Assert.Equal(committed.RatchetGeneration + 1, promoted.RatchetGeneration);
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Promotion, promotion.Action);
        Assert.Equal(priorDecision.C.Exact.ToArray(), promotion.C.Exact.ToArray());
        Assert.Equal(priorDecision.P.Exact.ToArray(), promotion.P.Exact.ToArray());
        Assert.Equal(priorDecision.EndpointHash.ToArray(), promotion.EndpointHash.ToArray());
        Assert.False(priorDecision.L.Exact.Span.SequenceEqual(promotion.L.Exact.Span));
        Assert.Equal(committed.Ordinal + 1, promotion.L.Ordinal);
        await AssertExactReplay(newest, newestProcessing, promoted, "warm highest sequence");
        await AssertExactReplay(first, firstProcessing, promoted, "warm oldest after higher sequence");
        await fixture.CompactHistoricalPeerRoutePrefix(receiver); fixture.ColdReopenReceiverStoreStorage();
        await AssertExactReplay(newest, newestProcessing, promoted, "cold highest sequence");
        await AssertExactReplay(fork, rejected, promoted, "cold intermediate after higher sequence");
        await AssertExactReplay(first, firstProcessing, promoted, "cold oldest after higher sequence");
        await fixture.AssertNoPagedRouteFault(receiver);
        foreach (var bytes in new[] { first, firstProcessing, fork, rejected, newest, newestProcessing }) CryptographicOperations.ZeroMemory(bytes);

        async Task AssertExactReplay(byte[] envelope, byte[] outcome, Did2MessagingFloor expected, string phase)
        {
            using (var replay = await fixture.ReceiveOwnedMessage(receiver, envelope)) Assert.Equal(outcome, replay.RouteProcessing.ToArray());
            var actual = await fixture.ReadMessagingFloor(receiver);
            var diagnostic = phase + ": ordinal " + expected.Ordinal + " -> " + actual.Ordinal +
                ", ratchet " + expected.RatchetGeneration + " -> " + actual.RatchetGeneration + ", floor phase " + actual.Phase;
            if (!expected.Exact.Span.SequenceEqual(actual.Exact.Span))
            {
                var body = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
                diagnostic += ", action " + body.Action + ", subject " + body.Subject + ", selected " + body.Selected.Kind + "/" +
                    body.Selected.Direction + "/" + body.Selected.Ordinal + ", live ordinal " + body.L.Ordinal +
                    ", completed source " + body.C.Reference.Ordinal + ", proposal source " + body.P.Reference.Ordinal;
            }
            Assert.True(expected.Exact.Span.SequenceEqual(actual.Exact.Span), diagnostic);
        }
    }

    private static async Task<(Did2MessagingSessionScope Sender, Did2MessagingSessionScope Receiver)> PrepareRouteFaultPair(Fixture fixture)
    {
        await fixture.SeedShortPermanentProposalAsync(validitySeconds: 800);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        fixture.TrackMailboxDispatchClock(); return (sender, receiver);
    }

    private static async Task AssertRetainedRouteFault(Fixture fixture, Did2MessagingSessionScope receiver)
    {
        var issuer = new OwnedGrantTransport(fixture, ownerOnPrimary: false); var transport = new RejectInitialDispatchFactory();
        var native = (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray();
        var sql = await fixture.ReadCompleteOrdinaryApplicationProjection(receiver);
        var roots = await fixture.ReadCompletedContactSendRetainedRoots(receiver);
        var error = await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.QueueNativeText(receiver, "blocked after authenticated peer route fault"));
        Assert.Contains("Retained authenticated route fault", error.Message, StringComparison.Ordinal);
        Assert.Equal(0, issuer.Calls); Assert.Equal(0, transport.Calls);
        Assert.Equal(native, (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(sql, await fixture.ReadCompleteOrdinaryApplicationProjection(receiver));
        Assert.Equal(roots, await fixture.ReadCompletedContactSendRetainedRoots(receiver));
        Assert.Empty(await fixture.ListOwnedMessages(receiver)); Assert.Empty(await fixture.ListOwnedReceiptObligations(receiver));
        foreach (var bytes in new[] { native, sql, roots }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task AssertNoPagedRouteFault(Did2MessagingSessionScope scope)
        {
            var stable = await ReadMessagingFloor(scope);
            await WithRouteReadSql(scope, (sql, _) => Assert.False(sql.ReadVerifiedPeerRouteFault(stable)));
        }
        internal sealed class DisposableRouteSenderBranch(Dictionary<string, byte[]> files) : IDisposable
        {
            internal Dictionary<string, byte[]> Files => files;
            public void Dispose() { foreach (var bytes in files.Values) CryptographicOperations.ZeroMemory(bytes); files.Clear(); }
        }
        private IEnumerable<string> DisposableRouteSenderFiles()
        {
            var root = Path.GetFullPath(directory) + Path.DirectorySeparatorChar;
            var peer = Path.GetFullPath(Path.Combine(directory, "peer")) + Path.DirectorySeparatorChar;
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                var full = Path.GetFullPath(file);
                if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Disposable fixture file escaped its directory.");
                if (!full.StartsWith(peer, StringComparison.OrdinalIgnoreCase) && !full.EndsWith(".lock", StringComparison.OrdinalIgnoreCase)) yield return full;
            }
        }
        internal DisposableRouteSenderBranch CaptureDisposableRouteSenderBranch()
        {
            Assert.IsType<CompactionDiskFixtureStorage>(innerStorage);
            // Every actual account operation has returned and disposed its SQL
            // connections/lease. Snapshot encrypted files in memory, never logs
            // or artifacts. This is hostile-peer test generation, not recovery.
            return new(DisposableRouteSenderFiles().ToDictionary(file => file, File.ReadAllBytes, StringComparer.OrdinalIgnoreCase));
        }
        internal void RestoreDisposableRouteSenderBranch(DisposableRouteSenderBranch branch)
        {
            var files = DisposableRouteSenderFiles().ToArray();
            foreach (var file in files) if (!branch.Files.ContainsKey(file)) File.Delete(file);
            foreach (var (file, bytes) in branch.Files) File.WriteAllBytes(file, bytes);
            ColdReopenCompactionStorage();
        }
    }
}
