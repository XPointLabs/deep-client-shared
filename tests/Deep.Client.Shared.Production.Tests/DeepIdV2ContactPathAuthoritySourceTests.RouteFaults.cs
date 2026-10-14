using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteProcessing_ActualAuthenticatedGapStaysRejectedAfterLatePredecessorAndColdPrefix()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        // Resume an actual device-signed shorter pending proposal through all
        // owned publication phases, leaving authority for a second successor.
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000,
            successorAdvertisementLifetimeSeconds: 2_000);
        byte[] first; ulong firstExpiry;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            firstExpiry = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ExpiresAtUnixMilliseconds;
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); first = sent.ExactEnvelope.ToArray();
        }
        // Actual next publication/control. Withhold only network delivery of
        // its predecessor; never alter native SQL or manufacture qualification.
        // Renew proactively while the withheld predecessor is STILL CURRENT;
        // its eventual rejection must be the retained gap, not expiry.
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000, proactive: true);
        byte[] second;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            Assert.Equal(2UL, ((ContactRouteUpdateDmc2Payload)ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload).RouteGeneration);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); second = sent.ExactEnvelope.ToArray();
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        byte[] rejected;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, second))
        { rejected = received.RouteProcessing.ToArray(); Assert.Equal(2, rejected[0]); }
        Assert.True(fixture.CurrentProofTime * 1_000 < firstExpiry);
        using (var late = await fixture.ReceiveOwnedMessage(receiver, first)) Assert.Equal(2, late.RouteProcessing[0]);
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(1, committed.Status); Assert.Equal(before.Ordinal + 2, committed.Ordinal);
        Assert.Equal(before.RatchetGeneration + 2, committed.RatchetGeneration);
        await fixture.CompactHistoricalPeerRoutePrefix(receiver); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, second)) Assert.Equal(rejected, replay.RouteProcessing.ToArray());
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await AssertRetainedRouteFault(fixture, receiver);
        foreach (var bytes in new[] { first, second, rejected }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteProcessing_ActualAuthenticatedSameGenerationForkPreservesLiveTrsAndColdFence()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        // Hostile sender clone of this DISPOSABLE local fixture only. Both
        // branches use actual registered PQ/owned/native producers. Receiver
        // custody is never restored, forged or assigned a parsed trust flag.
        using var branch = fixture.CaptureDisposableRouteSenderBranch();
        byte[] first;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId)) first = sent.ExactEnvelope.ToArray();
        using (var received = await fixture.ReceiveOwnedMessage(receiver, first)) Assert.Equal(1, received.RouteProcessing[0]);
        fixture.RestoreDisposableRouteSenderBranch(branch);
        // Advance the clone's real native counter without advertising a route.
        // Do not deliver this competing first envelope to the receiver.
        using (var text = await fixture.CreateOwnedText(sender, "withheld sender-fork branch"))
        using (var sent = await fixture.SendOwnedMessage(sender, text.OperationId, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span))) { }
        byte[] fork;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            Assert.Equal(1UL, ((ContactRouteUpdateDmc2Payload)ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload).RouteGeneration);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); fork = sent.ExactEnvelope.ToArray();
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        byte[] rejected;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, fork))
        { rejected = received.RouteProcessing.ToArray(); Assert.Equal(2, rejected[0]); }
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(1, committed.Status); Assert.Equal(before.Ordinal + 1, committed.Ordinal);
        Assert.Equal(before.RatchetGeneration + 1, committed.RatchetGeneration);
        await fixture.CompactHistoricalPeerRoutePrefix(receiver); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, fork)) Assert.Equal(rejected, replay.RouteProcessing.ToArray());
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, first)) Assert.Equal(1, replay.RouteProcessing[0]);
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await AssertRetainedRouteFault(fixture, receiver);
        foreach (var bytes in new[] { first, fork, rejected }) CryptographicOperations.ZeroMemory(bytes);
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
