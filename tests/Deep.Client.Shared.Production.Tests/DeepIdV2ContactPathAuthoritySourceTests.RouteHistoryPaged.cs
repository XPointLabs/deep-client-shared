using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_ActualSignedReceiveStagesThenCommitsSeparateDecisionsAndColdReplay()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        var before = await fixture.ReadMessagingFloor(receiver);
        byte[] envelope; int atoms;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload);
            Assert.Equal(DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement, page.Mode);
            Assert.InRange(page.Atoms.Count, 1, 3); atoms = page.Atoms.Count;
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId);
            envelope = sent.ExactEnvelope.ToArray();
        }
        byte[] originalOutcome;
        using (var received = await fixture.ReceiveOwnedMessage(receiver, envelope))
        {
            Assert.Equal(3, received.RouteProcessing[0]); originalOutcome = received.RouteProcessing.ToArray();
        }
        var decisions = await fixture.ReadPagedNativeDecisionRows(receiver);
        Assert.Equal(atoms + 2, decisions.Count);
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Bootstrap, decisions[0].Body.Action);
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Promotion, decisions[^1].Body.Action);
        foreach (var decision in decisions)
        {
            Assert.Equal(2, decision.Body.Subject);
            Assert.Equal(6, decision.Metadata[5]); Assert.Equal(0, decision.Metadata[6]); Assert.Equal(1, decision.Metadata[7]);
            var predecessor = Did2MessagingFloor.Decode(decision.Metadata.AsSpan(8, 188), receiver);
            Assert.Equal(predecessor.RatchetGeneration, BinaryPrimitives.ReadUInt64BigEndian(decision.Metadata.AsSpan(196)));
            Assert.True(predecessor.RatchetCommitment.SequenceEqual(decision.Metadata.AsSpan(204, 32)));
            Assert.True(predecessor.RatchetHash.SequenceEqual(decision.Metadata.AsSpan(236, 32)));
            Assert.True(SHA256.HashData(decision.Body.Exact.Span).AsSpan().SequenceEqual(decision.Metadata.AsSpan(300, 32)));
        }
        var committed = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(before.RatchetGeneration + 1, committed.RatchetGeneration);
        Assert.Equal(before.Ordinal + 1 + (ulong)decisions.Count, committed.Ordinal);
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, envelope))
            Assert.Equal(originalOutcome, replay.RouteProcessing.ToArray());
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(decisions.Count, (await fixture.ReadPagedNativeDecisionRows(receiver)).Count);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_ActualAuthoredPositionForkCommitsExactWholeControlFaultAndColdFence()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        // A pre-existing unsent text advances only the cloned branch's TRS,
        // leaving both genuine route authors at the same authored position.
        using var text = await fixture.CreateOwnedText(sender, "withheld earlier authored work");
        using var branch = fixture.CaptureDisposableRouteSenderBranch();
        byte[] firstEnvelope, firstDmc;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            firstDmc = command.ExactDmc2.ToArray();
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); firstEnvelope = sent.ExactEnvelope.ToArray();
        }
        using (var received = await fixture.ReceiveOwnedMessage(receiver, firstEnvelope)) Assert.Equal(3, received.RouteProcessing[0]);
        fixture.RestoreDisposableRouteSenderBranch(branch);
        using (var withheld = await fixture.SendOwnedMessage(sender, text.OperationId, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span))) { }
        byte[] forkEnvelope;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var first = ApplicationCoreCodec.DecodeDmc2(firstDmc); var fork = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
            Assert.Equal(first.SenderClientSequence, fork.SenderClientSequence);
            Assert.False(first.CanonicalBytes.Span.SequenceEqual(fork.CanonicalBytes.Span));
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); forkEnvelope = sent.ExactEnvelope.ToArray();
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        using (var received = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, received.RouteProcessing[0]);
        var after = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(before.RatchetGeneration + 1, after.RatchetGeneration);
        Assert.Equal(before.Ordinal + 2, after.Ordinal); // Original receive and one independent fault decision.
        Assert.Equal(before.Status, after.Status);
        var fault = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Conflict, fault.Action); Assert.Equal(0, fault.SelectedAtomIndex);
        Assert.Equal(0, fault.Conflicting.AtomIndex); Assert.True(fault.FirstFault.IsAbsent);
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, replay.RouteProcessing[0]);
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, firstEnvelope)) Assert.Equal(3, replay.RouteProcessing[0]);
        Assert.Equal(after.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await AssertRetainedRouteFault(fixture, receiver);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_IndependentlySignedSameGenerationPublicForkCommitsStickyDecision()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        using var branch = fixture.CaptureDisposableRouteSenderBranch();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000);
        byte[] firstRoute;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            firstRoute = page.Atoms.Last(atom => atom.IsCompleted).ExactCompletedRoute.ToArray();
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId);
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()); Assert.Equal(3, received.RouteProcessing[0]);
        }
        fixture.RestoreDisposableRouteSenderBranch(branch);
        fixture.ProofTime++; fixture.Sample++; // Independently sign another actual successor of the same predecessor.
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000);
        using (var text = await fixture.CreateOwnedText(sender, "withheld distinct public-fork branch"))
        using (var sent = await fixture.SendOwnedMessage(sender, text.OperationId, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span))) { }
        byte[] forkEnvelope;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            var competing = page.Atoms.Last(atom => atom.IsCompleted).ExactCompletedRoute;
            Assert.False(firstRoute.AsSpan().SequenceEqual(competing.Span));
            Assert.Equal(ContactRouteClosureCodec.Decode(firstRoute).Reachability.Field(3).ToArray(),
                ContactRouteClosureCodec.Decode(competing.Span).Reachability.Field(3).ToArray());
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); forkEnvelope = sent.ExactEnvelope.ToArray();
        }
        var before = await fixture.ReadMessagingFloor(receiver);
        using (var received = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, received.RouteProcessing[0]);
        var after = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(before.RatchetGeneration + 1, after.RatchetGeneration); Assert.Equal(before.Status, after.Status);
        var fault = (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body;
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Conflict, fault.Action);
        Assert.InRange(fault.SelectedAtomIndex, (byte)1, (byte)3); Assert.False(fault.Conflicting.IsAbsent);
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, forkEnvelope)) Assert.Equal(3, replay.RouteProcessing[0]);
        Assert.Equal(after.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await AssertRetainedRouteFault(fixture, receiver);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteHistoryPaged_FinalPageBeforePrefixDrainsRetainedCandidateWithoutNetworkReplay()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000,
            successorAdvertisementLifetimeSeconds: 2_000);
        byte[] first, final; byte[] finalRouteHash;
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId)) first = sent.ExactEnvelope.ToArray();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 1_000, proactive: true);
        using (var command = await fixture.CreateOwnedRouteUpdate(sender))
        {
            var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span).ParsedPayload);
            finalRouteHash = SHA256.HashData(page.Atoms.Last(atom => atom.IsCompleted).ExactCompletedRoute.Span);
            using var sent = await fixture.SendOwnedRouteUpdate(sender, command.OperationId); final = sent.ExactEnvelope.ToArray();
        }
        using (var received = await fixture.ReceivePagedOwnerOnly(receiver, final)) Assert.Equal(3, received.RouteProcessing[0]);
        var staged = await fixture.ReadMessagingFloor(receiver);
        using (var received = await fixture.ReceivePagedOwnerOnly(receiver, first)) Assert.Equal(3, received.RouteProcessing[0]);
        var preceding = await fixture.ReadMessagingFloor(receiver);
        Assert.True(preceding.Ordinal > staged.Ordinal);
        Assert.True(await fixture.ContinuePagedHistory(receiver));
        var decisions = await fixture.ReadPagedNativeDecisionRows(receiver);
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Promotion, decisions[^1].Body.Action);
        var promoted = decisions[^1].Body.L;
        Assert.True(promoted.Ordinal < decisions.Where(row => row.Body.Action == Did2RouteHistoryDecision.ActionKind.Promotion).First().Body.L.Ordinal);
        var stable = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(preceding.RatchetGeneration, stable.RatchetGeneration);
        Assert.False(await fixture.ContinuePagedHistory(receiver));
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        Assert.False(await fixture.ContinuePagedHistory(receiver));
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(finalRouteHash, (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body.EndpointHash.ToArray());
    }

    private sealed partial class Fixture
    {
        internal async Task<bool> ContinuePagedHistory(Did2MessagingSessionScope scope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            var pair = await source.VerifyForOwnMessagingAsync(account, scope, default);
            return await PagedOwner(scope).ContinueRouteHistoryAsync(CurrentProofTime, pq, scope, pair.Own, pair.Peer, source, default);
        }
        internal async Task<OwnedDid2MessagingPersistedEvent> ReceivePagedOwnerOnly(Did2MessagingSessionScope scope, byte[] envelope)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            var pair = await source.VerifyForOwnMessagingAsync(account, scope, default);
            return await PagedOwner(scope).ReceiveMessagingAsync(CurrentProofTime, pq, scope, envelope, pair.Own, pair.Peer, source, default);
        }
        private ProtectedDeepIdV2AccountOwner PagedOwner(Did2MessagingSessionScope scope)
        {
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            return new ProtectedDeepIdV2AccountOwner(NativeStorage(scope), new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock")),
                Path.Combine(folder, "deep-store-v2-account.dsv2"), Network, 1);
        }
        internal async Task<IReadOnlyList<(Did2RouteHistoryDecision Body, byte[] Metadata)>> ReadPagedNativeDecisionRows(Did2MessagingSessionScope scope)
        {
            var result = new List<(Did2RouteHistoryDecision Body, byte[] Metadata)>();
            await WithRouteReadSql(scope, (_, connection) =>
            {
                using var query = connection.CreateCommand();
                query.CommandText = "SELECT decision,metadata FROM route_decisions WHERE substr(decision,3,1)=x'02' ORDER BY ordinal;";
                using var rows = query.ExecuteReader();
                while (rows.Read()) result.Add((Did2RouteHistoryDecision.Decode(rows.GetFieldValue<byte[]>(0), scope), rows.GetFieldValue<byte[]>(1)));
            });
            return result;
        }
    }
}
