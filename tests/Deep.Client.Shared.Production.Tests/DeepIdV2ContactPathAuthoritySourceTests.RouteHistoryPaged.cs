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
        using var controls = await fixture.PrepareFreshPagedHistoryGap(sender);
        using (var received = await fixture.ReceivePagedOwnerOnly(receiver, controls.Final)) Assert.Equal(3, received.RouteProcessing[0]);
        var staged = await fixture.ReadMessagingFloor(receiver);
        Assert.DoesNotContain(await fixture.ReadPagedNativeDecisionRows(receiver),
            row => row.Body.Action == Did2RouteHistoryDecision.ActionKind.Promotion);
        foreach (var prefix in controls.Prefixes)
            using (var received = await fixture.ReceivePagedOwnerOnly(receiver, prefix)) Assert.Equal(3, received.RouteProcessing[0]);
        var preceding = await fixture.ReadMessagingFloor(receiver);
        Assert.True(preceding.Ordinal > staged.Ordinal);
        Assert.True(fixture.CurrentProofTime * 1_000 < controls.FinalExpiry,
            "Continuation must qualify the retained final announcement while it is actually current.");
        Assert.True(await fixture.ContinuePagedHistory(receiver));
        var decisions = await fixture.ReadPagedNativeDecisionRows(receiver);
        Assert.Equal(Did2RouteHistoryDecision.ActionKind.Promotion, decisions[^1].Body.Action);
        var promoted = decisions[^1].Body.L;
        var finalOperation = Deep.Protocol.MessagingWire.Dpe2Codec.Decode(controls.Final).OperationId;
        Assert.True(CryptographicOperations.FixedTimeEquals(promoted.Operation, finalOperation.Span),
            "Continuation promoted another original instead of the final page already received before its prefix.");
        Assert.True(promoted.Ordinal < await fixture.ReadGapPrefixEventOrdinal(receiver, controls.Prefixes[^1]),
            "The retained final original must precede the later delivered prefix in actual native receive order.");
        var stable = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(preceding.RatchetGeneration, stable.RatchetGeneration);
        Assert.False(await fixture.ContinuePagedHistory(receiver));
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        await fixture.ArchiveEntireEligibleSuffix(receiver);
        fixture.DropNativeRuntimes(); fixture.ColdReopenReceiverStoreStorage();
        Assert.False(await fixture.ContinuePagedHistory(receiver));
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(controls.FinalRouteHash, (await fixture.ReadPagedNativeDecisionRows(receiver))[^1].Body.EndpointHash.ToArray());
    }

    private sealed class FreshPagedHistoryGapControls(
        IReadOnlyList<byte[]> prefixes, byte[] final, byte[] finalRouteHash, ulong finalExpiry) : IDisposable
    {
        internal IReadOnlyList<byte[]> Prefixes { get; } = prefixes;
        internal byte[] Final { get; } = final;
        internal byte[] FinalRouteHash { get; } = finalRouteHash;
        internal ulong FinalExpiry { get; } = finalExpiry;
        public void Dispose()
        {
            foreach (var prefix in Prefixes) CryptographicOperations.ZeroMemory(prefix);
            CryptographicOperations.ZeroMemory(Final); CryptographicOperations.ZeroMemory(FinalRouteHash);
        }
    }

    private sealed partial class Fixture
    {
        internal async Task<FreshPagedHistoryGapControls> PrepareFreshPagedHistoryGap(Did2MessagingSessionScope sender)
        {
            // Four real publication generations exceed the codec's maximum
            // three atoms without inventing a fixed two-page payload shape.
            // Complete clock-advancing public work BEFORE minting controls.
            for (var generation = 1; generation <= 4; generation++)
                await RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300,
                    successorAdvertisementLifetimeSeconds: 500, proactive: generation != 1);
            var prefixes = new List<byte[]>(); byte[]? previousCursor = null;
            try
            {
                for (var pageNumber = 0; pageNumber < 8; pageNumber++)
                {
                    using var command = await CreateOwnedRouteUpdate(sender);
                    var message = ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span);
                    var page = Assert.IsType<ContactRouteHistoryDmc2Payload>(message.ParsedPayload);
                    Assert.InRange(page.Atoms.Count, 1, DeepIdV2ContactRouteHistoryCodec.MaximumAtoms);
                    if (previousCursor is not null) Assert.Equal(previousCursor, page.LeftCursor.ToArray());
                    var leftC = BinaryPrimitives.ReadUInt64BigEndian(page.LeftCursor.Span);
                    var leftP = BinaryPrimitives.ReadUInt64BigEndian(page.LeftCursor.Span[40..]);
                    var rightC = BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span);
                    var rightP = BinaryPrimitives.ReadUInt64BigEndian(page.RightCursor.Span[40..]);
                    Assert.True(rightC > leftC || rightP > leftP, "The genuine bounded page did not traverse its original public history.");
                    Assert.True(rightC >= leftC && rightP >= leftP);
                    previousCursor = page.RightCursor.ToArray();
                    using var sent = await SendOwnedRouteUpdate(sender, command.OperationId);
                    var envelope = sent.ExactEnvelope.ToArray();
                    if (page.Mode == DeepIdV2ContactRouteHistoryMode.EvidenceAndAnnouncement)
                    {
                        Assert.NotEmpty(prefixes);
                        Assert.Equal(4UL, rightC);
                        Assert.True(CurrentProofTime * 1_000 < message.ExpiresAtUnixMilliseconds,
                            "The real final announcement expired during its own native send.");
                        return new(prefixes, envelope, SHA256.HashData(page.Atoms.Last(atom => atom.IsCompleted).ExactCompletedRoute.Span),
                            message.ExpiresAtUnixMilliseconds);
                    }
                    Assert.Equal(DeepIdV2ContactRouteHistoryMode.Evidence, page.Mode);
                    prefixes.Add(envelope);
                }
                throw new InvalidDataException("The four-generation genuine history did not finish within its fixed page bound.");
            }
            catch { foreach (var prefix in prefixes) CryptographicOperations.ZeroMemory(prefix); throw; }
        }

        internal async Task RequireActualGapRequestAlreadyCommitted(Did2MessagingSessionScope scope,
            Did2MessagingFloor before, Did2MessagingFloor gap, byte[] finalEnvelope, byte[] finalEventHash)
        {
            byte[] requestOperation = [], requestEventHash = [], relationship = [], anchor = [];
            try
            {
                await WithRouteReadSql(scope, (sql, connection) =>
                {
                    using (var received = sql.ReadVerifiedOperation(gap, Deep.Protocol.MessagingWire.Dpe2Codec.Decode(finalEnvelope).OperationId.Span))
                    {
                        Assert.NotNull(received); Assert.Equal(2, received!.Direction);
                        Assert.True(received.Ordinal > before.Ordinal);
                        Assert.True(received.ExactEnvelope.SequenceEqual(finalEnvelope));
                        Assert.True(received.EventHash.SequenceEqual(finalEventHash));
                        using var exact = received.OwnAuthenticatedDmc2();
                        exact.Use(bytes =>
                        {
                            var control = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(bytes).ParsedPayload);
                            relationship = control.RelationshipId.ToArray(); anchor = control.OriginalAnchorHash.ToArray();
                        });
                    }
                    var outgoingCount = 0;
                    foreach (var outgoing in sql.ReadVerifiedOutgoingEvents(gap, default))
                        using (outgoing)
                        {
                            if (outgoing.Ordinal <= before.Ordinal) continue;
                            outgoingCount++;
                            requestOperation = Deep.Protocol.MessagingWire.Dpe2Codec.Decode(outgoing.ExactEnvelope).OperationId.ToArray();
                            requestEventHash = outgoing.EventHash.ToArray();
                        }
                    Assert.Equal(1, outgoingCount);
                });
                // The native request exists before this existing-request retry;
                // a newly minted operation cannot satisfy both comparisons.
                using (var request = await PrepareOwnedHistory(scope))
                {
                    Assert.NotNull(request);
                    Assert.True(CryptographicOperations.FixedTimeEquals(request!.OperationId.Span, requestOperation));
                    Assert.True(CryptographicOperations.FixedTimeEquals(SHA256.HashData(request.ExactDmc2.Span), requestEventHash));
                    var control = Assert.IsType<ContactRouteHistoryDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(request.ExactDmc2.Span).ParsedPayload);
                    Assert.Equal(DeepIdV2ContactRouteHistoryMode.HistoryRequest, control.Mode);
                    Assert.True(control.RequestEventHash.Span.IndexOfAnyExcept((byte)0) < 0);
                    Assert.True(control.RelationshipId.Span.SequenceEqual(relationship));
                    Assert.True(control.OriginalAnchorHash.Span.SequenceEqual(anchor));
                    Assert.True(control.LeftCursor.Span.SequenceEqual(control.RightCursor.Span));
                }
                Assert.Equal(gap.Exact.ToArray(), (await ReadMessagingFloor(scope)).Exact.ToArray());
            }
            finally
            {
                foreach (var bytes in new[] { requestOperation, requestEventHash, relationship, anchor })
                    CryptographicOperations.ZeroMemory(bytes);
            }
        }

        internal async Task<ulong> ReadGapPrefixEventOrdinal(Did2MessagingSessionScope scope, byte[] envelope)
        {
            var operation = Deep.Protocol.MessagingWire.Dpe2Codec.Decode(envelope).OperationId;
            ulong ordinal = 0;
            await WithRouteReadSql(scope, (sql, connection) =>
            {
                _ = sql.VerifyTip();
                using var query = connection.CreateCommand();
                query.CommandText = "SELECT ordinal FROM events WHERE operation=$operation;";
                query.Parameters.AddWithValue("$operation", operation.ToArray());
                ordinal = checked((ulong)Convert.ToInt64(query.ExecuteScalar()));
                Assert.True(ordinal > 0);
            });
            return ordinal;
        }

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
