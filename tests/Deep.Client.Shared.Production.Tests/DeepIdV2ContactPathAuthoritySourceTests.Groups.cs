using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2Groups_DirectoryLookupBorrowsOnlyTheActualHeldAccountLease()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGroupDirectoryBorrow();
    }

    [Fact]
    public async Task Did2Groups_EndpointBatchUsesActualLeaseAndDoesNotCacheFreshnessAcrossPhases()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGroupEndpointBatchBorrow();
    }

    [Fact]
    public async Task Did2Groups_ControlPlacementUsesTheExactPmtReferenceInTheFrozenRankTranscript()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGroupControlPlacement();
    }

    [Fact]
    public async Task Did2Groups_ControlAnchorSurvivesSignedViewAndSelectionEpochRenewal()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        await fixture.CheckGroupControlAnchorRenewal();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Groups_EndpointAcquisitionNeverSplicesDifferentSignedViews(bool capturedOwn)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x97));
        using var initial = await complete(fixture.Accounts);
        var scope = await fixture.EnsureSenderMessaging(init, hello);
        await fixture.CheckGroupEndpointViewAcquisition(scope, capturedOwn);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Groups_DescriptorNativeCustodyAndUnpublishedCommitBlocksApplicationSend()
    {
        // Actual account/SQLCipher/native crypto with independently signed
        // fixture proofs. This is NOT socket transport, Store or ACK evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var alice = await fixture.EnsureSenderMessaging(init, hello);
        var bob = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(bob, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(bob, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(alice, sent.ExactEnvelope.ToArray())) { }
        var hostileChunkChecked = false;
        var group = Convert.FromHexString(await fixture.Accounts.CreateGroupAsync("native group", fixture.Source()));
        await fixture.PrepareGroupAction(alice, "invite", group);
        await fixture.PrepareGroupAction(alice, "invite", group); // Resume retained invitation, never remint.
        await Transfer(alice, bob);
        Assert.Equal("Invited", Assert.Single(await fixture.AccountsForPeer().ListGroupsAsync()).State);
        var beforePrematureSend = await fixture.ReadMessagingFloor(bob);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.PrepareGroupAction(bob, "send", group, "not a member yet"));
        Assert.Equal(SHA256.HashData(beforePrematureSend.Exact.Span), SHA256.HashData((await fixture.ReadMessagingFloor(bob)).Exact.Span));
        await fixture.PrepareGroupAction(bob, "accept", group); await Transfer(bob, alice);
        Assert.Equal("Accepted", Assert.Single(await fixture.Accounts.ListGroupsAsync()).State);
        await fixture.PrepareGroupAction(alice, "advance", group); await Transfer(alice, bob);
        Assert.Equal("Active", Assert.Single(await fixture.Accounts.ListGroupsAsync()).State);
        // DR-0145: the short mailbox no longer transports new commits.
        Assert.Equal("Accepted", Assert.Single(await fixture.AccountsForPeer().ListGroupsAsync()).State);
        var beforeUnpublished = await fixture.ReadMessagingFloor(alice);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareGroupAction(alice, "send", group, "must not bypass GSR receipts"));
        Assert.Equal(SHA256.HashData(beforeUnpublished.Exact.Span), SHA256.HashData((await fixture.ReadMessagingFloor(alice)).Exact.Span));
        Assert.Equal(0, Assert.Single(await fixture.Accounts.ListGroupsAsync()).LocalMessageCommands);
        Assert.Empty(await fixture.Accounts.ListGroupMessagesAsync(group));
        Assert.Empty(await fixture.AccountsForPeer().ListGroupMessagesAsync(group));
        Assert.True(hostileChunkChecked);
        var retainedBatch = await fixture.ReadGroupBatch(alice, group);
        try {
            Assert.Single(retainedBatch, item => ApplicationCoreCodec.DecodeDmc2(item.Event).ContentKind == Dmc2ContentKind.GroupControlRendezvous);
            Assert.All(retainedBatch, item => Assert.True(item.NativeCommitted));
            var unfinished = await fixture.ReadGroupBatch(alice, group, pendingOnly: true);
            try
            {
                // A real native commit is not a Store receipt: none of these
                // test envelopes has been through the owned Store boundary.
                Assert.Equal(retainedBatch.Select(item => Convert.ToHexString(item.Operation)),
                    unfinished.Select(item => Convert.ToHexString(item.Operation)));
                Assert.All(unfinished, item => Assert.True(item.NativeCommitted));
            }
            finally { Clear(unfinished); }
        } finally { Clear(retainedBatch); }

        async Task Transfer(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            var batch = await fixture.ReadGroupBatch(sender, group);
            try
            {
                foreach (var item in batch.Where(item => !item.NativeCommitted))
                {
                    Assert.True(item.Adopted); // Adopted command != committed native or Store.
                    if (!hostileChunkChecked && ApplicationCoreCodec.DecodeDmc2(item.Event).ParsedPayload is Deep.Protocol.GroupV1.GroupDmc2Payload chunkPayload &&
                        chunkPayload.Record is Deep.Protocol.GroupV1.GroupCommitChunkRecord chunk && System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(4).Span) == 0)
                    { await fixture.RejectAlteredProtectedGroupChunk(sender, item, chunk); hostileChunkChecked = true; }
                    if (ApplicationCoreCodec.DecodeDmc2(item.Event).ContentKind == Dmc2ContentKind.GroupApplicationMessage)
                    {
                        var changed = item.Event.ToArray(); changed[^1] ^= 1;
                        var before = await fixture.ReadMessagingFloor(sender);
                        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, item.Operation, ApplicationCoreCodec.DecodeDmc2(changed)));
                        Assert.Equal(SHA256.HashData(before.Exact.Span), SHA256.HashData((await fixture.ReadMessagingFloor(sender)).Exact.Span));
                    }
                    using var native = await fixture.SendOwnedMessage(sender, item.Operation, ApplicationCoreCodec.DecodeDmc2(item.Event));
                    using (var received = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) { }
                    using (var replay = await fixture.ReceiveOwnedMessage(receiver, native.ExactEnvelope.ToArray())) { }
                }
                var reopened = await fixture.ReadGroupBatch(sender, group);
                try
                {
                    Assert.All(reopened, item => Assert.True(item.NativeCommitted));
                    Assert.Equal(batch.Select(item => Convert.ToHexString(SHA256.HashData(item.Operation))), reopened.Select(item => Convert.ToHexString(SHA256.HashData(item.Operation))));
                    Assert.Equal(batch.Select(item => Convert.ToHexString(SHA256.HashData(item.Event))), reopened.Select(item => Convert.ToHexString(SHA256.HashData(item.Event))));
                }
                finally { Clear(reopened); }
            }
            finally { Clear(batch); }
        }
        static void Clear(IReadOnlyList<ProtectedDid2GroupJournal.Outgoing> batch)
        { foreach (var item in batch) foreach (var bytes in new[] { item.Group, item.Operation, item.Scope, item.Event }) CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed partial class Fixture
    {
        internal async Task CheckGroupEndpointViewAcquisition(Did2MessagingSessionScope scope, bool capturedOwn, bool groupReadScope = false)
        {
            var parent = Source(); using var reads = groupReadScope ? parent.OpenCommandReadScope() : null;
            var source = reads?.Source ?? parent;
            var captured = capturedOwn ? await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default) : null;
            await AdvanceNetworkAsync();
            var next = successor; successor = null;
            Action switchView = () => successor = next;
            OnNextDirectoryProof = capturedOwn ? switchView : () => OnNextDirectoryProof = switchView;
            if (capturedOwn)
            {
                var error = await Assert.ThrowsAsync<MessagingEndpointSnapshotChangedException>(async () =>
                    await source.VerifyForOwnMessagingAsync(Accounts, scope, default, captured));
                Assert.Equal("Refreshed messaging endpoints no longer bind owned network custody.", error.Message);
            }
            else
            {
                var pair = await source.VerifyForOwnMessagingAsync(Accounts, scope, default);
                var ownTime = Deep.Protocol.AccountDirectoryV1.AccountDirectoryDtt1Codec.Decode(pair.Own.Proof.ExactDtt1.Span);
                var peerTime = Deep.Protocol.AccountDirectoryV1.AccountDirectoryDtt1Codec.Decode(pair.Peer.ExactDtt1.Span);
                Assert.Equal(ownTime.CurrentXnv1CoreHash.ToArray(), peerTime.CurrentXnv1CoreHash.ToArray());
                Assert.Equal(ownTime.CurrentXnv1Generation, peerTime.CurrentXnv1Generation);
                Assert.Equal(2, pair.Own.NamespaceRecords.ExactOrderedPmt2Chain.Count);
            }
            Assert.False((await NetworkStore.ReadAsync(default))!.ForkLatched);
        }

        internal async Task CheckGroupControlAnchorRenewal()
        {
            var first = await Source().VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var anchor = Deep.Protocol.ContactV1.ContactCodec.ArtifactReference("PMT2",
                Deep.Protocol.ContactV1.ContactCodec.Decode("PMT2", first.NamespaceRecords.ExactOrderedPmt2Chain.Last().Span)).CanonicalBytes;
            var selector = Bytes(32, 0x39);
            var before = Deep.Protocol.DeepExtension.PrivacyRouting.GroupControlPlacementVerifier.Create(first.Network, selector, anchor);
            await AdvanceNetworkAsync(); AuthorSignedEpochAdvance();
            var current = await Source().VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var latest = Deep.Protocol.ContactV1.ContactCodec.ArtifactReference("PMT2",
                Deep.Protocol.ContactV1.ContactCodec.Decode("PMT2", current.NamespaceRecords.ExactOrderedPmt2Chain.Last().Span)).CanonicalBytes;
            Assert.NotEqual(anchor.ToArray(), latest.ToArray());
            var retained = Deep.Protocol.DeepExtension.PrivacyRouting.GroupControlPlacementVerifier.Create(current.Network, selector, anchor);
            Assert.Same(current.Network, retained.Network);
            Assert.Equal(before.PlacementHash.ToArray(), retained.PlacementHash.ToArray());
            Assert.Equal(before.ViewHash.ToArray(), retained.ViewHash.ToArray());
            for (var i = 0; i < 2; i++) Assert.Equal(before.ReplicaIds[i].ToArray(), retained.ReplicaIds[i].ToArray());
            var altered = anchor.ToArray(); altered[^1] ^= 1;
            Assert.Throws<CryptographicException>(() => Deep.Protocol.DeepExtension.PrivacyRouting.GroupControlPlacementVerifier.Create(current.Network, selector, altered));
        }

        internal async Task CheckGroupControlPlacement()
        {
            var source = Source(); var own = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var pmt = Deep.Protocol.ContactV1.ContactCodec.Decode("PMT2", own.NamespaceRecords.ExactOrderedPmt2Chain.Last().Span);
            var reference = Deep.Protocol.ContactV1.ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
            var selector = Bytes(32, 0x39); var network = own.Network.NetworkId.ToArray(); var epoch = pmt.Field(6).ToArray();
            var input = GroupControlHash("Deep/Group/V1/control-placement-input", [.. network, .. selector]);
            var rows = pmt.Field(9).ToArray();
            var expected = Enumerable.Range(0, rows.Length / 136).Select(index => rows.AsSpan(index * 136, 32).ToArray())
                .Select(id => (Id: id, Rank: SHA256.HashData([.. "Deep/XPoint/V1/PMS2/rendezvous-sha256/v2"u8, 0, .. network, .. reference, .. epoch, .. input, .. id])))
                .OrderBy(row => Convert.ToHexString(row.Rank), StringComparer.Ordinal).ThenBy(row => Convert.ToHexString(row.Id), StringComparer.Ordinal)
                .Take(2).Select(row => row.Id).ToArray();
            var placement = Deep.Protocol.DeepExtension.PrivacyRouting.GroupControlPlacementVerifier.Create(own.Network, selector, reference);
            Assert.Equal(2, placement.ReplicaIds.Count);
            for (var i = 0; i < 2; i++) Assert.Equal(expected[i], placement.ReplicaIds[i].ToArray());
            var expectedHash = GroupControlHash("Deep/Group/V1/control-placement", [.. network, .. pmt.Field(5).Span, .. reference, .. epoch, .. selector, .. expected[0], .. expected[1]]);
            Assert.Equal(expectedHash, placement.PlacementHash.ToArray());
            Assert.Throws<ArgumentException>(() => Deep.Protocol.DeepExtension.PrivacyRouting.GroupControlPlacementVerifier.Create(own.Network, new byte[32], reference));
        }
        private static byte[] GroupControlHash(string domain, byte[] payload)
        {
            var label = System.Text.Encoding.ASCII.GetBytes(domain); var bytes = new byte[label.Length + 5 + payload.Length]; label.CopyTo(bytes, 0);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(label.Length + 1), checked((uint)payload.Length));
            payload.CopyTo(bytes, label.Length + 5); return SHA256.HashData(bytes);
        }

        internal async Task CheckGroupEndpointBatchBorrow()
        {
            var source = Source(); var own = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var pairs = new[] { new Deep.Client.Shared.Services.ContactV2.DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority(own, own.Proof),
                new Deep.Client.Shared.Services.ContactV2.DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority(own, own.Proof) };
            var actual = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await actual.AcquireAsync(default);
            var readings = await source.RecheckEndpointPairsUnderLeaseAsync(pairs, held, default);
            Assert.Equal(2, readings.Count); Assert.Same(readings[0], readings[1]);
            using var foreign = await new DeepIdV2AccountFileLease(Path.Combine(directory, "peer", "deep-store-v2-account.lock")).AcquireAsync(default);
            await Assert.ThrowsAsync<CryptographicException>(() => source.RecheckEndpointPairsUnderLeaseAsync(pairs, foreign, default));
            var before = Sample;
            try
            {
                Sample = own.Proof.FreshnessDeadlineMonotonicSeconds;
                await Assert.ThrowsAsync<CryptographicException>(() => source.RecheckEndpointPairsUnderLeaseAsync(pairs, held, default));
            }
            finally { Sample = before; }
            held.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => source.RecheckEndpointPairsUnderLeaseAsync(pairs, held, default));
        }

        internal async Task RejectAlteredProtectedGroupChunk(Did2MessagingSessionScope scope, ProtectedDid2GroupJournal.Outgoing item, Deep.Protocol.GroupV1.GroupCommitChunkRecord chunk)
        {
            var selectedStorage = scope.IsInitiator ? storage : peerStorage;
            using var value = await selectedStorage.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot, default);
            Assert.NotNull(value);
            var originalHash = value.Use(bytes => SHA256.HashData(bytes));
            using var decoded = value.Use(bytes => ProtectedDid2GroupJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            var outgoing = decoded.Outbox.Single(entry => entry.Operation.AsSpan().SequenceEqual(item.Operation));
            var at = outgoing.Event.AsSpan().IndexOf(chunk.CanonicalBytes.Span); Assert.True(at > 0);
            if (System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(5).Span) > 1)
            {
                var total = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(2).Span);
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(outgoing.Event.AsSpan(at + 60), total % 24576 == 0 ? total - 1 : total + 1);
            }
            else
            {
                // Preserve canonical geometry and hash, but alter exact bytes:
                // even a one-chunk bootstrap must bind the protected package.
                var length = chunk.CanonicalBytes.Length - 152;
                outgoing.Event[at + 152] ^= 1;
                SHA256.HashData(outgoing.Event.AsSpan(at + 152, length)).CopyTo(outgoing.Event, at + 108);
            }
            Assert.Throws<CryptographicException>(() => ProtectedDid2GroupJournal.Encode(decoded, scope.Network, scope.LocalAccount, scope.Instance));
            using var unchanged = await selectedStorage.ReadOwnedAsync(ProtectedDid2GroupJournal.Slot, default);
            Assert.Equal(originalHash, unchanged!.Use(bytes => SHA256.HashData(bytes)));
        }

        internal async Task CheckGroupDirectoryBorrow()
        {
            var source = Source();
            var own = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var candidate = peerCheckpoint!.Binding.DeepId.CanonicalBytes;
            var expected = peerCheckpoint.Binding.Record.DeepAccountId;
            var requests = ProofRequests;
            var verified = await source.VerifyGroupDirectoryAsync(candidate, expected, own, held, budget.Token);
            Assert.Equal(expected.ToArray(), verified.AccountId.ToArray()); Assert.True(ProofRequests > requests);
            using var foreign = await new DeepIdV2AccountFileLease(Path.Combine(directory, "peer", "deep-store-v2-account.lock")).AcquireAsync(default);
            requests = ProofRequests;
            await Assert.ThrowsAsync<CryptographicException>(async () => await source.VerifyGroupDirectoryAsync(candidate, expected, own, foreign, budget.Token));
            Assert.Equal(requests, ProofRequests);
            held.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(async () => await source.VerifyGroupDirectoryAsync(candidate, expected, own, held, budget.Token));
            // The scoped reader owns no transport. Its disposal must not close
            // the original proof client used by subsequent normal operations.
            _ = await source.VerifyForOwnPreKeyAuthoringAsync(Accounts, default);
        }

        private ProtectedDeepIdV2AccountOwner GroupOwner(Did2MessagingSessionScope scope)
        {
            var path = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            return new(scope.IsInitiator ? storage : peerStorage, new DeepIdV2AccountFileLease(Path.Combine(path, "deep-store-v2-account.lock")),
                Path.Combine(path, "deep-store-v2-account.dsv2"), Network, 1);
        }
        internal async Task PrepareGroupAction(Did2MessagingSessionScope scope, string action, byte[] group, string? text = null, bool omitTargets = false)
        {
            var account = scope.IsInitiator ? Accounts : peerAccounts!; var source = Source(account);
            var pair = await source.VerifyForOwnMessagingAsync(account, scope, default);
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            _ = await GroupOwner(scope).GroupActionAsync(1000, verifier, action, group, scope, text, pair.Own, pair.Peer, source, default, omitTargets ? Array.Empty<ProtectedDeepIdV2AccountOwner.GroupTarget>() : null);
        }
        internal async Task<IReadOnlyList<ProtectedDid2GroupJournal.Outgoing>> ReadGroupBatch(Did2MessagingSessionScope scope, byte[] group, bool pendingOnly = false)
        {
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            return await GroupOwner(scope).ReadGroupBatchAsync(1000, verifier, group, scope, default, pendingOnly);
        }
    }
}
