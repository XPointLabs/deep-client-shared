using System.Net;
using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.DeviceV1;
using Deep.Client.Shared.Persistence.PreKeyV2;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Client.Shared.Services.AttachmentV1;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2MailboxPaths_StoreKeepsRankedWriterWhileReadsUseEitherReplica(bool reverseRank)
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        var snapshot = OnionPathCandidateSnapshotFactory.Create(network);
        var candidates = snapshot.Candidates.OrderBy(candidate => Convert.ToHexString(candidate.NodeId.Span), StringComparer.Ordinal).ToArray();
        Assert.Equal(3, candidates.Length);
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var guards = new EntryGuardState(1, Fixture.Network, snapshot.ViewGeneration, snapshot.ViewHash.Span,
            Bytes(32, 0xa1), candidates[0].NodeId.Span, candidates.Select(candidate => candidate.NodeId));
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await custody.Guards.CompareExchangeAsync(null, guards, default)).Disposition);
        var placement = new Deep.Protocol.DeepExtension.MailboxCapabilities.BlindedPlacementId(Bytes(32, 0xa2));
        var first = candidates[reverseRank ? 1 : 0].NodeId;
        var second = candidates[reverseRank ? 0 : 1].NodeId;
        var route = new ScopedMailboxResolvedRoute(1, 1400,
            new(Bytes(32, 0xa3)), placement,
            Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxPlacementCommitment.Compute(placement),
            Bytes(32, 0xa4), new(first.Span,
                network.ResolveNodeIdentityPublicKey(first).Span,
                second.Span, network.ResolveNodeIdentityPublicKey(second).Span));
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        // Synthetic MAU3 grants exercise structural/path selection only.
        // They are not issued credentials; no socket, adapter receipt or ACK is claimed.
        foreach (var operation in new[] { OnionOperation.Store, OnionOperation.Retrieve, OnionOperation.Acknowledge })
        {
            var exact = Did2MailboxRouteBindingTests.Request(operation, route, Fixture.Network);
            var entries = new List<byte[]>();
            foreach (var selection in new[] { PrivacyMailboxRouteSelection.Primary, PrivacyMailboxRouteSelection.Fallback })
            {
                var paths = source.CreateOwnMailboxPaths(custody, selection);
                var attempt = await paths.PrepareOnRouteAsync(operation, exact, route, default);
                Assert.Equal(exact, attempt.Request.CanonicalBytes.ToArray());
                var entry = OnionEntryTransportFactory.Create(attempt.Path);
                entry.EnsureCurrent();
                var exit = operation == OnionOperation.Store || selection == PrivacyMailboxRouteSelection.Primary ? first : second;
                Assert.False(entry.Peer.NodeId.Span.SequenceEqual(exit.Span));
                if (!exit.Span.SequenceEqual(candidates[0].NodeId.Span))
                    Assert.Equal(candidates[0].NodeId.ToArray(), entry.Peer.NodeId.ToArray());
                entries.Add(entry.Peer.NodeId.ToArray());
                using var frame = await codec.BuildAsync(attempt.Path, attempt.Request, default);
                Assert.True(frame.Frame.Length > exact.Length);
            }
            Assert.Equal(operation == OnionOperation.Store, entries[0].AsSpan().SequenceEqual(entries[1]));
        }
        Assert.Equal(7, fixture.ProofRequests); // initial + each of six independent attempts
        Assert.Equal(1UL, (await custody.Guards.ReadAsync(default))!.Revision);
        // Use the already verifier-minted context to isolate caller-memory
        // mutation across the authority await, not to fake network authority.
        var mutable = Did2MailboxRouteBindingTests.Request(OnionOperation.Retrieve, route, Fixture.Network);
        var original = mutable.ToArray();
        var commitment = route.PlacementCommitment.ToArray();
        var mutator = new MutatingMailboxNetwork(network, () =>
        {
            Array.Clear(mutable);
            Assert.True(MemoryMarshal.TryGetArray(route.PlacementCommitment, out var exposed));
            exposed.AsSpan().Clear();
            Assert.True(MemoryMarshal.TryGetArray(route.MembershipCommitment, out exposed));
            exposed.AsSpan().Clear();
        });
        var isolated = new MailboxPrivacyPathProvider(mutator, custody.Guards,
            PrivacyMailboxRouteSelection.Primary, () => throw new InvalidOperationException("Retained guards must not reseed."));
        var captured = await isolated.PrepareOnRouteAsync(OnionOperation.Retrieve, mutable, route, default);
        Assert.Equal(original, captured.Request.CanonicalBytes.ToArray());
        Assert.Equal(commitment, mutator.Commitment);
    }

    private sealed class MutatingMailboxNetwork(VerifiedOnionNetworkContext network, Action mutate)
        : IMailboxPrivacyNetworkAuthoritySource
    {
        internal byte[]? Commitment { get; private set; }
        public async ValueTask<VerifiedOnionNetworkContext> GetCurrentForMailboxAsync(
            ReadOnlyMemory<byte> commitment, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Yield();
            mutate();
            Commitment = commitment.ToArray();
            return network;
        }
    }

    [Fact]
    public async Task Did2MailboxNetwork_UsesFreshOwnedProofAndRejectsAlteredNetworkWithoutFloorRewrite()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var mailbox = Assert.IsAssignableFrom<IMailboxPrivacyNetworkAuthoritySource>(source);
        foreach (var malformed in new[] { Array.Empty<byte>(), new byte[32], new byte[31], new byte[33] })
            await Assert.ThrowsAsync<ArgumentException>(async () => await mailbox.GetCurrentForMailboxAsync(malformed, default));
        Assert.Equal(0, fixture.ProofRequests);
        var first = await mailbox.GetCurrentForMailboxAsync(Bytes(32, 0x91), default);
        first.EnsureCurrent();
        Assert.Equal(Fixture.Network, first.NetworkId.ToArray());
        var floor = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(1, fixture.ProofRequests);
        var second = await mailbox.GetCurrentForMailboxAsync(Bytes(32, 0x92), default);
        second.EnsureCurrent();
        Assert.Equal(2, fixture.ProofRequests); // no cached current-proof authority
        Assert.Equal(floor.Revision, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () => await mailbox.GetCurrentForMailboxAsync(Bytes(32, 0x93), default));
        Assert.Equal(floor.Revision, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task Did2MailboxTransport_UnscopedAndForeignCustodyRejectBeforeNetworkOrEntropy()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var foreign = await fixture.ReopenAccount().OpenOwnOnionClientCustodyAsync();
        Assert.Throws<ArgumentException>(() => source.CreateOwnMailboxPaths(foreign, PrivacyMailboxRouteSelection.Primary));
        var ingress = new DeepIdV2MailboxOnionTransport(source, custody,
            PrivacyMailboxRouteSelection.Primary, new NoMailboxDecodePolicy());
        foreach (var send in new Func<Task<ReadOnlyMemory<byte>>>[]
        {
            () => ingress.StoreAsync(ReadOnlyMemory<byte>.Empty),
            () => ingress.RetrieveAsync(ReadOnlyMemory<byte>.Empty),
            () => ingress.AcknowledgeAsync(ReadOnlyMemory<byte>.Empty)
        })
        {
            var failure = await Assert.ThrowsAsync<ClientMailboxTransportException>(send);
            Assert.Equal(ClientMailboxTransportFailure.ProtocolViolation, failure.Failure);
            Assert.False(failure.Retryable);
        }
        Assert.Equal(0, fixture.ProofRequests);
        Assert.Null(await custody.Guards.ReadAsync(default));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ingress.RetrieveAsync(ReadOnlyMemory<byte>.Empty, cancelled.Token));
        Assert.Empty(typeof(DeepIdV2MailboxOnionTransport).GetConstructors());
    }

    private sealed class NoMailboxDecodePolicy : IMailboxClientDecodePolicyProvider
    {
        public Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxClientDecodePolicy GetCurrent() =>
            throw new InvalidOperationException("Unscoped dispatch must not read response policy.");
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactOwner_ExplicitAcceptanceExactRetryPeerReceiveAndReply()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xc1));
        byte[] dph;
        using (var sent = await complete(fixture.Accounts)) dph = sent.ExactDph2.ToArray();
        using (var received = await fixture.CompleteReceiver(dph))
            Assert.True(received.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(dph);
        Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await fixture.ReadOwnedContactState(receiver));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareOwnedContactAccept(sender, Bytes(32, 0xc2)));
        byte[] accepted, operation;
        using (var draft = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xc2)))
        { accepted = draft.ExactDmc2.ToArray(); operation = draft.Operation.ToArray(); }
        using (var retry = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xc3)))
        { Assert.Equal(accepted, retry.ExactDmc2.ToArray()); Assert.Equal(operation, retry.Operation.ToArray()); }
        Assert.Equal(3UL, ApplicationCoreCodec.DecodeDmc2(accepted).SenderClientSequence);
        byte[] ciphertext;
        var interrupted = false;
        using (DirectDmc2InboxTestHooks.Push(point =>
        { if (point == DirectDmc2InboxFaultPoint.AfterCommit) { interrupted = true; throw new IOException("Injected committed ContactAccept response loss."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(accepted)));
        Assert.True(interrupted);
        var committed = await fixture.ReadMessagingFloor(receiver);
        using (var sent = await fixture.SendOwnedMessage(receiver, operation, ApplicationCoreCodec.DecodeDmc2(accepted)))
            ciphertext = sent.ExactEnvelope.ToArray();
        Assert.Equal(committed.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        using (var received = await fixture.ReceiveOwnedMessage(sender, ciphertext))
        using (var plain = received.OwnAuthenticatedDmc2())
            Assert.True(plain.Use(bytes => bytes.SequenceEqual(accepted)));
        var peerFloor = await fixture.ReadMessagingFloor(sender);
        using (var replay = await fixture.ReceiveOwnedMessage(sender, ciphertext))
            Assert.Equal(2, replay.Direction);
        Assert.Equal(peerFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(Did2ContactAcceptanceState.LocalAcceptanceRetained, await fixture.ReadOwnedContactState(receiver));
        Assert.Equal(Did2ContactAcceptanceState.PeerAcceptanceRetained, await fixture.ReadOwnedContactState(sender));
        var lostText = false;
        using (Did2TextOutboxTestHooks.Push(point =>
        { if (point == Did2TextOutboxFailpoint.AfterSql) { lostText = true; throw new IOException("Injected owned text SQL response loss."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedText(receiver, Bytes(32, 0xc5), "reply after explicit contact acceptance"));
        Assert.True(lostText);
        ParsedDmc2 reply;
        using (var draft = await fixture.PrepareOwnedText(receiver, Bytes(32, 0xc5), "reply after explicit contact acceptance"))
        { Assert.Equal(4UL, draft.SenderSequence); reply = ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span); }
        using (var retry = await fixture.PrepareOwnedText(receiver, Bytes(32, 0xc5), "reply after explicit contact acceptance"))
            Assert.Equal(reply.CanonicalBytes.ToArray(), retry.ExactDmc2.ToArray());
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareOwnedText(receiver, Bytes(32, 0xc5), "changed command"));
        using (var sent = await fixture.SendOwnedMessage(receiver, Bytes(32, 0xc5), reply))
            ciphertext = sent.ExactEnvelope.ToArray();
        using (var received = await fixture.ReceiveOwnedMessage(sender, ciphertext))
        using (var plain = received.OwnAuthenticatedDmc2())
            Assert.True(plain.Use(bytes => bytes.SequenceEqual(reply.CanonicalBytes.Span)));
        var history = await fixture.ListOwnedMessages(sender);
        Assert.Single(history); Assert.Equal("reply after explicit contact acceptance", history[0].Text);
        Assert.False(history[0].IsLocalAuthor);
        foreach (var bytes in new[] { dph, accepted, operation, ciphertext }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MessagingOwner_RefreshesOwnedPeerAfterTtlWithoutImportingOrMutatingRatchet()
    {
        // Real owned account/seed/catalog and signed proofs; synthetic Registry/time,
        // not live-clock, socket or physical device evidence.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xba));
        using (var sent = await complete(fixture.Accounts)) Assert.NotEmpty(sent.ExactDph2.ToArray());
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var before = await fixture.ReadMessagingFloor(sender);
        var first = await fixture.RefreshOwnedMessaging(sender);
        var requests = fixture.ProofRequests;
        fixture.Sample = Math.Max(first.Own.Proof.FreshnessDeadlineMonotonicSeconds, first.Peer.FreshnessDeadlineMonotonicSeconds);
        var reading = await fixture.ReadAsync(default);
        Assert.False(first.Peer.IsCurrentAtMonotonic(reading.BootId.Span, fixture.Sample));
        var refreshed = await fixture.RefreshOwnedMessaging(sender);
        Assert.True(fixture.ProofRequests >= requests + 2);
        Assert.Equal(first.Peer.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes.ToArray(),
            refreshed.Peer.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes.ToArray());
        Assert.True(refreshed.Peer.IsCurrentAtMonotonic(reading.BootId.Span, fixture.Sample));
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await fixture.DropPeerBootstrap(sender);
        requests = fixture.ProofRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.RefreshOwnedMessaging(sender));
        Assert.Equal(requests, fixture.ProofRequests);
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MessagingOwner_OrdinarySendReceiveReopenGapAndExactReplay()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xbe));
        byte[] dph;
        using (var sent = await complete(fixture.Accounts)) dph = sent.ExactDph2.ToArray();
        using (var received = await fixture.CompleteReceiver(dph))
            Assert.True(received.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(dph);
        using (var acceptance = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xf0)))
        using (var sentAccept = await fixture.SendOwnedMessage(receiver, acceptance.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(acceptance.ExactDmc2)))
        using (var receivedAccept = await fixture.ReceiveOwnedMessage(sender, sentAccept.ExactEnvelope.ToArray())) { }
        async Task<ParsedDmc2> Text(Did2MessagingSessionScope scope, byte operation, string value)
        {
            using var draft = await fixture.PrepareOwnedText(scope, Bytes(32, operation), value);
            return ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span);
        }
        var senderBase = await fixture.ReadMessagingFloor(sender);
        var receiverBase = await fixture.ReadMessagingFloor(receiver);
        var first = await Text(sender, 0xe1, "Owned DID2 text 📨");
        var second = await Text(sender, 0xe2, "Owned DID2 reordered text");
        byte[] cipher1, cipher2;
        var lostSend = false;
        using (Did2MessagingCommitTestHooks.Push(point =>
        { if (point == Did2MessagingCommitFailpoint.AfterSql) { lostSend = true; throw new IOException("Injected lost DID2 send response."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedMessage(sender, Bytes(32, 0xe1), first));
        Assert.True(lostSend);
        var pendingSend = await fixture.ReadMessagingFloor(sender);
        Assert.Equal((byte)2, pendingSend.Phase); Assert.Equal(senderBase.Ordinal + 1, pendingSend.Ordinal);
        using (var send1 = await fixture.SendOwnedMessage(sender, Bytes(32, 0xe1), first)) cipher1 = send1.ExactEnvelope.ToArray();
        using (var send2 = await fixture.SendOwnedMessage(sender, Bytes(32, 0xe2), second)) cipher2 = send2.ExactEnvelope.ToArray();
        var senderFloor = await fixture.ReadMessagingFloor(sender);
        using (var retry = await fixture.SendOwnedMessage(sender, Bytes(32, 0xe1), first)) Assert.Equal(cipher1, retry.ExactEnvelope.ToArray());
        Assert.Equal(senderFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        async Task Receive(Did2MessagingSessionScope scope, byte[] cipher, ParsedDmc2 expected)
        {
            using var row = await fixture.ReceiveOwnedMessage(scope, cipher);
            Assert.Equal(2, row.Direction);
            using var plain = row.OwnAuthenticatedDmc2();
            Assert.True(plain.Use(bytes => bytes.SequenceEqual(expected.CanonicalBytes.Span)));
        }
        var interruptedReceive = false;
        using (Did2MessagingCommitTestHooks.Push(point =>
        { if (point == Did2MessagingCommitFailpoint.AfterPending) { interruptedReceive = true; throw new IOException("Injected pending DID2 receive interruption."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.ReceiveOwnedMessage(receiver, cipher2));
        Assert.True(interruptedReceive);
        Assert.Equal((byte)2, (await fixture.ReadMessagingFloor(receiver)).Phase);
        await Receive(receiver, cipher2, second);
        await Receive(receiver, cipher1, first);
        var receiverFloor = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(receiverBase.RatchetGeneration + 2, receiverFloor.RatchetGeneration); Assert.Equal(receiverBase.Ordinal + 2, receiverFloor.Ordinal);
        await Receive(receiver, cipher1, first);
        Assert.Equal(receiverFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        var tampered = cipher1.ToArray(); tampered[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedMessage(receiver, tampered));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedMessage(sender, cipher1));
        Assert.Equal(receiverFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        var reply = await Text(receiver, 0xe3, "Owned DID2 reply"); byte[] replyCipher;
        using (var sentReply = await fixture.SendOwnedMessage(receiver, Bytes(32, 0xe3), reply)) replyCipher = sentReply.ExactEnvelope.ToArray();
        await Receive(sender, replyCipher, reply);
        var before = await fixture.ReadMessagingFloor(sender);
        await Receive(sender, replyCipher, reply);
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        var senderHistory = await fixture.ListOwnedMessages(sender);
        var receiverHistory = await fixture.ListOwnedMessages(receiver);
        Assert.Equal(3, senderHistory.Count); Assert.Equal(3, receiverHistory.Count);
        Assert.Equal(new[] { "Owned DID2 text 📨", "Owned DID2 reordered text", "Owned DID2 reply" }.Order(),
            senderHistory.Select(message => message.Text).Order());
        Assert.Equal(senderHistory.Select(message => message.Text).Order(), receiverHistory.Select(message => message.Text).Order());
        Assert.Equal(2, senderHistory.Count(message => message.IsLocalAuthor));
        Assert.Single(receiverHistory, message => message.IsLocalAuthor);
        // Caller substitution is not a protected authored text command and
        // cannot authorize destructive latching or consume a ratchet position.
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, Bytes(32, 0xe1), second));
        var latched = await fixture.ReadMessagingFloor(sender);
        Assert.Equal(before.Exact.ToArray(), latched.Exact.ToArray());
        using (var retainedSend = await fixture.SendOwnedMessage(sender, Bytes(32, 0xe1), first)) Assert.Equal(cipher1, retainedSend.ExactEnvelope.ToArray());
        // Same actual account/session/counter, not a raw DAM1 send bypass.
        // Cipher chunks are copied locally only: this does not test BLOB-01.
        var assetOperation = Bytes(32, 0xe4); var offerOperation = Bytes(32, 0xe5);
        var fileBytes = System.Text.Encoding.UTF8.GetBytes("Owned DID2 attachment integrity 📨");
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, fileBytes, "document.txt", "text/plain", 1_400);
        using var draftOffer = await fixture.PrepareOwnedAttachmentOffer(sender, offerOperation, assetOperation);
        var offer = ApplicationCoreCodec.DecodeDmc2(draftOffer.ExactDmc2.Span);
        var offered = Assert.IsType<AttachmentOfferDmc2Payload>(offer.ParsedPayload);
        try
        {
            Assert.Equal(second.SenderClientSequence + 1, offer.SenderClientSequence);
            using var retainedManifest = asset.OwnManifest();
            Assert.True(retainedManifest.Use(bytes => bytes.SequenceEqual(offered.Manifest.CanonicalBytes.Span)));
            byte[] cipherOffer;
            using (var sent = await fixture.SendOwnedMessage(sender, offerOperation, offer)) cipherOffer = sent.ExactEnvelope.ToArray();
            using (var replay = await fixture.SendOwnedMessage(sender, offerOperation, offer)) Assert.Equal(cipherOffer, replay.ExactEnvelope.ToArray());
            using (var received = await fixture.ReceiveOwnedMessage(receiver, cipherOffer))
            using (var plain = received.OwnAuthenticatedDmc2())
            {
                var openedOffer = plain.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes));
                using var openedManifest = Assert.IsType<AttachmentOfferDmc2Payload>(openedOffer.ParsedPayload).Manifest;
                Assert.Equal(offered.Manifest.CanonicalBytes.ToArray(), openedManifest.CanonicalBytes.ToArray());
                var cipherChunk = asset.CopyCiphertext(0); var recoveredFile = AttachmentChunkCipher.Decrypt(openedManifest, 0, cipherChunk);
                try { Assert.Equal(fileBytes, recoveredFile); }
                finally { CryptographicOperations.ZeroMemory(cipherChunk); CryptographicOperations.ZeroMemory(recoveredFile); }
            }
            var afterOffer = await fixture.ReadMessagingFloor(receiver);
            using (var replay = await fixture.ReceiveOwnedMessage(receiver, cipherOffer)) { }
            Assert.Equal(afterOffer.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
            var followup = await Text(sender, 0xe6, "Owned DID2 text after attachment");
            Assert.Equal(offer.SenderClientSequence + 1, followup.SenderClientSequence);
            using var followupSend = await fixture.SendOwnedMessage(sender, Bytes(32, 0xe6), followup);
            await Receive(receiver, followupSend.ExactEnvelope.ToArray(), followup);
            // A text operation cannot be substituted with an offer, and a
            // shorter-lived adopted asset cannot gain current offer authority.
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareOwnedAttachmentOffer(sender, Bytes(32, 0xe1), assetOperation));
            using var expired = await fixture.PrepareOwnedAsset(sender, Bytes(32, 0xe7), fileBytes, "expired.txt", "text/plain", 1_001);
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareOwnedAttachmentOffer(sender, Bytes(32, 0xe8), Bytes(32, 0xe7)));
            CryptographicOperations.ZeroMemory(cipherOffer);
        }
        finally { offered.Manifest.Dispose(); CryptographicOperations.ZeroMemory(fileBytes); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2MessagingOwner_ImportsRetiresAndResumesWithoutInitialKeys()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var intent = Bytes(32, 0xad);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(intent);
        byte[] exact;
        using (var sent = await complete(fixture.Accounts)) exact = sent.ExactDph2.ToArray();
        using (var received = await fixture.CompleteReceiver(exact))
            Assert.True(received.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
        foreach (var point in new[] { InitialKeyRetirementFailpoint.AfterPending, InitialKeyRetirementFailpoint.AfterPreclaim,
            InitialKeyRetirementFailpoint.AfterSourceDelete, InitialKeyRetirementFailpoint.AfterStable })
        {
            var hit = false;
            using (InitialKeyRetirementTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected owner retirement interruption."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.EnsureSenderMessaging(init, hello));
            Assert.True(hit);
        }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        Assert.True(sender.IsInitiator);
        var senderFloor = await fixture.ReadMessagingFloor(sender);
        Assert.Equal((byte)1, senderFloor.Status); Assert.Equal(2UL, senderFloor.Ordinal);
        Assert.Equal(sender.Exact.ToArray(), (await fixture.EnsureSenderMessaging(init, hello)).Exact.ToArray());
        Assert.Equal(senderFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.EnsureSenderMessaging(hello, init));
        foreach (var point in new[] { InitialKeyRetirementFailpoint.AfterPending,
            InitialKeyRetirementFailpoint.AfterSourceDelete, InitialKeyRetirementFailpoint.AfterStable })
        {
            var hit = false;
            using (InitialKeyRetirementTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected owner retirement interruption."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.EnsureReceiverMessaging(exact));
            Assert.True(hit);
        }
        var receiver = await fixture.EnsureReceiverMessaging(exact);
        Assert.False(receiver.IsInitiator);
        var receiverFloor = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal((byte)1, receiverFloor.Status); Assert.Equal(2UL, receiverFloor.Ordinal);
        Assert.Equal(receiver.Exact.ToArray(), (await fixture.EnsureReceiverMessaging(exact)).Exact.ToArray());
        Assert.Equal(receiverFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(receiver)).Exact.ToArray());
        Assert.Equal(sender.Session.ToArray(), receiver.Session.ToArray());
        Assert.Equal(sender.Conversation.ToArray(), receiver.Conversation.ToArray());
        using var senderMetadata = await complete(fixture.ReopenAccount());
        Assert.False(senderMetadata.HasInitialState);
        using var receiverMetadata = await fixture.FindReceiver(exact, reopen: true);
        Assert.NotNull(receiverMetadata); Assert.False(receiverMetadata.HasInitialState);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ContactHelloVertical_TwoOwnedAccountsNativeCompletionExactRestart()
    {
        // Two independently created PQ accounts, real account custody and
        // signed proofs/claims, approved native providers. NOT device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, preview, prepare) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var first = await complete(fixture.Accounts);
        var ciphertext = first.ExactDph2.ToArray();
        Assert.Equal(hello.ConversationId.ToArray(), first.RequireInitialConversation(init.CanonicalBytes.Span, hello.CanonicalBytes.Span));
        using var retry = await complete(fixture.ReopenAccount());
        Assert.Equal(ciphertext, retry.ExactDph2.ToArray());
        Assert.Equal(first.SessionId.ToArray(), retry.SessionId.ToArray());
        var opened = await preview(ciphertext);
        Assert.Equal(Dph2Codec.Decode(ciphertext).ClaimOperationId.ToArray(), opened.Request.Field(2).ToArray());
        var openedAgain = await preview(retry.ExactDph2);
        Assert.Equal(opened.Request.CanonicalBytes.ToArray(), openedAgain.Request.CanonicalBytes.ToArray());
        Assert.Equal(opened.Result.WireBytes.ToArray(), openedAgain.Result.WireBytes.ToArray());
        var tampered = ciphertext.ToArray(); tampered[^1] ^= 1;
        await Assert.ThrowsAnyAsync<CryptographicException>(() => preview(tampered));
        using var prepared = await prepare(opened);
        Assert.Equal(first.SessionId.ToArray(), prepared.SessionId.ToArray());
        Assert.Equal(first.ClaimOperationId.ToArray(), prepared.ClaimOperationId.ToArray());
        using var payload = prepared.ConsumeForAtomicStore();
        Assert.Throws<InvalidOperationException>(() => prepared.ConsumeForAtomicStore());
        var recoveredInit = payload.SessionInitDmc2.ToArray();
        var recoveredHello = payload.FirstApplicationDmc2.ToArray();
        var recoveredTrs = payload.ExactTrs1.ToArray();
        try
        {
            Assert.Equal(init.CanonicalBytes.ToArray(), recoveredInit);
            Assert.Equal(hello.CanonicalBytes.ToArray(), recoveredHello);
            Assert.Equal(first.SessionId.ToArray(), payload.Reservation.SessionId.ToArray());
            Assert.Equal(first.ExactClaimReplayHash.ToArray(), payload.Reservation.Xpc1FullReplayHash.ToArray());
            Assert.NotEmpty(recoveredTrs);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveredInit); CryptographicOperations.ZeroMemory(recoveredHello);
            CryptographicOperations.ZeroMemory(recoveredTrs);
        }
        payload.Dispose();
        Assert.Throws<ObjectDisposedException>(() => payload.ExactTrs1);
        var substituted = hello.CanonicalBytes.ToArray(); substituted[^1] ^= 1;
        Assert.Throws<CryptographicException>(() => retry.RequireInitialConversation(init.CanonicalBytes.Span, substituted));
        using var received = await fixture.CompleteReceiver(ciphertext);
        Assert.Equal(first.SessionId.ToArray(), received.SessionId.ToArray());
        Assert.Equal(hello.ConversationId.ToArray(), received.ConversationId.ToArray());
        Assert.True(received.ExactInitSpan.SequenceEqual(init.CanonicalBytes.Span));
        Assert.True(received.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
        var afterReceiveRequests = fixture.ProofRequests;
        using var receivedAgain = await fixture.FindReceiver(ciphertext, reopen: true);
        Assert.NotNull(receivedAgain);
        Assert.True(received.CanonicalSpan.SequenceEqual(receivedAgain.CanonicalSpan));
        Assert.Equal(afterReceiveRequests, fixture.ProofRequests); // Historical exact replay needs no new claim/proof.
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ReceiverCustody_OneTimeConsumptionAndRecoveryAtEveryCommitBoundary()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var index = 0;
        foreach (var point in new[] { ResponderInitialSessionFailpoint.AfterPending,
            ResponderInitialSessionFailpoint.AfterSqlCommit, ResponderInitialSessionFailpoint.AfterStable })
        {
            var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(
                Bytes(32, checked((byte)(0xa1 + index))), oneTimeIndex: index);
            using var sent = await complete(fixture.Accounts);
            var exact = sent.ExactDph2.ToArray();
            Assert.Equal(Dpk2PrekeyKind.OneTime, Dph2Codec.Decode(exact).SelectedPrekey.Kind);
            using (ResponderInitialSessionTestHooks.Push(hit =>
                { if (hit == point) throw new IOException("Injected receiver commit boundary interruption."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CompleteReceiver(exact));
            var proofRequests = fixture.ProofRequests;
            using var recovered = await fixture.FindReceiver(exact, reopen: true);
            Assert.NotNull(recovered);
            Assert.Equal(sent.SessionId.ToArray(), recovered.SessionId.ToArray());
            Assert.True(recovered.ExactInitSpan.SequenceEqual(init.CanonicalBytes.Span));
            Assert.True(recovered.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
            Assert.Equal(proofRequests, fixture.ProofRequests);
            using var replay = await fixture.CompleteReceiver(exact);
            Assert.True(recovered.CanonicalSpan.SequenceEqual(replay.CanonicalSpan));
            Assert.Equal(proofRequests, fixture.ProofRequests);
            await fixture.AssertReceiverSqlAsync(index + 1, exact);
            index++;
        }
        // A SQL rollback cannot reopen any consumed secret or grant history.
        await fixture.RollBackReceiverSqlAsync();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.AccountsForPeer().HasOwnStagedPreKeyInventoryAsync());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ReceiverCustody_LastResortSignedLimitDeletionAndExactRestart()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xaf));
        using var sent = await complete(fixture.Accounts);
        var exact = sent.ExactDph2.ToArray();
        Assert.Equal(Dpk2PrekeyKind.LastResort, Dph2Codec.Decode(exact).SelectedPrekey.Kind);
        using var received = await fixture.CompleteReceiver(exact);
        Assert.True(received.ExactInitSpan.SequenceEqual(init.CanonicalBytes.Span));
        Assert.True(received.ExactHelloSpan.SequenceEqual(hello.CanonicalBytes.Span));
        await fixture.AssertReceiverSqlAsync(1, exact); // The signed local LR limit is1, not64.
        var proofs = fixture.ProofRequests;
        using var replay = await fixture.FindReceiver(exact, reopen: true);
        Assert.NotNull(replay); Assert.True(received.CanonicalSpan.SequenceEqual(replay.CanonicalSpan));
        Assert.Equal(proofs, fixture.ProofRequests);
        var changed = exact.ToArray(); changed[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.FindReceiver(changed, reopen: true));
        var (senderSeed, receiverSeed) = await fixture.CreateMessagingSeeds(sent, received, init, hello);
        using (senderSeed)
        using (receiverSeed)
        {
            Assert.True(senderSeed.IsInitiator); Assert.False(receiverSeed.IsInitiator);
            Assert.True(senderSeed.ConversationId.Span.SequenceEqual(receiverSeed.ConversationId.Span));
            Assert.True(senderSeed.RelationshipId.Span.SequenceEqual(receiverSeed.RelationshipId.Span));
            Assert.True(senderSeed.LocalDirectory.RecordHash.Span.SequenceEqual(receiverSeed.RemoteDirectory.RecordHash.Span));
            Assert.True(senderSeed.RemoteDirectory.RecordHash.Span.SequenceEqual(receiverSeed.LocalDirectory.RecordHash.Span));
            Assert.True(senderSeed.ExactTrs.SequenceEqual(sent.ExactTrsSpan));
            Assert.True(receiverSeed.ExactTrs.SequenceEqual(received.ExactTrsSpan));
            Assert.True(senderSeed.ExactSessionInit.SequenceEqual(init.CanonicalBytes.Span));
            Assert.True(receiverSeed.ExactContactHello.SequenceEqual(hello.CanonicalBytes.Span));
            await AssertNativeMessagingIsolation(senderSeed, receiverSeed, hello, fixture);
        }
        Assert.Throws<ObjectDisposedException>(() => senderSeed.ExactTrs.Length);
        Assert.Throws<ObjectDisposedException>(() => receiverSeed.ExactTrs.Length);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.CreateMessagingSeeds(sent, received, hello, init));
        var sample = fixture.Sample;
        try
        {
            fixture.Sample = checked(sample + 1_000);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.CreateMessagingSeeds(sent, received, init, hello));
        }
        finally { fixture.Sample = sample; }
        using var completedRetry = await complete(fixture.Accounts);
        Assert.True(sent.CanonicalSpan.SequenceEqual(completedRetry.CanonicalSpan));
        Assert.False(completedRetry.HasInitialState);
        Assert.Throws<InvalidOperationException>(() => completedRetry.ExactTrsSpan.ToArray());
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.BeginPreClaimAsync(Bytes(32, 0xaf)));
        using var retiredReceiver = await fixture.FindReceiver(exact, reopen: true);
        Assert.NotNull(retiredReceiver); Assert.False(retiredReceiver.HasInitialState);
    }

    // Native production crypto over DID2-owned initial states. The authority
    // here is deliberately test-only memory, not a shipping/durable E2E claim.
    private static async Task AssertNativeMessagingIsolation(OwnedInitialMessagingSeed senderSeed,
        OwnedInitialMessagingSeed receiverSeed, ParsedDmc2 hello, Fixture fixture)
    {
        var senderStorage = await fixture.RegisterMessagingStorage(senderSeed);
        using var sender = new Did2NativeMessagingIsolation(senderSeed, senderStorage.Storage, senderStorage.Reopen, fixture.RetireInitialKeys);
        var receiverStorage = await fixture.RegisterMessagingStorage(receiverSeed);
        using var receiver = new Did2NativeMessagingIsolation(receiverSeed, receiverStorage.Storage, receiverStorage.Reopen, fixture.RetireInitialKeys);
        ParsedDmc2 Text(OwnedInitialMessagingSeed seed, byte id, ulong sequence, string text) =>
            ApplicationCoreCodec.AuthorDmc2(seed.Initiation.NetworkId.Span, Bytes(32, id), seed.ConversationId.Span,
                seed.LocalDirectory.DeepAccountId.Span,
                seed.IsInitiator ? seed.Initiation.InitiatorDeviceId.Span : seed.Initiation.ResponderDeviceId.Span,
                sequence, hello.CreatedAtUnixMilliseconds + sequence, 0, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateMessageCreatePayload(text));
        var first = Text(senderSeed, 0xd1, 3, "DID2 Windows → Android: текст и emoji 📨");
        var second = Text(senderSeed, 0xd2, 4, "DID2 out-of-order second message");
        var firstCipher = await sender.Send(first, Bytes(32, 0xe1));
        var secondCipher = await sender.Send(second, Bytes(32, 0xe2));
        var senderGeneration = sender.Generation;
        Assert.Equal(firstCipher, await sender.Send(first, Bytes(32, 0xe1)));
        Assert.Equal(senderGeneration, sender.Generation);
        await Assert.ThrowsAsync<CryptographicException>(() => sender.Send(second, Bytes(32, 0xe1)));
        Assert.Equal(senderGeneration, sender.Generation);
        using (var openedSecond = await receiver.Receive(secondCipher))
        {
            var exact = openedSecond.TakeAuthenticatedDmc2();
            try { Assert.Equal(second.CanonicalBytes.ToArray(), exact); }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        using (var openedFirst = await receiver.Receive(firstCipher))
        {
            Assert.Equal(ExactDpe2ReceiveSuccessOutcome.OutOfOrderSkippedKey, openedFirst.Outcome);
            var exact = openedFirst.TakeAuthenticatedDmc2();
            try { Assert.Equal(first.CanonicalBytes.ToArray(), exact); }
            finally { CryptographicOperations.ZeroMemory(exact); }
        }
        var priorGeneration = receiver.Generation;
        using (var replay = await receiver.Receive(firstCipher))
        {
            Assert.Equal(ExactDpe2ReceiveSuccessOutcome.ExactReplay, replay.Outcome);
            Assert.False(replay.HasAuthenticatedDmc2);
            Assert.Equal(priorGeneration, receiver.Generation);
        }
        var tampered = firstCipher.ToArray(); tampered[^1] ^= 1;
        await Assert.ThrowsAnyAsync<CryptographicException>(() => receiver.Receive(tampered));
        Assert.Equal(priorGeneration, receiver.Generation);
        var reply = Text(receiverSeed, 0xd3, 1, "DID2 Android → Windows: reply");
        var replyCipher = await receiver.Send(reply, Bytes(32, 0xe3));
        using var openedReply = await sender.Receive(replyCipher);
        var replyExact = openedReply.TakeAuthenticatedDmc2();
        try { Assert.Equal(reply.CanonicalBytes.ToArray(), replyExact); }
        finally { CryptographicOperations.ZeroMemory(replyExact); }
        // Crypto custody must not force group/different semantic events into
        // the initial direct-contact conversation. This is NOT a verified
        // group membership/materialization test; that remains MSG's boundary.
        var otherConversation = ApplicationCoreCodec.AuthorDmc2(senderSeed.Initiation.NetworkId.Span,
            Bytes(32, 0xd4), Bytes(32, 0xd5), senderSeed.LocalDirectory.DeepAccountId.Span,
            senderSeed.Initiation.InitiatorDeviceId.Span, 5, hello.CreatedAtUnixMilliseconds + 5,
            0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("Separate semantic conversation"));
        var otherCipher = await sender.Send(otherConversation, Bytes(32, 0xe4));
        using var otherOpened = await receiver.Receive(otherCipher);
        var otherExact = otherOpened.TakeAuthenticatedDmc2();
        try { Assert.Equal(otherConversation.CanonicalBytes.ToArray(), otherExact); }
        finally { CryptographicOperations.ZeroMemory(otherExact); }
    }

    [Fact]
    public async Task Did2RendezvousCustody_ExactRestartLostCommitAndHostileSnapshot()
    {
        await using var fixture = await Fixture.CreateAsync();
        var intent = Bytes(32, 0xec);
        fixture.AfterNextRendezvousCommit(() => throw new IOException("Injected lost protected commit response."));
        await Assert.ThrowsAsync<IOException>(() => fixture.EnsureRendezvous(intent));
        var committed = await fixture.ReadRendezvousSnapshot();
        Assert.Equal(ProtectedContactRendezvousJournal.HeaderBytes + ProtectedContactRendezvousJournal.EntryBytes, committed.Length);
        var recovered = await fixture.EnsureRendezvous(intent, fixture.ReopenAccount());
        Assert.Equal(committed.AsSpan(ProtectedContactRendezvousJournal.HeaderBytes + 64).ToArray(), recovered.ExactXur1.ToArray());
        Assert.Equal(committed, await fixture.ReadRendezvousSnapshot());
        var again = await fixture.EnsureRendezvous(intent);
        Assert.Equal(recovered.ExactXur1.ToArray(), again.ExactXur1.ToArray());

        var account = committed.AsSpan(28, 32).ToArray();
        var instance = committed.AsSpan(60, 32).ToArray();
        using (var parsed = ProtectedContactRendezvousJournal.Decode(committed, Fixture.Network, account, instance))
            Assert.Equal(committed, ProtectedContactRendezvousJournal.Encode(parsed, Fixture.Network, account, instance));
        foreach (var offset in new[] { 0, 1, 3, 11, 12, 28, 60, ProtectedContactRendezvousJournal.HeaderBytes + 33,
            ProtectedContactRendezvousJournal.HeaderBytes + 64 })
        {
            var changed = committed.ToArray(); changed[offset] ^= 1;
            void DecodeChanged()
            {
                using var rejected = ProtectedContactRendezvousJournal.Decode(changed, Fixture.Network, account, instance);
            }
            if (offset == ProtectedContactRendezvousJournal.HeaderBytes + 33)
                Assert.Throws<CryptographicException>(DecodeChanged);
            else if (offset == ProtectedContactRendezvousJournal.HeaderBytes + 64)
                Assert.Throws<ContactFormatException>(DecodeChanged);
            else Assert.Throws<InvalidDataException>(DecodeChanged);
        }
        Assert.Throws<InvalidDataException>(() =>
        {
            using var rejected = ProtectedContactRendezvousJournal.Decode(committed.AsSpan(0, committed.Length - 1), Fixture.Network, account, instance);
        });
        var proofRequests = fixture.ProofRequests;
        var differentOwner = fixture.ReopenAccount();
        await Assert.ThrowsAsync<ArgumentException>(() => differentOwner.EnsureOwnContactRendezvousAsync(intent, fixture.Source()));
        Assert.Equal(proofRequests, fixture.ProofRequests);
        await fixture.RemoveRendezvousSnapshot();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Accounts.GetCurrentAsync());
        await fixture.ResetAccountAsync();
        Assert.Null(await fixture.Accounts.GetCurrentAsync());
    }

    [Fact]
    public async Task Did2OwnedRendezvous_RealAccountNetworkSignsAndRejectsClockAndKeySubstitution()
    {
        await using var fixture = await Fixture.CreateAsync();
        var (authored, network) = await fixture.AuthorRendezvous();
        Assert.True(network.BindsProjection(authored.Record.Field(6)));
        Assert.Equal(Bytes(32, 0xe1), authored.Record.Field(8).ToArray());
        Assert.Equal(ScalarMult.Base(Bytes(32, 0xe2)), authored.Record.Field(9).ToArray());
        Assert.Equal(538, authored.ExactXur1.Length);
        Assert.Equal(new byte[32], authored.Record.Field(5).ToArray());
        foreach (var mode in new[] { 1, 2, 3, 4, 5, 7, 8 })
            await Assert.ThrowsAnyAsync<CryptographicException>(() => fixture.AuthorRendezvous(mode));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.AuthorRendezvous(6));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2InitialSession_NativeCompletionAndExactRestartAfterEveryCommitBoundary()
    {
        // Real local DID2, signed network/proof/claim and approved native
        // providers. Loopback recipient/HTTP fixture, NOT physical E2E.
        await using var fixture = await Fixture.CreateAsync();
        var complete = await fixture.PrepareNativeInitialCompletion(Bytes(32, 0x94));
        using var first = await complete(fixture.Accounts);
        var exact = first.ExactDph2.ToArray(); var session = first.SessionId.ToArray();
        using var reopened = await complete(fixture.ReopenAccount());
        Assert.Equal(exact, reopened.ExactDph2.ToArray()); Assert.Equal(session, reopened.SessionId.ToArray());
        foreach (var point in new[] { DeviceStateStoreFailpoint.AfterInitialSessionPendingCheckpoint,
            DeviceStateStoreFailpoint.AfterInitialSessionSqlCommit, DeviceStateStoreFailpoint.AfterInitialSessionStableCheckpoint })
        {
            var retry = await fixture.PrepareNativeInitialCompletion(Bytes(32, checked((byte)(0x94 + (int)point))));
            using (DeviceStateStoreTestHooks.Push(hit => { if (hit == point) throw new DeviceStateStoreInjectedCrashException(hit); }))
                await Assert.ThrowsAsync<DeviceStateStoreInjectedCrashException>(() => retry(fixture.Accounts));
            using var recovered = await retry(fixture.ReopenAccount());
            using var same = await retry(fixture.ReopenAccount());
            Assert.Equal(recovered.ExactDph2.ToArray(), same.ExactDph2.ToArray());
            Assert.NotEqual(exact, recovered.ExactDph2.ToArray());
        }
    }

    [Fact]
    public async Task Did2PreClaim_ProtectedIntentRestoresExactOperationAfterRestartAndInterruptedReturn()
    {
        await using var fixture = await Fixture.CreateAsync();
        var intent = Bytes(32, 0x91);
        using var first = await fixture.BeginPreClaimAsync(intent);
        var operation = first.ClaimOperationId.ToArray();
        var commitment = first.SenderEphemeralCommitment.ToArray();
        var snapshot = await fixture.ReadPreClaimSnapshotAsync();
        using var reopened = await fixture.BeginPreClaimAsync(intent, fixture.ReopenAccount());
        Assert.Equal(operation, reopened.ClaimOperationId.ToArray());
        Assert.Equal(commitment, reopened.SenderEphemeralCommitment.ToArray());
        Assert.Equal(snapshot, await fixture.ReadPreClaimSnapshotAsync());

        var interruptedIntent = Bytes(32, 0x92);
        fixture.AfterNextPreClaimCommit(() => throw new IOException("Injected stop after protected preclaim commit."));
        await Assert.ThrowsAsync<IOException>(() => fixture.BeginPreClaimAsync(interruptedIntent));
        var committed = await fixture.ReadPreClaimSnapshotAsync();
        using var recovered = await fixture.BeginPreClaimAsync(interruptedIntent, fixture.ReopenAccount());
        Assert.NotEqual(operation, recovered.ClaimOperationId.ToArray());
        Assert.Equal(committed, await fixture.ReadPreClaimSnapshotAsync());

        using var cancellation = new CancellationTokenSource();
        var cancelledIntent = Bytes(32, 0x93);
        fixture.AfterNextPreClaimCommit(cancellation.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.BeginPreClaimAsync(cancelledIntent,
            cancellationToken: cancellation.Token));
        var cancelledSnapshot = await fixture.ReadPreClaimSnapshotAsync();
        using var afterCancellation = await fixture.BeginPreClaimAsync(cancelledIntent);
        Assert.Equal(cancelledSnapshot, await fixture.ReadPreClaimSnapshotAsync());

        fixture.RejectProof = true;
        await Assert.ThrowsAsync<DeepIdV2DirectoryProofUnavailableException>(() => fixture.BeginPreClaimAsync(intent));
        Assert.Equal(cancelledSnapshot, await fixture.ReadPreClaimSnapshotAsync());
        fixture.RejectProof = false;
        await fixture.RemovePreClaimSnapshotAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.ReopenAccount().GetCurrentAsync());
        Assert.Null(await fixture.ReadPreClaimSnapshotOrNullAsync()); // No silent recreation.
    }

    private static byte[] JournalRequest(byte operation, byte bundle = 0x51, byte[]? network = null) =>
        DeepIdV2PreKeyClaimRequestCodec.Encode(network ?? Fixture.Network, Bytes(32, operation),
            Bytes(32, 0x21), Bytes(32, 0x22), 1_100, 1_120, Fixture.Service,
            Bytes(32, bundle), Bytes(32, 0x52), Bytes(32, 0x53), Bytes(32, 0x54));

    [Fact]
    public async Task Did2ClaimCustody_ConcurrentExactReplayAndRestartRetainOnlyOriginalRequests()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var first = JournalRequest(0x61);
        var second = JournalRequest(0x62);
        Assert.Null(await custody.FindAsync(Bytes(32, 0x61), default));
        var writes = await Task.WhenAll(custody.ReserveAsync(first, default).AsTask(),
            custody.ReserveAsync(first, default).AsTask(), custody.ReserveAsync(second, default).AsTask());
        Assert.Equal(first, writes[0].ToArray());
        Assert.Equal(first, writes[1].ToArray());
        Assert.Equal(second, writes[2].ToArray());
        first[^1] ^= 1; // Returned/request buffers do not own the SQL winner.
        var reopened = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
        Assert.Equal(JournalRequest(0x61), (await reopened.FindAsync(Bytes(32, 0x61), default))!.Value.ToArray());
        Assert.Equal(second, (await reopened.FindAsync(Bytes(32, 0x62), default))!.Value.ToArray());
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await reopened.ReserveAsync(JournalRequest(0x63), cancelled.Token));
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReserveAsync(second[..^1], default));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.ReserveAsync(JournalRequest(0x63, network: Bytes(16, 0x12)), default));
        Assert.Null(await reopened.FindAsync(Bytes(32, 0x63), default));
        Assert.Equal(0, fixture.ProofRequests);
    }

    [Fact]
    public async Task Did2ClaimCustody_RequestSubstitutionLatchesAcrossOwnerRestart()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        await custody.ReserveAsync(JournalRequest(0x61), default);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await custody.ReserveAsync(JournalRequest(0x61, bundle: 0x55), default));
        var reopened = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.FindAsync(Bytes(32, 0x61), default));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.ReserveAsync(JournalRequest(0x62), default));
        Assert.Equal(0, fixture.ProofRequests);
    }

    [Fact]
    public async Task Did2ClaimCustody_SqlRollbackCannotReopen()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        await custody.ReserveAsync(JournalRequest(0x61), default);
        await using var connection = await fixture.OpenSqlAsync();
        using var read = connection.CreateCommand();
        read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=8;";
        var oldPayload = Assert.IsType<byte[]>(read.ExecuteScalar());
        await custody.ReserveAsync(JournalRequest(0x62), default);
        using var write = connection.CreateCommand();
        write.CommandText = "UPDATE protected_lkg_root SET revision=1,payload=$old WHERE root_kind=8;";
        write.Parameters.AddWithValue("$old", oldPayload);
        Assert.Equal(1, write.ExecuteNonQuery());
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await custody.FindAsync(Bytes(32, 0x61), default));
        await Assert.ThrowsAsync<CryptographicException>(() =>
            fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync());
        Assert.Equal(0, fixture.ProofRequests);
    }

    [Fact]
    public async Task Did2ClaimCustody_RequestOnlyAndMalformedSnapshotsRejectWithoutRepair()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        await custody.ReserveAsync(JournalRequest(0x61), default);
        var original = await fixture.ReadClaimSnapshotAsync();
        var oldGeneration = original.ToArray(); oldGeneration[0] = 2;
        var badFlag = original.ToArray(); badFlag[1] = 2;
        var emptyCount = original.ToArray(); emptyCount.AsSpan(2, 4).Clear();
        var hugeCount = original.ToArray(); hugeCount.AsSpan(2, 4).Fill(0xff);
        var wrongLength = original.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(wrongLength.AsSpan(444), 1);
        var truncatedResult = original.ToArray(); BinaryPrimitives.WriteUInt32BigEndian(truncatedResult.AsSpan(444), 4096);
        byte[][] hostile = [oldGeneration, badFlag, emptyCount, hugeCount,
            wrongLength, truncatedResult, original[..^1], [.. original, 0]];
        foreach (var payload in hostile)
        {
            await fixture.ReplaceClaimSnapshotForParserTestAsync(payload);
            await Assert.ThrowsAsync<InvalidDataException>(() => fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync());
            Assert.Equal(payload, await fixture.ReadClaimSnapshotAsync());
        }
        await fixture.ReplaceClaimSnapshotForParserTestAsync(original);
        Assert.Equal(JournalRequest(0x61), (await custody.FindAsync(Bytes(32, 0x61), default))!.Value.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimTransport_VerifiesBothSignaturesAndReusesExactRequest()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        foreach (var replay in new[] { false, true })
        {
            var (request, authority, publication) = await fixture.CreateClaimAsync(replay ? (byte)0x84 : (byte)0x83);
            var exact = fixture.AuthorClaimResult(request, authority, publication, replay);
            var onion = new ClaimOnion(authority, exact);
            onion.BeforeSend = async () => Assert.Equal(request.CanonicalBytes.ToArray(),
                (await custody.FindAsync(request.Field(2), default))!.Value.ToArray());
            var transport = new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody);
            var verified = await transport.ClaimExactAsync(request.CanonicalBytes);
            Assert.Equal(request.CanonicalBytes.ToArray(), verified.ExactRequest.ToArray());
            Assert.Equal(exact, verified.ExactResult.ToArray());
            Assert.Equal(authority.Placement.RankedReplicaNodeIds[0].ToArray(), onion.Exit);
            Assert.Equal(1, onion.Calls);
            Assert.Equal(request.CanonicalBytes.ToArray(), onion.Request);
            Assert.Equal(exact, (await custody.FindResultAsync(request.Field(2), default))!.Value.ToArray());

            var reopened = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
            // No second claim selection or response re-encoding on owner restart.
            var retryOnion = new ClaimOnion(authority, []);
            var recovered = await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), retryOnion, reopened)
                .ClaimExactAsync(request.CanonicalBytes);
            Assert.Equal(exact, recovered.ExactResult.ToArray());
            Assert.Equal(0, retryOnion.Calls);
            var copy = (await reopened.FindResultAsync(request.Field(2), default))!.Value.ToArray();
            copy[^1] ^= 1;
            Assert.Equal(exact, (await reopened.FindResultAsync(request.Field(2), default))!.Value.ToArray());
            var other = await fixture.Source().GetCurrentForPreKeyClaimAsync(Fixture.Network, Bytes(32, 0x85));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(other), retryOnion, reopened)
                    .ClaimExactAsync(request.CanonicalBytes));
            Assert.Equal(0, retryOnion.Calls); // Retention does not bypass current placement.
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimCustody_ExactResultCasRequiresReservationAndRejectsChangedWireAfterRestart()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var (request, authority, publication) = await fixture.CreateClaimAsync();
        var exact = fixture.AuthorClaimResult(request, authority, publication, false);
        var verified = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request,
            DeepIdV2PreKeyClaimResultCodec.Decode(exact, request.CanonicalBytes.Span), authority.Placement);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await custody.RecordVerifiedResultAsync(verified, default));
        await custody.ReserveAsync(request.CanonicalBytes, default);
        Assert.Null(await custody.FindResultAsync(request.Field(2), default));
        var reservedOnly = await fixture.ReadClaimSnapshotAsync();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await custody.RecordVerifiedResultAsync(verified, cancelled.Token));
        Assert.Null(await custody.FindResultAsync(request.Field(2), default));
        var retained = await Task.WhenAll(custody.RecordVerifiedResultAsync(verified, default).AsTask(),
            custody.RecordVerifiedResultAsync(verified, default).AsTask());
        Assert.All(retained, value => Assert.Equal(exact, value.ToArray()));
        var reopened = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
        Assert.Equal(exact, (await reopened.FindResultAsync(request.Field(2), default))!.Value.ToArray());
        await using (var sql = await fixture.OpenSqlAsync())
        {
            using var read = sql.CreateCommand();
            read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=8;";
            var winner = Assert.IsType<byte[]>(read.ExecuteScalar());
            using var write = sql.CreateCommand();
            write.CommandText = "UPDATE protected_lkg_root SET revision=$revision,payload=$payload WHERE root_kind=8;";
            write.Parameters.AddWithValue("$revision", 1);
            write.Parameters.AddWithValue("$payload", reservedOnly);
            Assert.Equal(1, write.ExecuteNonQuery());
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync());
            write.Parameters["$revision"].Value = 2;
            write.Parameters["$payload"].Value = winner;
            Assert.Equal(1, write.ExecuteNonQuery());
        }
        // Same signed tuple, different whole wire (Claimed -> Replay) is not
        // an exact local result replay and cannot silently replace the winner.
        var changed = fixture.AuthorClaimResult(request, authority, publication, true);
        var changedVerified = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request,
            DeepIdV2PreKeyClaimResultCodec.Decode(changed, request.CanonicalBytes.Span), authority.Placement);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.RecordVerifiedResultAsync(changedVerified, default));
        var forked = await fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await forked.FindResultAsync(request.Field(2), default));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await forked.ReserveAsync(request.CanonicalBytes, default));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimTransport_ResultFloorInterruptionCannotReleaseSuccess()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var (request, authority, publication) = await fixture.CreateClaimAsync();
        var exact = fixture.AuthorClaimResult(request, authority, publication, false);
        var onion = new ClaimOnion(authority, exact) { AfterSend = fixture.FailAfterNextOnionMarker };
        await Assert.ThrowsAsync<IOException>(async () =>
            await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                .ClaimExactAsync(request.CanonicalBytes));
        Assert.Equal(1, onion.Calls);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenAccount().OpenOwnClaimRequestCustodyAsync());
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                .ClaimExactAsync(request.CanonicalBytes));
        Assert.Equal(1, onion.Calls);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimTransport_RefusalNeverMintsCapabilityOrAutomaticallyRetries()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var (request, authority, _) = await fixture.CreateClaimAsync();
        foreach (var (status, retry) in new[] {
            (Xpc1V2Status.PreKeysUnavailable, 0u),
            (Xpc1V2Status.Expired, 0u),
            (Xpc1V2Status.RateLimited, 7u),
            (Xpc1V2Status.OutcomeUnknown, 1u) })
        {
            var body = DeepIdV2PreKeyClaimResultCodec.Encode(request.CanonicalBytes.Span,
                status, status == Xpc1V2Status.OutcomeUnknown ? Xpc1V2MutationOutcome.OutcomeUnknown :
                Xpc1V2MutationOutcome.None, 1_100, retry, []);
            var onion = new ClaimOnion(authority, body);
            var error = await Assert.ThrowsAsync<DeepIdV2PreKeyClaimUnavailableException>(async () =>
                await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                    .ClaimExactAsync(request.CanonicalBytes));
            Assert.Equal(status, error.Status);
            Assert.Equal(retry, error.RetryAfterSeconds);
            Assert.Equal(1, onion.Calls);
            Assert.Null(await custody.FindResultAsync(request.Field(2), default));
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimTransport_RejectsSubstitutionBeforeGrant()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var (request, authority, publication) = await fixture.CreateClaimAsync();
        foreach (var fault in new[] { "signature", "request", "authority", "placement" })
        {
            var body = fixture.AuthorClaimResult(request, authority, publication, false,
                badSignature: fault == "signature");
            if (fault == "request")
            {
                var changed = DeepIdV2PreKeyClaimRequestCodec.Encode(Fixture.Network,
                    Bytes(32, 0x84), authority.Placement.ViewHash.Span, authority.Placement.PlacementHash.Span,
                    1_100, 1_120, publication.Manifest.Field(2).Span, request.Field(17).Span,
                    request.Field(18).Span, request.Field(19).Span, request.Field(21).Span);
                body = fixture.AuthorClaimResult(DeepIdV2PreKeyClaimRequestCodec.Decode(changed),
                    authority, publication, false);
            }
            ContactResolvePathAuthority? returned = fault == "authority" ? null : authority;
            if (fault == "placement") returned = await fixture.Source().GetCurrentForPreKeyClaimAsync(
                Fixture.Network, Bytes(32, 0x85));
            var onion = new ClaimOnion(returned, body);
            Func<Task> claim = async () =>
                await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                    .ClaimExactAsync(request.CanonicalBytes);
            if (fault is "signature" or "request")
                await Assert.ThrowsAsync<ApplicationCoreFormatException>(claim);
            else
                await Assert.ThrowsAsync<CryptographicException>(claim);
            Assert.Equal(1, onion.Calls);
            Assert.Null(await custody.FindResultAsync(request.Field(2), default));
        }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ClaimTransport_CancelledResponseAndMismatchedInitialPlacementCannotGrant()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnClaimRequestCustodyAsync();
        var (request, authority, _) = await fixture.CreateClaimAsync();
        var other = await fixture.Source().GetCurrentForPreKeyClaimAsync(Fixture.Network, Bytes(32, 0x85));
        var onion = new ClaimOnion(authority, []);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(other), onion, custody)
                .ClaimExactAsync(request.CanonicalBytes));
        Assert.Equal(0, onion.Calls);
        using var cancellation = new CancellationTokenSource();
        onion.AfterSend = cancellation.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                .ClaimExactAsync(request.CanonicalBytes, cancellation.Token));
        Assert.Equal(1, onion.Calls);
        fixture.FailAfterNextOnionMarker();
        var next = DeepIdV2PreKeyClaimRequestCodec.Encode(Fixture.Network,
            Bytes(32, 0x86), request.Field(3).Span, request.Field(4).Span,
            1_100, 1_120, request.Field(16).Span, request.Field(17).Span,
            request.Field(18).Span, request.Field(19).Span, request.Field(21).Span);
        await Assert.ThrowsAsync<IOException>(async () =>
            await new DeepIdV2PreKeyClaimTransport(new ClaimAuthority(authority), onion, custody)
                .ClaimExactAsync(next));
        Assert.Equal(1, onion.Calls); // No dispatch after a floor-before-SQL interruption.
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.Accounts.OpenOwnClaimRequestCustodyAsync());
    }

    private sealed class ClaimAuthority(ContactResolvePathAuthority authority) : IContactResolvePathAuthoritySource
    {
        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(Xiq1Request request,
            CancellationToken cancellationToken) => throw new NotSupportedException();
        public ValueTask<ContactResolvePathAuthority> GetCurrentAsync(ContactResolveCanonicalPathRequest request,
            CancellationToken cancellationToken) => ValueTask.FromResult(authority);
    }

    private sealed class IgnoringCancellationClaimOnion(CancellationTokenSource cancellation) : IExactContactResolveOnionTransport
    {
        internal int Calls { get; private set; }
        public ValueTask<ExactContactResolveOnionResponse> SendExactAsync(ContactResolveCanonicalPathRequest request,
            ReadOnlyMemory<byte> requiredExitReplicaId, CancellationToken ct = default)
        {
            Calls++; cancellation.Cancel();
            return new(new TaskCompletionSource<ExactContactResolveOnionResponse>(TaskCreationOptions.RunContinuationsAsynchronously).Task);
        }
    }

    private sealed class ClaimOnion(ContactResolvePathAuthority? authority, byte[] body) : IExactContactResolveOnionTransport
    {
        internal int Calls { get; private set; }
        internal byte[]? Request { get; private set; }
        internal byte[]? Exit { get; private set; }
        internal Action? AfterSend { get; set; }
        internal Func<Task>? BeforeSend { get; set; }
        public async ValueTask<ExactContactResolveOnionResponse> SendExactAsync(ContactResolveCanonicalPathRequest request,
            ReadOnlyMemory<byte> requiredExitReplicaId, CancellationToken cancellationToken = default)
        {
            if (BeforeSend is not null) await BeforeSend();
            Calls++;
            Request = request.ExactRequest.ToArray();
            Exit = requiredExitReplicaId.ToArray();
            AfterSend?.Invoke();
            return new ExactContactResolveOnionResponse(body, authority);
        }
    }

    [Fact]
    public async Task DurableHistory_ExactPredecessorCasAndRawProjectionCannotReplaceAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var initial = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var store = Assert.IsAssignableFrom<IDeepIdV2NetworkHistoryStore>(fixture.NetworkStore);
        var retained = (await store.ReadHistoryAsync(default))!;
        await fixture.AssertHistoryAnchorEnvelopeAsync(retained.ExactHistory);
        var altered = retained.ExactHistory.ToArray(); altered[^1] ^= 1;
        await Assert.ThrowsAsync<IOException>(async () =>
            await store.ApplyVerifiedHistoryAsync(new(retained.Snapshot, altered), initial, default));
        await Assert.ThrowsAsync<IOException>(async () => await store.ApplyVerifiedHistoryAsync(null, initial, default));
        store.RequireAccountScope((await fixture.Accounts.GetCurrentAsync())!.AccountId);
        Assert.Throws<CryptographicException>(() => store.RequireAccountScope(Bytes(32, 0xaa)));
        await fixture.AdvanceNetworkAsync();
        var next = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await Assert.ThrowsAsync<IOException>(async () => await store.ApplyVerifiedHistoryAsync(retained, next, default));
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.CompareExchangeAsync(
            2, new(3, initial.ProtectedLkg!, false), default));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DurableHistory_MissingOrCorruptIndependentAnchorCannotReopen(bool corrupt)
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await fixture.DamageHistoryAnchorAsync(corrupt);
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task DurableHistory_HostileEnvelopeRejectsWithoutRewrite()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var read = connection.CreateCommand();
        read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=7;";
        var original = Assert.IsType<byte[]>(read.ExecuteScalar());
        var unknownVersion = original.ToArray(); unknownVersion[5] = 3;
        var anchorAsFloor = original.ToArray(); anchorAsFloor[7] = 1;
        var wrongLength = original.ToArray(); wrongLength[67] ^= 1;
        byte[][] hostile = [unknownVersion, anchorAsFloor, wrongLength,
            original[..^1], [.. original, 0], new byte[68 + 16 + 225 + 2 * 65_535 + 1]];
        using var write = connection.CreateCommand();
        write.CommandText = "UPDATE protected_lkg_root SET payload=$payload WHERE root_kind=7;";
        var parameter = write.Parameters.Add("$payload", SqliteType.Blob);
        foreach (var payload in hostile)
        {
            parameter.Value = payload;
            Assert.Equal(1, write.ExecuteNonQuery());
            await Assert.ThrowsAsync<InvalidDataException>(async () => await fixture.NetworkStore.ReadAsync(default));
            Assert.Equal(payload, Assert.IsType<byte[]>(read.ExecuteScalar()));
        }
        parameter.Value = original;
        Assert.Equal(1, write.ExecuteNonQuery());
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task DurableHistory_RehashedSqlHistoryCannotForgeIndependentAnchor()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var read = connection.CreateCommand();
        read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=7;";
        var envelope = Assert.IsType<byte[]>(read.ExecuteScalar());
        envelope[^1] ^= 1;
        SHA256.HashData(envelope.AsSpan(68)).CopyTo(envelope, 32);
        using var write = connection.CreateCommand();
        write.CommandText = "UPDATE protected_lkg_root SET payload=$payload WHERE root_kind=7;";
        write.Parameters.AddWithValue("$payload", envelope);
        Assert.Equal(1, write.ExecuteNonQuery());
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task DurableHistory_ReopenedAccountAdvancesChangedTipWithExpiredHistoricalKeys()
    {
        await using var fixture = await Fixture.CreateAsync(expiringHistory: true);
        var genesis = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var store = Assert.IsAssignableFrom<IDeepIdV2NetworkHistoryStore>(fixture.NetworkStore);
        var retained = (await store.ReadHistoryAsync(default))!;
        Assert.Equal(0UL, retained.Snapshot.ProtectedLkg.ViewGeneration);
        Assert.Equal(OnionNetworkProtectedHistoryCodec.Encode(genesis), retained.ExactHistory.ToArray());
        await fixture.AdvanceNetworkAsync();
        fixture.ProofTime = 1_100; // Historical view expires at 1,090; no clock rollback.
        fixture.Sample = 200;
        var reopenedAccount = fixture.ReopenAccount();
        fixture.NetworkStore = await fixture.ReopenNetworkStoreAsync();
        var reopened = fixture.Source(reopenedAccount);
        var next = await reopened.VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(1UL, next.ProtectedLkg!.ViewGeneration);
        Assert.True(OnionNetworkProtectedHistoryCodec.BindsPredecessor(next, retained.ExactHistory));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        var exact = (await ((IDeepIdV2NetworkHistoryStore)fixture.NetworkStore).ReadHistoryAsync(default))!.ExactHistory;
        _ = await fixture.Source(reopenedAccount).VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        Assert.Equal(exact.ToArray(), (await ((IDeepIdV2NetworkHistoryStore)fixture.NetworkStore).ReadHistoryAsync(default))!.ExactHistory.ToArray());
        fixture.OmitHistoricalPolicy = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source(reopenedAccount).VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(2UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task DurableHistory_CrashAfterProjectionOrHistoryAnchorFailsClosed(int phase)
    {
        await using var fixture = await Fixture.CreateAsync();
        if (phase == 0) fixture.FailAfterNextNetworkMarker();
        else fixture.FailAfterNextHistoryAnchor();
        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Theory]
    [InlineData(3)]
    [InlineData(7)]
    public async Task DurableHistory_MissingSqlHalfRejectsWithoutRepair(int rootKind)
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        await using var connection = await fixture.OpenSqlAsync();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind=$kind;";
        command.Parameters.AddWithValue("$kind", rootKind);
        Assert.Equal(1, command.ExecuteNonQuery());
        await Assert.ThrowsAsync<InvalidDataException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.ReopenNetworkStoreAsync());
    }

    [Fact]
    public async Task ClaimPath_UsesFreshAccountProofAndV2OnlyCanonicalPlacement()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var placement = await source.GetCurrentForPreKeyClaimAsync(Fixture.Network, Fixture.Service);
        var wire = Claim(placement.Placement.ViewHash.Span, placement.Placement.PlacementHash.Span);
        var request = ContactResolveCanonicalPathRequest.Decode(wire);
        Assert.Equal(ContactServiceRequestKind.ClaimPreKey, request.RequestKind);
        Assert.Equal(Fixture.Service, request.ShardKey.ToArray());
        var current = await source.GetCurrentAsync(request, default);
        Assert.Equal(2, fixture.ProofRequests);
        Assert.True(current.Placement.Binds(ContactServiceRequestKind.ClaimPreKey, Fixture.Service));
        var onion = OnionTerminalPayloadVerifierV1.VerifyRequest(current.Network,
            OnionOperation.ContactResolve, wire);
        Assert.Equal(wire, onion.CanonicalBytes.ToArray());
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var paths = new ContactResolvePrivacyPathProvider(source, custody.Guards);
        var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve, request,
            current.Placement.RankedReplicaNodeIds[1], default);
        Assert.Equal(3, fixture.ProofRequests);
        Assert.Equal(wire, prepared.Attempt.Request.CanonicalBytes.ToArray());
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(custody.Entropy),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
        Assert.False(built.Frame.IsEmpty); // Real codec/entropy, not socket/device delivery.

        var old = wire.ToArray(); BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        Assert.Throws<ApplicationCoreFormatException>(() => ContactResolveCanonicalPathRequest.Decode(old));
        var wrong = Claim(placement.Placement.ViewHash.Span, Bytes(32, 0xee));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.GetCurrentAsync(ContactResolveCanonicalPathRequest.Decode(wrong), default));
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () => await source.GetCurrentAsync(request, default));

        static byte[] Claim(ReadOnlySpan<byte> view, ReadOnlySpan<byte> placementHash) =>
            DeepIdV2PreKeyClaimRequestCodec.Encode(Fixture.Network, Bytes(32, 0xb0), view,
                placementHash, 1_000, 1_200, Fixture.Service, Bytes(32, 0xb1),
                Bytes(32, 0xb2), Bytes(32, 0xb3), Bytes(32, 0xb4));
    }

    [Fact]
    public async Task FullSignedSuccessorHistory_CanMintRepeatedlyAndReopenWithoutReplayingGenesisAgainstTip()
    {
        await using var fixture = await Fixture.CreateAsync(withSuccessor: true);
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(1UL, network.ProtectedLkg!.ViewGeneration);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        _ = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        var reopened = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        Assert.Equal(XPointNetworkProtectedLkgCodec.Encode(network.ProtectedLkg),
            XPointNetworkProtectedLkgCodec.Encode(reopened.ProtectedLkg!));
        Assert.Equal(4, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.OmitHistoricalPolicy = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task InitialInventory_UsesRealCurrentClosureAndPreservesExactRetryAfterReopen()
    {
        // The approved whole ML-KEM asset is currently validated on Windows.
        // This fixture is native/SQL evidence, not physical-device evidence.
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var staged = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        Assert.Equal(1, fixture.ProofRequests);
        fixture.VerifyInventory(staged, (await source.VerifyForOwnPreKeyAuthoringAsync(
            fixture.Accounts, default)).Proof);
        var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
        Assert.Equal(32, publication.OneTimeMembers.Count);
        var inventoryExpires = BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span);
        Assert.True(inventoryExpires > 1_500); // Short-lived ADH1 is refreshed, not signed into pre-key lifetime.
        Assert.True(inventoryExpires <= DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span).ExpiresAtUnixSeconds);
        Assert.Equal(86_400UL, inventoryExpires - BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(14).Span));
        var service = DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span);
        var placement = await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2));
        Assert.Equal(placement.Placement.PlacementHash.ToArray(), publication.PlacementHash.ToArray());
        Assert.True(await fixture.Accounts.HasOwnStagedPreKeyInventoryAsync());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        await AssertRealOnionCustodyAsync(fixture, source, staged, publication, placement);
        fixture.RejectProof = true;
        var before = fixture.ProofRequests;
        var retry = await fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
        var reopened = fixture.ReopenAccount();
        var afterRestart = await reopened.EnsureOwnInitialPreKeyInventoryAsync(fixture.Source(reopened));
        Assert.Equal(staged.ExactXpp1.ToArray(), retry.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXpp1.ToArray(), afterRestart.ExactXpp1.ToArray());
        Assert.Equal(staged.ExactXps1.ToArray(), afterRestart.ExactXps1.ToArray());
        Assert.Equal(before, fixture.ProofRequests); // Stored retry is not fresh authority.
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, service.Field(2)));
        var custody = await reopened.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAnyAsync<IOException>(() => reopened.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(reopened), custody)); // Stored retry cannot dispatch without fresh proof.
    }

    [Fact]
    public async Task ExpiredProtectedInventoryRejectsLocallyBeforeOnionDispatchWithoutReplacingKeys()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await fixture.StageExpiredInventoryAsync(source);
        var exact = (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(source, custody));
        Assert.Equal(exact, (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray());
        Assert.Null(await fixture.Accounts.ReadOwnPreKeyCommitPairAsync());
        Assert.Null(await custody.Guards.ReadAsync(default)); // No path/entropy reservation or send.
    }

    [Fact]
    public async Task CompletedPublication_ReopenReauthenticatesExactPairWithoutOnionReservation()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var reopened = fixture.ReopenAccount();
        var custody = await reopened.OpenOwnOnionClientCustodyAsync();
        var before = fixture.ProofRequests;
        var actual = await reopened.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(reopened), custody);
        Assert.Equal(before + 1, fixture.ProofRequests); // Fresh proof, not stored-authority reuse.
        Assert.Equal(expected.ExactFirstXic1.ToArray(), actual.ExactFirstXic1.ToArray());
        Assert.Equal(expected.ExactSecondXic1.ToArray(), actual.ExactSecondXic1.ToArray());
        Assert.Null(await custody.Guards.ReadAsync(default)); // No request/path/entropy or network dispatch.
        var again = await reopened.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(reopened), custody);
        Assert.Equal(before + 2, fixture.ProofRequests);
        Assert.Equal(expected.ExactFirstXic1.ToArray(), again.ExactFirstXic1.ToArray());
        Assert.Null(await custody.Guards.ReadAsync(default));
    }

    [Fact]
    public async Task CompletedPublication_DoesNotSubstituteSavedPairForFreshProof()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() => fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_ExpiredInventoryRemainsExpiredDespiteValidStoredSignatures()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync(expiredInventory: true);
        var staged = (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(staged, (await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync())!.ExactXpp1.ToArray());
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_RejectsAlteredNetworkClosureDespiteValidStoredPair()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CompletedPublication_RejectsBadSignatureOrUnselectedReplicaWithoutRepublishing(
        bool badSignature, bool unselectedReplica)
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync(badSignature, unselectedReplica);
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    [Fact]
    public async Task CompletedPublication_RechecksFreshnessAfterSuspendedProtectedPairRead()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var injected = false;
        fixture.AfterNextCommitPairRead(() =>
        {
            // The 30-second nonce-response window is not the lifetime of an
            // already verified current-value capability. Advance past the
            // actual revocation-freshness TTL, not an assumed 40-second lease.
            fixture.Sample += AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds;
            injected = true;
        });
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.True(injected);
    }

    [Fact]
    public async Task CompletedPublication_RechecksCancellationAfterSuspendedProtectedPairRead()
    {
        if (!OperatingSystem.IsWindows()) return;
        await using var fixture = await Fixture.CreateAsync();
        var expected = await fixture.StageAndRecordPairAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        using var cancel = new CancellationTokenSource();
        fixture.AfterNextCommitPairRead(cancel.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Accounts.PublishOwnStagedPreKeyInventoryAsync(fixture.Source(), custody, cancel.Token));
        Assert.Null(await custody.Guards.ReadAsync(default));
        Assert.Equal(expected.ExactFirstXic1.ToArray(),
            (await fixture.Accounts.ReadOwnPreKeyCommitPairAsync())!.ExactFirstXic1.ToArray());
    }

    private static async Task AssertRealOnionCustodyAsync(Fixture fixture,
        DeepIdV2ContactPathAuthoritySource source, StagedDeepIdV2PreKeyPublication staged,
        ParsedXpp1V2 publication, ContactResolvePathAuthority authority)
    {
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        var fragments = DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(staged.ExactXpp1.Span,
            authority.Placement.ViewHash.Span, staged.ExactDid2.Span, staged.ExactDca1.Span, staged.ExactXps1.Span);
        var request = ContactResolveCanonicalPathRequest.FromDid2BoundedPublication(
            DeepIdV2BoundedPreKeyPublicationCodec.Decode(fragments[0]), publication.Manifest.Field(2).Span,
            Math.Min(BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span),
                authority.Placement.ValidUntilUnixSeconds));
        var paths = new ContactResolvePrivacyPathProvider(source, custody.Guards);
        var ledger = new CapturingEntropyLedger(custody.Entropy);
        var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(ledger),
            new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
        // Exercise both rotating marker slots beyond their initial insert.
        // Two frames alone missed the third-write immutable-slot defect.
        foreach (var exit in authority.Placement.RankedReplicaNodeIds.Concat(authority.Placement.RankedReplicaNodeIds))
        {
            var prepared = await paths.PrepareExactAsync(OnionOperation.ContactResolve, request, exit, default);
            var entry = OnionEntryTransportFactory.Create(prepared.Attempt.Path);
            entry.EnsureCurrent();
            using var built = await codec.BuildAsync(prepared.Attempt.Path, prepared.Attempt.Request, default);
            Assert.False(built.Frame.IsEmpty);
            Assert.NotNull(ledger.LastBatch);
            Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
                await custody.Entropy.CommitAsync(ledger.LastBatch!, default));
        }
        var reopened = await fixture.ReopenAccount().OpenOwnOnionClientCustodyAsync();
        Assert.Equal(OnionEntropyCommitOutcome.Duplicate,
            await reopened.Entropy.CommitAsync(ledger.LastBatch!, default));
        Assert.Equal(EntryGuardStateCodec.Encode((await custody.Guards.ReadAsync(default))!),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        // A frame was sealed locally; no network send, XIC1 or device claim.
    }

    private sealed class CapturingEntropyLedger(IOnionEntropyUniquenessLedger inner) : IOnionEntropyUniquenessLedger
    {
        internal OnionEntropyCommitmentBatch? LastBatch { get; private set; }
        public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(OnionEntropyCommitmentBatch batch, CancellationToken ct)
        {
            var result = await inner.CommitAsync(batch, ct);
            if (result == OnionEntropyCommitOutcome.Committed) LastBatch = batch;
            return result;
        }
    }

    private sealed class RejectClientReceiveVault : IOnionKeyAgreementVault
    {
        public ValueTask<byte[]> DeriveX25519SharedSecretAsync(OnionKeyHandle keyHandle,
            ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct) =>
            throw new InvalidOperationException("The client must never ask for an XNode receive key.");
    }

    [Fact]
    public async Task InitialInventory_MissingProofCancellationAndWrongOwnerDoNotStage()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            fixture.ReopenAccount().EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(0, fixture.ProofRequests);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() =>
            fixture.Accounts.EnsureOwnInitialPreKeyInventoryAsync(source));
        Assert.Equal(1, fixture.ProofRequests);
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task OwnAuthoringAuthority_RejectsExpiredClockAndChangedNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var authoring = await source.VerifyForOwnPreKeyAuthoringAsync(fixture.Accounts, default);
        fixture.Sample = authoring.Proof.FreshnessDeadlineMonotonicSeconds;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        fixture.Sample = 100;
        var floor = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(floor.Revision,
            new(floor.Revision + 1, floor.ProtectedLkg, true), default);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.RecheckOwnPreKeyAuthoringAsync(authoring, default));
        Assert.Null(await fixture.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task RealDid2AccountAndSignedNetwork_VerifyThenMintRechecksProofAndRehydratesExactFloor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        var network = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        network.EnsureCurrent();
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        Assert.Equal(1, fixture.ProofRequests);
        var first = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.True(first.Placement.Binds(ContactServiceRequestKind.PublishPreKeyInventory, Fixture.Service));
        Assert.NotNull(await fixture.NetworkStore.ReadAsync(default));
        var second = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), second.Placement.PlacementHash.ToArray());
        Assert.Equal(3, fixture.ProofRequests);
        var reopened = fixture.Source();
        var restoredNetwork = await reopened.VerifyCurrentNetworkAsync(Fixture.Network);
        restoredNetwork.EnsureCurrent();
        Assert.Equal(XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(network.ProtectedLkg)),
            XPointNetworkProtectedLkgCodec.Encode(
                Assert.IsType<XPointNetworkProtectedLkg>(restoredNetwork.ProtectedLkg)));
        var restored = await reopened.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(first.Placement.PlacementHash.ToArray(), restored.Placement.PlacementHash.ToArray());
        Assert.Equal(5, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task MissingFreshProof_CannotReusePreviouslyMintedNetworkAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        _ = await source.VerifyCurrentNetworkAsync(Fixture.Network);
        fixture.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(2, fixture.ProofRequests);
        Assert.Equal(1UL, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
        fixture.RejectProof = false;
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        Assert.Equal(3, fixture.ProofRequests);
    }

    [Fact]
    public async Task AlteredSignedNodeClosure_DoesNotInitializeNetworkCustody()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.AlterNode = true;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Null(await fixture.NetworkStore.ReadAsync(default));
    }

    [Fact]
    public async Task UnrelatedNetworkAndProtectedFork_RejectBeforeFetchingAnyProof()
    {
        await using var fixture = await Fixture.CreateAsync();
        var source = fixture.Source();
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Bytes(16, 0x22), Fixture.Service));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.VerifyCurrentNetworkAsync(Bytes(16, 0x22)));
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, new byte[32]));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network, cancelled.Token));
        Assert.Equal(0, fixture.ProofRequests);
        _ = await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var current = (await fixture.NetworkStore.ReadAsync(default))!;
        await fixture.NetworkStore.CompareExchangeAsync(current.Revision,
            new(current.Revision + 1, current.ProtectedLkg, true), default);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await source.VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal(1, fixture.ProofRequests);
    }

    [Fact]
    public void RawNetworkClosureOwnsCopiesAndRejectsOversizedListsBeforeCopying()
    {
        var value = new byte[] { 1 };
        ReadOnlyMemory<byte>[] one = [value];
        var closure = new DeepIdV2NetworkClosureArtifacts(one, one, one, one, one, one, one, one);
        value[0] = 2;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        Assert.Equal((byte)1, closure.ExactOrderedPma2Chain[0].Span[0]);
        Assert.True(MemoryMarshal.TryGetArray(closure.ExactOrderedPma2Chain[0], out var mailboxCopy));
        mailboxCopy.Array![mailboxCopy.Offset] = 9;
        Assert.Equal((byte)1, closure.ExactOrderedPma2Chain[0].Span[0]);
        Assert.True(MemoryMarshal.TryGetArray(closure.ExactOrderedXnv1Chain[0], out var exported));
        exported.Array![exported.Offset] = 3;
        Assert.Equal((byte)1, closure.ExactOrderedXnv1Chain[0].Span[0]);
        var tooMany = Enumerable.Repeat<ReadOnlyMemory<byte>>(value, 4097).ToArray();
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, tooMany, tooMany, one, one, one));
        Assert.Throws<ArgumentException>(() =>
            new DeepIdV2NetworkClosureArtifacts(one, one, one, [value, value], one, one, one, one));
    }

    [Fact]
    public void AccountPublisherRequiresDid2OnlyAuthoritySource()
    {
        var method = typeof(DeepIdV2AccountService).GetMethod(
            nameof(DeepIdV2AccountService.PublishOwnStagedPreKeyInventoryAsync))!;
        Assert.Equal(typeof(DeepIdV2ContactPathAuthoritySource), method.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(DeepIdV2OnionClientCustody), method.GetParameters()[1].ParameterType);
        Assert.Empty(typeof(DeepIdV2OnionClientCustody).GetConstructors());
    }

    [Fact]
    public async Task OnionGuardCustody_PreservesCasAfterReopenAndRejectsSqlRollbackAndForeignOwner()
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        Assert.Null(await custody.Guards.ReadAsync(default));
        var first = Guard(1);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        Assert.Equal(EntryGuardStoreWriteDisposition.Conflict,
            (await custody.Guards.CompareExchangeAsync(null, first, default)).Disposition);
        var reopenedAccount = fixture.ReopenAccount();
        var reopened = await reopenedAccount.OpenOwnOnionClientCustodyAsync();
        Assert.Equal(EntryGuardStateCodec.Encode(first),
            EntryGuardStateCodec.Encode((await reopened.Guards.ReadAsync(default))!));
        await Assert.ThrowsAsync<ArgumentException>(() => reopenedAccount.PublishOwnStagedPreKeyInventoryAsync(
            fixture.Source(reopenedAccount), custody));
        Assert.Equal(0, fixture.ProofRequests);
        var second = Guard(2);
        Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
            (await reopened.Guards.CompareExchangeAsync(1, second, default)).Disposition);
        for (ulong revision = 3; revision <= 8; revision++)
            Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
                (await reopened.Guards.CompareExchangeAsync(revision - 1, Guard(revision), default)).Disposition);
        await using (var connection = await fixture.OpenSqlAsync())
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE protected_lkg_root SET revision=1,payload=$payload WHERE root_kind=4;";
            command.Parameters.AddWithValue("$payload", EntryGuardStateCodec.Encode(first));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => reopenedAccount.OpenOwnOnionClientCustodyAsync());
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await custody.Guards.ReadAsync(default));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(5)]
    public async Task OnionGuardMarkerBeforeSqlCrash_RejectsReadAndReopenWithoutEmittingAuthority(int committed)
    {
        await using var fixture = await Fixture.CreateAsync();
        var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
        for (ulong revision = 1; revision <= (ulong)committed; revision++)
            Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
                (await custody.Guards.CompareExchangeAsync(revision == 1 ? null : revision - 1, Guard(revision), default)).Disposition);
        fixture.FailAfterNextOnionMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await custody.Guards.CompareExchangeAsync(committed == 0 ? null : (ulong)committed, Guard((ulong)committed + 1), default));
        await Assert.ThrowsAsync<CryptographicException>(async () => await custody.Guards.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.Accounts.OpenOwnOnionClientCustodyAsync());
        Assert.Equal(0, fixture.ProofRequests);
    }

    private static EntryGuardState Guard(ulong revision) => new(revision, Fixture.Network,
        1, Bytes(32, 0x21), Bytes(32, 0x22), Bytes(32, 0x23), [Bytes(32, 0x23)]);

    [Fact]
    public async Task AccountNetworkFloor_RejectsSqlRollbackCorruptionDeletionAndRepin()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service);
        var initial = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(XPointNetworkStoreWriteDisposition.Conflict,
            (await fixture.NetworkStore.CompareExchangeAsync(null, initial, default)).Disposition);
        await using var connection = await fixture.OpenSqlAsync();
        byte[] Payload(int kind = 3)
        {
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=$kind;";
            read.Parameters.AddWithValue("$kind", kind);
            return Assert.IsType<byte[]>(read.ExecuteScalar());
        }
        void Replace(long revision, byte[] payload, int kind = 3)
        {
            using var write = connection.CreateCommand();
            write.CommandText = "UPDATE protected_lkg_root SET revision=$revision,payload=$payload WHERE root_kind=$kind;";
            write.Parameters.AddWithValue("$kind", kind);
            write.Parameters.AddWithValue("$revision", revision);
            write.Parameters.AddWithValue("$payload", payload);
            Assert.Equal(1, write.ExecuteNonQuery());
        }
        var oldPayload = Payload();
        var oldHistory = Payload(7);
        var latched = new XPointNetworkStateSnapshot(2, initial.ProtectedLkg, true);
        Assert.Equal(XPointNetworkStoreWriteDisposition.Applied,
            (await fixture.NetworkStore.CompareExchangeAsync(1, latched, default)).Disposition);
        var currentPayload = Payload();
        var currentHistory = Payload(7);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await fixture.NetworkStore.CompareExchangeAsync(2, new(3, initial.ProtectedLkg, false), default));
        var reopened = await fixture.ReopenNetworkStoreAsync();
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        Replace(1, oldPayload);
        Replace(1, oldHistory, 7); // Restore the whole SQL snapshot, not a split row.
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        Replace(2, currentPayload);
        Replace(2, currentHistory, 7);
        Assert.True((await reopened.ReadAsync(default))!.ForkLatched);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync(changedPin: true));
        Replace(2, [1]);
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
        using (var delete = connection.CreateCommand())
        {
            delete.CommandText = "DELETE FROM protected_lkg_root WHERE root_kind IN (3,7);";
            Assert.Equal(2, delete.ExecuteNonQuery());
        }
        await Assert.ThrowsAsync<CryptographicException>(async () => await reopened.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
        await connection.DisposeAsync();
        await fixture.ResetAccountAsync();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await reopened.ReadAsync(default));
    }

    [Fact]
    public async Task NetworkMarkerCommittedBeforeSqlCrash_RejectsEmptyFloorAndReopen()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.FailAfterNextNetworkMarker();
        await Assert.ThrowsAsync<IOException>(async () =>
            await fixture.Source().GetCurrentForPublicationAsync(Fixture.Network, Fixture.Service));
        await Assert.ThrowsAsync<CryptographicException>(async () => await fixture.NetworkStore.ReadAsync(default));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReopenNetworkStoreAsync());
    }

    /// <summary>Real account-owned SQLCipher DID2 state and native ML-DSA;
    /// signed public network ceremony and nonce-bound HTTP proof bytes. The
    /// HTTP/secure-storage adapters are in-memory; directory and network
    /// floors use real SQLCipher. This is not TLS, ONION or device evidence.</summary>
    private sealed partial class Fixture : HttpMessageHandler, IAsyncDisposable,
        IOnionMonotonicClock
    {
        internal static readonly byte[] Network = Bytes(16, 0x11);
        internal static readonly byte[] Service = Bytes(32, 0x35);
        private static readonly byte[] Boot = Bytes(16, 0xf3);
        private readonly string directory = Path.Combine(Path.GetTempPath(),
            "deep-did2-path-" + Guid.NewGuid().ToString("N"));
        private readonly InMemoryDeepSecureStorage innerStorage = new();
        private readonly InMemoryDeepSecureStorage peerStorage = new();
        private DeepIdV2AccountService? peerAccounts;
        private VerifiedAdc1V2? peerCheckpoint;
        private IXPointNetworkStateStore? peerNetworkStore;
        private DeepIdV2DirectoryProofClient? peerProofs;
        private Func<ReadOnlyMemory<byte>, Task<DeepIdV2InitialContactSessionCommit>>? receiverCompletion;
        private Func<DeepIdV2InitialSessionCommit, DeepIdV2InitialContactSessionCommit, ParsedDmc2, ParsedDmc2,
            Task<(OwnedInitialMessagingSeed Sender, OwnedInitialMessagingSeed Receiver)>>? messagingSeeds;
        private Func<ParsedDmc2, ParsedDmc2, Task<Did2MessagingSessionScope>>? ensureSenderMessaging;
        private Func<ReadOnlyMemory<byte>, Task<Did2MessagingSessionScope>>? ensureReceiverMessaging;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, ParsedDmc2, Task<OwnedDid2MessagingPersistedEvent>>? sendOwnedMessage;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, Task<OwnedDid2MessagingPersistedEvent>>? receiveOwnedMessage;
        private Func<Did2MessagingSessionScope, Task<IReadOnlyList<DirectMessageCreateSnapshot>>>? listOwnedMessages;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, Task<OwnedDid2ContactAcceptDraft>>? prepareOwnedContactAccept;
        private Func<Did2MessagingSessionScope, Task<Did2ContactAcceptanceState>>? readOwnedContactState;
        private Func<Did2MessagingSessionScope, Task<DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority>>? refreshOwnedMessaging;
        internal Task<DeepIdV2ContactPathAuthoritySource.MessagingEndpointAuthority> RefreshOwnedMessaging(Did2MessagingSessionScope scope) =>
            (refreshOwnedMessaging ?? throw new InvalidOperationException("Owned endpoint refresh is absent."))(scope);
        internal Task DropPeerBootstrap(Did2MessagingSessionScope scope) =>
            (scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage).DeleteBatchAsync([ProtectedDid2MessagingPeerBootstrap.Slot(scope)]);
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, string, Task<DirectTextOutboxEntry>>? prepareOwnedText;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, Task<DirectTextOutboxEntry>>? prepareOwnedAttachmentOffer;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, byte[], string, string, ulong, Task<OwnedAttachmentPreparation>>? prepareOwnedAsset;
        internal Task<OwnedAttachmentPreparation> PrepareOwnedAsset(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
            byte[] bytes, string filename, string mediaType, ulong expiry) =>
            (prepareOwnedAsset ?? throw new InvalidOperationException("Owned asset preparation is absent."))(scope, operation, bytes, filename, mediaType, expiry);
        internal Task<DirectTextOutboxEntry> PrepareOwnedAttachmentOffer(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> operation,
            ReadOnlyMemory<byte> assetOperation) =>
            (prepareOwnedAttachmentOffer ?? throw new InvalidOperationException("Owned offer preparation is absent."))(scope, operation, assetOperation);
        internal Task<DirectTextOutboxEntry> PrepareOwnedText(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> op, string text) =>
            (prepareOwnedText ?? throw new InvalidOperationException("Owned text command is absent."))(scope, op, text);
        internal Task<OwnedDid2ContactAcceptDraft> PrepareOwnedContactAccept(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> op) =>
            (prepareOwnedContactAccept ?? throw new InvalidOperationException("Owned acceptance command is absent."))(scope, op);
        internal Task<Did2ContactAcceptanceState> ReadOwnedContactState(Did2MessagingSessionScope scope) =>
            (readOwnedContactState ?? throw new InvalidOperationException("Owned contact state read is absent."))(scope);
        internal Task<IReadOnlyList<DirectMessageCreateSnapshot>> ListOwnedMessages(Did2MessagingSessionScope scope) =>
            (listOwnedMessages ?? throw new InvalidOperationException("Owned inbox read closure is absent."))(scope);
        internal Task<OwnedDid2MessagingPersistedEvent> SendOwnedMessage(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> op, ParsedDmc2 message) =>
            (sendOwnedMessage ?? throw new InvalidOperationException("Owned send closure is absent."))(scope, op, message);
        internal Task<OwnedDid2MessagingPersistedEvent> ReceiveOwnedMessage(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> envelope) =>
            (receiveOwnedMessage ?? throw new InvalidOperationException("Owned receive closure is absent."))(scope, envelope);
        internal Task<Did2MessagingSessionScope> EnsureSenderMessaging(ParsedDmc2 initial, ParsedDmc2 hello) =>
            (ensureSenderMessaging ?? throw new InvalidOperationException("Owner messaging closure is absent."))(initial, hello);
        internal Task<Did2MessagingSessionScope> EnsureReceiverMessaging(ReadOnlyMemory<byte> exact) =>
            (ensureReceiverMessaging ?? throw new InvalidOperationException("Owner messaging closure is absent."))(exact);
        internal Task<Did2MessagingFloor> ReadMessagingFloor(Did2MessagingSessionScope scope) =>
            new Did2MessagingProtectedCheckpoint(scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage, scope).ReadAsync(default);

        internal Task<(OwnedInitialMessagingSeed Sender, OwnedInitialMessagingSeed Receiver)> CreateMessagingSeeds(
            DeepIdV2InitialSessionCommit sent, DeepIdV2InitialContactSessionCommit received, ParsedDmc2 init, ParsedDmc2 hello) =>
            (messagingSeeds ?? throw new InvalidOperationException("Messaging seed closure has not been prepared."))(sent, received, init, hello);
        private readonly NetworkMarkerFaultStorage storage;
        private readonly Signer root = new(0x20);
        private readonly Signer[] witnesses = [new(0x30), new(0x31), new(0x32)];
        private readonly Signer[] nodes = [new(0x70), new(0x71), new(0x72)];
        private readonly IDeepMlDsa65VerifierLease pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
        private VerifiedXPointNetworkBootstrap bootstrap = null!;
        private AuthoredXPointNetworkOperationalGenesis operational = null!;
        private AuthoredXPointNetworkOperationalSuccessor? successor;
        private OwnedPublicationReplica? nativeHelloPublicationReplica;
        private AuthoredAccountDirectoryHeadMutation genesis = null!;
        private AuthoredAccountDirectoryHeadMutation head = null!;
        private VerifiedAdc1V2 checkpoint = null!;
        private DeepIdV2AccountService accounts = null!;
        private DeepIdV2DirectoryProofClient proofs = null!;
        private HttpClient http = null!;
        private HttpDeepIdV2NetworkClosureArtifactSource closure = null!;
        internal IXPointNetworkStateStore NetworkStore { get; set; } = null!;
        internal int ProofRequests { get; private set; }
        internal bool RejectProof { get; set; }
        internal bool AlterNode { get; set; }
        internal bool OmitHistoricalPolicy { get; set; }
        internal ulong Sample { get; set; } = 100;
        internal ulong ProofTime { get; set; } = 1_100;
        internal DeepIdV2AccountService Accounts => accounts;
        internal DeepIdV2AccountService ReopenAccount() => new(storage, directory, Network, 1,
            new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
            DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
        internal Task<DeepIdV2InitialContactSessionCommit> CompleteReceiver(ReadOnlyMemory<byte> exact) =>
            (receiverCompletion ?? throw new InvalidOperationException("Receiver closure has not been prepared."))(exact);
        internal async Task<Did2InitialKeyRetirementReceipt> RetireInitialKeys(Did2InitialStateTransfer transfer)
        {
            var sender = transfer.Scope.IsInitiator;
            var preclaimBefore = sender ? await ReadPreClaimSnapshotAsync() : null;
            byte[]? receiverState = null;
            if (!sender)
            {
                await using var observer = await OpenPeerPreKeySqlAsync();
                using var read = observer.CreateCommand(); read.CommandText = "SELECT exact_state FROM receiver_initial_state WHERE ordinal=1;";
                receiverState = (byte[])read.ExecuteScalar()!;
            }
            var stateDirectory = sender ? directory : Path.Combine(directory, "peer");
            var secure = sender ? (IDeepSecureStorage)storage : peerStorage;
            ProtectedDeepIdV2AccountOwner ReopenOwner() => new(secure,
                new DeepIdV2AccountFileLease(Path.Combine(stateDirectory, "deep-store-v2-account.lock")),
                Path.Combine(stateDirectory, "deep-store-v2-account.dsv2"), Network, 1);
            // Resume after every meaningful deletion crash boundary, including
            // protected stable already written. No key is restored for retry.
            var points = sender ? new[] { InitialKeyRetirementFailpoint.AfterPending, InitialKeyRetirementFailpoint.AfterPreclaim,
                InitialKeyRetirementFailpoint.AfterSourceDelete, InitialKeyRetirementFailpoint.AfterStable } :
                new[] { InitialKeyRetirementFailpoint.AfterPending, InitialKeyRetirementFailpoint.AfterSourceDelete, InitialKeyRetirementFailpoint.AfterStable };
            foreach (var point in points)
            {
                var hit = false;
                using (InitialKeyRetirementTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected initial retirement stop."); } }))
                    await Assert.ThrowsAsync<IOException>(() => ReopenOwner().RetireInitialMessagingKeysAsync(1_000, pq, transfer, default));
                Assert.True(hit);
            }
            var receipt = await ReopenOwner().RetireInitialMessagingKeysAsync(1_000, pq, transfer, default);
            Assert.Equal(receipt.ExactEntry.ToArray(), (await ReopenOwner().RetireInitialMessagingKeysAsync(1_000, pq, transfer, default)).ExactEntry.ToArray());
            if (sender)
            {
                using var journal = await innerStorage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot);
                var decoded = journal!.Use(value => ProtectedDph2PreClaimJournal.Decode(value, Network, transfer.Scope.LocalAccount, transfer.Scope.Instance));
                Assert.Empty(decoded.Claims); Assert.Single(decoded.Retired);
                var tombstone = journal.Use(static value => value.ToArray());
                try
                {
                    Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDph2PreClaimJournal.Slot, tombstone, preclaimBefore!));
                    await Assert.ThrowsAsync<CryptographicException>(() => ReopenAccount().GetCurrentAsync());
                }
                finally
                {
                    // Test fault-injection cleanup, NOT runtime recovery/repair.
                    Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDph2PreClaimJournal.Slot, preclaimBefore!, tombstone));
                    CryptographicOperations.ZeroMemory(tombstone); CryptographicOperations.ZeroMemory(preclaimBefore!);
                }
            }
            else
            {
                try
                {
                    await using (var observer = await OpenPeerPreKeySqlAsync())
                    {
                        using var insert = observer.CreateCommand(); insert.CommandText = "INSERT INTO receiver_initial_state VALUES(1,$state);";
                        insert.Parameters.AddWithValue("$state", receiverState!); Assert.Equal(1, insert.ExecuteNonQuery());
                    }
                    await Assert.ThrowsAsync<CryptographicException>(() => AccountsForPeer().HasOwnStagedPreKeyInventoryAsync());
                }
                finally
                {
                    await using var observer = await OpenPeerPreKeySqlAsync();
                    using var deletion = observer.CreateCommand(); deletion.CommandText = "DELETE FROM receiver_initial_state WHERE ordinal=1;";
                    Assert.Equal(1, deletion.ExecuteNonQuery()); CryptographicOperations.ZeroMemory(receiverState!);
                }
            }
            return receipt;
        }
        internal DeepIdV2AccountService AccountsForPeer() => peerAccounts!;
        internal async Task<(OwnedDid2MessagingStorage Storage, Func<Task<OwnedDid2MessagingStorage>> Reopen)>
            RegisterMessagingStorage(OwnedInitialMessagingSeed seed)
        {
            var sender = seed.IsInitiator;
            var secure = sender ? (IDeepSecureStorage)storage : peerStorage;
            var stateDirectory = sender ? directory : Path.Combine(directory, "peer");
            var path = Path.Combine(stateDirectory, "deep-store-v2-account.dsv2");
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(stateDirectory, "deep-store-v2-account.lock"));
            var account = seed.LocalDirectory.DeepAccountId.ToArray();
            Did2MessagingSessionScope scope;
            using (var held = await accountLease.AcquireAsync(default))
            {
                var instance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(secure, Network, account, default);
                Assert.True(instance.AsSpan().SequenceEqual(seed.Instance));
                scope = await new ProtectedDid2MessagingSessionCatalog(secure, Network, account, instance).RegisterAsync(seed, default);
                var again = await new ProtectedDid2MessagingSessionCatalog(secure, Network, account, instance).RegisterAsync(seed, default);
                Assert.True(scope.Exact.SequenceEqual(again.Exact));
            }
            async Task<OwnedDid2MessagingStorage> Open()
            {
                var owner = new ProtectedDeepIdV2AccountOwner(secure, accountLease, path, Network, 1);
                using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException("Fixture account is absent.");
                using var held = await accountLease.AcquireAsync(default);
                return await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(secure, path, current, scope, default);
            }
            return (await Open(), Open);
        }
        internal Task<DeepIdV2InitialContactSessionCommit?> FindReceiver(ReadOnlyMemory<byte> exact, bool reopen = false) =>
            (reopen ? new DeepIdV2AccountService(peerStorage, Path.Combine(directory, "peer"), Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess)
                : peerAccounts!).FindOwnInitialContactSessionAsync(exact);

        internal void AfterNextCommitPairRead(Action action) => storage.AfterCommitPairRead = action;
        internal void AfterNextPreClaimCommit(Action action) => storage.AfterPreClaimCommit = action;
        internal void AfterNextRendezvousCommit(Action action) => storage.AfterRendezvousCommit = action;
        internal Task<VerifiedDeepIdV2ContactUpdateRendezvous> EnsureRendezvous(byte[] intent,
            DeepIdV2AccountService? owner = null)
        {
            owner ??= accounts;
            return owner.EnsureOwnContactRendezvousAsync(intent, Source(owner));
        }
        internal async Task<byte[]> ReadRendezvousSnapshot()
        {
            using var value = await innerStorage.ReadOwnedAsync(ProtectedContactRendezvousJournal.Slot);
            return value?.Use(bytes => bytes.ToArray()) ?? throw new InvalidDataException("Fixture snapshot absent.");
        }
        internal Task RemoveRendezvousSnapshot() => innerStorage.DeleteBatchAsync([ProtectedContactRendezvousJournal.Slot]);
        internal async Task<InitiatorDph2PreKeyClaim> BeginPreClaimAsync(byte[] intent,
            DeepIdV2AccountService? owner = null, CancellationToken cancellationToken = default)
        {
            owner ??= accounts;
            var authoring = await Source(owner).VerifyForOwnPreKeyAuthoringAsync(owner, cancellationToken);
            return await owner.BeginOwnDph2ClaimAsync(intent, proofs, authoring.Authority,
                authoring.Proof, Boot, Sample, new OnionTrustedTimeAuthority(this), 32, cancellationToken);
        }
        internal async Task<byte[]?> ReadPreClaimSnapshotOrNullAsync()
        {
            using var value = await innerStorage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot);
            return value?.Use(bytes => bytes.ToArray());
        }
        internal async Task<byte[]> ReadPreClaimSnapshotAsync() =>
            await ReadPreClaimSnapshotOrNullAsync() ?? throw new InvalidDataException("Fixture snapshot absent.");
        internal Task RemovePreClaimSnapshotAsync() => innerStorage.DeleteBatchAsync([ProtectedDph2PreClaimJournal.Slot]);

        internal async Task<(VerifiedDeepIdV2ContactUpdateRendezvous, VerifiedOnionNetworkContext)>
            AuthorRendezvous(int mode = 0)
        {
            var current = await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var retained = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(
                    checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            using var unrelated = mode == 1 ? new Deep.Protocol.Identity.OwnedGenesisDeviceSecrets() : null;
            var keyId = Bytes(32, 0xe1); var publicKey = ScalarMult.Base(Bytes(32, 0xe2));
            if (mode == 2) publicKey = checkpoint.Binding.Identity.ActiveDevices.Single().Certificate.DeviceX25519PublicKey.ToArray();
            if (mode == 8) { publicKey = new byte[32]; publicKey[0] = 1; }
            var proof = mode == 7 ? (await Source().VerifyForOwnPreKeyAuthoringAsync(accounts, default)).Proof : current.Proof;
            using var canceled = new CancellationTokenSource();
            var reads = 0;
            var clock = new CallbackRendezvousClock(() =>
            {
                var first = reads++ == 0;
                if (mode == 0) { keyId[0] ^= 1; publicKey[0] ^= 1; }
                if (mode == 6) canceled.Cancel();
                return new OnionMonotonicReading(mode == 4 && !first ? Bytes(16, 0xf4) : Boot,
                    mode == 3 && first ? Sample + 1 : mode == 5 && !first ? current.Proof.FreshnessDeadlineMonotonicSeconds : Sample);
            });
            var result = await DeepIdV2ContactUpdateRendezvousAuthor.AuthorGenesisAsync(proof,
                current.Network, unrelated ?? retained!, keyId, publicKey,
                current.Proof.TrustedLowerUnixSeconds, checked(current.Proof.TrustedUpperUnixSeconds + 10),
                new OnionTrustedTimeAuthority(clock), canceled.Token);
            return (result, current.Network);
        }

        private sealed class CallbackRendezvousClock(Func<OnionMonotonicReading> read) : IOnionMonotonicClock
        {
            public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(read());
            }
        }

        internal async Task<Func<DeepIdV2AccountService, Task<DeepIdV2InitialSessionCommit>>>
            PrepareNativeInitialCompletion(byte[] intent)
        {
            var source = Source(); var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var current = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), checkpoint.Binding, checkpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(current.Proof, authorization, Boot, Sample);
            using var secrets = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, Network,
                checkpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(
                checkpoint.Binding.Identity.ActiveDevices.Single(), default);
            using var owned = secrets!.ExportOwnedPersistenceCopy();
            var seed = new byte[32]; var agreement = new byte[32]; var device = new byte[32]; var handle = new byte[32];
            byte[]? privateKey = null;
            ParsedDcr1V2 resolver;
            try
            {
                owned.CopyTo(seed, agreement, device, handle);
                privateKey = PublicKeyAuth.GenerateKeyPair(seed).PrivateKey;
                resolver = NativeRecipientClosure(staged, privateKey);
            }
            finally
            {
                foreach (var secret in new[] { seed, agreement, device, handle, privateKey })
                    if (secret is not null) CryptographicOperations.ZeroMemory(secret);
            }
            using var started = await BeginPreClaimAsync(intent);
            var path = await source.GetCurrentForPreKeyClaimAsync(Network, publication.Manifest.Field(2));
            var issued = BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(14).Span);
            var request = DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
                Network, started.ClaimOperationId.Span, path.Placement.ViewHash.Span, path.Placement.PlacementHash.Span,
                issued, 1_120, publication.Manifest.Field(2).Span, resolver.Bundle.ObjectHash.Span,
                publication.Manifest.Field(6).Span[6..], publication.Manifest.Field(3).Span, started.SenderEphemeralCommitment.Span));
            var result = DeepIdV2PreKeyClaimResultCodec.Decode(AuthorClaimResult(request, path, publication, false), request.CanonicalBytes.Span);
            var time = new OnionTrustedTimeAuthority(this);
            var claim = await DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(request, result, path.Placement, recipient, resolver, time, default);
            var dmd = checkpoint.Directory.Record; var conversation = Bytes(32, 0xa4);
            var init = ApplicationCoreCodec.AuthorDmc2(Network, Bytes(32, 0xa5), conversation, dmd.DeepAccountId.Span,
                dmd.ActiveDevices[0].DeviceId.Span, 1, 1_100_000, 1_120_000, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateSessionInitPayload(Bytes(32, 0xa6), dmd,
                    SessionInitCapabilities.TextCore | SessionInitCapabilities.DeviceControl));
            var first = ApplicationCoreCodec.AuthorDmc2(Network, Bytes(32, 0xa7), conversation, dmd.DeepAccountId.Span,
                dmd.ActiveDevices[0].DeviceId.Span, 2, 1_100_001, 0, Dmc2Flags.None, [],
                ApplicationCoreCodec.CreateMessageCreatePayload("native initial custody"));
            return account => account.CommitOwnDph2InitialSessionAsync(intent, publication.LastResortMember.CanonicalBytes,
                proofs, current.Authority, current.Proof, current.Proof, Boot, Sample, claim, time,
                init.CanonicalBytes, first.CanonicalBytes, 32);
        }

        internal async Task<(Func<DeepIdV2AccountService, Task<DeepIdV2InitialSessionCommit>> Complete,
            ParsedDmc2 Hello, ParsedDmc2 Init,
            Func<ReadOnlyMemory<byte>, Task<Dph2InitialClaimPreview>> Preview,
            Func<Dph2InitialClaimPreview, Task<ResponderInitialSessionCommitCapability>> Prepare)> PrepareNativeHelloCompletion(byte[] intent, int oneTimeIndex = -1, bool verifyDraftRecovery = false)
        {
            var recipientAccount = peerAccounts ?? throw new InvalidOperationException("Peer fixture is required.");
            var recipientCheckpoint = peerCheckpoint!;
            var senderSource = Source(); var recipientSource = Source(recipientAccount);
            var staged = await recipientAccount.EnsureOwnInitialPreKeyInventoryAsync(recipientSource);
            var recipientCurrent = await recipientSource.VerifyForOwnPreKeyAuthoringAsync(recipientAccount, default);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span), recipientCheckpoint.Binding, recipientCheckpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(recipientCurrent.Proof, authorization, Boot, Sample);
            // Start at the actual owned contact publisher/read boundary, not
            // a manually framed DCR with unverified random route references.
            using var threshold = new OwnedRouteThreshold(this);
            var plan = await recipientAccount.ReadOwnPermanentContactPlanAsync();
            var publicationIntent = plan.Intent.ToArray();
            var profile = plan.Profile;
            var config = Did2OwnedPermanentContactPlan.Configuration();
            var publishedContact = await recipientAccount.EnsureOwnContactObjectAsync(publicationIntent, recipientSource,
                config, threshold, profile);
            var recipientRoute = await recipientAccount.EnsureOwnContactRouteAsync(publicationIntent, recipientSource, config, threshold);
            var publicationSource = new OwnedPublicationSource(this, recipientRoute);
            // This represents one durable replica service across retries. A
            // reopened committed owner correctly does not dispatch again; its
            // previously observed exact publication must remain at the replica.
            var alreadyPublished = nativeHelloPublicationReplica is not null;
            var publicationReplica = nativeHelloPublicationReplica ??= new OwnedPublicationReplica(this, recipientRoute);
            var priorCalls = publicationReplica.Calls;
            var committedPublication = await recipientAccount.EnsureOwnPermanentContactPublishedAsync(
                recipientSource, threshold, publicationSource, publicationReplica);
            Assert.Equal(committedPublication.RequestHash.ToArray(),
                Xpu1Codec.Decode(publicationReplica.ExactPublication.Span).RequestHash.ToArray());
            if (alreadyPublished) Assert.Equal(priorCalls, publicationReplica.Calls);
            _ = await EnsurePrivateReplyPublicationAsync(accounts);
            var address = (await recipientAccount.GetCurrentAsync())!.PermanentId;
            var resolved = await accounts.ResolvePermanentContactAsync(address, senderSource,
                new SyntheticPermanentRead(this, senderSource, publicationReplica.ExactPublication));
            nativeMessagingContact = resolved;
            nativeMessagingPublication = publicationReplica.ExactPublication;
            var resolver = resolved.Contact;
            Assert.Equal(publishedContact.Closure.CanonicalBytes.ToArray(), resolver.CanonicalBytes.ToArray());
            recipient = resolved.Authorization;
            if (verifyDraftRecovery)
            {
                using var preclaimBefore = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot);
                await Assert.ThrowsAsync<InvalidOperationException>(() => accounts.PrepareOwnPermanentContactClaimAsync(intent, resolved, senderSource, 32));
                using var preclaimAfter = await storage.ReadOwnedAsync(ProtectedDph2PreClaimJournal.Slot);
                Assert.Equal(preclaimBefore!.Use(bytes => bytes.ToArray()), preclaimAfter!.Use(bytes => bytes.ToArray()));
            }
            // Author through the actual owner before claim consumption. Own
            // the caller intent before its first asynchronous proof lookup.
            var draftIntent = intent.ToArray(); var intentMutated = false;
            OnNextDirectoryProof = () => { draftIntent.AsSpan().Clear(); intentMutated = true; };
            if (verifyDraftRecovery)
            {
                storage.FailAfterContactDraftCommit = true;
                await Assert.ThrowsAsync<IOException>(() => accounts.PrepareOwnInitialContactDraftAsync(draftIntent, resolved, senderSource));
            }
            using var draft = await accounts.PrepareOwnInitialContactDraftAsync(verifyDraftRecovery ? intent : draftIntent, resolved, senderSource);
            Assert.True(intentMutated); Assert.True(draftIntent.All(value => value == 0));
            var init = ApplicationCoreCodec.DecodeDmc2(draft.ExactInit);
            var hello = ApplicationCoreCodec.DecodeDmc2(draft.ExactHello);
            if (verifyDraftRecovery) await CheckInitialDraftRootAsync(intent, init, hello, resolved, senderSource);
            var reopenedDraftAccount = ReopenAccount();
            using (var retryDraft = await reopenedDraftAccount.PrepareOwnInitialContactDraftAsync(intent, resolved, Source(reopenedDraftAccount)))
            {
                Assert.Equal(draft.ExactInit.ToArray(), retryDraft.ExactInit.ToArray());
                Assert.Equal(draft.ExactHello.ToArray(), retryDraft.ExactHello.ToArray());
            }
            // Production orchestration chooses the verified publisher service,
            // protected operation/ephemeral commitment and authoritative time.
            // The test no longer constructs XPK from the staged inventory.
            var request = await accounts.PrepareOwnPermanentContactClaimAsync(intent, resolved, senderSource, 32);
            var retainedRequest = await accounts.PrepareOwnPermanentContactClaimAsync(intent, resolved, senderSource, 32);
            Assert.Equal(request.CanonicalBytes.ToArray(), retainedRequest.CanonicalBytes.ToArray());
            using var started = await BeginPreClaimAsync(intent);
            var path = await senderSource.GetCurrentForPreKeyClaimAsync(Network, publication.Manifest.Field(2));
            Assert.Equal(started.ClaimOperationId.ToArray(), request.Field(2).ToArray());
            Assert.Equal(started.SenderEphemeralCommitment.ToArray(), request.Field(21).ToArray());
            Assert.Equal(publication.Manifest.Field(6).Span[6..].ToArray(), request.Field(18).ToArray());
            var exactResult = AuthorClaimResult(request, path, publication, false, oneTimeIndex: oneTimeIndex);
            var custody = await accounts.OpenOwnClaimRequestCustodyAsync();
            using (var cancelledDispatch = new CancellationTokenSource())
            {
                var ignoringToken = new IgnoringCancellationClaimOnion(cancelledDispatch);
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                    await new DeepIdV2PreKeyClaimTransport(senderSource, ignoringToken, custody)
                        .ClaimExactAsync(request.CanonicalBytes, cancelledDispatch.Token));
                Assert.Equal(1, ignoringToken.Calls);
                Assert.Null(await custody.FindResultAsync(request.Field(2), default));
            }
            var claimTransport = new DeepIdV2PreKeyClaimTransport(senderSource, new ClaimOnion(path, exactResult), custody);
            var verifiedResult = await claimTransport.ClaimExactAsync(request.CanonicalBytes);
            var result = DeepIdV2PreKeyClaimResultCodec.Decode(verifiedResult.ExactResult.Span, request.CanonicalBytes.Span);
            var time = new OnionTrustedTimeAuthority(this);
            var clockReads = 0;
            var reversingClock = new CallbackRendezvousClock(() => new(Boot,
                ++clockReads == 1 ? Sample + 1 : Sample));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(request, result, path.Placement,
                    recipient, resolver, new(reversingClock)));
            Assert.Equal(2, clockReads);
            var claim = await DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync(request, result, path.Placement, recipient, resolver, time);
            var current = await senderSource.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            Assert.True(8 + 438 + 16384 + 1 + 4 + init.CanonicalBytes.Length + 4 + hello.CanonicalBytes.Length <= 32764,
                "The actual three-node contact with its private reply route must fit the unchanged initial bucket.");
            receiverCompletion = async exact =>
            {
                var retained = await recipientAccount.FindOwnInitialContactSessionAsync(exact);
                if (retained is not null) return retained;
                var opened = await recipientAccount.PreviewOwnDph2InitialClaimAsync(exact, current.Proof, recipientSource, 32);
                var promoted = await opened.VerifyCurrentAsync(path.Placement, recipient, resolver, current.Proof, time);
                return await recipientAccount.CommitOwnInitialContactSessionAsync(promoted, current.Proof, recipientSource, 32);
            };
            messagingSeeds = async (sent, received, exactInit, exactHello) =>
            {
                var senderLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
                var receiverLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "peer", "deep-store-v2-account.lock"));
                OwnedInitialMessagingSeed senderSeed;
                // The real file lock has its own 30-second acquisition bound.
                // Allow cold SQLCipher verification on ARM64 to finish; nested
                // acquisition still fails, rather than being excused by this budget.
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                using (var held = await senderLease.AcquireAsync(bounded.Token))
                {
                    var senderInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(storage,
                        Network, sent.Record.InitiatorAccountId, bounded.Token);
                    senderSeed = await OwnedInitialMessagingSeed.FromSenderAsync(sent, exactInit.CanonicalBytes,
                        exactHello.CanonicalBytes, senderInstance, current, recipientCurrent.Proof, senderSource, held, bounded.Token);
                }
                try
                {
                    using var held = await receiverLease.AcquireAsync(bounded.Token);
                    var receiverInstance = await SqliteDeepIdV2AccountGeneration.ReadAccountInstanceUnderLeaseAsync(peerStorage,
                        Network, received.Record.ResponderAccountId, bounded.Token);
                    var receiverSeed = await OwnedInitialMessagingSeed.FromReceiverAsync(received, receiverInstance,
                        recipientCurrent, current.Proof, recipientSource, held, bounded.Token);
                    return (senderSeed, receiverSeed);
                }
                catch { senderSeed.Dispose(); throw; }
            };
            ensureSenderMessaging = async (initial, contact) =>
            {
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await accounts.EnsureOwnSenderMessagingAsync(intent, initial.CanonicalBytes,
                    contact.CanonicalBytes, recipientCurrent.Proof, senderSource, bounded.Token);
            };
            ensureReceiverMessaging = async exact =>
            {
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await recipientAccount.EnsureOwnReceiverMessagingAsync(exact, current.Proof, recipientSource, bounded.Token);
            };
            // Recreate the service and source every ordinary operation. No
            // cached TRS/replay map or test transaction authority participates.
            (DeepIdV2AccountService Account, DeepIdV2ContactPathAuthoritySource Source)
                ReopenMessaging(Did2MessagingSessionScope scope)
            {
                var reopened = scope.IsInitiator ? ReopenAccount() : new DeepIdV2AccountService(peerStorage,
                    Path.Combine(directory, "peer"), Network, 1, new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                    DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                return (reopened, new DeepIdV2ContactPathAuthoritySource(bootstrap.GenesisPin, reopened,
                    scope.IsInitiator ? proofs : peerProofs!, closure, scope.IsInitiator ? NetworkStore : peerNetworkStore!, this));
            }
            refreshOwnedMessaging = async scope =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Source.VerifyForOwnMessagingAsync(reopened.Account, scope, bounded.Token);
            };
            sendOwnedMessage = async (scope, op, message) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.SendOwnMessagingAsync(scope, op, message.CanonicalBytes,
                    reopened.Source, bounded.Token);
            };
            prepareOwnedText = async (scope, op, text) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.PrepareOwnDirectTextAsync(scope, op, text, reopened.Source, bounded.Token);
            };
            prepareOwnedAsset = async (scope, op, bytes, filename, mediaType, expiry) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                using var input = new MemoryStream(bytes, writable: false);
                return await reopened.Account.PrepareOwnAttachmentAsync(op, input, bytes.Length, filename, mediaType, expiry, bounded.Token);
            };
            prepareOwnedAttachmentOffer = async (scope, op, asset) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.PrepareOwnDirectAttachmentOfferAsync(scope, op, asset, reopened.Source, bounded.Token);
            };
            receiveOwnedMessage = async (scope, exact) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.ReceiveOwnMessagingEnvelopeAsync(exact, reopened.Source, bounded.Token);
            };
            listOwnedMessages = async scope =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.ListOwnMessagingMessagesAsync(scope, reopened.Source, bounded.Token);
            };
            prepareOwnedContactAccept = async (scope, op) =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.PrepareOwnContactAcceptAsync(scope, op, reopened.Source, bounded.Token);
            };
            readOwnedContactState = async scope =>
            {
                var reopened = ReopenMessaging(scope);
                using var bounded = new CancellationTokenSource(TimeSpan.FromMinutes(3));
                return await reopened.Account.ReadOwnContactAcceptanceAsync(scope, reopened.Source, bounded.Token);
            };
            return (account => account.CompleteOwnInitialContactAsync(intent, resolved, Source(account),
                new ClaimOnion(path, exactResult)), hello, init,
                exact => recipientAccount.PreviewOwnDph2InitialClaimAsync(exact, current.Proof, recipientSource, 32),
                async preview =>
                {
                    var promoted = await preview.VerifyCurrentAsync(path.Placement, recipient, resolver, current.Proof, time);
                    await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                        await preview.VerifyCurrentAsync(path.Placement, recipient, resolver, current.Proof, time));
                    var freshRecipient = await recipientSource.VerifyForOwnPreKeyAuthoringAsync(recipientAccount, default);
                    var reading = await recipientSource.RecheckOwnPreKeyAuthoringAsync(freshRecipient, default);
                    var peerDirectory = Path.Combine(directory, "peer");
                    var lease = new DeepIdV2AccountFileLease(Path.Combine(peerDirectory, "deep-store-v2-account.lock"));
                    var statePath = Path.Combine(peerDirectory, "deep-store-v2-account.dsv2");
                    var owner = new ProtectedDeepIdV2AccountOwner(peerStorage, lease, statePath, Network, 1);
                    using var ownedRecipient = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidOperationException();
                    using var held = await lease.AcquireAsync(default);
                    await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                        await SqliteDeepIdV2AccountGeneration.PrepareInitialSessionUnderLeaseAsync(peerStorage,
                            statePath, ownedRecipient, promoted, freshRecipient with { Proof = current.Proof },
                            current.Proof, reading, time, 32, default));
                    var priorSample = Sample;
                    try
                    {
                        Sample = checked(priorSample + 1_000);
                        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                            await SqliteDeepIdV2AccountGeneration.PrepareInitialSessionUnderLeaseAsync(peerStorage,
                                statePath, ownedRecipient, promoted, freshRecipient, current.Proof, reading, time, 32, default));
                    }
                    finally { Sample = priorSample; }
                    using var canceled = new CancellationTokenSource(); canceled.Cancel();
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                        await SqliteDeepIdV2AccountGeneration.PrepareInitialSessionUnderLeaseAsync(peerStorage,
                            statePath, ownedRecipient, promoted, freshRecipient, current.Proof, reading, time, 32, canceled.Token));
                    // Isolated preparation evidence only: no atomic responder
                    // transaction/inbox/ACK is claimed by this fixture.
                    return await SqliteDeepIdV2AccountGeneration.PrepareInitialSessionUnderLeaseAsync(peerStorage,
                        statePath, ownedRecipient, promoted, freshRecipient, current.Proof, reading, time, 32, default);
                });
        }

        // Exact V2 fixture framing, not a shipping authoring API or publication
        // authority. Every output is checked by the real closed Protocol codecs.
        private ParsedDcr1V2 NativeRecipientClosure(StagedDeepIdV2PreKeyPublication staged, byte[] signingKey,
            VerifiedAdc1V2? selectedCheckpoint = null)
        {
            var checkpoint = selectedCheckpoint ?? this.checkpoint;
            var dmd = checkpoint.Directory.Record; var identity = checkpoint.Binding.Identity;
            var device = identity.ActiveDevices.Single().Certificate;
            var dca = DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span);
            var xps = DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span);
            var issued = xps.Field(10); var expiry = xps.Field(11);
            ReadOnlyMemory<byte>[] inviteFields = [Network, Bytes(32, 0xb1), U64(0), new byte[32],
                Ref("PMT2"u8, 1, Bytes(32, 0xb2)), Bytes(32, 0xb3), Bytes(32, 0xb4), Bytes(32, 0xb5),
                new byte[] { 1 }, new byte[4], U16(1), Bytes(32, 0xb6), issued, expiry,
                Ref("DPD1"u8, 1, device.CanonicalHash.Span), Ref("DCA1"u8, 2, dca.RecordHash.Span),
                Bytes(64, 0xb7), Ref("XRA1"u8, 1, Bytes(32, 0xb8))];
            var unsignedInvite = DeepIdV2InviteRendezvousCodec.Decode(V2Record("XIR1"u8, inviteFields));
            inviteFields[16] = PublicKeyAuth.SignDetached(unsignedInvite.SignatureInput.ToArray(), signingKey);
            var invite = DeepIdV2InviteRendezvousCodec.Decode(V2Record("XIR1"u8, inviteFields));
            var descriptor = new byte[651]; U16(1).CopyTo(descriptor, 0); U16(1).CopyTo(descriptor, 2);
            invite.ObjectHash.Span.CopyTo(descriptor.AsSpan(4)); BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(36), 611);
            invite.CanonicalBytes.Span.CopyTo(descriptor.AsSpan(40));
            var services = new byte[357]; services[0] = 1; BinaryPrimitives.WriteUInt32BigEndian(services.AsSpan(1), 352);
            staged.ExactXps1.Span.CopyTo(services.AsSpan(5));
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(checkpoint.Binding.DeepId, Network, 0,
                genesis.CoreHash.Span, 1, new byte[38], new byte[32]);
            ReadOnlyMemory<byte>[] fields = [Network, dmd.DeepAccountId, identity.Account.Certificate.CanonicalBytes,
                Ref("DRS1"u8, 1, identity.Revocations.Snapshot.CanonicalHash.Span), dmd.CanonicalBytes,
                staged.ExactDca1, Bytes(32, 0xb9), U64(0), new byte[32], device.DeviceId,
                new byte[] { 1 }, services, new byte[] { 1 }, descriptor, ReadOnlyMemory<byte>.Empty,
                new byte[] { 0, 0, 0, 1 }, issued, expiry, Bytes(64, 0xba), lookup.CanonicalBytes,
                U64(0).Concat(genesis.CoreHash.ToArray()).ToArray(), checkpoint.Binding.DeepId.RecordHash,
                checkpoint.Binding.DeepId.CanonicalBytes, checkpoint.Binding.Record.CanonicalBytes];
            var unsigned = DeepIdV2ContactBundleCodec.Decode(V2Record("DCB1"u8, fields));
            fields[18] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), signingKey);
            var bundle = DeepIdV2ContactBundleCodec.Decode(V2Record("DCB1"u8, fields));
            byte[] Support(ushort kind, ReadOnlySpan<byte> exact)
            {
                var bytes = new byte[6 + exact.Length]; BinaryPrimitives.WriteUInt16BigEndian(bytes, kind);
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(2), checked((uint)exact.Length)); exact.CopyTo(bytes.AsSpan(6)); return bytes;
            }
            var support = Support(1, identity.Revocations.Snapshot.CanonicalBytes.Span)
                .Concat(Support(2, device.CanonicalBytes.Span)).ToArray();
            return DeepIdV2ResolverClosureCodec.Decode(V2Record("DCR1"u8, [Network, bundle.CanonicalBytes, U16(2), support]));
        }

        private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
        private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
        private static byte[] Ref(ReadOnlySpan<byte> magic, ushort version, ReadOnlySpan<byte> hash)
        {
            var bytes = new byte[38]; magic.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), version); hash.CopyTo(bytes.AsSpan(6)); return bytes;
        }
        private static byte[] V2Record(ReadOnlySpan<byte> magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        {
            var bytes = new byte[12 + fields.Sum(field => 8 + field.Length)]; magic.CopyTo(bytes);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), DeepIdV2Codec.Suite);
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count)); var offset = 12;
            for (var index = 0; index < fields.Count; index++)
            {
                BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1)));
                BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
                fields[index].Span.CopyTo(bytes.AsSpan(offset + 8)); offset += 8 + fields[index].Length;
            }
            return bytes;
        }

        internal async Task<(ParsedXpk1V2 Request, ContactResolvePathAuthority Authority,
            ParsedXpp1V2 Publication)> CreateClaimAsync(byte operation = 0x83)
        {
            var source = Source();
            var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var authority = await source.GetCurrentForPreKeyClaimAsync(Network, publication.Manifest.Field(2));
            var request = DeepIdV2PreKeyClaimRequestCodec.Decode(DeepIdV2PreKeyClaimRequestCodec.Encode(
                Network, Bytes(32, operation), authority.Placement.ViewHash.Span,
                authority.Placement.PlacementHash.Span, 1_100, 1_120,
                publication.Manifest.Field(2).Span, Bytes(32, 0x82),
                publication.Manifest.Field(6).Span[6..], publication.Manifest.Field(3).Span,
                Bytes(32, 0x81)));
            return (request, authority, publication);
        }

        internal byte[] AuthorClaimResult(ParsedXpk1V2 request, ContactResolvePathAuthority authority,
            ParsedXpp1V2 publication, bool replay, bool badSignature = false, int oneTimeIndex = -1)
        {
            var member = oneTimeIndex >= 0 ? publication.OneTimeMembers[oneTimeIndex] : publication.LastResortMember;
            var useCounter = checked((ushort)(oneTimeIndex >= 0 ? 0 : 1));
            var manifest = publication.Manifest;
            var signingInput = DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(
                request.CanonicalBytes.Span, member.CanonicalBytes.Span, manifest.CanonicalBytes.Span, 1, useCounter);
            var selected = authority.Placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span)).ToArray();
            var rows = new byte[193]; rows[0] = 2;
            for (var index = 0; index < 2; index++)
            {
                selected[index].Span.CopyTo(rows.AsSpan(1 + index * 96));
                nodes.Single(node => node.SignerId.Span.SequenceEqual(selected[index].Span))
                    .SignCommit(signingInput).CopyTo(rows, 33 + index * 96);
            }
            if (badSignature) rows[33] ^= 1;
            var counter = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(counter, useCounter);
            var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, 1);
            var lastIndex = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(lastIndex,
                oneTimeIndex >= 0 ? checked((ushort)oneTimeIndex) : ushort.MaxValue);
            var inclusion = oneTimeIndex >= 0 ? OneTimeProof(publication, oneTimeIndex) : [];
            ReadOnlyMemory<byte>[] payload = [member.CanonicalBytes,
                oneTimeIndex >= 0 ? member.OneTimePrekeyId : new byte[32],
                DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(request.CanonicalBytes.Span,
                    member.CanonicalBytes.Span, manifest.CanonicalBytes.Span, 1, useCounter),
                manifest.Field(12), manifest.Field(13), manifest.Field(5), manifest.Field(15),
                counter, generation, rows, manifest.CanonicalBytes, lastIndex, inclusion];
            return DeepIdV2PreKeyClaimResultCodec.Encode(request.CanonicalBytes.Span,
                replay ? Xpc1V2Status.Replay : Xpc1V2Status.Claimed,
                Xpc1V2MutationOutcome.DurablyCommitted, 1_100, 0, payload);
        }

        // Independent fixture oracle for the fixed 32-member test inventory;
        // production receipt verification checks its exact root and path.
        private static byte[] OneTimeProof(ParsedXpp1V2 publication, int position)
        {
            Assert.Equal(32, publication.OneTimeMembers.Count);
            var level = publication.OneTimeMembers.Select((member, index) =>
            {
                var leaf = new byte[34]; BinaryPrimitives.WriteUInt16BigEndian(leaf, checked((ushort)index));
                member.ExactHash.Span.CopyTo(leaf.AsSpan(2));
                return FixtureHash("Deep/ContactResolver/V2/prekey-inventory-leaf", leaf);
            }).ToArray();
            var proof = new byte[160];
            for (var depth = 0; depth < 5; depth++)
            {
                level[position ^ 1].CopyTo(proof, depth * 32);
                var next = new byte[level.Length / 2][];
                for (var index = 0; index < next.Length; index++)
                {
                    var pair = new byte[64]; level[index * 2].CopyTo(pair, 0); level[index * 2 + 1].CopyTo(pair, 32);
                    next[index] = FixtureHash("Deep/ContactResolver/V2/prekey-inventory-node", pair);
                }
                level = next; position /= 2;
            }
            Assert.Equal(publication.Manifest.Field(10).ToArray(), level[0]);
            return proof;
        }
        private static byte[] FixtureHash(string domain, byte[] value)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(System.Text.Encoding.ASCII.GetBytes(domain)); hash.AppendData([0]);
            var length = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
            hash.AppendData(length); hash.AppendData(value); return hash.GetHashAndReset();
        }

        // Storage-level internal recording deliberately omits transport verification
        // so negative tests prove the public completion path does not trust a marker.
        internal async Task<DeepIdV2PreKeyCommitSnapshot> StageAndRecordPairAsync(
            bool badSignature = false, bool unselectedReplica = false, bool expiredInventory = false)
        {
            var source = Source();
            if (expiredInventory) await StageExpiredInventoryAsync(source);
            var staged = expiredInventory
                ? (await accounts.ReadOwnStagedPreKeyPublicationAsync())!
                : await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var publication = DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span);
            var authority = await source.GetCurrentForPublicationAsync(Network, publication.Manifest.Field(2));
            var selected = authority.Placement.RankedReplicaNodeIds;
            var signers = selected.Select(id => nodes.Single(node =>
                node.SignerId.Span.SequenceEqual(id.Span))).ToArray();
            if (unselectedReplica)
                signers[0] = nodes.Single(node => !selected.Any(id => node.SignerId.Span.SequenceEqual(id.Span)));
            var first = Receipt(signers[0]);
            var second = Receipt(signers[1]);
            if (!badSignature && !unselectedReplica)
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(publication, authority.Placement, first, second);
            await accounts.RecordPreKeyCommitPairAfterVerificationAsync(staged.ExactXpp1, first, second);
            return (await accounts.ReadOwnPreKeyCommitPairAsync())!;

            ParsedXic1V2 Receipt(Signer signer)
            {
                var time = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(time, Math.Min(1_100UL,
                    BinaryPrimitives.ReadUInt64BigEndian(publication.Manifest.Field(15).Span) - 1));
                ReadOnlyMemory<byte>[] fields = [publication.NetworkId, publication.PublicationOperationId,
                    publication.Manifest.ExactHash, publication.PlacementHash, signer.SignerId, time];
                var signature = signer.SignCommit(DeepIdV2PreKeyCommitReceiptCodec.CreateSignatureInput(fields));
                if (badSignature) signature[0] ^= 1;
                return DeepIdV2PreKeyCommitReceiptCodec.Decode(DeepIdV2PreKeyCommitReceiptCodec.Encode(fields, signature));
            }
        }

        internal void VerifyInventory(StagedDeepIdV2PreKeyPublication staged,
            VerifiedDeepIdV2DirectoryFreshness fresh)
        {
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(
                DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                checkpoint.Binding, checkpoint.Directory);
            var authorization = DeepIdV2CurrentContactAuthorizationVerifier.Verify(fresh, dca, Boot, Sample);
            DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(checkpoint.Binding.DeepId,
                staged.ExactXps1.Span, authorization,
                DeepIdV2PreKeyPublicationCodec.Decode(staged.ExactXpp1.Span), Boot, Sample);
        }

        internal async Task StageExpiredInventoryAsync(DeepIdV2ContactPathAuthoritySource source)
        {
            var fresh = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            using var author = await accounts.OpenLocalPreKeyAuthoringAuthorityAsync();
            var context = new Deep.Protocol.MessagingCrypto.Dpk2AuthoringContext(
                ApplicationCoreVerifier.StartDmd1Lineage(checkpoint.Directory).Next, 1, 1, 1, 1_000, 1_000, 1_100);
            var service = author.AuthorPreKeyServiceV2(context, checkpoint.Binding, 32, 1);
            var placement = ContactServicePlacementFactory.Create(fresh.Network,
                ContactServiceRequestKind.PublishPreKeyInventory, service.ServiceCapability);
            var drs = new byte[38];
            "DRS1"u8.CopyTo(drs);
            BinaryPrimitives.WriteUInt16BigEndian(drs.AsSpan(4), 1);
            checkpoint.Binding.Identity.Revocations.Snapshot.CanonicalHash.Span.CopyTo(drs.AsSpan(6));
            using var inventory = author.AuthorInventoryV2(context, checkpoint.Binding, service, drs,
                new byte[32], Bytes(32, 0x67), placement.PlacementHash.Span, 32, 1);
            await accounts.StageOwnInitialPreKeyInventoryAsync(service, inventory);
        }

        private Fixture() => storage = new(innerStorage);
        internal void FailAfterNextNetworkMarker() => storage.FailAfterNetworkMarker = true;
        internal void FailAfterNextHistoryAnchor() => storage.FailAfterHistoryAnchor = true;
        internal async Task AssertHistoryAnchorEnvelopeAsync(ReadOnlyMemory<byte> history)
        {
            using var anchor = await innerStorage.ReadOwnedAsync(Assert.IsType<string>(storage.LastHistoryAnchorSlot));
            var value = anchor!.Use(bytes => bytes.ToArray());
            try
            {
                Assert.Equal(68, value.Length);
                Assert.Equal("DNF2"u8.ToArray(), value[..4]);
                Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(4)));
                Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(6)));
                Assert.Equal((uint)history.Length, BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(64)));
                Assert.Equal(SHA256.HashData(history.Span), value[32..64]);
            }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        internal async Task DamageHistoryAnchorAsync(bool corrupt)
        {
            var slot = Assert.IsType<string>(storage.LastHistoryAnchorSlot);
            if (!corrupt) { await innerStorage.DeleteBatchAsync([slot]); return; }
            using var owned = await innerStorage.ReadOwnedAsync(slot);
            var value = owned!.Use(bytes => bytes.ToArray()); value[^1] ^= 1;
            try
            {
                // Fault injection replaces the immutable slot; production writes
                // must continue rejecting an already occupied anchor revision.
                await innerStorage.DeleteBatchAsync([slot]);
                await innerStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, value)]);
            }
            finally { CryptographicOperations.ZeroMemory(value); }
        }
        internal void FailAfterNextOnionMarker() => storage.FailAfterOnionMarker = true;
        internal Task ResetAccountAsync() => accounts.ResetExplicitlyAsync();

        internal async Task<byte[]> ReadClaimSnapshotAsync()
        {
            await using var sql = await OpenSqlAsync();
            using var read = sql.CreateCommand();
            read.CommandText = "SELECT payload FROM protected_lkg_root WHERE root_kind=8;";
            return Assert.IsType<byte[]>(read.ExecuteScalar());
        }

        internal async Task ReplaceClaimSnapshotForParserTestAsync(byte[] payload)
        {
            // Fixture owner deliberately changes both SQL and its protected
            // hash to reach the local format parser, not the rollback guard.
            // Production has no raw snapshot/floor replacement entry point.
            await using var sql = await OpenSqlAsync();
            using var write = sql.CreateCommand();
            write.CommandText = "UPDATE protected_lkg_root SET payload=$payload WHERE root_kind=8;";
            write.Parameters.AddWithValue("$payload", payload);
            Assert.Equal(1, write.ExecuteNonQuery());
            var slot = Assert.IsType<string>(storage.LastClaimFloorSlot);
            using var owned = await innerStorage.ReadOwnedAsync(slot);
            var marker = owned!.Use(bytes => bytes.ToArray());
            try
            {
                SHA256.HashData(payload).CopyTo(marker, 44);
                await innerStorage.DeleteBatchAsync([slot]);
                await innerStorage.WriteBatchAsync([new DeepSecureStorageWrite(slot, marker)]);
            }
            finally { CryptographicOperations.ZeroMemory(marker); }
        }

        internal async Task<IXPointNetworkStateStore> ReopenNetworkStoreAsync(bool changedPin = false)
        {
            var reopened = new DeepIdV2AccountService(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var pin = changedPin ? new XPointNetworkGenesisPin(Network, Bytes(32, 0x55)) : bootstrap.GenesisPin;
            return await reopened.OpenNetworkLkgStoreAsync(pin);
        }

        internal async Task AssertReceiverSqlAsync(int count, byte[] exact)
        {
            await using var sql = await OpenPeerPreKeySqlAsync();
            using var read = sql.CreateCommand();
            read.CommandText = "SELECT COUNT(*) FROM receiver_sessions;";
            Assert.Equal(count, Convert.ToInt32(read.ExecuteScalar()));
            read.CommandText = "SELECT COUNT(*) FROM secrets;";
            Assert.Equal(33 - count, Convert.ToInt32(read.ExecuteScalar()));
            read.CommandText = "SELECT COUNT(*) FROM secrets WHERE exact_dpk2_hash=$hash;";
            read.Parameters.AddWithValue("$hash", Dph2Codec.Decode(exact).ExactDpk2Hash.ToArray());
            Assert.Equal(0, Convert.ToInt32(read.ExecuteScalar()));
            using var protectedTip = await peerStorage.ReadOwnedAsync(ResponderInitialSessionCheckpoint.Slot);
            using var rootRecord = await peerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var instance = rootRecord!.Use(value => value.Slice(56, 32).ToArray());
            var tip = protectedTip!.Use(value => value.ToArray());
            using var parsed = ResponderInitialSessionCheckpoint.Decode(tip, instance,
                peerCheckpoint!.Binding.Record.DeepAccountId.Span, Network);
            Assert.Equal((byte)1, parsed.Phase); Assert.Equal(checked((ulong)count), parsed.Sequence);
        }

        internal async Task RollBackReceiverSqlAsync()
        {
            await using var sql = await OpenPeerPreKeySqlAsync();
            using var transaction = sql.BeginTransaction();
            using var write = sql.CreateCommand();
            write.Transaction = transaction;
            write.CommandText = "DELETE FROM receiver_initial_state WHERE ordinal=(SELECT MAX(ordinal) FROM receiver_sessions);";
            Assert.Equal(1, write.ExecuteNonQuery());
            write.CommandText = "DELETE FROM receiver_sessions WHERE ordinal=(SELECT MAX(ordinal) FROM receiver_sessions);";
            Assert.Equal(1, write.ExecuteNonQuery());
            transaction.Commit();
        }

        private async Task<SqliteConnection> OpenPeerPreKeySqlAsync()
        {
            using var rootRecord = await peerStorage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var record = rootRecord!.Use(value => value.ToArray());
            byte[]? key = null;
            var certificate = peerCheckpoint!.Binding.Identity.ActiveDevices.Single().Certificate;
            // Test-only observer: same specified account/instance-bound PKV2 key.
            var transcript = new List<byte>("Deep/STORE-V2/prekey-state-key"u8.ToArray());
            transcript.AddRange(Network); transcript.AddRange(peerCheckpoint.Binding.Record.DeepAccountId.ToArray());
            transcript.AddRange(U64(peerCheckpoint.Binding.Identity.Account.Certificate.AccountGeneration));
            transcript.AddRange(certificate.DeviceId.ToArray()); transcript.AddRange(U64(certificate.DeviceGeneration));
            transcript.AddRange(Ref("DPD1"u8, 1, certificate.CanonicalHash.Span));
            transcript.AddRange(record.AsSpan(56, 32).ToArray());
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(directory, "peer", "deep-store-v2-account.dsv2.prekeys.pkv2"),
                Mode = SqliteOpenMode.ReadWrite, Pooling = false
            }.ToString());
            try
            {
                key = HMACSHA256.HashData(record.AsSpan(88, 32), transcript.ToArray());
                connection.Open();
                Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, key));
                return connection;
            }
            catch { connection.Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(record); if (key is not null) CryptographicOperations.ZeroMemory(key); }
        }

        internal async Task<SqliteConnection> OpenSqlAsync()
        {
            using var record = await storage.ReadOwnedAsync("deep.store.v2.sql-generation");
            var key = record!.Use(value => value.Slice(88, 32).ToArray());
            try { return SqliteDeepIdV2AccountGeneration.OpenAccountConnectionForTests(Path.Combine(directory, "deep-store-v2-account.dsv2"), key, create: false); }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        internal static async Task<Fixture> CreateAsync(bool withSuccessor = false, bool expiringHistory = false, bool withPeer = false,
            bool longMailboxWindow = false)
        {
            var fixture = new Fixture();
            try { await fixture.InitializeAsync(withSuccessor, expiringHistory, withPeer, longMailboxWindow); return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private async Task InitializeAsync(bool withSuccessor, bool expiringHistory, bool withPeer, bool longMailboxWindow)
        {
            if (longMailboxWindow && (withSuccessor || expiringHistory))
                throw new ArgumentException("The moving mailbox clock has a separate fixture window.");
            // Cold native/SQLCipher recovery takes longer than the short 500s
            // static-fixture view. Author a genuinely longer signed view/head,
            // still within the root interval; never suppress expiry validation.
            var windowExpiry = longMailboxWindow ? 6_000UL : 1_500UL;
            Directory.CreateDirectory(directory);
            accounts = new(storage, directory, Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await accounts.CreateAsync("DID2 path test");
            bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                new(Bytes(32, 0x12), Network,
                    [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                    witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0,
                        w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2,
                    [new(Bytes(32, 0x60), Bytes(32, 0x61), 1, "time1.invalid", 4460, Bytes(32, 0x62), 5),
                     new(Bytes(32, 0x63), Bytes(32, 0x64), 1, "time2.invalid", 4460, Bytes(32, 0x65), 5)],
                    5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
            var descriptors = nodes.Select((signer, index) => new XPointNetworkOperationalNode(signer,
                Bytes(32, (byte)(0x80 + index)), Bytes(32, (byte)(0x90 + index)),
                Bytes(32, (byte)(0xa0 + index)), Bytes(32, (byte)(0xb0 + index)),
                (uint)(64_500 + index), 840, Bytes(32, (byte)(0xc0 + index)),
                IPAddress.Parse($"192.0.2.{index + 1}"), 443,
                Bytes(32, (byte)(0xd0 + index)), Bytes(32, (byte)(0xd8 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0xe0 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0xe8 + index))),
                Enumerable.Range(0, 5).Select(role => (ReadOnlyMemory<byte>)
                    PublicKey((byte)(0x10 + index * 5 + role))).ToArray())).ToArray();
            if (expiringHistory) ProofTime = 1_020;
            var pendingOperational = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(new(
                Bytes(32, 0x12), bootstrap, [root], witnesses, descriptors, Bytes(32, 0xf1),
                Bytes(32, 0xf5), Bytes(32, 0xf6), PublicKey(0x31), PublicKey(0x32),
                990, 1_000, expiringHistory ? 1_090UL : windowExpiry));
            var admission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                await accounts.PrepareGenesisAdmissionAsync()).Admission;
            checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(admission, 1_000, 1, 2, pq);
            if (withPeer)
            {
                var peerDirectory = Path.Combine(directory, "peer"); Directory.CreateDirectory(peerDirectory);
                peerAccounts = new(peerStorage, peerDirectory, Network, 1,
                    new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                await peerAccounts.CreateAsync("Independent DID2 peer");
                var peerAdmission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await peerAccounts.PrepareGenesisAdmissionAsync()).Admission;
                peerCheckpoint = DeepIdV2GenesisAdmissionVerifier.Verify(peerAdmission, 1_000, 1, 2, pq);
            }
            genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                bootstrap.Authority, 990, windowExpiry, witnesses);
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(bootstrap.Authority,
                genesis.ProtectedHead, new([], [], peerCheckpoint is null ? [checkpoint] : [checkpoint, peerCheckpoint], 990, windowExpiry, 2), witnesses);
            // DR-0070: topology is authored only after independently verifying
            // a genuine DID2 proof against the signed candidate network view.
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead,
                head.ExactAllTransitions, peerCheckpoint is null ? [checkpoint] : [checkpoint, peerCheckpoint],
                checkpoint.Checkpoint.DirectoryLeafKey.Span, genesis.ProtectedHead);
            var nonce = Bytes(32, 0xf2);
            var issued = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority,
                new(Network, nonce, Boot, Sample, head.ExactAdh1.Span, pendingOperational.ExactXnv1.Span,
                    ProofTime, 5, ProofTime, ProofTime + 30,
                    AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, ProofTime, 5), 2),
                material, witnesses, 1, pq);
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(checkpoint.Binding.DeepId, Network,
                genesis.ProtectedHead.LogGeneration, genesis.CoreHash.Span, 1, new byte[38], new byte[32]);
            var freshness = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(bootstrap.Authority,
                issued.ExactAdh1, issued.ExactDtt1, issued.ExactAdp1V2, nonce,
                VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, checkpoint.Binding.DeepId),
                new(Boot, Sample, Sample, Sample), genesis.ProtectedHead, 1, 2, pq);
            operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
                pendingOperational, freshness, new OnionTrustedTimeAuthority(this));
            if (withSuccessor)
                await AdvanceNetworkAsync();
            var floor = await accounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority,
                genesis.ExactAdh1, genesis.CoreHash);
            NetworkStore = await accounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin);
            if (peerAccounts is not null) peerNetworkStore = await peerAccounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin);
            http = new(this, disposeHandler: false);
            var transport = new HttpServiceRequestTransport(http,
                DeepIdV2DirectoryProofClient.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            proofs = new(transport, new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production), this, pq, floor);
            if (peerAccounts is not null)
            {
                var peerFloor = await peerAccounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority, genesis.ExactAdh1, genesis.CoreHash);
                peerProofs = new(new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                    DeepIdV2DirectoryProofClient.CreateTransportOptions("https://registry.example/"), HttpServiceEndpointPolicy.Production),
                    new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                    DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://registry.example/"), HttpServiceEndpointPolicy.Production),
                    this, pq, peerFloor);
            }
            closure = new(new HttpServiceRequestTransport(new HttpClient(this, disposeHandler: false),
                HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://registry.example/"),
                HttpServiceEndpointPolicy.Production));
        }

        internal async Task AdvanceNetworkAsync()
        {
            Assert.Null(successor);
            var rollovers = nodes.Select((signer, index) => new XPointNetworkOperationalNodeRollover(
                signer, Bytes(32, (byte)(0x40 + index)), Bytes(32, (byte)(0x48 + index)),
                ScalarMult.Base(Bytes(32, (byte)(0x50 + index))),
                ScalarMult.Base(Bytes(32, (byte)(0x58 + index))))).ToArray();
            successor = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(
                Bytes(32, 0x13), bootstrap, [root], witnesses, rollovers,
                operational.ExactXvp1, operational.ExactXnd1, [operational.ExactXnv1],
                operational.ExactXnh1, operational.ExactPma2, operational.ExactPmt2,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(operational.ExactXnh1.Span),
                Deep.Protocol.ContactV1.ContactCodec.Decode("PMT2", operational.ExactPmt2.Span).ArtifactHash.Span,
                HeadReference(head.CoreHash.Span), 1_070, 1_080, 1_500));
        }

        internal DeepIdV2ContactPathAuthoritySource Source(DeepIdV2AccountService? account = null) =>
            new(bootstrap.GenesisPin, account ?? accounts,
                ReferenceEquals(account, peerAccounts) && peerAccounts is not null ? peerProofs! : proofs, closure,
                ReferenceEquals(account, peerAccounts) && peerAccounts is not null ? peerNetworkStore! : NetworkStore, this);

        private DeepIdV2NetworkClosureArtifacts PublicClosure()
        {
            var descriptors = (successor?.ExactXnd1 ?? operational.ExactXnd1)
                .Select(value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
            if (AlterNode) { var bytes = descriptors[0].ToArray(); bytes[^1] ^= 1; descriptors[0] = bytes; }
            if (successor is not null)
                return new DeepIdV2NetworkClosureArtifacts(
                    [bootstrap.ExactXna1], [bootstrap.ExactDts1],
                    OmitHistoricalPolicy ? [successor.ExactXvp1] : [operational.ExactXvp1, successor.ExactXvp1],
                    [operational.ExactXnv1, successor.ExactXnv1],
                    [operational.ExactXnh1, successor.ExactXnh1], descriptors,
                    [operational.ExactPmt2, successor.ExactPmt2], MailboxPolicies());
            return new DeepIdV2NetworkClosureArtifacts(
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], descriptors, [operational.ExactPmt2],
                MailboxPolicies());
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath)
            {
                var network = XPointNetworkClosureWireCodec.DecodeRequest(
                    await request.Content!.ReadAsByteArrayAsync(cancellationToken));
                Assert.Equal(Network, network);
                var raw = PublicClosure();
                var encoded = XPointNetworkClosureWireCodec.EncodeResponse(network,
                    raw.ExactXna1AuthorityChain, raw.ExactDts1PolicyChain,
                    raw.ExactOrderedXvp1Chain, raw.ExactOrderedXnv1Chain,
                    raw.ExactOrderedXnh1Chain, raw.ExactActiveXnd1, raw.ExactOrderedPmt2Chain,
                    raw.ExactOrderedPma2Chain);
                var distributed = new HttpResponseMessage(HttpStatusCode.OK)
                { RequestMessage = request, Content = new ByteArrayContent(encoded) };
                distributed.Content.Headers.ContentType = new(XPointNetworkClosureWireCodec.ResponseMediaType);
                return distributed;
            }
            if (request.RequestUri.AbsolutePath == "/api/v2/account-directory/history")
            {
                if (RejectProof) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
                var exact = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
                var encoded = DeepIdV2DirectoryHistoryWireCodec.AuthorResponse(bootstrap.Authority, exact,
                    RouteRequestHistoryHeads(), head.ExactAllTransitions);
                var historyResponse = new HttpResponseMessage(HttpStatusCode.OK)
                { RequestMessage = request, Content = new ByteArrayContent(encoded) };
                historyResponse.Content.Headers.ContentType = new(DeepIdV2DirectoryHistoryWireCodec.ResponseMediaType);
                return historyResponse;
            }
            ProofRequests++;
            var observer = OnNextDirectoryProof; OnNextDirectoryProof = null; observer?.Invoke();
            if (RejectProof) return new(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
            var query = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            var floor = RouteRequestHistoryHeads().SingleOrDefault(value =>
                value.LogGeneration == query.Lookup.MinimumAdhGeneration) ??
                throw new CryptographicException("Unknown test directory floor.");
            var material = DeepIdV2DirectoryProofMaterialAuthor.Create(head.ProtectedHead,
                head.ExactAllTransitions, peerCheckpoint is null ? [checkpoint] : [checkpoint, peerCheckpoint], query.DirectoryLeafKey.Span, floor);
            var proofTime = CurrentProofTime;
            var issued = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(bootstrap.Authority,
                new(Network, query.Nonce.Span, query.BootId.Span, query.ClientMonotonicSendSample,
                    head.ExactAdh1.Span, (successor?.ExactXnv1 ?? operational.ExactXnv1).Span, proofTime, 5, proofTime, proofTime + 30,
                    AccountDirectoryDtt1IssuanceEpoch.Derive(bootstrap.Authority, proofTime, 5), 2),
                material, witnesses, 1, pq, cancellationToken);
            var body = DeepIdV2DirectoryProofWireCodec.EncodeResponse(query, issued);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            { RequestMessage = request, Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
            response.Headers.CacheControl = new() { NoStore = true };
            return response;
        }

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(Boot, checked(Sample + MailboxElapsedSeconds)));
        }

        public ValueTask DisposeAsync()
        {
            if (mailboxSqlBeforePreparation is not null) CryptographicOperations.ZeroMemory(mailboxSqlBeforePreparation);
            closure?.Dispose(); proofs?.Dispose(); peerProofs?.Dispose(); http?.Dispose(); pq.Dispose(); innerStorage.Dispose(); peerStorage.Dispose();
            foreach (var signer in witnesses.Concat(nodes).Append(root)) signer.Dispose();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            Dispose(); return ValueTask.CompletedTask;
        }
    }

    private sealed class NetworkMarkerFaultStorage(IDeepSecureStorage inner) : IDeepSecureStorage
    {
        public Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected,
            ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions,
            CancellationToken ct = default) => inner.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, ct);
        internal Action? AfterPreClaimCommit { get; set; }
        internal Action? AfterRendezvousCommit { get; set; }
        internal Action? AfterCommitPairRead { get; set; }
        internal bool FailAfterContactDraftCommit { get; set; }
        internal bool FailAfterNetworkMarker { get; set; }
        internal bool FailAfterHistoryAnchor { get; set; }
        internal string? LastHistoryAnchorSlot { get; private set; }
        internal bool FailAfterOnionMarker { get; set; }
        internal byte? FailRouteReadbackPhase { get; set; }
        private bool failNextRouteReadback;
        internal string? LastClaimFloorSlot { get; private set; }
        public async Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected,
            ReadOnlyMemory<byte> replacement, CancellationToken ct = default)
        {
            var applied = await inner.CompareExchangeAsync(slot, expected, replacement, ct);
            if (applied && slot == ProtectedDid2ContactRouteJournal.Slot && FailRouteReadbackPhase is { } phase &&
                replacement.Length > ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + 32 &&
                replacement.Span[ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + 32] == phase)
            {
                FailRouteReadbackPhase = null; failNextRouteReadback = true;
            }
            if (applied && slot == ProtectedDid2ContactStartJournal.Slot && FailAfterContactDraftCommit)
            {
                FailAfterContactDraftCommit = false;
                throw new IOException("Injected stop after durable contact draft CAS, before release.");
            }
            if (applied && slot == ProtectedContactRendezvousJournal.Slot && AfterRendezvousCommit is { } afterRendezvous)
            {
                AfterRendezvousCommit = null;
                afterRendezvous();
            }
            if (applied && slot == ProtectedDph2PreClaimJournal.Slot && AfterPreClaimCommit is { } afterPreClaim)
            {
                AfterPreClaimCommit = null;
                afterPreClaim();
            }
            if (applied && replacement.Length == 80 &&
                BinaryPrimitives.ReadInt32BigEndian(replacement.Span[76..]) == 8)
                LastClaimFloorSlot = slot;
            if (applied && FailAfterOnionMarker && slot.Contains(".onion-custody.", StringComparison.Ordinal))
            {
                FailAfterOnionMarker = false;
                throw new IOException("Injected stop after ONION marker, before SQL commit.");
            }
            return applied;
        }
        public async Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default)
        {
            var value = await inner.ReadOwnedAsync(slot, ct);
            if (slot == ProtectedDid2ContactRouteJournal.Slot && failNextRouteReadback)
            {
                failNextRouteReadback = false; value?.Dispose();
                throw new IOException("Injected failure reading back exact committed route custody.");
            }
            if (slot == "deep.store.v2.prekey-commit-pair-v1" && AfterCommitPairRead is { } action)
            {
                AfterCommitPairRead = null;
                action();
            }
            return value;
        }
        public async Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default)
        {
            LastHistoryAnchorSlot = writes.SingleOrDefault(write =>
                write.Slot.Contains(".network-lkg-floor.history.", StringComparison.Ordinal))?.Slot ?? LastHistoryAnchorSlot;
            if (FailAfterNetworkMarker && writes.Any(write => write.Slot.Contains(".network-lkg-floor.", StringComparison.Ordinal)))
            {
                FailAfterNetworkMarker = false;
                // Commit only the first projection marker, before the history anchor.
                await inner.WriteBatchAsync([writes[0]], ct);
                throw new IOException("Injected stop after network marker, before history anchor and SQL commit.");
            }
            await inner.WriteBatchAsync(writes, ct);
            LastClaimFloorSlot = writes.SingleOrDefault(write => write.Value.Length == 80 &&
                BinaryPrimitives.ReadInt32BigEndian(write.Value.Span[76..]) == 8)?.Slot ?? LastClaimFloorSlot;
            if (FailAfterOnionMarker && writes.Any(write => write.Slot.Contains(".onion-custody.", StringComparison.Ordinal)))
            {
                FailAfterOnionMarker = false;
                throw new IOException("Injected stop after ONION marker, before SQL commit.");
            }
            if (FailAfterHistoryAnchor && writes.Any(write => write.Slot.Contains(".network-lkg-floor.history.", StringComparison.Ordinal)))
            {
                FailAfterHistoryAnchor = false;
                throw new IOException("Injected stop after both network anchors, before SQL commit.");
            }
        }
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) => inner.DeleteBatchAsync(slots, ct);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => inner.PurgeStoreV2NamespaceAsync(ct);
    }

    private sealed class Signer : IDisposable, IXPointNetworkBootstrapRootSigner,
        IXPointNetworkWitnessSigner, IAccountDirectoryAdh1WitnessSigner
    {
        private readonly byte marker;
        private readonly KeyPair key;
        internal Signer(byte marker)
        {
            this.marker = marker;
            var seed = Bytes(32, marker);
            try { key = PublicKeyAuth.GenerateKeyPair(seed); }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
        public ReadOnlyMemory<byte> RootKeyId => Bytes(32, marker);
        public ReadOnlyMemory<byte> SignerId => marker >= 0x70 ? key.PublicKey : RootKeyId;
        public ReadOnlyMemory<byte> WitnessId => SignerId;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, (byte)(marker + 0x40));
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request,
            Memory<byte> signature64, CancellationToken ct) => Sign(request.SigningInput, signature64, ct);
        internal byte[] SignCommit(ReadOnlyMemory<byte> input) => PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(destination);
            return ValueTask.FromResult(64);
        }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => Witness(input, ct);
        private ValueTask<ReadOnlyMemory<byte>> Witness(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey));
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] HeadReference(ReadOnlySpan<byte> coreHash)
    {
        var reference = new byte[38];
        "ADH1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        coreHash.CopyTo(reference.AsSpan(6));
        return reference;
    }
    private static byte[] PublicKey(byte marker)
    {
        var seed = Bytes(32, marker); var pair = PublicKeyAuth.GenerateKeyPair(seed);
        try { return pair.PublicKey.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(seed); CryptographicOperations.ZeroMemory(pair.PrivateKey); }
    }
}
