using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxReceive_ActualPublicationRetainedPageSemanticFaultLostAckAndNextEmptyPoll(bool selectedSuccessor)
    {
        // Actual PQ accounts, committed DPE2/ratchet, SQLCipher, protected page,
        // materialization and signed ACK. In-process issuer/terminal and signed
        // fixture time: NOT socket/device or a remote attachment transfer.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, longMailboxWindow: true);
        var intent = Bytes(32, 0xa1);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(intent, verifyDraftRecovery: true);
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        var prematureGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var prematureTransport = new RejectInitialDispatchFactory();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeInitial(intent, prematureGrants, prematureTransport));
        Assert.Equal(0, prematureGrants.Calls); Assert.Equal(0, prematureTransport.Calls);
        fixture.TrackMailboxDispatchClock();
        var depositGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var initialStore = new OwnedStoreFixture(fixture, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
        var callerIntent = intent.ToArray(); var mutated = false;
        fixture.OnNextDirectoryProof = () => { callerIntent.AsSpan().Clear(); mutated = true; };
        var started = await fixture.StartNativeContact(callerIntent, depositGrants, initialStore);
        var sender = started.Conversation.Scope;
        var initialReceipt = started.StorageReceipt;
        Assert.True(mutated); Assert.True(callerIntent.All(value => value == 0));
        Assert.True(initialReceipt.IngressDispatched); Assert.True(initialStore.BuiltHeldFrame);
        var cachedInitial = (await fixture.StartNativeContact(intent, depositGrants, initialStore)).StorageReceipt;
        Assert.False(cachedInitial.IngressDispatched); Assert.Equal(1, initialStore.Calls); Assert.Equal(1, depositGrants.Calls);
        await fixture.VerifyNativeApplicationStartOperation(intent);
        // The allocation is quorum-committed: a delayed first receive must not
        // confuse the 120-second mutation request with a delivery deadline.
        fixture.Sample += 121; fixture.ProofTime += 121;
        var grants = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
        var initialTerminal = new OwnedReadTerminal(fixture, initial) { RetainedEnvelope = initialStore.StoredEnvelope };
        var initialReceived = await fixture.SynchronizeNativeReceiver(grants, initialTerminal);
        Assert.Equal(1, initialReceived.ProcessedEnvelopes); Assert.Equal(1, initialReceived.DurableTombstones);
        Assert.Equal(1, initialTerminal.RetrieveCalls); Assert.Equal(1, initialTerminal.AckCalls);
        // Exact historical replay returns the actual initialized scope without
        // reopening a spent prekey or registering a second session.
        var receiver = await fixture.ReceiveNativeMailboxInitial(initial);
        Assert.Equal(Did2ContactAcceptanceState.IncomingRequest, await fixture.ReadOwnedContactState(receiver));
        var earlyGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var earlyTransport = new RejectInitialDispatchFactory();
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.SendNativeText(receiver, Bytes(32, 0xb0), "no implicit acceptance", earlyGrants, earlyTransport));
        Assert.Equal(0, earlyGrants.Calls); Assert.Equal(0, earlyTransport.Calls);
        var acceptOperation = Bytes(32, 0xa2);
        // The reverse response uses the authenticated Hello private route, not
        // a public permanent-ID resolver or a direct receiver injection.
        var reverseGrants = new OwnedGrantTransport(fixture, ownerOnPrimary: false);
        var acceptStore = new OwnedStoreFixture(fixture, receiver, acceptOperation, null);
        var acceptReceipt = await fixture.AcceptNativeContact(receiver, acceptOperation, reverseGrants, acceptStore);
        var acceptCipher = acceptStore.StoredEnvelope!.Ciphertext.ToArray();
        Assert.True(acceptReceipt.IngressDispatched); Assert.True(acceptStore.BuiltHeldFrame);
        Assert.Equal(1, reverseGrants.Calls); Assert.Equal(1, acceptStore.Calls);
        // Local acceptance is not remote delivery. The app can explicitly retry
        // after reopen with a new UI input ID, but must use the retained winner.
        var repeatedAccept = await fixture.AcceptNativeContact(receiver, Bytes(32, 0xb1), reverseGrants, acceptStore);
        Assert.False(repeatedAccept.IngressDispatched);
        Assert.Equal(1, reverseGrants.Calls); Assert.Equal(1, acceptStore.Calls);
        var ownRetrieval = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true);
        var acceptTerminal = new OwnedReadTerminal(fixture, acceptCipher, ownerOnPrimary: true)
        { RetainedEnvelope = acceptStore.StoredEnvelope };
        var accepted = await fixture.SynchronizeNativeSender(ownRetrieval, acceptTerminal);
        Assert.Equal(1, accepted.ProcessedEnvelopes); Assert.Equal(1, accepted.DurableTombstones);
        Assert.Equal(1, ownRetrieval.Calls); Assert.Equal(1, acceptTerminal.RetrieveCalls); Assert.Equal(1, acceptTerminal.AckCalls);
        Assert.True(acceptTerminal.BuiltRetrieveFrame); Assert.True(acceptTerminal.BuiltAckFrame);
        Assert.Equal(Did2ContactAcceptanceState.PeerAcceptanceRetained, await fixture.ReadOwnedContactState(sender));
        using (var replay = await fixture.ReceiveOwnedMessage(sender, acceptCipher)) { }
        var textOperation = Bytes(32, 0xa3);
        var textStore = new OwnedStoreFixture(fixture, sender, textOperation, null) { Cursor = 2 };
        var textReceipt = await fixture.SendNativeText(sender, textOperation, "Owned Retrieve → semantic inbox → ACK", depositGrants, textStore);
        var cipher = textStore.StoredEnvelope!.Ciphertext.ToArray();
        Assert.True(textReceipt.IngressDispatched); Assert.Equal(2UL, textReceipt.Cursor);
        Assert.Equal(1, textStore.Calls); Assert.Equal(1, depositGrants.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        var localHistory = await fixture.ListNativeApplicationMessages(sender);
        Assert.Equal(1, localHistory.Count(value => value.Text == "Owned Retrieve → semantic inbox → ACK" && value.IsLocalAuthor));
        var terminal = new OwnedReadTerminal(fixture, cipher)
        { RetainedEnvelope = textStore.StoredEnvelope, LoseAckReply = true, Cursor = 2, ExpectedAckCounter = 4 };
        var hitPageCommitFault = false;
        using (ClientMailboxRetrieveTestHooks.Push(point =>
        { if (point == ClientMailboxRetrieveFailpoint.AfterPageCommit) { hitPageCommitFault = true; throw new IOException("Injected page-commit/outcome-journal interruption."); } }))
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.True(hitPageCommitFault); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
        using (var read = await fixture.ReadPeerMailboxReads()) { Assert.Equal(3, read.Phase); Assert.NotEmpty(read.Active!.Page); }
        if (selectedSuccessor) await fixture.StageVerifiedGrantSuccessorAsync(grants, own: false);
        // The real dispatch clock advanced while cold SQL ran. Model that
        // elapsed time in both signed fixture time and its monotonic sample
        // before obtaining a new proof; do not make the captured envelope future.
        fixture.Sample += 40; fixture.ProofTime += 40;
        var hitSemanticFault = false;
        using (DirectDmc2InboxTestHooks.Push(point =>
        { if (point == DirectDmc2InboxFaultPoint.BeforeCommit) { hitSemanticFault = true; throw new IOException("Injected semantic inbox commit failure."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.True(hitSemanticFault); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(0, terminal.AckCalls);
        using (var read = await fixture.ReadPeerMailboxReads()) { Assert.Equal(4, read.Phase); Assert.NotEmpty(read.Active!.Page); }
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(grants, terminal));
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls); Assert.Equal(1, grants.Calls);
        using (var read = await fixture.ReadPeerMailboxReads()) { Assert.Equal(6, read.Phase); Assert.Equal(4UL, read.Active!.AckCounter); }
        fixture.Sample += 40; fixture.ProofTime += 40; terminal.LoseAckReply = false;
        var completed = await fixture.SynchronizeNativeReceiver(grants, terminal);
        Assert.Equal(1, completed.ProcessedEnvelopes); Assert.Equal(1, completed.DurableTombstones); Assert.False(completed.HasMore);
        Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls); Assert.Equal(1, grants.Calls);
        Assert.True(terminal.BuiltRetrieveFrame); Assert.True(terminal.BuiltAckFrame);
        using (var read = await fixture.ReadPeerMailboxReads())
        { Assert.Equal(0, read.Phase); Assert.Null(read.Active); Assert.Equal(4UL, Assert.Single(read.Counters).Value); Assert.Equal(2UL, Assert.Single(read.Traversals).Value.PollGeneration); }
        var history = await fixture.ListNativeApplicationMessages(receiver);
        Assert.Equal(1, history.Count(value => value.Text == "Owned Retrieve → semantic inbox → ACK" && !value.IsLocalAuthor));
        if (!selectedSuccessor)
        {
            var empty = await fixture.SynchronizeNativeReceiver(grants, terminal);
            Assert.Equal(0, empty.ProcessedEnvelopes); Assert.Equal(0, empty.DurableTombstones);
            Assert.Equal(2, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls); Assert.Equal(1, grants.Calls);
            using var read = await fixture.ReadPeerMailboxReads();
            Assert.Equal(0, read.Phase); Assert.Equal(5UL, Assert.Single(read.Counters).Value);
            Assert.Equal(3UL, Assert.Single(read.Traversals).Value.PollGeneration);
        }
        else
        {
            // Changed selection cannot replace the captured Retrieve/ACK grant.
            using var custody = await fixture.ReadPeerGrantsAsync();
            var originalName = Convert.ToHexString(SHA256.HashData(grants.OriginalRequest.Span));
            var scope = Convert.ToHexString(custody.Entries[originalName].AsSpan(0, 32));
            Assert.Equal(2, custody.Entries.Values.Count(value => Convert.ToHexString(value.AsSpan(0, 32)) == scope));
            var selected = new KeyValuePair<string, ProtectedDid2MailboxGrantJournal.Selection>(scope, custody.Selections[scope]);
            Assert.NotEqual(originalName, selected.Value.Current);
            Assert.Equal(ProtectedDid2MailboxGrantJournal.Acquisition(
                ProtectedDid2MailboxGrantJournal.CurrentWinner(custody, selected.Key)!), selected.Value.Current);
            Assert.Equal(1, grants.Calls); // No acquisition during old page/ACK recovery.
        }
        await fixture.VerifyOfflineNativeHistory(sender, receiver, "Owned Retrieve → semantic inbox → ACK");
        CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(cipher);
        CryptographicOperations.ZeroMemory(acceptCipher); CryptographicOperations.ZeroMemory(acceptOperation);
    }

    private sealed partial class Fixture
    {
        // One coordinator statement namespace across Store and ACK terminals.
        // Cached retries retain the original signed statement and sequence.
        private long mailboxCoordinatorSequence;
        internal ulong NextMailboxCoordinatorSequence() => checked((ulong)Interlocked.Increment(ref mailboxCoordinatorSequence));
        private long? mailboxClockStarted;
        private ulong MailboxElapsedSeconds => mailboxClockStarted is { } started
            ? checked((ulong)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalSeconds) : 0;
        internal ulong CurrentProofTime => checked(ProofTime + MailboxElapsedSeconds);
        internal void TrackMailboxDispatchClock() => mailboxClockStarted = System.Diagnostics.Stopwatch.GetTimestamp();
        internal Task<Did2MessagingSessionScope> ReceiveNativeMailboxInitial(ReadOnlyMemory<byte> exact)
        { var reopened = ReopenGrantReader(); return reopened.ReceiveOwnMailboxInitialAsync(exact, GrantReaderSource(reopened)); }
        internal Task<DeepIdV2MailboxSynchronizationResult> SynchronizeNativeReceiver(IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory terminal)
        { var reopened = ReopenGrantReader(); return reopened.SynchronizeOwnMailboxAsync(GrantReaderSource(reopened), grants, terminal); }
        internal Task<DeepIdV2MailboxSynchronizationResult> SynchronizeNativeSender(IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory terminal)
        { var reopened = ReopenAccount(); return reopened.SynchronizeOwnMailboxAsync(Source(reopened), grants, terminal); }
        internal async Task<ProtectedDid2MailboxReadJournal.State> ReadPeerMailboxReads(bool own = false)
        {
            var selected = own ? innerStorage : peerStorage;
            using var key = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            using var root = await selected.ReadOwnedAsync(ProtectedDid2MailboxReadJournal.Slot) ?? throw new InvalidOperationException();
            var scope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            try { return root.Use(bytes => ProtectedDid2MailboxReadJournal.Decode(bytes, Network, scope.AsSpan(0, 32), scope.AsSpan(32))); }
            finally { CryptographicOperations.ZeroMemory(scope); }
        }
    }

    [Theory]
    [InlineData(0UL, 100UL)] [InlineData(100UL, 100UL)] [InlineData(99UL, 100UL)]
    public void ContactAcceptExpiredHelloIsRejectedWithoutExtendingItsInterval(ulong expiry, ulong creation)
    {
        Assert.Throws<InvalidOperationException>(() => ProtectedDeepIdV2AccountOwner.RequireAcceptDraftExpiry(expiry, creation));
        ProtectedDeepIdV2AccountOwner.RequireAcceptDraftExpiry(creation + 1, creation);
    }

    [Fact]
    public void OwnedMailboxPollingPublicSurfaceHasNoCallerTransportOrAckAuthority()
    {
        var method = Assert.Single(typeof(DeepIdV2AccountService).GetMethods(),
            candidate => candidate.Name == "SynchronizeOwnMailboxAsync");
        Assert.Equal(new[] { typeof(DeepIdV2ContactPathAuthoritySource), typeof(CancellationToken) },
            method.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.Equal(typeof(Task<DeepIdV2MailboxSynchronizationResult>), method.ReturnType);
        Assert.Empty(typeof(DeepIdV2MailboxSynchronizationResult).GetConstructors());
        Assert.All(typeof(DeepIdV2MailboxSynchronizationResult).GetProperties(), property => Assert.Null(property.SetMethod));
        Assert.Equal(new[] { "DurableTombstones", "HasMore", "ProcessedEnvelopes" },
            typeof(DeepIdV2MailboxSynchronizationResult).GetProperties().Select(property => property.Name).Order());
    }

    private sealed class RejectInitialDispatchFactory : IDid2OwnedMailboxTransportFactory
    {
        internal int Calls;
        public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext context, IMailboxClientDecodePolicyProvider decoder)
        { Calls++; throw new InvalidOperationException("Uninitialized source must reject before a transport callback."); }
    }

    private sealed class OwnedReadTerminal(Fixture fixture, byte[] cipher, bool ownerOnPrimary = false) : IDid2OwnedMailboxTransportFactory,
        IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress
    {
        private Did2OwnedMailboxTransportContext context = null!;
        private IMailboxClientDecodePolicyProvider policy = null!;
        private MailboxEncryptedEnvelope? envelope;
        private byte[]? ackRequest, ackResponse;
        private bool tombstoned;
        internal MailboxEncryptedEnvelope? RetainedEnvelope;
        internal ulong Cursor = 1, ExpectedAckCounter = 2;
        internal int RetrieveCalls, AckCalls;
        internal bool LoseAckReply, BuiltRetrieveFrame, BuiltAckFrame;
        public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext loan, IMailboxClientDecodePolicyProvider decoder)
        { context = loan; policy = decoder; return this; }
        private async Task BuildHeldFrame(OnionOperation operation, ReadOnlyMemory<byte> exact, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            var paths = context.Source.CreateOwnHeldMailboxPaths(context, PrivacyMailboxRouteSelection.Primary);
            var attempt = await paths.PrepareOnRouteAsync(operation, exact, route, ct);
            var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(context.Custody.Entropy), new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
            using var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct);
            Assert.True(built.Frame.Length > exact.Length); await context.RequireCurrentAsync(ct);
        }
        public async Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> exact, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            RetrieveCalls++;
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact.Span);
            var request = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(mau.Binding.CanonicalRequest.Span);
            using (var root = await fixture.ReadPeerMailboxReads(own: ownerOnPrimary))
            { Assert.Equal(2, root.Phase); Assert.Equal(mau.Presentation.ReplayCounter, root.Active!.RetrieveCounter); Assert.Equal(SHA256.HashData(exact.Span), root.Active.RetrieveMauHash); }
            Assert.Equal(8, request.MaximumItems);
            await BuildHeldFrame(OnionOperation.Retrieve, exact, route, ct); BuiltRetrieveFrame = true;
            var decode = policy.GetCurrent();
            envelope ??= RetainedEnvelope ?? new()
            {
                Epoch = request.Epoch, MailboxId = request.MailboxId, PlacementId = request.PlacementId,
                OperationId = Bytes(16, 0xb1), DeduplicationDigest = SHA256.HashData(cipher), Ciphertext = cipher.ToArray(),
                CreatedAtUnixSeconds = decode.NowUnixSeconds,
                ExpiresAtUnixSeconds = Math.Min(decode.EpochWindow.CurrentExpiresAtUnixSeconds, decode.NowUnixSeconds + MailboxClientLimits.MaximumTtlSeconds)
            };
            return MailboxClientCodec.EncodeRetrievePage(new()
            {
                Epoch = request.Epoch, OperationId = request.OperationId, NextCursor = tombstoned ? 0UL : Cursor, HasMore = false,
                ContinuationToken = ReadOnlyMemory<byte>.Empty, Items = tombstoned ? [] : [new() { Cursor = Cursor, Envelope = envelope }]
            });
        }
        public async Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> exact, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            AckCalls++;
            var mau = MailboxAuthenticatedClientRequestCodec.Decode(exact.Span);
            var request = MailboxAuthenticatedRequestTranscript.DecodeAckBody(mau.Binding.CanonicalRequest.Span);
            using (var root = await fixture.ReadPeerMailboxReads(own: ownerOnPrimary))
            { Assert.Equal(6, root.Phase); Assert.Equal(ExpectedAckCounter, root.Active!.AckCounter); Assert.Equal(SHA256.HashData(exact.Span), root.Active.AckMauHash); }
            if (ackRequest is null) ackRequest = exact.ToArray(); else Assert.Equal(ackRequest, exact.ToArray());
            await BuildHeldFrame(OnionOperation.Acknowledge, exact, route, ct); BuiltAckFrame = true;
            Assert.Equal(Cursor, Assert.Single(request.Acknowledgements).Cursor);
            Assert.Equal(envelope!.DeduplicationDigest.ToArray(), request.Acknowledgements[0].EnvelopeDigest.ToArray());
            if (ackResponse is null)
            {
                var crypto = new SodiumMailboxPeerReplicationCrypto();
                byte Marker(ReadOnlyMemory<byte> id) => (byte)Enumerable.Range(0x70, 3).Single(value => PublicKey((byte)value).AsSpan().SequenceEqual(id.Span));
                MailboxReplicaReceiptV2 Receipt(ReadOnlyMemory<byte> id) => crypto.SignReplicaResponse(new()
                {
                    Status = MailboxReceiptStatus.Durable, Disposition = MailboxReplicaDisposition.Tombstone,
                    ReplicaId = id, OperationId = request.OperationId, Epoch = request.Epoch, Cursor = Cursor,
                    AcceptedAtUnixSeconds = policy.GetCurrent().NowUnixSeconds, DurableAtUnixSeconds = policy.GetCurrent().NowUnixSeconds,
                    ExpiresAtUnixSeconds = envelope!.ExpiresAtUnixSeconds, BlindedMailboxId = envelope.MailboxId.Bytes,
                    PlacementCommitment = route.PlacementCommitment, MembershipCommitment = route.MembershipCommitment,
                    EnvelopeDigest = envelope.DeduplicationDigest, Signature = new byte[64]
                }, Bytes(32, Marker(id)));
                var quorum = MailboxReceiptV3Codec.EncodeDurableQuorum(crypto.SignQuorumResponse(new MailboxDurableQuorumReceiptV3
                {
                    CoordinatorId = route.Replicas.FirstId, CoordinatorSequence = fixture.NextMailboxCoordinatorSequence(), FirstReplica = Receipt(route.Replicas.FirstId),
                    SecondReplica = Receipt(route.Replicas.SecondId), Signature = new byte[64]
                }, Bytes(32, Marker(route.Replicas.FirstId))));
                ackResponse = MailboxAggregateAckCodec.EncodeMqr3(new() { Epoch = request.Epoch, OperationId = request.OperationId, TombstoneQuorums = [quorum] });
            }
            tombstoned = true;
            if (LoseAckReply) throw new IOException("Injected lost ACK response after actual terminal tombstone.");
            return ackResponse.ToArray();
        }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => throw new InvalidOperationException();
    }
}
