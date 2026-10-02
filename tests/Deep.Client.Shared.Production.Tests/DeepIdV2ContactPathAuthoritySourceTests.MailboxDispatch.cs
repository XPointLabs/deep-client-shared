using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_CommittedTextFaultsExactReopenLostReplyAndDurableReceipt()
    {
        // Real account/PQ/ratchet/SQLCipher/owner and signed receipts. In-process
        // grant/terminal fixture and synthetic signed clock: NOT socket/device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xad));
        byte[] initial;
        using (var sent = await complete(fixture.Accounts)) initial = sent.ExactDph2.ToArray();
        using (var received = await fixture.CompleteReceiver(initial)) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial);
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xae)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xaf);
        byte[] cipher;
        using (var text = await fixture.PrepareOwnedText(sender, operation, "Owned mailbox delivery 📨"))
        using (var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span)))
            cipher = sent.ExactEnvelope.ToArray();
        var pendingText = Assert.Single(await fixture.ListNativePendingText());
        Assert.Equal(operation, pendingText.LogicalOperation.ToArray());
        Assert.Equal(Convert.ToHexString(sender.Conversation), pendingText.ConversationId);
        Assert.Equal("Owned mailbox delivery 📨", pendingText.Text);
        Assert.Equal(3UL, pendingText.SenderSequence);
        var mutableOperation = pendingText.LogicalOperation.ToArray(); mutableOperation.AsSpan().Clear();
        Assert.Equal(operation, pendingText.LogicalOperation.ToArray());
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, cipher) { LoseReply = true };
        foreach (var point in new[] { Did2MailboxSendFailpoint.BeforeSql, Did2MailboxSendFailpoint.AfterSql, Did2MailboxSendFailpoint.BeforeDispatch })
        {
            var callerOperation = operation.ToArray();
            var mutatedDuringRefresh = false;
            if (point == Did2MailboxSendFailpoint.BeforeSql)
                fixture.OnNextDirectoryProof = () => { callerOperation.AsSpan().Clear(); mutatedDuringRefresh = true; };
            using (Did2MailboxSendTestHooks.Push(found =>
            {
                if (found != point) return;
                if (point == Did2MailboxSendFailpoint.BeforeSql) fixture.CaptureMailboxSqlBeforePreparation();
                throw new IOException("Injected owned Store interruption.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, callerOperation, grants, transport));
            if (point == Did2MailboxSendFailpoint.BeforeSql)
            { Assert.True(mutatedDuringRefresh); Assert.True(callerOperation.All(value => value == 0)); }
            CryptographicOperations.ZeroMemory(callerOperation);
            Assert.Equal(0, transport.Calls);
            using var state = await fixture.ReadMailboxSends();
            Assert.Equal(point == Did2MailboxSendFailpoint.BeforeDispatch, Assert.Single(state.Entries).Value.Prepared);
            Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        }
        // BeforeDispatch has already durably reserved its retry lease even
        // though the injected interruption precedes the terminal callback.
        // Do not rely on slow SQL password derivation to expire that lease.
        fixture.Sample += 40; fixture.ProofTime += 40;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        using (var protectedState = await fixture.ReadMailboxSends())
        {
            var entry = Assert.Single(protectedState.Entries).Value;
            Assert.True(entry.Prepared); Assert.Equal(1UL, entry.Counter);
            Assert.Equal(SHA256.HashData(transport.ExactRequest!), entry.MauHash.ToArray());
        }
        await Assert.ThrowsAsync<ClientMailboxRetryLeaseException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls);
        fixture.Sample += 40; fixture.ProofTime += 40; transport.LoseReply = false;
        var beforeCompletion = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.BeforeOrdinaryCompletion) return;
            beforeCompletion = true; throw new IOException("Injected failure after verified Store but before protected completion.");
        }))
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.True(beforeCompletion); Assert.Equal(2, transport.Calls);
        Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        var afterCompletion = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        {
            if (point != Did2MailboxSendFailpoint.AfterOrdinaryCompletion) return;
            afterCompletion = true; throw new IOException("Injected UI-return failure after protected Store completion.");
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.True(afterCompletion); Assert.Equal(2, transport.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        var durable = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        // Real retry already obtained the signed result before the injected
        // completion crash. Recover that exact receipt without a third ingress.
        Assert.False(durable.IngressDispatched); Assert.Equal(1UL, durable.Cursor);
        Assert.Equal(2, transport.Calls); Assert.Equal(1, grants.Calls); Assert.True(transport.BuiltHeldFrame);
        Assert.Empty(await fixture.ListNativePendingText());
        var cached = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.False(cached.IngressDispatched); Assert.Equal(durable.Cursor, cached.Cursor); Assert.Equal(2, transport.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        using (var received = await fixture.ReceiveOwnedMessage(receiver, cipher)) { }
        var history = await fixture.ListOwnedMessages(receiver);
        Assert.Contains(history, message => message.Text == "Owned mailbox delivery 📨" && !message.IsLocalAuthor);
        fixture.RollBackMailboxSqlBeforePreparation();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(2, transport.Calls); Assert.Equal(1, grants.Calls);
        using (var retained = await fixture.ReadMailboxSends())
            Assert.Equal(1UL, Assert.Single(retained.Entries).Value.Counter);
        await fixture.DeleteMailboxSendRoot();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(2, transport.Calls);
        CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(cipher);
    }

    private sealed partial class Fixture
    {
        private VerifiedDeepIdV2PermanentContactResolveClosure? nativeMessagingContact;
        private ReadOnlyMemory<byte> nativeMessagingPublication;
        internal Action? OnNextDirectoryProof;
        private byte[]? mailboxSqlBeforePreparation;
        internal Task<ClientMailboxStoreResult> DeliverNativeMessage(Did2MessagingSessionScope scope, byte[] op,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.DeliverOwnMessagingAsync(scope, op, source, grants, transport);
        }
        internal Task<ClientMailboxStoreResult> DeliverNativeInitial(byte[] intent,
            IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory transport)
        {
            var account = ReopenAccount();
            var source = Source(account);
            return account.DeliverOwnInitialContactAsync(intent, nativeMessagingContact!, source, grants, transport,
                contactRead: new SyntheticPermanentRead(this, source, nativeMessagingPublication));
        }
        internal async Task<ProtectedDid2MailboxSendJournal.State> ReadMailboxSends(bool own = true)
        {
            var selected = own ? innerStorage : peerStorage;
            using var key = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            using var root = await selected.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var scope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            try { return root.Use(bytes => ProtectedDid2MailboxSendJournal.Decode(bytes, Network, scope.AsSpan(0, 32), scope.AsSpan(32))); }
            finally { CryptographicOperations.ZeroMemory(scope); }
        }
        internal async Task<Did2MessagingSessionScope> ReadStoredSendScope(byte[] scopeHash, bool own)
        {
            var selected = own ? innerStorage : peerStorage;
            using var key = await selected.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            var owner = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            try
            {
                using var root = await selected.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidOperationException();
                using var catalog = root.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, Network, owner.AsSpan(0, 32), owner.AsSpan(32)));
                var found = new List<Did2MessagingSessionScope>();
                for (var index = 0; index < catalog.Count; index++)
                    if (catalog.Scope(index).Hash.SequenceEqual(scopeHash))
                    { Assert.Equal(2, catalog.Phase(index)); found.Add(catalog.Scope(index)); }
                return Assert.Single(found);
            }
            finally { CryptographicOperations.ZeroMemory(owner); }
        }
        internal Task DeleteMailboxSendRoot() => innerStorage.DeleteBatchAsync([ProtectedDid2MailboxSendJournal.Slot]);
        private string MailboxSqlFixturePath()
        {
            var parent = Path.GetFullPath(directory) + Path.DirectorySeparatorChar;
            var path = Path.GetFullPath(Path.Combine(directory, "deep-store-v2-account.dsv2.application.dmb1"));
            Assert.StartsWith(parent, path, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(path));
            Assert.Equal(0, (int)(File.GetAttributes(path) & FileAttributes.ReparsePoint));
            foreach (var suffix in new[] { "-journal", "-wal", "-shm" }) Assert.False(File.Exists(path + suffix));
            return path;
        }
        internal void CaptureMailboxSqlBeforePreparation()
        {
            // Test-only encrypted snapshot, after grant installation and before
            // the first SQL prepare. No SQL key is exported and no lineage is broken.
            Assert.Null(mailboxSqlBeforePreparation);
            var path = MailboxSqlFixturePath();
            Assert.InRange(new FileInfo(path).Length, 1, 4 * 1024 * 1024);
            mailboxSqlBeforePreparation = File.ReadAllBytes(path);
            Assert.False(mailboxSqlBeforePreparation.AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        }
        internal void RollBackMailboxSqlBeforePreparation()
        {
            var snapshot = mailboxSqlBeforePreparation ?? throw new InvalidOperationException("No encrypted fixture snapshot exists.");
            var path = MailboxSqlFixturePath();
            try
            {
                File.WriteAllBytes(path, snapshot); // Only this disposable closed fixture SQL.
                var readback = File.ReadAllBytes(path);
                try { Assert.Equal(snapshot, readback); }
                finally { CryptographicOperations.ZeroMemory(readback); }
            }
            finally { CryptographicOperations.ZeroMemory(snapshot); mailboxSqlBeforePreparation = null; }
        }
    }

    private sealed class OwnedStoreFixture(Fixture fixture, Did2MessagingSessionScope? scope, byte[] op, byte[]? dpe, bool ownerOnPrimary = true) :
        IDid2OwnedMailboxTransportFactory, IClientMailboxBinaryIngress, IRouteBoundClientMailboxBinaryIngress
    {
        private Did2OwnedMailboxTransportContext? context;
        private IMailboxClientDecodePolicyProvider? policy;
        internal byte[]? ExactRequest { get; private set; }
        internal MailboxEncryptedEnvelope? StoredEnvelope { get; private set; }
        private byte[]? durableResponse;
        internal ulong Cursor = 1;
        internal bool LoseReply { get; set; }
        internal int Calls { get; private set; }
        internal bool BuiltHeldFrame { get; private set; }
        public IClientMailboxBinaryIngress Create(Did2OwnedMailboxTransportContext loan, IMailboxClientDecodePolicyProvider decode)
        { context = loan; policy = decode; return this; }
        public async Task<ReadOnlyMemory<byte>> StoreOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct)
        {
            Calls++;
            var decoded = MailboxAuthenticatedClientRequestCodec.Decode(request.Span);
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(decoded.Binding.CanonicalRequest.Span);
            if (dpe is not null) Assert.Equal(dpe, envelope.Ciphertext.ToArray());
            StoredEnvelope ??= envelope;
            if (ExactRequest is null) ExactRequest = request.ToArray(); else Assert.Equal(ExactRequest, request.ToArray());
            using (var journal = await fixture.ReadMailboxSends(own: scope?.IsInitiator ?? ownerOnPrimary))
            {
                var entry = Assert.Single(journal.Entries, value => value.Value.Operation.SequenceEqual(op)).Value;
                scope ??= await fixture.ReadStoredSendScope(entry.ScopeHash.ToArray(), ownerOnPrimary);
                Assert.True(entry.Prepared); Assert.Equal(op, entry.Operation.ToArray()); Assert.Equal(scope.Hash.ToArray(), entry.ScopeHash.ToArray());
                Assert.Equal(SHA256.HashData(envelope.Ciphertext.Span), entry.EnvelopeHash.ToArray());
                Assert.Equal(SHA256.HashData(request.Span), entry.MauHash.ToArray()); Assert.Equal(decoded.Presentation.ReplayCounter, entry.Counter);
            }
            var paths = context!.Source.CreateOwnHeldMailboxPaths(context, PrivacyMailboxRouteSelection.Primary);
            var attempt = await paths.PrepareOnRouteAsync(OnionOperation.Store, request, route, ct);
            var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(context.Custody.Entropy), new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
            using (var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct))
                Assert.True(built.Frame.Length > request.Length);
            BuiltHeldFrame = true;
            await context.RequireCurrentAsync(ct);
            if (durableResponse is not null)
            {
                if (LoseReply) throw new IOException("Injected lost Store reply after exact request dispatch.");
                return durableResponse.ToArray();
            }
            var ids = route.Replicas; var crypto = new SodiumMailboxPeerReplicationCrypto();
            MailboxReplicaReceiptV2 Receipt(ReadOnlyMemory<byte> id)
            {
                var marker = Enumerable.Range(0x70, 3).Single(value => PublicKey((byte)value).AsSpan().SequenceEqual(id.Span));
                return crypto.SignReplicaResponse(new()
                {
                    Status = MailboxReceiptStatus.Durable, Disposition = MailboxReplicaDisposition.Stored,
                    ReplicaId = id, OperationId = envelope.OperationId, Epoch = envelope.Epoch, Cursor = Cursor,
                    AcceptedAtUnixSeconds = policy!.GetCurrent().NowUnixSeconds,
                    DurableAtUnixSeconds = policy.GetCurrent().NowUnixSeconds, ExpiresAtUnixSeconds = envelope.ExpiresAtUnixSeconds,
                    BlindedMailboxId = envelope.MailboxId.Bytes, PlacementCommitment = route.PlacementCommitment,
                    MembershipCommitment = route.MembershipCommitment, EnvelopeDigest = envelope.DeduplicationDigest, Signature = new byte[64]
                }, Bytes(32, (byte)marker));
            }
            var firstMarker = Enumerable.Range(0x70, 3).Single(value => PublicKey((byte)value).AsSpan().SequenceEqual(ids.FirstId.Span));
            durableResponse = MailboxReceiptV3Codec.EncodeDurableQuorum(crypto.SignQuorumResponse(new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = ids.FirstId, CoordinatorSequence = fixture.NextMailboxCoordinatorSequence(), FirstReplica = Receipt(ids.FirstId),
                SecondReplica = Receipt(ids.SecondId), Signature = new byte[64]
            }, Bytes(32, (byte)firstMarker)));
            if (LoseReply) throw new IOException("Injected lost Store reply after durable quorum creation.");
            return durableResponse.ToArray();
        }
        public Task<ReadOnlyMemory<byte>> StoreAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> RetrieveAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(ReadOnlyMemory<byte> request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> RetrieveOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => throw new InvalidOperationException();
        public Task<ReadOnlyMemory<byte>> AcknowledgeOnRouteAsync(ReadOnlyMemory<byte> request, ScopedMailboxResolvedRoute route, CancellationToken ct) => throw new InvalidOperationException();
    }
}
