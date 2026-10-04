using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Persistence.XPointNetworkV1;
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
    [Theory]
    [InlineData(0)] // Full journal, new operation.
    [InlineData(1)] // Existing operation, different retained route.
    [InlineData(2)] // Existing operation, different retained ciphertext.
    [InlineData(3)] // Floors are full even though no working entries remain.
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_RejectsUnavailableOrChangedCustodyBeforeGrantAcquisition(int fault)
    {
        // Real accounts, native ratchet and committed ciphertext. The filled
        // local commitment journal is a rejection fixture, NOT grant authority
        // or proof of 512 remotely delivered messages.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xad));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xae)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xaf);
        using var text = await fixture.PrepareOwnedText(sender, operation, "Capacity must precede network mutation");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var expectedJournalHash = await fixture.StageRejectedMailboxSend(sender, operation, committed.ExactEnvelope.ToArray(), fault);
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray());
        var error = await Record.ExceptionAsync(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(0, grants.Calls); Assert.Equal(0, transport.Calls);
        if (fault is 0 or 3) Assert.IsType<IOException>(error); else Assert.IsType<CryptographicException>(error);
        using var retainedGrants = await fixture.ReadPeerGrantsAsync(own: true);
        Assert.Empty(retainedGrants.Entries); Assert.Equal(1UL, retainedGrants.Revision);
        using var retainedSends = await fixture.ReadMailboxSends();
        Assert.Equal(fault == 0 ? ProtectedDid2MailboxSendJournal.MaximumEntries : fault == 3 ? 0 : 1, retainedSends.Entries.Count);
        var retainedExact = ProtectedDid2MailboxSendJournal.Encode(retainedSends, sender.Network, sender.LocalAccount, sender.Instance);
        try { Assert.Equal(expectedJournalHash, SHA256.HashData(retainedExact)); }
        finally { CryptographicOperations.ZeroMemory(retainedExact); }
        Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_FullWorkingJournalStillReconcilesExactUnknownAttempt()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xad));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xae)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xaf);
        using var text = await fixture.PrepareOwnedText(sender, operation, "Reconcile before working-set retirement");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray()) { LoseReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(1, grants.Calls);
        var originalRequest = transport.ExactRequest!.ToArray();
        var expectedRoot = await fixture.FillMailboxWorkingSetAroundPreparedAttempt(sender, committed.ExactEnvelope.ToArray());
        fixture.Sample += 40; fixture.ProofTime += 40; transport.LoseReply = false;
        var settled = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.Equal(1UL, settled.Cursor); Assert.Equal(2, transport.Calls); Assert.Equal(1, grants.Calls);
        Assert.Equal(originalRequest, transport.ExactRequest);
        Assert.Empty(await fixture.ListNativePendingText());
        using var retained = await fixture.ReadMailboxSends();
        Assert.Equal(ProtectedDid2MailboxSendJournal.MaximumEntries, retained.Entries.Count);
        var exact = ProtectedDid2MailboxSendJournal.Encode(retained, sender.Network, sender.LocalAccount, sender.Instance);
        try { Assert.Equal(expectedRoot, SHA256.HashData(exact)); }
        finally { CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(originalRequest); }
        // Full working-set occupancy is staged local metadata, NOT 512 signed
        // grants/deliveries, compaction, renewal or physical endpoint evidence.
    }

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
        // A valid but changed protected root during issuance is not the root
        // this attempt inspected. Keep the issued request pending, not a winner.
        byte[] originalSendRoot = [];
        grants.BeforeReturn = async () => originalSendRoot = await fixture.AdvanceEmptyMailboxSendRevision();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, grants.Calls); Assert.Equal(0, transport.Calls);
        using (var grantState = await fixture.ReadPeerGrantsAsync(own: true))
            Assert.False(ProtectedDid2MailboxGrantJournal.HasWinner(Assert.Single(grantState.Entries).Value));
        using (var changed = await fixture.ReadMailboxSends())
        { Assert.Empty(changed.Entries); Assert.Equal(2UL, changed.Revision); }
        await fixture.RestoreMailboxSendRoot(originalSendRoot);
        CryptographicOperations.ZeroMemory(originalSendRoot); grants.BeforeReturn = null;
        foreach (var point in new[] { Did2MailboxSendFailpoint.BeforeSql, Did2MailboxSendFailpoint.AfterSql,
            Did2MailboxSendFailpoint.BeforePreparedRoot, Did2MailboxSendFailpoint.AfterPreparedRoot, Did2MailboxSendFailpoint.BeforeDispatch })
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
            var expectedPrepared = point is Did2MailboxSendFailpoint.AfterPreparedRoot or Did2MailboxSendFailpoint.BeforeDispatch;
            Assert.Equal(expectedPrepared, Assert.Single(state.Entries).Value.Prepared);
            Assert.Equal(expectedPrepared ? 1UL : 0UL, Assert.Single(state.Floors).Value.HighestCounter);
            Assert.Equal(operation, Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        }
        // BeforeDispatch has already durably reserved its retry lease even
        // though the injected interruption precedes the terminal callback.
        // Do not rely on slow SQL password derivation to expire that lease.
        fixture.Sample += 40; fixture.ProofTime += 40;
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls); Assert.Equal(2, grants.Calls); Assert.True(grants.ExactRetry);
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
        Assert.Equal(2, transport.Calls); Assert.Equal(2, grants.Calls); Assert.True(transport.BuiltHeldFrame);
        Assert.Empty(await fixture.ListNativePendingText());
        var cached = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.False(cached.IngressDispatched); Assert.Equal(durable.Cursor, cached.Cursor); Assert.Equal(2, transport.Calls);
        Assert.Empty(await fixture.ListNativePendingText());
        using (var received = await fixture.ReceiveOwnedMessage(receiver, cipher)) { }
        var history = await fixture.ListOwnedMessages(receiver);
        Assert.Contains(history, message => message.Text == "Owned mailbox delivery 📨" && !message.IsLocalAuthor);
        fixture.RollBackMailboxSqlBeforePreparation();
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(2, transport.Calls); Assert.Equal(2, grants.Calls);
        using (var retained = await fixture.ReadMailboxSends())
            Assert.Equal(1UL, Assert.Single(retained.Entries).Value.Counter);
        await fixture.DeleteMailboxSendRoot();
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(2, transport.Calls);
        CryptographicOperations.ZeroMemory(initial); CryptographicOperations.ZeroMemory(cipher);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OwnedMailboxSend_RemovedWorkingCommitmentCannotSignRolledBackCounter()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xad));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xae)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var operation = Bytes(32, 0xaf);
        using var text = await fixture.PrepareOwnedText(sender, operation, "Independent counter floor");
        using var committed = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, committed.ExactEnvelope.ToArray()) { LoseReply = true };
        using (Did2MailboxSendTestHooks.Push(point =>
        { if (point == Did2MailboxSendFailpoint.BeforeSql) fixture.CaptureMailboxSqlBeforePreparation(); }))
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, grants.Calls); Assert.Equal(1, transport.Calls);
        await fixture.RemoveMailboxWorkingEntryPreservingFloor(sender, operation);
        fixture.RollBackMailboxSqlBeforePreparation(); fixture.Sample += 40; fixture.ProofTime += 40;
        var enteredSigningPreparation = false;
        using (Did2MailboxSendTestHooks.Push(point =>
        { if (point == Did2MailboxSendFailpoint.BeforeSql) enteredSigningPreparation = true; }))
        {
            var error = await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
            Assert.Equal("Owned MCP3 signing differs from the protected exact grant/counter floor.", error.Message);
        }
        Assert.True(enteredSigningPreparation); Assert.Equal(1, grants.Calls); Assert.Equal(1, transport.Calls);
        using var reopened = await fixture.ReadMailboxSends();
        Assert.Equal(1UL, Assert.Single(reopened.Floors).Value.HighestCounter);
        Assert.False(Assert.Single(reopened.Entries).Value.Prepared);
        // This deliberately incomplete cleanup plus encrypted SQL rollback is
        // a corruption fixture, NOT a production compaction/settlement API.
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
        internal async Task RemoveMailboxWorkingEntryPreservingFloor(Did2MessagingSessionScope scope, byte[] operation)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = root.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
                var name = Convert.ToHexString(ProtectedDid2MailboxSendJournal.Key(scope.Hash, operation));
                var entry = Assert.Single(state.Entries).Value; Assert.Equal(name, entry.Name);
                Assert.Equal(2UL, state.MinimumCounter(entry.GrantHash));
                entry.Dispose(); state.Entries.Clear(); state.Revision++;
                next = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, next));
            }
            finally { CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next); }
        }
        internal async Task<byte[]> AdvanceEmptyMailboxSendRevision()
        {
            using var key = await innerStorage.ReadOwnedAsync("deep.store.v2.sql-generation") ?? throw new InvalidOperationException();
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var ownerScope = key.Use(bytes => bytes.Slice(24, 64).ToArray());
            var snapshot = root.Use(bytes => bytes.ToArray());
            byte[] next = [];
            try
            {
                using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
                Assert.Empty(state.Entries); Assert.Equal(1UL, state.Revision);
                state.Revision++; next = ProtectedDid2MailboxSendJournal.Encode(state, Network, ownerScope.AsSpan(0, 32), ownerScope.AsSpan(32));
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, next));
                var saved = snapshot; snapshot = []; return saved;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ownerScope); CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next);
            }
        }
        internal async Task RestoreMailboxSendRoot(byte[] exact)
        {
            // Only the disposable corruption fixture: not a production repair,
            // compaction, rollback exemption or account-owner API.
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var changed = root.Use(bytes => bytes.ToArray());
            try { Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, changed, exact)); }
            finally { CryptographicOperations.ZeroMemory(changed); }
        }
        internal async Task<byte[]> StageRejectedMailboxSend(Did2MessagingSessionScope scope, byte[] requestedOperation,
            ReadOnlyMemory<byte> cipher, int fault)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = root.Use(bytes => bytes.ToArray());
            using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
            Assert.Empty(state.Entries);
            var routeHash = SHA256.HashData(nativeMessagingContact!.Route.ExactRouteClosure.Span);
            if (fault == 1) routeHash[0] ^= 1;
            var retainedCipher = cipher.ToArray();
            if (fault == 2) retainedCipher[0] ^= 1;
            for (var index = 0; index < (fault is 0 or 3 ? ProtectedDid2MailboxSendJournal.MaximumEntries : 1); index++)
            {
                var operation = fault is 0 or 3 ? SHA256.HashData(BitConverter.GetBytes(index)) : requestedOperation;
                state.EnrollScope(operation, operation);
                if (fault == 3) { state.Revision++; continue; }
                var entry = ProtectedDid2MailboxSendJournal.Entry.Pending(scope, operation, operation, routeHash, new()
                {
                    Epoch = 1, MailboxId = new(Bytes(32, 0x16)), PlacementId = new(Bytes(32, 0x17)),
                    OperationId = operation.AsMemory(0, 16), DeduplicationDigest = SHA256.HashData(retainedCipher),
                    CreatedAtUnixSeconds = 1000, ExpiresAtUnixSeconds = 1200, Ciphertext = retainedCipher
                });
                state.Entries.Add(entry.Name, entry); state.Revision++;
            }
            var next = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
            try
            {
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, next));
                return SHA256.HashData(next);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next);
                CryptographicOperations.ZeroMemory(retainedCipher);
            }
        }
        internal async Task<byte[]> FillMailboxWorkingSetAroundPreparedAttempt(Did2MessagingSessionScope scope, ReadOnlyMemory<byte> cipher)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidOperationException();
            var snapshot = root.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var state = ProtectedDid2MailboxSendJournal.Decode(snapshot, scope.Network, scope.LocalAccount, scope.Instance);
                var real = Assert.Single(state.Entries).Value; Assert.True(real.Prepared);
                var routeHash = real.RouteHash.ToArray();
                for (var index = 0; state.Entries.Count < ProtectedDid2MailboxSendJournal.MaximumEntries; index++)
                {
                    var operation = SHA256.HashData(BitConverter.GetBytes(index));
                    state.EnrollScope(operation, operation);
                    var entry = ProtectedDid2MailboxSendJournal.Entry.Pending(scope, operation, operation, routeHash, new()
                    {
                        Epoch = 1, MailboxId = new(Bytes(32, 0x16)), PlacementId = new(Bytes(32, 0x17)),
                        OperationId = operation.AsMemory(0, 16), DeduplicationDigest = SHA256.HashData(cipher.Span),
                        CreatedAtUnixSeconds = 1000, ExpiresAtUnixSeconds = 1200, Ciphertext = cipher
                    });
                    state.Entries.Add(entry.Name, entry); state.Revision++;
                }
                next = ProtectedDid2MailboxSendJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.True(await innerStorage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, snapshot, next));
                return SHA256.HashData(next);
            }
            finally { CryptographicOperations.ZeroMemory(snapshot); CryptographicOperations.ZeroMemory(next); }
        }

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
            // This is the real installed signed PMS2 pair, not a fabricated
            // credential. Prefer the writer as guard in this disposable test
            // so a wrong fallback exit changes the observable entry.
            var network = await context!.GetCurrentForMailboxAsync(route.PlacementCommitment, ct);
            var snapshot = OnionPathCandidateSnapshotFactory.Create(network);
            var guards = await context.Custody.Guards.ReadAsync(ct);
            var next = new EntryGuardState(checked((guards?.Revision ?? 0) + 1), network.NetworkId.Span,
                snapshot.ViewGeneration, snapshot.ViewHash.Span, guards is null ? Bytes(32, 0xa1) : guards.LocalSalt.Span,
                route.Replicas.FirstId.Span, snapshot.Candidates.Select(candidate => candidate.NodeId));
            Assert.Equal(EntryGuardStoreWriteDisposition.Applied,
                (await context.Custody.Guards.CompareExchangeAsync(guards?.Revision, next, ct)).Disposition);
            var codec = new PrivacyRoutingCodec(new OnionEntropyAuthority(context.Custody.Entropy), new OnionKeyAgreementAuthority(new RejectClientReceiveVault()));
            byte[]? firstEntry = null;
            foreach (var selection in new[] { PrivacyMailboxRouteSelection.Primary, PrivacyMailboxRouteSelection.Fallback })
            {
                var paths = context.Source.CreateOwnHeldMailboxPaths(context, selection);
                var attempt = await paths.PrepareOnRouteAsync(OnionOperation.Store, request, route, ct);
                var entry = OnionEntryTransportFactory.Create(attempt.Path);
                Assert.False(entry.Peer.NodeId.Span.SequenceEqual(route.Replicas.FirstId.Span));
                if (firstEntry is null) firstEntry = entry.Peer.NodeId.ToArray(); else Assert.Equal(firstEntry, entry.Peer.NodeId.ToArray());
                using var built = await codec.BuildAsync(attempt.Path, attempt.Request, ct);
                Assert.True(built.Frame.Length > request.Length);
            }
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
