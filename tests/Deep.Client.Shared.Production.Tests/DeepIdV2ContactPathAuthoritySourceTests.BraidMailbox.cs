using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_ExhaustedPeersUseMailboxStoreReadAckWithExactLostReplies()
    {
        // Actual native accounts, SQLCipher, protected Store/read/ACK and held
        // onion preparation. Signed in-process terminals are not physical E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        var pending = new List<(Did2MessagingSessionScope Recipient, byte[] Cipher)>();
        try
        {
            foreach (var (sender, recipient, start) in new[] { (alice, bob, (byte)1), (bob, alice, (byte)50) })
                for (var index = 0; index < 32; index++)
                {
                    using var draft = await fixture.CreateOwnedText(sender, "mailbox recovery pending " + index);
                    var operation = draft.OperationId.ToArray();
                    try
                    {
                        using var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
                        pending.Add((recipient, sent.ExactEnvelope.ToArray()));
                    }
                    catch (CryptographicException error) when
                        (error.Message == "A receive/send gap step omitted mandatory fresh PQ contribution.")
                    { Assert.Equal(31, index); break; }
                }
            Assert.Equal(63, pending.Count); // Prior ContactAccept occupies Bob's remaining data slot.
            var semantic = new[] { (await fixture.ListOwnedMessages(alice)).Count, (await fixture.ListOwnedMessages(bob)).Count };
            var obligations = new[] { (await fixture.ListOwnedReceiptObligations(alice)).Count, (await fixture.ListOwnedReceiptObligations(bob)).Count };
            var deposits = new[] { new OwnedGrantTransport(fixture, ownerOnPrimary: true), new OwnedGrantTransport(fixture, ownerOnPrimary: false) };
            var retrieves = new[] { new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: true),
                new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false) };
            for (var step = 0; step < 4; step++)
            {
                var sender = step % 2 == 0 ? alice : bob;
                var recipient = step % 2 == 0 ? bob : alice;
                var operation = Bytes(32, checked((byte)(200 + step)));
                using var authored = await fixture.SendOwnedBraid(sender, operation);
                var exact = authored.ExactControl.ToArray();
                var floor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
                var store = new OwnedStoreFixture(fixture, sender, operation, exact, ownerOnPrimary: sender.IsInitiator)
                { Cursor = checked((ulong)(step / 2 + 1)), LoseReply = step == 0 };
                if (step == 0)
                {
                    await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
                        fixture.DeliverNativeBraid(sender, operation, deposits[0], store));
                    var original = store.ExactRequest!.ToArray();
                    fixture.ColdReopenBraidStorage(sender);
                    fixture.Sample += 40; fixture.ProofTime += 40; store.LoseReply = false;
                    Assert.True((await fixture.DeliverNativeBraid(sender, operation, deposits[0], store)).IngressDispatched);
                    Assert.Equal(original, store.ExactRequest); Assert.Equal(2, store.Calls);
                }
                else Assert.True((await fixture.DeliverNativeBraid(sender, operation, deposits[sender.IsInitiator ? 0 : 1], store)).IngressDispatched);
                var calls = store.Calls;
                Assert.False((await fixture.DeliverNativeBraid(sender, operation, deposits[sender.IsInitiator ? 0 : 1], store)).IngressDispatched);
                Assert.Equal(calls, store.Calls);
                Assert.Equal(floor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
                Assert.Equal(exact, store.StoredEnvelope!.Ciphertext.ToArray());
                var terminal = new OwnedReadTerminal(fixture, exact, ownerOnPrimary: recipient.IsInitiator)
                { RetainedEnvelope = store.StoredEnvelope, Cursor = store.Cursor,
                    ExpectedAckCounter = checked((ulong)(step / 2 + 1) * 2), LoseAckReply = step == 0 };
                Task<DeepIdV2MailboxSynchronizationResult> Poll() => recipient.IsInitiator
                    ? fixture.SynchronizeNativeSender(retrieves[0], terminal)
                    : fixture.SynchronizeNativeReceiver(retrieves[1], terminal);
                if (step == 0)
                {
                    await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(Poll);
                    var committed = (await fixture.ReadMessagingFloor(recipient)).Exact.ToArray();
                    fixture.ColdReopenBraidStorage(recipient);
                    fixture.Sample += 40; fixture.ProofTime += 40; terminal.LoseAckReply = false;
                    Assert.Equal(1, (await Poll()).DurableTombstones);
                    Assert.Equal(committed, (await fixture.ReadMessagingFloor(recipient)).Exact.ToArray());
                    Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls);
                }
                else
                {
                    var received = await Poll();
                    Assert.Equal(1, received.ProcessedEnvelopes); Assert.Equal(1, received.DurableTombstones);
                    Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(1, terminal.AckCalls);
                }
                Assert.True(terminal.BuiltRetrieveFrame); Assert.True(terminal.BuiltAckFrame);
                using var replay = await fixture.ReceiveOwnedBraid(recipient, exact);
                Assert.Equal(4, replay.Direction);
                CryptographicOperations.ZeroMemory(exact); CryptographicOperations.ZeroMemory(floor);
            }
            Assert.Equal(semantic[0], (await fixture.ListOwnedMessages(alice)).Count);
            Assert.Equal(semantic[1], (await fixture.ListOwnedMessages(bob)).Count);
            Assert.Equal(obligations[0], (await fixture.ListOwnedReceiptObligations(alice)).Count);
            Assert.Equal(obligations[1], (await fixture.ListOwnedReceiptObligations(bob)).Count);
            foreach (var (sender, recipient, id) in new[] { (alice, bob, (byte)210), (bob, alice, (byte)211) })
            {
                using var draft = await fixture.CreateOwnedText(sender, "fresh after mailbox Braid");
                using var sent = await fixture.SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
                using var received = await fixture.ReceiveOwnedMessage(recipient, sent.ExactEnvelope.ToArray());
            }
            foreach (var item in pending)
            { using var received = await fixture.ReceiveOwnedMessage(item.Recipient, item.Cipher); }
        }
        finally { foreach (var item in pending) CryptographicOperations.ZeroMemory(item.Cipher); }
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_FirstObsoleteControlAckSurvivesRootRetirementWithoutClaimingReceiveOrErasingUnknownStore()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        var operation = Bytes(32, 200);
        using var authored = await fixture.SendOwnedBraid(alice, operation);
        var exact = authored.ExactControl.ToArray();
        try
        {
            var deposit = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
            var store = new OwnedStoreFixture(fixture, alice, operation, exact) { LoseReply = true };
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() =>
                fixture.DeliverNativeBraid(alice, operation, deposit, store));
            var originalMau = store.ExactRequest!.ToArray();
            // The actual ordinary exchange completes output1 without receiving
            // the DBR2 operation. Alice's last data still uses sending epoch0,
            // so the first ACK must use installed-output + retained-root MAC.
            await SendBraidHistoryText(fixture, alice, bob, 1);
            await SendBraidHistoryText(fixture, bob, alice, 50);
            await SendBraidHistoryText(fixture, alice, bob, 2);
            await SendBraidHistoryText(fixture, bob, alice, 51);
            var before = (await fixture.ReadMessagingFloor(bob)).Exact.ToArray();
            var messages = (await fixture.ListOwnedMessages(bob)).Count;
            var obligations = (await fixture.ListOwnedReceiptObligations(bob)).Count;
            var bad = exact.ToArray(); bad[^1] ^= 1;
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveNativeBraidMailbox(bob, bad));
            Assert.Equal(before, (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
            var retrieval = new OwnedGrantTransport(fixture, selfRetrieve: true, ownerOnPrimary: false);
            var terminal = new OwnedReadTerminal(fixture, exact) { RetainedEnvelope = store.StoredEnvelope, LoseAckReply = true };
            await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.SynchronizeNativeReceiver(retrieval, terminal));
            Assert.Equal(before, (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
            Assert.Equal(messages, (await fixture.ListOwnedMessages(bob)).Count);
            Assert.Equal(obligations, (await fixture.ListOwnedReceiptObligations(bob)).Count);
            using (var pendingRead = await fixture.ReadPeerMailboxReads())
            { Assert.Equal(6, pendingRead.Phase); Assert.NotEmpty(pendingRead.Active!.AckBody); }
            // Real direction2 peer data proves purpose completion and moves
            // both data frontiers before the next output retires original root0.
            await SendBraidHistoryText(fixture, alice, bob, 3);
            await SendBraidHistoryText(fixture, bob, alice, 52);
            foreach (var (sender, recipient, id) in new[] { (bob, alice, (byte)201), (alice, bob, (byte)202),
                         (bob, alice, (byte)203), (alice, bob, (byte)204) })
            {
                using var sent = await fixture.SendOwnedBraid(sender, Bytes(32, id));
                using var received = await fixture.ReceiveOwnedBraid(recipient, sent.ExactControl.ToArray());
            }
            await fixture.RequireBraidNativeEpochsForMailboxTest(bob, current: 2, send: 1, receive: 1);
            var retiredFloor = (await fixture.ReadMessagingFloor(bob)).Exact.ToArray();
            messages = (await fixture.ListOwnedMessages(bob)).Count;
            obligations = (await fixture.ListOwnedReceiptObligations(bob)).Count;
            fixture.ColdReopenBraidStorage(bob);
            fixture.Sample += 40; fixture.ProofTime += 40; terminal.LoseAckReply = false;
            var completed = await fixture.SynchronizeNativeReceiver(retrieval, terminal);
            Assert.Equal(1, completed.DurableTombstones); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(2, terminal.AckCalls);
            Assert.Equal(retiredFloor, (await fixture.ReadMessagingFloor(bob)).Exact.ToArray());
            Assert.Equal(messages, (await fixture.ListOwnedMessages(bob)).Count);
            Assert.Equal(obligations, (await fixture.ListOwnedReceiptObligations(bob)).Count);
            // Completed native purpose is not non-delivery/Store settlement.
            // No new ingress is allowed, but the unknown request remains exact.
            var calls = store.Calls; var issues = deposit.Calls;
            await Assert.ThrowsAsync<IOException>(() => fixture.DeliverNativeBraid(alice, operation, deposit, store));
            Assert.Equal(calls, store.Calls); Assert.Equal(issues, deposit.Calls);
            using var pendingSend = await fixture.ReadMailboxSends(own: true);
            var entry = pendingSend.Current(alice.Hash, operation)!;
            Assert.NotNull(entry); Assert.True(entry.Prepared); Assert.False(entry.Closed);
            Assert.Equal(SHA256.HashData(originalMau), entry.MauHash.ToArray());
            Assert.Equal(SHA256.HashData(exact), entry.EnvelopeHash.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private sealed partial class Fixture
    {
        internal async Task RequireBraidNativeEpochsForMailboxTest(Did2MessagingSessionScope scope,
            ulong current, ulong send, ulong receive)
        {
            var selected = scope.IsInitiator ? storage : peerStorage;
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var path = Path.Combine(folder, "deep-store-v2-account.dsv2");
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(folder, "deep-store-v2-account.lock"));
            var accountOwner = new ProtectedDeepIdV2AccountOwner(selected, accountLease, path, Network, 1);
            using var account = await accountOwner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException("Fixture account absent.");
            using var held = await accountLease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(selected, path, account, scope, default);
            var floor = await opened.Custody.ReconcileAsync(default);
            using var native = opened.Sql.ReadVerifiedLatest(floor);
            var epochs = native.Use(bytes =>
            {
                Assert.True(bytes.Length > 536 + 1060); Assert.True(bytes.Slice(536, 4).SequenceEqual("TRC1"u8));
                Assert.Equal((byte)2, bytes[540]); var component = bytes[536..];
                Assert.Equal((byte)2, component[392]);
                // Numeric metadata only. Never export actual native keys/TRS.
                return new[] { BinaryPrimitives.ReadUInt64BigEndian(component[360..]),
                    BinaryPrimitives.ReadUInt64BigEndian(component[368..]), BinaryPrimitives.ReadUInt64BigEndian(component[376..]),
                    BinaryPrimitives.ReadUInt64BigEndian(component[400..]), BinaryPrimitives.ReadUInt64BigEndian(component[728..]) };
            });
            Assert.Equal(new[] { current, send, receive, 1UL, 2UL }, epochs); held.RequireActive();
        }

        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, IDid2MailboxGrantTransport,
            IDid2OwnedMailboxTransportFactory, Task<ClientMailboxStoreResult>>? deliverNativeBraid;
        private Func<Did2MessagingSessionScope, ReadOnlyMemory<byte>, Task<Did2MessagingSessionScope>>? receiveNativeBraidMailbox;
        internal Task<Did2MessagingSessionScope> ReceiveNativeBraidMailbox(Did2MessagingSessionScope endpoint,
            ReadOnlyMemory<byte> exact) => receiveNativeBraidMailbox!(endpoint, exact);
        internal Task<ClientMailboxStoreResult> DeliverNativeBraid(Did2MessagingSessionScope scope,
            ReadOnlyMemory<byte> operation, IDid2MailboxGrantTransport grants, IDid2OwnedMailboxTransportFactory terminal) =>
            deliverNativeBraid!(scope, operation, grants, terminal);
    }
}
