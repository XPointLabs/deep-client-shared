using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OutboxCompaction_CachedEncryptionRequiresExactRetainedHistoryWithoutNewRatchet()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        using (var reply = await fixture.PrepareOwnedText(receiver, Bytes(32, 0xc1), "independent recipient receipt work"))
        using (var sentReply = await fixture.SendOwnedMessage(receiver, reply.OperationId.ToArray(), ApplicationCoreCodec.DecodeDmc2(reply.ExactDmc2.Span)))
        using (var receivedReply = await fixture.ReceiveOwnedMessage(sender, sentReply.ExactEnvelope.ToArray())) { }
        var receiptBefore = Assert.Single(await fixture.ListOwnedReceiptObligations(sender)).EventHash.ToArray();
        var operation = Bytes(32, 0xc0); byte[] exact, cipher;
        using (var text = await fixture.PrepareOwnedText(sender, operation, "exact retained ciphertext"))
        {
            exact = text.ExactDmc2.ToArray();
            using var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(exact));
            cipher = sent.ExactEnvelope.ToArray();
        }
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var transport = new OwnedStoreFixture(fixture, sender, operation, cipher);
        _ = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
        // Selection, not just cached replay, must work after original issuer
        // expiry and a signed network successor. It makes no new dispatch.
        await fixture.AdvanceOriginalStoreEpochForTestAsync(2_100);
        fixture.ColdReopenCompactionStorage();
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(sender, async () =>
        {
            using var selected = await fixture.PrepareNativeOutboxCompaction(sender);
        });
        var proofsBeforeCleanup = fixture.ProofRequests;
        await fixture.CompactNativeOrdinaryOutbox(sender, default);
        Assert.Equal(proofsBeforeCleanup + 1, fixture.ProofRequests); // Own proof only; no peer re-admission.
        using (var sends = await fixture.ReadMailboxSends())
        { Assert.Empty(sends.Entries); Assert.Equal(1UL, Assert.Single(sends.Floors).Value.HighestCounter); }
        Assert.Equal(receiptBefore, Assert.Single(await fixture.ListOwnedReceiptObligations(sender)).EventHash.ToArray());
        var stable = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var application = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var root = await fixture.ReadAuthoredRootDigestAsync();
        using (var replay = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(exact)))
            Assert.Equal(cipher, replay.ExactEnvelope.ToArray());
        Assert.Equal(stable, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync());
        var changed = exact.ToArray(); changed[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(changed)));
        Assert.Equal(stable, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        var cached = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
        Assert.False(cached.IngressDispatched); Assert.Equal(1, transport.Calls);
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        await fixture.AssertCompactedStoreRejectsMissingOrChangedCoordinatorStatement(sender,
            () => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        await fixture.AssertCompactedStoreRejectsChangedPublicEvidence(sender,
            () => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(1, transport.Calls);
        Assert.Equal(stable, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(application, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync());
        await fixture.RemoveRetainedAuthoredHistoryForTest(sender);
        var missing = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(exact)));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.DeliverNativeMessage(sender, operation, grants, transport));
        Assert.Equal(stable, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(missing, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync()); Assert.Equal(1, transport.Calls);
        foreach (var bytes in new[] { exact, cipher, stable, application, root, changed, missing }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2OutboxCompaction_EncryptedColdRecoveryAllHandoversPreservesHistoryCountersAndCachedStore()
    {
        // Actual account/ratchet/SQLCipher/disk custody and signed native Store
        // receipts; synthetic endpoint/clock fixture, NOT physical device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true,
            longMailboxWindow: true, initialMailboxAuthorityExpiry: 2_000);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true); var index = 0;
        foreach (var point in Enum.GetValues<Did2CompactionFailpoint>())
        {
            var operation = Bytes(32, checked((byte)(0xc0 + index)));
            byte[] cipher;
            using (var text = await fixture.PrepareOwnedText(sender, operation, "retained history after outbox cleanup " + index))
            {
                Assert.Equal(checked((ulong)(3 + index)), text.SenderSequence);
                using var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span));
                cipher = sent.ExactEnvelope.ToArray();
            }
            var transport = new OwnedStoreFixture(fixture, sender, operation, cipher);
            var durable = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
            fixture.AdvanceSyntheticMailboxClockPast(transport.DurableTimeForFixture);
            var beforeFloor = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
            using (var sends = await fixture.ReadMailboxSends())
            { Assert.Single(sends.Entries); Assert.Equal(checked((ulong)index + 1), Assert.Single(sends.Floors).Value.HighestCounter); }
            byte[] expectedAfter;
            using (var selected = await fixture.PrepareNativeOutboxCompaction(sender)) expectedAfter = selected.Plan.SqlAfter.ToArray();
            var row = await fixture.CaptureOrdinaryWorkingRow(sender, operation);
            using (Did2CompactionTestHooks.Push(actual => { if (actual == point) throw new IOException("Injected ordinary compaction handover."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CompactNativeOrdinaryOutbox(sender, default));
            if (point == Did2CompactionFailpoint.AfterStage)
                await fixture.AssertOrdinaryPreparedDependenciesRejectMissingAndChangedState(sender, operation);
            if (point == Did2CompactionFailpoint.AfterSqlRecorded)
            {
                await fixture.RestoreOrdinaryWorkingRow(sender, row);
                await fixture.AssertOrdinaryRecoveryRefusalUnchanged(sender);
                await fixture.DeleteOrdinaryWorkingRow(sender, operation);
            }
            fixture.ColdReopenCompactionStorage();
            if (point == Did2CompactionFailpoint.AfterHistoryAdopted)
            {
                // The first fault left Ordinary adopted and Send original.
                // Cold recovery must then adopt only Send, and survive a
                // second fault before disposing either successor part.
                using (Did2CompactionTestHooks.Push(actual => { if (actual == point) throw new IOException("Injected send-root adoption interruption."); }))
                    await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
                fixture.ColdReopenCompactionStorage();
            }
            await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            await fixture.AssertSenderCompactionIdle(sender);
            Assert.Equal(beforeFloor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(expectedAfter, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            Assert.Empty(await fixture.ListNativePendingText());
            using (var sends = await fixture.ReadMailboxSends())
            { Assert.Empty(sends.Entries); Assert.Equal(checked((ulong)index + 1), Assert.Single(sends.Floors).Value.HighestCounter); }
            Assert.Equal(index + 1, (await fixture.ListOwnedMessages(sender)).Count);
            using (var received = await fixture.ReceiveOwnedMessage(receiver, cipher)) { }
            Assert.Equal(index + 1, (await fixture.ListOwnedMessages(receiver)).Count);
            var cached = await fixture.DeliverNativeMessage(sender, operation, grants, transport);
            Assert.False(cached.IngressDispatched); Assert.Equal(durable.Cursor, cached.Cursor); Assert.Equal(1, transport.Calls);
            Assert.Equal(expectedAfter, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.PrepareOwnedText(sender, operation, "cannot remint compacted operation"));
            Assert.Equal(expectedAfter, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            foreach (var bytes in row.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(cipher); CryptographicOperations.ZeroMemory(beforeFloor); CryptographicOperations.ZeroMemory(expectedAfter);
            index++;
        }

        var pendingOperation = Bytes(32, 0xd0); byte[] pendingCipher;
        using (var text = await fixture.PrepareOwnedText(sender, pendingOperation, "unknown is never eligible"))
        using (var sent = await fixture.SendOwnedMessage(sender, pendingOperation, ApplicationCoreCodec.DecodeDmc2(text.ExactDmc2.Span)))
            pendingCipher = sent.ExactEnvelope.ToArray();
        var pendingTransport = new OwnedStoreFixture(fixture, sender, pendingOperation, pendingCipher) { LoseReply = true };
        await Assert.ThrowsAsync<ClientMailboxDispatchOutcomeUnknownException>(() => fixture.DeliverNativeMessage(sender, pendingOperation, grants, pendingTransport));
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.PrepareNativeOutboxCompaction(sender));
        using (var sends = await fixture.ReadMailboxSends()) Assert.Single(sends.Entries);
        // Match the real bounded outcome-unknown retry lease; an immediate
        // second dispatch is intentionally refused, not a cleanup defect.
        fixture.Sample += 40; fixture.ProofTime += 40;
        pendingTransport.LoseReply = false; _ = await fixture.DeliverNativeMessage(sender, pendingOperation, grants, pendingTransport);
        fixture.AdvanceSyntheticMailboxClockPast(pendingTransport.DurableTimeForFixture);
        var unchanged = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        var stable = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        using (var cancel = new CancellationTokenSource())
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterStage) cancel.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CompactNativeOrdinaryOutbox(sender, cancel.Token));
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterPartsDeleted) throw new IOException("Injected ordinary abort clear."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().AbandonUncommittedOwnedOrdinaryOutboxAsync(default));
        fixture.ColdReopenCompactionStorage(); await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertSenderCompactionIdle(sender);
        Assert.Equal(unchanged, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        using (var cancel = new CancellationTokenSource())
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterSql) cancel.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CompactNativeOrdinaryOutbox(sender, cancel.Token));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SenderCompactionOwner().AbandonUncommittedOwnedOrdinaryOutboxAsync(default));
        fixture.ColdReopenCompactionStorage(); await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertSenderCompactionIdle(sender);
        Assert.Equal(stable, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Empty(await fixture.ListNativePendingText());
        Assert.Equal(7, (await fixture.ListOwnedMessages(sender)).Count);
        Assert.Equal(2, pendingTransport.Calls);
        await fixture.RetireUsedOrdinarySendFloorAfterExclusionAsync(sender);
        // Real verified floor retirement already happened above. Removing
        // acquisition custody here is fault injection, NOT deletion permission.
        await fixture.RemovePastGrantWorkingCustodyForTest(sender);
        fixture.ColdReopenCompactionStorage();
        var retainedStore = await fixture.DeliverNativeMessage(sender, pendingOperation, grants, pendingTransport);
        Assert.False(retainedStore.IngressDispatched); Assert.Equal(2, pendingTransport.Calls);
        Assert.Equal(1, grants.Calls);
        using (var sends = await fixture.ReadMailboxSends()) { Assert.Empty(sends.Entries); Assert.Empty(sends.Floors); }
        using (var grantState = await fixture.ReadPeerGrantsAsync(own: true)) Assert.Empty(grantState.Entries);
        CryptographicOperations.ZeroMemory(pendingCipher); CryptographicOperations.ZeroMemory(unchanged); CryptographicOperations.ZeroMemory(stable);
    }

    private sealed partial class Fixture
    {
        internal async Task RemovePastGrantWorkingCustodyForTest(Did2MessagingSessionScope scope)
        {
            var fileLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await fileLease.AcquireAsync(default);
            using var raw = await storage.ReadOwnedAsync(ProtectedDid2MailboxGrantJournal.Slot) ?? throw new InvalidDataException();
            var original = raw.Use(bytes => bytes.ToArray()); byte[] next = [];
            try
            {
                using var state = ProtectedDid2MailboxGrantJournal.Decode(original, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.Single(state.Entries);
                foreach (var entry in state.Entries.Values) CryptographicOperations.ZeroMemory(entry);
                state.Entries.Clear(); state.Selections.Clear(); state.Revision = checked(state.Revision + 1);
                next = ProtectedDid2MailboxGrantJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
                Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxGrantJournal.Slot, original, next));
            }
            finally { CryptographicOperations.ZeroMemory(original); CryptographicOperations.ZeroMemory(next); }
        }

        internal async Task AssertCompactedStoreRejectsChangedPublicEvidence(Did2MessagingSessionScope scope,
            Func<Task> replay)
        {
            object[] row = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT * FROM mailbox_store_public_evidence;";
                using var reader = read.ExecuteReader(); Assert.True(reader.Read());
                row = new object[reader.FieldCount]; reader.GetValues(row); Assert.Equal(11, row.Length); Assert.False(reader.Read());
            });
            try
            {
                var columns = new[] { "account_scope", "logical_id", "exact_pma", "exact_view", "first_descriptor", "second_descriptor" };
                if (((byte[])row[8]).Length != 0) columns = [.. columns, "original_dcr", "original_route", "original_peer_adp"];
                foreach (var mutation in Enumerable.Range(-2, columns.Length + 2))
                {
                    await WithAuthoredApplicationConnectionAsync(scope, connection =>
                    {
                        using var write = connection.CreateCommand();
                        if (mutation == -2) write.CommandText = "DELETE FROM mailbox_store_public_evidence WHERE operation_id=$op;";
                        else if (mutation == -1) write.CommandText = "UPDATE mailbox_store_public_evidence SET first_descriptor=second_descriptor,second_descriptor=first_descriptor WHERE operation_id=$op;";
                        else
                        {
                            var changed = ((byte[])row[mutation + 2]).ToArray(); changed[^1] ^= 1;
                            write.CommandText = "UPDATE mailbox_store_public_evidence SET " + columns[mutation] + "=$value WHERE operation_id=$op;";
                            write.Parameters.AddWithValue("$value", changed);
                        }
                        write.Parameters.AddWithValue("$op", row[1]); Assert.Equal(1, write.ExecuteNonQuery());
                    });
                    var before = await ReadCompleteOrdinaryApplicationProjection(scope);
                    try
                    {
                        var error = await Record.ExceptionAsync(replay);
                        Assert.True(error is CryptographicException or FormatException or InvalidDataException,
                            error?.GetType().Name ?? "Changed public evidence was accepted");
                        Assert.Equal(before, await ReadCompleteOrdinaryApplicationProjection(scope));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(before);
                        await WithAuthoredApplicationConnectionAsync(scope, connection =>
                        {
                            using var tx = connection.BeginTransaction();
                            using var delete = connection.CreateCommand(); delete.Transaction = tx;
                            delete.CommandText = "DELETE FROM mailbox_store_public_evidence WHERE operation_id=$op;";
                            delete.Parameters.AddWithValue("$op", row[1]); delete.ExecuteNonQuery();
                            using var insert = connection.CreateCommand(); insert.Transaction = tx;
                            insert.CommandText = "INSERT INTO mailbox_store_public_evidence VALUES(" + string.Join(",", Enumerable.Range(0, row.Length).Select(index => "$v" + index)) + ");";
                            for (var index = 0; index < row.Length; index++) insert.Parameters.AddWithValue("$v" + index, row[index]);
                            Assert.Equal(1, insert.ExecuteNonQuery()); tx.Commit();
                        });
                    }
                }
            }
            finally { foreach (var bytes in row.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes); }
        }

        internal async Task AssertCompactedStoreRejectsMissingOrChangedCoordinatorStatement(
            Did2MessagingSessionScope scope, Func<Task<ClientMailboxStoreResult>> replay)
        {
            object[] row = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand();
                read.CommandText = "SELECT installation_scope,statement_key,statement_digest,expires_at FROM client_mailbox_coordinator_journal;";
                using var reader = read.ExecuteReader(); Assert.True(reader.Read());
                row = new object[reader.FieldCount]; reader.GetValues(row); Assert.False(reader.Read());
            });
            try
            {
                foreach (var mutation in new[]
                {
                    "DELETE FROM client_mailbox_coordinator_journal WHERE statement_key=$key;",
                    "UPDATE client_mailbox_coordinator_journal SET statement_digest=zeroblob(32) WHERE statement_key=$key;",
                    "UPDATE client_mailbox_coordinator_journal SET expires_at=zeroblob(8) WHERE statement_key=$key;"
                })
                {
                    await WithAuthoredApplicationConnectionAsync(scope, connection =>
                    {
                        using var write = connection.CreateCommand(); write.CommandText = mutation;
                        write.Parameters.AddWithValue("$key", row[1]); Assert.Equal(1, write.ExecuteNonQuery());
                    });
                    var before = await ReadCompleteOrdinaryApplicationProjection(scope);
                    try
                    {
                        await Assert.ThrowsAsync<CryptographicException>(replay);
                        Assert.Equal(before, await ReadCompleteOrdinaryApplicationProjection(scope));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(before);
                        await WithAuthoredApplicationConnectionAsync(scope, connection =>
                        {
                            using var tx = connection.BeginTransaction();
                            using var delete = connection.CreateCommand(); delete.Transaction = tx;
                            delete.CommandText = "DELETE FROM client_mailbox_coordinator_journal WHERE statement_key=$key;";
                            delete.Parameters.AddWithValue("$key", row[1]); delete.ExecuteNonQuery();
                            using var insert = connection.CreateCommand(); insert.Transaction = tx;
                            insert.CommandText = "INSERT INTO client_mailbox_coordinator_journal(installation_scope,statement_key,statement_digest,expires_at) VALUES($v0,$v1,$v2,$v3);";
                            for (var index = 0; index < row.Length; index++) insert.Parameters.AddWithValue("$v" + index, row[index]);
                            Assert.Equal(1, insert.ExecuteNonQuery()); tx.Commit();
                        });
                    }
                }
            }
            finally { foreach (var bytes in row.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes); }
        }

        internal async Task RetireUsedOrdinarySendFloorAfterExclusionAsync(Did2MessagingSessionScope scope)
        {
            using (var sends = await ReadMailboxSends())
            { Assert.Empty(sends.Entries); Assert.Equal(7UL, Assert.Single(sends.Floors).Value.HighestCounter); }
            byte[] selector; ulong ceiling;
            using (var grants = await ReadPeerGrantsAsync(own: true))
            {
                var entry = Assert.Single(grants.Entries).Value;
                selector = Convert.FromHexString(ProtectedDid2MailboxGrantJournal.Acquisition(entry));
                ceiling = ProtectedDid2MailboxGrantJournal.PossibleGrantExpiry(entry);
            }
            var nativeBefore = (await ReadMessagingFloor(scope)).Exact.ToArray();
            var applicationBefore = await ReadCompleteOrdinaryApplicationProjection(scope);
            await AdvanceNetworkAsync(expiry: 6_000); AuthorSignedEpochAdvance();
            var next = checked(ceiling + 5); Sample = checked(Sample + next - ProofTime); ProofTime = next;
            var account = ReopenAccount();
            using (var exclusion = await account.OpenMailboxEpochExclusionAsync(selector, Source(account)))
                await exclusion.RetireIdleMailboxCounterFloorAsync();
            ColdReopenCompactionStorage(); await SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            using (var sends = await ReadMailboxSends()) { Assert.Empty(sends.Entries); Assert.Empty(sends.Floors); }
            Assert.Equal(nativeBefore, (await ReadMessagingFloor(scope)).Exact.ToArray());
            Assert.Equal(applicationBefore, await ReadCompleteOrdinaryApplicationProjection(scope));
            Assert.Equal(7, (await ListOwnedMessages(scope)).Count);
            foreach (var bytes in new[] { selector, nativeBefore, applicationBefore }) CryptographicOperations.ZeroMemory(bytes);
        }

        internal Task RemoveRetainedAuthoredHistoryForTest(Did2MessagingSessionScope scope) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var delete = connection.CreateCommand();
                delete.CommandText = "DELETE FROM authenticated_dmc2_inbox WHERE conversation_id=$conversation AND author_account_id=$account AND author_device_id=$device AND content_kind=$kind;";
                delete.Parameters.AddWithValue("$conversation", scope.Conversation.ToArray()); delete.Parameters.AddWithValue("$account", scope.LocalAccount.ToArray());
                delete.Parameters.AddWithValue("$device", scope.LocalDevice.ToArray()); delete.Parameters.AddWithValue("$kind", (int)Dmc2ContentKind.MessageCreate);
                Assert.Equal(1, delete.ExecuteNonQuery());
            });
        internal void AdvanceSyntheticMailboxClockPast(ulong durableTime)
        {
            // Installation uses a conservative elapsed upper bound. The
            // synthetic proof source must advance too, not freeze before its
            // own fixture-signed durable receipt and weaken runtime checks.
            var upper = checked(CurrentProofTime + 5);
            if (upper > durableTime) return;
            var delta = checked(durableTime - upper + 1); Sample = checked(Sample + delta); ProofTime = checked(ProofTime + delta);
        }
        internal Task CompactNativeOrdinaryOutbox(Did2MessagingSessionScope scope, CancellationToken ct)
        {
            var account = scope.IsInitiator ? ReopenAccount() : ReopenGrantReader();
            var source = scope.IsInitiator ? Source(account) : GrantReaderSource(account);
            return account.CompactOwnOrdinaryOutboxAsync(scope, 32, source, ct);
        }
        internal async Task<byte[]> ReadCompleteOrdinaryApplicationProjection(Did2MessagingSessionScope scope)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var lease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(secure,
                Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), scope, held, lease, default);
            return await application.ReadCompleteOrdinaryCompactionProjectionAsync(scope, default);
        }
        internal async Task<object[]> CaptureOrdinaryWorkingRow(Did2MessagingSessionScope scope, byte[] operation)
        {
            object[] result = [];
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT * FROM direct_text_outbox WHERE operation_id=$operation;";
                read.Parameters.AddWithValue("$operation", operation); using var reader = read.ExecuteReader(); Assert.True(reader.Read());
                result = new object[reader.FieldCount]; reader.GetValues(result); Assert.False(reader.Read());
            });
            return result;
        }
        internal Task RestoreOrdinaryWorkingRow(Did2MessagingSessionScope scope, object[] row) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var insert = connection.CreateCommand(); insert.CommandText = "INSERT INTO direct_text_outbox VALUES(" + string.Join(",", Enumerable.Range(0, row.Length).Select(index => "$v" + index)) + ");";
                for (var index = 0; index < row.Length; index++) insert.Parameters.AddWithValue("$v" + index, row[index]);
                Assert.Equal(1, insert.ExecuteNonQuery());
            });
        internal Task DeleteOrdinaryWorkingRow(Did2MessagingSessionScope scope, byte[] operation) =>
            WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var delete = connection.CreateCommand(); delete.CommandText = "DELETE FROM direct_text_outbox WHERE operation_id=$operation;";
                delete.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, delete.ExecuteNonQuery());
            });
        internal async Task AssertOrdinaryRecoveryRefusalUnchanged(Did2MessagingSessionScope scope)
        {
            var before = await ReadAuthoredApplicationDigestAsync(scope);
            var root = await ReadAuthoredRootDigestAsync();
            using var send = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            var sendHash = send.Use(bytes => SHA256.HashData(bytes));
            using var originalPlan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException("Fixture plan absent.");
            var planHash = originalPlan.Use(bytes => SHA256.HashData(bytes));
            var error = await Record.ExceptionAsync(() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
            Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful recovery");
            Assert.Equal(before, await ReadAuthoredApplicationDigestAsync(scope)); Assert.Equal(root, await ReadAuthoredRootDigestAsync());
            using var retainedSend = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException();
            Assert.Equal(sendHash, retainedSend.Use(bytes => SHA256.HashData(bytes)));
            using var retainedPlan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException("Fixture plan disappeared.");
            Assert.Equal(planHash, retainedPlan.Use(bytes => SHA256.HashData(bytes)));
            CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(root);
            CryptographicOperations.ZeroMemory(planHash);
            CryptographicOperations.ZeroMemory(sendHash);
        }
        internal async Task AssertOrdinaryPreparedDependenciesRejectMissingAndChangedState(Did2MessagingSessionScope scope, byte[] operation)
        {
            // Send adopted before Ordinary is a non-prefix root mixture, not
            // evidence permitting SQL deletion or repair of the other root.
            using (var originalSend = await storage.ReadOwnedAsync(ProtectedDid2MailboxSendJournal.Slot) ?? throw new InvalidDataException())
            {
                var before = originalSend.Use(bytes => bytes.ToArray()); byte[] after;
                var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
                using (var held = await lease.AcquireAsync(default))
                {
                    var plans = new ProtectedDid2CompactionPlan(storage, lease, scope.Network, scope.LocalAccount, scope.Instance);
                    using var plan = await plans.ReadAsync(held, default);
                    using var parts = await plans.ReadSuccessorsAsync(plan, held, default);
                    using var successor = parts.Use(bytes => plan.OwnSuccessor(1, bytes));
                    after = successor.Use(bytes => bytes.ToArray());
                }
                var replaced = false;
                try
                {
                    replaced = await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, before, after);
                    Assert.True(replaced);
                    await AssertOrdinaryRecoveryRefusalUnchanged(scope);
                }
                finally
                {
                    if (replaced) Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MailboxSendJournal.Slot, after, before));
                    CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(after);
                }
            }
            foreach (var slot in new[] { ProtectedDid2CompactionPlan.PartSlot(0), ProtectedDid2MessagingPeerBootstrap.Slot(scope), SqliteDeepIdV2AccountGeneration.ApplicationStateSlot })
            {
                using var original = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException("Fixture dependency absent.");
                var bytes = original.Use(raw => raw.ToArray());
                try
                {
                    await storage.DeleteBatchAsync([slot]); await AssertOrdinaryRecoveryRefusalUnchanged(scope);
                }
                finally { await storage.WriteBatchAsync([new DeepSecureStorageWrite(slot, bytes)]); CryptographicOperations.ZeroMemory(bytes); }
            }
            // Same-shape selected payload substitution must be rejected before
            // destructive SQL; this is a hostile fixture, never a repair API.
            var row = await CaptureOrdinaryWorkingRow(scope, operation);
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var update = connection.CreateCommand(); update.CommandText = "UPDATE direct_text_outbox SET exact_dmc2=zeroblob(length(exact_dmc2)) WHERE operation_id=$operation;";
                update.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, update.ExecuteNonQuery());
            });
            try { await AssertOrdinaryRecoveryRefusalUnchanged(scope); }
            finally { await DeleteOrdinaryWorkingRow(scope, operation); await RestoreOrdinaryWorkingRow(scope, row); foreach (var bytes in row.OfType<byte[]>()) CryptographicOperations.ZeroMemory(bytes); }
        }
    }
}
