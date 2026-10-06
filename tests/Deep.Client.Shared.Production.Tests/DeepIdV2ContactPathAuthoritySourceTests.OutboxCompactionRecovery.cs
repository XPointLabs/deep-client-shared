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
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
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
        await fixture.CompactNativeOrdinaryOutbox(sender, default);
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
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
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
            await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
            await fixture.AssertSenderCompactionIdle(sender);
            Assert.Equal(beforeFloor, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            Assert.Equal(expectedAfter, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
            Assert.Empty(await fixture.ListNativePendingText());
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
        CryptographicOperations.ZeroMemory(pendingCipher); CryptographicOperations.ZeroMemory(unchanged); CryptographicOperations.ZeroMemory(stable);
    }

    private sealed partial class Fixture
    {
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
            var account = ReopenAccount(); return account.CompactOwnOrdinaryOutboxAsync(scope, 32, Source(account), ct);
        }
        internal async Task<byte[]> ReadCompleteOrdinaryApplicationProjection(Did2MessagingSessionScope scope)
        {
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var application = await SqliteDeepIdV2AccountGeneration.OpenExistingApplicationForCompactionUnderLeaseAsync(storage,
                Path.Combine(directory, "deep-store-v2-account.dsv2"), scope, held, lease, default);
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
            using var originalPlan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException("Fixture plan absent.");
            var planHash = originalPlan.Use(bytes => SHA256.HashData(bytes));
            var error = await Record.ExceptionAsync(() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
            Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "Unexpected successful recovery");
            Assert.Equal(before, await ReadAuthoredApplicationDigestAsync(scope)); Assert.Equal(root, await ReadAuthoredRootDigestAsync());
            using var retainedPlan = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException("Fixture plan disappeared.");
            Assert.Equal(planHash, retainedPlan.Use(bytes => SHA256.HashData(bytes)));
            CryptographicOperations.ZeroMemory(before); CryptographicOperations.ZeroMemory(root);
            CryptographicOperations.ZeroMemory(planHash);
        }
        internal async Task AssertOrdinaryPreparedDependenciesRejectMissingAndChangedState(Did2MessagingSessionScope scope, byte[] operation)
        {
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
