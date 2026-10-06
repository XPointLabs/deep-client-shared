using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Compaction_ActualEncryptedOwnerAllHandoversColdResumeAndCancellationPreserveExactEvents()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        byte[] acceptance;
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            acceptance = sent.ExactEnvelope.ToArray();
        using (var received = await fixture.ReceiveOwnedMessage(sender, acceptance)) { }

        var ordinal = (await fixture.ReadMessagingFloor(sender)).Ordinal;
        var index = 0;
        foreach (var point in Enum.GetValues<Did2CompactionFailpoint>())
        {
            var before = await fixture.ReadMessagingFloor(sender);
            var rows = index == 0 ? checked((int)before.Ordinal) : 1;
            var predecessorRows = await fixture.CaptureCompactionPrefixRows(sender, rows);
            using (Did2CompactionTestHooks.Push(actual => { if (actual == point) throw new IOException("Injected compaction handover."); }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CompactSenderPrefix(sender, rows, default));
            if (point == Did2CompactionFailpoint.AfterStage)
                await fixture.AssertPreparedCompactionRejectsMissingPartsGuardAndSqlSubstitution(sender);
            if (point == Did2CompactionFailpoint.AfterSqlRecorded)
            {
                // Hostile exact SQL rollback after the durable commit marker.
                // These fixture-only writes are not production rehydration.
                await fixture.RestoreCompactionPrefixRows(sender, predecessorRows);
                await fixture.AssertCompactionRefusalDoesNotMutate(sender);
                await fixture.RemoveRestoredCompactionPrefixRows(sender, predecessorRows);
            }
            foreach (var row in predecessorRows)
            { CryptographicOperations.ZeroMemory(row.Predecessor); CryptographicOperations.ZeroMemory(row.Head); CryptographicOperations.ZeroMemory(row.Metadata); }
            fixture.ColdReopenCompactionStorage();
            using (var reopened = await fixture.ReadSenderCompactionCurrent()) Assert.NotNull(reopened);
            Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            await fixture.AssertSenderCompactionIdle(sender);
            using (var replay = await fixture.ReceiveOwnedMessage(sender, acceptance)) { }
            Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            var operation = Bytes(32, checked((byte)(0xb0 + index)));
            using var draft = await fixture.PrepareOwnedText(sender, operation, "after exact prefix recovery " + index);
            byte[] envelope;
            using (var sent = await fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span))) envelope = sent.ExactEnvelope.ToArray();
            using (var received = await fixture.ReceiveOwnedMessage(receiver, envelope)) { }
            CryptographicOperations.ZeroMemory(envelope);
            Assert.Equal(++ordinal, (await fixture.ReadMessagingFloor(sender)).Ordinal); index++;
        }

        // Cancellation before SQL retains an exact prepared predecessor. An
        // explicit durable abort can itself crash after deleting staging parts.
        var stable = await fixture.ReadMessagingFloor(sender);
        using (var cancellation = new CancellationTokenSource())
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterStage) cancellation.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CompactSenderPrefix(sender, 1, cancellation.Token));
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterPartsDeleted) throw new IOException("Injected durable abort clear."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SenderCompactionOwner().AbandonUncommittedOwnedPrefixAsync(default));
        fixture.ColdReopenCompactionStorage();
        await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await fixture.AssertSenderCompactionIdle(sender);

        // After SQL commit, abort must reject; no fresh proof/signature is
        // needed to finish that same persisted local transaction.
        using (var cancellation = new CancellationTokenSource())
        using (Did2CompactionTestHooks.Push(point => { if (point == Did2CompactionFailpoint.AfterSql) cancellation.Cancel(); }))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CompactSenderPrefix(sender, 1, cancellation.Token));
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SenderCompactionOwner().AbandonUncommittedOwnedPrefixAsync(default));
        fixture.ColdReopenCompactionStorage(); await fixture.SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default);
        await fixture.AssertSenderCompactionIdle(sender);
        Assert.Equal(stable.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(6, (await fixture.ListOwnedMessages(receiver)).Count);
        CryptographicOperations.ZeroMemory(acceptance);
    }

    private sealed partial class Fixture
    {
        internal sealed record PrefixRow(long Ordinal, byte[] Predecessor, byte[] Head, byte[] Metadata);
        // Opening only the already-owned database deliberately avoids ordinary
        // account reconciliation, which would resume the plan under test.
        private async Task WithCompactionConnection(Did2MessagingSessionScope scope, Action<SqliteConnection> inspect)
        {
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            using var held = await lease.AcquireAsync(default);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, Network, scope.LocalAccount, scope.Instance).ReadAsync(default);
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                Path.Combine(directory, "deep-store-v2-account.dsv2"), catalog, scope, held, lease);
            inspect(connection); held.RequireActive();
        }
        internal async Task<List<PrefixRow>> CaptureCompactionPrefixRows(Did2MessagingSessionScope scope, int count)
        {
            var result = new List<PrefixRow>();
            await WithCompactionConnection(scope, connection =>
            {
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT ordinal,predecessor,head,metadata FROM journal ORDER BY ordinal LIMIT $count;";
                command.Parameters.AddWithValue("$count", count);
                using var reader = command.ExecuteReader();
                while (reader.Read()) result.Add(new(reader.GetInt64(0), (byte[])reader[1], (byte[])reader[2], (byte[])reader[3]));
            });
            Assert.Equal(count, result.Count); return result;
        }
        internal Task RestoreCompactionPrefixRows(Did2MessagingSessionScope scope, IReadOnlyList<PrefixRow> rows) =>
            WithCompactionConnection(scope, connection =>
            {
                using var transaction = connection.BeginTransaction();
                foreach (var row in rows)
                {
                    using var command = connection.CreateCommand(); command.Transaction = transaction;
                    command.CommandText = "INSERT INTO journal(ordinal,predecessor,head,metadata) VALUES($ordinal,$predecessor,$head,$metadata);";
                    command.Parameters.AddWithValue("$ordinal", row.Ordinal); command.Parameters.AddWithValue("$predecessor", row.Predecessor);
                    command.Parameters.AddWithValue("$head", row.Head); command.Parameters.AddWithValue("$metadata", row.Metadata);
                    Assert.Equal(1, command.ExecuteNonQuery());
                }
                transaction.Commit();
            });
        internal Task RemoveRestoredCompactionPrefixRows(Did2MessagingSessionScope scope, IReadOnlyList<PrefixRow> rows) =>
            WithCompactionConnection(scope, connection =>
            {
                using var transaction = connection.BeginTransaction();
                foreach (var row in rows)
                {
                    using var command = connection.CreateCommand(); command.Transaction = transaction;
                    command.CommandText = "DELETE FROM journal WHERE ordinal=$ordinal AND predecessor=$predecessor AND head=$head AND metadata=$metadata;";
                    command.Parameters.AddWithValue("$ordinal", row.Ordinal); command.Parameters.AddWithValue("$predecessor", row.Predecessor);
                    command.Parameters.AddWithValue("$head", row.Head); command.Parameters.AddWithValue("$metadata", row.Metadata);
                    Assert.Equal(1, command.ExecuteNonQuery());
                }
                transaction.Commit();
            });
        internal async Task AssertPreparedCompactionRejectsMissingPartsGuardAndSqlSubstitution(Did2MessagingSessionScope scope)
        {
            var partSlot = ProtectedDid2CompactionPlan.PartSlot(0);
            using (var original = await storage.ReadOwnedAsync(partSlot) ?? throw new InvalidDataException("Fixture part absent."))
            {
                await storage.DeleteBatchAsync([partSlot]);
                await AssertCompactionRefusalDoesNotMutate(scope);
                await storage.WriteBatchAsync([new(partSlot, original.Use(bytes => bytes.ToArray()))]); // Fixture restoration only.
            }
            var peerSlot = ProtectedDid2MessagingPeerBootstrap.Slot(scope);
            using (var original = await storage.ReadOwnedAsync(peerSlot) ?? throw new InvalidDataException("Fixture peer absent."))
            {
                await storage.DeleteBatchAsync([peerSlot]);
                await AssertCompactionRefusalDoesNotMutate(scope);
                await storage.WriteBatchAsync([new(peerSlot, original.Use(bytes => bytes.ToArray()))]); // Fixture restoration only.
            }
            byte[]? plaintext = null;
            await WithCompactionConnection(scope, connection =>
            {
                using var read = connection.CreateCommand(); read.CommandText = "SELECT plaintext FROM events WHERE direction=2;";
                plaintext = Assert.IsType<byte[]>(read.ExecuteScalar());
                using var corrupt = connection.CreateCommand();
                corrupt.CommandText = "UPDATE events SET plaintext=zeroblob(length(plaintext)) WHERE direction=2;";
                Assert.Equal(1, corrupt.ExecuteNonQuery());
            });
            try
            {
                await AssertCompactionRefusalDoesNotMutate(scope);
                await WithCompactionConnection(scope, connection =>
                {
                    using var restore = connection.CreateCommand(); restore.CommandText = "UPDATE events SET plaintext=$original WHERE direction=2;";
                    restore.Parameters.AddWithValue("$original", plaintext); Assert.Equal(1, restore.ExecuteNonQuery());
                });
            }
            finally { if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext); }
        }
        internal async Task AssertCompactionRefusalDoesNotMutate(Did2MessagingSessionScope scope)
        {
            var slots = new[] { Did2CompactionPlan.Slot, ProtectedDid2CompactionPlan.PartSlot(0),
                ProtectedDid2MessagingSessionCatalog.Slot, scope.FloorSlot, Did2MessagingHistoryCheckpoint.Slot(scope),
                ProtectedDid2MessagingPeerBootstrap.Slot(scope), SqliteDeepIdV2AccountGeneration.CompactionRegistrationSlot };
            var before = new List<byte[]?>(); byte[]? sqlBefore = null, sqlAfter = null;
            foreach (var slot in slots)
            { using var value = await storage.ReadOwnedAsync(slot); before.Add(value?.Use(bytes => SHA256.HashData(bytes))); }
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(storage, scope, default);
            await WithCompactionConnection(scope, connection => sqlBefore = new Did2MessagingSqlJournal(connection, scope, history).ReadCompleteCompactionProjection());
            await Assert.ThrowsAsync<InvalidDataException>(() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
            for (var index = 0; index < slots.Length; index++)
            { using var value = await storage.ReadOwnedAsync(slots[index]); Assert.Equal(before[index], value?.Use(bytes => SHA256.HashData(bytes))); }
            await WithCompactionConnection(scope, connection => sqlAfter = new Did2MessagingSqlJournal(connection, scope, history).ReadCompleteCompactionProjection());
            Assert.Equal(sqlBefore, sqlAfter);
            foreach (var value in before) if (value is not null) CryptographicOperations.ZeroMemory(value);
        }
        internal ProtectedDeepIdV2AccountOwner SenderCompactionOwner() => new(storage,
            new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")),
            Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, 1);
        internal Task CompactSenderPrefix(Did2MessagingSessionScope scope, int rows, CancellationToken ct) =>
            SenderCompactionOwner().CompactOwnedMessagingPrefixAsync(1_000, pq, scope, rows, ct);
        internal ValueTask<VerifiedDeepIdV2CurrentAccount?> ReadSenderCompactionCurrent() =>
            SenderCompactionOwner().ReadCurrentAsync(1_000, pq, default);
        internal void ColdReopenCompactionStorage() => Assert.IsType<CompactionDiskFixtureStorage>(innerStorage).Reopen();
        internal async Task AssertSenderCompactionIdle(Did2MessagingSessionScope scope)
        {
            using var plan = await ProtectedDid2CompactionPlan.ReadRegisteredAsync(storage, Network, scope.LocalAccount.ToArray(), scope.Instance.ToArray(), default);
            Assert.Equal(0, plan.Phase);
            for (var index = 0; index < 16; index++)
            { using var absent = await storage.ReadOwnedAsync(ProtectedDid2CompactionPlan.PartSlot(index)); Assert.Null(absent); }
            await WithSenderHistoryStorage(scope, async (opened, _, _, _) =>
            { var floor = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadAsync(default); Assert.Equal(opened.Sql.VerifyTip().Exact.ToArray(), floor.Exact.ToArray()); });
        }
    }

    // Test-only backend reopen: same real journal file, new store/protector
    // handles. No runtime adapter, snapshot import or plaintext export.
    private sealed class CompactionDiskFixtureStorage : IDeepSecureStorage, IDisposable
    {
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        private readonly string path;
        private JournaledDeepSecureStorage store;
        internal CompactionDiskFixtureStorage(string directory)
        { Directory.CreateDirectory(directory); path = Path.Combine(directory, "compaction-fixture.protected.bin"); store = Open(); }
        private JournaledDeepSecureStorage Open() => new(path, new CompactionFixtureProtector(key));
        internal void Reopen() { store.Dispose(); store = Open(); }
        public Task<OwnedDeepSecret?> ReadOwnedAsync(string slot, CancellationToken ct = default) => store.ReadOwnedAsync(slot, ct);
        public Task WriteBatchAsync(IReadOnlyList<DeepSecureStorageWrite> writes, CancellationToken ct = default) => store.WriteBatchAsync(writes, ct);
        public Task<bool> CompareExchangeAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, CancellationToken ct = default) => store.CompareExchangeAsync(slot, expected, replacement, ct);
        public Task<bool> CompareExchangeAndInsertAsync(string slot, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement, IReadOnlyList<DeepSecureStorageWrite> insertions, CancellationToken ct = default) => store.CompareExchangeAndInsertAsync(slot, expected, replacement, insertions, ct);
        public Task DeleteBatchAsync(IReadOnlyList<string> slots, CancellationToken ct = default) => store.DeleteBatchAsync(slots, ct);
        public Task PurgeStoreV1NamespaceAsync(CancellationToken ct = default) => store.PurgeStoreV1NamespaceAsync(ct);
        public Task PurgeStoreV2NamespaceAsync(CancellationToken ct = default) => store.PurgeStoreV2NamespaceAsync(ct);
        public void Dispose() { store.Dispose(); CryptographicOperations.ZeroMemory(key); }
    }
    private sealed class CompactionFixtureProtector(ReadOnlySpan<byte> secret) : IDeepSecretProtector, IDisposable
    {
        private readonly byte[] key = secret.ToArray();
        public byte[] Protect(ReadOnlySpan<byte> plaintext)
        {
            var raw = new byte[28 + plaintext.Length]; RandomNumberGenerator.Fill(raw.AsSpan(0, 12));
            using var aes = new AesGcm(key, 16); aes.Encrypt(raw.AsSpan(0, 12), plaintext, raw.AsSpan(28), raw.AsSpan(12, 16)); return raw;
        }
        public byte[] Unprotect(ReadOnlySpan<byte> ciphertext)
        {
            var raw = new byte[ciphertext.Length - 28];
            try { using var aes = new AesGcm(key, 16); aes.Decrypt(ciphertext[..12], ciphertext[28..], ciphertext.Slice(12, 16), raw); return raw; }
            catch { CryptographicOperations.ZeroMemory(raw); throw; }
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key);
    }
}
