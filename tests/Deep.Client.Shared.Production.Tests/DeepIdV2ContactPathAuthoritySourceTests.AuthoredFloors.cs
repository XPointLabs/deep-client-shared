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
    public async Task Did2AuthoredFloor_ActualOwnerPendingSqlStableFaultsColdResumeWithoutSequenceReuse()
    {
        // Real account/consent/native ratchet/SQLCipher and independently signed
        // proofs. In-process proof source, not socket or physical-device E2E.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0x91));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0x92)))
        using (var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
        using (var received = await fixture.ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
        var ratchetBefore = await fixture.ReadMessagingFloor(sender);
        var points = new[] { Did2TextOutboxFailpoint.AfterPending, Did2TextOutboxFailpoint.AfterSql, Did2TextOutboxFailpoint.AfterStable };
        for (var i = 0; i < points.Length; i++)
        {
            var op = Bytes(32, checked((byte)(0x93 + i))); var point = points[i];
            var interrupted = false;
            using (Did2TextOutboxTestHooks.Push(found =>
            {
                if (found != point) return;
                interrupted = true; throw new IOException("Injected owned authored-floor handover interruption.");
            }))
                await Assert.ThrowsAsync<IOException>(() => fixture.PrepareOwnedText(sender, op, "authored-floor recovery"));
            Assert.True(interrupted);
            byte[] retainedHash;
            using (var journal = await fixture.ReadAuthoredTextJournalAsync(sender))
            {
                var command = journal.Entries[Convert.ToHexString(op)];
                retainedHash = command.EventHash.ToArray();
                Assert.Equal(checked((ulong)i + 3), command.Sequence);
                Assert.Equal(point != Did2TextOutboxFailpoint.AfterStable, command.Pending);
                Assert.Equal(checked((ulong)i + 4), journal.NextSequence(sender));
                Assert.Single(journal.Floors);
            }
            // PrepareOwnedText constructs a new account/source on each call.
            using (var resumed = await fixture.PrepareOwnedText(sender, op, "authored-floor recovery"))
            {
                Assert.Equal(checked((ulong)i + 3), resumed.SenderSequence);
                Assert.Equal(retainedHash, SHA256.HashData(resumed.ExactDmc2.Span));
                using var retry = await fixture.PrepareOwnedText(sender, op, "authored-floor recovery");
                Assert.Equal(resumed.ExactDmc2.ToArray(), retry.ExactDmc2.ToArray());
            }
            using var stable = await fixture.ReadAuthoredTextJournalAsync(sender);
            Assert.Null(stable.Pending); Assert.Equal(checked((ulong)i + 4), stable.NextSequence(sender));
            Assert.Equal(ratchetBefore.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
            CryptographicOperations.ZeroMemory(retainedHash);
        }

        // Fixture-only disposition shape: remove both working copies, never
        // native committed events, independent local history or either floor.
        // This does not authorize production cleanup or imply remote Store.
        var committedOperation = Bytes(32, 0x93);
        using (var original = await fixture.PrepareOwnedText(sender, committedOperation, "authored-floor recovery"))
        using (var sent = await fixture.SendOwnedMessage(sender, committedOperation,
            ApplicationCoreCodec.DecodeDmc2(original.ExactDmc2.Span))) { }
        var committedFloor = await fixture.ReadMessagingFloor(sender);
        Assert.Equal("authored-floor recovery", Assert.Single(await fixture.ListNativeApplicationMessages(sender)).Text);
        await fixture.RemoveAuthoredWorkingCopiesForTestAsync(sender, committedOperation);
        using (var retained = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            Assert.Equal(6UL, retained.NextSequence(sender));
            Assert.Equal(2, retained.Entries.Count); Assert.Null(retained.Pending);
        }
        var protectedBefore = await fixture.ReadAuthoredRootDigestAsync();
        var applicationBefore = await fixture.ReadAuthoredApplicationDigestAsync(sender);
        // The actual cold owner must refuse before reserving a logical ID,
        // advancing the authored counter or materializing another SQL row.
        using (Did2TextOutboxTestHooks.Push(_ => throw new IOException("Retired replay reached a write handover.")))
            await Assert.ThrowsAsync<CryptographicException>(() =>
                fixture.PrepareOwnedText(sender, committedOperation, "authored-floor recovery"));
        Assert.Equal(protectedBefore, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(applicationBefore, await fixture.ReadAuthoredApplicationDigestAsync(sender));
        Assert.Equal(committedFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        var history = Assert.Single(await fixture.ListNativeApplicationMessages(sender));
        Assert.True(history.IsLocalAuthor); Assert.Equal("authored-floor recovery", history.Text);
        using (var next = await fixture.PrepareOwnedText(sender, Bytes(32, 0x96), "next distinct operation"))
        {
            Assert.Equal(6UL, next.SenderSequence);
            using var retained = await fixture.ReadAuthoredTextJournalAsync(sender);
            Assert.Equal(7UL, retained.NextSequence(sender)); Assert.Null(retained.Pending);
        }
        Assert.Equal(committedFloor.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        CryptographicOperations.ZeroMemory(protectedBefore); CryptographicOperations.ZeroMemory(applicationBefore);
    }

    private sealed partial class Fixture
    {
        internal async Task<ProtectedDid2DirectTextJournal.State> ReadAuthoredTextJournalAsync(Did2MessagingSessionScope scope)
        {
            using var root = await innerStorage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ??
                throw new InvalidDataException("Test observer lost the actual authored root.");
            return root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
        }

        internal async Task<byte[]> ReadAuthoredRootDigestAsync(bool own = true)
        {
            using var root = await (own ? innerStorage : peerStorage).ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ??
                throw new InvalidDataException("Fixture authored root absent.");
            return root.Use(bytes => SHA256.HashData(bytes));
        }

        // Test-only access to the already-existing encrypted application SQL.
        // The key is derived from actual owned account registration under its
        // lease; no production callback, supplied path or repair API is added.
        private Task WithAuthoredApplicationConnectionAsync(Did2MessagingSessionScope scope,
            Action<SqliteConnection> inspect, bool acquireOwnerLease = true)
            => WithOwnedApplicationConnectionAsync(scope.IsInitiator, scope.Network.ToArray(), scope.LocalAccount.ToArray(), inspect, acquireOwnerLease);

        private async Task WithOwnedApplicationConnectionAsync(bool own, ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> account,
            Action<SqliteConnection> inspect, bool acquireOwnerLease = true)
        {
            var accountDirectory = own ? directory : Path.Combine(directory, "peer");
            var secure = own ? (IDeepSecureStorage)storage : peerStorage;
            // Only an explicit hostile-database fault injection may bypass the
            // fixture lease while the real product owner already holds it.
            using var held = acquireOwnerLease ? await new DeepIdV2AccountFileLease(Path.Combine(accountDirectory,
                "deep-store-v2-account.lock")).AcquireAsync(default).ConfigureAwait(false) : null;
            using var registration = await SqliteDeepIdV2AccountGeneration.ReadCompactionRegistrationUnderLeaseAsync(
                secure, network, account, default).ConfigureAwait(false);
            var key = registration.Use(record =>
            {
                var domain = "Deep/STORE-V2/application-state-key"u8;
                var context = new byte[domain.Length + 1 + 80];
                try
                {
                    domain.CopyTo(context); record.Slice(8, 48).CopyTo(context.AsSpan(domain.Length + 1));
                    record.Slice(56, 32).CopyTo(context.AsSpan(domain.Length + 49));
                    return HMACSHA256.HashData(record.Slice(88, 32), context);
                }
                finally { CryptographicOperations.ZeroMemory(context); }
            });
            try
            {
                using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = Path.Combine(accountDirectory, "deep-store-v2-account.dsv2.application.dmb1"),
                    Mode = SqliteOpenMode.ReadWrite, Pooling = false
                }.ToString());
                connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, key));
                inspect(connection); held?.RequireActive();
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        internal async Task RemoveAuthoredWorkingCopiesForTestAsync(Did2MessagingSessionScope scope, byte[] operation)
        {
            // Hostile/test-only state construction, not a settlement selector.
            await WithAuthoredApplicationConnectionAsync(scope, connection =>
            {
                using var transaction = connection.BeginTransaction();
                using var command = connection.CreateCommand(); command.Transaction = transaction;
                command.CommandText = "DELETE FROM direct_text_outbox WHERE operation_id=$operation;";
                command.Parameters.AddWithValue("$operation", operation); Assert.Equal(1, command.ExecuteNonQuery());
                transaction.Commit();
            });
            using var held = await new DeepIdV2AccountFileLease(Path.Combine(directory,
                "deep-store-v2-account.lock")).AcquireAsync(default);
            using var root = await storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot) ??
                throw new InvalidDataException("Fixture authored root absent.");
            using var journal = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes,
                scope.Network, scope.LocalAccount, scope.Instance));
            Assert.True(journal.Entries.Remove(Convert.ToHexString(operation), out var removed)); removed!.Dispose();
            journal.Revision = checked(journal.Revision + 1);
            var next = ProtectedDid2DirectTextJournal.Encode(journal, scope.Network, scope.LocalAccount, scope.Instance);
            var previous = root.Use(bytes => bytes.ToArray());
            try { Assert.True(await storage.CompareExchangeAsync(ProtectedDid2DirectTextJournal.Slot, previous, next)); }
            finally { CryptographicOperations.ZeroMemory(previous); CryptographicOperations.ZeroMemory(next); }
            held.RequireActive();
        }

        internal async Task<byte[]> ReadAuthoredApplicationDigestAsync(Did2MessagingSessionScope scope)
        {
            using var buffer = new MemoryStream(); using var writer = new BinaryWriter(buffer);
            try
            {
                await WithAuthoredApplicationConnectionAsync(scope, connection =>
                {
                    foreach (var table in new[] { "direct_text_outbox", "direct_sender_sequences", "authenticated_dmc2_inbox" })
                    {
                        writer.Write(table);
                        using var command = connection.CreateCommand(); command.CommandText = $"SELECT * FROM {table} ORDER BY 1,2,3;";
                        using var reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            writer.Write(true);
                            for (var index = 0; index < reader.FieldCount; index++)
                            {
                                var value = reader.GetValue(index);
                                if (value is byte[] bytes)
                                {
                                    try { writer.Write((byte)1); writer.Write(bytes.Length); writer.Write(bytes); }
                                    finally { CryptographicOperations.ZeroMemory(bytes); }
                                }
                                else if (value is long number) { writer.Write((byte)2); writer.Write(number); }
                                else throw new InvalidDataException("Unexpected fixture application cell type.");
                            }
                        }
                        writer.Write(false);
                    }
                });
                writer.Flush(); return SHA256.HashData(buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length)));
            }
            finally { CryptographicOperations.ZeroMemory(buffer.GetBuffer()); }
        }
    }
}
