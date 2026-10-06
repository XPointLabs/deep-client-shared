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
    public async Task Did2HistoryCheckpoint_ActualOwnedPrefixColdReopenPreservesAcceptanceReplayAndNextRatchet()
    {
        // Genuine account/contact/retirement/native crypto/SQLCipher. The SQL
        // trim/root adoption below is explicit fixture staging of the proposed
        // owner outcome, not production compaction or deletion authorization.
        await using var fixture = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xa1));
        using var initial = await complete(fixture.Accounts);
        using (var received = await fixture.CompleteReceiver(initial.ExactDph2.ToArray())) { }
        var sender = await fixture.EnsureSenderMessaging(init, hello);
        var receiver = await fixture.EnsureReceiverMessaging(initial.ExactDph2.ToArray());
        byte[] acceptance, ciphertext;
        using (var accept = await fixture.PrepareOwnedContactAccept(receiver, Bytes(32, 0xa2)))
        {
            acceptance = accept.ExactDmc2.ToArray();
            using var sent = await fixture.SendOwnedMessage(receiver, accept.Operation.ToArray(), ApplicationCoreCodec.DecodeDmc2(acceptance));
            ciphertext = sent.ExactEnvelope.ToArray();
        }
        using (var received = await fixture.ReceiveOwnedMessage(sender, ciphertext)) { }
        var before = await fixture.ReadMessagingFloor(sender);
        using var selected = await fixture.PrepareSenderCompaction(sender, checked((int)before.Ordinal));
        Assert.Equal(1, selected.Plan.Phase); Assert.Equal(5, selected.Plan.RootCount);
        Assert.Equal(checked((int)before.Ordinal), selected.Plan.RowCount);
        selected.Successors.Use(bytes => selected.Plan.ValidateSuccessors(bytes));
        await fixture.WithSenderHistoryStorage(sender, async (opened, secure, observer, held) =>
        {
            var original = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, sender, default);
            Assert.Equal(0UL, original.Basis.Ordinal);
            var candidate = opened.Sql.CaptureHistoryPrefix(before, checked((int)before.Ordinal));
            var effects = opened.Sql.CaptureHistoryPrefixEffects(before, checked((int)before.Ordinal));
            Assert.Equal(candidate.Exact.ToArray(), effects.Successor.Exact.ToArray());
            Assert.Equal(effects.Before.ToArray(), opened.Sql.ReadCompleteCompactionProjection());
            Assert.Equal(effects.Before.ToArray(), selected.Plan.Exact.Slice(160, 32).ToArray());
            Assert.Equal(effects.After.ToArray(), selected.Plan.Exact.Slice(192, 32).ToArray());
            using (var selectedHistory = selected.Successors.Use(bytes => selected.Plan.OwnSuccessor(3, bytes)))
                Assert.Equal(candidate.Exact.ToArray(), selectedHistory.Use(bytes => bytes.ToArray()));
            Assert.Throws<InvalidDataException>(() => opened.Sql.CaptureHistoryPrefixEffects(before, 0));
            Assert.Throws<InvalidDataException>(() => opened.Sql.CaptureHistoryPrefixEffects(before, 33));
            Assert.Throws<InvalidDataException>(() => opened.Sql.CaptureHistoryPrefixEffects(before, checked((int)before.Ordinal + 1)));
            Assert.Equal(before.Exact.ToArray(), candidate.Basis.Exact.ToArray());
            Assert.Equal(1UL, candidate.HistoryCount); Assert.Equal(2UL, candidate.Revision);
            using var ratchet = opened.Sql.ReadVerifiedLatest(before);
            var ratchetHash = ratchet.Use(bytes => SHA256.HashData(bytes));
            using (var trim = observer.CreateCommand())
            {
                trim.CommandText = "DELETE FROM journal WHERE ordinal<=$prefix;";
                trim.Parameters.AddWithValue("$prefix", checked((long)candidate.Basis.Ordinal));
                Assert.Equal(checked((int)before.Ordinal), trim.ExecuteNonQuery());
            }
            Assert.Equal(effects.After.ToArray(), opened.Sql.ReadCompleteCompactionProjection());
            // The SQL outcome cannot be consumed with the old/SQL-only basis.
            Assert.Throws<CryptographicException>(() => opened.Sql.VerifyTip());
            held.RequireActive();
            Assert.True(await secure.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(sender), original.Exact, candidate.Exact));
            var after = new Did2MessagingSqlJournal(observer, sender,
                await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, sender, default));
            Assert.Equal(before.Exact.ToArray(), after.VerifyTip().Exact.ToArray());
            using var latest = after.ReadVerifiedLatest(before); Assert.Equal(ratchetHash, latest.Use(bytes => SHA256.HashData(bytes)));
            using var retained = after.ReadVerifiedReceiveForEvent(before, SHA256.HashData(acceptance)); Assert.NotNull(retained);
            using var exact = retained!.OwnAuthenticatedDmc2(); Assert.True(exact.Use(bytes => bytes.SequenceEqual(acceptance)));
            var retainedInitial = after.ReadVerifiedActiveInitialEvents(before);
            Assert.Equal(init.CanonicalBytes.ToArray(), retainedInitial.SessionInit); Assert.Equal(hello.CanonicalBytes.ToArray(), retainedInitial.Hello);
            CryptographicOperations.ZeroMemory(retainedInitial.SessionInit); CryptographicOperations.ZeroMemory(retainedInitial.Hello);
            // Rollback of the mandatory protected root does not rehydrate SQL.
            Assert.True(await secure.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(sender), candidate.Exact, original.Exact));
            Assert.Throws<CryptographicException>(() => new Did2MessagingSqlJournal(observer, sender,
                Did2MessagingHistoryCheckpoint.RegisteredEmpty(sender)).VerifyTip());
            Assert.True(await secure.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(sender), original.Exact, candidate.Exact));
            // A payload substitution keeps SQL shape/count, but cannot preserve
            // the authenticated retained-prefix commitment.
            using (var corrupt = observer.CreateCommand())
            { corrupt.CommandText = "UPDATE events SET plaintext=zeroblob(length(plaintext)) WHERE direction=2;"; Assert.Equal(1, corrupt.ExecuteNonQuery()); }
            Assert.ThrowsAny<Exception>(() => after.VerifyTip());
            Assert.NotEqual(effects.After.ToArray(), after.ReadCompleteCompactionProjection());
            using (var restore = observer.CreateCommand())
            { restore.CommandText = "UPDATE events SET plaintext=$original WHERE direction=2;"; restore.Parameters.AddWithValue("$original", acceptance); Assert.Equal(1, restore.ExecuteNonQuery()); }
            Assert.Equal(before.Exact.ToArray(), after.VerifyTip().Exact.ToArray());
            Assert.Equal(effects.After.ToArray(), after.ReadCompleteCompactionProjection());
            // Missing history is never initialized by a reader.
            await secure.DeleteBatchAsync([Did2MessagingHistoryCheckpoint.Slot(sender)]);
            await Assert.ThrowsAsync<InvalidDataException>(() => Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, sender, default));
            using (var missing = await secure.ReadOwnedAsync(Did2MessagingHistoryCheckpoint.Slot(sender))) Assert.Null(missing);
            await secure.WriteBatchAsync([new(Did2MessagingHistoryCheckpoint.Slot(sender), candidate.Exact)]); // Fixture restoration only.
        });
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using (var replay = await fixture.ReceiveOwnedMessage(sender, ciphertext)) { }
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using var draft = await fixture.PrepareOwnedText(sender, Bytes(32, 0xa3), "after authenticated history checkpoint");
        byte[] nextCipher;
        using (var next = await fixture.SendOwnedMessage(sender, Bytes(32, 0xa3), ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span)))
            nextCipher = next.ExactEnvelope.ToArray();
        var progressed = await fixture.ReadMessagingFloor(sender);
        Assert.Equal(before.Ordinal + 1, progressed.Ordinal); Assert.Equal(before.RatchetGeneration + 1, progressed.RatchetGeneration);
        using (var received = await fixture.ReceiveOwnedMessage(receiver, nextCipher)) { }
        Assert.Single(await fixture.ListOwnedMessages(receiver));
        CryptographicOperations.ZeroMemory(acceptance); CryptographicOperations.ZeroMemory(ciphertext); CryptographicOperations.ZeroMemory(nextCipher);
    }

    private sealed partial class Fixture
    {
        internal Task<Did2CompactionPlan.Preparation> PrepareSenderCompaction(Did2MessagingSessionScope scope, int prefixRows)
        {
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(storage, lease, path, Network, 1);
            return owner.PrepareOwnedMessagingPrefixCompactionAsync(1_000, pq, scope, prefixRows, default);
        }

        internal async Task WithSenderHistoryStorage(Did2MessagingSessionScope scope,
            Func<OwnedDid2MessagingStorage, IDeepSecureStorage, SqliteConnection, HeldDeepIdV2AccountLease, Task> inspect)
        {
            Assert.True(scope.IsInitiator);
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(storage, lease, path, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException("Fixture account absent.");
            using var held = await lease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOwnedMessagingUnderLeaseAsync(storage, path, current, scope, default);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(storage, Network, scope.LocalAccount, scope.Instance).ReadAsync(default);
            using var key = catalog.ReadKey(catalog.FindExact(scope));
            var sqlPath = Path.Combine(path + ".messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            using var observer = key.Use(bytes => SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(sqlPath, bytes, false));
            await inspect(opened, storage, observer, held); held.RequireActive();
        }
    }
}
