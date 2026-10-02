using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

// Local codec/SQL mirror coverage, not endpoint/crypto/consent authority.
public sealed class Did2OwnedTextOutboxTests
{
    [Fact]
    public void VerifiedStorePhaseIsMonotonicScopedAndRetiresOldJournal()
    {
        var scope = Scope(); var op = B(32, 31); using var state = Pending(scope, op, 3);
        var entry = Assert.Single(state.Entries).Value;
        Assert.Throws<InvalidOperationException>(() => entry.WithVerifiedStore());
        Stabilize(state, op);
        entry = state.Entries[Convert.ToHexString(op)];
        Assert.False(entry.Stored);
        var stored = entry.WithVerifiedStore(); state.Entries[Convert.ToHexString(op)] = stored; entry.Dispose();
        Assert.True(stored.Stored); Assert.False(stored.Pending);
        Assert.Equal(op, stored.Operation.ToArray()); Assert.Equal(3UL, stored.Sequence);
        Assert.Throws<InvalidOperationException>(() => stored.WithVerifiedStore());
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal((byte)2, exact[0]); Assert.Equal(4UL, BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(4)));
        using var reopened = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.True(Assert.Single(reopened.Entries).Value.Stored);
        var retired = exact.ToArray(); retired[0] = 1;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(retired, scope.Network, scope.LocalAccount, scope.Instance));
        var mismatchedRevision = exact.ToArray(); mismatchedRevision[92 + 516] = 2;
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(mismatchedRevision, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public void OtherCodecKindsCannotEnterTheAccountSendPathWithoutOwners()
    {
        foreach (var kind in Enum.GetValues<Dmc2ContentKind>())
        {
            if (kind is Dmc2ContentKind.MessageCreate or Dmc2ContentKind.ContactAccept or Dmc2ContentKind.AttachmentOffer)
                Deep.Client.Shared.Services.DeepIdV2AccountService.RequireOwnedSendKind(kind);
            else
                Assert.Throws<NotSupportedException>(() =>
                    Deep.Client.Shared.Services.DeepIdV2AccountService.RequireOwnedSendKind(kind));
        }
        Assert.Throws<NotSupportedException>(() =>
            Deep.Client.Shared.Services.DeepIdV2AccountService.RequireOwnedSendKind((Dmc2ContentKind)255));
    }

    [Theory]
    [InlineData("picture.png", "image/png")]
    [InlineData("document.bin", "application/octet-stream")]
    public async Task TextAttachmentOfferTextSharesProtectedSequenceAndExactSqlRecovery(string filename, string mediaType)
    {
        // Structural command/SQL evidence only. It cannot authorize an asset,
        // authenticated upload, current session or physical delivery.
        var scope = Scope(); var op = B(32, 31); var assetOp = B(32, 32); var nextOp = B(32, 33);
        using var fixture = new SqlFixture(); using var state = Pending(scope, op, 3);
        var plaintext = B(1000, 77);
        using var prepared = await Deep.Client.Shared.Services.AttachmentV1.AttachmentObjectPreparation.PrepareAsync(
            new MemoryStream(plaintext), plaintext.Length, scope.Network.ToArray(), filename, mediaType, 2000, default);
        using var ownedManifest = prepared.OwnManifest(); using var manifest = ownedManifest.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var offer = ApplicationCoreCodec.AuthorDmc2(scope.Network, B(32, 47), scope.Conversation, scope.LocalAccount,
            scope.LocalDevice, 4, 2000, 0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest));
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            using var text = await Mirror(store, state, scope, op); Stabilize(state, op);
            Assert.Equal(4UL, state.NextSequence(scope));
            state.Entries.Add(Convert.ToHexString(assetOp), ProtectedDid2DirectTextJournal.Entry.Prepare(scope, assetOp, offer));
            using var first = await Mirror(store, state, scope, assetOp);
            Assert.Equal(4UL, first!.SenderSequence); Assert.Equal(offer.CanonicalBytes.ToArray(), first.ExactDmc2.ToArray());
            using var retry = await Mirror(store, state, scope, assetOp);
            Assert.Equal(first.ExactDmc2.ToArray(), retry!.ExactDmc2.ToArray());
            Stabilize(state, assetOp);
        }
        using (var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key)))
        {
            using var retained = await Mirror(reopened, state, scope, assetOp);
            Assert.Equal(offer.CanonicalBytes.ToArray(), retained!.ExactDmc2.ToArray());
            Assert.Equal(5UL, state.NextSequence(scope));
            state.Entries.Add(Convert.ToHexString(nextOp), Make(scope, nextOp, 5));
            using var next = await Mirror(reopened, state, scope, nextOp); Assert.Equal(5UL, next!.SenderSequence);
            Stabilize(state, nextOp); Assert.Equal(6UL, state.NextSequence(scope));
            var changed = offer.CanonicalBytes.ToArray(); changed[^1] ^= 1;
            Assert.Throws<CryptographicException>(() => state.Entries[Convert.ToHexString(assetOp)].RequireEvent(changed));
            fixture.Execute("UPDATE direct_sender_sequences SET next_sequence=4;");
            await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, state, scope, assetOp));
        }
        CryptographicOperations.ZeroMemory(plaintext);
    }

    [Fact]
    public void JournalPhaseShapeScopeAndDisposalAreClosed()
    {
        var scope = Scope(); var op = B(32, 31);
        using var state = Pending(scope, op, 3);
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var decoded = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Single(decoded.Entries); Assert.True(decoded.Pending!.Pending); Assert.Equal(4UL, decoded.NextSequence(scope));
        foreach (var offset in new[] { 0, 1, 3, 11, 12, 28, 60, 128, 92 + 436, 92 + 468,
            92 + 476, 92 + 484, 92 + 516, 92 + 517, 92 + 520, exact.Length - 1 })
        {
            var changed = exact.ToArray(); changed[offset] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => ProtectedDid2DirectTextJournal.Decode(changed, scope.Network, scope.LocalAccount, scope.Instance));
        }
        // Operation is authenticated by protected storage, not derived from
        // the random logical ID. A different valid operation alone is not a
        // malformed codec input; zero and duplicate commands are forbidden.
        var zeroOperation = exact.ToArray(); zeroOperation.AsSpan(92, 32).Clear();
        Assert.ThrowsAny<Exception>(() => ProtectedDid2DirectTextJournal.Decode(zeroOperation, scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(exact[..^1], scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode([.. exact, 0], scope.Network, scope.LocalAccount, scope.Instance));
        var pending = decoded.Pending!;
        Stabilize(decoded, op);
        Assert.Throws<ObjectDisposedException>(() => pending.PendingDmc2.ToArray());
        var stable = ProtectedDid2DirectTextJournal.Encode(decoded, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(92 + 524, stable.Length); Assert.Equal(3UL, BinaryPrimitives.ReadUInt64BigEndian(stable.AsSpan(4)));
        using var retained = ProtectedDid2DirectTextJournal.Decode(stable, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Null(retained.Pending);
        var observed = retained.Entries.Values.Single(); retained.Dispose();
        Assert.Throws<ObjectDisposedException>(() => observed.Exact.ToArray());
    }

    [Fact]
    public void DuplicatePendingLogicalPositionGapAndExhaustedSequenceReject()
    {
        var scope = Scope(); using var state = Pending(scope, B(32, 31), 3);
        var next = Make(scope, B(32, 32), 4); state.Entries.Add(Convert.ToHexString(next.Operation), next);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        state.Entries.Remove(Convert.ToHexString(next.Operation)); next.Dispose();
        Stabilize(state, B(32, 31));
        var gap = Make(scope, B(32, 33), 5); state.Entries.Add(Convert.ToHexString(gap.Operation), gap);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        state.Entries.Remove(Convert.ToHexString(gap.Operation)); gap.Dispose();
        var collided = Make(scope, B(32, 34), 3); state.Entries.Add(Convert.ToHexString(collided.Operation), collided);
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<CryptographicException>(() => Make(scope, B(32, 35), long.MaxValue));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExactPendingBeforeAndAfterSqlRollsForwardAndStableSurvivesReopen(bool initiator)
    {
        var scope = Scope(initiator); var op = B(32, 31); var initial = initiator ? 3UL : 4UL;
        using var fixture = new SqlFixture(); using var state = Pending(scope, op, initial);
        byte[] exact;
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            // Structural responder fixture represents the counter committed
            // with ContactAccept; it is not consent/crypto authority.
            if (!initiator) fixture.InsertCounter(scope, 4);
            using var first = await Mirror(store, state, scope, op); Assert.NotNull(first);
            exact = first!.ExactDmc2.ToArray(); Assert.Equal(initial, first.SenderSequence);
            using var repeat = await Mirror(store, state, scope, op); Assert.Equal(exact, repeat!.ExactDmc2.ToArray());
            Stabilize(state, op);
            using var stable = await Mirror(store, state, scope, op); Assert.Equal(exact, stable!.ExactDmc2.ToArray());
        }
        using (var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key)))
        {
            using var stable = await Mirror(reopened, state, scope, op); Assert.Equal(exact, stable!.ExactDmc2.ToArray());
            var original = state.Entries[Convert.ToHexString(op)];
            state.Entries[Convert.ToHexString(op)] = original.WithVerifiedStore(); original.Dispose();
            using var completed = await Mirror(reopened, state, scope, op); Assert.Equal(exact, completed!.ExactDmc2.ToArray());
            var retainedRows = new List<DirectTextOutboxEntry>();
            try
            {
                using var ignored = await reopened.ReconcileOwnedTextOutboxAsync(state, scope.LocalAccount.ToArray(), 1,
                    scope, ReadOnlyMemory<byte>.Empty, default, retainedRows);
                Assert.Equal(op, Assert.Single(retainedRows).OperationId.ToArray());
                Assert.True(state.Entries[Convert.ToHexString(op)].Stored);
            }
            finally { foreach (var row in retainedRows) row.Dispose(); }
            var nextOp = B(32, 32); var next = Make(scope, nextOp, initial + 1);
            state.Entries.Add(Convert.ToHexString(nextOp), next);
            using var second = await Mirror(reopened, state, scope, nextOp);
            Assert.Equal(initial + 1, second!.SenderSequence); Stabilize(state, nextOp);
            using var old = await Mirror(reopened, state, scope, op); Assert.Equal(exact, old!.ExactDmc2.ToArray());
        }
    }

    [Theory]
    [InlineData("DELETE FROM direct_text_outbox;")]
    [InlineData("UPDATE direct_sender_sequences SET next_sequence=3;")]
    [InlineData("UPDATE direct_sender_sequences SET next_sequence=9;")]
    [InlineData("UPDATE direct_text_outbox SET recipient_account_id=zeroblob(32);")]
    [InlineData("UPDATE direct_text_outbox SET operation_id=zeroblob(32);")]
    [InlineData("UPDATE direct_text_outbox SET exact_dmc2_hash=zeroblob(32);")]
    [InlineData("UPDATE direct_text_outbox SET created_at=1;")]
    public async Task StableSqlLossRollbackOrMetadataSubstitutionRejectsWithoutRecreation(string tamper)
    {
        var scope = Scope(); var op = B(32, 31); using var fixture = new SqlFixture(); using var state = Pending(scope, op, 3);
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        { using var first = await Mirror(store, state, scope, op); Stabilize(state, op); }
        fixture.Execute(tamper);
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, state, scope, op));
        Assert.Equal(tamper.StartsWith("DELETE", StringComparison.Ordinal) ? 0L : 1L,
            fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
    }

    [Fact]
    public async Task LostResponderAcceptanceCounterCannotBeRecreatedByText()
    {
        var scope = Scope(false); var op = B(32, 31);
        using var fixture = new SqlFixture();
        using var empty = new ProtectedDid2DirectTextJournal.State();
        using var pending = Pending(scope, op, 4);
        using var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(store, empty, scope, []));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(store, pending, scope, op));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_sender_sequences;"));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
    }

    [Fact]
    public async Task OversizedSqlTextCannotBeReadAsAnOwnedDraft()
    {
        var scope = Scope(); var op = B(32, 31);
        using var fixture = new SqlFixture(); using var state = Pending(scope, op, 3);
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        { using var first = await Mirror(store, state, scope, op); Stabilize(state, op); }
        // Simulate hostile preexisting bytes without removing production DDL
        // checks. This pragma applies only to the fixture mutation connection.
        fixture.Execute("PRAGMA ignore_check_constraints=ON; UPDATE direct_text_outbox SET exact_dmc2=zeroblob(16669); PRAGMA ignore_check_constraints=OFF;");
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, state, scope, op));
        Assert.Equal(16669L, fixture.Scalar("SELECT length(exact_dmc2) FROM direct_text_outbox;"));
    }

    [Fact]
    public async Task SqlCannotSupplyAnInitialCounterOrAnUnprotectedCommand()
    {
        var scope = Scope(); var op = B(32, 31); using var fixture = new SqlFixture();
        using var state = new ProtectedDid2DirectTextJournal.State();
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        { using var empty = await Mirror(store, state, scope, []); Assert.Null(empty); }
        fixture.InsertCounter(scope, 9);
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, state, scope, []));
        fixture.Execute("DELETE FROM direct_sender_sequences;");
        using var unprotected = await reopened.StageDirectTextAsync(scope.Network.ToArray(), scope.LocalAccount.ToArray(), 1,
            scope.LocalDevice.ToArray(), scope.Conversation.ToArray(), scope.RemoteAccount.ToArray(), scope.RemoteDevice.ToArray(),
            "not an owned protected command", DateTimeOffset.FromUnixTimeMilliseconds(1000));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, state, scope, op));
    }

    private static Task<DirectTextOutboxEntry?> Mirror(SqliteDeepMailboxStore store, ProtectedDid2DirectTextJournal.State state,
        Did2MessagingSessionScope scope, byte[] operation) => store.ReconcileOwnedTextOutboxAsync(state,
        scope.LocalAccount.ToArray(), 1, scope, operation, CancellationToken.None);
    private static ProtectedDid2DirectTextJournal.State Pending(Did2MessagingSessionScope scope, byte[] op, ulong sequence)
    { var state = new ProtectedDid2DirectTextJournal.State(); state.Entries.Add(Convert.ToHexString(op), Make(scope, op, sequence)); return state; }
    private static ProtectedDid2DirectTextJournal.Entry Make(Did2MessagingSessionScope scope, byte[] op, ulong sequence)
    {
        var logical = op.ToArray(); logical[0] ^= 0x10;
        var text = ApplicationCoreCodec.AuthorDmc2(scope.Network, logical, scope.Conversation, scope.LocalAccount,
            scope.LocalDevice, sequence, 1000, 0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("protected 📨"));
        return ProtectedDid2DirectTextJournal.Entry.Prepare(scope, op, text);
    }
    private static void Stabilize(ProtectedDid2DirectTextJournal.State state, byte[] op)
    { var name = Convert.ToHexString(op); var old = state.Entries[name]; state.Entries[name] = old.Stabilize(); old.Dispose(); }
    private static Did2MessagingSessionScope Scope(bool initiator = true)
    { var frame = Did2ContactAcceptCustodyTests.Scope().Exact.ToArray(); frame[1] = initiator ? (byte)1 : (byte)2; return Did2MessagingSessionScope.RestoreMetadata(frame); }
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();
    private sealed class SqlFixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-owned-text-" + Guid.NewGuid().ToString("N") + ".db");
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);
        private SqliteConnection Open()
        { var db = new SqliteConnection($"Data Source={Path};Pooling=False"); db.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(db, Key)); return db; }
        internal void Execute(string sql) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
        internal long Scalar(string sql) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql; return (long)cmd.ExecuteScalar()!; }
        internal void InsertCounter(Did2MessagingSessionScope scope, long value)
        {
            using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "INSERT INTO direct_sender_sequences VALUES($c,$d,$n);";
            cmd.Parameters.AddWithValue("$c", scope.Conversation.ToArray()); cmd.Parameters.AddWithValue("$d", scope.LocalDevice.ToArray()); cmd.Parameters.AddWithValue("$n", value); cmd.ExecuteNonQuery();
        }
        public void Dispose()
        { CryptographicOperations.ZeroMemory(Key); foreach (var file in new[] { Path, Path + "-wal", Path + "-shm", Path + "-journal" }) File.Delete(file); }
    }
}
