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
        state.RetainStore(Convert.ToHexString(op)); var stored = state.Entries[Convert.ToHexString(op)];
        Assert.True(stored.Stored); Assert.False(stored.Pending);
        Assert.Equal(op, stored.Operation.ToArray()); Assert.Equal(3UL, stored.Sequence);
        Assert.Throws<InvalidOperationException>(() => stored.WithVerifiedStore());
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal((byte)3, exact[0]); Assert.Equal(4UL, BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(4)));
        using var reopened = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.True(Assert.Single(reopened.Entries).Value.Stored);
        foreach (var oldGeneration in new byte[] { 1, 2 })
        {
            var retired = exact.ToArray(); retired[0] = oldGeneration;
            Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(retired, scope.Network, scope.LocalAccount, scope.Instance));
            var oldEmpty = exact[..92].ToArray(); oldEmpty[0] = oldGeneration;
            BinaryPrimitives.WriteUInt16BigEndian(oldEmpty.AsSpan(2), 0);
            BinaryPrimitives.WriteUInt64BigEndian(oldEmpty.AsSpan(4), 1);
            Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(oldEmpty, scope.Network, scope.LocalAccount, scope.Instance));
        }
        var mismatchedRevision = exact.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(mismatchedRevision.AsSpan(4), 1);
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
            state.AddPending(ProtectedDid2DirectTextJournal.Entry.Prepare(scope, assetOp, offer));
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
            state.AddPending(Make(scope, nextOp, 5));
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
        var entryStart = ProtectedDid2DirectTextJournal.HeaderBytes + ProtectedDid2DirectTextJournal.FloorBytes;
        foreach (var offset in new[] { 0, 1, 3, 12, 28, 60, 94, 128, entryStart + 436, entryStart + 468,
            entryStart + 476, entryStart + 484, entryStart + 516, entryStart + 517, entryStart + 520, exact.Length - 1 })
        {
            var changed = exact.ToArray(); changed[offset] ^= 0x80;
            Assert.ThrowsAny<Exception>(() => ProtectedDid2DirectTextJournal.Decode(changed, scope.Network, scope.LocalAccount, scope.Instance));
        }
        // Operation is authenticated by protected storage, not derived from
        // the random logical ID. A different valid operation alone is not a
        // malformed codec input; zero and duplicate commands are forbidden.
        var zeroOperation = exact.ToArray(); zeroOperation.AsSpan(entryStart, 32).Clear();
        Assert.ThrowsAny<Exception>(() => ProtectedDid2DirectTextJournal.Decode(zeroOperation, scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode(exact[..^1], scope.Network, scope.LocalAccount, scope.Instance));
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Decode([.. exact, 0], scope.Network, scope.LocalAccount, scope.Instance));
        var pending = decoded.Pending!;
        Stabilize(decoded, op);
        Assert.Throws<ObjectDisposedException>(() => pending.PendingDmc2.ToArray());
        var stable = ProtectedDid2DirectTextJournal.Encode(decoded, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(entryStart + 524, stable.Length); Assert.Equal(3UL, BinaryPrimitives.ReadUInt64BigEndian(stable.AsSpan(4)));
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
            state.RetainStore(Convert.ToHexString(op));
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
            state.AddPending(next);
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task IndependentAuthoredFloorSurvivesEmptyWorkingSetAndColdSqlReopen(bool initiator)
    {
        var scope = Scope(initiator); var initial = initiator ? 3UL : 4UL;
        var firstOp = B(32, 31); var secondOp = B(32, 32);
        using var fixture = new SqlFixture(); using var state = Pending(scope, firstOp, initial);
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        {
            if (!initiator) fixture.InsertCounter(scope, 4);
            using var first = await Mirror(store, state, scope, firstOp); Stabilize(state, firstOp);
            state.RetainStore(Convert.ToHexString(firstOp));
        }
        // A fixture models already authorized cleanup, not a production
        // compactor/deletion permission. No runtime cleanup is activated.
        state.Entries[Convert.ToHexString(firstOp)].Dispose(); state.Entries.Clear();
        fixture.Execute("DELETE FROM direct_text_outbox;");
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Empty(cold.Entries); Assert.Equal(4UL, cold.Revision);
        Assert.Equal(initial + 1, cold.NextSequence(scope)); Assert.Single(cold.Floors);
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        using var empty = await Mirror(reopened, cold, scope, []); Assert.Null(empty);
        cold.AddPending(Make(scope, secondOp, initial + 1));
        using var prepared = await Mirror(reopened, cold, scope, secondOp);
        Assert.Equal(initial + 1, prepared!.SenderSequence);
        Stabilize(cold, secondOp); Assert.Equal(initial + 2, cold.NextSequence(scope));
        var retained = ProtectedDid2DirectTextJournal.Encode(cold, scope.Network, scope.LocalAccount, scope.Instance);
        using var nextCold = ProtectedDid2DirectTextJournal.Decode(retained, scope.Network, scope.LocalAccount, scope.Instance);
        Assert.Equal(initial + 2, nextCold.NextSequence(scope));
    }

    [Theory]
    [InlineData("DELETE FROM direct_sender_sequences;")]
    [InlineData("UPDATE direct_sender_sequences SET next_sequence=3;")]
    [InlineData("UPDATE direct_sender_sequences SET next_sequence=9;")]
    public async Task EmptyWorkingSetCannotRepairOrRollBackItsSqlCounter(string tamper)
    {
        var scope = Scope(); var op = B(32, 31);
        using var fixture = new SqlFixture(); using var state = Pending(scope, op, 3);
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key)))
        { using var first = await Mirror(store, state, scope, op); Stabilize(state, op); }
        state.Entries[Convert.ToHexString(op)].Dispose(); state.Entries.Clear();
        fixture.Execute("DELETE FROM direct_text_outbox;"); fixture.Execute(tamper);
        var exact = ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, scope.Network, scope.LocalAccount, scope.Instance);
        using var reopened = SqliteDeepMailboxStore.OpenExisting(new(fixture.Path, fixture.Key));
        await Assert.ThrowsAsync<CryptographicException>(() => Mirror(reopened, cold, scope, []));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM direct_text_outbox;"));
        Assert.Equal(tamper.StartsWith("DELETE", StringComparison.Ordinal) ? 0L : 1L,
            fixture.Scalar("SELECT count(*) FROM direct_sender_sequences;"));
    }

    [Fact]
    public void MissingForeignRegressedOrExhaustedAuthoredFloorsFailClosed()
    {
        var scope = Scope(); var op = B(32, 31); using var state = Pending(scope, op, 3);
        var position = ProtectedDid2DirectTextJournal.Position(scope); var floor = state.Floors[position];
        foreach (var next in new[] { 0UL, 3UL, 5UL, ulong.MaxValue })
        {
            state.Floors[position] = floor with { NextSequence = next };
            Assert.ThrowsAny<Exception>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        }
        state.Floors.Clear();
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
        state.Floors.Add(position, floor);
        var different = scope.Exact.ToArray(); different[340] ^= 1;
        Assert.Throws<CryptographicException>(() => state.NextSequence(Did2MessagingSessionScope.RestoreMetadata(different)));
        state.Floors[position] = floor with { NextSequence = long.MaxValue };
        Assert.Throws<InvalidOperationException>(() => state.RequireCapacity(scope));
        foreach (var entry in state.Entries.Values) entry.Dispose(); state.Entries.Clear(); state.Floors.Clear();
        Assert.Throws<InvalidDataException>(() => ProtectedDid2DirectTextJournal.Encode(state, scope.Network, scope.LocalAccount, scope.Instance));
    }

    [Fact]
    public void BoundedAuthoredFloorsRemainEnrolledWithoutWorkingRows()
    {
        using var state = new ProtectedDid2DirectTextJournal.State();
        Did2MessagingSessionScope? enrolled = null;
        for (var i = 0; i < ProtectedDid2DirectTextJournal.MaximumFloors; i++)
        {
            var bytes = Scope().Exact.ToArray();
            SHA256.HashData(BitConverter.GetBytes(i)).CopyTo(bytes, 244);
            var scope = Did2MessagingSessionScope.RestoreMetadata(bytes); enrolled ??= scope;
            state.Floors.Add(ProtectedDid2DirectTextJournal.Position(scope), new(scope, 4));
        }
        state.Revision = checked(1UL + 2UL * (ulong)state.Floors.Count);
        var bound = enrolled!;
        var exact = ProtectedDid2DirectTextJournal.Encode(state, bound.Network, bound.LocalAccount, bound.Instance);
        using var cold = ProtectedDid2DirectTextJournal.Decode(exact, bound.Network, bound.LocalAccount, bound.Instance);
        Assert.Empty(cold.Entries); Assert.Equal(ProtectedDid2DirectTextJournal.MaximumFloors, cold.Floors.Count);
        cold.RequireCapacity(bound);
        var other = Scope(); Assert.False(cold.Floors.ContainsKey(ProtectedDid2DirectTextJournal.Position(other)));
        Assert.Throws<InvalidOperationException>(() => cold.RequireCapacity(other));
        Assert.Equal(ProtectedDid2DirectTextJournal.MaximumFloors, cold.Floors.Count);
    }

    private static Task<DirectTextOutboxEntry?> Mirror(SqliteDeepMailboxStore store, ProtectedDid2DirectTextJournal.State state,
        Did2MessagingSessionScope scope, byte[] operation) => store.ReconcileOwnedTextOutboxAsync(state,
        scope.LocalAccount.ToArray(), 1, scope, operation, CancellationToken.None);
    private static ProtectedDid2DirectTextJournal.State Pending(Did2MessagingSessionScope scope, byte[] op, ulong sequence)
    { var state = new ProtectedDid2DirectTextJournal.State(); state.AddPending(Make(scope, op, sequence)); return state; }
    private static ProtectedDid2DirectTextJournal.Entry Make(Did2MessagingSessionScope scope, byte[] op, ulong sequence)
    {
        var logical = op.ToArray(); logical[0] ^= 0x10;
        var text = ApplicationCoreCodec.AuthorDmc2(scope.Network, logical, scope.Conversation, scope.LocalAccount,
            scope.LocalDevice, sequence, 1000, 0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateMessageCreatePayload("protected 📨"));
        return ProtectedDid2DirectTextJournal.Entry.Prepare(scope, op, text);
    }
    private static void Stabilize(ProtectedDid2DirectTextJournal.State state, byte[] op)
    { state.Stabilize(Convert.ToHexString(op)); }
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
