using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.MessagingV1;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;
using Deep.Client.Shared.Services.AttachmentV1;

namespace Deep.Client.Shared.Production.Tests;

public sealed class AuthenticatedDirectDmc2InboxTests
{
    // Structural projection only; authentication is covered by the owned native lane.
    [Fact]
    public async Task CanonicalHistoryProjectsUnicodeAndRejectsForeignOwnersAndInvalidLimits()
    {
        using var fixture = new Fixture();
        var exact = Event("Привет 👋\n第二行");
        try
        {
            using (var initial = Open(true, fixture))
            using (var handoff = Handoff(exact, 0x71))
                Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(initial, handoff));
            using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
            using var reopened = SqliteDeepMailboxStore.OpenExisting(options);
            var message = Assert.Single(await reopened.ListDirectMessageCreatesAsync(Local, 1, Conversation));
            Assert.Equal("Привет 👋\n第二行", message.Text);
            Assert.False(message.IsLocalAuthor);
            Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1000), message.CreatedAt);
            Assert.Empty(await reopened.ListDirectAttachmentOffersAsync(Local, 1, Conversation));
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.ListDirectMessageCreatesAsync(Local, 2, Conversation));
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.ListDirectAttachmentOffersAsync(Bytes(32, 0x98), 1, Conversation));
            foreach (var limit in new[] { 0, 101 })
            {
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => reopened.ListDirectMessageCreatesAsync(Local, 1, Conversation, limit));
                await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => reopened.ListDirectAttachmentOffersAsync(Local, 1, Conversation, limit));
            }
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData("exact_dmc2_hash=zeroblob(32)")]
    [InlineData("exact_dmc2=zeroblob(16669)")]
    [InlineData("exact_dmc2=zeroblob(282)")]
    [InlineData("exact_dmc2=printf('%0300d',0)")]
    public async Task CanonicalHistoryRejectsCorruptHashesAndHostileSqlPayloads(string assignment)
    {
        using var fixture = new Fixture();
        var exact = Event("retained");
        try
        {
            using (var initial = Open(true, fixture))
            using (var handoff = Handoff(exact, 0x71))
                Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(initial, handoff));
            using (var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False"))
            {
                connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
                using var change = connection.CreateCommand();
                change.CommandText = "UPDATE authenticated_dmc2_inbox SET " + assignment + ";";
                Assert.Equal(1, change.ExecuteNonQuery());
            }
            using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
            using var reopened = SqliteDeepMailboxStore.OpenExisting(options);
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.ListDirectMessageCreatesAsync(Local, 1, Conversation));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    // Structural handoff seam only. This checks event storage and exact
    // attachment bytes, not real E2EE authentication or blob transport.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AttachmentOfferAndCancelRetainExactCiphertextManifestWithoutBecomingText(bool sqlite)
    {
        using var fixture = new Fixture();
        var source = Enumerable.Range(0, 262145).Select(i => (byte)i).ToArray();
        using var prepared = await AttachmentObjectPreparation.PrepareAsync(new MemoryStream(source), source.Length,
            Network, "photo.png", "image/png", 2_000_000_000, CancellationToken.None);
        using var manifestOwner = prepared.OwnManifest();
        using var manifest = manifestOwner.Use(bytes => ApplicationCoreCodec.DecodeDam1(bytes));
        var offer = ApplicationCoreCodec.AuthorDmc2(Network, Logical, Conversation, Remote, AuthorDevice,
            3, 1000, 0, Dmc2Flags.None, [], ApplicationCoreCodec.CreateAttachmentOfferPayload(manifest)).CanonicalBytes.ToArray();
        var cancelId = Bytes(32, 0x66);
        var cancel = ApplicationCoreCodec.AuthorDmc2(Network, cancelId, Conversation, Remote, AuthorDevice,
            4, 1001, 0, Dmc2Flags.Silent, [], ApplicationCoreCodec.CreateAttachmentCancelPayload(
                manifest.ObjectId.Span, AttachmentCancelReason.SenderCancelled)).CanonicalBytes.ToArray();
        using (var store = Open(sqlite, fixture))
        {
            using var offered = Handoff(offer, 0x81); using var cancelled = Handoff(cancel, 0x82);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, offered));
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Materialize(store, offered));
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, cancelled));
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Materialize(store, cancelled));
            var retained = await Read(store); Assert.Equal(offer, retained);
            using var restored = Assert.IsType<AttachmentOfferDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(retained!).ParsedPayload).Manifest;
            var offset = 0;
            for (uint index = 0; index < prepared.ChunkCount; index++)
            {
                var plain = AttachmentChunkCipher.Decrypt(restored, index, prepared.CopyCiphertext(index));
                try { Assert.Equal(source.AsSpan(offset, plain.Length).ToArray(), plain); offset += plain.Length; }
                finally { CryptographicOperations.ZeroMemory(plain); }
            }
            if (store is SqliteDeepMailboxStore disk)
            {
                Assert.Equal(cancel, await disk.ReadDirectDmc2Async(Local, 1, Conversation, cancelId, AuthorDevice));
                Assert.Empty(await disk.ListDirectMessageCreatesAsync(Local, 1, Conversation));
                var history = Assert.Single(await disk.ListDirectAttachmentOffersAsync(Local, 1, Conversation));
                Assert.Equal("photo.png", history.Filename); Assert.Equal("image/png", history.MediaType);
                Assert.Equal((ulong)source.Length, history.PlaintextBytes); Assert.False(history.IsLocalAuthor);
                Assert.Equal(manifest.ObjectId.ToArray(), history.ObjectId.ToArray());
                Assert.Equal(Logical, history.LogicalId.ToArray()); Assert.Equal(AuthorDevice, history.AuthorDeviceId.ToArray());
                Assert.Equal(2_000_000_000UL, history.ExpiresAtUnixSeconds);
                var observed = history.ObjectId.ToArray(); observed[0] ^= 1;
                Assert.Equal(manifest.ObjectId.ToArray(), history.ObjectId.ToArray());
                Assert.DoesNotContain(typeof(DirectAttachmentOfferSnapshot).GetProperties(
                    System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic),
                    property => property.Name.Contains("Key", StringComparison.OrdinalIgnoreCase) || property.PropertyType == typeof(ParsedDam1));
            }
        }
        if (sqlite)
        {
            using var reopened = Open(true, fixture);
            Assert.Equal(offer, await Read(reopened));
            var history = Assert.Single(await ((SqliteDeepMailboxStore)reopened).ListDirectAttachmentOffersAsync(Local, 1, Conversation));
            Assert.Equal("photo.png", history.Filename); Assert.Equal(manifest.ObjectId.ToArray(), history.ObjectId.ToArray());
        }
        CryptographicOperations.ZeroMemory(offer); CryptographicOperations.ZeroMemory(cancel);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DifferentLogicalIdAtSameAuthoredPositionDurablyForks(bool sqlite)
    {
        using var fixture = new Fixture();
        var first = Event("incumbent");
        var conflicting = Event("position collision", Bytes(32, 0x65));
        try
        {
            using (var store = Open(sqlite, fixture))
            using (var incumbent = Handoff(first, 0x71))
            using (var collision = Handoff(conflicting, 0x72))
            {
                Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, incumbent));
                Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Materialize(store, collision));
                Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Materialize(store, incumbent));
                Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Materialize(store, collision));
                await Assert.ThrowsAsync<CryptographicException>(async () => await Read(store));
                if (!sqlite) return;
            }
            using var reopened = Open(true, fixture);
            using var retry = Handoff(conflicting, 0x73);
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched, await Materialize(reopened, retry));
            await Assert.ThrowsAsync<CryptographicException>(async () => await Read(reopened));
        }
        finally { CryptographicOperations.ZeroMemory(first); CryptographicOperations.ZeroMemory(conflicting); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistinctAuthoredPositionsAreNotDuplicates(bool sqlite)
    {
        using var fixture = new Fixture(); using var store = Open(sqlite, fixture);
        var first = Event("first"); var next = Event("next", Bytes(32, 0x65), 4);
        try
        {
            using var one = Handoff(first, 0x71); using var two = Handoff(next, 0x72);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, one));
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(store, two));
            var read = await Read(store); Assert.Equal(first, read); CryptographicOperations.ZeroMemory(read!);
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay, await Materialize(store, two));
        }
        finally { CryptographicOperations.ZeroMemory(first); CryptographicOperations.ZeroMemory(next); }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void OrdinaryDirectEventsCannotUseInitialPositions(ulong sequence)
    {
        var exact = Event("invalid position", sequence: sequence);
        try { Assert.Throws<CryptographicException>(() => Handoff(exact, 0x71)); }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData("PRAGMA user_version=4;")]
    [InlineData("CREATE INDEX extra_event_index ON authenticated_dmc2_inbox(content_kind);")]
    [InlineData("DROP INDEX idx_authenticated_dmc2_authored_position;")]
    [InlineData("CREATE TRIGGER extra_event_trigger AFTER INSERT ON authenticated_dmc2_inbox BEGIN SELECT 1; END;")]
    public void NonCurrentOrChangedSchemaIsNeverMigrated(string tamper)
    {
        using var fixture = new Fixture();
        using (var store = new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key))) store.RequireInitializedEmpty();
        using (var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False"))
        {
            connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
            using var command = connection.CreateCommand(); command.CommandText = tamper; command.ExecuteNonQuery();
        }
        using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(options));
    }

    [Fact]
    public async Task InitializedEmptyPolicyDoesNotAcceptMaterializedRowsAndExistingCannotRecreate()
    {
        using var fixture = new Fixture();
        using var options = new SqliteDeepMailboxStoreOptions(fixture.Path, fixture.Key);
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(options));
        var exact = Event("not empty");
        try
        {
            using var store = new SqliteDeepMailboxStore(options); store.RequireInitializedEmpty();
            using var handoff = Handoff(exact, 0x71);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized, await store.MaterializeDirectDmc2Async(handoff));
            Assert.Throws<LocalStateResetRequiredException>(() => store.RequireInitializedEmpty());
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
        File.Delete(fixture.Path);
        Assert.Throws<LocalStateResetRequiredException>(() => SqliteDeepMailboxStore.OpenExisting(options));
        Assert.False(File.Exists(fixture.Path));
    }

    [Theory]
    [InlineData("sender_sequence=x'0000000000000004'")]
    [InlineData("content_kind=0")]
    [InlineData("author_account_id=zeroblob(32)")]
    [InlineData("exact_dmc2_hash=zeroblob(32)")]
    public async Task ExactReplayDoesNotBlessCorruptSqlSemanticMetadata(string assignment)
    {
        using var fixture = new Fixture(); var exact = Event("retained");
        try
        {
            using (var initial = Open(true, fixture))
            using (var handoff = Handoff(exact, 0x71))
                Assert.Equal(DirectDmc2InboxDisposition.Materialized, await Materialize(initial, handoff));
            using (var connection = new SqliteConnection($"Data Source={fixture.Path};Pooling=False"))
            {
                connection.Open(); Assert.Equal(SQLitePCL.raw.SQLITE_OK, MailboxRandomKeyTestEncoding.Apply(connection, fixture.Key));
                using var change = connection.CreateCommand();
                change.CommandText = "UPDATE authenticated_dmc2_inbox SET " + assignment + ";";
                Assert.Equal(1, change.ExecuteNonQuery());
            }
            using var reopened = Open(true, fixture); using var retry = Handoff(exact, 0x72);
            await Assert.ThrowsAsync<CryptographicException>(async () => await Materialize(reopened, retry));
            await Assert.ThrowsAsync<CryptographicException>(async () => await Read(reopened));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExactCrossSessionReplayAndChangedBytesFork(bool sqlite)
    {
        using var fixture = new Fixture();
        using var store = Open(sqlite, fixture);
        var firstBytes = Event("first");
        var changedBytes = Event("changed");
        try
        {
            using var first = Handoff(firstBytes, 0x71);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                await Materialize(store, first));
            var read = await Read(store);
            Assert.Equal(firstBytes, read);
            CryptographicOperations.ZeroMemory(read!);

            using var crossSessionReplay = Handoff(firstBytes, 0x72);
            Assert.Equal(DirectDmc2InboxDisposition.ExactReplay,
                await Materialize(store, crossSessionReplay));
            var afterCallerClearedCopy = await Read(store);
            Assert.Equal(firstBytes, afterCallerClearedCopy);
            CryptographicOperations.ZeroMemory(afterCallerClearedCopy!);

            using var conflicting = Handoff(changedBytes, 0x73);
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                await Materialize(store, conflicting));
            Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                await Materialize(store, first));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(store));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstBytes);
            CryptographicOperations.ZeroMemory(changedBytes);
        }
    }

    [Fact]
    public async Task SqliteMaterializationAndForkSurviveRestart()
    {
        using var fixture = new Fixture();
        var exact = Event("durable");
        var conflict = Event("different");
        try
        {
            using (var firstStore = Open(sqlite: true, fixture))
            using (var first = Handoff(exact, 0x74))
                Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                    await Materialize(firstStore, first));

            using (var restarted = Open(sqlite: true, fixture))
            {
                var read = await Read(restarted);
                Assert.Equal(exact, read);
                CryptographicOperations.ZeroMemory(read!);
                using var changed = Handoff(conflict, 0x75);
                Assert.Equal(DirectDmc2InboxDisposition.ForkLatched,
                    await Materialize(restarted, changed));
            }
            using var forked = Open(sqlite: true, fixture);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(forked));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exact);
            CryptographicOperations.ZeroMemory(conflict);
        }
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task SqliteCrashIsPriorOrExactlyMaterialized(
        int crashPointValue, bool committed)
    {
        var crashPoint = (DirectDmc2InboxFaultPoint)crashPointValue;
        using var fixture = new Fixture();
        var exact = Event("crash");
        try
        {
            using (var firstStore = Open(sqlite: true, fixture))
            using (var handoff = Handoff(exact, 0x77))
            using (DirectDmc2InboxTestHooks.Push(point =>
                       { if (point == crashPoint)
                               throw new InvalidOperationException("Injected inbox crash."); }))
                await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                    await Materialize(firstStore, handoff));

            using var restarted = Open(sqlite: true, fixture);
            var recovered = await Read(restarted);
            Assert.Equal(committed, recovered is not null);
            if (recovered is not null)
            {
                Assert.Equal(exact, recovered);
                CryptographicOperations.ZeroMemory(recovered);
            }
            using var retry = Handoff(exact, 0x78);
            Assert.Equal(committed
                    ? DirectDmc2InboxDisposition.ExactReplay
                    : DirectDmc2InboxDisposition.Materialized,
                await Materialize(restarted, retry));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongAccountGenerationAndUnauthenticatedScopeReject(bool sqlite)
    {
        using var fixture = new Fixture();
        using var store = Open(sqlite, fixture);
        var exact = Event("scope");
        try
        {
            Assert.Throws<CryptographicException>(() => AuthenticatedDirectDmc2.CreateForTests(
                exact, Network, Local, 1, Conversation, Remote,
                Bytes(32, 0x99), Bytes(32, 0x76), Bytes(32, 0x86)));
            using var first = Handoff(exact, 0x76);
            Assert.Equal(DirectDmc2InboxDisposition.Materialized,
                await Materialize(store, first));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Read(store, generation: 2));
            using var anotherGeneration = AuthenticatedDirectDmc2.CreateForTests(
                exact, Network, Local, 2, Conversation, Remote,
                AuthorDevice, Bytes(32, 0x80), Bytes(32, 0x90));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await Materialize(store, anotherGeneration));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    [Fact]
    public void MailboxOptionsClearOwnedKeyOnDispose()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        using var options = new SqliteDeepMailboxStoreOptions("unused.db", key);
        var observed = options.EncryptionKey;
        options.Dispose();
        Assert.True(observed.Span.IndexOfAnyExcept((byte)0) < 0);
        Assert.Throws<ObjectDisposedException>(() => _ = options.EncryptionKey);
        Assert.True(key.AsSpan().IndexOfAnyExcept((byte)0) >= 0);
        CryptographicOperations.ZeroMemory(key);
    }

    [Fact]
    public void EphemeralTypingCannotEnterDurableDirectHistory()
    {
        var exact = ApplicationCoreCodec.AuthorDmc2(
            Network, Logical, Conversation, Remote, AuthorDevice,
            1, 1_000, 2_000, Dmc2Flags.Silent, [],
            ApplicationCoreCodec.CreateTypingPayload(
                TypingOperation.Start, Bytes(32, 0xA1))).CanonicalBytes.ToArray();
        try
        {
            Assert.Throws<CryptographicException>(() => Handoff(exact, 0x81));
        }
        finally { CryptographicOperations.ZeroMemory(exact); }
    }

    private static readonly byte[] Network = Bytes(16, 0x11);
    private static readonly byte[] Local = Bytes(32, 0x21);
    private static readonly byte[] Remote = Bytes(32, 0x31);
    private static readonly byte[] AuthorDevice = Bytes(32, 0x41);
    private static readonly byte[] Conversation = Bytes(32, 0x51);
    private static readonly byte[] Logical = Bytes(32, 0x61);

    private static byte[] Event(string text, byte[]? logical = null, ulong sequence = 3) => ApplicationCoreCodec.AuthorDmc2(
        Network, logical ?? Logical, Conversation, Remote, AuthorDevice,
        sequence, 1_000, 0, Dmc2Flags.None, [],
        ApplicationCoreCodec.CreateMessageCreatePayload(text)).CanonicalBytes.ToArray();

    private static AuthenticatedDirectDmc2 Handoff(byte[] exact, byte operation) =>
        AuthenticatedDirectDmc2.CreateForTests(
            exact, Network, Local, 1, Conversation, Remote, AuthorDevice,
            Bytes(32, operation), Bytes(32, unchecked((byte)(operation + 0x10))));

    private static IDisposable Open(bool sqlite, Fixture fixture) => sqlite
        ? new SqliteDeepMailboxStore(new(fixture.Path, fixture.Key))
        : new InMemoryAuthenticatedDirectDmc2Inbox();

    private static Task<DirectDmc2InboxDisposition> Materialize(
        IDisposable store, AuthenticatedDirectDmc2 handoff) => store switch
        {
            SqliteDeepMailboxStore disk => disk.MaterializeDirectDmc2Async(handoff),
            InMemoryAuthenticatedDirectDmc2Inbox memory =>
                memory.MaterializeDirectDmc2Async(handoff),
            _ => throw new InvalidOperationException(),
        };

    private static Task<byte[]?> Read(IDisposable store, ulong generation = 1) =>
        store switch
        {
            SqliteDeepMailboxStore disk => disk.ReadDirectDmc2Async(
                Local, generation, Conversation, Logical, AuthorDevice),
            InMemoryAuthenticatedDirectDmc2Inbox memory =>
                memory.ReadDirectDmc2Async(
                    Local, generation, Conversation, Logical, AuthorDevice),
            _ => throw new InvalidOperationException(),
        };

    private static byte[] Bytes(int length, byte start) =>
        Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-direct-inbox-" + Guid.NewGuid().ToString("N"));

        internal Fixture() => Directory.CreateDirectory(directory);
        internal string Path => System.IO.Path.Combine(directory, "mailbox.db");
        internal byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            Directory.Delete(directory, recursive: true);
        }
    }
}
