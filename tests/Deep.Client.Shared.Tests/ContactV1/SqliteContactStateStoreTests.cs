using System.Buffers.Binary;
using Deep.Client.Shared.Domain.ContactV1;
using Deep.Client.Shared.Persistence.ContactV1;
using Deep.Client.Shared.Services.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.ContactV1;

public sealed class SqliteContactStateStoreTests
{
    private static readonly byte[] Network = Bytes(16, 0x11);

    [Fact]
    public async Task RestartPreservesExactPendingAddressesFirstTimestampAndDeterministicOrder()
    {
        using var fixture = StoreFixture.Create();
        var firstTime = DateTimeOffset.FromUnixTimeSeconds(1_900_000_100);
        var secondTime = firstTime.AddSeconds(-10);
        byte[] firstCanonical;
        using (var store = new SqliteContactStateStore(fixture.Options))
        {
            var first = await ImportDidAsync(store, 0x31, firstTime);
            var second = await ImportDidAsync(store, 0x32, secondTime);
            firstCanonical = first.PendingAddress.Address.CanonicalBytes.ToArray();
            firstCanonical[0] ^= 0x7f;

            var replay = await ImportDidAsync(store, 0x31, firstTime.AddDays(2));
            Assert.Equal(PendingContactAddressWriteDisposition.Idempotent, replay.Disposition);
            Assert.Equal(firstTime, replay.PendingAddress.ImportedAt);
            Assert.Equal(secondTime, second.PendingAddress.ImportedAt);
            store.ValidateEncryptedFilesForTesting();
        }

        using var reopened = new SqliteContactStateStore(fixture.Options);
        var restored = await reopened.ReadPendingAddressesAsync();

        Assert.Equal(2, restored.Count);
        Assert.Equal(secondTime, restored[0].ImportedAt);
        Assert.Equal(firstTime, restored[1].ImportedAt);
        Assert.NotEqual(firstCanonical, restored[1].Address.CanonicalBytes.ToArray());
        Assert.Equal(ContactStoreScope.CurrentStoreGeneration, reopened.Scope.StoreGeneration);
        Assert.Equal(fixture.Options.Scope.AccountId, reopened.Scope.AccountId);
    }

    [Fact]
    public async Task ConcurrentPutIsAtomicIdempotentAndKeepsFirstImportedAt()
    {
        using var fixture = StoreFixture.Create();
        using var storeA = new SqliteContactStateStore(fixture.Options);
        using var storeB = new SqliteContactStateStore(fixture.Options);
        var firstTime = DateTimeOffset.FromUnixTimeSeconds(1_900_000_200);
        var services = new[]
        {
            new ContactAddressImportService(storeA, Network, new FixedTimeProvider(firstTime)),
            new ContactAddressImportService(storeB, Network, new FixedTimeProvider(firstTime)),
        };
        var did = Did(0x41).Text;
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var tasks = Enumerable.Range(0, 32)
            .Select(index => Task.Run(async () =>
            {
                await start.Task;
                return await services[index % services.Length].ImportAsync(did);
            }))
            .ToArray();
        start.TrySetResult();
        var results = await Task.WhenAll(tasks);

        Assert.Single(results, static result =>
            result.Disposition == PendingContactAddressWriteDisposition.Added);
        Assert.Equal(31, results.Count(static result =>
            result.Disposition == PendingContactAddressWriteDisposition.Idempotent));
        var persisted = Assert.Single(await storeA.ReadPendingAddressesAsync());
        Assert.Equal(firstTime, persisted.ImportedAt);
    }

    [Fact]
    public async Task EqualTimestampListUsesKindThenCanonicalBytesAsStableTieBreakers()
    {
        using var fixture = StoreFixture.Create();
        using var store = new SqliteContactStateStore(fixture.Options);
        var time = DateTimeOffset.FromUnixTimeSeconds(1_900_000_250);
        await ImportDidAsync(store, 0x52, time);
        await ImportDidAsync(store, 0x51, time);

        var rows = await store.ReadPendingAddressesAsync();

        Assert.Equal(2, rows.Count);
        Assert.True(rows[0].Address.CanonicalBytes.Span.SequenceCompareTo(
            rows[1].Address.CanonicalBytes.Span) < 0);
    }

    [Fact]
    public async Task ExactTenThousandCapacityRejectsNextWithoutEviction()
    {
        using var fixture = StoreFixture.Create();
        using (var store = new SqliteContactStateStore(fixture.Options)) { }
        SeedPendingDids(fixture.Options, count: 9_999);

        using var reopened = new SqliteContactStateStore(fixture.Options);
        var service = new ContactAddressImportService(reopened, Network,
            new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_900_001_000)));
        var last = await service.ImportAsync(Did(20_000).Text);
        Assert.Equal(PendingContactAddressWriteDisposition.Added, last.Disposition);

        var full = await Assert.ThrowsAsync<ContactAddressImportException>(async () =>
            await service.ImportAsync(Did(20_001).Text));

        Assert.Equal(ContactAddressImportFailure.LocalCapacityExceeded, full.Failure);
        Assert.Equal(10_000, (await reopened.ReadPendingAddressesAsync()).Count);
    }

    [Fact]
    public async Task WrongAccountStoreGenerationAndKeyFailClosedWithoutMixingData()
    {
        using var fixture = StoreFixture.Create();
        using (var store = new SqliteContactStateStore(fixture.Options))
            await ImportDidAsync(store, 0x59, DateTimeOffset.FromUnixTimeSeconds(1_900_000_275));

        using var wrongAccountOptions = fixture.OptionsFor(scope: Scope(0x72));
        var wrongAccount = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(wrongAccountOptions));
        Assert.Equal(ContactStateStoreOpenFailure.ScopeMismatch, wrongAccount.Reason);

        using var wrongGenerationOptions = fixture.OptionsFor(scope: new ContactStoreScope(
            fixture.Options.Scope.AccountId, ContactStoreScope.CurrentStoreGeneration + 1));
        var wrongGeneration = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(wrongGenerationOptions));
        Assert.Equal(ContactStateStoreOpenFailure.UnsupportedGeneration, wrongGeneration.Reason);

        using var wrongKeyOptions = fixture.OptionsFor(keyMarker: 0xE2);
        var wrongKey = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(wrongKeyOptions));
        Assert.Equal(ContactStateStoreOpenFailure.UnreadableOrWrongKey, wrongKey.Reason);

        using var correct = new SqliteContactStateStore(fixture.Options);
        Assert.Single(await correct.ReadPendingAddressesAsync());
    }

    [Fact]
    public void SqlCipherKeyIsMandatoryAndPlaintextDatabaseNeverOpens()
    {
        using var fixture = StoreFixture.Create();
        Assert.Throws<ArgumentException>(() => new SqliteContactStateStoreOptions(
            fixture.Path, [], Scope()));
        Assert.Throws<ArgumentException>(() => new SqliteContactStateStoreOptions(
            fixture.Path, new byte[32], Scope()));
        Assert.Throws<ArgumentException>(() => new SqliteContactStateStoreOptions(
            fixture.Path, Bytes(31, 0xE1), Scope()));

        using (var plaintext = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = fixture.Path,
            Pooling = false,
        }.ToString()))
        {
            plaintext.Open();
            using var command = plaintext.CreateCommand();
            command.CommandText = "CREATE TABLE not_contact_state(value INTEGER);";
            command.ExecuteNonQuery();
        }

        var failure = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.UnreadableOrWrongKey, failure.Reason);
    }

    [Fact]
    public void UnsupportedSchemaAndModifiedDdlFailClosed()
    {
        using var fixture = StoreFixture.Create();
        using (var store = new SqliteContactStateStore(fixture.Options)) { }
        using (var database = OpenEncrypted(fixture.Options))
            Execute(database, "PRAGMA user_version=99;");

        var generation = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.UnsupportedGeneration, generation.Reason);

        fixture.ResetDatabaseFiles();
        using (var store = new SqliteContactStateStore(fixture.Options)) { }
        using (var database = OpenEncrypted(fixture.Options))
        {
            Execute(database, """
                PRAGMA writable_schema=ON;
                UPDATE sqlite_master SET sql=replace(sql,'kind IN (1,2)','kind IN (1,3)')
                WHERE name='pending_contact_addresses';
                PRAGMA writable_schema=OFF;
                """);
        }

        var schema = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.Corrupt, schema.Reason);
    }

    [Fact]
    public async Task SemanticallyCorruptRowFailsDuringOpenNotAfterFirstRead()
    {
        using var fixture = StoreFixture.Create();
        using (var store = new SqliteContactStateStore(fixture.Options))
            await ImportDidAsync(store, 0x61, DateTimeOffset.FromUnixTimeSeconds(1_900_000_300));
        using (var database = OpenEncrypted(fixture.Options))
        {
            using var command = database.CreateCommand();
            command.CommandText = """
                PRAGMA ignore_check_constraints=ON;
                UPDATE pending_contact_addresses SET canonical_text=$text;
                PRAGMA ignore_check_constraints=OFF;
                """;
            command.Parameters.AddWithValue("$text", new string('q', 90));
            command.ExecuteNonQuery();
        }

        var corrupt = Assert.Throws<ContactStateStoreOpenException>(() =>
            new SqliteContactStateStore(fixture.Options));
        Assert.Equal(ContactStateStoreOpenFailure.Corrupt, corrupt.Reason);
    }

    [Fact]
    public async Task CancelledOperationsDoNotReadOrMutateState()
    {
        using var fixture = StoreFixture.Create();
        using var store = new SqliteContactStateStore(fixture.Options);
        var existing = await ImportDidAsync(store, 0x71,
            DateTimeOffset.FromUnixTimeSeconds(1_900_000_400));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.ReadPendingAddressesAsync(cancelled.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.ReadPendingAddressAsync(existing.PendingAddress.Address.Kind,
                existing.PendingAddress.Address.CanonicalBytes, cancelled.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.PutPendingAddressAsync(existing.PendingAddress, cancelled.Token).AsTask());

        Assert.Single(await store.ReadPendingAddressesAsync());
    }

    [Fact]
    public async Task DisposedStoreRejectsOperationsAndZeroizesOwnedKey()
    {
        using var fixture = StoreFixture.Create();
        var store = new SqliteContactStateStore(fixture.Options);
        store.Dispose();

        Assert.True(store.EncryptionKeyIsZeroized);
        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            store.ReadPendingAddressesAsync().AsTask());
    }

    [Fact]
    public async Task OptionsOwnOneReopenKeyCopyAndDisposeZeroizesItWithoutBreakingOpenStore()
    {
        using var fixture = StoreFixture.Create();
        var callerKey = Bytes(32, 0xD3);
        using var options = new SqliteContactStateStoreOptions(
            fixture.Path, callerKey, fixture.Options.Scope);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(callerKey);
        using var store = new SqliteContactStateStore(options);
        await ImportDidAsync(store, 0x73, DateTimeOffset.FromUnixTimeSeconds(1_900_000_500));

        options.Dispose();

        Assert.True(options.EncryptionKeyIsZeroized);
        Assert.Single(await store.ReadPendingAddressesAsync());
        Assert.Throws<ObjectDisposedException>(() => new SqliteContactStateStore(options));
        store.Dispose();
        Assert.True(store.EncryptionKeyIsZeroized);
    }

    private static async Task<ContactAddressImportResult> ImportDidAsync(
        IContactStateStore store,
        int marker,
        DateTimeOffset importedAt)
    {
        var service = new ContactAddressImportService(store, Network, new FixedTimeProvider(importedAt));
        return await service.ImportAsync(Did(marker).Text);
    }

    private static ParsedDid1 Did(int marker)
    {
        var addressKey = Bytes(32, 0x22);
        BinaryPrimitives.WriteInt32BigEndian(addressKey.AsSpan(28), marker);
        var readCapability = Bytes(16, 0x33);
        BinaryPrimitives.WriteInt32BigEndian(readCapability.AsSpan(12), marker);
        return ApplicationCoreCodec.AuthorDid1(addressKey, readCapability);
    }

    private static void SeedPendingDids(SqliteContactStateStoreOptions options, int count)
    {
        using var database = OpenEncrypted(options);
        using var transaction = database.BeginTransaction(deferred: false);
        using var command = database.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO pending_contact_addresses(
              kind,canonical_bytes,network_id,canonical_text,expires_at,imported_at_utc_ticks)
            VALUES(1,$canonical,$network,$text,NULL,$imported);
            """;
        var canonical = command.Parameters.Add("$canonical", SqliteType.Blob);
        command.Parameters.AddWithValue("$network", Network);
        var text = command.Parameters.Add("$text", SqliteType.Text);
        var imported = command.Parameters.Add("$imported", SqliteType.Integer);
        for (var index = 1; index <= count; index++)
        {
            var did = Did(index);
            canonical.Value = did.CanonicalBytes.ToArray();
            text.Value = did.Text;
            imported.Value = index;
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        transaction.Commit();
    }

    private static SqliteConnection OpenEncrypted(SqliteContactStateStoreOptions options)
    {
        SQLitePCL.Batteries_V2.Init();
        var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = options.StatePath,
            Pooling = false,
        }.ToString());
        database.Open();
        var key = new byte[32];
        options.CopyEncryptionKeyTo(key);
        try
        {
            Assert.Equal(SQLitePCL.raw.SQLITE_OK,
                SQLitePCL.raw.sqlite3_key(database.Handle, key));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        }
        return database;
    }

    private static void Execute(SqliteConnection database, string sql)
    {
        using var command = database.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static ContactStoreScope Scope(
        byte accountMarker = 0x71,
        int storeGeneration = ContactStoreScope.CurrentStoreGeneration) =>
        new(DeepAccountIdentityCapability.FromVerifiedInputs(
            DeepNetworkId16.FromVerifiedBytes(Network),
            accountGeneration: 1,
            AccountEd25519PublicKey32.FromVerifiedBytes(Bytes(32, accountMarker))).AccountId,
            storeGeneration);

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class StoreFixture : IDisposable
    {
        private StoreFixture(string directory)
        {
            Directory = directory;
            Path = System.IO.Path.Combine(directory, "contacts.db");
            Options = new SqliteContactStateStoreOptions(Path, Bytes(32, 0xE1), Scope());
        }

        internal string Directory { get; }
        internal string Path { get; }
        internal SqliteContactStateStoreOptions Options { get; }

        internal static StoreFixture Create()
        {
            var directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                "deep-contact-v1-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(directory);
            return new StoreFixture(directory);
        }

        internal SqliteContactStateStoreOptions OptionsFor(
            byte keyMarker = 0xE1,
            ContactStoreScope? scope = null) =>
            new(Path, Bytes(32, keyMarker), scope ?? Options.Scope);

        internal void ResetDatabaseFiles()
        {
            SqliteConnection.ClearAllPools();
            foreach (var file in new[] { Path, Path + "-wal", Path + "-shm" })
                if (File.Exists(file)) File.Delete(file);
        }

        public void Dispose()
        {
            Options.Dispose();
            SqliteConnection.ClearAllPools();
            if (System.IO.Directory.Exists(Directory))
                System.IO.Directory.Delete(Directory, recursive: true);
        }
    }
}
