using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;
using Sodium;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class MailboxCredentialStateRepositoryTests
{
    [Fact]
    public async Task Import_restart_and_counter_allocation_never_reuses_a_counter()
    {
        var fixture = new Fixture();
        var state = new InMemoryClientMailboxStateRepository();
        await state.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
        Assert.Equal(1UL, (await state.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250)).ReplayCounter);
        var restarted = state.RestartInstallationForTests();
        Assert.Equal(2UL, (await restarted.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250)).ReplayCounter);
        await Assert.ThrowsAsync<InvalidOperationException>(() => restarted.SwitchCredentialEpochAsync(6, 199));
        await restarted.SwitchCredentialEpochAsync(6, 250);
        Assert.Equal(1UL, (await restarted.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250)).ReplayCounter);
    }

    [Fact]
    public async Task Import_rejects_wrong_holder_revocation_and_generation_equivocation()
    {
        var fixture = new Fixture();
        var state = new InMemoryClientMailboxStateRepository();
        await state.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
        var changed = fixture.Bundle.Clone();
        await Assert.ThrowsAsync<InvalidDataException>(() => state.ImportCredentialGenerationAsync(
            changed, fixture.Policy with { HolderPublicKey = Bytes(32, 111) }));
        await Assert.ThrowsAsync<InvalidDataException>(() => state.ImportCredentialGenerationAsync(
            new MailboxCredentialGeneration(changed.Generation.Span, Bytes(32, 77), changed.NetworkId.Span,
                changed.IssuerPublicKey.Span, changed.HolderPublicKey.Span, changed.OwnMailboxId.Span,
                changed.PeerMailboxId.Span, changed.Current, changed.Next, changed.OwnRetrieve,
                changed.OwnDeposit, changed.PeerDeposit, changed.Replicas), fixture.Policy));
        var revoked = new Fixture(revoke: true);
        await Assert.ThrowsAsync<InvalidDataException>(() => new InMemoryClientMailboxStateRepository()
            .ImportCredentialGenerationAsync(revoked.Bundle, revoked.Policy));
    }

    [Fact]
    public async Task Factory_emits_verifiable_mau2_and_rejects_live_revocation()
    {
        var fixture = new Fixture(); var state = new InMemoryClientMailboxStateRepository();
        await state.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
        var revoked = new Revocations(); var factory = new MailboxAuthenticatedRequestFactory(state, revoked,
            new FixedTimeProvider(250));
        var frame = await factory.CreateRetrieveAsync(fixture.Signer, Bytes(16, 91), 0, 10, Array.Empty<byte>());
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(frame.GetCanonicalMau2Copy());
        Assert.Equal(MailboxAuthenticatedOperation.Retrieve, decoded.Binding.Operation);
        Assert.Equal(1UL, decoded.Presentation.ReplayCounter);
        revoked.Revoked = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => factory.CreateRetrieveAsync(
            fixture.Signer, Bytes(16, 92), 0, 10, Array.Empty<byte>()));
        revoked.Revoked = false;
        var afterRevocation = await factory.CreateRetrieveAsync(
            fixture.Signer,
            Bytes(16, 93),
            0,
            10,
            Array.Empty<byte>());
        Assert.Equal(
            3UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                afterRevocation.GetCanonicalMau2Copy()).Presentation.ReplayCounter);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            factory.CreateRetrieveAsync(
                new InvalidSignatureSigner(fixture.Signer.GetEd25519PublicKey()),
                Bytes(16, 94),
                0,
                10,
                Array.Empty<byte>()));
        var afterInvalidSignature = await factory.CreateRetrieveAsync(
            fixture.Signer,
            Bytes(16, 95),
            0,
            10,
            Array.Empty<byte>());
        Assert.Equal(
            5UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                afterInvalidSignature.GetCanonicalMau2Copy()).Presentation.ReplayCounter);
    }

    [Fact]
    public async Task Invalid_factory_input_does_not_lease_or_burn_a_counter()
    {
        var fixture = new Fixture();
        var state = new InMemoryClientMailboxStateRepository();
        await state.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
        var factory = new MailboxAuthenticatedRequestFactory(
            state,
            new Revocations(),
            new FixedTimeProvider(250));

        await Assert.ThrowsAsync<MailboxClientException>(() =>
            factory.CreateStoreAsync(
                fixture.Signer,
                new MailboxEncryptedEnvelope
                {
                    Epoch = fixture.Bundle.Current.Epoch,
                    MailboxId = new BlindedMailboxId(
                        fixture.Bundle.PeerMailboxId.Span),
                    PlacementId = new BlindedPlacementId(
                        fixture.Bundle.Current.PlacementId.Span),
                    OperationId = new byte[16],
                    DeduplicationDigest = Bytes(32, 98),
                    CreatedAtUnixSeconds = 200,
                    ExpiresAtUnixSeconds = 300,
                    Ciphertext = Bytes(
                        MailboxClientLimits.MinimumCiphertextLength,
                        99)
                }));
        await Assert.ThrowsAsync<ArgumentException>(() => factory.CreateRetrieveAsync(
            fixture.Signer,
            new byte[16],
            0,
            0,
            Array.Empty<byte>()));
        await Assert.ThrowsAsync<ArgumentException>(() => factory.CreateAckAsync(
            fixture.Signer,
            Bytes(16, 96),
            true,
            Array.Empty<byte>(),
            []));

        var valid = await factory.CreateRetrieveAsync(
            fixture.Signer,
            Bytes(16, 97),
            0,
            10,
            Array.Empty<byte>());
        Assert.Equal(
            1UL,
            MailboxAuthenticatedClientRequestCodec.Decode(
                valid.GetCanonicalMau2Copy()).Presentation.ReplayCounter);
    }

    [Fact]
    public async Task Sqlite_restart_counter_boundary_is_durable()
    {
        var fixture = new Fixture();
        var path = Path.Combine(Path.GetTempPath(), "deep-mailbox-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using (var first = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key")))
            {
                await first.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
                Assert.Equal(1UL, (await first.LeaseCredentialAsync(MailboxCredentialGrantKind.PeerDeposit, 250)).ReplayCounter);
            }
            using var restarted = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key"));
            Assert.Equal(2UL, (await restarted.LeaseCredentialAsync(MailboxCredentialGrantKind.PeerDeposit, 250)).ReplayCounter);
        }
        finally
        {
            foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
                if (File.Exists(candidate)) File.Delete(candidate);
        }
    }

    [Fact]
    public void Sqlite_v6_is_rejected_without_schema_mutation()
    {
        var path = Path.Combine(Path.GetTempPath(), "deep-mailbox-v6-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using (var connection = Open(path))
            using (var command = connection.CreateCommand())
            {
                command.CommandText = """
                    CREATE TABLE client_mailbox_meta (id INTEGER PRIMARY KEY CHECK(id = 1), schema_version INTEGER NOT NULL);
                    INSERT INTO client_mailbox_meta(id, schema_version) VALUES(1, 6);
                    CREATE TABLE client_mailbox_traversal (scope BLOB PRIMARY KEY NOT NULL, after_cursor BLOB NOT NULL, continuation_token BLOB NOT NULL);
                    CREATE TABLE client_mailbox_inbox (scope BLOB NOT NULL, cursor BLOB NOT NULL, digest BLOB NOT NULL, expires_at BLOB NOT NULL, canonical_envelope BLOB NOT NULL, acknowledged INTEGER NOT NULL, PRIMARY KEY(scope, cursor), UNIQUE(scope, digest));
                    CREATE TABLE client_mailbox_expired_quarantine (scope BLOB NOT NULL, cursor BLOB NOT NULL, digest BLOB NOT NULL, expires_at BLOB NOT NULL, canonical_envelope BLOB NOT NULL, quarantined_at INTEGER NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(scope, cursor, digest));
                    CREATE TABLE client_mailbox_coordinator_journal (installation_scope BLOB NOT NULL, statement_key BLOB NOT NULL, statement_digest BLOB NOT NULL, expires_at BLOB NOT NULL, PRIMARY KEY(installation_scope, statement_key));
                    """;
                command.ExecuteNonQuery();
            }
            var before = File.ReadAllBytes(path);
            Assert.Throws<InvalidDataException>(() => new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key")));
            Assert.Equal(before, File.ReadAllBytes(path));
            Assert.False(File.Exists(path + "-wal"));
            Assert.False(File.Exists(path + "-shm"));
            using var verify = Open(path); using var tables = verify.CreateCommand();
            tables.CommandText = "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'client_mailbox_credentials';";
            Assert.Equal(0L, (long)tables.ExecuteScalar()!);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Sqlite_two_instances_allocate_distinct_monotonic_counters()
    {
        var fixture = new Fixture(); var path = NewPath();
        try
        {
            using var first = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key"));
            using var second = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key"));
            await first.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
            var tasks = Enumerable.Range(0, 24).Select(index => (index & 1) == 0
                ? first.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250)
                : second.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250));
            var counters = (await Task.WhenAll(tasks)).Select(item => item.ReplayCounter).Order().ToArray();
            Assert.Equal(Enumerable.Range(1, 24).Select(static value => (ulong)value), counters);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Counter_exhaustion_and_postcommit_failure_never_reuse()
    {
        var fixture = new Fixture(); var path = NewPath();
        try
        {
            using (var state = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key")))
            {
                await state.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
                _ = await state.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250);
            }
            var key = SHA256.HashData(fixture.Bundle.OwnRetrieve.CurrentGrant.Span);
            using (var connection = Open(path)) using (var update = connection.CreateCommand())
            {
                update.CommandText = "UPDATE client_mailbox_replay_counters SET next_counter = $counter WHERE grant_key = $key;";
                update.Parameters.Add("$counter", SqliteType.Blob).Value = U64(ulong.MaxValue);
                update.Parameters.Add("$key", SqliteType.Blob).Value = key;
                update.ExecuteNonQuery();
            }
            using var exhausted = new SqliteClientMailboxStateRepository(new SqliteSessionStoreOptions(path, "test-key"));
            await Assert.ThrowsAsync<InvalidOperationException>(() => exhausted.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnRetrieve, 250));
        }
        finally { DeleteDatabase(path); }

        var armed = false;
        var fault = new InMemoryClientMailboxStateRepository(point =>
        {
            if (armed && point == ClientMailboxCommitFaultPoint.AfterCommit) throw new IOException("test");
        });
        await fault.ImportCredentialGenerationAsync(fixture.Bundle, fixture.Policy);
        armed = true;
        await Assert.ThrowsAsync<IOException>(() => fault.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnDeposit, 250));
        var restarted = fault.RestartInstallationForTests();
        Assert.Equal(2UL, (await restarted.LeaseCredentialAsync(MailboxCredentialGrantKind.OwnDeposit, 250)).ReplayCounter);
    }

    [Fact]
    public async Task Import_rejects_wrong_issuer_network_placement_replica_and_bounds()
    {
        var fixture = new Fixture();
        foreach (var policy in new[]
        {
            fixture.Policy with { IssuerPublicKey = Bytes(32, 100) },
            fixture.Policy with { NetworkId = Bytes(16, 101) },
            fixture.Policy with { Replicas = new MailboxCredentialReplicaPair(Bytes(32, 80), Bytes(32, 81), Bytes(32, 82), Bytes(32, 83)) }
        })
            await Assert.ThrowsAsync<InvalidDataException>(() => new InMemoryClientMailboxStateRepository().ImportCredentialGenerationAsync(fixture.Bundle, policy));
        var invalidPlacement = new MailboxCredentialEpoch(5, 100, 300, fixture.Bundle.Current.MembershipCommitment.Span,
            Bytes(32, 90), fixture.Bundle.Current.PlacementCommitment.Span);
        var malformed = new MailboxCredentialGeneration(fixture.Bundle.Generation.Span, fixture.Bundle.ManifestHash.Span,
            fixture.Bundle.NetworkId.Span, fixture.Bundle.IssuerPublicKey.Span, fixture.Bundle.HolderPublicKey.Span,
            fixture.Bundle.OwnMailboxId.Span, fixture.Bundle.PeerMailboxId.Span, invalidPlacement, fixture.Bundle.Next,
            fixture.Bundle.OwnRetrieve, fixture.Bundle.OwnDeposit, fixture.Bundle.PeerDeposit, fixture.Bundle.Replicas);
        await Assert.ThrowsAsync<InvalidDataException>(() => new InMemoryClientMailboxStateRepository().ImportCredentialGenerationAsync(malformed, fixture.Policy));
        Assert.Throws<ArgumentException>(() => new MailboxCredentialGrantSet(new byte[1], new byte[1]));
    }

    [Theory]
    [InlineData("CREATE TABLE foreign_state(value INTEGER);")]
    [InlineData("CREATE VIEW hostile_view AS SELECT schema_version FROM client_mailbox_meta;")]
    [InlineData("CREATE TRIGGER hostile_trigger AFTER UPDATE ON client_mailbox_meta BEGIN SELECT 1; END;")]
    public async Task Sqlite_preflight_rejects_every_unexpected_user_object_without_mutation(
        string hostileSql)
    {
        var fixture = new Fixture();
        var path = NewPath();
        try
        {
            await CreateCurrentDatabaseAsync(path, fixture);
            using (var connection = Open(path))
            using (var command = connection.CreateCommand())
            {
                command.CommandText = hostileSql;
                command.ExecuteNonQuery();
                command.CommandText =
                    "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;";
                command.ExecuteNonQuery();
            }
            var before = File.ReadAllBytes(path);
            Assert.False(File.Exists(path + "-wal"));
            Assert.False(File.Exists(path + "-shm"));
            Assert.Throws<InvalidDataException>(() =>
                new SqliteClientMailboxStateRepository(
                    new SqliteSessionStoreOptions(path, "test-key")));
            Assert.Equal(before, File.ReadAllBytes(path));
            Assert.False(File.Exists(path + "-wal"));
            Assert.False(File.Exists(path + "-shm"));
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Preflight_catalog_and_detail_reads_share_one_snapshot()
    {
        var fixture = new Fixture();
        var path = NewPath();
        try
        {
            await CreateCurrentDatabaseAsync(path, fixture);
            using (var connection = Open(path))
            using (var command = connection.CreateCommand())
            {
                command.CommandText = "PRAGMA journal_mode = WAL;";
                _ = command.ExecuteScalar();
            }

            var injected = false;
            Assert.Throws<InvalidDataException>(() =>
                new SqliteClientMailboxStateRepository(
                    new SqliteSessionStoreOptions(path, "test-key"),
                    commitFault: null,
                    schemaPreflightFault: point =>
                    {
                        Assert.Equal(
                            ClientMailboxSchemaPreflightPoint.AfterCatalogSnapshot,
                            point);
                        using var writer = Open(path);
                        using var create = writer.CreateCommand();
                        create.CommandText =
                            "CREATE VIEW snapshot_race_view AS " +
                            "SELECT schema_version FROM client_mailbox_meta;";
                        create.ExecuteNonQuery();
                        injected = true;
                    }));
            Assert.True(injected);
        }
        finally { DeleteDatabase(path); }
    }

    [Fact]
    public async Task Epoch_switch_winning_race_cannot_mismatch_mau2_or_burn_next_grant()
    {
        var fixture = new Fixture();
        var path = NewPath();
        using var switchEntered = new ManualResetEventSlim();
        using var releaseSwitch = new ManualResetEventSlim();
        var armed = false;
        try
        {
            using var switching = new SqliteClientMailboxStateRepository(
                new SqliteSessionStoreOptions(path, "test-key"),
                point =>
                {
                    if (armed && point == ClientMailboxCommitFaultPoint.BeforeCommit)
                    {
                        switchEntered.Set();
                        Assert.True(releaseSwitch.Wait(TimeSpan.FromSeconds(10)));
                    }
                });
            await switching.ImportCredentialGenerationAsync(
                fixture.Bundle,
                fixture.Policy);
            using var leasing = new SqliteClientMailboxStateRepository(
                new SqliteSessionStoreOptions(path, "test-key"));
            var factory = new MailboxAuthenticatedRequestFactory(
                leasing,
                new Revocations(),
                new FixedTimeProvider(250));
            var oldEnvelope = Envelope(fixture.Bundle.Current, fixture.Bundle, 98);

            armed = true;
            var switchTask = Task.Run(async () =>
                await switching.SwitchCredentialEpochAsync(6, 250));
            Assert.True(switchEntered.Wait(TimeSpan.FromSeconds(10)));
            var createTask = Task.Run(async () =>
                await factory.CreateStoreAsync(fixture.Signer, oldEnvelope));
            releaseSwitch.Set();
            await switchTask;

            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await createTask);
            var firstNextLease = await leasing.LeaseCredentialAsync(
                MailboxCredentialGrantKind.PeerDeposit,
                250);
            Assert.Equal(6UL, firstNextLease.ActiveEpoch);
            Assert.Equal(1UL, firstNextLease.ReplayCounter);
        }
        finally
        {
            releaseSwitch.Set();
            DeleteDatabase(path);
        }
    }

    private sealed class Fixture
    {
        private readonly byte[] issuerSeed = Bytes(32, 1);
        private readonly byte[] holderSeed = Bytes(32, 33);
        public Fixture(bool revoke = false)
        {
            var crypto = new SodiumMailboxCapabilityCrypto();
            var issuer = crypto.GetPublicKey(issuerSeed); var holder = crypto.GetPublicKey(holderSeed);
            var current = new MailboxCredentialEpoch(5, 100, 300, Bytes(32, 5), Bytes(32, 6), Placement(Bytes(32, 6)));
            var next = new MailboxCredentialEpoch(6, 200, 400, Bytes(32, 7), Bytes(32, 8), Placement(Bytes(32, 8)));
            Bundle = new MailboxCredentialGeneration(Bytes(32, 9), Bytes(32, 10), Bytes(16, 11), issuer, holder,
                Bytes(32, 12), Bytes(32, 13), current, next,
                Set(MailboxCapabilityDomain.Retrieve, 20), Set(MailboxCapabilityDomain.Deposit, 40),
                Set(MailboxCapabilityDomain.Deposit, 60), new MailboxCredentialReplicaPair(Bytes(32, 70), Bytes(32, 71), Bytes(32, 72), Bytes(32, 73)));
            var revocations = new Revocations { Revoked = revoke };
            Policy = new MailboxCredentialImportPolicy(Bundle.Generation, Bundle.ManifestHash, Bundle.NetworkId, issuer, holder, Bundle.Replicas, revocations, 250);
            Signer = new Signer(holderSeed, holder);
        }
        public MailboxCredentialGeneration Bundle { get; }
        public MailboxCredentialImportPolicy Policy { get; }
        public Signer Signer { get; }
        private MailboxCredentialGrantSet Set(MailboxCapabilityDomain domain, byte serial) => new(
            Grant(domain, BundleEpoch.Current, serial), Grant(domain, BundleEpoch.Next, (byte)(serial + 1)));
        private byte[] Grant(MailboxCapabilityDomain domain, int epoch, byte serial)
        {
            var placement = epoch == 5 ? Bytes(32, 6) : Bytes(32, 8);
            var membership = epoch == 5 ? Bytes(32, 5) : Bytes(32, 7);
            var grant = new MailboxAuthenticatedGrant { Domain = domain, Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Bytes(16, 11), Epoch = (ulong)epoch, Generation = (ulong)epoch, Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = epoch == 5 ? 100UL : 200UL, ExpiresAtUnixSeconds = epoch == 5 ? 300UL : 400UL,
                OverlapUntilUnixSeconds = 0, PlacementCommitment = Placement(placement), MembershipCommitment = membership,
                IssuerPublicKey = new SodiumMailboxCapabilityCrypto().GetPublicKey(issuerSeed),
                HolderPublicKey = new SodiumMailboxCapabilityCrypto().GetPublicKey(holderSeed), IssuerSignature = new byte[64] };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(new SodiumMailboxCapabilityCrypto().SignGrant(grant, issuerSeed));
        }
        private static class BundleEpoch { public const int Current = 5; public const int Next = 6; }
    }

    private sealed class Revocations : IMailboxCapabilityRevocationSource
    { public bool Revoked { get; set; } public bool IsRevoked(MailboxCapabilityRevocationQuery query) => Revoked; }
    private sealed class Signer(byte[] seed, byte[] key) : IMailboxOperationSigner
    {
        public Deep.Client.Shared.Domain.SessionId SessionId => Deep.Client.Shared.Domain.SessionId.Parse("05" + new string('a', 64));
        public byte[] GetEd25519PublicKey() => key.ToArray();
        public byte[] SignMailboxPresentation(MailboxAuthenticatedOperation operation, ReadOnlySpan<byte> bytes) =>
            PublicKeyAuth.SignDetached(bytes.ToArray(), PublicKeyAuth.GenerateKeyPair(seed).PrivateKey);
    }
    private sealed class InvalidSignatureSigner(byte[] key) : IMailboxOperationSigner
    {
        public Deep.Client.Shared.Domain.SessionId SessionId =>
            Deep.Client.Shared.Domain.SessionId.Parse("05" + new string('b', 64));
        public byte[] GetEd25519PublicKey() => key.ToArray();
        public byte[] SignMailboxPresentation(
            MailboxAuthenticatedOperation operation,
            ReadOnlySpan<byte> bytes) => Bytes(64, 1);
    }
    private sealed class FixedTimeProvider(long seconds) : TimeProvider
    { public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(seconds); }
    private static byte[] Placement(byte[] id) => MailboxPlacementCommitment.Compute(new BlindedPlacementId(id));
    private static MailboxEncryptedEnvelope Envelope(
        MailboxCredentialEpoch epoch,
        MailboxCredentialGeneration generation,
        byte value) => new()
        {
            Epoch = epoch.Epoch,
            MailboxId = new BlindedMailboxId(generation.PeerMailboxId.Span),
            PlacementId = new BlindedPlacementId(epoch.PlacementId.Span),
            OperationId = Bytes(16, value),
            DeduplicationDigest = Bytes(32, (byte)(value + 1)),
            CreatedAtUnixSeconds = 200,
            ExpiresAtUnixSeconds = 300,
            Ciphertext = Bytes(MailboxClientLimits.MinimumCiphertextLength, value)
        };
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static string NewPath() => Path.Combine(Path.GetTempPath(), "deep-mailbox-" + Guid.NewGuid().ToString("N") + ".db");
    private static SqliteConnection Open(string path)
    {
        SQLitePCL.Batteries_V2.Init();
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Password = "test-key", Pooling = false }.ToString());
        connection.Open(); return connection;
    }
    private static async Task CreateCurrentDatabaseAsync(
        string path,
        Fixture fixture)
    {
        using var repository = new SqliteClientMailboxStateRepository(
            new SqliteSessionStoreOptions(path, "test-key"));
        await repository.ImportCredentialGenerationAsync(
            fixture.Bundle,
            fixture.Policy);
    }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static void DeleteDatabase(string path)
    { foreach (var candidate in new[] { path, path + "-wal", path + "-shm" }) if (File.Exists(candidate)) File.Delete(candidate); }
}
