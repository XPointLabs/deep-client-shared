using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence;

public sealed class MailboxRuntimeCheckpointConcurrencyTests
{
    private const string BundleKey = "test.mailbox.runtime.bundle";
    private const string RevocationKey = "test.mailbox.runtime.revocation";

    [Fact]
    public async Task IndependentStores_ConcurrentNewerAndStaleRevocation_PublishOnlyNewerAtomically()
    {
        using var fixture = new Fixture();
        using var newerEnteredBeforeCommit = new ManualResetEventSlim();
        using var releaseNewerCommit = new ManualResetEventSlim();
        using var staleInvocationStarted = new ManualResetEventSlim();
        var blockNewerCommit = 0;
        using var first = new SqliteSessionStore(
            new SqliteSessionStoreOptions(fixture.Path),
            point =>
            {
                if (point != ClientMailboxCommitFaultPoint.BeforeCommit ||
                    Volatile.Read(ref blockNewerCommit) == 0)
                    return;
                newerEnteredBeforeCommit.Set();
                if (!releaseNewerCommit.Wait(TimeSpan.FromSeconds(5)))
                    throw new TimeoutException(
                        "Newer checkpoint commit was not released by the race test.");
            });
        using var second = new SqliteSessionStore(fixture.Path);
        var initial = fixture.Initial;
        var newer = fixture.Rotate(initial, 0x61);
        var rejectedCandidate = fixture.Rotate(initial, 0x71);
        var initialCheckpoint = Checkpoint(
            epoch: 7, pair: '1', generatedAt: 100, expiresAt: 1_000,
            snapshot: 'a');
        var newerCheckpoint = Checkpoint(
            epoch: 8, pair: '2', generatedAt: 200, expiresAt: 1_200,
            snapshot: 'b');
        var staleRevocation = newerCheckpoint with
        {
            Revocation = Revocation(150, 1_300, 'c')
        };
        await first.ApplyScopedMailboxRuntimeSnapshotAsync(
            [initial], fixture.Authority, initialCheckpoint);

        Volatile.Write(ref blockNewerCommit, 1);
        var publishNewer = Task.Run(() =>
            first.ApplyScopedMailboxRuntimeSnapshotAsync(
                [newer], fixture.Authority, newerCheckpoint));
        Assert.True(newerEnteredBeforeCommit.Wait(TimeSpan.FromSeconds(5)));
        var publishStale = Task.Factory.StartNew(
            () =>
            {
                staleInvocationStarted.Set();
                return AttemptAsync(
                    second, [rejectedCandidate], staleRevocation)
                    .GetAwaiter().GetResult();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        Assert.True(staleInvocationStarted.Wait(TimeSpan.FromSeconds(5)));
        await Task.Delay(50);
        releaseNewerCommit.Set();
        await publishNewer;
        var concurrentStale = await publishStale;
        Assert.True(
            concurrentStale is InvalidDataException or
                SqliteException { SqliteErrorCode: 5 },
            concurrentStale?.ToString());
        Assert.IsType<InvalidDataException>(await AttemptAsync(
            second, [rejectedCandidate], staleRevocation));
        Assert.Equal(newerCheckpoint.Bundle,
            await first.GetAsync<MailboxBundleRuntimeCheckpoint>(BundleKey));
        AssertRevocationEqual(newerCheckpoint.Revocation,
            first.ReadMailboxRevocationCheckpoint(RevocationKey));
        Assert.Equal(8UL,
            (await first.ReadScopedMailboxRouteAsync(
                fixture.Selector, fixture.Authority)).Epoch);
        Assert.Equal(newer.Next.PlacementId.ToArray(),
            ReadEpochPlacement(fixture.Path, epoch: 9));
        Assert.Equal(1, Count(fixture.Path, "mailbox_credential_scopes"));
        Assert.Equal(2, Count(fixture.Path, "mailbox_credential_epochs"));

        async Task<Exception?> AttemptAsync(
            SqliteSessionStore store,
            IReadOnlyList<ScopedMailboxCredentialGeneration> generations,
            MailboxRuntimeSnapshotCheckpoint checkpoint)
        {
            try
            {
                await store.ApplyScopedMailboxRuntimeSnapshotAsync(
                    generations, fixture.Authority, checkpoint);
                return null;
            }
            catch (Exception exception)
            {
                return exception;
            }
        }
    }

    [Fact]
    public async Task SameEpochOwnershipOrPairGenerationSubstitution_IsRejected()
    {
        using var fixture = new Fixture();
        using var store = new SqliteSessionStore(fixture.Path);
        var committed = Checkpoint(
            epoch: 7, pair: '3', generatedAt: 100, expiresAt: 1_000,
            snapshot: 'd');
        await store.ApplyScopedMailboxRuntimeSnapshotAsync(
            [fixture.Initial], fixture.Authority, committed);

        var ownershipSubstitution = committed with
        {
            Bundle = committed.Bundle with { Ownership = "OfficialManaged" },
            Revocation = Revocation(200, 1_200, 'e')
        };
        var pairSubstitution = committed with
        {
            Bundle = committed.Bundle with { PairGeneration = Hex('4') },
            Revocation = Revocation(200, 1_200, 'f')
        };

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.ApplyScopedMailboxRuntimeSnapshotAsync(
                [fixture.Initial], fixture.Authority, ownershipSubstitution));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.ApplyScopedMailboxRuntimeSnapshotAsync(
                [fixture.Initial], fixture.Authority, pairSubstitution));

        Assert.Equal(committed.Bundle,
            await store.GetAsync<MailboxBundleRuntimeCheckpoint>(BundleKey));
        AssertRevocationEqual(committed.Revocation,
            store.ReadMailboxRevocationCheckpoint(RevocationKey));
        Assert.Equal(7UL,
            (await store.ReadScopedMailboxRouteAsync(
                fixture.Selector, fixture.Authority)).Epoch);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("{\"schemaVersion\":1,\"generatedAtUnixSeconds\":200," +
        "\"expiresAtUnixSeconds\":100,\"snapshotSha256\":\"aaaaaaaaaaaaaaaa" +
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"revokedKeys\":[]}")]
    public async Task CorruptPersistedRevocationJsonOrShape_ReadsFailClosed(
        string corruptPayload)
    {
        using var fixture = new Fixture();
        using var store = new SqliteSessionStore(fixture.Path);
        await store.ApplyScopedMailboxRuntimeSnapshotAsync(
            [fixture.Initial], fixture.Authority,
            Checkpoint(7, '5', 100, 1_000, 'a'));
        WriteSetting(fixture.Path, RevocationKey, corruptPayload);

        Assert.Throws<InvalidDataException>(() =>
            store.ReadMailboxRevocationCheckpoint(RevocationKey));
    }

    [Fact]
    public async Task Coordinator_CancellationDoesNotLeakPermit_AndWaitingWriterPreventsBarging()
    {
        var coordinator = MailboxRuntimePolicyCoordinator.Detached();
        var firstReader = await coordinator.AcquireDispatchAsync();
        var secondReader = await coordinator.AcquireDispatchAsync();
        var writerTask = coordinator.AcquirePublicationAsync().AsTask();
        await Task.Yield();
        Assert.False(writerTask.IsCompleted);

        using var cancellation = new CancellationTokenSource();
        var canceledReader = coordinator.AcquireDispatchAsync(
            cancellation.Token).AsTask();
        var bargingReader = coordinator.AcquireDispatchAsync().AsTask();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => canceledReader);
        Assert.False(bargingReader.IsCompleted);

        await firstReader.DisposeAsync();
        Assert.False(writerTask.IsCompleted);
        await secondReader.DisposeAsync();
        var writer = await writerTask.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(bargingReader.IsCompleted);

        await writer.DisposeAsync();
        var admittedReader = await bargingReader.WaitAsync(TimeSpan.FromSeconds(5));
        await admittedReader.DisposeAsync();

        var finalWriter = await coordinator.AcquirePublicationAsync()
            .AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await finalWriter.DisposeAsync();
    }

    [Fact]
    public void SqliteFileIdentity_CollapsesHardLinkAliasesToOneCoordinator()
    {
        using var fixture = new Fixture();
        string firstIdentity;
        using (var first = new SqliteSessionStore(fixture.Path))
            firstIdentity = first.CanonicalStateIdentity;
        SqliteConnection.ClearAllPools();
        var alias = fixture.Path + ".hardlink";
        CreateHardLink(alias, fixture.Path);
        try
        {
            using var second = new SqliteSessionStore(alias);
            Assert.Equal(firstIdentity, second.CanonicalStateIdentity);
            var issuer = Bytes(32, 0xa5);
            Assert.Same(
                MailboxRuntimePolicyCoordinator.For(firstIdentity, issuer),
                MailboxRuntimePolicyCoordinator.For(
                    second.CanonicalStateIdentity, issuer));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { alias, alias + "-wal", alias + "-shm" })
                if (File.Exists(candidate)) File.Delete(candidate);
        }
    }

    private static MailboxRuntimeSnapshotCheckpoint Checkpoint(
        ulong epoch,
        char pair,
        ulong generatedAt,
        ulong expiresAt,
        char snapshot) => new(
        BundleKey,
        new MailboxBundleRuntimeCheckpoint(
            1,
            "android-windows-pair",
            "android",
            "UserManaged",
            epoch,
            Hex(pair)),
        RevocationKey,
        Revocation(generatedAt, expiresAt, snapshot));

    private static MailboxRevocationRuntimeCheckpoint Revocation(
        ulong generatedAt,
        ulong expiresAt,
        char snapshot) => new(
        1,
        generatedAt,
        expiresAt,
        Hex(snapshot),
        []);

    private static string Hex(char value) => new(value, 64);

    private static void CreateHardLink(string alias, string existing)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!CreateHardLinkWindows(alias, existing, IntPtr.Zero))
                throw new IOException(
                    "Unable to create hard-link alias for the identity test.");
            return;
        }
        if ((OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()) &&
            LinkUnix(existing, alias) == 0)
            return;
        throw new PlatformNotSupportedException(
            "Hard-link identity test requires Windows, Linux, or Android.");
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int LinkUnix(string existing, string alias);

    private static void AssertRevocationEqual(
        MailboxRevocationRuntimeCheckpoint expected,
        MailboxRevocationRuntimeCheckpoint actual)
    {
        Assert.Equal(expected.SchemaVersion, actual.SchemaVersion);
        Assert.Equal(expected.GeneratedAtUnixSeconds,
            actual.GeneratedAtUnixSeconds);
        Assert.Equal(expected.ExpiresAtUnixSeconds,
            actual.ExpiresAtUnixSeconds);
        Assert.Equal(expected.SnapshotSha256, actual.SnapshotSha256);
        Assert.Equal(expected.RevokedKeys, actual.RevokedKeys,
            StringComparer.Ordinal);
    }

    private static int Count(string path, string table)
    {
        using var connection = Open(path);
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT count(*) FROM {table};";
        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static byte[] ReadEpochPlacement(string path, ulong epoch)
    {
        using var connection = Open(path);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT placement_id FROM mailbox_credential_epochs
            WHERE epoch=$epoch;
            """;
        command.Parameters.Add("$epoch", SqliteType.Blob).Value = U64(epoch);
        return Assert.IsType<byte[]>(command.ExecuteScalar());
    }

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static void WriteSetting(string path, string key, string payload)
    {
        using var connection = Open(path);
        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE settings SET payload_json=$payload WHERE key=$key;
            """;
        command.Parameters.AddWithValue("$key", key);
        command.Parameters.AddWithValue("$payload", payload);
        Assert.Equal(1, command.ExecuteNonQuery());
    }

    private static SqliteConnection Open(string path)
    {
        var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        return connection;
    }

    private sealed class Fixture : IDisposable
    {
        private readonly byte[] issuerSeed = Bytes(32, 0x01);
        private readonly byte[] holderSeed = Bytes(32, 0x21);
        private readonly SodiumMailboxCapabilityCrypto crypto = new();

        public Fixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"deep-runtime-checkpoint-{Guid.NewGuid():N}.db");
            var account = OutboxAccountScope.FromBytes(Bytes(32, 0x11));
            Selector = new MailboxCredentialSelector(
                account,
                MailboxCredentialScopeKind.Self,
                Bytes(32, 0x13),
                Bytes(32, 0x12));
            IssuerPublicKey = crypto.GetPublicKey(issuerSeed);
            Authority = new VerifiedOfficialMailboxAuthority(
                Bytes(16, 0x15),
                1,
                [
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Deposit),
                    Issuer(IssuerPublicKey, MailboxCapabilityDomain.Retrieve)
                ],
                true,
                static () => true,
                new NoRevocations(),
                new FrozenTimeProvider());
            Initial = Generation(Selector, 0x31);
        }

        public string Path { get; }
        public MailboxCredentialSelector Selector { get; }
        public VerifiedOfficialMailboxAuthority Authority { get; }
        public byte[] IssuerPublicKey { get; }
        public ScopedMailboxCredentialGeneration Initial { get; }

        public ScopedMailboxCredentialGeneration Rotate(
            ScopedMailboxCredentialGeneration prior,
            byte marker)
        {
            var nextPlacement = new BlindedPlacementId(Bytes(32, marker));
            var next = new MailboxCredentialEpoch(
                prior.Next.Epoch + 1,
                1_250,
                1_600,
                Bytes(32, checked((byte)(marker + 1))),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            return new ScopedMailboxCredentialGeneration(
                prior.Selector,
                SHA256.HashData([marker, (byte)9]),
                prior.HolderPublicKey,
                prior.MailboxId,
                prior.Next,
                next,
                new MailboxCredentialGrantSet(
                    prior.Retrieve!.NextGrant.Span,
                    Grant(MailboxCapabilityDomain.Retrieve,
                        checked((byte)(marker + 2)), next)),
                new MailboxCredentialGrantSet(
                    prior.Deposit!.NextGrant.Span,
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(marker + 3)), next)),
                prior.Replicas);
        }

        private ScopedMailboxCredentialGeneration Generation(
            MailboxCredentialSelector selector,
            byte marker)
        {
            var currentPlacement = new BlindedPlacementId(Bytes(32, marker));
            var nextPlacement = new BlindedPlacementId(
                Bytes(32, checked((byte)(marker + 1))));
            var current = new MailboxCredentialEpoch(
                7,
                900,
                1_300,
                Bytes(32, checked((byte)(marker + 2))),
                currentPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(currentPlacement));
            var next = new MailboxCredentialEpoch(
                8,
                1_100,
                1_450,
                Bytes(32, checked((byte)(marker + 3))),
                nextPlacement.Bytes.Span,
                MailboxPlacementCommitment.Compute(nextPlacement));
            var serial = checked((byte)(marker + 0x40));
            return new ScopedMailboxCredentialGeneration(
                selector,
                SHA256.HashData([marker, (byte)1]),
                crypto.GetPublicKey(holderSeed),
                SHA256.HashData([marker, (byte)2]),
                current,
                next,
                new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Retrieve, serial, current),
                    Grant(MailboxCapabilityDomain.Retrieve,
                        checked((byte)(serial + 1)), next)),
                new MailboxCredentialGrantSet(
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(serial + 2)), current),
                    Grant(MailboxCapabilityDomain.Deposit,
                        checked((byte)(serial + 3)), next)),
                new MailboxCredentialReplicaPair(
                    Bytes(32, 0xd1),
                    Bytes(32, 0xd2),
                    Bytes(32, 0xd3),
                    Bytes(32, 0xd4)));
        }

        private byte[] Grant(
            MailboxCapabilityDomain domain,
            byte serial,
            MailboxCredentialEpoch epoch)
        {
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Authority.NetworkId,
                Epoch = epoch.Epoch,
                Generation = epoch.Epoch,
                Serial = Bytes(16, serial),
                NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
                ExpiresAtUnixSeconds = epoch.ExpiresAtUnixSeconds,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = epoch.PlacementCommitment,
                MembershipCommitment = epoch.MembershipCommitment,
                IssuerPublicKey = IssuerPublicKey,
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = new byte[64]
            };
            return MailboxAuthenticatedCapabilityCodec.EncodeGrant(
                crypto.SignGrant(unsigned, issuerSeed));
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            foreach (var candidate in new[] { Path, Path + "-wal", Path + "-shm" })
            {
                for (var attempt = 0; File.Exists(candidate); attempt++)
                {
                    try
                    {
                        File.Delete(candidate);
                    }
                    catch (IOException) when (attempt < 20)
                    {
                        SqliteConnection.ClearAllPools();
                        Thread.Sleep(25);
                    }
                }
            }
        }

        private static MailboxCapabilityIssuerAuthority Issuer(
            ReadOnlyMemory<byte> publicKey,
            MailboxCapabilityDomain domain) => new()
        {
            PublicKey = publicKey.ToArray(),
            Domain = domain,
            AllowedLifecycle = MailboxCapabilityLifecycle.Active,
            MinimumGeneration = 1,
            MaximumGeneration = ulong.MaxValue,
            ValidFromUnixSeconds = 1,
            ValidUntilUnixSeconds = ulong.MaxValue
        };
    }

    private sealed class NoRevocations : IFreshMailboxCapabilityRevocationSource
    {
        public void ValidateFreshness() { }
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class FrozenTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(1_200);
    }

    private static byte[] Bytes(int count, byte start)
    {
        var value = new byte[count];
        for (var index = 0; index < count; index++)
            value[index] = unchecked((byte)(start + index));
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0) value[0] = 1;
        return value;
    }
}
