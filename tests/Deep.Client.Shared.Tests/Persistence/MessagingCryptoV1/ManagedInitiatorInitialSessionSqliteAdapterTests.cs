using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Tests.Persistence.MessagingCryptoV1;

public sealed class ManagedInitiatorInitialSessionSqliteAdapterTests
{
    [Fact]
    public async Task AtomicCommitPersistsExactDispatchAndReplaysAfterRestart()
    {
        using var fixture = new Fixture();
        await using (var store = fixture.Open())
        {
            var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(store, fixture.VerifiedScope);
            var snapshot = fixture.Snapshot(store);
            var committed = await adapter.CommitForTestsAsync(snapshot);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized, committed.Disposition);
            snapshot.Dispose();
            Assert.True(snapshot.IsClearedForTesting);
            using var dispatch = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
                await adapter.ReadPendingDispatchAsync());
            Assert.Equal(fixture.ExactDph2, dispatch.ExactDph2.ToArray());
            Assert.Equal(fixture.SessionId, dispatch.SessionId.ToArray());
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var restartedAdapter = new ManagedInitiatorInitialSessionSqliteAdapter(
            restarted, fixture.VerifiedScope);
        using (var replay = fixture.Snapshot(restarted))
            Assert.Equal(MessagingCryptoV1CommitDisposition.ExactReplay,
                (await restartedAdapter.CommitForTestsAsync(replay)).Disposition);
        using var recovered = Assert.IsType<InitiatorInitialSessionDispatchEnvelope>(
            await restartedAdapter.ReadPendingDispatchAsync());
        Assert.Equal(fixture.ExactDph2, recovered.ExactDph2.ToArray());
    }

    [Theory]
    [InlineData(11, false)]
    [InlineData(12, false)]
    [InlineData(13, false)]
    [InlineData(14, false)]
    [InlineData(15, true)]
    public async Task EveryInitiatorFailpointRestartsAsPriorOrExactCommitted(
        int pointValue,
        bool committed)
    {
        var point = (MessagingCryptoV1StoreFailpoint)pointValue;
        using var fixture = new Fixture();
        await using (var store = fixture.Open())
        {
            var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(store, fixture.VerifiedScope);
            using var snapshot = fixture.Snapshot(store);
            using (MessagingCryptoV1StoreTestHooks.Push(hit =>
                       { if (hit == point) throw new MessagingCryptoV1InjectedCrashException(hit); }))
            {
                var failure = await Assert.ThrowsAsync<MessagingCryptoV1InjectedCrashException>(async () =>
                    await adapter.CommitForTestsAsync(snapshot));
                Assert.Equal(point, failure.Point);
            }
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var restartedAdapter = new ManagedInitiatorInitialSessionSqliteAdapter(
            restarted, fixture.VerifiedScope);
        Assert.Equal(committed, await restarted.ReadHeadAsync() is not null);
        Assert.Equal(committed, await restartedAdapter.ReadPendingDispatchAsync() is not null);
        using var retry = fixture.Snapshot(restarted);
        Assert.Equal(
            committed
                ? MessagingCryptoV1CommitDisposition.ExactReplay
                : MessagingCryptoV1CommitDisposition.Initialized,
            (await restartedAdapter.CommitForTestsAsync(retry)).Disposition);
    }

    [Fact]
    public async Task SameSessionWithDifferentExactDph2LatchesForkDurably()
    {
        using var fixture = new Fixture();
        await using (var store = fixture.Open())
        {
            var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(store, fixture.VerifiedScope);
            using (var accepted = fixture.Snapshot(store))
                Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
                    (await adapter.CommitForTestsAsync(accepted)).Disposition);
            var conflictingDph2 = fixture.CreateDph2(initialCiphertextSeed: 0x72);
            using var conflicting = InitiatorInitialSessionProtocolSnapshot.CreateForTests(
                conflictingDph2, fixture.ExactTrs1, fixture.VerifiedScope, store);
            var result = await adapter.CommitForTestsAsync(conflicting);
            Assert.Equal(MessagingCryptoV1CommitDisposition.ForkLatched, result.Disposition);
            Assert.True(result.ForkLatched);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await adapter.ReadPendingDispatchAsync());
        }

        await using var restarted = fixture.Open(allowCreate: false);
        Assert.True((await restarted.ReadHeadAsync())!.ForkLatched);
        var restartedAdapter = new ManagedInitiatorInitialSessionSqliteAdapter(
            restarted, fixture.VerifiedScope);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restartedAdapter.ReadPendingDispatchAsync());
    }

    [Fact]
    public async Task WrongContactRemoteOrLocalGenerationRejectsBeforeMutation()
    {
        using var fixture = new Fixture();
        await using var store = fixture.Open();

        var wrongContact = fixture.ScopeWith(conversationSeed: 0xC9);
        Assert.Throws<CryptographicException>(() =>
            new ManagedInitiatorInitialSessionSqliteAdapter(store, wrongContact));

        var wrongRemote = fixture.ScopeWith(remoteDeviceSeed: 0xE9);
        Assert.Throws<CryptographicException>(() =>
            InitiatorInitialSessionProtocolSnapshot.CreateForTests(
                fixture.ExactDph2, fixture.ExactTrs1, wrongRemote, store));

        var wrongLocalDph2 = fixture.CreateDph2(
            initialCiphertextSeed: 0x71,
            localDeviceGeneration: fixture.LocalDeviceGeneration + 1);
        Assert.Throws<CryptographicException>(() =>
            InitiatorInitialSessionProtocolSnapshot.CreateForTests(
                wrongLocalDph2, fixture.ExactTrs1, fixture.VerifiedScope, store));
        Assert.Null(await store.ReadHeadAsync());
    }

    [Fact]
    public async Task ReverifiedPeerGenerationDriftBlocksPersistedDispatch()
    {
        using var fixture = new Fixture();
        await using var store = fixture.Open();
        var adapter = new ManagedInitiatorInitialSessionSqliteAdapter(store, fixture.VerifiedScope);
        using (var snapshot = fixture.Snapshot(store))
            Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
                (await adapter.CommitForTestsAsync(snapshot)).Disposition);

        var successorScope = fixture.ScopeWith(
            remoteAccountGeneration: fixture.RemoteAccountGeneration + 1,
            remoteDirectoryGeneration: 20);
        var successorAdapter = new ManagedInitiatorInitialSessionSqliteAdapter(store, successorScope);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await successorAdapter.ReadPendingDispatchAsync());
    }

    [Fact]
    public void ProductionSurfaceConsumesOnlyProtocolCapabilityAndVerifiedScope()
    {
        var commit = Assert.Single(
            typeof(ManagedInitiatorInitialSessionSqliteAdapter)
                .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic),
            method => method.Name == "CommitAsync");
        Assert.Equal(typeof(InitiatorInitialSessionCommitCapability),
            commit.GetParameters()[0].ParameterType);
        var constructors = typeof(ManagedInitiatorInitialSessionSqliteAdapter)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic);
        var constructor = Assert.Single(constructors);
        Assert.Equal(
            [typeof(SqliteMessagingCryptoV1Store), typeof(InitiatorInitialSessionVerifiedScope)],
            constructor.GetParameters().Select(parameter => parameter.ParameterType));
        var forbidden = string.Join('|', typeof(ManagedInitiatorInitialSessionSqliteAdapter)
            .GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
            .SelectMany(method => method.GetParameters())
            .Select(parameter => parameter.ParameterType.FullName));
        Assert.DoesNotContain("PrivateKey", forbidden, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Provider", forbidden, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Boolean", forbidden, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(
            Path.GetTempPath(), "deep-initiator-session", Guid.NewGuid().ToString("N"));

        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            StatePath = Path.Combine(directory, "initiator.db");
            Key = Bytes(0x91);
            ExactDph2 = CreateDph2(0x71);
            SessionId = Dph2Codec.Decode(ExactDph2).SessionId.ToArray();
            Scope = new MessagingCryptoV1StoreScope(
                LocalAccountId, LocalAccountGeneration, LocalDeviceId,
                LocalDeviceGeneration, ConversationId, SessionId, 1);
            VerifiedScope = ScopeWith();
            ExactTrs1 = Trs1(Scope, RemoteDeviceId, RemoteDeviceGeneration);
        }

        internal string StatePath { get; }
        internal byte[] Key { get; }
        internal byte[] ExactDph2 { get; }
        internal byte[] ExactTrs1 { get; }
        internal byte[] SessionId { get; }
        internal MessagingCryptoV1StoreScope Scope { get; }
        internal InitiatorInitialSessionVerifiedScope VerifiedScope { get; }
        internal byte[] LocalAccountId { get; } = Bytes(0xA1);
        internal ulong LocalAccountGeneration => 7;
        internal byte[] LocalDeviceId { get; } = Bytes(0xB1);
        internal ulong LocalDeviceGeneration => 11;
        internal byte[] ConversationId { get; } = Bytes(0xC1);
        internal byte[] RemoteAccountId { get; } = Bytes(0xD1);
        internal ulong RemoteAccountGeneration => 13;
        internal byte[] RemoteDeviceId { get; } = Bytes(0xE1);
        internal ulong RemoteDeviceGeneration => 17;

        internal SqliteMessagingCryptoV1Store Open(bool allowCreate = true)
        {
            using var options = new MessagingCryptoV1StoreOptions(
                StatePath, Key, Scope, allowCreate);
            return new SqliteMessagingCryptoV1Store(options);
        }

        internal InitiatorInitialSessionProtocolSnapshot Snapshot(
            SqliteMessagingCryptoV1Store store) =>
            InitiatorInitialSessionProtocolSnapshot.CreateForTests(
                ExactDph2, ExactTrs1, VerifiedScope, store);

        internal InitiatorInitialSessionVerifiedScope ScopeWith(
            byte conversationSeed = 0xC1,
            byte remoteDeviceSeed = 0xE1,
            ulong? remoteAccountGeneration = null,
            ulong remoteDirectoryGeneration = 19) =>
            InitiatorInitialSessionVerifiedScope.CreateForTests(
                Bytes16(0x31), LocalAccountId, 2, Bytes(0x41),
                Bytes(conversationSeed), Bytes(0x42), Bytes(0x43),
                RemoteAccountId, remoteAccountGeneration ?? RemoteAccountGeneration,
                remoteDirectoryGeneration,
                Bytes(remoteDeviceSeed), RemoteDeviceGeneration);

        internal byte[] CreateDph2(
            byte initialCiphertextSeed,
            ulong? localDeviceGeneration = null)
        {
            var dpd1Reference = new byte[38];
            "DPD1"u8.CopyTo(dpd1Reference);
            BinaryPrimitives.WriteUInt16BigEndian(dpd1Reference.AsSpan(4), 1);
            Bytes(0x51).CopyTo(dpd1Reference, 6);
            var record = new Dph2Record(
                Bytes16(0x31),
                LocalAccountId,
                LocalDeviceId,
                localDeviceGeneration ?? LocalDeviceGeneration,
                dpd1Reference,
                RemoteAccountId,
                RemoteDeviceId,
                RemoteDeviceGeneration,
                Bytes(0x52),
                Bytes(0x53),
                Bytes(0x54),
                0,
                Bytes(0x55),
                Bytes(0x56),
                Dph2SelectedPrekey.OneTime(Bytes(0x57), Bytes(0x58), Bytes(0x59)),
                Enumerable.Repeat((byte)0x61, 1088).ToArray(),
                Bytes(0x62),
                Enumerable.Repeat((byte)0x63, 24).ToArray(),
                Dph2InitialCiphertext.Import(
                    Enumerable.Repeat(initialCiphertextSeed, 4112).ToArray()));
            return Dph2Codec.Encode(record);
        }

        public void Dispose()
        {
            Zero(Key, ExactDph2, ExactTrs1, SessionId, LocalAccountId,
                LocalDeviceId, ConversationId, RemoteAccountId, RemoteDeviceId);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static byte[] Trs1(
        MessagingCryptoV1StoreScope scope,
        ReadOnlySpan<byte> remoteDeviceId,
        ulong remoteDeviceGeneration)
    {
        var result = new byte[601];
        "TRS1"u8.CopyTo(result);
        result[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)result.Length));
        scope.SessionId.CopyTo(result.AsSpan(12, 32));
        Fill(result.AsSpan(44, 64), 0x65);
        scope.LocalDeviceId.CopyTo(result.AsSpan(108, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(140), scope.DeviceGeneration);
        Fill(result.AsSpan(148, 32), 0x66);
        remoteDeviceId.CopyTo(result.AsSpan(180, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), remoteDeviceGeneration);
        Fill(result.AsSpan(220, 32), 0x67);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), 1);
        Fill(result.AsSpan(260, 32), 0x68);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1);
        Fill(result.AsSpan(300, 32), 0x69);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1);
        Fill(result.AsSpan(348, 32), 0x6A);
        Fill(result.AsSpan(404, 32), 0x6B);
        Fill(result.AsSpan(460, 32), 0x6C);
        Fill(result.AsSpan(492, 32), 0x6D);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), 1);
        result[536] = 0x6E;
        Fill(result.AsSpan(537, 32), 0x6F);
        var checksum = MessagingCryptoV1Trs1.Sha256Domain(
            "Deep/LocalState/V1/triple-ratchet-state-checksum",
            result.AsSpan(0, result.Length - 32));
        checksum.CopyTo(result, result.Length - 32);
        CryptographicOperations.ZeroMemory(checksum);
        return result;
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] Bytes16(byte value) => Enumerable.Repeat(value, 16).ToArray();
    private static void Fill(Span<byte> destination, byte value) => destination.Fill(value);
    private static void Zero(params byte[][] values)
    {
        foreach (var value in values) CryptographicOperations.ZeroMemory(value);
    }
}
