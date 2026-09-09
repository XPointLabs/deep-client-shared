using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Tests.Persistence.MessagingCryptoV1;

public sealed class MessagingCryptoV1PreparationLeaseTests
{
    private static readonly PlanConstructor CreatePlan = BuildPlanConstructor();

    [Fact]
    public async Task AtomicPreparationContextIsExactStableAcrossRestartAndStoreOwned()
    {
        using var fixture = new Fixture();
        var initial = Trs1(fixture.Scope, 7, 0x31);
        byte[] journalHead;
        byte[] stateCommitment;
        using (var facts = FactsLease(initial, fixture.Scope))
            stateCommitment = facts.StateCommitment.ToArray();

        MessagingCryptoV1PreparationSnapshot beforeRestart;
        await using (var store = fixture.Open())
        {
            journalHead = await Initialize(store, initial);
            using var lease = await store.AcquireSendPreparationLeaseAsync();
            beforeRestart = lease.CaptureForTesting();
            AssertContext(beforeRestart, initial, stateCommitment, journalHead, 7, 0,
                ExactDpe2ReceiveReplayDisposition.Fresh);
            Assert.Equal(
                RetentionCommitment(fixture.Scope, journalHead, journalGeneration: 0, exactDpe2Count: 0),
                beforeRestart.RetentionCommitment);
        }

        await using (var reopened = fixture.Open(allowCreate: false))
        using (var lease = await reopened.AcquireSendPreparationLeaseAsync())
        using (var afterRestart = lease.CaptureForTesting())
        {
            AssertContext(afterRestart, initial, stateCommitment, journalHead, 7, 0,
                ExactDpe2ReceiveReplayDisposition.Fresh);
            Assert.Equal(beforeRestart.ExactTrs1Hash, afterRestart.ExactTrs1Hash);
            Assert.Equal(beforeRestart.ExpectedStateCommitment, afterRestart.ExpectedStateCommitment);
            Assert.Equal(beforeRestart.LatestProtectedCommitment, afterRestart.LatestProtectedCommitment);
            Assert.Equal(beforeRestart.JournalPredecessor, afterRestart.JournalPredecessor);
            Assert.Equal(beforeRestart.RetentionCommitment, afterRestart.RetentionCommitment);
        }

        beforeRestart.Dispose();
        Assert.All(beforeRestart.RetentionCommitment, static value => Assert.Equal(0, value));
        CryptographicOperations.ZeroMemory(stateCommitment);
    }

    [Fact]
    public async Task ConcurrentCommitCannotProduceMixedStateAndJournalContext()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x41);
        var next = Trs1(fixture.Scope, 2, 0x42);
        var exactDpe2 = Dpe2(fixture.Scope, operationSeed: 0x21, ciphertextSeed: 0x51);
        await using var writer = fixture.Open();
        var genesis = await Initialize(writer, prior);
        await using var reader = fixture.Open(allowCreate: false);
        using var plan = ReceivePlan(fixture.Scope, prior, next, genesis, exactDpe2);
        var authority = new ExactDpe2SqliteDurableTransactionAuthority(writer);
        var entered = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();

        var commitTask = Task.Run(async () =>
        {
            using var hook = MessagingCryptoV1StoreTestHooks.Push(point =>
            {
                if (point != MessagingCryptoV1StoreFailpoint.AfterStateUpdate) return;
                entered.Set();
                if (!release.Wait(TimeSpan.FromSeconds(10)))
                    throw new TimeoutException("The preparation concurrency test did not release the writer.");
            });
            return await authority.CommitAsync(plan, Completion(plan));
        });

        Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
        var acquireTask = reader.AcquireSendPreparationLeaseAsync().AsTask();
        release.Set();
        var receipt = await commitTask;
        Assert.Equal(ExactDpe2DurableCommitDisposition.Committed, receipt.Disposition);
        using var concurrentLease = await acquireTask;
        using var concurrent = concurrentLease.CaptureForTesting();

        using var priorFacts = FactsLease(prior, fixture.Scope);
        using var nextFacts = FactsLease(next, fixture.Scope);
        var isPrior = concurrent.ExpectedStateGeneration == priorFacts.Generation &&
            concurrent.ExpectedJournalGeneration == 0 &&
            concurrent.ExpectedStateCommitment.SequenceEqual(priorFacts.StateCommitment) &&
            concurrent.LatestProtectedCommitment.SequenceEqual(priorFacts.StateCommitment) &&
            concurrent.JournalPredecessor.SequenceEqual(genesis) &&
            concurrent.ExactTrs1Hash.SequenceEqual(priorFacts.ExactHash);
        var isNext = concurrent.ExpectedStateGeneration == nextFacts.Generation &&
            concurrent.ExpectedJournalGeneration == 1 &&
            concurrent.ExpectedStateCommitment.SequenceEqual(nextFacts.StateCommitment) &&
            concurrent.LatestProtectedCommitment.SequenceEqual(nextFacts.StateCommitment) &&
            concurrent.ExactTrs1Hash.SequenceEqual(nextFacts.ExactHash) &&
            !concurrent.JournalPredecessor.SequenceEqual(genesis);
        Assert.True(isPrior || isNext, "Preparation exposed a mixed durable snapshot.");
    }

    [Fact]
    public async Task ReceiveReplayDispositionIsDerivedFromExactRetainedEnvelopeAcrossRestart()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x51);
        var next = Trs1(fixture.Scope, 2, 0x52);
        var exactDpe2 = Dpe2(fixture.Scope, operationSeed: 0x22, ciphertextSeed: 0x61);
        byte[] committedHead;

        await using (var store = fixture.Open())
        {
            var genesis = await Initialize(store, prior);
            using (var freshLease = await store.AcquireReceivePreparationLeaseAsync(exactDpe2))
            using (var fresh = freshLease.CaptureForTesting())
            {
                Assert.Equal(ExactDpe2ReceiveReplayDisposition.Fresh, fresh.ReceiveReplayDisposition);
                Assert.Equal(SHA256.HashData(exactDpe2), fresh.ExactReceiveEnvelopeHash);
            }

            using var plan = ReceivePlan(fixture.Scope, prior, next, genesis, exactDpe2);
            var receipt = await new ExactDpe2SqliteDurableTransactionAuthority(store)
                .CommitAsync(plan, Completion(plan));
            Assert.Equal(ExactDpe2DurableCommitDisposition.Committed, receipt.Disposition);
            committedHead = (await store.ReadHeadAsync())!.JournalHead.ToArray();
        }

        await using var reopened = fixture.Open(allowCreate: false);
        using (var replayLease = await reopened.AcquireReceivePreparationLeaseAsync(exactDpe2))
        using (var replay = replayLease.CaptureForTesting())
        {
            Assert.Equal(ExactDpe2ReceiveReplayDisposition.ExactReplay, replay.ReceiveReplayDisposition);
            Assert.Equal(2UL, replay.ExpectedStateGeneration);
            Assert.Equal(1UL, replay.ExpectedJournalGeneration);
            Assert.Equal(committedHead, replay.JournalPredecessor);
            Assert.Equal(SHA256.HashData(exactDpe2), replay.ExactReceiveEnvelopeHash);
            Assert.Equal(
                RetentionCommitment(fixture.Scope, committedHead, journalGeneration: 1, exactDpe2Count: 1),
                replay.RetentionCommitment);
        }

        var changed = Dpe2(fixture.Scope, operationSeed: 0x22, ciphertextSeed: 0x62);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reopened.AcquireReceivePreparationLeaseAsync(changed));
    }

    [Fact]
    public async Task ReceivePreparationLeaseOwnsExactEnvelopeAgainstCallerMutation()
    {
        using var fixture = new Fixture();
        var initial = Trs1(fixture.Scope, 1, 0x63);
        var exactDpe2 = Dpe2(fixture.Scope, operationSeed: 0x23, ciphertextSeed: 0x64);
        var expectedHash = SHA256.HashData(exactDpe2);
        await using var store = fixture.Open();
        await Initialize(store, initial);

        using var lease = await store.AcquireReceivePreparationLeaseAsync(exactDpe2);
        CryptographicOperations.ZeroMemory(exactDpe2);
        using var snapshot = lease.CaptureForTesting();

        Assert.Equal(expectedHash, snapshot.ExactReceiveEnvelopeHash);
        Assert.Equal(ExactDpe2ReceiveReplayDisposition.Fresh, snapshot.ReceiveReplayDisposition);
        CryptographicOperations.ZeroMemory(expectedHash);
    }

    [Fact]
    public async Task LeaseAndSnapshotsAreBoundedSingleOwnerAndZeroizedOnDispose()
    {
        using var fixture = new Fixture();
        var initial = Trs1(fixture.Scope, 1, 0x71);
        await using var store = fixture.Open();
        await Initialize(store, initial);

        var lease = await store.AcquireSendPreparationLeaseAsync();
        var snapshot = lease.CaptureForTesting();
        Assert.Contains(snapshot.RetentionCommitment, static value => value != 0);
        snapshot.Dispose();
        Assert.All(snapshot.ExactTrs1Hash, static value => Assert.Equal(0, value));
        Assert.All(snapshot.ExpectedStateCommitment, static value => Assert.Equal(0, value));
        Assert.All(snapshot.LatestProtectedCommitment, static value => Assert.Equal(0, value));
        Assert.All(snapshot.JournalPredecessor, static value => Assert.Equal(0, value));
        Assert.All(snapshot.RetentionCommitment, static value => Assert.Equal(0, value));

        lease.Dispose();
        Assert.True(lease.IsClearedForTesting);
        Assert.Throws<ObjectDisposedException>(() => lease.PrepareSend([], [], []));

        var exactDpe2 = Dpe2(fixture.Scope, operationSeed: 0x31, ciphertextSeed: 0x72);
        var receiveLease = await store.AcquireReceivePreparationLeaseAsync(exactDpe2);
        receiveLease.Dispose();
        Assert.True(receiveLease.IsClearedForTesting);
        Assert.Throws<ObjectDisposedException>(() => receiveLease.PrepareReceive());

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await store.AcquireSendPreparationLeaseAsync(cancellation.Token));

        var oversized = new byte[50_706];
        await Assert.ThrowsAsync<MessagingWireFormatException>(async () =>
            await store.AcquireReceivePreparationLeaseAsync(oversized));
        CryptographicOperations.ZeroMemory(oversized);
    }

    private static void AssertContext(
        MessagingCryptoV1PreparationSnapshot snapshot,
        byte[] exactTrs1,
        byte[] stateCommitment,
        byte[] journalHead,
        ulong stateGeneration,
        ulong journalGeneration,
        ExactDpe2ReceiveReplayDisposition replayDisposition)
    {
        Assert.Equal(MessagingCryptoV1PreparationKind.Send, snapshot.Kind);
        Assert.Equal(SHA256.HashData(exactTrs1), snapshot.ExactTrs1Hash);
        Assert.Equal(stateGeneration, snapshot.ExpectedStateGeneration);
        Assert.Equal(stateCommitment, snapshot.ExpectedStateCommitment);
        Assert.Equal(stateGeneration, snapshot.LatestProtectedGeneration);
        Assert.Equal(stateCommitment, snapshot.LatestProtectedCommitment);
        Assert.Equal(journalGeneration, snapshot.ExpectedJournalGeneration);
        Assert.Equal(journalHead, snapshot.JournalPredecessor);
        Assert.Equal(replayDisposition, snapshot.ReceiveReplayDisposition);
        Assert.Equal(32, snapshot.RetentionCommitment.Length);
        Assert.Contains(snapshot.RetentionCommitment, static value => value != 0);
        Assert.Empty(snapshot.ExactReceiveEnvelopeHash);
    }

    private static byte[] RetentionCommitment(
        MessagingCryptoV1StoreScope scope,
        byte[] journalHead,
        ulong journalGeneration,
        ulong exactDpe2Count)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, "Deep/Client/MessagingCryptoV1/replay-retention/v1"u8);
        Append(hash, U64(1));
        Append(hash, U64(3));
        Append(hash, U64(MessagingCryptoV1Limits.MaximumJournalEntries));
        Append(hash, U64(journalGeneration == 0 ? 0UL : 1UL));
        Append(hash, U64(journalGeneration));
        Append(hash, U64(exactDpe2Count));
        Append(hash, scope.SessionId);
        Append(hash, U64(scope.DatabaseGeneration));
        Append(hash, journalHead);
        return hash.GetHashAndReset();
    }

    private static async Task<byte[]> Initialize(SqliteMessagingCryptoV1Store store, byte[] state)
    {
        await store.ProvisionOpaqueInitialPreKeysForTestsAsync(
            Bytes(0xE1), Bytes(0xF1), Bytes(0xE2), Bytes(0xF2));
        using var initialization = MessagingCryptoV1InitialSessionHandoff.CreateForTests(
            Bytes(0x10), Bytes(0xA5), Bytes(0xA6), Bytes(0xE1), Bytes(0xE2), state);
        return (await store.CommitInitialSessionAsync(initialization)).JournalHead.ToArray();
    }

    private static byte[] Dpe2(
        MessagingCryptoV1StoreScope scope,
        byte operationSeed,
        byte ciphertextSeed)
    {
        var networkId = Enumerable.Repeat((byte)0x11, 16).ToArray();
        var header = new Dtr2Record(
            networkId, Bytes(0x12), 0, 0, 1, 0, 0, 1, Dtr2BraidMessage.None());
        var ciphertext = Enumerable.Repeat(ciphertextSeed, 4_112).ToArray();
        var record = new Dpe2Record(
            networkId,
            scope.SessionId,
            Bytes(0x13),
            scope.LocalDeviceId,
            Bytes(operationSeed),
            header,
            Dpe2Ciphertext.Import(ciphertext));
        return Dpe2Codec.Encode(record);
    }

    private static ExactDpe2DurablePersistencePlan ReceivePlan(
        MessagingCryptoV1StoreScope scope,
        byte[] prior,
        byte[] next,
        byte[] journalHead,
        byte[] exactDpe2)
    {
        var record = Dpe2Codec.Decode(exactDpe2);
        using var priorFacts = FactsLease(prior, scope);
        using var nextFacts = FactsLease(next, scope);
        var operationId = record.OperationId.ToArray();
        var headerHash = MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(record);
        var envelopeHash = MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record);
        try
        {
            return CreatePlan(
                ExactDpe2DurableDirection.Receive,
                priorFacts.Generation,
                nextFacts.Generation,
                priorFacts.Generation,
                0,
                operationId,
                headerHash,
                envelopeHash,
                exactDpe2,
                journalHead,
                prior,
                next,
                priorFacts.StateCommitment,
                nextFacts.StateCommitment,
                priorFacts.StateCommitment,
                Bytes(0x81),
                Bytes(0x82),
                envelopeHash,
                Bytes(0x83),
                Bytes(0x84),
                [],
                true,
                true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(operationId);
            CryptographicOperations.ZeroMemory(headerHash);
            CryptographicOperations.ZeroMemory(envelopeHash);
        }
    }

    private static ExactDpe2DurableCommitCompletion Completion(ExactDpe2DurablePersistencePlan plan) =>
        (ExactDpe2DurableCommitCompletion)typeof(ExactDpe2DurableCommitCompletion)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single().Invoke([plan]);

    private static PlanConstructor BuildPlanConstructor()
    {
        var constructor = typeof(ExactDpe2DurablePersistencePlan)
            .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single();
        var parameters = constructor.GetParameters().Select(static value => value.ParameterType).ToArray();
        var method = new DynamicMethod(
            "CreateExactDpe2PreparationPlanForTests",
            typeof(ExactDpe2DurablePersistencePlan),
            parameters,
            typeof(MessagingCryptoV1PreparationLeaseTests).Module,
            skipVisibility: true);
        var il = method.GetILGenerator();
        for (short index = 0; index < parameters.Length; index++) il.Emit(OpCodes.Ldarg, index);
        il.Emit(OpCodes.Newobj, constructor);
        il.Emit(OpCodes.Ret);
        return method.CreateDelegate<PlanConstructor>();
    }

    private delegate ExactDpe2DurablePersistencePlan PlanConstructor(
        ExactDpe2DurableDirection direction,
        ulong priorStateGeneration,
        ulong nextStateGeneration,
        ulong checkpointPriorGeneration,
        ulong expectedJournalGeneration,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> exactHeaderHash,
        ReadOnlySpan<byte> exactEnvelopeHash,
        ReadOnlySpan<byte> exactEnvelope,
        ReadOnlySpan<byte> journalPredecessor,
        ReadOnlySpan<byte> priorTrs1,
        ReadOnlySpan<byte> nextTrs1,
        ReadOnlySpan<byte> priorStateCommitment,
        ReadOnlySpan<byte> nextStateCommitment,
        ReadOnlySpan<byte> checkpointPriorCommitment,
        ReadOnlySpan<byte> deletionManifestCommitment,
        ReadOnlySpan<byte> messageKeyDeletionEvidence,
        ReadOnlySpan<byte> replayEvidenceCommitment,
        ReadOnlySpan<byte> deduplicationMutationCommitment,
        ReadOnlySpan<byte> pqFenceMutationCommitment,
        ReadOnlySpan<byte> terminalStateCommitment,
        bool messageKeyDeleted,
        bool hasStateMutation);

    private static FactsOwner FactsLease(byte[] trs1, MessagingCryptoV1StoreScope scope) =>
        new(MessagingCryptoV1Trs1.Validate(trs1, scope));

    private sealed class FactsOwner(MessagingCryptoV1Trs1Facts facts) : IDisposable
    {
        internal ulong Generation => facts.Generation;
        internal byte[] StateCommitment => facts.StateCommitment;
        internal byte[] ExactHash => facts.ExactHash;
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
        }
    }

    private static byte[] Trs1(MessagingCryptoV1StoreScope scope, ulong generation, byte seed)
    {
        var result = new byte[601];
        "TRS1"u8.CopyTo(result);
        result[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), (uint)result.Length);
        scope.SessionId.CopyTo(result.AsSpan(12, 32));
        Fill(result.AsSpan(44, 64), seed);
        scope.LocalDeviceId.CopyTo(result.AsSpan(108, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(140), scope.DeviceGeneration);
        Fill(result.AsSpan(148, 32), (byte)(seed + 1));
        Fill(result.AsSpan(180, 32), (byte)(seed + 2));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), 1);
        Fill(result.AsSpan(220, 32), (byte)(seed + 3));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), generation);
        Fill(result.AsSpan(260, 32), (byte)(seed + 4));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1);
        Fill(result.AsSpan(300, 32), (byte)(seed + 5));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1);
        Fill(result.AsSpan(348, 32), (byte)(seed + 6));
        Fill(result.AsSpan(404, 32), (byte)(seed + 7));
        Fill(result.AsSpan(460, 32), (byte)(seed + 8));
        Fill(result.AsSpan(492, 32), (byte)(seed + 9));
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), 1);
        result[536] = (byte)(seed + 10);
        Fill(result.AsSpan(537, 32), (byte)(seed + 11));
        var checksum = MessagingCryptoV1Trs1.Sha256Domain(
            "Deep/LocalState/V1/triple-ratchet-state-checksum",
            result.AsSpan(0, result.Length - 32));
        checksum.CopyTo(result, result.Length - 32);
        CryptographicOperations.ZeroMemory(checksum);
        return result;
    }

    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Bytes(byte value) =>
        Enumerable.Repeat(value == 0 ? (byte)1 : value, 32).ToArray();

    private static void Fill(Span<byte> destination, byte value) =>
        destination.Fill(value == 0 ? (byte)1 : value);

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "deep-messaging-crypto-preparation", Guid.NewGuid().ToString("N"));

        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "ratchet.db");
            Key = Bytes(0x91);
            Scope = new MessagingCryptoV1StoreScope(
                Bytes(0xA1), 1, Bytes(0xB1), 1, Bytes(0xC1), Bytes(0xD1), 1);
        }

        internal string Path { get; }
        internal byte[] Key { get; }
        internal MessagingCryptoV1StoreScope Scope { get; }

        internal SqliteMessagingCryptoV1Store Open(bool allowCreate = true)
        {
            using var options = new MessagingCryptoV1StoreOptions(Path, Key, Scope, allowCreate);
            return new SqliteMessagingCryptoV1Store(options);
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
