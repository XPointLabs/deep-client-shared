using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Emit;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Client.Shared.Tests.Persistence.MessagingCryptoV1;

public sealed class ExactDpe2SqliteDurableTransactionAuthorityTests
{
    private static readonly PlanConstructor CreatePlan = BuildPlanConstructor();
    [Fact]
    public async Task CommitAndLostCallbackRetryAreDurableAcrossRestart()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x31);
        var next = Trs1(fixture.Scope, 2, 0x32);
        byte[] journalHead;
        await using (var store = fixture.Open())
        {
            journalHead = await Initialize(store, prior);
            using var plan = Plan(fixture.Scope, prior, next, journalHead,
                operation: 0x21, envelope: 0x41, direction: ExactDpe2DurableDirection.Send);
            var authority = new ExactDpe2SqliteDurableTransactionAuthority(store);
            using (MessagingCryptoV1StoreTestHooks.Push(point =>
                       { if (point == MessagingCryptoV1StoreFailpoint.AfterCommit)
                               throw new MessagingCryptoV1InjectedCrashException(point); }))
            {
                var completion = Completion(plan);
                await Assert.ThrowsAsync<MessagingCryptoV1InjectedCrashException>(async () =>
                    await authority.CommitAsync(plan, completion));
                Assert.Equal(ExactDpe2DurableCommitDisposition.Committed,
                    completion.Complete(ExactDpe2DurableCommitDisposition.Committed).Disposition);
            }
        }

        await using var restarted = fixture.Open(allowCreate: false);
        using var retry = Plan(fixture.Scope, prior, next, journalHead,
            operation: 0x21, envelope: 0x41, direction: ExactDpe2DurableDirection.Send);
        var receipt = await new ExactDpe2SqliteDurableTransactionAuthority(restarted)
            .CommitAsync(retry, Completion(retry));
        Assert.Equal(ExactDpe2DurableCommitDisposition.ExactReplay, receipt.Disposition);
        Assert.Equal(2UL, (await restarted.ReadHeadAsync())!.StateGeneration);
    }

    [Fact]
    public async Task AuthenticatedReceiveReplayDoesNotAdvanceRatchet()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x51);
        var next = Trs1(fixture.Scope, 2, 0x52);
        await using var store = fixture.Open();
        var genesis = await Initialize(store, prior);
        var authority = new ExactDpe2SqliteDurableTransactionAuthority(store);
        using (var fresh = Plan(fixture.Scope, prior, next, genesis,
                   operation: 0x22, envelope: 0x42, direction: ExactDpe2DurableDirection.Receive))
        {
            var receipt = await authority.CommitAsync(fresh, Completion(fresh));
            Assert.Equal(ExactDpe2DurableCommitDisposition.Committed, receipt.Disposition);
        }

        var head = (await store.ReadHeadAsync())!;
        using var replay = Plan(fixture.Scope, next, null, head.JournalHead.Span,
            operation: 0x22, envelope: 0x42, direction: ExactDpe2DurableDirection.Receive,
            expectedJournal: 1);
        var replayReceipt = await authority.CommitAsync(replay, Completion(replay));
        Assert.Equal(ExactDpe2DurableCommitDisposition.ExactReplay, replayReceipt.Disposition);
        var unchanged = (await store.ReadHeadAsync())!;
        Assert.Equal(2UL, unchanged.StateGeneration);
        Assert.Equal(1UL, unchanged.JournalGeneration);
    }

    [Fact]
    public async Task ConcurrentWritersYieldOneCommitAndOneCasConflict()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x61);
        var winner = Trs1(fixture.Scope, 2, 0x62);
        var loser = Trs1(fixture.Scope, 2, 0x63);
        await using var first = fixture.Open();
        var genesis = await Initialize(first, prior);
        await using var second = fixture.Open(allowCreate: false);
        using var firstPlan = Plan(fixture.Scope, prior, winner, genesis,
            operation: 0x23, envelope: 0x43, direction: ExactDpe2DurableDirection.Send);
        using var secondPlan = Plan(fixture.Scope, prior, loser, genesis,
            operation: 0x24, envelope: 0x44, direction: ExactDpe2DurableDirection.Send);
        var firstTask = new ExactDpe2SqliteDurableTransactionAuthority(first)
            .CommitAsync(firstPlan, Completion(firstPlan)).AsTask();
        var secondTask = new ExactDpe2SqliteDurableTransactionAuthority(second)
            .CommitAsync(secondPlan, Completion(secondPlan)).AsTask();
        var receipts = await Task.WhenAll(firstTask, secondTask);
        Assert.Single(receipts, static value =>
            value.Disposition == ExactDpe2DurableCommitDisposition.Committed);
        Assert.Single(receipts, static value =>
            value.Disposition == ExactDpe2DurableCommitDisposition.CasConflict);
    }

    [Fact]
    public async Task ConflictingReplayTokenDurablyLatchesFork()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x71);
        var next = Trs1(fixture.Scope, 2, 0x72);
        await using var store = fixture.Open();
        var genesis = await Initialize(store, prior);
        var authority = new ExactDpe2SqliteDurableTransactionAuthority(store);
        using (var accepted = Plan(fixture.Scope, prior, next, genesis,
                   operation: 0x25, envelope: 0x45, direction: ExactDpe2DurableDirection.Send))
            Assert.Equal(ExactDpe2DurableCommitDisposition.Committed,
                (await authority.CommitAsync(accepted, Completion(accepted))).Disposition);

        using var conflicting = Plan(fixture.Scope, prior, Trs1(fixture.Scope, 2, 0x73), genesis,
            operation: 0x26, envelope: 0x45, direction: ExactDpe2DurableDirection.Send);
        Assert.Equal(ExactDpe2DurableCommitDisposition.ForkLatched,
            (await authority.CommitAsync(conflicting, Completion(conflicting))).Disposition);
        Assert.True((await store.ReadHeadAsync())!.ForkLatched);
    }

    [Fact]
    public async Task CancellationBeforeMutationDoesNotConsumeCompletion()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x11);
        var next = Trs1(fixture.Scope, 2, 0x12);
        await using var store = fixture.Open();
        var genesis = await Initialize(store, prior);
        using var plan = Plan(fixture.Scope, prior, next, genesis,
            operation: 0x27, envelope: 0x47, direction: ExactDpe2DurableDirection.Send);
        var completion = Completion(plan);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await new ExactDpe2SqliteDurableTransactionAuthority(store)
                .CommitAsync(plan, completion, cancellation.Token));
        Assert.Equal(ExactDpe2DurableCommitDisposition.CasConflict,
            completion.Complete(ExactDpe2DurableCommitDisposition.CasConflict).Disposition);
        Assert.Equal(1UL, (await store.ReadHeadAsync())!.StateGeneration);
    }

    [Fact]
    public async Task ReceiptFromAnotherPlanIsRejectedByProtocolCapabilityBinding()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x21);
        var next = Trs1(fixture.Scope, 2, 0x22);
        await using var store = fixture.Open();
        var genesis = await Initialize(store, prior);
        using var expectedPlan = Plan(fixture.Scope, prior, next, genesis,
            operation: 0x28, envelope: 0x48, direction: ExactDpe2DurableDirection.Send);
        using var foreignPlan = Plan(fixture.Scope, prior, next, genesis,
            operation: 0x28, envelope: 0x48, direction: ExactDpe2DurableDirection.Send);
        var foreignCompletion = Completion(foreignPlan);
        var receipt = await new ExactDpe2SqliteDurableTransactionAuthority(store)
            .CommitAsync(expectedPlan, foreignCompletion);
        var expectedCompletion = Completion(expectedPlan);
        var consume = typeof(ExactDpe2DurableCommitReceipt).GetMethod(
            "ConsumeAndVerify", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var failure = Assert.Throws<TargetInvocationException>(() =>
            consume.Invoke(receipt, [expectedPlan, expectedCompletion]));
        Assert.IsType<CryptographicException>(failure.InnerException);
    }

    [Fact]
    public async Task CapacityFailsClosedWithoutMintingReceipt()
    {
        using var fixture = new Fixture();
        var prior = Trs1(fixture.Scope, 1, 0x29);
        var next = Trs1(fixture.Scope, 2, 0x2A);
        await using var store = fixture.Open();
        var genesis = await Initialize(store, prior);
        using var plan = Plan(fixture.Scope, prior, next, genesis,
            operation: 0x29, envelope: 0x49, direction: ExactDpe2DurableDirection.Send);
        var completion = Completion(plan);
        using (MessagingCryptoV1StoreTestHooks.PushJournalCapacity(0))
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await new ExactDpe2SqliteDurableTransactionAuthority(store)
                    .CommitAsync(plan, completion));
        Assert.Equal(ExactDpe2DurableCommitDisposition.CasConflict,
            completion.Complete(ExactDpe2DurableCommitDisposition.CasConflict).Disposition);
        Assert.Equal(0UL, (await store.ReadHeadAsync())!.JournalGeneration);

        var snapshot = ExactDpe2ProtocolPlanSnapshot.Capture(plan);
        snapshot.Dispose();
        Assert.True(snapshot.IsClearedForTesting);
    }

    private static async Task<byte[]> Initialize(SqliteMessagingCryptoV1Store store, byte[] state)
    {
        await store.ProvisionOpaqueInitialPreKeysForTestsAsync(
            Bytes(0xE1), Bytes(0xF1), Bytes(0xE2), Bytes(0xF2));
        using var initialization = MessagingCryptoV1InitialSessionHandoff.CreateForTests(
            Bytes(0x10), Bytes(0xA5), Bytes(0xA6), Bytes(0xE1), Bytes(0xE2), state);
        return (await store.CommitInitialSessionAsync(initialization)).JournalHead.ToArray();
    }

    private static ExactDpe2DurablePersistencePlan Plan(
        MessagingCryptoV1StoreScope scope,
        byte[] prior,
        byte[]? next,
        ReadOnlySpan<byte> journalHead,
        byte operation,
        byte envelope,
        ExactDpe2DurableDirection direction,
        ulong expectedJournal = 0)
    {
        var priorFacts = MessagingCryptoV1Trs1.Validate(prior, scope);
        MessagingCryptoV1Trs1Facts? nextFacts = next is null ? null :
            MessagingCryptoV1Trs1.Validate(next, scope);
        var exactEnvelope = Enumerable.Repeat(envelope, 4_513).ToArray();
        try
        {
            return CreatePlan(
                direction,
                priorFacts.Generation,
                nextFacts?.Generation ?? priorFacts.Generation,
                priorFacts.Generation,
                expectedJournal,
                Bytes(operation),
                Bytes(unchecked((byte)(envelope + 1))),
                Bytes(envelope),
                exactEnvelope,
                journalHead.ToArray(),
                prior,
                next ?? Array.Empty<byte>(),
                priorFacts.StateCommitment,
                nextFacts?.StateCommitment ?? Array.Empty<byte>(),
                priorFacts.StateCommitment,
                Bytes(0x81),
                next is null ? Array.Empty<byte>() : Bytes(0x82),
                Bytes(0x83),
                direction == ExactDpe2DurableDirection.Receive ? Bytes(0x84) : Array.Empty<byte>(),
                Bytes(0x85),
                Array.Empty<byte>(),
                next is not null,
                next is not null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priorFacts.StateCommitment);
            CryptographicOperations.ZeroMemory(priorFacts.ExactHash);
            if (nextFacts is not null)
            {
                CryptographicOperations.ZeroMemory(nextFacts.StateCommitment);
                CryptographicOperations.ZeroMemory(nextFacts.ExactHash);
            }
            CryptographicOperations.ZeroMemory(exactEnvelope);
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
        var method = new DynamicMethod("CreateExactDpe2PlanForTests",
            typeof(ExactDpe2DurablePersistencePlan), parameters,
            typeof(ExactDpe2SqliteDurableTransactionAuthorityTests).Module, skipVisibility: true);
        var il = method.GetILGenerator();
        for (short index = 0; index < parameters.Length; index++) il.Emit(OpCodes.Ldarg, index);
        il.Emit(OpCodes.Newobj, constructor); il.Emit(OpCodes.Ret);
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

    private static byte[] Trs1(MessagingCryptoV1StoreScope scope, ulong generation, byte seed)
    {
        var result = new byte[601];
        "TRS1"u8.CopyTo(result); result[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), (uint)result.Length);
        scope.SessionId.CopyTo(result.AsSpan(12, 32));
        Fill(result.AsSpan(44, 64), seed); scope.LocalDeviceId.CopyTo(result.AsSpan(108, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(140), scope.DeviceGeneration);
        Fill(result.AsSpan(148, 32), (byte)(seed + 1)); Fill(result.AsSpan(180, 32), (byte)(seed + 2));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), 1);
        Fill(result.AsSpan(220, 32), (byte)(seed + 3));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), generation);
        Fill(result.AsSpan(260, 32), (byte)(seed + 4));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1);
        Fill(result.AsSpan(300, 32), (byte)(seed + 5));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1);
        Fill(result.AsSpan(348, 32), (byte)(seed + 6)); Fill(result.AsSpan(404, 32), (byte)(seed + 7));
        Fill(result.AsSpan(460, 32), (byte)(seed + 8)); Fill(result.AsSpan(492, 32), (byte)(seed + 9));
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), 1); result[536] = (byte)(seed + 10);
        Fill(result.AsSpan(537, 32), (byte)(seed + 11));
        var checksum = MessagingCryptoV1Trs1.Sha256Domain(
            "Deep/LocalState/V1/triple-ratchet-state-checksum", result.AsSpan(0, result.Length - 32));
        checksum.CopyTo(result, result.Length - 32); CryptographicOperations.ZeroMemory(checksum);
        return result;
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value == 0 ? (byte)1 : value, 32).ToArray();
    private static void Fill(Span<byte> destination, byte value) => destination.Fill(value == 0 ? (byte)1 : value);

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-exact-dpe2-authority", Guid.NewGuid().ToString("N"));
        internal Fixture()
        {
            Directory.CreateDirectory(directory); Path = System.IO.Path.Combine(directory, "ratchet.db");
            Key = Bytes(0x91); Scope = new MessagingCryptoV1StoreScope(
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
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }
}
