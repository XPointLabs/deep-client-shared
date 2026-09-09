using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Deep.Client.Shared.Persistence.PreKeyV1;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Identity;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Tests.Persistence.PreKeyV1;

[Collection("SQLite global pool isolation")]
[Trait("RequiresApprovedMlKemRuntime", "true")]
public sealed class SqlitePreKeyV1SecretOwnerTests
{
    [Fact]
    public async Task StoreIsEncryptedAndExactDeviceGenerationScopeSurvivesRestart()
    {
        using var fixture = new Fixture();
        var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x21);
        await using (var owner = fixture.Open())
            Assert.Equal(PreKeyV1ProvisionDisposition.Provisioned,
                await owner.ProvisionAsync(fixture.Provision(owner, material)));

        Assert.False(File.ReadAllBytes(fixture.Path).AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
        await using (var reopened = fixture.Open(allowCreate: false))
            Assert.Equal(PreKeyV1ClaimDisposition.Reserved,
                (await reopened.ReserveAndRestoreForTestsAsync(
                    fixture.Claim(material, 0x22))).Disposition);

        var wrongScope = fixture.Scope(accountGeneration: 2);
        var mismatch = Assert.Throws<PreKeyV1StoreOpenException>(() => fixture.Open(wrongScope, allowCreate: false));
        Assert.Equal(PreKeyV1StoreOpenFailure.ScopeMismatch, mismatch.Reason);

        var wrongKey = fixture.Key.ToArray();
        wrongKey[0] ^= 0x7f;
        using var options = new PreKeyV1StoreOptions(fixture.Path, wrongKey, fixture.Scope(), allowCreate: false);
        var unreadable = Assert.Throws<PreKeyV1StoreOpenException>(() => new SqlitePreKeyV1SecretOwner(options));
        Assert.Equal(PreKeyV1StoreOpenFailure.UnreadableOrWrongKey, unreadable.Reason);
        CryptographicOperations.ZeroMemory(wrongKey);
        material.Dispose();
    }

    [Fact]
    public async Task OneTimeClaimIsExclusiveCallbackOnlyAndFinalReplayIsIdempotent()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x31);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));

        var result = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x41));
        Assert.Equal(PreKeyV1ClaimDisposition.Reserved, result.Disposition);
        Assert.True(result.SecretCallbackInvoked);

        var replay = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x41));
        Assert.Equal(PreKeyV1ClaimDisposition.ExactReservedReplay, replay.Disposition);

        Assert.Equal(PreKeyV1ClaimDisposition.Consumed,
            (await owner.ConsumeAsync(fixture.Claim(material, 0x41))).Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.ExactFinalReplay,
            (await owner.ConsumeAsync(fixture.Claim(material, 0x41))).Disposition);
        var finalReplay = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x41));
        Assert.Equal(PreKeyV1ClaimDisposition.ExactFinalReplay, finalReplay.Disposition);
        Assert.False(finalReplay.SecretCallbackInvoked);
    }

    [Theory]
    [InlineData((int)PreKeyV1StoreFailpoint.AfterClaimInsert)]
    [InlineData((int)PreKeyV1StoreFailpoint.AfterInventoryUpdate)]
    [InlineData((int)PreKeyV1StoreFailpoint.BeforeReserveCommit)]
    public async Task CrashBeforeReserveCommitRollsBackTheWholeClaim(int failpointValue)
    {
        var failpoint = (PreKeyV1StoreFailpoint)failpointValue;
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x51);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));
        using (PreKeyV1StoreTestHooks.Push(point =>
                   { if (point == failpoint) throw new PreKeyV1InjectedCrashException(point); }))
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x61)));

        var retry = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x61));
        Assert.Equal(PreKeyV1ClaimDisposition.Reserved, retry.Disposition);
    }

    [Fact]
    public async Task CrashAfterReserveCommitReplaysSameSecretsAfterRestart()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x71);
        await using (var owner = fixture.Open())
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            using (PreKeyV1StoreTestHooks.Push(point =>
                       { if (point == PreKeyV1StoreFailpoint.AfterReserveCommit)
                               throw new PreKeyV1InjectedCrashException(point); }))
                await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                    await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x72)));
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var retry = await restarted.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x72));
        Assert.Equal(PreKeyV1ClaimDisposition.ExactReservedReplay, retry.Disposition);
    }

    [Fact]
    public async Task ChangedOneTimeClaimPermanentlyLatchesForkAcrossRestart()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x81);
        await using (var owner = fixture.Open())
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x82));
            var conflict = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x83));
            Assert.Equal(PreKeyV1ClaimDisposition.ForkLatched, conflict.Disposition);
            Assert.True(conflict.ForkLatched);
        }

        await using var restarted = fixture.Open(allowCreate: false);
        Assert.Equal(PreKeyV1ClaimDisposition.AlreadyForkLatched,
            (await restarted.ConsumeAsync(fixture.Claim(material, 0x82))).Disposition);
    }

    [Fact]
    public async Task FinalizeCrashIsAtomicAndRecoverable()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x91);
        await using (var owner = fixture.Open())
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x92));
            using (PreKeyV1StoreTestHooks.Push(point =>
                       { if (point == PreKeyV1StoreFailpoint.BeforeFinalizeCommit)
                               throw new PreKeyV1InjectedCrashException(point); }))
                await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                    await owner.ConsumeAsync(fixture.Claim(material, 0x92)));
        }

        await using (var restarted = fixture.Open(allowCreate: false))
        {
            Assert.Equal(PreKeyV1ClaimDisposition.ExactReservedReplay,
                (await restarted.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0x92))).Disposition);
            using (PreKeyV1StoreTestHooks.Push(point =>
                       { if (point == PreKeyV1StoreFailpoint.AfterFinalizeCommit)
                               throw new PreKeyV1InjectedCrashException(point); }))
                await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                    await restarted.ConsumeAsync(fixture.Claim(material, 0x92)));
        }

        await using var finalRestart = fixture.Open(allowCreate: false);
        Assert.Equal(PreKeyV1ClaimDisposition.ExactFinalReplay,
            (await finalRestart.ConsumeAsync(fixture.Claim(material, 0x92))).Disposition);
    }

    [Fact]
    public async Task LastResortUsesMonotonicBoundedCountersAndThenZeroizesItsSecret()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.LastResort, 0xa1, reuseLimit: 2);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));

        for (ushort counter = 1; counter <= 2; counter++)
        {
            var claim = fixture.Claim(material, unchecked((byte)(0xa1 + counter)), counter);
            var used = await owner.ReserveAndRestoreForTestsAsync(claim);
            Assert.Equal(PreKeyV1ClaimDisposition.Reserved, used.Disposition);
            Assert.Equal(counter, used.LastResortCounter);
            Assert.Equal(PreKeyV1ClaimDisposition.Consumed,
                (await owner.ConsumeAsync(fixture.Claim(material,
                    unchecked((byte)(0xa1 + counter)), counter))).Disposition);
        }

        var exhausted = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0xa4, 3));
        Assert.Equal(PreKeyV1ClaimDisposition.Unavailable, exhausted.Disposition);
        Assert.False(exhausted.SecretCallbackInvoked);
        var exactHash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(material.Record);
        try
        {
            Assert.True(await owner.AreLastResortSecretsClearedForTestsAsync(exactHash));
            await owner.DisposeAsync();
            await using var restarted = fixture.Open(allowCreate: false);
            Assert.True(await restarted.AreLastResortSecretsClearedForTestsAsync(exactHash));
            var afterRestart = await restarted.ReserveAndRestoreForTestsAsync(
                fixture.Claim(material, 0xa5, 3));
            Assert.Equal(PreKeyV1ClaimDisposition.Unavailable, afterRestart.Disposition);
        }
        finally { CryptographicOperations.ZeroMemory(exactHash); }
    }

    [Fact]
    public async Task LastResortChangedClaimAtSameCounterLatchesFork()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.LastResort, 0xb1, reuseLimit: 4);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));
        await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0xb2, 1));
        var conflict = await owner.ReserveAndRestoreForTestsAsync(fixture.Claim(material, 0xb3, 1));
        Assert.Equal(PreKeyV1ClaimDisposition.ForkLatched, conflict.Disposition);
    }

    [Fact]
    public async Task ProvisionCapabilitiesAreSingleUseAndOwnedBuffersAreCleared()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0xc1);
        await using var owner = fixture.Open();
        var capability = fixture.Provision(owner, material);
        Assert.Equal(PreKeyV1ProvisionDisposition.Provisioned, await owner.ProvisionAsync(capability));
        Assert.True(capability.IsClearedForTesting);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await owner.ProvisionAsync(capability));

        await owner.DisposeAsync();
        Assert.True(owner.IsKeyZeroedForTesting);
        using var options = new PreKeyV1StoreOptions(fixture.Path, fixture.Key, fixture.Scope(), allowCreate: false);
        options.Dispose();
        Assert.True(options.IsKeyZeroedForTesting);
    }

    [Fact]
    public void InitialSessionCommitPermitIsOpaqueSingleUseAndZeroizesTransferredBuffers()
    {
        var permit = SqlitePreKeyV1SecretOwner.InitialSessionCommitPermit.CreateForTests(
            Dpk2PrekeyKind.OneTime,
            Bytes(32, 0xd1), Bytes(32, 0xd2), Bytes(32, 0xd3),
            Bytes(32, 0xd4), Bytes(32, 0xd5), Bytes(600, 0xd6));

        using var handoff = MessagingCryptoV1InitialSessionHandoff
            .CreateFromDeviceWidePreKeyOwner(permit);
        var payload = handoff.Consume();
        Assert.Equal(32, payload.ClaimOperationId.Length);
        Assert.Equal(600, payload.ExactTrs1.Length);
        payload.Dispose();
        Assert.All(payload.ClaimOperationId, static value => Assert.Equal(0, value));
        Assert.All(payload.ExactTrs1, static value => Assert.Equal(0, value));
        Assert.Throws<InvalidOperationException>(() => permit.Consume());
        permit.Dispose();

        using var disposedPermit = SqlitePreKeyV1SecretOwner.InitialSessionCommitPermit.CreateForTests(
            Dpk2PrekeyKind.LastResort,
            Bytes(32, 0xe1), Bytes(32, 0xe2), Bytes(32, 0xe3),
            [], Bytes(32, 0xe5), Bytes(600, 0xe6));
        var disposedHandoff = MessagingCryptoV1InitialSessionHandoff
            .CreateFromDeviceWidePreKeyOwner(disposedPermit);
        disposedHandoff.Dispose();
        Assert.Throws<InvalidOperationException>(() => disposedHandoff.Consume());
    }

    [Fact]
    public async Task OneTimeInitialSessionSagaCommitsFinalizesAndExactReplaySkipsSecrets()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0xe1);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));
        await using var sessions = fixture.OpenMessaging(0xe2);
        var initialized = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0xe2), sessions,
            Trs1(fixture.MessagingScope(0xe2), 0x21));

        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.Initialized, initialized.Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.Consumed, initialized.PreKeyDisposition);
        Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized, initialized.SessionDisposition);

        var replay = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0xe2), sessions,
            Trs1(fixture.MessagingScope(0xe2), 0x21));
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.ExactReplay, replay.Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.ExactFinalReplay, replay.PreKeyDisposition);
    }

    [Fact]
    public async Task LastResortInitialSessionSagaHasNoX25519IdAndAdvancesCounter()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.LastResort, 0xc1, reuseLimit: 2);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));
        await using var sessions = fixture.OpenMessaging(0xc2);

        var initialized = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0xc2, lastResortCounter: 1), sessions,
            Trs1(fixture.MessagingScope(0xc2), 0x31));

        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.Initialized, initialized.Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.Consumed, initialized.PreKeyDisposition);
        Assert.Equal(0, await sessions.ReadInitialPreKeyCountForTestsAsync());

        var replay = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0xc2, lastResortCounter: 1), sessions,
            Trs1(fixture.MessagingScope(0xc2), 0x31));
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.ExactReplay, replay.Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.ExactFinalReplay, replay.PreKeyDisposition);
        Assert.Equal(MessagingCryptoV1CommitDisposition.ExactReplay, replay.SessionDisposition);
    }

    [Theory]
    [InlineData((int)Dpk2PrekeyKind.OneTime)]
    [InlineData((int)Dpk2PrekeyKind.LastResort)]
    public async Task CrashAfterSessionCommitReplaysCommitAndCompletesPreKeyFinalizeAfterRestart(
        int kindValue)
    {
        var kind = (Dpk2PrekeyKind)kindValue;
        var counter = kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0;
        using var fixture = new Fixture();
        using var material = fixture.Create(kind, 0xa1, reuseLimit: 2);
        await using (var owner = fixture.Open())
        await using (var sessions = fixture.OpenMessaging(0xa2))
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            using var crash = PreKeyV1StoreTestHooks.Push(point =>
            {
                if (point == PreKeyV1StoreFailpoint.AfterSessionCommitBeforeFinalize)
                    throw new PreKeyV1InjectedCrashException(point);
            });
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.CommitInitialSessionSagaForTestsAsync(
                    fixture.Claim(material, 0xa2, counter), sessions,
                    Trs1(fixture.MessagingScope(0xa2), 0x41)));
        }

        await using var restartedOwner = fixture.Open(allowCreate: false);
        await using var restartedSessions = fixture.OpenMessaging(0xa2, allowCreate: false);
        var recovered = await restartedOwner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0xa2, counter), restartedSessions,
            Trs1(fixture.MessagingScope(0xa2), 0x41));
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.ExactReplay, recovered.Disposition);
        Assert.Equal(MessagingCryptoV1CommitDisposition.ExactReplay, recovered.SessionDisposition);
        Assert.Equal(PreKeyV1ClaimDisposition.Consumed, recovered.PreKeyDisposition);
    }

    [Fact]
    public async Task CrashBeforeInitialSessionBindingCommitRollsBackBindingAndRetriesExactly()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x91);
        await using (var owner = fixture.Open())
        await using (var sessions = fixture.OpenMessaging(0x93))
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            using var crash = PreKeyV1StoreTestHooks.Push(point =>
            {
                if (point == PreKeyV1StoreFailpoint.AfterInitialSessionBindingBeforeCommit)
                    throw new PreKeyV1InjectedCrashException(point);
            });
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.CommitInitialSessionSagaForTestsAsync(
                    fixture.Claim(material, 0x93), sessions,
                    Trs1(fixture.MessagingScope(0x93), 0x42)));
        }

        await using var restartedOwner = fixture.Open(allowCreate: false);
        await using var restartedSessions = fixture.OpenMessaging(0x93, allowCreate: false);
        var recovered = await restartedOwner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0x93), restartedSessions,
            Trs1(fixture.MessagingScope(0x93), 0x42));
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.Initialized, recovered.Disposition);
        Assert.Equal(PreKeyV1ClaimDisposition.Consumed, recovered.PreKeyDisposition);
    }

    [Theory]
    [InlineData((int)Dpk2PrekeyKind.OneTime)]
    [InlineData((int)Dpk2PrekeyKind.LastResort)]
    public async Task ChangedTrs1AfterDurableBindingLatchesForkAcrossRestart(int kindValue)
    {
        var kind = (Dpk2PrekeyKind)kindValue;
        var counter = kind == Dpk2PrekeyKind.LastResort ? (ushort)1 : (ushort)0;
        using var fixture = new Fixture();
        using var material = fixture.Create(kind, 0x81, reuseLimit: 2);
        await using (var owner = fixture.Open())
        await using (var sessions = fixture.OpenMessaging(0x82))
        {
            await owner.ProvisionAsync(fixture.Provision(owner, material));
            using var crash = PreKeyV1StoreTestHooks.Push(point =>
            {
                if (point == PreKeyV1StoreFailpoint.AfterInitialSessionBindingCommit)
                    throw new PreKeyV1InjectedCrashException(point);
            });
            await Assert.ThrowsAsync<PreKeyV1InjectedCrashException>(async () =>
                await owner.CommitInitialSessionSagaForTestsAsync(
                    fixture.Claim(material, 0x82, counter), sessions,
                    Trs1(fixture.MessagingScope(0x82), 0x51)));
        }

        await using (var restartedOwner = fixture.Open(allowCreate: false))
        await using (var restartedSessions = fixture.OpenMessaging(0x82, allowCreate: false))
        {
            var conflict = await restartedOwner.CommitInitialSessionSagaForTestsAsync(
                fixture.Claim(material, 0x82, counter), restartedSessions,
                Trs1(fixture.MessagingScope(0x82), 0x52));
            Assert.Equal(PreKeyV1InitialSessionSagaDisposition.ForkLatched, conflict.Disposition);
            Assert.True(conflict.ForkLatched);
        }

        await using var finalOwner = fixture.Open(allowCreate: false);
        var latched = await finalOwner.ReserveAndRestoreForTestsAsync(
            fixture.Claim(material, 0x82, counter));
        Assert.Equal(PreKeyV1ClaimDisposition.AlreadyForkLatched, latched.Disposition);
    }

    [Fact]
    public async Task FinalReplayFailsClosedWhenCommittedSessionDatabaseWasLost()
    {
        using var fixture = new Fixture();
        using var material = fixture.Create(Dpk2PrekeyKind.OneTime, 0x61);
        await using var owner = fixture.Open();
        await owner.ProvisionAsync(fixture.Provision(owner, material));
        await using (var sessions = fixture.OpenMessaging(0x62))
        {
            var initialized = await owner.CommitInitialSessionSagaForTestsAsync(
                fixture.Claim(material, 0x62), sessions,
                Trs1(fixture.MessagingScope(0x62), 0x71));
            Assert.Equal(PreKeyV1InitialSessionSagaDisposition.Initialized, initialized.Disposition);
        }

        fixture.DeleteMessagingDatabaseForTest();
        await using var replacement = fixture.OpenMessaging(0x62);
        var replay = await owner.CommitInitialSessionSagaForTestsAsync(
            fixture.Claim(material, 0x62), replacement,
            Trs1(fixture.MessagingScope(0x62), 0x71));
        Assert.Equal(PreKeyV1InitialSessionSagaDisposition.SessionRejected, replay.Disposition);
        Assert.Null(replay.SessionDisposition);
    }

    private static byte[] Trs1(MessagingCryptoV1StoreScope scope, byte seed)
    {
        var result = new byte[601];
        "TRS1"u8.CopyTo(result); result[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)result.Length));
        scope.SessionId.CopyTo(result.AsSpan(12, 32));
        Fill(result.AsSpan(44, 64), seed); scope.LocalDeviceId.CopyTo(result.AsSpan(108, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(140), scope.DeviceGeneration);
        Fill(result.AsSpan(148, 32), unchecked((byte)(seed + 1))); Fill(result.AsSpan(180, 32), unchecked((byte)(seed + 2)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), 1); Fill(result.AsSpan(220, 32), unchecked((byte)(seed + 3)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), 1); Fill(result.AsSpan(260, 32), unchecked((byte)(seed + 4)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1); Fill(result.AsSpan(300, 32), unchecked((byte)(seed + 5)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1); Fill(result.AsSpan(348, 32), unchecked((byte)(seed + 6)));
        Fill(result.AsSpan(404, 32), unchecked((byte)(seed + 7))); Fill(result.AsSpan(460, 32), unchecked((byte)(seed + 8)));
        Fill(result.AsSpan(492, 32), unchecked((byte)(seed + 9))); BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), 1); result[536] = unchecked((byte)(seed + 10));
        Fill(result.AsSpan(537, 32), unchecked((byte)(seed + 11)));
        var checksum = MessagingCryptoV1Trs1.Sha256Domain(
            "Deep/LocalState/V1/triple-ratchet-state-checksum", result.AsSpan(0, result.Length - 32));
        checksum.CopyTo(result, result.Length - 32); CryptographicOperations.ZeroMemory(checksum);
        return result;
    }

    private static void Fill(Span<byte> destination, byte value) =>
        destination.Fill(value == 0 ? (byte)1 : value);

    private sealed class Fixture : IDisposable
    {
        private readonly OpaquePreKeyV1AuthoringFixture authoring;
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-prekey-v1", Guid.NewGuid().ToString("N"));

        internal Fixture()
        {
            authoring = OpaquePreKeyV1AuthoringFixture.CreateAsync().GetAwaiter().GetResult();
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "prekeys.db");
            MessagingPath = System.IO.Path.Combine(directory, "messages.db");
            Key = Bytes(32, 0x11);
            NetworkId = authoring.NetworkId.ToArray();
            AccountId = authoring.AccountId.ToArray();
            DeviceId = authoring.DeviceId.ToArray();
            Dpd1Hash = authoring.Dpd1Hash.ToArray();
            Dpd1Reference = authoring.Dpd1Reference.ToArray();
        }

        internal string Path { get; }
        internal string MessagingPath { get; }
        internal byte[] Key { get; }
        internal byte[] NetworkId { get; }
        internal byte[] AccountId { get; }
        internal byte[] DeviceId { get; }
        internal byte[] Dpd1Hash { get; }
        internal byte[] Dpd1Reference { get; }

        internal PreKeyV1StoreScope Scope(ulong accountGeneration = 1, ulong deviceGeneration = 1) =>
            new(NetworkId, AccountId, accountGeneration, DeviceId, deviceGeneration,
                Dpd1Reference, Dpd1Hash, databaseGeneration: 13);

        internal SqlitePreKeyV1SecretOwner Open(bool allowCreate = true) => Open(Scope(), allowCreate);

        internal SqlitePreKeyV1SecretOwner Open(PreKeyV1StoreScope scope, bool allowCreate)
        {
            using var options = new PreKeyV1StoreOptions(Path, Key, scope, allowCreate);
            return new SqlitePreKeyV1SecretOwner(options);
        }

        internal MessagingCryptoV1StoreScope MessagingScope(byte operationSeed) => new(
            AccountId, 1, DeviceId, 1, Bytes(32, 0x71), Bytes(32, operationSeed + 1), 17);

        internal SqliteMessagingCryptoV1Store OpenMessaging(byte operationSeed, bool allowCreate = true)
        {
            using var options = new MessagingCryptoV1StoreOptions(
                MessagingPath, Bytes(32, 0x19), MessagingScope(operationSeed), allowCreate);
            return new SqliteMessagingCryptoV1Store(options);
        }

        internal void DeleteMessagingDatabaseForTest()
        {
            foreach (var path in new[] { MessagingPath, MessagingPath + "-wal", MessagingPath + "-shm" })
                if (File.Exists(path)) File.Delete(path);
        }

        internal Material Create(Dpk2PrekeyKind kind, byte seed, ushort reuseLimit = 0)
        {
            _ = seed;
            var offering = authoring.Author(kind, inventoryEpoch: 23, reuseLimit);
            return new Material(offering, offering.Record, offering.ExactDpk2.ToArray());
        }

        internal PreKeyV1ProvisioningCapability Provision(
            SqlitePreKeyV1SecretOwner owner,
            Material material) => owner.SealAuthored(material.Offering);

        internal PreKeyV1ClaimCapability Claim(Material material, byte operationSeed, ushort lastResortCounter = 0)
        {
            var hash = MessagingWireCryptographicInputs.ComputeExactDpk2Hash(material.Record);
            try
            {
                return PreKeyV1ClaimCapability.CreateForTests(
                    material.Record.MlKemKind, lastResortCounter,
                    Bytes(32, operationSeed), Bytes(32, operationSeed + 1), hash,
                    Bytes(32, operationSeed + 2), Bytes(32, operationSeed + 3),
                    material.Record.OneTimeX25519PrekeyId.Span,
                    material.Record.MlKemPrekeyId.Span);
            }
            finally { CryptographicOperations.ZeroMemory(hash); }
        }

        public void Dispose()
        {
            authoring.Dispose();
            CryptographicOperations.ZeroMemory(Key);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class Material(
        AuthoredDpk2Offering offering,
        Dpk2Record record,
        byte[] exactDpk2) : IDisposable
    {
        internal AuthoredDpk2Offering Offering { get; } = offering;
        internal Dpk2Record Record { get; } = record;
        internal byte[] ExactDpk2 { get; } = exactDpk2;

        public void Dispose()
        {
            Offering.Dispose();
            CryptographicOperations.ZeroMemory(ExactDpk2);
        }
    }

    private static byte[] Bytes(int length, int seed)
    {
        var result = new byte[length];
        for (var index = 0; index < result.Length; index++)
            result[index] = unchecked((byte)(seed + index * 17 + 1));
        return result;
    }
}
