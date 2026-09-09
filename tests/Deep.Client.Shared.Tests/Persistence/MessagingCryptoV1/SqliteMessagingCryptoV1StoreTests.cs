using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.MessagingCryptoV1;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Tests.Persistence.MessagingCryptoV1;

public sealed class SqliteMessagingCryptoV1StoreTests
{
    [Fact]
    public async Task ExactTransitionAndReplaySurviveRestartWithoutReleasingRawState()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x31);
        var next = Trs1(fixture.Scope, 2, 0x32);
        var later = Trs1(fixture.Scope, 3, 0x33);
        byte[] genesisHead;

        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var initialization = Initialization(0x11, initial);
            var initialized = await store.CommitInitialSessionAsync(initialization);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized, initialized.Disposition);
            Assert.True(initialization.IsClearedForTesting);
            genesisHead = initialized.JournalHead.ToArray();

            using var transition = Transition(0x21, 0x41, 0x51, genesisHead, initial, next);
            var committed = await store.CommitAsync(transition);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Committed, committed.Disposition);
            Assert.Equal(2UL, committed.StateGeneration);
            Assert.Equal(1UL, committed.JournalGeneration);
            Assert.True(transition.IsClearedForTesting);
        }

        await using (var reopened = fixture.Open(allowCreate: false))
        {
            var head = Assert.IsType<MessagingCryptoV1HeadSnapshot>(await reopened.ReadHeadAsync());
            Assert.Equal(2UL, head.StateGeneration);
            Assert.Equal(1UL, head.JournalGeneration);
            Assert.False(head.ForkLatched);
            Assert.False(head.TerminallyLatched);

            using var lease = await reopened.AcquireSendPreparationLeaseAsync();
            using var preparation = lease.CaptureForTesting();
            Assert.Equal(SHA256.HashData(next), preparation.ExactTrs1Hash);
            Assert.Equal(head.StateGeneration, preparation.ExpectedStateGeneration);
            Assert.True(head.StateCommitment.Span.SequenceEqual(preparation.ExpectedStateCommitment));
            Assert.Equal(head.JournalGeneration, preparation.ExpectedJournalGeneration);
            Assert.True(head.JournalHead.Span.SequenceEqual(preparation.JournalPredecessor));

            using var laterTransition = Transition(0x22, 0x42, 0x52,
                head.JournalHead.Span, next, later);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Committed,
                (await reopened.CommitAsync(laterTransition)).Disposition);

            using var replay = Transition(0x21, 0x41, 0x51, genesisHead, initial, next);
            var result = await reopened.CommitAsync(replay);
            Assert.Equal(MessagingCryptoV1CommitDisposition.ExactReplay, result.Disposition);
            Assert.Equal(2UL, result.StateGeneration);
            Assert.Equal(1UL, result.JournalGeneration);
            Assert.Equal(3UL, (await reopened.ReadHeadAsync())!.StateGeneration);
        }
    }

    [Fact]
    public async Task CrossInstanceStaleTransitionFailsCasWithoutForking()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 4, 0x14);
        var winner = Trs1(fixture.Scope, 5, 0x15);
        var stale = Trs1(fixture.Scope, 5, 0x16);
        await using var first = fixture.Open();
        await ProvisionInitialPreKeys(first);
        using var initialization = Initialization(0x10, initial);
        var initialized = await first.CommitInitialSessionAsync(initialization);
        await using var second = fixture.Open(allowCreate: false);

        using var winnerTransition = Transition(0x20, 0x30, 0x40,
            initialized.JournalHead.Span, initial, winner);
        Assert.Equal(MessagingCryptoV1CommitDisposition.Committed,
            (await first.CommitAsync(winnerTransition)).Disposition);

        using var staleTransition = Transition(0x21, 0x31, 0x41,
            initialized.JournalHead.Span, initial, stale);
        var staleResult = await second.CommitAsync(staleTransition);
        Assert.Equal(MessagingCryptoV1CommitDisposition.CasConflict, staleResult.Disposition);
        Assert.False(staleResult.ForkLatched);
        Assert.Equal(5UL, staleResult.StateGeneration);
    }

    [Fact]
    public async Task ChangedBytesForOneReplayTokenDurablyLatchFork()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x61);
        var next = Trs1(fixture.Scope, 2, 0x62);
        var changed = Trs1(fixture.Scope, 2, 0x63);
        byte[] genesisHead;

        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var initialization = Initialization(0x12, initial);
            genesisHead = (await store.CommitInitialSessionAsync(initialization)).JournalHead.ToArray();
            using var accepted = Transition(0x22, 0x42, 0x52, genesisHead, initial, next);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Committed,
                (await store.CommitAsync(accepted)).Disposition);

            using var conflicting = Transition(0x23, 0x42, 0x53, genesisHead, initial, changed);
            var fork = await store.CommitAsync(conflicting);
            Assert.Equal(MessagingCryptoV1CommitDisposition.ForkLatched, fork.Disposition);
            Assert.True(fork.ForkLatched);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.AcquireSendPreparationLeaseAsync());
        }

        await using var reopened = fixture.Open(allowCreate: false);
        var head = Assert.IsType<MessagingCryptoV1HeadSnapshot>(await reopened.ReadHeadAsync());
        Assert.True(head.ForkLatched);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await reopened.AcquireSendPreparationLeaseAsync());
        using var later = Transition(0x24, 0x44, 0x54, head.JournalHead.Span,
            next, Trs1(fixture.Scope, 3, 0x64));
        Assert.Equal(MessagingCryptoV1CommitDisposition.AlreadyForkLatched,
            (await reopened.CommitAsync(later)).Disposition);
    }

    [Fact]
    public async Task ProtocolRollbackLatchIsDurableAndNeverReleasesState()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x65);
        var terminal = Trs1(fixture.Scope, 2, 0x66, terminal: true);
        byte[] terminalCommitment;
        var facts = MessagingCryptoV1Trs1.Validate(terminal, fixture.Scope);
        try { terminalCommitment = facts.StateCommitment.ToArray(); }
        finally
        {
            CryptographicOperations.ZeroMemory(facts.StateCommitment);
            CryptographicOperations.ZeroMemory(facts.ExactHash);
        }

        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var initialization = Initialization(0x14, initial);
            var initialized = await store.CommitInitialSessionAsync(initialization);
            using var transition = MessagingCryptoV1PreparedTransition.CreateForTests(
                MessagingCryptoV1Direction.RollbackLatch,
                Bytes(0x26), Bytes(0x46), Bytes(0x56), initialized.JournalHead.Span,
                initial, terminal, Bytes(0x85), Bytes(0x86), Bytes(0x87),
                terminalStateCommitment: terminalCommitment);
            var result = await store.CommitAsync(transition);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Committed, result.Disposition);
            Assert.True(result.TerminallyLatched);
            Assert.False(result.ForkLatched);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.AcquireSendPreparationLeaseAsync());
        }

        await using var reopened = fixture.Open(allowCreate: false);
        var head = Assert.IsType<MessagingCryptoV1HeadSnapshot>(await reopened.ReadHeadAsync());
        Assert.True(head.TerminallyLatched);
        Assert.False(head.ForkLatched);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await reopened.AcquireSendPreparationLeaseAsync());
        CryptographicOperations.ZeroMemory(terminalCommitment);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(4, false)]
    [InlineData(5, true)]
    public async Task RestartAtEveryCommitFailpointIsPriorOrExactNext(
        int failpointValue,
        bool committedBeforeCrash)
    {
        var failpoint = (MessagingCryptoV1StoreFailpoint)failpointValue;
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 8, 0x71);
        var next = Trs1(fixture.Scope, 9, 0x72);
        byte[] genesisHead;
        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var initialization = Initialization(0x13, initial);
            genesisHead = (await store.CommitInitialSessionAsync(initialization)).JournalHead.ToArray();
            using var transition = Transition(0x25, 0x45, 0x55, genesisHead, initial, next);
            using (MessagingCryptoV1StoreTestHooks.Push(point =>
                       { if (point == failpoint) throw new MessagingCryptoV1InjectedCrashException(point); }))
            {
                var failure = await Assert.ThrowsAsync<MessagingCryptoV1InjectedCrashException>(async () =>
                    await store.CommitAsync(transition));
                Assert.Equal(failpoint, failure.Point);
            }
        }

        await using var restarted = fixture.Open(allowCreate: false);
        var head = Assert.IsType<MessagingCryptoV1HeadSnapshot>(await restarted.ReadHeadAsync());
        Assert.Equal(committedBeforeCrash ? 9UL : 8UL, head.StateGeneration);
        Assert.Equal(committedBeforeCrash ? 1UL : 0UL, head.JournalGeneration);
        using var retry = Transition(0x25, 0x45, 0x55, genesisHead, initial, next);
        var retryResult = await restarted.CommitAsync(retry);
        Assert.Equal(committedBeforeCrash
                ? MessagingCryptoV1CommitDisposition.ExactReplay
                : MessagingCryptoV1CommitDisposition.Committed,
            retryResult.Disposition);
        Assert.Equal(9UL, retryResult.StateGeneration);
    }

    [Fact]
    public async Task WrongKeyScopeMismatchAndAuthenticatedCorruptionFailClosed()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x21);
        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var initialization = Initialization(0x18, initial);
            await store.CommitInitialSessionAsync(initialization);
        }

        var wrongKey = Enumerable.Repeat((byte)0xEE, 32).ToArray();
        using (var options = new MessagingCryptoV1StoreOptions(fixture.Path, wrongKey, fixture.Scope, false))
        {
            var failure = Assert.Throws<MessagingCryptoV1StoreOpenException>(() =>
                new SqliteMessagingCryptoV1Store(options));
            Assert.Equal(MessagingCryptoV1StoreOpenFailure.UnreadableOrWrongKey, failure.Reason);
        }

        var otherScope = new MessagingCryptoV1StoreScope(
            Bytes(0xA1), 1, Bytes(0xB1), 1, Bytes(0xC2), Bytes(0xD1), 1);
        using (var options = new MessagingCryptoV1StoreOptions(fixture.Path, fixture.Key, otherScope, false))
        {
            var failure = Assert.Throws<MessagingCryptoV1StoreOpenException>(() =>
                new SqliteMessagingCryptoV1Store(options));
            Assert.Equal(MessagingCryptoV1StoreOpenFailure.ScopeMismatch, failure.Reason);
        }

        TamperStateHash(fixture.Path, fixture.Key);
        using (var options = new MessagingCryptoV1StoreOptions(fixture.Path, fixture.Key, fixture.Scope, false))
        {
            var failure = Assert.Throws<MessagingCryptoV1StoreOpenException>(() =>
                new SqliteMessagingCryptoV1Store(options));
            Assert.Equal(MessagingCryptoV1StoreOpenFailure.Corrupt, failure.Reason);
        }
    }

    [Fact]
    public async Task InitialSessionConsumesBothPreKeysAndLostCallbackIsExactReplayAfterRestart()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x2A);
        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            Assert.Equal(2, await store.ReadInitialPreKeyCountForTestsAsync());
            using var handoff = Initialization(0x31, initial);
            Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
                (await store.CommitInitialSessionAsync(handoff)).Disposition);
            Assert.Equal(0, await store.ReadInitialPreKeyCountForTestsAsync());
            Assert.True(handoff.IsClearedForTesting);
        }

        await using var restarted = fixture.Open(allowCreate: false);
        using var replay = Initialization(0x31, initial);
        Assert.Equal(MessagingCryptoV1CommitDisposition.ExactReplay,
            (await restarted.CommitInitialSessionAsync(replay)).Disposition);
        Assert.Equal(0, await restarted.ReadInitialPreKeyCountForTestsAsync());
    }

    [Fact]
    public async Task MissingMandatoryPreKeyFailsClosedWithoutCreatingState()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x2B);
        await using var store = fixture.Open();
        using (var handoff = Initialization(0x32, initial))
        {
            var result = await store.CommitInitialSessionAsync(handoff);
            Assert.Equal(MessagingCryptoV1CommitDisposition.PreKeyUnavailable, result.Disposition);
        }
        Assert.Null(await store.ReadHeadAsync());

        await ProvisionInitialPreKeys(store);
        using var retry = Initialization(0x32, initial);
        Assert.Equal(MessagingCryptoV1CommitDisposition.Initialized,
            (await store.CommitInitialSessionAsync(retry)).Disposition);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task ChangedClaimBytesOrConsumedPreKeyReuseDurablyLatchFork(int conflictKind)
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x2C);
        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var accepted = Initialization(0x33, initial);
            await store.CommitInitialSessionAsync(accepted);

            using var conflicting = conflictKind switch
            {
                1 => Initialization(0x33, initial, xpc1: 0xB5),
                2 => Initialization(0x33, initial, dph2: 0xB6),
                3 => Initialization(0x33, Trs1(fixture.Scope, 1, 0x2D)),
                4 => Initialization(0x34, Trs1(fixture.Scope, 1, 0x2D), x25519: 0xE1, mlKem: 0xE3),
                5 => Initialization(0x34, Trs1(fixture.Scope, 1, 0x2D), x25519: 0xE3, mlKem: 0xE2),
                _ => throw new ArgumentOutOfRangeException(nameof(conflictKind)),
            };
            var result = await store.CommitInitialSessionAsync(conflicting);
            Assert.Equal(MessagingCryptoV1CommitDisposition.ForkLatched, result.Disposition);
            Assert.True(result.ForkLatched);
        }

        await using var restarted = fixture.Open(allowCreate: false);
        Assert.True((await restarted.ReadHeadAsync())!.ForkLatched);
        using var exactOriginal = Initialization(0x33, initial);
        Assert.Equal(MessagingCryptoV1CommitDisposition.AlreadyForkLatched,
            (await restarted.CommitInitialSessionAsync(exactOriginal)).Disposition);
    }

    [Theory]
    [InlineData(6, false)]
    [InlineData(7, false)]
    [InlineData(8, false)]
    [InlineData(9, false)]
    [InlineData(10, true)]
    public async Task InitialSessionCrashIsPriorOrExactCommittedState(int pointValue, bool committed)
    {
        var point = (MessagingCryptoV1StoreFailpoint)pointValue;
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x2E);
        await using (var store = fixture.Open())
        {
            await ProvisionInitialPreKeys(store);
            using var handoff = Initialization(0x35, initial);
            using (MessagingCryptoV1StoreTestHooks.Push(hit =>
                       { if (hit == point) throw new MessagingCryptoV1InjectedCrashException(hit); }))
                await Assert.ThrowsAsync<MessagingCryptoV1InjectedCrashException>(async () =>
                    await store.CommitInitialSessionAsync(handoff));
        }

        await using var restarted = fixture.Open(allowCreate: false);
        Assert.Equal(committed, await restarted.ReadHeadAsync() is not null);
        Assert.Equal(committed ? 0 : 2, await restarted.ReadInitialPreKeyCountForTestsAsync());
        using var retry = Initialization(0x35, initial);
        Assert.Equal(committed ? MessagingCryptoV1CommitDisposition.ExactReplay : MessagingCryptoV1CommitDisposition.Initialized,
            (await restarted.CommitInitialSessionAsync(retry)).Disposition);
    }

    [Fact]
    public async Task ConcurrentExactInitialHandoffsCommitOnceAndReplayOnce()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x2F);
        await using var firstStore = fixture.Open();
        await ProvisionInitialPreKeys(firstStore);
        await using var secondStore = fixture.Open(allowCreate: false);
        using var first = Initialization(0x36, initial);
        using var second = Initialization(0x36, initial);
        var results = await Task.WhenAll(
            firstStore.CommitInitialSessionAsync(first).AsTask(),
            secondStore.CommitInitialSessionAsync(second).AsTask());
        Assert.Equal(1, results.Count(result => result.Disposition == MessagingCryptoV1CommitDisposition.Initialized));
        Assert.Equal(1, results.Count(result => result.Disposition == MessagingCryptoV1CommitDisposition.ExactReplay));
        Assert.Equal(0, await firstStore.ReadInitialPreKeyCountForTestsAsync());
    }

    [Fact]
    public async Task BoundsEncryptionAndManagedSecretZeroizationAreEnforced()
    {
        using var fixture = new StoreFixture();
        var initial = Trs1(fixture.Scope, 1, 0x28);
        var options = new MessagingCryptoV1StoreOptions(fixture.Path, fixture.Key, fixture.Scope);
        await using var store = new SqliteMessagingCryptoV1Store(options);
        options.Dispose();
        Assert.True(options.IsKeyZeroedForTesting);
        await ProvisionInitialPreKeys(store);
        using (var initialization = Initialization(0x19, initial))
            await store.CommitInitialSessionAsync(initialization);

        Span<byte> first16 = stackalloc byte[16];
        using (var stream = new FileStream(fixture.Path, FileMode.Open, FileAccess.Read,
                   FileShare.ReadWrite | FileShare.Delete))
            Assert.Equal(first16.Length, stream.Read(first16));
        Assert.False(first16.SequenceEqual("SQLite format 3\0"u8));

        var oversized = new byte[MessagingCryptoV1Limits.MaximumTrs1Bytes + 1];
        "TRS1"u8.CopyTo(oversized);
        oversized[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(oversized.AsSpan(5), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(oversized.AsSpan(8), checked((uint)oversized.Length));
        Assert.Throws<ArgumentOutOfRangeException>(() => Initialization(0x1A, oversized));
        CryptographicOperations.ZeroMemory(oversized);

        var malformed = Trs1(fixture.Scope, 2, 0x29);
        malformed[^1] ^= 0x01;
        using var invalid = Initialization(0x1B, malformed);
        await Assert.ThrowsAsync<FormatException>(async () => await store.CommitInitialSessionAsync(invalid));
        Assert.True(invalid.IsClearedForTesting);
        CryptographicOperations.ZeroMemory(malformed);

        await store.DisposeAsync();
        Assert.True(store.IsKeyZeroedForTesting);
        Assert.Contains(typeof(Deep.Protocol.MessagingCrypto.IExactDpe2DurableTransactionAuthority),
            typeof(ExactDpe2SqliteDurableTransactionAuthority).GetInterfaces());
    }

    private static MessagingCryptoV1InitialSessionHandoff Initialization(
        byte seed,
        byte[] state,
        byte xpc1 = 0xA5,
        byte dph2 = 0xA6,
        byte x25519 = 0xE1,
        byte mlKem = 0xE2) =>
        MessagingCryptoV1InitialSessionHandoff.CreateForTests(
            Bytes(seed), Bytes(xpc1), Bytes(dph2), Bytes(x25519), Bytes(mlKem), state);

    private static ValueTask ProvisionInitialPreKeys(
        SqliteMessagingCryptoV1Store store,
        byte x25519 = 0xE1,
        byte mlKem = 0xE2) => store.ProvisionOpaqueInitialPreKeysForTestsAsync(
            Bytes(x25519), Bytes(0xF1), Bytes(mlKem), Bytes(0xF2));

    private static MessagingCryptoV1PreparedTransition Transition(
        byte operation,
        byte replay,
        byte envelope,
        ReadOnlySpan<byte> journalHead,
        byte[] prior,
        byte[] next) => MessagingCryptoV1PreparedTransition.CreateForTests(
            MessagingCryptoV1Direction.Send,
            Bytes(operation), Bytes(replay), Bytes(envelope), journalHead,
            prior, next, Bytes(0x81), Bytes(0x82), Bytes(0x83), Bytes(0x84));

    private static byte[] Trs1(
        MessagingCryptoV1StoreScope scope,
        ulong generation,
        byte seed,
        bool terminal = false)
    {
        var componentLength = terminal ? 0 : 1;
        var result = new byte[600 + componentLength];
        "TRS1"u8.CopyTo(result);
        result[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(5), 0x0201);
        result[7] = terminal ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), checked((uint)result.Length));
        scope.SessionId.CopyTo(result.AsSpan(12, 32));
        Fill(result.AsSpan(44, 64), seed);
        scope.LocalDeviceId.CopyTo(result.AsSpan(108, 32));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(140), scope.DeviceGeneration);
        Fill(result.AsSpan(148, 32), unchecked((byte)(seed + 1)));
        Fill(result.AsSpan(180, 32), unchecked((byte)(seed + 2)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(212), 1);
        Fill(result.AsSpan(220, 32), unchecked((byte)(seed + 3)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(252), generation);
        Fill(result.AsSpan(260, 32), unchecked((byte)(seed + 4)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(292), 1);
        Fill(result.AsSpan(300, 32), unchecked((byte)(seed + 5)));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(332), 1);
        Fill(result.AsSpan(348, 32), unchecked((byte)(seed + 6)));
        Fill(result.AsSpan(404, 32), unchecked((byte)(seed + 7)));
        Fill(result.AsSpan(460, 32), unchecked((byte)(seed + 8)));
        Fill(result.AsSpan(492, 32), unchecked((byte)(seed + 9)));
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(524), 100);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(528), checked((uint)componentLength));
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(532), 0);
        if (!terminal) result[536] = unchecked((byte)(seed + 10));
        var commitmentOffset = 536 + componentLength;
        Fill(result.AsSpan(commitmentOffset, 32), unchecked((byte)(seed + 11)));
        var checksum = MessagingCryptoV1Trs1.Sha256Domain(
            "Deep/LocalState/V1/triple-ratchet-state-checksum",
            result.AsSpan(0, result.Length - 32));
        checksum.CopyTo(result, result.Length - 32);
        CryptographicOperations.ZeroMemory(checksum);
        return result;
    }

    private static void TamperStateHash(string path, byte[] key)
    {
        SQLitePCL.Batteries_V2.Init();
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        Assert.Equal(SQLitePCL.raw.SQLITE_OK, SQLitePCL.raw.sqlite3_key(connection.Handle, key));
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE ratchet_state SET state_hash=$hash WHERE singleton=1;";
        command.Parameters.AddWithValue("$hash", Bytes(0xFE));
        Assert.Equal(1, command.ExecuteNonQuery());
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private static void Fill(Span<byte> destination, byte value) => destination.Fill(value == 0 ? (byte)1 : value);

    private sealed class StoreFixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "deep-messaging-crypto-v1", Guid.NewGuid().ToString("N"));

        internal StoreFixture()
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
