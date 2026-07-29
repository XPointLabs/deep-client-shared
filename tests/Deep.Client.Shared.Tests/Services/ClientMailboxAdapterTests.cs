using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Tests.Services;

public sealed class ClientMailboxAdapterTests
{
    private const string DatabaseKey =
        "p10b4-test-mailbox-state-key-0123456789abcdef";

    [Fact]
    public void ActivationAndScope_AreFailClosedDomainSeparatedAndRedacted()
    {
        Assert.False(ClientFeatureFlags.Defaults.ClientMailboxAdapterEnabled);
        Assert.False(ClientFeatureFlags.ReleaseDefaults.ClientMailboxAdapterEnabled);
        var issuer = Range(0x20, 32);
        var mailbox = new BlindedMailboxId(Range(0x60, 32));
        var first = ClientMailboxScope.Derive(issuer, mailbox, epoch: 7);
        var second = ClientMailboxScope.Derive(
            Range(0x21, 32),
            mailbox,
            epoch: 7);
        var nextEpoch = ClientMailboxScope.Derive(issuer, mailbox, epoch: 8);

        Assert.NotEqual(first.ToArray(), second.ToArray());
        Assert.NotEqual(first.ToArray(), nextEpoch.ToArray());
        Assert.Null(typeof(ClientMailboxScope).GetMethod(
            "FromBytes",
            System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.Static));
        var activation = new ClientMailboxActivation(
            enabled: false,
            issuer,
            route: null,
            ingressConfigured: false);
        Assert.DoesNotContain(Convert.ToHexString(issuer), activation.ToString());
    }

    [Fact]
    public void PinnedRoute_RejectsSameKeyDifferentIds_AndForgedTwoOfTwo()
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var seed = Range(0x10, 32);
        Assert.Throws<ArgumentException>(() => new ClientMailboxPinnedRoute(
            new BlindedPlacementId(Range(0xa0, 32)),
            Range(0x80, 32),
            Range(0x20, 32),
            crypto.GetPublicKey(seed),
            Range(0x40, 32),
            crypto.GetPublicKey(seed)));

        var fixture = new ReceiptFixture();
        var forged = fixture.Quorum(secondSignedWithFirstKey: true);
        Assert.Throws<MailboxReceiptException>(() =>
            new PinnedClientMailboxReceiptVerifier(fixture.Crypto)
                .VerifyDurable(forged, fixture.Expectation()));
    }

    [Fact]
    public async Task Store_PersistsAcceptedThenDurable_IsRestartIdempotent()
    {
        var fixture = new ReceiptFixture();
        var ingress = new SequenceIngress(
            new ClientMailboxStoreIngressResult(
                ClientMailboxIngressState.Accepted,
                fixture.AcceptedReceipt()),
            new ClientMailboxStoreIngressResult(
                ClientMailboxIngressState.Durable,
                fixture.Quorum()));
        var outbox = new InMemorySessionStore();
        var state = new InMemoryClientMailboxStateRepository();
        var adapter = fixture.Adapter(ingress, outbox, state);
        var outboxScope = OutboxAccountScope.FromBytes(Range(0x02, 32));

        Assert.Equal(
            ClientMailboxIngressState.Accepted,
            (await adapter.StoreAsync(outboxScope, fixture.StoreRequest())).State);
        Assert.Equal(
            ClientMailboxIngressState.Durable,
            (await adapter.StoreAsync(outboxScope, fixture.StoreRequest())).State);
        var persisted = await outbox.ReadTransportOutboxAsync(
            outboxScope,
            OutboxLogicalId.FromBytes(fixture.OperationId));
        Assert.Equal(TransportOutboxState.Durable, persisted.Item!.State);
        Assert.NotEqual(TransportOutboxState.Delivered, persisted.Item.State);

        var restarted = fixture.Adapter(ingress, outbox, state);
        var idempotent = await restarted.StoreAsync(
            outboxScope,
            fixture.StoreRequest());
        Assert.Equal(42UL, idempotent.Cursor);
        Assert.Equal(2, ingress.StoreCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DurableCommit_CrashBeforeOrAfterCommitNeverAdvancesWithoutInbox(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = Scope(0x11);
        var page = Page(1, 1, hasMore: true, token: Range(0x70, 32));
        try
        {
            foreach (var faultPoint in new[]
                     {
                         ClientMailboxCommitFaultPoint.BeforeCommit,
                         ClientMailboxCommitFaultPoint.AfterCommit
                     })
            {
                var fired = false;
                var repository = CreateFaultingRepository(
                    sqlite,
                    path,
                    point =>
                    {
                        if (!fired && point == faultPoint)
                        {
                            fired = true;
                            throw new IOException("simulated-crash");
                        }
                    });
                try
                {
                    await Assert.ThrowsAsync<IOException>(() =>
                        repository.CommitRetrievePageAsync(
                            scope,
                            new ClientMailboxTraversal(0, []),
                            page));

                    if (faultPoint == ClientMailboxCommitFaultPoint.BeforeCommit)
                    {
                        Assert.Equal(
                            0UL,
                            (await repository.ReadTraversalAsync(scope)).AfterCursor);
                    }
                    else
                    {
                        Assert.Single(
                            await repository.ReadDurableInboxAsync(scope));
                        var recovered = await repository.CommitRetrievePageAsync(
                            scope,
                            new ClientMailboxTraversal(
                                page.NextCursor,
                                page.ContinuationToken.Span),
                            Page(2, 0, hasMore: false, token: []));
                        Assert.Empty(recovered.DurableInbox);
                        Assert.Single(
                            await repository.ReadDurableInboxAsync(scope));
                        Assert.Equal(0UL, recovered.Traversal.AfterCursor);
                    }
                }
                finally
                {
                    (repository as IDisposable)?.Dispose();
                }

                if (sqlite)
                {
                    DeleteSqliteFiles(path);
                }
            }
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MultiPageContinuation_PersistsAcrossRestart_FinalResetsCycle(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = Scope(0x12);
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            var firstPage = Page(1, 1, hasMore: true, token: Range(0x30, 32));
            var first = await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                firstPage);
            Assert.Single(first.DurableInbox);
            Assert.Equal(1UL, first.Traversal.AfterCursor);
            Assert.Equal(
                firstPage.ContinuationToken.ToArray(),
                first.Traversal.GetContinuationTokenCopy());

            repository = Restart(repository, sqlite, path, scope);
            var resumed = await repository.ReadTraversalAsync(scope);
            Assert.Equal(firstPage.ContinuationToken.ToArray(),
                resumed.GetContinuationTokenCopy());
            var final = await repository.CommitRetrievePageAsync(
                scope,
                resumed,
                Page(2, 1, hasMore: false, token: []));
            Assert.Equal(0UL, final.Traversal.AfterCursor);
            Assert.Empty(final.Traversal.GetContinuationTokenCopy());
            Assert.Single(final.DurableInbox);

            repository = Restart(repository, sqlite, path, scope);
            var newCycle = await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                Page(1, 2, hasMore: false, token: []));
            Assert.Equal(2, newCycle.DurableInbox.Count);
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CapacityFailure_UsesCloneValidateSwapAndPreservesTraversal(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = Scope(0x13);
        var repository = CreateRepository(sqlite, path);
        try
        {
            var first = Page(1, 100, true, Range(0x40, 32));
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                first);
            var second = Page(101, 100, true, Range(0x50, 32));
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(100, first.ContinuationToken.Span),
                second);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                repository.CommitRetrievePageAsync(
                    scope,
                    new ClientMailboxTraversal(200, second.ContinuationToken.Span),
                    Page(201, 1, false, [])));
            var unchanged = await repository.ReadTraversalAsync(scope);
            Assert.Equal(200UL, unchanged.AfterCursor);
            Assert.Equal(
                second.ContinuationToken.ToArray(),
                unchanged.GetContinuationTokenCopy());
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task Adapter_RequiresPersistedContinuationAndAllowsNewCycleAfterFinal()
    {
        var fixture = new ReceiptFixture();
        var first = fixture.RetrievePage(
            operationByte: 0x70,
            cursor: 42,
            hasMore: true,
            token: Range(0x44, 32));
        var final = fixture.RetrievePage(
            operationByte: 0x71,
            cursor: 43,
            hasMore: false,
            token: []);
        var ingress = new RetrieveSequenceIngress(first, final);
        var adapter = fixture.Adapter(
            ingress,
            new InMemorySessionStore(),
            new InMemoryClientMailboxStateRepository());

        var firstResult = await adapter.RetrieveAsync(
            fixture.RetrieveRequest(
                0x70,
                afterCursor: 0,
                token: ReadOnlyMemory<byte>.Empty));
        Assert.Equal(42UL, firstResult.AfterCursor);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            adapter.RetrieveAsync(
                fixture.RetrieveRequest(
                    0x71,
                    afterCursor: 42,
                    token: ReadOnlyMemory<byte>.Empty)));
        Assert.Equal(1, ingress.RetrieveCalls);

        var finalResult = await adapter.RetrieveAsync(
            fixture.RetrieveRequest(
                0x71,
                afterCursor: 42,
                token: firstResult.ContinuationToken));
        Assert.Equal(0UL, finalResult.AfterCursor);
        Assert.Empty(finalResult.ContinuationToken.ToArray());
        Assert.Single(finalResult.NewItems);
        var next = await adapter.ReadTraversalAsync(fixture.MailboxId, epoch: 7);
        Assert.Equal(0UL, next.AfterCursor);
    }

    [Fact]
    public async Task Ack_BindsPersistedEnvelopeExpiryAndIsIdempotent()
    {
        var fixture = new ReceiptFixture();
        var state = new InMemoryClientMailboxStateRepository();
        var page = fixture.RetrievePage(0x70, 42, false, []);
        var scope = fixture.Scope;
        await state.CommitRetrievePageAsync(
            scope,
            new ClientMailboxTraversal(0, []),
            page);
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var ack = fixture.AckRequest(acknowledgement);
        var forgedExpiry = fixture.Mar1(
            ack,
            expiresAt: 1130,
            coordinatorSequence: 84);
        var ingress = new AckSequenceIngress(forgedExpiry, fixture.Mar1(
            ack,
            expiresAt: 1120,
            coordinatorSequence: 84));
        var adapter = fixture.Adapter(ingress, new InMemorySessionStore(), state);

        await Assert.ThrowsAsync<MailboxReceiptException>(() =>
            adapter.AcknowledgeAsync(ack));
        Assert.Equal(
            ClientMailboxAckState.Pending,
            await state.CheckAcknowledgementsAsync(scope, [acknowledgement]));
        var applied = await adapter.AcknowledgeAsync(ack);
        Assert.False(applied.Idempotent);
        var replay = await adapter.AcknowledgeAsync(ack);
        Assert.True(replay.Idempotent);
        Assert.Equal(2, ingress.AckCalls);
    }

    [Fact]
    public async Task NonFinalAck_RequiresExactPersistedPageToken()
    {
        var fixture = new ReceiptFixture();
        var state = new InMemoryClientMailboxStateRepository();
        var token = Range(0x66, 32);
        var page = fixture.RetrievePage(0x70, 42, true, token);
        await state.CommitRetrievePageAsync(
            fixture.Scope,
            new ClientMailboxTraversal(0, []),
            page);
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var canonical = fixture.AckRequest(acknowledgement) with
        {
            IsFinalPage = false,
            ContinuationToken = token
        };
        var ingress = new AckSequenceIngress(fixture.Mar1(
            canonical,
            expiresAt: 1120,
            coordinatorSequence: 85));
        var adapter = fixture.Adapter(ingress, new InMemorySessionStore(), state);
        var wrong = canonical with
        {
            ContinuationToken = Range(0x67, 32)
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            adapter.AcknowledgeAsync(wrong));
        Assert.Equal(0, ingress.AckCalls);

        Assert.False((await adapter.AcknowledgeAsync(canonical)).Idempotent);
        Assert.Equal(1, ingress.AckCalls);
        var traversal = await adapter.ReadTraversalAsync(
            fixture.MailboxId,
            epoch: 7);
        Assert.Equal(token, traversal.GetContinuationTokenCopy());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CoordinatorJournal_IsPersistentBoundToMembershipAndEpoch(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = Scope(0x14);
        var journalScope = ClientMailboxJournalScope.Derive(Range(0x14, 32));
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Applied,
                await Record(
                    repository,
                    journalScope,
                    Range(0x80, 32),
                    Range(0x01, 32)));
            repository = Restart(repository, sqlite, path, scope, journalScope);
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Idempotent,
                await Record(
                    repository,
                    journalScope,
                    Range(0x80, 32),
                    Range(0x01, 32)));
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Equivocation,
                await Record(
                    repository,
                    journalScope,
                    Range(0x80, 32),
                    Range(0x02, 32)));
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Applied,
                await Record(
                    repository,
                    journalScope,
                    Range(0x81, 32),
                    Range(0x02, 32)));
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CoordinatorJournal_IsGlobalAcrossMailboxScopesAndRestart(
        bool sqlite)
    {
        var path = TempDatabase();
        var firstMailbox = Scope(0x21);
        var secondMailbox = Scope(0x31);
        var journalScope = ClientMailboxJournalScope.Derive(Range(0x41, 32));
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            await repository.CommitRetrievePageAsync(
                firstMailbox,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, false, []));
            await repository.CommitRetrievePageAsync(
                secondMailbox,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, false, []));
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Applied,
                await Record(
                    repository,
                    journalScope,
                    Range(0x80, 32),
                    Range(0x01, 32)));

            repository = Restart(
                repository,
                sqlite,
                path,
                firstMailbox,
                journalScope);
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Equivocation,
                await Record(
                    repository,
                    journalScope,
                    Range(0x80, 32),
                    Range(0x02, 32)));
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExpiredReconciliation_IsAtomicAndNeverFabricatesAck(
        bool sqlite)
    {
        foreach (var faultPoint in new[]
                 {
                     ClientMailboxCommitFaultPoint.BeforeCommit,
                     ClientMailboxCommitFaultPoint.AfterCommit
                 })
        {
            var path = TempDatabase();
            var scope = Scope(0x51);
            IClientMailboxStateRepository seed = CreateRepository(sqlite, path);
            try
            {
                await seed.CommitRetrievePageAsync(
                    scope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, false, []));
                var encoded = sqlite
                    ? null
                    : Assert.IsType<InMemoryClientMailboxStateRepository>(seed)
                        .ExportStateForTests(scope);
                (seed as IDisposable)?.Dispose();

                var fired = false;
                var repository = CreateFaultingRepository(
                    sqlite,
                    path,
                    point =>
                    {
                        if (!fired && point == faultPoint)
                        {
                            fired = true;
                            throw new IOException("expiry-crash");
                        }
                    });
                if (!sqlite)
                {
                    Assert.IsType<InMemoryClientMailboxStateRepository>(repository)
                        .ImportStateForTests(scope, encoded!);
                }

                await Assert.ThrowsAsync<IOException>(() =>
                    repository.ReconcileExpiredAsync(scope, 1120));
                var inbox = await repository.ReadDurableInboxAsync(scope);
                var quarantineCount = ExpiredQuarantineCount(repository, scope);
                if (faultPoint == ClientMailboxCommitFaultPoint.BeforeCommit)
                {
                    Assert.Single(inbox);
                    Assert.Equal(0, quarantineCount);
                }
                else
                {
                    Assert.Empty(inbox);
                    Assert.Equal(1, quarantineCount);
                }

                (repository as IDisposable)?.Dispose();
            }
            finally
            {
                (seed as IDisposable)?.Dispose();
                DeleteSqliteFiles(path);
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentExpiryReconciliation_QuarantinesExactlyOnce(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = Scope(0x52);
        var repository = CreateRepository(sqlite, path);
        try
        {
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, false, []));
            var results = await Task.WhenAll(
                repository.ReconcileExpiredAsync(scope, 1120),
                repository.ReconcileExpiredAsync(scope, 1120));

            Assert.Equal(
                1,
                results.Sum(static result =>
                    result.QuarantinedUnacknowledged));
            Assert.All(results, static result =>
                Assert.Equal(0, result.RemovedAcknowledged));
            Assert.Empty(await repository.ReadDurableInboxAsync(scope));
            Assert.Equal(1, ExpiredQuarantineCount(repository, scope));
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RemoteAckThenCrash_ExpiresToQuarantineWithoutDeliveredState(
        bool sqlite)
    {
        var path = TempDatabase();
        var fixture = new ReceiptFixture();
        IClientMailboxStateRepository seed = CreateRepository(sqlite, path);
        try
        {
            var page = fixture.RetrievePage(0x70, 42, false, []);
            await seed.CommitRetrievePageAsync(
                fixture.Scope,
                new ClientMailboxTraversal(0, []),
                page);
            var encoded = sqlite
                ? null
                : Assert.IsType<InMemoryClientMailboxStateRepository>(seed)
                    .ExportStateForTests(fixture.Scope);
            (seed as IDisposable)?.Dispose();

            var fired = false;
            var repository = CreateFaultingRepository(
                sqlite,
                path,
                point =>
                {
                    if (!fired &&
                        point == ClientMailboxCommitFaultPoint.BeforeCommit)
                    {
                        fired = true;
                        throw new IOException("post-remote-ack-crash");
                    }
                });
            if (!sqlite)
            {
                Assert.IsType<InMemoryClientMailboxStateRepository>(repository)
                    .ImportStateForTests(fixture.Scope, encoded!);
            }

            var acknowledgement = page.Items[0].ToAcknowledgement();
            var ingress = new AckSequenceIngress(fixture.Mar1(
                fixture.AckRequest(acknowledgement),
                expiresAt: 1120,
                coordinatorSequence: 85));
            var time = new MutableTimeProvider(1050);
            var adapter = fixture.Adapter(
                ingress,
                new InMemorySessionStore(),
                repository,
                time);
            await Assert.ThrowsAsync<IOException>(() =>
                adapter.AcknowledgeAsync(fixture.AckRequest(acknowledgement)));
            Assert.Equal(1, ingress.AckCalls);

            time.SetUnixSeconds(1120);
            Assert.Empty(await adapter.ReadDurableInboxAsync(
                fixture.MailboxId,
                epoch: 7));
            Assert.Equal(1, ExpiredQuarantineCount(repository, fixture.Scope));
            Assert.Equal(1, ingress.AckCalls);
            (repository as IDisposable)?.Dispose();
        }
        finally
        {
            (seed as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task Cms2Migration_IsBackedUpAtomicAndIdempotent()
    {
        var path = TempDatabase();
        var scope = Scope(0x61);
        var memory = new InMemoryClientMailboxStateRepository();
        await memory.CommitRetrievePageAsync(
            scope,
            new ClientMailboxTraversal(0, []),
            Page(1, 1, true, Range(0x71, 32)));
        var legacyState = ClientMailboxStateCodec.Decode(
            memory.ExportStateForTests(scope));
        legacyState.CoordinatorStatements.Add(
            new ClientMailboxCoordinatorStatement
            {
                MembershipCommitment = Range(0x80, 32),
                Epoch = 7,
                CoordinatorId = Range(0x30, 32),
                CoordinatorSequence = 9,
                StatementDigest = Range(0x01, 32),
                ExpiresAtUnixSeconds = 1120
            });
        var cms2 = ClientMailboxStateCodec.Encode(legacyState);
        var journalScope = ClientMailboxJournalScope.Derive(Range(0x61, 32));
        try
        {
            using (var seed = CreateSqlite(path))
            {
                seed.InsertRawStateForTests(scope, cms2);
            }

            Assert.Throws<IOException>(() =>
            {
                using var interrupted = new SqliteClientMailboxStateRepository(
                    Options(path),
                    point =>
                    {
                        if (point ==
                            ClientMailboxMigrationFaultPoint.AfterBackupBeforeRewrite)
                        {
                            throw new IOException("cms2-migration-interrupted");
                        }
                    });
            });

            using (var migrated = CreateSqlite(path))
            {
                Assert.Equal(1, migrated.BackupCountForTests());
                Assert.Equal(0, migrated.LegacyStateCountForTests());
                Assert.Equal(1, migrated.NormalizedInboxCountForTests(scope));
                Assert.Single(await migrated.ReadDurableInboxAsync(scope));
                Assert.Equal(
                    Range(0x71, 32),
                    (await migrated.ReadTraversalAsync(scope))
                    .GetContinuationTokenCopy());
                Assert.Equal(
                    ClientMailboxCoordinatorRecordResult.Equivocation,
                    await Record(
                        migrated,
                        journalScope,
                        Range(0x80, 32),
                        Range(0x02, 32)));
            }

            using var reopened = CreateSqlite(path);
            Assert.Equal(1, reopened.BackupCountForTests());
            Assert.Equal(0, reopened.LegacyStateCountForTests());
            Assert.Equal(1, reopened.NormalizedInboxCountForTests(scope));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task Cms2Decoder_NormalizesLengthAndEnvelopeMutations()
    {
        var truncatedToken = new byte[32];
        "CMS2"u8.CopyTo(truncatedToken);
        BinaryPrimitives.WriteUInt16BigEndian(
            truncatedToken.AsSpan(12, 2),
            1);
        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxStateCodec.Decode(truncatedToken));

        var scope = Scope(0x71);
        var memory = new InMemoryClientMailboxStateRepository();
        await memory.CommitRetrievePageAsync(
            scope,
            new ClientMailboxTraversal(0, []),
            Page(1, 1, false, []));
        var corruptEnvelope = memory.ExportStateForTests(scope);
        corruptEnvelope[32 + 64] ^= 0xff;
        Assert.Throws<InvalidDataException>(() =>
            ClientMailboxStateCodec.Decode(corruptEnvelope));
    }

    [Fact]
    public void Sqlite_RequiresSqlCipherKeyPath()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new SqliteClientMailboxStateRepository(
                new SqliteSessionStoreOptions(TempDatabase())));
    }

    [Fact]
    public async Task Sqlite_StateIsEncryptedAndContainsNoRawIdentifiers()
    {
        var path = TempDatabase();
        var issuer = Range(0x22, 32);
        var mailbox = new BlindedMailboxId(Range(0x55, 32));
        var scope = ClientMailboxScope.Derive(issuer, mailbox, epoch: 7);
        try
        {
            using (var repository = CreateSqlite(path))
            {
                await repository.CommitRetrievePageAsync(
                    scope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, false, []));
                Assert.Equal(0, repository.LegacyStateCountForTests());
                Assert.Equal(1, repository.NormalizedInboxCountForTests(scope));
            }

            var bytes = await File.ReadAllBytesAsync(path);
            Assert.False(bytes.AsSpan(0, 16).SequenceEqual("SQLite format 3\0"u8));
            Assert.False(Contains(bytes, issuer));
            Assert.False(Contains(bytes, mailbox.Bytes.Span));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task Cms1Migration_BackupInterruptionAndCorruptionAreFailClosed()
    {
        var path = TempDatabase();
        var scope = Scope(0x15);
        var options = Options(path);
        try
        {
            using (var seed = new SqliteClientMailboxStateRepository(options))
            {
                seed.InsertRawStateForTests(scope, Cms1(cursor: 7, count: 1));
            }

            Assert.Throws<IOException>(() =>
            {
                using var interrupted = new SqliteClientMailboxStateRepository(
                    options,
                    point =>
                    {
                        if (point ==
                            ClientMailboxMigrationFaultPoint.AfterBackupBeforeRewrite)
                        {
                            throw new IOException("migration-interrupted");
                        }
                    });
            });

            using (var migrated = new SqliteClientMailboxStateRepository(options))
            {
                Assert.Equal(1, migrated.BackupCountForTests());
                Assert.Equal(
                    0UL,
                    (await migrated.ReadTraversalAsync(scope)).AfterCursor);
                migrated.InsertRawStateForTests(scope, "CORRUPT"u8);
            }

            Assert.Throws<InvalidDataException>(() =>
            {
                using var corrupt =
                    new SqliteClientMailboxStateRepository(options);
            });
            using var recovered = new SqliteClientMailboxStateRepository(options);
            Assert.Equal(1, recovered.QuarantineCountForTests());
            Assert.Equal(
                0UL,
                (await recovered.ReadTraversalAsync(scope)).AfterCursor);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    private static async Task<ClientMailboxCoordinatorRecordResult> Record(
        IClientMailboxStateRepository repository,
        ClientMailboxJournalScope scope,
        byte[] membership,
        byte[] digest) =>
        await repository.RecordCoordinatorStatementAsync(
            scope,
            membership,
            epoch: 7,
            coordinatorId: Range(0x30, 32),
            coordinatorSequence: 9,
            statementDigest: digest,
            expiresAtUnixSeconds: 1120,
            nowUnixSeconds: 1050);

    private static IClientMailboxStateRepository Restart(
        IClientMailboxStateRepository repository,
        bool sqlite,
        string path,
        ClientMailboxScope scope,
        ClientMailboxJournalScope? journalScope = null)
    {
        if (sqlite)
        {
            (repository as IDisposable)?.Dispose();
            return CreateSqlite(path);
        }

        var memory = Assert.IsType<InMemoryClientMailboxStateRepository>(repository);
        var encoded = memory.ExportStateForTests(scope);
        var journal = journalScope is null
            ? null
            : memory.ExportJournalForTests(journalScope);
        var restarted = new InMemoryClientMailboxStateRepository();
        restarted.ImportStateForTests(scope, encoded);
        if (journalScope is not null && journal is not null)
        {
            restarted.ImportJournalForTests(journalScope, journal);
        }

        return restarted;
    }

    private static IClientMailboxStateRepository CreateRepository(
        bool sqlite,
        string path) =>
        sqlite ? CreateSqlite(path) : new InMemoryClientMailboxStateRepository();

    private static IClientMailboxStateRepository CreateFaultingRepository(
        bool sqlite,
        string path,
        Action<ClientMailboxCommitFaultPoint> fault) =>
        sqlite
            ? new SqliteClientMailboxStateRepository(
                Options(path),
                migrationFault: null,
                commitFault: fault)
            : new InMemoryClientMailboxStateRepository(fault);

    private static SqliteClientMailboxStateRepository CreateSqlite(string path) =>
        new(Options(path));

    private static int ExpiredQuarantineCount(
        IClientMailboxStateRepository repository,
        ClientMailboxScope scope) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.ExpiredQuarantineCountForTests(scope),
            SqliteClientMailboxStateRepository sqlite =>
                sqlite.ExpiredQuarantineCountForTests(scope),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static SqliteSessionStoreOptions Options(string path) =>
        new(path, DatabaseKey);

    private static MailboxRetrievePage Page(
        ulong firstCursor,
        int count,
        bool hasMore,
        byte[] token,
        byte operationByte = 0x50)
    {
        var items = Enumerable.Range(0, count)
            .Select(index => Envelope(firstCursor + checked((ulong)index)))
            .ToArray();
        return new MailboxRetrievePage
        {
            Epoch = 7,
            OperationId = Filled(operationByte, 16),
            NextCursor = items.Length == 0 ? 0 : items[^1].Cursor,
            HasMore = hasMore,
            ContinuationToken = token,
            Items = items
        };
    }

    private static MailboxRetrievedEnvelope Envelope(ulong cursor) => new()
    {
        Cursor = cursor,
        Envelope = new MailboxEncryptedEnvelope
        {
            Epoch = 7,
            MailboxId = new BlindedMailboxId(Range(0x90, 32)),
            PlacementId = new BlindedPlacementId(Range(0xb0, 32)),
            OperationId = SHA256.HashData(UInt64Bytes(cursor))[..16],
            DeduplicationDigest = SHA256.HashData(UInt64Bytes(cursor)),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1120,
            Ciphertext = Range(0x01, 64)
        }
    };

    private static byte[] Cms1(ulong cursor, int count)
    {
        var encoded = new byte[16 + (count * 40)];
        "CMS1"u8.CopyTo(encoded);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(4, 8), cursor);
        BinaryPrimitives.WriteUInt32BigEndian(
            encoded.AsSpan(12, 4),
            checked((uint)count));
        for (var index = 0; index < count; index++)
        {
            BinaryPrimitives.WriteUInt64BigEndian(
                encoded.AsSpan(16 + (index * 40), 8),
                checked((ulong)index + 1));
            SHA256.HashData(UInt64Bytes(checked((ulong)index + 1))
                ).CopyTo(encoded, 24 + (index * 40));
        }

        return encoded;
    }

    private static byte[] UInt64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Filled(int value, int length) =>
        Enumerable.Repeat(unchecked((byte)value), length).ToArray();

    private static ClientMailboxScope Scope(int seed) =>
        ClientMailboxScope.Derive(
            Filled(seed, 32),
            new BlindedMailboxId(Filled(seed + 1, 32)),
            epoch: 7);

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(static value => unchecked((byte)value))
            .ToArray();

    private static string TempDatabase() => Path.Combine(
        Path.GetTempPath(),
        $"deep-client-mailbox-{Guid.NewGuid():N}.db");

    private static bool Contains(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var offset = 0; offset <= haystack.Length - needle.Length; offset++)
        {
            if (haystack.Slice(offset, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private static void DeleteSqliteFiles(string path)
    {
        foreach (var candidate in new[] { path, path + "-wal", path + "-shm" })
        {
            if (File.Exists(candidate))
            {
                File.Delete(candidate);
            }
        }
    }

    private sealed class ReceiptFixture
    {
        private readonly byte[] firstSeed = Range(0x10, 32);
        private readonly byte[] secondSeed = Range(0x50, 32);
        private readonly byte[] firstId = Range(0x20, 32);
        private readonly byte[] secondId = Range(0x60, 32);
        private readonly byte[] membership = Range(0x80, 32);
        private readonly BlindedPlacementId placementId =
            new(Range(0xa0, 32));
        private readonly byte[] operationId = Range(0x70, 16);
        private readonly byte[] envelopeDigest = Range(0xe0, 32);
        private readonly byte[] issuer = Range(0x11, 32);

        public ReceiptFixture()
        {
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            Route = new ClientMailboxPinnedRoute(
                placementId,
                membership,
                firstId,
                Crypto.GetPublicKey(firstSeed),
                secondId,
                Crypto.GetPublicKey(secondSeed));
        }

        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public ClientMailboxPinnedRoute Route { get; }
        public BlindedMailboxId MailboxId { get; } =
            new(Range(0xc0, 32));
        public byte[] OperationId => operationId.ToArray();
        public ClientMailboxScope Scope =>
            ClientMailboxScope.Derive(issuer, MailboxId, epoch: 7);

        public ClientMailboxAdapter Adapter(
            IClientMailboxBinaryIngress ingress,
            ITransportOutboxRepository outbox,
            IClientMailboxStateRepository state,
            TimeProvider? timeProvider = null) =>
            new(
                ClientFeatureFlags.Defaults with
                {
                    ClientMailboxAdapterEnabled = true
                },
                new ClientMailboxActivation(
                    enabled: true,
                    issuer,
                    Route,
                    ingressConfigured: true),
                ingress,
                outbox,
                state,
                new PinnedClientMailboxReceiptVerifier(Crypto),
                Policy(),
                timeProvider ??
                    new FixedTimeProvider(
                        DateTimeOffset.FromUnixTimeSeconds(1050)));

        public MailboxStoreRequest StoreRequest() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            DepositCapability = Capability(deposit: true, operationId),
            Envelope = EnvelopeModel(cursor: 42)
        };

        public MailboxRetrieveRequest RetrieveRequest(
            byte operationByte,
            ulong afterCursor,
            ReadOnlyMemory<byte> token) => new()
            {
                Epoch = 7,
                OperationId = Filled(operationByte, 16),
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = Capability(
                deposit: false,
                Filled(operationByte, 16)),
                MailboxId = MailboxId,
                PlacementId = placementId,
                AfterCursor = afterCursor,
                MaximumItems = 10,
                ContinuationToken = token
            };

        public MailboxRetrievePage RetrievePage(
            byte operationByte,
            ulong cursor,
            bool hasMore,
            byte[] token) => new()
            {
                Epoch = 7,
                OperationId = Filled(operationByte, 16),
                NextCursor = cursor,
                HasMore = hasMore,
                ContinuationToken = token,
                Items =
            [
                new MailboxRetrievedEnvelope
                {
                    Cursor = cursor,
                    Envelope = EnvelopeModel(cursor)
                }
            ]
            };

        public MailboxAckRequest AckRequest(
            MailboxAcknowledgement acknowledgement) => new()
            {
                Epoch = 7,
                OperationId = Range(0x75, 16),
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = Capability(
                deposit: false,
                Range(0x75, 16)),
                MailboxId = MailboxId,
                PlacementId = placementId,
                IsFinalPage = true,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Acknowledgements = [acknowledgement]
            };

        public byte[] Mar1(
            MailboxAckRequest request,
            ulong expiresAt,
            ulong coordinatorSequence) =>
            MailboxAggregateAckCodec.EncodeMqr3(
                new MailboxAggregateAckResponse
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId,
                    TombstoneQuorums =
                    [
                        Quorum(
                            disposition: MailboxReplicaDisposition.Tombstone,
                            envelopeDigest: request.Acknowledgements[0]
                                .EnvelopeDigest.ToArray(),
                            expiresAt: expiresAt,
                            coordinatorSequence: coordinatorSequence)
                    ]
                });

        public ClientMailboxReceiptExpectation Expectation() => new()
        {
            Epoch = 7,
            OperationId = operationId,
            MailboxId = MailboxId,
            Route = Route,
            EnvelopeDigest = envelopeDigest,
            ExpiresAtUnixSeconds = 1120,
            AllowedDispositions =
                new HashSet<MailboxReplicaDisposition>
                {
                    MailboxReplicaDisposition.Stored
                },
            Cursor = 42
        };

        public byte[] AcceptedReceipt()
        {
            var durable = Replica(
                firstId,
                firstSeed,
                42,
                MailboxReplicaDisposition.Stored,
                envelopeDigest,
                1120);
            return MailboxReceiptV2Codec.EncodeReplica(
                Crypto.SignReplicaResponse(
                    durable with
                    {
                        Status = MailboxReceiptStatus.Accepted,
                        DurableAtUnixSeconds = 0,
                        Signature = ReadOnlyMemory<byte>.Empty
                    },
                    firstSeed));
        }

        public byte[] Quorum(
            ulong cursor = 42,
            ulong coordinatorSequence = 42,
            MailboxReplicaDisposition disposition =
                MailboxReplicaDisposition.Stored,
            byte[]? envelopeDigest = null,
            ulong expiresAt = 1120,
            bool secondSignedWithFirstKey = false)
        {
            envelopeDigest ??= this.envelopeDigest;
            var first = Replica(
                firstId,
                firstSeed,
                cursor,
                disposition,
                envelopeDigest,
                expiresAt);
            var second = Replica(
                secondId,
                secondSignedWithFirstKey ? firstSeed : secondSeed,
                cursor,
                disposition,
                envelopeDigest,
                expiresAt);
            var unsigned = new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = firstId,
                CoordinatorSequence = coordinatorSequence,
                FirstReplica = first,
                SecondReplica = second,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return MailboxReceiptV3Codec.EncodeDurableQuorum(
                Crypto.SignQuorumResponse(unsigned, firstSeed));
        }

        private MailboxReplicaReceiptV2 Replica(
            byte[] replicaId,
            byte[] signingSeed,
            ulong cursor,
            MailboxReplicaDisposition disposition,
            byte[] digest,
            ulong expiresAt)
        {
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = disposition,
                ReplicaId = replicaId,
                OperationId = disposition == MailboxReplicaDisposition.Tombstone
                    ? Range(0x75, 16)
                    : operationId,
                Epoch = 7,
                Cursor = cursor,
                AcceptedAtUnixSeconds = 1050,
                DurableAtUnixSeconds = 1051,
                ExpiresAtUnixSeconds = expiresAt,
                BlindedMailboxId = MailboxId.Bytes,
                PlacementCommitment =
                    MailboxPlacementCommitment.Compute(placementId),
                MembershipCommitment = membership,
                EnvelopeDigest = digest,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            return Crypto.SignReplicaResponse(unsigned, signingSeed);
        }

        private MailboxEncryptedEnvelope EnvelopeModel(ulong cursor) => new()
        {
            Epoch = 7,
            MailboxId = MailboxId,
            PlacementId = placementId,
            OperationId = operationId,
            DeduplicationDigest = cursor == 42
                ? envelopeDigest
                : SHA256.HashData(UInt64Bytes(cursor)),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1120,
            Ciphertext = Range(0x01, 64)
        };

        private static MailboxCapabilityPresentation Capability(
            bool deposit,
            byte[] idempotency) => new()
            {
                DomainValue = deposit
                ? new RotatingDepositCapability(Range(0x30, 32))
                : new RotatingRetrieveCapability(Range(0x40, 32)),
                Lifecycle = MailboxCapabilityLifecycle.Active,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                Generation = 7,
                NotBeforeBucket = 900,
                ExpiresAtBucket = 1200,
                OverlapUntilBucket = 0,
                ReplayCounter = 1,
                IdempotencyKey = idempotency
            };
    }

    private sealed class SequenceIngress(
        params ClientMailboxStoreIngressResult[] responses)
        : IClientMailboxBinaryIngress
    {
        private int index;
        public int StoreCalls { get; private set; }

        public Task<ClientMailboxStoreIngressResult> StoreAsync(
            ReadOnlyMemory<byte> canonicalMst1,
            CancellationToken cancellationToken = default)
        {
            StoreCalls++;
            return Task.FromResult(responses[index++]);
        }

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMrt1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMak1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class RetrieveSequenceIngress(
        params MailboxRetrievePage[] pages)
        : IClientMailboxBinaryIngress
    {
        private int index;
        public int RetrieveCalls { get; private set; }

        public Task<ClientMailboxStoreIngressResult> StoreAsync(
            ReadOnlyMemory<byte> canonicalMst1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMrt1,
            CancellationToken cancellationToken = default)
        {
            RetrieveCalls++;
            return Task.FromResult<ReadOnlyMemory<byte>>(
                MailboxClientCodec.EncodeRetrievePage(pages[index++]));
        }

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMak1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class AckSequenceIngress(params byte[][] responses)
        : IClientMailboxBinaryIngress
    {
        private int index;
        public int AckCalls { get; private set; }

        public Task<ClientMailboxStoreIngressResult> StoreAsync(
            ReadOnlyMemory<byte> canonicalMst1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> RetrieveAsync(
            ReadOnlyMemory<byte> canonicalMrt1,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<ReadOnlyMemory<byte>> AcknowledgeAsync(
            ReadOnlyMemory<byte> canonicalMak1,
            CancellationToken cancellationToken = default)
        {
            AckCalls++;
            return Task.FromResult<ReadOnlyMemory<byte>>(responses[index++]);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MutableTimeProvider(long unixSeconds) : TimeProvider
    {
        private DateTimeOffset now =
            DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

        public void SetUnixSeconds(long value) =>
            now = DateTimeOffset.FromUnixTimeSeconds(value);

        public override DateTimeOffset GetUtcNow() => now;
    }

    private static MailboxClientDecodePolicy Policy() => new()
    {
        NowUnixSeconds = 1050,
        EpochWindow = new MailboxEpochWindow
        {
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 1100,
            CurrentExpiresAtUnixSeconds = 1120,
            NextExpiresAtUnixSeconds = 1200
        },
        CapabilityPolicy = new MailboxCapabilityDecodePolicy
        {
            CurrentBucket = 1050,
            MinimumGeneration = 7
        }
    };
}
