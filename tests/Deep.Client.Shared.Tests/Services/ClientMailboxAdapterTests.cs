using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Features;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Data.Sqlite;

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
                var page = Page(1, 1, false, []);
                await seed.CommitRetrievePageAsync(
                    scope,
                    new ClientMailboxTraversal(0, []),
                    page);
                var storedState = sqlite
                    ? null
                    : CurrentStoredState(page.Items[0], acknowledged: false);
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
                        .SeedCurrentStatesForTests([(scope, storedState!)]);
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
    public async Task InstallationInboxBound_PrunesAcknowledgedRetiredScopeFirst(
        bool sqlite)
    {
        var path = TempDatabase();
        var scopes = Enumerable.Range(
                0,
                ClientMailboxStateLimits.MaximumInstallationInboxEntries)
            .Select(UniqueScope)
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(
                repository,
                scopes.Select((scope, index) => (
                    scope,
                    CurrentStoredState(
                        acknowledged: index is 0 or 1,
                        continuation: index == 1))).ToArray());
            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationInboxEntries,
                InstallationInboxCount(repository));

            var newScope = UniqueScope(scopes.Length + 1);
            await repository.CommitRetrievePageAsync(
                newScope,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, false, []));

            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationInboxEntries,
                InstallationInboxCount(repository));
            Assert.Equal(0, InboxEntryCount(repository, scopes[0]));
            Assert.Equal(1, InboxEntryCount(repository, scopes[1]));
            Assert.Equal(1, InboxEntryCount(repository, newScope));
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
    public async Task InstallationInboxBound_FailsClosedWhenAllRowsAreUnacknowledged(
        bool sqlite)
    {
        var path = TempDatabase();
        var scopes = Enumerable.Range(
                0,
                ClientMailboxStateLimits.MaximumInstallationInboxEntries)
            .Select(index => UniqueScope(index + 2000))
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            var encoded = CurrentStoredState(
                acknowledged: false,
                continuation: false);
            SeedStates(
                repository,
                scopes.Select(scope => (scope, encoded)).ToArray());
            var rejectedScope = UniqueScope(4000);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                repository.CommitRetrievePageAsync(
                    rejectedScope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, false, [])));

            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationInboxEntries,
                InstallationInboxCount(repository));
            Assert.Equal(0, InboxEntryCount(repository, rejectedScope));
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
    public async Task InstallationInboxByteBound_FailsClosedBelowCountBound(
        bool sqlite)
    {
        const int ciphertextBytes = 48 * 1024;
        var path = TempDatabase();
        var item = EnvelopeWithCiphertext(1, ciphertextBytes);
        var encoded = CurrentStoredState(item, acknowledged: false);
        var canonicalBytes =
            MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope).Length;
        var seedCount = ClientMailboxStateLimits.MaximumInstallationInboxBytes /
            canonicalBytes;
        Assert.InRange(
            seedCount,
            1,
            ClientMailboxStateLimits.MaximumInstallationInboxEntries - 1);
        var scopes = Enumerable.Range(0, seedCount)
            .Select(index => UniqueScope(index + 4100))
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(
                repository,
                scopes.Select(scope => (scope, encoded)).ToArray());
            var rejectedScope = UniqueScope(4999);
            var page = PageFromItem(item);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                repository.CommitRetrievePageAsync(
                    rejectedScope,
                    new ClientMailboxTraversal(0, []),
                    page));

            Assert.Equal(seedCount, InstallationInboxCount(repository));
            Assert.Equal(0, InboxEntryCount(repository, rejectedScope));
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
    public async Task P10B7_TraversalScopeBound_RotatingLiveScopesFailClosedAcrossRestart(
        bool sqlite)
    {
        var path = TempDatabase();
        var encoded = CurrentTraversalOnlyState(cursor: 1, tokenBytes: 32);
        var snapshots = Enumerable.Range(
                0,
                ClientMailboxStateLimits.MaximumInstallationScopes)
            .Select(index => (UniqueScope(index + 21000), encoded))
            .ToArray();
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(repository, snapshots);
            var rejectedScope = UniqueScope(23000);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                repository.CommitRetrievePageAsync(
                    rejectedScope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, true, Range(0x31, 32))));

            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationScopes,
                InstallationTraversalCount(repository));
            Assert.Equal(
                0UL,
                (await repository.ReadTraversalAsync(rejectedScope)).AfterCursor);

            repository = RestartInstallation(repository, sqlite, path);
            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationScopes,
                InstallationTraversalCount(repository));
            Assert.Equal(
                0UL,
                (await repository.ReadTraversalAsync(rejectedScope)).AfterCursor);
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
    public async Task P10B7_TraversalScopeBound_EvictsOnlyFullyRetiredScope(
        bool sqlite)
    {
        var path = TempDatabase();
        var live = CurrentTraversalOnlyState(cursor: 1, tokenBytes: 32);
        var retired = new ClientMailboxStoredState();
        var snapshots = Enumerable.Range(
                0,
                ClientMailboxStateLimits.MaximumInstallationScopes)
            .Select(index => (
                UniqueScope(index + 24000),
                index == 0 ? retired : live))
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(repository, snapshots);
            var replacement = UniqueScope(26000);
            await repository.CommitRetrievePageAsync(
                replacement,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, true, Range(0x41, 32)));

            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationScopes,
                InstallationTraversalCount(repository));
            Assert.Equal(
                0UL,
                (await repository.ReadTraversalAsync(snapshots[0].Item1))
                .AfterCursor);
            Assert.Equal(
                1UL,
                (await repository.ReadTraversalAsync(replacement)).AfterCursor);
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
    public async Task P10B7_TraversalTokenByteBound_FailsBelowScopeCount(
        bool sqlite)
    {
        const int tokenBytes = MailboxClientLimits.MaximumContinuationTokenLength;
        var path = TempDatabase();
        var encoded = CurrentTraversalOnlyState(cursor: 1, tokenBytes);
        var seedCount =
            ClientMailboxStateLimits.MaximumInstallationTraversalTokenBytes /
            tokenBytes;
        Assert.InRange(
            seedCount,
            1,
            ClientMailboxStateLimits.MaximumInstallationScopes - 1);
        var snapshots = Enumerable.Range(0, seedCount)
            .Select(index => (UniqueScope(index + 27000), encoded))
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(repository, snapshots);
            var rejectedScope = UniqueScope(28000);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                repository.CommitRetrievePageAsync(
                    rejectedScope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, true, Filled(0x52, tokenBytes))));

            Assert.Equal(seedCount, InstallationTraversalCount(repository));
            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationTraversalTokenBytes,
                InstallationTraversalTokenBytes(repository));
        }
        finally
        {
            (repository as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task P10B7_SqliteTraversalScopeBound_IsAtomicAcrossRepositoryRace()
    {
        var path = TempDatabase();
        var encoded = CurrentTraversalOnlyState(cursor: 1, tokenBytes: 32);
        var snapshots = Enumerable.Range(
                0,
                ClientMailboxStateLimits.MaximumInstallationScopes - 1)
            .Select(index => (UniqueScope(index + 29000), encoded))
            .ToArray();
        try
        {
            using var first = CreateSqlite(path);
            first.SeedCurrentStatesForTests(snapshots);
            using var second = CreateSqlite(path);
            var attempts = new[]
            {
                CommitCapturingFailure(first, UniqueScope(31000), 0x61),
                CommitCapturingFailure(second, UniqueScope(31001), 0x62)
            };
            var results = await Task.WhenAll(attempts);

            Assert.Single(results, static error => error is null);
            Assert.Single(results.OfType<InvalidDataException>());
            Assert.Equal(
                ClientMailboxStateLimits.MaximumInstallationScopes,
                first.InstallationTraversalCountForTests());
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task P10B8_InMemorySequentialFinalRetrieveAckConflict_DoesNotBypassScopeBound()
    {
        var repository = new InMemoryClientMailboxStateRepository();
        var count = ClientMailboxStateLimits.MaximumInstallationScopes + 1;
        for (var index = 0; index < count; index++)
        {
            var scope = UniqueScope(index + 38000);
            var page = Page(1, 0, hasMore: false, token: []);
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                page);
            Assert.Equal(
                ClientMailboxAckState.Conflict,
                await repository.CommitAcknowledgementsAsync(
                    scope,
                    [Envelope(1).ToAcknowledgement()]));
        }

        Assert.Equal(0, InstallationTraversalCount(repository));
        var restarted = repository.RestartInstallationForTests();
        Assert.Equal(0, InstallationTraversalCount(restarted));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task P10B8_FinalRetrieveAckLifecycle_HasBackendParity(
        bool sqlite)
    {
        var path = TempDatabase();
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            var scope = UniqueScope(39000);
            var page = Page(1, 1, hasMore: false, token: []);
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                page);
            Assert.Equal(
                ClientMailboxAckState.Pending,
                await repository.CommitAcknowledgementsAsync(
                    scope,
                    [page.Items[0].ToAcknowledgement()]));
            Assert.Equal(1, InstallationTraversalCount(repository));
            repository = RestartInstallation(repository, sqlite, path);
            Assert.Equal(1, InstallationTraversalCount(repository));
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
    public async Task P10B8_AbsentAckConflict_DoesNotAllocateTraversalScope(
        bool sqlite)
    {
        var path = TempDatabase();
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            var scope = UniqueScope(40000);
            Assert.Equal(
                ClientMailboxAckState.Conflict,
                await repository.CommitAcknowledgementsAsync(
                    scope,
                    [Envelope(1).ToAcknowledgement()]));
            Assert.Equal(0, InstallationTraversalCount(repository));

            repository = RestartInstallation(repository, sqlite, path);
            Assert.Equal(0, InstallationTraversalCount(repository));
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
    public async Task InstallationSweep_ReconcilesAbandonedScopesAcrossRestartAndRace(
        bool sqlite)
    {
        var path = TempDatabase();
        var scopes = Enumerable.Range(0, 32)
            .Select(index => UniqueScope(index + 5000))
            .ToArray();
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            var encoded = CurrentStoredState(
                acknowledged: false,
                continuation: false);
            SeedStates(
                repository,
                scopes.Select(scope => (scope, encoded)).ToArray());
            repository = RestartInstallation(repository, sqlite, path);
            var unrelated = UniqueScope(6000);
            IClientMailboxStateRepository concurrent = sqlite
                ? CreateSqlite(path)
                : repository;
            ClientMailboxExpiryReconciliationResult[] results;
            try
            {
                results = await Task.WhenAll(
                    repository.ReconcileExpiredAsync(unrelated, 1120),
                    concurrent.ReconcileExpiredAsync(unrelated, 1120));
            }
            finally
            {
                if (!ReferenceEquals(concurrent, repository))
                {
                    (concurrent as IDisposable)?.Dispose();
                }
            }

            Assert.Equal(
                scopes.Length,
                results.Sum(static result =>
                    result.QuarantinedUnacknowledged));
            Assert.Equal(0, InstallationInboxCount(repository));
            Assert.Equal(
                scopes.Length,
                InstallationExpiredQuarantineCount(repository));
            Assert.All(scopes, scope =>
                Assert.Equal(0, InboxEntryCount(repository, scope)));
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
    public async Task InstallationQuarantineBound_PrunesDeterministicOldestScope(
        bool sqlite)
    {
        var path = TempDatabase();
        var scopes = Enumerable.Range(
                0,
                ClientMailboxStateLimits
                    .MaximumInstallationExpiredQuarantineEntries)
            .Select(index => UniqueScope(index + 7000))
            .OrderBy(static scope => Convert.ToHexString(scope.ToArray()),
                StringComparer.Ordinal)
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            var encoded = CurrentStoredState(
                acknowledged: false,
                continuation: false);
            SeedStates(
                repository,
                scopes.Select(scope => (scope, encoded)).ToArray());
            await repository.ReconcileExpiredAsync(UniqueScope(8001), 1120);
            Assert.Equal(
                ClientMailboxStateLimits
                    .MaximumInstallationExpiredQuarantineEntries,
                InstallationExpiredQuarantineCount(repository));

            var newestScope = UniqueScope(9001);
            await repository.CommitRetrievePageAsync(
                newestScope,
                new ClientMailboxTraversal(0, []),
                Page(1, 1, false, []));
            await repository.ReconcileExpiredAsync(newestScope, 1121);

            Assert.Equal(
                ClientMailboxStateLimits
                    .MaximumInstallationExpiredQuarantineEntries,
                InstallationExpiredQuarantineCount(repository));
            Assert.Equal(0, ExpiredQuarantineCount(repository, scopes[0]));
            Assert.Equal(1, ExpiredQuarantineCount(repository, newestScope));
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
    public async Task InstallationQuarantine_AgesOutAcrossAllScopes(
        bool sqlite)
    {
        var path = TempDatabase();
        var scope = UniqueScope(9100);
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(
                repository,
                [(scope, CurrentStoredState(
                    acknowledged: false,
                    continuation: false))]);
            await repository.ReconcileExpiredAsync(scope, 1120);
            Assert.Equal(1, InstallationExpiredQuarantineCount(repository));

            await repository.ReconcileExpiredAsync(
                UniqueScope(9101),
                1120 +
                ClientMailboxStateLimits.ExpiredQuarantineRetentionSeconds +
                1);
            Assert.Equal(0, InstallationExpiredQuarantineCount(repository));
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
    public async Task InstallationQuarantineByteBound_PrunesOldestBelowCountBound(
        bool sqlite)
    {
        const int ciphertextBytes = 48 * 1024;
        var path = TempDatabase();
        var item = EnvelopeWithCiphertext(1, ciphertextBytes);
        var encoded = CurrentStoredState(item, acknowledged: false);
        var canonicalBytes =
            MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope).Length;
        var seedCount =
            ClientMailboxStateLimits.MaximumInstallationExpiredQuarantineBytes /
            canonicalBytes;
        Assert.InRange(
            seedCount,
            1,
            ClientMailboxStateLimits
                .MaximumInstallationExpiredQuarantineEntries - 1);
        var scopes = Enumerable.Range(0, seedCount)
            .Select(index => UniqueScope(index + 9200))
            .OrderBy(static scope => Convert.ToHexString(scope.ToArray()),
                StringComparer.Ordinal)
            .ToArray();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedStates(
                repository,
                scopes.Select(scope => (scope, encoded)).ToArray());
            await repository.ReconcileExpiredAsync(UniqueScope(9300), 1120);
            var newestScope = UniqueScope(20000);
            await repository.CommitRetrievePageAsync(
                newestScope,
                new ClientMailboxTraversal(0, []),
                PageFromItem(item));
            await repository.ReconcileExpiredAsync(newestScope, 1121);

            Assert.Equal(
                seedCount,
                InstallationExpiredQuarantineCount(repository));
            Assert.Equal(0, ExpiredQuarantineCount(repository, scopes[0]));
            Assert.Equal(1, ExpiredQuarantineCount(repository, newestScope));
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
    public async Task CoordinatorJournal_IsGlobalAcrossIssuerRotationAndCapacity(
        bool sqlite)
    {
        var path = TempDatabase();
        IClientMailboxStateRepository repository = CreateRepository(sqlite, path);
        try
        {
            var firstScope = ClientMailboxJournalScope.Derive(Range(0x61, 32));
            var rotatedScope = ClientMailboxJournalScope.Derive(Range(0x62, 32));
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Applied,
                await Record(
                    repository,
                    firstScope,
                    Range(0x80, 32),
                    Range(0x01, 32)));
            repository = RestartInstallation(repository, sqlite, path);
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Equivocation,
                await Record(
                    repository,
                    rotatedScope,
                    Range(0x80, 32),
                    Range(0x02, 32)));

            SeedCoordinatorJournal(
                repository,
                ClientMailboxStateLimits.MaximumCoordinatorStatements,
                expiresAtUnixSeconds: 1120);
            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.CapacityExceeded,
                await Record(
                    repository,
                    rotatedScope,
                    Range(0x90, 32),
                    Range(0x03, 32)));
            Assert.Equal(
                ClientMailboxStateLimits.MaximumCoordinatorStatements,
                CoordinatorJournalCount(repository));

            Assert.Equal(
                ClientMailboxCoordinatorRecordResult.Applied,
                await repository.RecordCoordinatorStatementAsync(
                    rotatedScope,
                    Range(0x91, 32),
                    epoch: 7,
                    coordinatorId: Range(0x31, 32),
                    coordinatorSequence: 10,
                    statementDigest: Range(0x04, 32),
                    expiresAtUnixSeconds: 1200,
                    nowUnixSeconds: 1120));
            Assert.Equal(1, CoordinatorJournalCount(repository));
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
    public async Task InstallationAgeBounds_RejectFarFutureJournalRetention(
        bool sqlite)
    {
        var path = TempDatabase();
        var repository = CreateRepository(sqlite, path);
        try
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                repository.RecordCoordinatorStatementAsync(
                    ClientMailboxJournalScope.Derive(Range(0x63, 32)),
                    Range(0x80, 32),
                    epoch: 7,
                    coordinatorId: Range(0x30, 32),
                    coordinatorSequence: 9,
                    statementDigest: Range(0x01, 32),
                    expiresAtUnixSeconds:
                        1050 +
                        ClientMailboxStateLimits.MaximumActiveInboxAgeSeconds +
                        1,
                    nowUnixSeconds: 1050));
            Assert.Equal(0, CoordinatorJournalCount(repository));
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
    public async Task CoordinatorJournalCapacity_IsAtomicAcrossConcurrentIssuers(
        bool sqlite)
    {
        var path = TempDatabase();
        var repository = CreateRepository(sqlite, path);
        try
        {
            SeedCoordinatorJournal(
                repository,
                ClientMailboxStateLimits.MaximumCoordinatorStatements - 1,
                expiresAtUnixSeconds: 1200);
            IClientMailboxStateRepository concurrent = sqlite
                ? CreateSqlite(path)
                : repository;
            ClientMailboxCoordinatorRecordResult[] results;
            try
            {
                results = await Task.WhenAll(
                    repository.RecordCoordinatorStatementAsync(
                        ClientMailboxJournalScope.Derive(Range(0x64, 32)),
                        Range(0x81, 32),
                        epoch: 7,
                        coordinatorId: Range(0x32, 32),
                        coordinatorSequence: 1100,
                        statementDigest: Range(0x05, 32),
                        expiresAtUnixSeconds: 1200,
                        nowUnixSeconds: 1050),
                    concurrent.RecordCoordinatorStatementAsync(
                        ClientMailboxJournalScope.Derive(Range(0x65, 32)),
                        Range(0x82, 32),
                        epoch: 7,
                        coordinatorId: Range(0x33, 32),
                        coordinatorSequence: 1101,
                        statementDigest: Range(0x06, 32),
                        expiresAtUnixSeconds: 1200,
                        nowUnixSeconds: 1050));
            }
            finally
            {
                if (!ReferenceEquals(concurrent, repository))
                {
                    (concurrent as IDisposable)?.Dispose();
                }
            }

            Assert.Single(results, static result =>
                result == ClientMailboxCoordinatorRecordResult.Applied);
            Assert.Single(results, static result =>
                result ==
                ClientMailboxCoordinatorRecordResult.CapacityExceeded);
            Assert.Equal(
                ClientMailboxStateLimits.MaximumCoordinatorStatements,
                CoordinatorJournalCount(repository));
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
        var scope = Scope(0x70);
        IClientMailboxStateRepository seed = CreateRepository(sqlite, path);
        try
        {
            var page = Page(42, 1, false, []);
            await seed.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                page);
            var storedState = sqlite
                ? null
                : CurrentStoredState(page.Items[0], acknowledged: false);
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
                    .SeedCurrentStatesForTests([(scope, storedState!)]);
            }

            var acknowledgement = page.Items[0].ToAcknowledgement();
            await Assert.ThrowsAsync<IOException>(() =>
                repository.CommitAcknowledgementsAsync(
                    scope,
                    [acknowledgement]));

            await repository.ReconcileExpiredAsync(scope, 1120);
            Assert.Empty(await repository.ReadDurableInboxAsync(scope));
            Assert.Equal(1, ExpiredQuarantineCount(repository, scope));
            (repository as IDisposable)?.Dispose();
        }
        finally
        {
            (seed as IDisposable)?.Dispose();
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void CanonicalInbox_RejectsEnvelopeBeyondMaximumActiveAge()
    {
        var expiresAt = 1000 +
            ClientMailboxStateLimits.MaximumActiveInboxAgeSeconds +
            1;
        var envelope = new MailboxEncryptedEnvelope
        {
            Epoch = 7,
            MailboxId = new BlindedMailboxId(Range(0x90, 32)),
            PlacementId = new BlindedPlacementId(Range(0xb0, 32)),
            OperationId = Range(0x70, 16),
            DeduplicationDigest = Range(0xe0, 32),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = expiresAt,
            Ciphertext = Range(0x01, 64)
        };
        Assert.Throws<MailboxClientException>(() =>
            MailboxClientCodec.EncodeEncryptedEnvelope(envelope));
    }

    [Fact]
    public void Sqlite_UsesTheSingleSessionStorePath()
    {
        var path = TempDatabase();
        try
        {
            using var store = new SqliteSessionStore(
                new SqliteSessionStoreOptions(path));
            Assert.IsAssignableFrom<IClientMailboxStateRepository>(store);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void Sqlite_PreCurrentMailboxSchemaRequiresExplicitWipeReset()
    {
        var path = TempDatabase();
        try
        {
            using (var connection = new SqliteConnection(
                       new SqliteConnectionStringBuilder
                       {
                           DataSource = path,
                           Password = DatabaseKey,
                           Pooling = false
                       }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE client_mailbox_meta (
                        id INTEGER PRIMARY KEY,
                        schema_version INTEGER NOT NULL);
                    INSERT INTO client_mailbox_meta(id, schema_version) VALUES(1, 5);
                    CREATE TABLE client_mailbox_state (
                        scope BLOB PRIMARY KEY,
                        state_blob BLOB NOT NULL);
                    """;
                command.ExecuteNonQuery();
            }

            var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
                new SqliteSessionStore(Options(path)));
            Assert.Contains("Reset local data", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void Sqlite_PartialCurrentVersionSchemaRequiresExplicitWipeReset()
    {
        var path = TempDatabase();
        try
        {
            using (var connection = new SqliteConnection(
                       new SqliteConnectionStringBuilder
                       {
                           DataSource = path,
                           Password = DatabaseKey,
                           Pooling = false
                       }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE client_mailbox_meta (
                        id INTEGER PRIMARY KEY CHECK(id = 1),
                        schema_version INTEGER NOT NULL);
                    INSERT INTO client_mailbox_meta(id, schema_version) VALUES(1, 6);
                    """;
                command.ExecuteNonQuery();
            }

            var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
                new SqliteSessionStore(Options(path)));
            Assert.Contains("Reset local data", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void Sqlite_SpoofedCurrentVersionShapeRequiresExplicitWipeReset()
    {
        var path = TempDatabase();
        try
        {
            using (var connection = new SqliteConnection(
                       new SqliteConnectionStringBuilder
                       {
                           DataSource = path,
                           Password = DatabaseKey,
                           Pooling = false
                       }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE client_mailbox_meta (
                        id INTEGER PRIMARY KEY CHECK(id = 1),
                        schema_version INTEGER NOT NULL);
                    INSERT INTO client_mailbox_meta(id, schema_version) VALUES(1, 6);
                    CREATE TABLE client_mailbox_traversal (scope BLOB);
                    CREATE TABLE client_mailbox_inbox (scope BLOB);
                    CREATE TABLE client_mailbox_expired_quarantine (scope BLOB);
                    CREATE TABLE client_mailbox_coordinator_journal (installation_scope BLOB);
                    """;
                command.ExecuteNonQuery();
            }

            var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
                new SqliteSessionStore(Options(path)));
            Assert.Contains("Reset local data", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public void Sqlite_SpoofedCurrentVersionConstraintsRequireExplicitWipeReset()
    {
        var path = TempDatabase();
        try
        {
            using (var connection = new SqliteConnection(
                       new SqliteConnectionStringBuilder
                       {
                           DataSource = path,
                           Password = DatabaseKey,
                           Pooling = false
                       }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE client_mailbox_meta (
                        id INTEGER PRIMARY KEY CHECK(id = 1),
                        schema_version INTEGER NOT NULL);
                    INSERT INTO client_mailbox_meta(id, schema_version) VALUES(1, 6);
                    CREATE TABLE client_mailbox_traversal (
                        scope BLOB PRIMARY KEY NOT NULL,
                        after_cursor BLOB NOT NULL,
                        continuation_token BLOB NOT NULL);
                    CREATE TABLE client_mailbox_inbox (
                        scope BLOB NOT NULL,
                        cursor BLOB NOT NULL,
                        digest BLOB NOT NULL,
                        expires_at BLOB NOT NULL,
                        canonical_envelope BLOB NOT NULL,
                        acknowledged INTEGER NOT NULL,
                        PRIMARY KEY(scope, cursor));
                    CREATE TABLE client_mailbox_expired_quarantine (
                        scope BLOB NOT NULL,
                        cursor BLOB NOT NULL,
                        digest BLOB NOT NULL,
                        expires_at BLOB NOT NULL,
                        canonical_envelope BLOB NOT NULL,
                        quarantined_at INTEGER NOT NULL,
                        reason TEXT NOT NULL,
                        PRIMARY KEY(scope, cursor, digest));
                    CREATE TABLE client_mailbox_coordinator_journal (
                        installation_scope BLOB NOT NULL,
                        statement_key BLOB NOT NULL,
                        statement_digest BLOB NOT NULL,
                        expires_at BLOB NOT NULL,
                        PRIMARY KEY(installation_scope, statement_key));
                    CREATE INDEX ix_client_mailbox_inbox_scope_expiry
                        ON client_mailbox_inbox(scope, expires_at);
                    CREATE INDEX ix_client_mailbox_inbox_expiry_scope
                        ON client_mailbox_inbox(expires_at, scope);
                    CREATE INDEX ix_client_mailbox_inbox_scope_ack_cursor
                        ON client_mailbox_inbox(scope, acknowledged, cursor);
                    CREATE INDEX ix_client_mailbox_quarantine_age
                        ON client_mailbox_expired_quarantine(
                            quarantined_at, expires_at, scope);
                    CREATE INDEX ix_client_mailbox_journal_scope_expiry
                        ON client_mailbox_coordinator_journal(
                            installation_scope, expires_at);
                    """;
                command.ExecuteNonQuery();
            }

            var exception = Assert.Throws<LocalStateResetRequiredException>(() =>
                new SqliteSessionStore(Options(path)));
            Assert.Contains("Reset local data", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
    }

    [Fact]
    public async Task Sqlite_FreshCurrentMailboxStateSurvivesRestart()
    {
        var path = TempDatabase();
        var scope = Scope(0x46);
        try
        {
            using (var fresh = CreateSqlite(path))
            {
                await fresh.CommitRetrievePageAsync(
                    scope,
                    new ClientMailboxTraversal(0, []),
                    Page(1, 1, true, Range(0x56, 32)));
            }

            using var reopened = CreateSqlite(path);
            Assert.Equal(1UL, (await reopened.ReadTraversalAsync(scope)).AfterCursor);
            Assert.Single(await reopened.ReadDurableInboxAsync(scope));
        }
        finally
        {
            DeleteSqliteFiles(path);
        }
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

        return repository;
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
            ? new SqliteSessionStore(Options(path), fault)
            : new InMemoryClientMailboxStateRepository(fault);

    private static SqliteSessionStore CreateSqlite(string path) =>
        new(Options(path));

    private static int ExpiredQuarantineCount(
        IClientMailboxStateRepository repository,
        ClientMailboxScope scope) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.ExpiredQuarantineCountForTests(scope),
            SqliteSessionStore sqlite =>
                sqlite.ExpiredQuarantineCountForTests(scope),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static int InstallationInboxCount(
        IClientMailboxStateRepository repository) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.InstallationInboxCountForTests(),
            SqliteSessionStore sqlite =>
                sqlite.InstallationInboxCountForTests(),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static int InstallationTraversalCount(
        IClientMailboxStateRepository repository) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.InstallationTraversalCountForTests(),
            SqliteSessionStore sqlite =>
                sqlite.InstallationTraversalCountForTests(),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static long InstallationTraversalTokenBytes(
        IClientMailboxStateRepository repository) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.InstallationTraversalTokenBytesForTests(),
            SqliteSessionStore sqlite =>
                sqlite.InstallationTraversalTokenBytesForTests(),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static int InboxEntryCount(
        IClientMailboxStateRepository repository,
        ClientMailboxScope scope) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.InboxEntryCountForTests(scope),
            SqliteSessionStore sqlite =>
                sqlite.NormalizedInboxCountForTests(scope),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static int InstallationExpiredQuarantineCount(
        IClientMailboxStateRepository repository) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.InstallationExpiredQuarantineCountForTests(),
            SqliteSessionStore sqlite =>
                sqlite.InstallationExpiredQuarantineCountForTests(),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static int CoordinatorJournalCount(
        IClientMailboxStateRepository repository) =>
        repository switch
        {
            InMemoryClientMailboxStateRepository memory =>
                memory.CoordinatorJournalCountForTests(),
            SqliteSessionStore sqlite =>
                sqlite.CoordinatorJournalCountForTests(),
            _ => throw new InvalidOperationException("Unknown test repository.")
        };

    private static void SeedCoordinatorJournal(
        IClientMailboxStateRepository repository,
        int count,
        ulong expiresAtUnixSeconds)
    {
        switch (repository)
        {
            case InMemoryClientMailboxStateRepository memory:
                memory.SeedCoordinatorJournalForTests(
                    count,
                    expiresAtUnixSeconds);
                break;
            case SqliteSessionStore sqlite:
                sqlite.SeedCoordinatorJournalForTests(
                    count,
                    expiresAtUnixSeconds);
                break;
            default:
                throw new InvalidOperationException("Unknown test repository.");
        }
    }

    private static void SeedStates(
        IClientMailboxStateRepository repository,
        IReadOnlyList<(ClientMailboxScope Scope, ClientMailboxStoredState State)> snapshots)
    {
        switch (repository)
        {
            case InMemoryClientMailboxStateRepository memory:
                memory.SeedCurrentStatesForTests(snapshots);
                break;
            case SqliteSessionStore sqlite:
                sqlite.SeedCurrentStatesForTests(snapshots);
                break;
            default:
                throw new InvalidOperationException("Unknown test repository.");
        }
    }

    private static IClientMailboxStateRepository RestartInstallation(
        IClientMailboxStateRepository repository,
        bool sqlite,
        string path)
    {
        if (sqlite)
        {
            (repository as IDisposable)?.Dispose();
            return CreateSqlite(path);
        }

        return Assert.IsType<InMemoryClientMailboxStateRepository>(repository)
            .RestartInstallationForTests();
    }

    private static SqliteSessionStoreOptions Options(string path) =>
        new(path, DatabaseKey);

    private static async Task<Exception?> CommitCapturingFailure(
        IClientMailboxStateRepository repository,
        ClientMailboxScope scope,
        byte operationByte)
    {
        try
        {
            await repository.CommitRetrievePageAsync(
                scope,
                new ClientMailboxTraversal(0, []),
                Page(
                    1,
                    1,
                    hasMore: true,
                    Range(operationByte, 32),
                    operationByte));
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

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

    private static ClientMailboxScope UniqueScope(int seed) =>
        ClientMailboxScope.Derive(
            SHA256.HashData([
                .. "test-unique-issuer"u8,
                .. UInt64Bytes(checked((ulong)seed + 1))
            ]),
            new BlindedMailboxId(SHA256.HashData([
                .. "test-unique-mailbox"u8,
                .. UInt64Bytes(checked((ulong)seed + 1))
            ])),
            epoch: checked((ulong)seed + 1));

    private static ClientMailboxStoredState CurrentStoredState(
        bool acknowledged,
        bool continuation) =>
        CurrentStoredState(
            Envelope(1),
            acknowledged,
            continuation ? Range(0x44, 32) : []);

    private static ClientMailboxStoredState CurrentTraversalOnlyState(
        ulong cursor,
        int tokenBytes) => new()
        {
            AfterCursor = cursor,
            ContinuationToken = Filled(0x43, tokenBytes)
        };

    private static ClientMailboxStoredState CurrentStoredState(
        MailboxRetrievedEnvelope item,
        bool acknowledged) =>
        CurrentStoredState(item, acknowledged, []);

    private static ClientMailboxStoredState CurrentStoredState(
        MailboxRetrievedEnvelope item,
        bool acknowledged,
        byte[] continuationToken)
    {
        var state = new ClientMailboxStoredState
        {
            AfterCursor = continuationToken.Length == 0 ? 0UL : item.Cursor,
            ContinuationToken = continuationToken
        };
        state.Entries.Add(new ClientMailboxStoredEntry
        {
            Cursor = item.Cursor,
            Digest = item.Envelope.DeduplicationDigest.ToArray(),
            ExpiresAtUnixSeconds = item.Envelope.ExpiresAtUnixSeconds,
            CanonicalEnvelope = MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope),
            Acknowledged = acknowledged
        });
        return state;
    }

    private static MailboxRetrievedEnvelope EnvelopeWithCiphertext(
        ulong cursor,
        int ciphertextBytes) => new()
        {
            Cursor = cursor,
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(Range(0x90, 32)),
                PlacementId = new BlindedPlacementId(Range(0xb0, 32)),
                OperationId = SHA256.HashData(UInt64Bytes(cursor))[..16],
                DeduplicationDigest = SHA256.HashData([
                    .. "large-envelope"u8,
                    .. UInt64Bytes(cursor)
                ]),
                CreatedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1120,
                Ciphertext = Filled(0x5a, ciphertextBytes)
            }
        };

    private static MailboxRetrievePage PageFromItem(
        MailboxRetrievedEnvelope item) => new()
        {
            Epoch = 7,
            OperationId = Range(0x50, 16),
            NextCursor = item.Cursor,
            HasMore = false,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Items = [item]
        };

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
