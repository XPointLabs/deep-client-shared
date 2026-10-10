using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Client.Shared.Services.ContactV2;
using Sodium;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2ArchivedReadPath_ExpiredGrantAndAdvancedEpochDoNotShortenObjectRetention()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1, beforeHorizonOnly: true);
    }

    [Fact]
    public async Task Did2ArchivedReadPath_ActualObjectHorizonJointSqlAndProtectedDisposition()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1);
    }

    [Theory]
    [InlineData(false, 0)] [InlineData(false, 1)] [InlineData(false, 2)] [InlineData(false, 3)]
    [InlineData(false, 4)] [InlineData(false, 5)] [InlineData(false, 6)] [InlineData(false, 7)]
    [InlineData(true, 0)] [InlineData(true, 1)] [InlineData(true, 2)] [InlineData(true, 3)]
    [InlineData(true, 4)] [InlineData(true, 5)] [InlineData(true, 6)] [InlineData(true, 7)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchivedReadPath_EveryColdHandoverPreservesOriginalNativeContactAndAck(bool nonempty, int handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: nonempty, encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty, handover);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Did2ArchivedReadPath_CancellationAbandonsOnlyExactBeforeSql(bool afterSql)
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: afterSql ? 1 : 0, cancel: true);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchivedReadPath_HostileSqlFloorsRejectBeforeStageWithoutChangingCustody(bool nonempty)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: nonempty, encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty, handover: -1, hostileSql: true);
    }

    [Fact]
    public async Task Did2ArchivedReadPath_ColdPreparedRecoveryRejectsLostChangedExtraPartsAndSqlWithoutAdoption()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1, hostileRecovery: true);
    }

    [Fact]
    public async Task Did2ArchivedReadPath_ProtectedDependencyLossRejectsBeforeStageAndPreservesLastPath()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true, longMailboxWindow: true,
            initialMailboxAuthorityExpiry: 2_000, objectHorizonWindow: true);
        await fixture.CheckArchivedReadPathAsync(nonempty: false, handover: -1, hostileProtected: true);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckArchivedReadPathAsync(bool nonempty, int handover, bool cancel = false, bool beforeHorizonOnly = false,
            bool hostileSql = false, bool hostileRecovery = false, bool hostileProtected = false)
        {
            await SeedShortPermanentProposalAsync(validitySeconds: 800);
            // This test creates and delivers a real native contact before
            // expiry. The deliberately100-second retained-read fixture window
            // is too short for that independent setup. Author its original
            // threshold within the already signed800-second XRA, before use;
            // never extend any existing record or the later object horizon.
            var original = await PrepareRetainedPublicationAsync(elapsed: false, signedExpiry: 1_900);
            var issuer = new OwnedGrantTransport(this, selfRetrieve: true);
            Did2MessagingSessionScope? sender = null;
            byte[]? acceptCipher = null;
            OwnedReadTerminal terminal;
            if (nonempty)
            {
                var intent = Bytes(32, 0xd4);
                var (complete, hello, init, _, _) = await PrepareNativeHelloCompletion(intent, verifyDraftRecovery: false);
                byte[] initial;
                using (var committed = await complete(accounts)) initial = committed.ExactDph2.ToArray();
                sender = await EnsureSenderMessaging(init, hello);
                TrackMailboxDispatchClock();
                var initialStore = new OwnedStoreFixture(this, null, ProtectedDeepIdV2AccountOwner.InitialMailboxOperation(intent), initial);
                _ = await StartNativeContact(intent, new OwnedGrantTransport(this, ownerOnPrimary: true), initialStore);
                var incoming = new OwnedReadTerminal(this, initial) { RetainedEnvelope = initialStore.StoredEnvelope };
                _ = await SynchronizeNativeReceiver(new OwnedGrantTransport(this, selfRetrieve: true, ownerOnPrimary: false), incoming);
                var receiver = await ReceiveNativeMailboxInitial(initial);
                var acceptOperation = Bytes(32, 0xd5);
                var acceptStore = new OwnedStoreFixture(this, receiver, acceptOperation, null);
                _ = await AcceptNativeContact(receiver, acceptOperation, new OwnedGrantTransport(this, ownerOnPrimary: false), acceptStore);
                acceptCipher = acceptStore.StoredEnvelope!.Ciphertext.ToArray();
                // A real completed non-final page keeps a nonempty traversal.
                // Final ACK correctly resets the cursor and is covered by the
                // ordinary receive fixtures; it cannot model a lost cursor here.
                terminal = new OwnedReadTerminal(this, acceptCipher, ownerOnPrimary: true)
                    { RetainedEnvelope = acceptStore.StoredEnvelope, HasMoreAfterPage = true };
            }
            else
            {
                TrackMailboxDispatchClock();
                terminal = new OwnedReadTerminal(this, [], ownerOnPrimary: true) { ReturnEmptyPage = true };
            }
            var synchronized = await SynchronizeNativeSender(issuer, terminal);
            Assert.Equal(nonempty ? 1 : 0, synchronized.ProcessedEnvelopes);
            Assert.Equal(nonempty, synchronized.HasMore);
            await RenewNativeSenderPublicationPastExpiryAsync();
            byte[] acquisition;
            using (var grants = await ReadPeerGrantsAsync(own: true))
            {
                var selected = grants.Entries.Single(pair => FixedTestRoute(pair.Value, original.Route.ExactHash.Span));
                acquisition = Convert.FromHexString(selected.Key);
            }
            await AdvanceNetworkAsync(expiry: 6_000);
            AuthorSignedEpochAdvance();
            var elapsed = checked(2_100UL - ProofTime); ProofTime += elapsed; Sample += elapsed;
            var account = ReopenAccount();
            _ = await Source(account).VerifyForOwnPreKeyAuthoringAsync(account, default);
            using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
            {
                var failure = await Assert.ThrowsAsync<IOException>(() => exclusion.RetireArchivedReadPathAsync());
                Assert.Contains("accepted-object retention", failure.Message, StringComparison.Ordinal);
            }
            using (var idle = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException())
                Assert.Equal(0, idle.Use(bytes => bytes[1]));
            if (beforeHorizonOnly)
            {
                using var publications = await RouteState(); Assert.Equal(2, publications.Entries.Count);
                using var retained = await ReadPeerGrantsAsync(own: true); Assert.True(retained.Entries.ContainsKey(Convert.ToHexString(acquisition)));
                Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls);
                CryptographicOperations.ZeroMemory(acquisition); return;
            }
            var horizon = checked(BinaryPrimitives.ReadUInt64BigEndian(original.Route.Authorization.Field(13).Span) +
                (ulong)MailboxClientLimits.MaximumTtlSeconds + 31);
            var future = checked(horizon - ProofTime); ProofTime += future; Sample += future;
            await AdvanceObjectHorizonAuthorityAsync();
            account = ReopenAccount();
            _ = await Source(account).VerifyForOwnPreKeyAuthoringAsync(account, default);
            var accountId = (await account.GetCurrentAsync())!.AccountId.ToArray();
            var native = (await account.ReadOwnMailboxReplayFenceAsync()).Digest.ToArray();
            var readScope = ClientMailboxScope.Derive(original.Route.ExactHash.Span, new BlindedMailboxId(original.Route.Reachability.Field(2).Span),
                BinaryPrimitives.ReadUInt64BigEndian(original.Route.Selection.Field(4).Span));
            var originalSql = await ArchivedPathSqlProjection(accountId, original.Route.ExactHash);
            var originalRoots = await ArchivedPathRootSnapshot();
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            byte[] currentPublication;
            using (var publications = await RouteState()) currentPublication = publications.Entries[Convert.ToHexString(plan.Intent.Span)].Exact.ToArray();
            if (hostileSql)
                await CheckArchivedPathHostileSqlAsync(account, acquisition, accountId, original.Route, readScope, native, nonempty);
            if (hostileProtected)
                await CheckArchivedPathProtectedDependenciesAsync(account, acquisition, accountId, original.Route, readScope, plan.Intent);
            if (hostileRecovery)
            {
                using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
                using (Did2CompactionTestHooks.Push(point =>
                    { if (point == Did2CompactionFailpoint.AfterStage) throw new IOException("Injected prepared retained-path stop."); }))
                    await Assert.ThrowsAsync<IOException>(() => exclusion.RetireArchivedReadPathAsync());
                await CheckPreparedArchivedPathRefusalsAsync(accountId, original.Route.ExactHash, readScope);
                account = ReopenAccount();
            }
            var points = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSql,
                Did2CompactionFailpoint.AfterSqlRecorded, Did2CompactionFailpoint.AfterHistoryAdopted,
                Did2CompactionFailpoint.AfterHistoryAdopted, Did2CompactionFailpoint.AfterHistoryAdopted,
                Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
            using var cancellation = new CancellationTokenSource();
            var adoptions = 0; var hit = false;
            using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
            using (Did2CompactionTestHooks.Push(point =>
            {
                if (point == Did2CompactionFailpoint.AfterHistoryAdopted) adoptions++;
                if (handover < 0 || point != points[handover] || handover is >= 3 and <= 5 && adoptions != handover - 2) return;
                hit = true;
                if (cancel) cancellation.Cancel(); else throw new IOException("Injected joint retained-path handover.");
            }))
            {
                if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => exclusion.RetireArchivedReadPathAsync(cancellation.Token));
                else if (handover >= 0) await Assert.ThrowsAsync<IOException>(() => exclusion.RetireArchivedReadPathAsync());
                else await exclusion.RetireArchivedReadPathAsync();
            }
            if (handover >= 0) Assert.True(hit);
            ColdReopenCompactionStorage();
            var recovery = SenderCompactionOwner();
            var abandoned = cancel && handover == 0;
            if (abandoned) await recovery.AbandonUncommittedRetainedPathAsync(default);
            else
            {
                if (handover == 1)
                    await Assert.ThrowsAsync<CryptographicException>(() => recovery.AbandonUncommittedRetainedPathAsync(default));
                else if (handover is >= 2 and <= 6)
                    await Assert.ThrowsAsync<InvalidOperationException>(() => recovery.AbandonUncommittedRetainedPathAsync(default));
                await recovery.ResumeOwnedLocalCompactionAsync(default);
            }
            using (var idle = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException()) Assert.Equal(0, idle.Use(bytes => bytes[1]));
            using (var publications = await RouteState())
            {
                Assert.Equal(abandoned ? 2 : 1, publications.Entries.Count);
                Assert.Equal(currentPublication, publications.Entries[Convert.ToHexString(plan.Intent.Span)].Exact.ToArray());
            }
            using (var grants = await ReadPeerGrantsAsync(own: true)) Assert.Equal(abandoned, grants.Entries.ContainsKey(Convert.ToHexString(acquisition)));
            using (var read = await ReadPeerMailboxReads(own: true)) Assert.Equal(abandoned, read.Traversals.ContainsKey(Convert.ToHexString(readScope.Value)));
            var finalRoots = await ArchivedPathRootSnapshot();
            for (var i = 0; i < finalRoots.Length; i++)
                if (abandoned || i >= 3) Assert.Equal(originalRoots[i], finalRoots[i]);
            if (abandoned) Assert.Equal(originalSql, await ArchivedPathSqlProjection(accountId, original.Route.ExactHash));
            else
            {
                await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                {
                    using var query = sql.CreateCommand();
                    query.CommandText = "SELECT (SELECT count(*) FROM mailbox_credential_scopes WHERE issuer_context=$route)+(SELECT count(*) FROM client_mailbox_traversal WHERE scope=$scope)+(SELECT count(*) FROM client_mailbox_poll_clock WHERE scope=$scope);";
                    query.Parameters.AddWithValue("$route", original.Route.ExactHash.ToArray()); query.Parameters.AddWithValue("$scope", readScope.Value.ToArray());
                    Assert.Equal(0L, (long)query.ExecuteScalar()!);
                });
            }
            var reopened = ReopenAccount();
            Assert.Equal(native, (await reopened.ReadOwnMailboxReplayFenceAsync()).Digest.ToArray());
            if (sender is not null)
            {
                Assert.Equal(Did2ContactAcceptanceState.PeerAcceptanceRetained, await ReadOwnedContactState(sender));
                using var replay = await ReceiveOwnedMessage(sender, acceptCipher!);
            }
            Assert.Equal(1, issuer.Calls); Assert.Equal(1, terminal.RetrieveCalls); Assert.Equal(nonempty ? 1 : 0, terminal.AckCalls);
            foreach (var bytes in new[] { acquisition, accountId, native, originalSql, currentPublication }) CryptographicOperations.ZeroMemory(bytes);
            if (acceptCipher is not null) CryptographicOperations.ZeroMemory(acceptCipher);
        }

        private static bool FixedTestRoute(byte[] entry, ReadOnlySpan<byte> route) =>
            ContactRouteClosureCodec.Decode(ProtectedDid2MailboxGrantJournal.OriginalRoute(entry).Span).ExactHash.Span.SequenceEqual(route);

        private async Task CheckPreparedArchivedPathRefusalsAsync(byte[] accountId, ReadOnlyMemory<byte> route, ClientMailboxScope scope)
        {
            ColdReopenCompactionStorage();
            using var staged = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            var exactPlan = staged.Use(bytes => bytes.ToArray());
            using var plan = Did2CompactionPlan.Decode(exactPlan, Network, accountId, exactPlan.AsSpan(64, 32));
            Assert.Equal(1, plan.Phase);
            var firstSlot = ProtectedDid2CompactionPlan.PartSlot(0);
            var extraSlot = ProtectedDid2CompactionPlan.PartSlot(plan.PartCount);
            using var first = await storage.ReadOwnedAsync(firstSlot) ?? throw new InvalidDataException();
            var originalPart = first.Use(bytes => bytes.ToArray());
            var corruptPart = originalPart.ToArray(); corruptPart[^1] ^= 1;
            var roots = await ArchivedPathRootSnapshot();
            var baselineSql = await ArchivedPathSqlProjection(accountId, route);
            byte[] generation = [];
            await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
            {
                using var query = sql.CreateCommand(); query.CommandText = "SELECT generation FROM client_mailbox_poll_clock WHERE scope=$scope;";
                query.Parameters.AddWithValue("$scope", scope.Value.ToArray()); generation = (byte[])query.ExecuteScalar()!;
            });
            try
            {
                foreach (var fault in new[] { "lost-part", "changed-part", "extra-part", "changed-sql" })
                {
                    if (fault == "lost-part") await storage.DeleteBatchAsync([firstSlot]);
                    else if (fault == "changed-part") Assert.True(await storage.CompareExchangeAsync(firstSlot, originalPart, corruptPart));
                    else if (fault == "extra-part") await storage.WriteBatchAsync([new DeepSecureStorageWrite(extraSlot, originalPart)]);
                    else await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                    {
                        using var query = sql.CreateCommand(); query.CommandText = "DELETE FROM client_mailbox_poll_clock WHERE scope=$scope;";
                        query.Parameters.AddWithValue("$scope", scope.Value.ToArray()); Assert.Equal(1, query.ExecuteNonQuery());
                    });
                    var damagedSql = await ArchivedPathSqlProjection(accountId, route);
                    try
                    {
                        for (var attempt = 0; attempt < 2; attempt++)
                        {
                            ColdReopenCompactionStorage();
                            await Assert.ThrowsAsync<InvalidDataException>(() => SenderCompactionOwner().ResumeOwnedLocalCompactionAsync(default));
                            using var unchanged = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                            Assert.Equal(exactPlan, unchanged.Use(bytes => bytes.ToArray()));
                            var actualRoots = await ArchivedPathRootSnapshot();
                            for (var index = 0; index < roots.Length; index++) Assert.Equal(roots[index], actualRoots[index]);
                            Assert.Equal(damagedSql, await ArchivedPathSqlProjection(accountId, route));
                            using var actualPart = await storage.ReadOwnedAsync(firstSlot);
                            if (fault == "lost-part") Assert.Null(actualPart);
                            else Assert.Equal(fault == "changed-part" ? corruptPart : originalPart, actualPart!.Use(bytes => bytes.ToArray()));
                            using var extra = await storage.ReadOwnedAsync(extraSlot);
                            if (fault == "extra-part") Assert.Equal(originalPart, extra!.Use(bytes => bytes.ToArray()));
                            else Assert.Null(extra);
                        }
                    }
                    finally
                    {
                        // Isolated hostile-fixture restoration, never product recovery.
                        if (fault == "lost-part") await storage.WriteBatchAsync([new DeepSecureStorageWrite(firstSlot, originalPart)]);
                        else if (fault == "changed-part") Assert.True(await storage.CompareExchangeAsync(firstSlot, corruptPart, originalPart));
                        else if (fault == "extra-part") await storage.DeleteBatchAsync([extraSlot]);
                        else await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                        {
                            using var query = sql.CreateCommand(); query.CommandText = "INSERT INTO client_mailbox_poll_clock(scope,generation) VALUES($scope,$value);";
                            query.Parameters.AddWithValue("$scope", scope.Value.ToArray()); query.Parameters.AddWithValue("$value", generation);
                            Assert.Equal(1, query.ExecuteNonQuery());
                        });
                        CryptographicOperations.ZeroMemory(damagedSql);
                    }
                    Assert.Equal(baselineSql, await ArchivedPathSqlProjection(accountId, route));
                }
                await SenderCompactionOwner().AbandonUncommittedRetainedPathAsync(default);
                Assert.Equal(baselineSql, await ArchivedPathSqlProjection(accountId, route));
            }
            finally
            {
                foreach (var bytes in new[] { exactPlan, originalPart, corruptPart, baselineSql, generation })
                    CryptographicOperations.ZeroMemory(bytes);
            }
        }

        private async Task CheckArchivedPathHostileSqlAsync(DeepIdV2AccountService account, byte[] acquisition,
            byte[] accountId, ParsedContactRouteClosure route, ClientMailboxScope scope, byte[] native, bool nonempty)
        {
            byte[] generation = [], counterScope = [], counter = [], cursor = [], token = [];
            await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
            {
                using var query = sql.CreateCommand();
                query.Parameters.AddWithValue("$scope", scope.Value.ToArray());
                query.CommandText = "SELECT generation FROM client_mailbox_poll_clock WHERE scope=$scope;";
                generation = (byte[])query.ExecuteScalar()!; Assert.NotEqual(0UL, BinaryPrimitives.ReadUInt64BigEndian(generation));
                query.CommandText = "SELECT after_cursor,continuation_token FROM client_mailbox_traversal WHERE scope=$scope;";
                using (var rows = query.ExecuteReader())
                    if (rows.Read()) { cursor = (byte[])rows[0]; token = (byte[])rows[1]; Assert.False(rows.Read()); }
                query.CommandText = "SELECT c.scope_id,c.next_counter FROM mailbox_replay_counters c JOIN mailbox_credential_scopes s ON s.scope_id=c.scope_id WHERE s.issuer_context=$route;";
                query.Parameters.AddWithValue("$route", route.ExactHash.ToArray());
                using var counters = query.ExecuteReader(); Assert.True(counters.Read());
                counterScope = (byte[])counters[0]; counter = (byte[])counters[1]; Assert.False(counters.Read());
                Assert.True(BinaryPrimitives.ReadUInt64BigEndian(counter) >= 2);
            });
            var faults = new List<string> { "missing-poll", "changed-poll", "zero-replay" };
            if (nonempty)
            {
                Assert.Equal(8, cursor.Length);
                Assert.True(BinaryPrimitives.ReadUInt64BigEndian(cursor) != 0 || token.Length != 0);
                faults.Add("missing-nonempty-cursor");
            }
            var roots = await ArchivedPathRootSnapshot();
            var baselineSql = await ArchivedPathSqlProjection(accountId, route.ExactHash);
            using var idle = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
            var plan = idle.Use(bytes => bytes.ToArray());
            try
            {
                foreach (var fault in faults)
                {
                    using (var exclusion = await account.OpenMailboxEpochExclusionAsync(acquisition, Source(account)))
                    {
                        // Test-only hostile database writes deliberately bypass
                        // the fixture lease while the product owner holds it.
                        async Task Sql(Action<Microsoft.Data.Sqlite.SqliteCommand> action) =>
                            await WithOwnedApplicationConnectionAsync(true, Network, accountId, db =>
                            {
                                using var command = db.CreateCommand();
                                command.Parameters.AddWithValue("$scope", scope.Value.ToArray());
                                command.Parameters.AddWithValue("$counterScope", counterScope);
                                action(command);
                            }, acquireOwnerLease: false);
                        await Sql(command =>
                        {
                            command.CommandText = fault switch
                            {
                                "missing-poll" => "DELETE FROM client_mailbox_poll_clock WHERE scope=$scope;",
                                "changed-poll" => "UPDATE client_mailbox_poll_clock SET generation=$value WHERE scope=$scope;",
                                "zero-replay" => "UPDATE mailbox_replay_counters SET next_counter=$value WHERE scope_id=$counterScope;",
                                "missing-nonempty-cursor" => "DELETE FROM client_mailbox_traversal WHERE scope=$scope;",
                                _ => throw new InvalidOperationException()
                            };
                            var changed = new byte[8];
                            if (fault == "changed-poll") BinaryPrimitives.WriteUInt64BigEndian(changed,
                                checked(BinaryPrimitives.ReadUInt64BigEndian(generation) + 1));
                            command.Parameters.AddWithValue("$value", changed);
                            Assert.Equal(1, command.ExecuteNonQuery());
                        });
                        byte[] damagedSql = [];
                        await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                            damagedSql = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, route.ExactHash.Span, default),
                            acquireOwnerLease: false);
                        try
                        {
                            for (var attempt = 0; attempt < 2; attempt++)
                            {
                                await Assert.ThrowsAsync<CryptographicException>(() => exclusion.RetireArchivedReadPathAsync());
                                using var unchanged = await storage.ReadOwnedAsync(Did2CompactionPlan.Slot) ?? throw new InvalidDataException();
                                Assert.Equal(plan, unchanged.Use(bytes => bytes.ToArray()));
                                var actualRoots = await ArchivedPathRootSnapshot();
                                for (var index = 0; index < roots.Length; index++) Assert.Equal(roots[index], actualRoots[index]);
                                await WithOwnedApplicationConnectionAsync(true, Network, accountId, sql =>
                                    Assert.Equal(damagedSql, SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, route.ExactHash.Span, default)),
                                    acquireOwnerLease: false);
                            }
                        }
                        finally
                        {
                            // Restore only this isolated fixture's deliberately
                            // damaged row; this is not a runtime repair path.
                            await Sql(command =>
                            {
                                command.CommandText = fault switch
                                {
                                    "missing-poll" => "INSERT INTO client_mailbox_poll_clock(scope,generation) VALUES($scope,$value);",
                                    "changed-poll" => "UPDATE client_mailbox_poll_clock SET generation=$value WHERE scope=$scope;",
                                    "zero-replay" => "UPDATE mailbox_replay_counters SET next_counter=$value WHERE scope_id=$counterScope;",
                                    "missing-nonempty-cursor" => "INSERT INTO client_mailbox_traversal(scope,after_cursor,continuation_token) VALUES($scope,$cursor,$token);",
                                    _ => throw new InvalidOperationException()
                                };
                                command.Parameters.AddWithValue("$value", fault == "zero-replay" ? counter : generation);
                                command.Parameters.AddWithValue("$cursor", cursor); command.Parameters.AddWithValue("$token", token);
                                Assert.Equal(1, command.ExecuteNonQuery());
                            });
                            CryptographicOperations.ZeroMemory(damagedSql);
                        }
                    }
                    Assert.Equal(baselineSql, await ArchivedPathSqlProjection(accountId, route.ExactHash));
                    Assert.Equal(native, (await account.ReadOwnMailboxReplayFenceAsync()).Digest.ToArray());
                }
            }
            finally
            {
                foreach (var bytes in new[] { generation, counterScope, counter, cursor, token, baselineSql, plan })
                    CryptographicOperations.ZeroMemory(bytes);
            }
        }

        // Two genuine paired renewals are needed because the original DTS ends
        // at9000 and each policy is bounded to30days. No genesis reset, widened
        // DTS/head or synthetic freshness enters the actual owned scenario.
        private async Task AdvanceObjectHorizonAuthorityAsync()
        {
            Assert.NotNull(successor); Assert.NotNull(epochSuccessorPmt);
            var authorities = new List<ReadOnlyMemory<byte>> { bootstrap.ExactXna1 };
            var policies = new List<ReadOnlyMemory<byte>> { bootstrap.ExactDts1 };
            foreach (var (from, until) in new[] { (8_500UL, 2_592_500UL), (2_580_000UL, 2_700_000UL) })
            {
                var previous = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin, authorities, policies);
                var renewedRoot = await XPointNetworkBootstrapAuthor.AuthorSameKeyRenewalAsync(Bytes(32, 0x16), previous,
                    policies, from, from, 3_100_000, from, until, [root]);
                authorities.Add(renewedRoot.ExactXna1); policies.Add(renewedRoot.ExactDts1);
            }
            objectHorizonAuthority = XPointNetworkAuthorityVerifier.Verify(bootstrap.GenesisPin, authorities, policies);
            Assert.Equal(2UL, objectHorizonAuthority.AuthorityGeneration);
            Assert.Equal(bootstrap.ExactXna1.ToArray(), authorities[0].ToArray());
            retainedIssuanceHistory ??= new() { [0] = genesis.ProtectedHead };
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            var fromTime = checked(CurrentProofTime - 10); var untilTime = checked(CurrentProofTime + 3_600);
            head = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(objectHorizonAuthority, head.ProtectedHead,
                new(head.ExactAllTransitions, peerCheckpoint is null ? [checkpoint] : [checkpoint, peerCheckpoint], [], fromTime, untilTime, 2), witnesses);
            retainedIssuanceHistory[head.ProtectedHead.LogGeneration] = head.ProtectedHead;
            var rollovers = nodes.Select((signer, index) => new XPointNetworkOperationalNodeRollover(signer,
                Bytes(32, checked((byte)(0x60 + index))), Bytes(32, checked((byte)(0x68 + index))),
                ScalarMult.Base(Bytes(32, checked((byte)(0x80 + index)))), ScalarMult.Base(Bytes(32, checked((byte)(0x88 + index)))))).ToArray();
            var renewed = await XPointNetworkOperationalSuccessorAuthor.AuthorAsync(new(Bytes(32, 0x15), objectHorizonAuthority,
                [root], witnesses, rollovers, successor!.ExactXvp1, successor.ExactXnd1,
                [operational.ExactXnv1, successor.ExactXnv1], successor.ExactXnh1, successor.ExactPma2, epochSuccessorPmt!.Value,
                XPointNetworkOperationalSuccessorAuthor.ComputeXnh1CoreHash(successor.ExactXnh1.Span),
                ContactCodec.Decode("PMT2", epochSuccessorPmt.Value.Span).ArtifactHash.Span,
                HeadReference(head.CoreHash.Span), fromTime, fromTime, untilTime));
            objectHorizonClosure = new(authorities, policies,
                [operational.ExactXvp1, successor.ExactXvp1, renewed.ExactXvp1],
                [operational.ExactXnv1, successor.ExactXnv1, renewed.ExactXnv1],
                [operational.ExactXnh1, successor.ExactXnh1, renewed.ExactXnh1], renewed.ExactXnd1,
                [operational.ExactPmt2, epochSuccessorPmt.Value, renewed.ExactPmt2],
                [operational.ExactPma2, successor.ExactPma2, renewed.ExactPma2]);
        }

        private async Task<byte[]> ArchivedPathSqlProjection(byte[] account, ReadOnlyMemory<byte> route)
        {
            byte[] result = [];
            await WithOwnedApplicationConnectionAsync(true, Network, account, sql =>
                result = SqliteDeepMailboxStore.ReadCompleteLocalSqlProjection(sql, route.Span, default));
            return result;
        }

        private async Task<byte[][]> ArchivedPathRootSnapshot()
        {
            var slots = new[] { ProtectedDid2MailboxGrantJournal.Slot, ProtectedDid2MailboxReadJournal.Slot, ProtectedDid2ContactRouteJournal.Slot,
                ProtectedDid2MailboxSendJournal.Slot, ProtectedDid2DirectTextJournal.Slot, ProtectedDid2MessagingSessionCatalog.Slot,
                ProtectedDid2AttachmentJournal.Slot, ProtectedDid2ContactStartJournal.Slot, ProtectedDid2ContactAcceptJournal.Slot };
            var hashes = new List<byte[]>();
            foreach (var slot in slots)
            { using var raw = await storage.ReadOwnedAsync(slot) ?? throw new InvalidDataException(); hashes.Add(raw.Use(bytes => SHA256.HashData(bytes))); }
            return hashes.ToArray();
        }
    }
}
