using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("AfterSourceFrozen")] [InlineData("AfterSchemaSql")] [InlineData("AfterSchemaStaged")]
    [InlineData("AfterBatchSql")] [InlineData("AfterBatchProgress")]
    [InlineData("AfterFinalSql")] [InlineData("AfterFinalReady")]
    [InlineData("AfterCatalogAndRoot")] [InlineData("AfterAdoptionReadback")] [InlineData("AfterCleanup")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveEnrollment_EveryDurableCutColdResumesExactNativeSource(string cut)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        using var original = await fixture.StageActualLegacyArchiveInput([pair.Sender]);
        var hit = false;
        using (Did2MessagingArchiveEnrollmentTestHooks.Push(point =>
            { if (point.ToString() == cut) { hit = true; throw new IOException("Interrupted explicit archive enrollment."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnrollArchiveAccount());
        Assert.True(hit, "The declared enrollment durability boundary was not reached.");
        await fixture.AssertArchiveSourceUnchanged(original);
        using (var progress = await fixture.NativeStorage(pair.Sender).ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot))
            if (progress is not null)
            {
                if (cut == "AfterSourceFrozen")
                {
                    var frozen = progress.Use(bytes => ProtectedDid2MessagingArchiveEnrollment.Decode(bytes, pair.Sender));
                    Assert.Equal(ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SourceFrozen, frozen.Phase);
                    Assert.True(frozen.SourceHistory.HistoryCount > 0);
                    Assert.Equal(0UL, frozen.Cursor); Assert.Equal(0UL, frozen.Count);
                    Assert.True(frozen.Guard(ProtectedDid2MessagingArchiveEnrollment.GuardKind.OriginalSql)
                        .SequenceEqual(original.Originals[0]), "Stored source guard differs from the independent canonical rowid/cell transcript.");
                    Assert.True(frozen.TargetBasis.Exact.Span.SequenceEqual(frozen.SourceHistory.Basis.Exact.Span));
                    Assert.Throws<InvalidDataException>(() => frozen.FinalRoot(pair.Sender));
                }
                await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ListOwnedMessages(pair.Sender));
                await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.CreateOwnedText(pair.Sender, "blocked during explicit enrollment"));
            }
        fixture.ColdReopenCompactionStorage();
        await fixture.EnrollArchiveAccount();
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(original);
        using (var next = await fixture.CreateOwnedText(pair.Sender, "fresh work after exact archive adoption"))
        using (var sent = await fixture.SendOwnedMessage(pair.Sender, next.OperationId, ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(pair.Receiver, sent.ExactEnvelope.ToArray())) { }
        Assert.Equal(original.Floors[0].Ordinal + 1, (await fixture.ReadMessagingFloor(pair.Sender)).Ordinal);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveEnrollment_TwoActualSessionsAndNewRegistrationStayBlockedUntilWholeAccountCompletes()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var first = await fixture.PrepareArchiveEnrollmentPair(0);
        var second = await fixture.PrepareArchiveEnrollmentPair(1);
        var pending = await fixture.PrepareNativeHelloCompletion(Bytes(32, 0xc8), oneTimeIndex: 2);
        using var completed = await pending.Complete(fixture.Accounts);
        using var original = await fixture.StageActualLegacyArchiveInput([first.Sender, second.Sender]);
        var hit = false;
        using (Did2MessagingArchiveEnrollmentTestHooks.Push(point =>
            { if (point.ToString() == "AfterCatalogAndRoot") { hit = true; throw new IOException("First session adopted before account cleanup."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnrollArchiveAccount());
        Assert.True(hit);
        await fixture.AssertPartiallyIndexedArchiveCatalog(original, indexed: 1);
        foreach (var scope in original.Scopes)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ListOwnedMessages(scope));
            await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.CreateOwnedText(scope, "no new authored work across another session's enrollment"));
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.EnsureSenderMessaging(pending.Init, pending.Hello));
        await fixture.AssertArchiveSourceUnchanged(original);
        fixture.ColdReopenCompactionStorage(); await fixture.EnrollArchiveAccount();
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(original);
        foreach (var scope in original.Scopes) Assert.NotEmpty(await fixture.ListOwnedMessages(scope));
        // Registration is checked through the same previously completed native
        // source after the account-wide barrier is actually gone.
        var registered = await fixture.EnsureSenderMessaging(pending.Init, pending.Hello);
        Assert.False(original.Scopes.Any(scope => scope.Exact.SequenceEqual(registered.Exact)));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveEnrollment_AdoptedMissingRootNeverRebuildsEvenWithFinalReadyProgress()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        using var original = await fixture.StageActualLegacyArchiveInput([pair.Sender]);
        using (Did2MessagingArchiveEnrollmentTestHooks.Push(point =>
            { if (point.ToString() == "AfterCatalogAndRoot") throw new IOException("Adoption committed before release."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnrollArchiveAccount());
        var secure = fixture.NativeStorage(pair.Sender);
        using var progress = await secure.ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot);
        Assert.NotNull(progress);
        Assert.Equal(ProtectedDid2MessagingArchiveEnrollment.PhaseKind.FinalReady,
            progress!.Use(bytes => ProtectedDid2MessagingArchiveEnrollment.Decode(bytes, pair.Sender).Phase));
        await secure.DeleteBatchAsync([Did2MessagingArchiveRoot.Slot(pair.Sender)]);
        fixture.ColdReopenCompactionStorage();
        var error = await Record.ExceptionAsync(() => fixture.EnrollArchiveAccount());
        Assert.True(error is InvalidDataException or CryptographicException, error?.GetType().Name ?? "A missing adopted root was reconstructed.");
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ListOwnedMessages(pair.Sender));
        using var absent = await secure.ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(pair.Sender)); Assert.Null(absent);
        using var stillFenced = await secure.ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot); Assert.NotNull(stillFenced);
        await fixture.AssertArchiveSourceUnchanged(original);
    }

    private sealed partial class Fixture
    {
        internal async Task<(Did2MessagingSessionScope Sender, Did2MessagingSessionScope Receiver)> PrepareArchiveEnrollmentPair(int index)
        {
            var prepared = await PrepareNativeHelloCompletion(Bytes(32, checked((byte)(0xc1 + index))), oneTimeIndex: index);
            using var initial = await prepared.Complete(Accounts);
            using (var received = await CompleteReceiver(initial.ExactDph2.ToArray())) { }
            var sender = await EnsureSenderMessaging(prepared.Init, prepared.Hello);
            var receiver = await EnsureReceiverMessaging(initial.ExactDph2.ToArray());
            var acceptanceOperation = Bytes(32, checked((byte)(0xd1 + index)));
            using (var accept = await PrepareOwnedContactAccept(receiver, acceptanceOperation))
            using (var sent = await SendOwnedMessage(receiver, accept.Operation, ApplicationCoreCodec.DecodeDmc2(accept.ExactDmc2)))
            using (var received = await ReceiveOwnedMessage(sender, sent.ExactEnvelope.ToArray())) { }
            using (var draft = await CreateOwnedText(sender, "actual native archived source " + index))
            using (var sent = await SendOwnedMessage(sender, draft.OperationId, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span)))
            using (var received = await ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
            return (sender, receiver);
        }

        internal Task EnrollArchiveAccount(CancellationToken ct = default) => new ProtectedDeepIdV2AccountOwner(storage,
            new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock")),
            Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, 1).EnrollMessagingArchiveAsync(1_000, pq, ct);

        internal sealed class ArchiveSourceObservation(Did2MessagingSessionScope[] scopes, Did2MessagingFloor[] floors,
            byte[][] histories, byte[][] originals, byte[] catalog, byte[] authored) : IDisposable
        {
            internal Did2MessagingSessionScope[] Scopes { get; } = scopes;
            internal Did2MessagingFloor[] Floors { get; } = floors;
            internal byte[][] Histories { get; } = histories;
            internal byte[][] Originals { get; } = originals;
            internal byte[] Catalog { get; } = catalog;
            internal byte[] Authored { get; } = authored;
            public void Dispose()
            { foreach (var value in Histories.Concat(Originals).Append(Catalog).Append(Authored)) CryptographicOperations.ZeroMemory(value); }
        }

        internal async Task<ArchiveSourceObservation> StageActualLegacyArchiveInput(Did2MessagingSessionScope[] scopes)
        {
            Assert.All(scopes, scope => Assert.True(scope.IsInitiator));
            var floors = new List<Did2MessagingFloor>(); var histories = new List<byte[]>();
            foreach (var scope in scopes)
            {
                var floor = await ReadMessagingFloor(scope); var before = await ReadNativeHistory(scope);
                Assert.Equal(0UL, before.Basis.Ordinal);
                Did2MessagingHistoryCheckpoint? oldHistory = null;
                await WithRouteReadSql(scope, (full, connection) =>
                {
                    // Derive the genuine old protected history with the full
                    // source verifier before reproducing its already-committed
                    // legacy prefix outcome. This is test setup, not enrollment
                    // or compaction authorization and never touches retained data.
                    oldHistory = full.CaptureHistoryPrefix(floor, checked((int)floor.Ordinal));
                    using var transaction = connection.BeginTransaction();
                    using (var trim = connection.CreateCommand())
                    {
                        trim.Transaction = transaction; trim.CommandText = "DELETE FROM journal WHERE ordinal<=$ordinal;";
                        trim.Parameters.AddWithValue("$ordinal", checked((long)floor.Ordinal));
                        Assert.Equal(checked((int)floor.Ordinal), trim.ExecuteNonQuery());
                    }
                    using (var schema = connection.CreateCommand())
                    {
                        schema.Transaction = transaction;
                        schema.CommandText = "DROP TABLE archive_state; DROP TABLE archive_reducers; DROP TABLE archive_nodes; PRAGMA user_version=5;";
                        schema.ExecuteNonQuery();
                    }
                    transaction.Commit();
                });
                Assert.NotNull(oldHistory);
                Assert.True(await storage.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(scope), before.Exact, oldHistory!.Exact));
                floors.Add(floor); histories.Add(oldHistory.Exact.ToArray());
            }
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
            var catalog = owned.Use(bytes => bytes.ToArray());
            using var registered = ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(catalog, Network, scopes[0].LocalAccount, scopes[0].Instance);
            Assert.Equal(scopes.Length, registered.Count);
            catalog[0] = 1;
            for (var index = 0; index < registered.Count; index++) catalog[92 + index * 440 + 1] = 0;
            BinaryPrimitives.WriteUInt64BigEndian(catalog.AsSpan(4), checked((ulong)(1 + registered.Count +
                Enumerable.Range(0, registered.Count).Count(index => registered.Phase(index) == 2))));
            Assert.True(await storage.CompareExchangeAsync(ProtectedDid2MessagingSessionCatalog.Slot, owned.Use(bytes => bytes.ToArray()), catalog));
            await storage.DeleteBatchAsync(scopes.Select(Did2MessagingArchiveRoot.Slot).ToArray());
            var originals = new List<byte[]>();
            foreach (var scope in scopes) originals.Add(await ArchiveOriginalFingerprint(scope));
            using var authored = await storage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.ApplicationStateSlot) ?? throw new InvalidDataException();
            return new(scopes, floors.ToArray(), histories.ToArray(), originals.ToArray(), catalog, authored.Use(bytes => SHA256.HashData(bytes)));
        }

        internal async Task AssertArchiveSourceUnchanged(ArchiveSourceObservation original)
        {
            for (var index = 0; index < original.Scopes.Length; index++)
            {
                var scope = original.Scopes[index]; var actual = await ArchiveOriginalFingerprint(scope);
                Assert.True(actual.AsSpan().SequenceEqual(original.Originals[index]), "Enrollment changed an original SQL cell or events rowid.");
                using var history = await storage.ReadOwnedAsync(Did2MessagingHistoryCheckpoint.Slot(scope));
                Assert.True(history!.Use(bytes => bytes.SequenceEqual(original.Histories[index])), "Enrollment changed immutable source history.");
                var floor = await ReadMessagingFloor(scope);
                Assert.True(floor.Exact.Span.SequenceEqual(original.Floors[index].Exact.Span), "Enrollment advanced native/TRS state.");
            }
            using var authored = await storage.ReadOwnedAsync(SqliteDeepIdV2AccountGeneration.ApplicationStateSlot);
            Assert.True(authored!.Use(bytes => SHA256.HashData(bytes).AsSpan().SequenceEqual(original.Authored)), "Enrollment or blocked work changed authored custody.");
        }

        internal async Task AssertPartiallyIndexedArchiveCatalog(ArchiveSourceObservation original, int indexed)
        {
            var scope = original.Scopes[0];
            using var owned = await storage.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot);
            using var catalog = owned!.Use(bytes => ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, Network, scope.LocalAccount, scope.Instance));
            Assert.Equal(2, catalog.Version); Assert.Equal(indexed, Enumerable.Range(0, catalog.Count).Count(i => catalog.ArchiveState(i) == 1));
            if (indexed == 1 && catalog.Count > 1)
            {
                Assert.Equal(1, catalog.ArchiveState(0));
                using var progress = await storage.ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot);
                Assert.NotNull(progress);
                Assert.True(progress!.Use(bytes => ProtectedDid2MessagingArchiveEnrollment.Decode(bytes, catalog.Scope(0))
                    .ScopeHash.SequenceEqual(catalog.Scope(0).Hash)), "Enrollment did not select the lowest remaining actual scope.");
            }
            var normalized = catalog.Exact.ToArray(); normalized[0] = 1;
            foreach (var i in Enumerable.Range(0, catalog.Count)) normalized[92 + i * 440 + 1] = 0;
            BinaryPrimitives.WriteUInt64BigEndian(normalized.AsSpan(4), BinaryPrimitives.ReadUInt64BigEndian(original.Catalog.AsSpan(4)));
            Assert.True(normalized.AsSpan().SequenceEqual(original.Catalog), "Enrollment changed registration phases, scopes or private keys.");
            CryptographicOperations.ZeroMemory(normalized);
        }

        internal async Task AssertArchiveAdoptedWithoutSourceMutation(ArchiveSourceObservation original)
        {
            await AssertArchiveSourceUnchanged(original);
            await AssertPartiallyIndexedArchiveCatalog(original, original.Scopes.Length);
            using var progress = await storage.ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot); Assert.Null(progress);
            foreach (var scope in original.Scopes)
            {
                using var root = await storage.ReadOwnedAsync(Did2MessagingArchiveRoot.Slot(scope)); Assert.NotNull(root);
                var archive = root!.Use(bytes => Did2MessagingArchiveRoot.Decode(bytes, scope));
                archive.RequireSource(await ReadNativeHistory(scope));
                Assert.Equal(1UL, archive.Revision); Assert.True(archive.ArchiveCount > 0);
                await WithArchiveFixtureSql(scope, connection =>
                {
                    using var mirror = connection.CreateCommand(); mirror.CommandText = "SELECT exact FROM archive_state WHERE singleton=1;";
                    Assert.True(Assert.IsType<byte[]>(mirror.ExecuteScalar()).AsSpan().SequenceEqual(archive.Exact.Span), "SQL mirror did not match the independently adopted root.");
                });
            }
        }

        private async Task<byte[]> ArchiveOriginalFingerprint(Did2MessagingSessionScope scope)
        {
            byte[]? result = null;
            await WithArchiveFixtureSql(scope, connection =>
            {
                using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var ddl = new Dictionary<string, string>(StringComparer.Ordinal);
                using (var schema = connection.CreateCommand())
                {
                    schema.CommandText = "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name IN ('events','initial_events','journal','ratchet','scope') ORDER BY name;";
                    using var rows = schema.ExecuteReader();
                    while (rows.Read()) ddl.Add(rows.GetString(0), rows.GetString(1).TrimEnd(';'));
                }
                Assert.Equal(5, ddl.Count);
                var archiveDdl = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["archive_nodes"] = "CREATE TABLE archive_nodes (hash BLOB PRIMARY KEY NOT NULL CHECK(typeof(hash)='blob' AND length(hash)=32), exact BLOB NOT NULL CHECK(typeof(exact)='blob' AND length(exact) BETWEEN 104 AND 320))",
                    ["archive_reducers"] = "CREATE TABLE archive_reducers (hash BLOB PRIMARY KEY NOT NULL CHECK(typeof(hash)='blob' AND length(hash)=32), exact BLOB NOT NULL CHECK(typeof(exact)='blob' AND length(exact)=960))",
                    ["archive_state"] = "CREATE TABLE archive_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), exact BLOB NOT NULL CHECK(typeof(exact)='blob' AND length(exact)=608))"
                };
                digest.AppendData("Deep/STORE-V2/archive-enrollment-source"u8); digest.AppendData([0]); digest.AppendData(scope.Hash);
                digest.AppendData(SchemaHash(5)); digest.AppendData(SchemaHash(6));
                var application = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(application, 0x444d5332); digest.AppendData(application);
                foreach (var table in new[] { "events", "initial_events", "journal", "ratchet", "scope" })
                {
                    AppendDdl(digest, table, ddl[table]);
                    using var query = connection.CreateCommand();
                    query.CommandText = table == "events" ? "SELECT rowid,* FROM events ORDER BY ordinal;" :
                        "SELECT * FROM " + table + " ORDER BY " + (table == "journal" ? "ordinal" : "singleton") + ";";
                    using var rows = query.ExecuteReader(); var count = 0UL;
                    while (rows.Read())
                    {
                        digest.AppendData([1]); Append64(checked((ulong)rows.FieldCount));
                        for (var cell = 0; cell < rows.FieldCount; cell++)
                        {
                            var value = rows.GetValue(cell);
                            if (value is DBNull) digest.AppendData([0]);
                            else if (value is long number) { digest.AppendData([1]); var raw = new byte[8]; BinaryPrimitives.WriteInt64BigEndian(raw, number); digest.AppendData(raw); }
                            else if (value is byte[] bytes) { digest.AppendData([2]); Append64(checked((ulong)bytes.Length)); digest.AppendData(bytes); }
                            else throw new InvalidDataException("Unexpected original SQL storage type.");
                        }
                        count++;
                    }
                    digest.AppendData([0]); Append64(count);
                }
                result = digest.GetHashAndReset();
                void Append64(ulong value) { var raw = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(raw, value); digest.AppendData(raw); }
                byte[] SchemaHash(int version)
                {
                    using var schema = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    schema.AppendData("Deep/STORE-V2/archive-schema"u8); schema.AppendData([0]);
                    var header = new byte[10]; BinaryPrimitives.WriteUInt32BigEndian(header, 0x444d5332);
                    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4), checked((uint)version));
                    BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(8), checked((ushort)(version == 5 ? 5 : 8))); schema.AppendData(header);
                    foreach (var entry in (version == 5 ? ddl : ddl.Concat(archiveDdl).ToDictionary(pair => pair.Key, pair => pair.Value))
                        .OrderBy(pair => pair.Key, StringComparer.Ordinal)) AppendDdl(schema, entry.Key, entry.Value);
                    return schema.GetHashAndReset();
                }
                static void AppendDdl(IncrementalHash hash, string name, string definition)
                {
                    var nameBytes = Encoding.UTF8.GetBytes(name); var bytes = Encoding.UTF8.GetBytes(definition);
                    var length = new byte[4]; BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)nameBytes.Length));
                    hash.AppendData(length.AsSpan(0, 2)); hash.AppendData(nameBytes);
                    BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length)); hash.AppendData(length); hash.AppendData(bytes);
                }
            });
            return result!;
        }

        internal async Task WithArchiveFixtureSql(Did2MessagingSessionScope scope, Action<SqliteConnection> inspect)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = NativeStorage(scope); var owner = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await owner.AcquireAsync(default);
            using var raw = await secure.ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
            using var catalog = raw.Use(bytes => ProtectedDid2MessagingSessionCatalog.DecodeForEnrollment(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var key = catalog.ReadKey(catalog.FindExact(scope));
            var path = Path.Combine(accountDirectory, "deep-store-v2-account.dsv2.messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            using var connection = key.Use(bytes => SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, bytes, false));
            inspect(connection); held.RequireOwner(owner);
        }
    }
}
