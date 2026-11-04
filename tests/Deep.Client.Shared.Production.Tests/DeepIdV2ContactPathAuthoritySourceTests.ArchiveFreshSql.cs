using System.Data;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_ProviderEdgeClosesPhysicalConnectionAndSelectedRawPageChangeRejects()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await fixture.PrepareActiveNativePair();
        await fixture.CompactActiveNativePrefix(sender, checked((int)(await fixture.ReadMessagingFloor(sender)).Ordinal));
        await fixture.CheckArchiveFreshPhysicalRead(sender);
    }

    private sealed partial class Fixture
    {
        internal async Task CheckArchivePostProofTuple(Did2MessagingSessionScope scope)
        {
            using var writer = await ArchiveFixtureWriter(scope);
            byte[] operation = [], metadata = [], envelope = []; long rowid = 0;
            writer.Execute(connection =>
            {
                using var query = connection.CreateCommand(); query.CommandText = "SELECT rowid,operation,metadata,envelope FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
                using var row = query.ExecuteReader(); Assert.True(row.Read()); rowid = row.GetInt64(0);
                operation = row.GetFieldValue<byte[]>(1); metadata = row.GetFieldValue<byte[]>(2); envelope = row.GetFieldValue<byte[]>(3);
            });
            var changedMetadata = metadata.ToArray(); var changedEnvelope = envelope.ToArray(); changedEnvelope[^1] ^= 1;
            MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(Dpe2Codec.Decode(changedEnvelope)).CopyTo(changedMetadata, 332);
            try
            {
                await WithArchiveOwnedStorage(scope, async opened =>
                {
                    var floor = await ReadMessagingFloor(scope); var hit = false;
                    using (Did2ActiveReadTestHooks.Push(() =>
                    {
                        hit = true;
                        writer.Execute(connection =>
                        {
                            using var change = connection.CreateCommand();
                            change.CommandText = "UPDATE events SET metadata=$metadata,envelope=$envelope WHERE rowid=$rowid;";
                            change.Parameters.AddWithValue("$metadata", changedMetadata); change.Parameters.AddWithValue("$envelope", changedEnvelope);
                            change.Parameters.AddWithValue("$rowid", rowid); Assert.Equal(1, change.ExecuteNonQuery());
                        });
                    }))
                        await Assert.ThrowsAsync<CryptographicException>(async () =>
                        { using var rejected = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), default); });
                    Assert.True(hit);
                    Restore();
                    using var restored = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), default); Assert.NotNull(restored);
                });
            }
            finally
            {
                Restore(); foreach (var bytes in new[] { operation, metadata, envelope, changedMetadata, changedEnvelope }) CryptographicOperations.ZeroMemory(bytes);
            }
            void Restore() => writer.Execute(connection =>
            {
                using var restore = connection.CreateCommand(); restore.CommandText = "UPDATE events SET metadata=$metadata,envelope=$envelope WHERE rowid=$rowid;";
                restore.Parameters.AddWithValue("$metadata", metadata); restore.Parameters.AddWithValue("$envelope", envelope);
                restore.Parameters.AddWithValue("$rowid", rowid); Assert.Equal(1, restore.ExecuteNonQuery());
            });
        }

        internal async Task CheckArchivePostProofBounds(Did2MessagingSessionScope scope, string column)
        {
            using var writer = await ArchiveFixtureWriter(scope);
            byte[] operation = []; object original = DBNull.Value; long rowid = 0;
            writer.Execute(connection =>
            {
                using var query = connection.CreateCommand(); query.CommandText = "SELECT rowid,operation FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
                using (var row = query.ExecuteReader()) { Assert.True(row.Read()); rowid = row.GetInt64(0); operation = row.GetFieldValue<byte[]>(1); }
                using var value = connection.CreateCommand();
                value.CommandText = column == "ratchet" ? "SELECT exact_state FROM ratchet WHERE singleton=1;" : "SELECT " + column + " FROM events WHERE rowid=$rowid;";
                if (column != "ratchet") value.Parameters.AddWithValue("$rowid", rowid); original = value.ExecuteScalar() ?? DBNull.Value;
            });
            try
            {
                await WithArchiveOwnedStorage(scope, async opened =>
                {
                    var floor = await ReadMessagingFloor(scope); var hit = false;
                    using (Did2ActiveReadTestHooks.Push(() =>
                    {
                        hit = true;
                        writer.Execute(connection =>
                        {
                            using var change = connection.CreateCommand();
                            change.CommandText = "PRAGMA ignore_check_constraints=ON; " + (column == "ratchet" ?
                                "UPDATE ratchet SET exact_state=zeroblob(33554432) WHERE singleton=1;" :
                                "UPDATE events SET " + column + "=zeroblob(33554432) WHERE rowid=$rowid;");
                            if (column != "ratchet") change.Parameters.AddWithValue("$rowid", rowid); Assert.Equal(1, change.ExecuteNonQuery());
                        });
                    }))
                    {
                        if (column == "ratchet") await Assert.ThrowsAsync<InvalidDataException>(async () =>
                            { using var rejected = await opened.WithSqlAsync(sql => sql.ReadVerifiedLatest(floor), default); });
                        else await Assert.ThrowsAsync<CryptographicException>(async () =>
                            { using var rejected = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), default); });
                    }
                    Assert.True(hit); Restore();
                    using var restored = await opened.WithSqlAsync(sql => sql.ReadVerifiedOperation(floor, operation), default); Assert.NotNull(restored);
                });
            }
            finally { Restore(); CryptographicOperations.ZeroMemory(operation); if (original is byte[] bytes) CryptographicOperations.ZeroMemory(bytes); }
            void Restore() => writer.Execute(connection =>
            {
                using var restore = connection.CreateCommand(); restore.CommandText = column == "ratchet" ?
                    "UPDATE ratchet SET exact_state=$value WHERE singleton=1;" : "UPDATE events SET " + column + "=$value WHERE rowid=$rowid;";
                restore.Parameters.AddWithValue("$value", original); if (column != "ratchet") restore.Parameters.AddWithValue("$rowid", rowid);
                Assert.Equal(1, restore.ExecuteNonQuery());
            });
        }

        internal async Task WithArchiveOwnedStorage(Did2MessagingSessionScope scope, Func<OwnedDid2MessagingStorage, Task> inspect)
        {
            Assert.True(scope.IsInitiator);
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2");
            var lease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(storage, lease, path, Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            using var held = await lease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(storage, path, current, scope, default);
            await inspect(opened); held.RequireOwner(lease);
        }

        private async Task<ArchiveExternalWriter> ArchiveFixtureWriter(Did2MessagingSessionScope scope)
        {
            using var raw = await NativeStorage(scope).ReadOwnedAsync(ProtectedDid2MessagingSessionCatalog.Slot) ?? throw new InvalidDataException();
            using var catalog = raw.Use(bytes => ProtectedDid2MessagingSessionCatalog.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
            using var key = catalog.ReadKey(catalog.FindExact(scope));
            var folder = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var path = Path.Combine(folder, "deep-store-v2-account.dsv2.messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            return key.Use(bytes => new ArchiveExternalWriter(path, bytes.ToArray()));
        }
        // Deliberately adversarial test-only writer owns a private copy, never
        // a runtime/provider key loan or a connection borrowed by a hook.
        private sealed class ArchiveExternalWriter(string path, byte[] key) : IDisposable
        {
            internal void Execute(Action<SqliteConnection> operation)
            { using var connection = SqliteDeepIdV2AccountGeneration.OpenMessagingConnectionForTests(path, key, false); operation(connection); }
            public void Dispose() => CryptographicOperations.ZeroMemory(key);
        }

        internal async Task CheckArchiveFreshPhysicalRead(Did2MessagingSessionScope scope)
        {
            byte[] operation = []; var pageNumber = 0L; var pageSize = 0;
            await WithArchiveFixtureSql(scope, connection =>
            {
                using var selected = connection.CreateCommand(); selected.CommandText = "SELECT operation FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
                operation = Assert.IsType<byte[]>(selected.ExecuteScalar());
                using var page = connection.CreateCommand(); page.CommandText = "SELECT rootpage FROM sqlite_schema WHERE type='table' AND name='events';";
                pageNumber = Convert.ToInt64(page.ExecuteScalar());
                using var size = connection.CreateCommand(); size.CommandText = "PRAGMA page_size;"; pageSize = Convert.ToInt32(size.ExecuteScalar());
            });
            Assert.True(pageNumber > 1); Assert.True(pageSize >= 512);
            var path = Path.Combine(directory, "deep-store-v2-account.dsv2.messaging", Convert.ToHexStringLower(scope.Hash) + ".dms2");
            var offset = checked((pageNumber - 1) * pageSize); var originalPage = new byte[pageSize];
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            { file.Position = offset; file.ReadExactly(originalPage); }
            var accountLease = new DeepIdV2AccountFileLease(Path.Combine(directory, "deep-store-v2-account.lock"));
            var owner = new ProtectedDeepIdV2AccountOwner(storage, accountLease,
                Path.Combine(directory, "deep-store-v2-account.dsv2"), Network, 1);
            using var current = await owner.ReadCurrentAsync(1_000, pq, default) ?? throw new InvalidDataException();
            using var held = await accountLease.AcquireAsync(default);
            using var opened = await SqliteDeepIdV2AccountGeneration.OpenOrdinaryMessagingUnderLeaseAsync(storage,
                Path.Combine(directory, "deep-store-v2-account.dsv2"), current, scope, default);
            var floor = await ReadMessagingFloor(scope); SqliteConnection? first = null, second = null;
            using (var selected = await opened.WithSqlAsync(sql =>
            {
                first = ActualConnection(sql); Assert.Equal(ConnectionState.Open, first.State);
                return sql.ReadVerifiedOperation(floor, operation);
            }, default)) Assert.NotNull(selected);
            Assert.NotNull(first); Assert.Equal(ConnectionState.Closed, first!.State);
            var hit = false; var damaged = originalPage.ToArray(); damaged[100] ^= 1;
            try
            {
                storage.AfterMessagingRegistrationReadGroup = () =>
                {
                    hit = true; Assert.Equal(ConnectionState.Closed, first.State);
                    WritePage(damaged);
                };
                var error = await Record.ExceptionAsync(async () =>
                {
                    using var rejected = await opened.WithSqlAsync(sql =>
                    {
                        second = ActualConnection(sql); Assert.Equal(ConnectionState.Open, second.State);
                        Assert.NotSame(first, second);
                        return sql.ReadVerifiedOperation(floor, operation);
                    }, default);
                });
                Assert.True(hit, "The actual protected provider callback did not run.");
                Assert.True(error is SqliteException or CryptographicException or InvalidDataException,
                    "A physically changed selected encrypted page was released from a prior successful read: " + (error?.GetType().Name ?? "none"));
                // Fresh native provenance is checked before entering the
                // consumer. It may reject the damaged page before second is
                // assigned; no failed-open connection may survive either way.
                if (second is not null)
                { Assert.NotSame(first, second); Assert.Equal(ConnectionState.Closed, second.State); }
                var persistedPage = new byte[pageSize];
                try
                {
                    using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    exclusive.Position = offset; exclusive.ReadExactly(persistedPage);
                    Assert.True(persistedPage.AsSpan().SequenceEqual(damaged), "Rejected read repaired or replaced the physically damaged page.");
                }
                finally { CryptographicOperations.ZeroMemory(persistedPage); }
                var stable = await ReadMessagingFloor(scope);
                Assert.True(stable.Exact.Span.SequenceEqual(floor.Exact.Span), "Rejected selected archive read advanced native state.");
            }
            finally
            {
                storage.AfterMessagingRegistrationReadGroup = null; WritePage(originalPage);
                CryptographicOperations.ZeroMemory(originalPage); CryptographicOperations.ZeroMemory(damaged); CryptographicOperations.ZeroMemory(operation);
            }
            void WritePage(byte[] value)
            {
                using var file = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                file.Position = offset; file.Write(value); file.Flush(true);
            }
        }

        private static SqliteConnection ActualConnection(Did2MessagingSqlJournal sql) =>
            Assert.IsType<SqliteConnection>(typeof(Did2MessagingSqlJournal).GetField("connection",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(sql));
    }
}
