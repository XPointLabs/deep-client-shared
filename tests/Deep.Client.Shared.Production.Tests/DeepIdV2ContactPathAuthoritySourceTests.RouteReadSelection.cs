using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, "route-marker")]
    [InlineData(true, "route-marker")]
    [InlineData(false, "ordinary-plaintext")]
    [InlineData(true, "ordinary-plaintext")]
    [InlineData(false, "ordinary-envelope")]
    [InlineData(true, "ordinary-envelope")]
    [InlineData(false, "missing-route")]
    [InlineData(true, "missing-route")]
    [InlineData(false, "ordinary-plaintext-type")]
    [InlineData(true, "ordinary-plaintext-type")]
    [InlineData(false, "ordinary-envelope-type")]
    [InlineData(true, "ordinary-envelope-type")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2RouteRead_FilteredNativeSelectionStillAuthenticatesEveryRow(bool compact, string defect)
    {
        // Genuine owned contact, native send/receive and SQLCipher. The fixture
        // tampers only its own registered SQL after positive read-back checks.
        await using var fixture = await Fixture.CreateAsync(withPeer: true,
            encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        async Task<byte[]> SendOrdinary(string text)
        {
            using var command = await fixture.CreateOwnedText(sender, text);
            using var sent = await fixture.SendOwnedMessage(sender, command.OperationId,
                ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            return command.OperationId.ToArray();
        }
        var ordinaryOperation = await SendOrdinary("ordinary before route");
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        using var route = await fixture.CreateOwnedRouteUpdate(sender);
        var routeOperation = route.OperationId.ToArray();
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, routeOperation))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            Assert.Equal(1, received.RouteProcessing[0]);
        _ = await SendOrdinary("ordinary after route");
        if (compact)
        {
            await fixture.CompactHistoricalPeerRoutePrefix(receiver);
            fixture.ColdReopenReceiverStoreStorage();
        }
        var floor = await fixture.ReadMessagingFloor(receiver);
        await fixture.WithRouteReadSql(receiver, (sql, connection) =>
        {
            var ordinaryAndControlRows = 0;
            // Route duplicate verification does point lookup from inside the
            // longer native reader. Exercise the same nested-reader lifetime.
            foreach (var native in sql.ReadVerifiedIncomingEvents(floor, default))
            {
                using var selected = sql.ReadVerifiedReceiveForEvent(floor, native.EventHash);
                Assert.NotNull(selected);
                Assert.Equal(native.Ordinal, selected!.Ordinal);
                Assert.Equal(native.ExactEnvelope.ToArray(), selected.ExactEnvelope.ToArray());
                ordinaryAndControlRows++;
            }
            Assert.Equal(3, ordinaryAndControlRows);
            using (var selected = sql.ReadVerifiedReceiveForEvent(floor, SHA256.HashData(route.ExactDmc2.Span)))
            {
                Assert.NotNull(selected);
                using var plain = selected!.OwnAuthenticatedDmc2();
                Assert.True(plain.Use(bytes => bytes.SequenceEqual(route.ExactDmc2.Span)));
            }
            using (var controls = sql.ReadVerifiedIncomingRouteControls(floor, default).GetEnumerator())
            {
                Assert.True(controls.MoveNext());
                var selected = controls.Current;
                Assert.Equal(1, selected.RouteProcessing[0]);
                using var plain = selected.OwnAuthenticatedDmc2();
                Assert.True(plain.Use(bytes => bytes.SequenceEqual(route.ExactDmc2.Span)));
                Assert.False(controls.MoveNext());
                Assert.Throws<ObjectDisposedException>(() => selected.OwnAuthenticatedDmc2());
            }
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                Assert.Throws<OperationCanceledException>(() =>
                    sql.ReadVerifiedIncomingRouteControls(floor, cancelled.Token).GetEnumerator().MoveNext());
            }
            if (compact)
            {
                var rollback = new Did2MessagingSqlJournal(connection, receiver,
                    Did2MessagingHistoryCheckpoint.RegisteredEmpty(receiver));
                Assert.Throws<CryptographicException>(() =>
                    rollback.ReadVerifiedIncomingRouteControls(floor, default).GetEnumerator().MoveNext());
            }
            var typedColumn = defect switch
            {
                "ordinary-plaintext-type" => "plaintext",
                "ordinary-envelope-type" => "envelope",
                _ => null
            };
            byte[]? originalHash = null;
            if (typedColumn is not null)
            {
                using var original = connection.CreateCommand();
                original.CommandText = "SELECT CAST(" + typedColumn + " AS BLOB) FROM events WHERE operation=$op;";
                original.Parameters.AddWithValue("$op", ordinaryOperation);
                var exact = (byte[])original.ExecuteScalar()!;
                try { originalHash = SHA256.HashData(exact); }
                finally { CryptographicOperations.ZeroMemory(exact); }
            }
            using var change = connection.CreateCommand();
            change.CommandText = defect switch
            {
                "route-marker" => "UPDATE events SET metadata=CAST(substr(metadata,1,608)||zeroblob(64) AS BLOB) WHERE operation=$op;",
                "ordinary-plaintext" => "UPDATE events SET plaintext=zeroblob(length(plaintext)) WHERE operation=$op;",
                "ordinary-envelope" => "UPDATE events SET envelope=zeroblob(length(envelope)) WHERE operation=$op;",
                "missing-route" => "DELETE FROM events WHERE operation=$op;",
                "ordinary-plaintext-type" => "UPDATE events SET plaintext=CAST(plaintext AS TEXT) WHERE operation=$op;",
                "ordinary-envelope-type" => "UPDATE events SET envelope=CAST(envelope AS TEXT) WHERE operation=$op;",
                _ => throw new InvalidOperationException("Unknown route-reader fixture defect.")
            };
            change.Parameters.AddWithValue("$op", defect is "route-marker" or "missing-route" ? routeOperation : ordinaryOperation);
            Assert.Equal(1, change.ExecuteNonQuery());
            if (typedColumn is not null)
            {
                using var changed = connection.CreateCommand();
                changed.CommandText = "SELECT typeof(" + typedColumn + "),CAST(" + typedColumn + " AS BLOB) FROM events WHERE operation=$op;";
                changed.Parameters.AddWithValue("$op", ordinaryOperation);
                using var row = changed.ExecuteReader(); Assert.True(row.Read());
                Assert.Equal("text", row.GetString(0));
                var exact = row.GetFieldValue<byte[]>(1);
                try { Assert.Equal(originalHash, SHA256.HashData(exact)); }
                finally { CryptographicOperations.ZeroMemory(exact); }
                Assert.False(row.Read());
            }
            // A production compaction projection correctly rejects TEXT in a
            // BLOB column. A test-only raw snapshot must still represent that
            // hostile state, so the target reader is actually reached and its
            // refusal is proved not to repair, delete or rewrite any SQL cell.
            var before = ReadRouteReadRawSqlProjection(connection);
            var rejected = Record.Exception(() =>
            {
                using var controls = sql.ReadVerifiedIncomingRouteControls(floor, default).GetEnumerator();
                _ = controls.MoveNext();
            });
            switch (defect)
            {
                case "ordinary-plaintext":
                    Assert.IsType<ApplicationCoreFormatException>(rejected);
                    break;
                case "ordinary-envelope":
                    Assert.IsType<MessagingWireFormatException>(rejected);
                    break;
                case "ordinary-plaintext-type":
                case "ordinary-envelope-type":
                    Assert.IsType<InvalidDataException>(rejected);
                    break;
                default:
                    Assert.True(rejected is InvalidDataException or CryptographicException,
                        "Unexpected rejection type: " + rejected?.GetType().Name);
                    break;
            }
            Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
        });
    }

    // Mutation witness only, never authenticated authority or a compaction
    // commitment. CAST preserves hostile TEXT bytes without decoding them.
    private static byte[] ReadRouteReadRawSqlProjection(SqliteConnection connection)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Append(ReadOnlySpan<byte> bytes)
        {
            Span<byte> length = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)bytes.Length));
            hash.AppendData(length); hash.AppendData(bytes);
        }
        var tables = new List<(string Name, string Sql)>();
        using (var schema = connection.CreateCommand())
        {
            schema.CommandText = "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;";
            using var rows = schema.ExecuteReader();
            while (rows.Read()) tables.Add((rows.GetString(0), rows.GetString(1)));
        }
        Assert.Equal(new[] { "events", "initial_events", "journal", "ratchet", "scope" }, tables.Select(table => table.Name));
        foreach (var table in tables)
        {
            Append(Encoding.UTF8.GetBytes(table.Name)); Append(Encoding.UTF8.GetBytes(table.Sql));
            var columns = new List<string>();
            using (var info = connection.CreateCommand())
            {
                info.CommandText = "PRAGMA table_info(\"" + table.Name + "\");";
                using var rows = info.ExecuteReader();
                while (rows.Read()) columns.Add("\"" + rows.GetString(1).Replace("\"", "\"\"", StringComparison.Ordinal) + "\"");
            }
            using var query = connection.CreateCommand();
            var order = table.Name is "events" or "journal" ? "ordinal" : "singleton";
            query.CommandText = "SELECT " + string.Join(",", columns.Select(column => "typeof(" + column + "),CAST(" + column + " AS BLOB)")) +
                " FROM \"" + table.Name + "\" ORDER BY " + order + ";";
            using var row = query.ExecuteReader();
            while (row.Read())
            {
                hash.AppendData([1]);
                for (var index = 0; index < columns.Count; index++)
                {
                    Append(Encoding.UTF8.GetBytes(row.GetString(index * 2)));
                    if (row.IsDBNull(index * 2 + 1)) { Append([]); continue; }
                    var bytes = row.GetFieldValue<byte[]>(index * 2 + 1);
                    try { Append(bytes); }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
            }
            hash.AppendData([0]);
        }
        return hash.GetHashAndReset();
    }

    private sealed partial class Fixture
    {
        internal async Task WithRouteReadSql(Did2MessagingSessionScope scope,
            Action<Did2MessagingSqlJournal, SqliteConnection> inspect)
        {
            var accountDirectory = scope.IsInitiator ? directory : Path.Combine(directory, "peer");
            var secure = scope.IsInitiator ? (IDeepSecureStorage)storage : peerStorage;
            var ownerLease = new DeepIdV2AccountFileLease(Path.Combine(accountDirectory, "deep-store-v2-account.lock"));
            using var held = await ownerLease.AcquireAsync(default);
            using var catalog = await new ProtectedDid2MessagingSessionCatalog(secure,
                scope.Network, scope.LocalAccount, scope.Instance).ReadAsync(default);
            using var connection = SqliteDeepIdV2AccountGeneration.OpenExistingMessagingForCompactionUnderLease(
                Path.Combine(accountDirectory, "deep-store-v2-account.dsv2"), catalog, scope, held, ownerLease);
            var history = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, scope, default);
            inspect(new Did2MessagingSqlJournal(connection, scope, history), connection);
            held.RequireOwner(ownerLease);
        }
    }
}
