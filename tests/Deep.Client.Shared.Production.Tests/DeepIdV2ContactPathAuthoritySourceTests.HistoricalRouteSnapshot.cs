using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData(false, "none")]
    [InlineData(true, "none")]
    [InlineData(false, "ordinary-type")]
    [InlineData(true, "ordinary-envelope")]
    [InlineData(false, "route-marker")]
    [InlineData(true, "missing-route")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task HistoricalRouteSnapshot_RealEncryptedHistoryIsBoundedFreshAndDisposalSafe(bool compact, string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        byte[] ordinaryOperation;
        using (var command = await fixture.CreateOwnedText(sender, "historical snapshot ordinary row"))
        using (var sent = await fixture.SendOwnedMessage(sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            ordinaryOperation = command.OperationId.ToArray();
        await fixture.RenewNativeSenderPublicationPastExpiryAsync(renewedRouteLifetimeSeconds: 300);
        using var route = await fixture.CreateOwnedRouteUpdate(sender);
        var routeOperation = route.OperationId.ToArray();
        using (var sent = await fixture.SendOwnedRouteUpdate(sender, routeOperation))
        using (var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray()))
            Assert.Equal(3, received.RouteProcessing[0]);
        if (compact)
        {
            await fixture.CompactHistoricalPeerRoutePrefix(receiver);
            fixture.ColdReopenReceiverStoreStorage();
        }
        var floor = await fixture.ReadMessagingFloor(receiver);
        var foreign = await fixture.ReadMessagingFloor(sender);
        await fixture.WithRouteReadSql(receiver, (sql, connection) =>
        {
            Assert.NotNull(Record.Exception(() => { using var rejected = sql.OpenHistoricalRouteRead(foreign); }));
            var snapshot = sql.OpenHistoricalRouteRead(floor);
            try
            {
                var initial = snapshot.ReadInitialEvents();
                try
                {
                    Assert.IsType<ContactHelloDmc2Payload>(ApplicationCoreCodec.DecodeDmc2(initial.Hello).ParsedPayload);
                    Assert.NotEmpty(initial.SessionInit);
                }
                finally { CryptographicOperations.ZeroMemory(initial.SessionInit); CryptographicOperations.ZeroMemory(initial.Hello); }
                using var ordinary = snapshot.ReadOperation(ordinaryOperation);
                Assert.NotNull(ordinary);
                // The legacy filter retains only outcomes1/2. Count8 keeps
                // immutable stage3 and is selected by its actual native source.
                using (var legacy = snapshot.ReadIncomingRouteControls(default).GetEnumerator()) Assert.False(legacy.MoveNext());
                var selectedRoute = snapshot.ReadOperation(routeOperation);
                Assert.NotNull(selectedRoute);
                using (selectedRoute)
                {
                    Assert.Equal(3, selectedRoute.RouteProcessing[0]);
                    using var exact = selectedRoute.OwnAuthenticatedDmc2();
                    Assert.True(exact.Use(bytes => bytes.SequenceEqual(route.ExactDmc2.Span)));
                    Assert.True(exact.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes).ParsedPayload is ContactRouteHistoryDmc2Payload));
                    using var earliest = snapshot.ReadReceiveForEvent(selectedRoute.EventHash);
                    Assert.NotNull(earliest);
                    Assert.Equal(selectedRoute.Ordinal, earliest.Ordinal);
                    Assert.Equal(selectedRoute.ExactEnvelope.ToArray(), earliest.ExactEnvelope.ToArray());
                }
                Assert.Throws<ObjectDisposedException>(() => selectedRoute.OwnAuthenticatedDmc2());
                using var cancellation = new CancellationTokenSource();
                cancellation.Cancel();
                using (var reader = snapshot.ReadIncomingRouteControls(cancellation.Token).GetEnumerator())
                    Assert.Throws<OperationCanceledException>(() => reader.MoveNext());
                // Cancellation released its reader; the owned read transaction
                // is still usable until its explicit disposal.
                using var selectedAgain = snapshot.ReadOperation(ordinaryOperation);
                Assert.NotNull(selectedAgain);
            }
            finally { snapshot.Dispose(); }
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadInitialEvents());
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadOperation(ordinaryOperation));
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadIncomingRouteControls(default).GetEnumerator().MoveNext());
            OwnedDid2MessagingPersistedEvent? last = null;
            var controls = 0;
            foreach (var native in sql.ReadVerifiedIncomingEvents(floor, default))
            {
                if (native.RouteProcessing[0] == 0) continue;
                Assert.Equal(3, native.RouteProcessing[0]);
                last = native;
                using var exact = native.OwnAuthenticatedDmc2();
                Assert.True(exact.Use(bytes => bytes.SequenceEqual(route.ExactDmc2.Span)));
                Assert.True(exact.Use(bytes => ApplicationCoreCodec.DecodeDmc2(bytes).ParsedPayload is ContactRouteHistoryDmc2Payload));
                using var earliest = sql.ReadVerifiedReceiveForEvent(floor, native.EventHash);
                Assert.NotNull(earliest);
                Assert.Equal(native.Ordinal, earliest.Ordinal);
                Assert.Equal(native.ExactEnvelope.ToArray(), earliest.ExactEnvelope.ToArray());
                controls++;
            }
            Assert.Equal(1, controls);
            Assert.Throws<ObjectDisposedException>(() => last!.OwnAuthenticatedDmc2());
            using (var cancellation = new CancellationTokenSource())
            using (var reader = sql.ReadVerifiedIncomingEvents(floor, cancellation.Token).GetEnumerator())
            {
                Assert.True(reader.MoveNext());
                var cancelled = reader.Current;
                cancellation.Cancel();
                Assert.Throws<OperationCanceledException>(() => reader.MoveNext());
                Assert.Throws<ObjectDisposedException>(() => cancelled.OwnAuthenticatedDmc2());
            }
            // No lingering reader/transaction may prevent a fresh full read.
            using (var fresh = sql.OpenHistoricalRouteRead(floor))
            using (var selected = fresh.ReadOperation(ordinaryOperation)) Assert.NotNull(selected);
            if (defect == "none") return;
            using var mutate = connection.CreateCommand();
            mutate.CommandText = defect switch
            {
                "ordinary-type" => "UPDATE events SET envelope=CAST(envelope AS TEXT) WHERE operation=$op;",
                "ordinary-envelope" => "UPDATE events SET envelope=zeroblob(length(envelope)) WHERE operation=$op;",
                "route-marker" => "UPDATE events SET metadata=CAST(substr(metadata,1,608)||zeroblob(64) AS BLOB) WHERE operation=$op;",
                _ => "DELETE FROM events WHERE operation=$op;"
            };
            mutate.Parameters.AddWithValue("$op", defect is "route-marker" or "missing-route" ? routeOperation : ordinaryOperation);
            Assert.Equal(1, mutate.ExecuteNonQuery());
            var before = ReadRouteReadRawSqlProjection(connection);
            Assert.NotNull(Record.Exception(() =>
            {
                using var rejected = sql.OpenHistoricalRouteRead(floor);
                // An archived payload is authenticated when actually selected.
                using var selected = rejected.ReadOperation(defect is "route-marker" or "missing-route" ? routeOperation : ordinaryOperation);
            }));
            Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
        });
    }
}
