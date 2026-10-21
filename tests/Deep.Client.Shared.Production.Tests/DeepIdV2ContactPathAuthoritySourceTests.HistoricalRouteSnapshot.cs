using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

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
            Assert.Equal(1, received.RouteProcessing[0]);
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
                OwnedDid2MessagingPersistedEvent? last = null;
                var controls = 0;
                foreach (var native in snapshot.ReadIncomingRouteControls(default))
                {
                    last = native;
                    using var exact = native.OwnAuthenticatedDmc2();
                    Assert.True(exact.Use(bytes => bytes.SequenceEqual(route.ExactDmc2.Span)));
                    using var earliest = snapshot.ReadReceiveForEvent(native.EventHash);
                    Assert.Equal(native.Ordinal, earliest!.Ordinal);
                    Assert.Equal(native.ExactEnvelope.ToArray(), earliest.ExactEnvelope.ToArray());
                    controls++;
                }
                Assert.Equal(1, controls);
                Assert.Throws<ObjectDisposedException>(() => last!.OwnAuthenticatedDmc2());
                using var cancellation = new CancellationTokenSource();
                using (var reader = snapshot.ReadIncomingRouteControls(cancellation.Token).GetEnumerator())
                {
                    Assert.True(reader.MoveNext()); cancellation.Cancel();
                    Assert.Throws<OperationCanceledException>(() => reader.MoveNext());
                }
                // Cancellation released its reader; the owned read transaction
                // is still usable until its explicit disposal.
                using var selectedAgain = snapshot.ReadOperation(ordinaryOperation);
                Assert.NotNull(selectedAgain);
            }
            finally { snapshot.Dispose(); }
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadInitialEvents());
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadOperation(ordinaryOperation));
            Assert.Throws<ObjectDisposedException>(() => snapshot.ReadIncomingRouteControls(default).GetEnumerator().MoveNext());
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
            Assert.NotNull(Record.Exception(() => { using var rejected = sql.OpenHistoricalRouteRead(floor); }));
            Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
        });
    }
}
