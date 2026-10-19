using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("none")]
    [InlineData("unselected-type")]
    [InlineData("unselected-envelope")]
    [InlineData("unselected-missing")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task NativeReadBatch_ActualEncryptedRowsRemainFreshOrderedAndWholeJournalVerified(string defect)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        async Task<byte[]> Send(string text)
        {
            using var command = await fixture.CreateOwnedText(sender, text);
            using var sent = await fixture.SendOwnedMessage(sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
            using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
            return command.OperationId.ToArray();
        }
        var first = await Send("native read batch first"); var second = await Send("native read batch second");
        var absent = SHA256.HashData("absent native batch operation"u8);
        var floor = await fixture.ReadMessagingFloor(receiver);
        await fixture.WithRouteReadSql(receiver, (sql, connection) =>
        {
            var rows = sql.ReadVerifiedOperations(floor, [second, absent, first]);
            try
            {
                Assert.Equal(3, rows.Count); Assert.Null(rows[1]);
                Assert.True(rows[0]!.Ordinal > rows[2]!.Ordinal);
                using var single = sql.ReadVerifiedOperation(floor, second);
                Assert.Equal(single!.ExactEnvelope.ToArray(), rows[0]!.ExactEnvelope.ToArray());
            }
            finally { foreach (var row in rows) row?.Dispose(); }
            Assert.Throws<ObjectDisposedException>(() => rows[0]!.OwnAuthenticatedDmc2());
            if (defect == "none") return;
            using var corrupt = connection.CreateCommand();
            corrupt.CommandText = defect switch
            {
                "unselected-type" => "UPDATE events SET envelope=CAST(envelope AS TEXT) WHERE operation=$op;",
                "unselected-envelope" => "UPDATE events SET envelope=zeroblob(length(envelope)) WHERE operation=$op;",
                _ => "DELETE FROM events WHERE operation=$op;"
            };
            corrupt.Parameters.AddWithValue("$op", second); Assert.Equal(1, corrupt.ExecuteNonQuery());
            var before = ReadRouteReadRawSqlProjection(connection);
            Assert.NotNull(Record.Exception(() => sql.ReadVerifiedOperations(floor, [first])));
            Assert.Equal(before, ReadRouteReadRawSqlProjection(connection));
        });
    }
}
