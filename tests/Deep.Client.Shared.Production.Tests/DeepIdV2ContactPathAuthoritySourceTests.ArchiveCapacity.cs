using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingWire;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_FreshBraidAt63MaintainsOneExactBatchWhileOriginalRetryDoesNot()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        var originalOperation = Bytes(32, 0xe5);
        using var original = await fixture.SendOwnedBraid(sender, originalOperation);
        using (var received = await fixture.ReceiveOwnedBraid(receiver, original.ExactControl.ToArray())) { }
        byte[] originalReceive;
        using (var reply = await fixture.SendOwnedBraid(receiver, Bytes(32, 0xe6)))
        {
            originalReceive = reply.ExactControl.ToArray();
            using var received = await fixture.ReceiveOwnedBraid(sender, originalReceive);
        }
        await fixture.FillArchiveWorkingSuffixTo63(sender, receiver, finalFromReceiver: true);
        var before = await fixture.ReadMessagingFloor(sender); var archive = await fixture.ReadNativeArchive(sender);
        var immutable = await fixture.ReadNativeHistory(sender);
        var receiverBefore = await fixture.ReadMessagingFloor(receiver); var receiverArchive = await fixture.ReadNativeArchive(receiver);
        var receiverImmutable = await fixture.ReadNativeHistory(receiver);
        Assert.Equal(63UL, receiverBefore.Ordinal - receiverArchive.Basis.Ordinal);
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var retry = await fixture.SendOwnedBraid(sender, originalOperation))
        {
            Assert.True(original.ExactControl.SequenceEqual(retry.ExactControl));
            Assert.Equal(0, work.MaintenanceBatches);
        }
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var retry = await fixture.ReceiveOwnedBraid(sender, originalReceive))
        {
            Assert.True(originalReceive.AsSpan().SequenceEqual(retry.ExactControl));
            Assert.Equal(0, work.MaintenanceBatches);
        }
        var afterReplay = await fixture.ReadMessagingFloor(sender);
        Assert.True(before.Exact.Span.SequenceEqual(afterReplay.Exact.Span));
        CryptographicOperations.ZeroMemory(originalReceive);
        var operation = Bytes(32, 0xe7); var hit = false;
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) { hit = true; throw new IOException("Braid soft-limit prefix interrupted."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedBraid(sender, operation));
        Assert.True(hit);
        var interrupted = await fixture.ReadMessagingFloor(sender);
        Assert.True(before.Exact.Span.SequenceEqual(interrupted.Exact.Span));
        fixture.ColdReopenCompactionStorage();
        byte[] exactControl;
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var sent = await fixture.SendOwnedBraid(sender, operation))
        {
            exactControl = sent.ExactControl.ToArray();
            Assert.Equal(1, work.MaintenanceBatches);
        }
        var receiverBraid = await fixture.ReadArchiveCapacityBraidPublicState(receiver);
        Assert.Equal(receiverBraid.Epoch, Dbr2Codec.Decode(exactControl).BraidEpoch);
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var received = await fixture.ReceiveOwnedBraid(receiver, exactControl))
        {
            Assert.True(exactControl.AsSpan().SequenceEqual(received.ExactControl));
            Assert.Equal(1, work.MaintenanceBatches);
        }
        CryptographicOperations.ZeroMemory(exactControl);
        var after = await fixture.ReadNativeArchive(sender); var stable = await fixture.ReadMessagingFloor(sender);
        Assert.Equal(archive.Basis.Ordinal + 32, after.Basis.Ordinal); Assert.Equal(before.Ordinal + 1, stable.Ordinal);
        Assert.Equal(32UL, stable.Ordinal - after.Basis.Ordinal);
        var source = await fixture.ReadNativeHistory(sender); Assert.True(immutable.Exact.Span.SequenceEqual(source.Exact.Span));
        var receiverAfter = await fixture.ReadNativeArchive(receiver); var receiverStable = await fixture.ReadMessagingFloor(receiver);
        Assert.Equal(receiverArchive.Basis.Ordinal + 32, receiverAfter.Basis.Ordinal);
        Assert.Equal(receiverBefore.Ordinal + 1, receiverStable.Ordinal);
        Assert.Equal(32UL, receiverStable.Ordinal - receiverAfter.Basis.Ordinal);
        var receiverSource = await fixture.ReadNativeHistory(receiver);
        Assert.True(receiverImmutable.Exact.Span.SequenceEqual(receiverSource.Exact.Span));
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2IndexedArchive_ClosedLocalConflictUsesReserved64WithoutAuthorizingCallerSubstitutionOrArchivingLatch()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await fixture.PrepareActiveNativePair();
        await fixture.FillArchiveWorkingSuffixTo63(sender, receiver);
        byte[] operation = [];
        await fixture.WithArchiveFixtureSql(sender, connection =>
        {
            using var query = connection.CreateCommand(); query.CommandText = "SELECT operation FROM events WHERE direction=1 ORDER BY ordinal LIMIT 1;";
            operation = Assert.IsType<byte[]>(query.ExecuteScalar());
        });
        var before = await fixture.ReadMessagingFloor(sender); var archive = await fixture.ReadNativeArchive(sender);
        using var different = await fixture.CreateOwnedText(sender, "independently authored different local command");
        var parsed = ApplicationCoreCodec.DecodeDmc2(different.ExactDmc2.Span);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.SendOwnedMessage(sender, operation, parsed));
        var unchanged = await fixture.ReadMessagingFloor(sender);
        Assert.True(before.Exact.Span.SequenceEqual(unchanged.Exact.Span), "An unowned caller operation/content pairing authorized a terminal latch.");
        // Explicit lower diagnostic of CLOSED local native fork evidence.
        // This does not claim public authored-command or business authorization.
        await fixture.WithArchiveOwnedStorage(sender, async opened =>
        {
            var conflict = await opened.WithSqlAsync(sql => Did2OwnedSendConflict.Verify(sql, sender, before,
                operation, different.ExactDmc2.Span), default);
            using var work = Did2MessagingSqlJournal.NativeWork.Measure();
            await opened.Custody.LatchOwnedSendAsync(conflict, default);
            Assert.Equal(0, work.MaintenanceBatches);
        });
        var terminal = await fixture.ReadMessagingFloor(sender); var stillArchived = await fixture.ReadNativeArchive(sender);
        Assert.Equal(2, terminal.Status); Assert.Equal(before.Ordinal + 1, terminal.Ordinal);
        Assert.Equal(64UL, terminal.Ordinal - stillArchived.Basis.Ordinal);
        Assert.True(archive.Exact.Span.SequenceEqual(stillArchived.Exact.Span), "A terminal latch became an active archive basis.");
        await fixture.WithArchiveFixtureSql(sender, connection =>
        {
            using var query = connection.CreateCommand(); query.CommandText = "SELECT metadata FROM journal ORDER BY ordinal DESC LIMIT 1;";
            var header = Assert.IsType<byte[]>(query.ExecuteScalar()); Assert.Equal(4, header[5]);
        });
        var blocked = await Record.ExceptionAsync(() => fixture.CreateOwnedText(sender, "terminal state is not fresh permission"));
        Assert.True(blocked is InvalidOperationException or CryptographicException or InvalidDataException, "A latched session authorized fresh work.");
        CryptographicOperations.ZeroMemory(operation);
    }

    private sealed partial class Fixture
    {
        internal async Task FillArchiveWorkingSuffixTo63(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver,
            bool finalFromReceiver = false)
        {
            while ((await ReadMessagingFloor(sender)).Ordinal - (await ReadNativeArchive(sender)).Basis.Ordinal < 62)
                foreach (var scope in new[] { sender, receiver })
                {
                    using var command = await CreateOwnedText(scope, "genuine indexed suffix capacity feedback");
                    using var sent = await SendOwnedMessage(scope, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
                    using var received = await ReceiveOwnedMessage(scope.IsInitiator ? receiver : sender, sent.ExactEnvelope.ToArray());
                }
            if (finalFromReceiver)
            {
                foreach (var scope in new[] { sender, receiver })
                {
                    var at62 = await ReadMessagingFloor(scope);
                    var archiveAt62 = await ReadNativeArchive(scope);
                    Assert.Equal(62UL, at62.Ordinal - archiveAt62.Basis.Ordinal);
                }
                var senderAt62 = await ReadArchiveCapacityBraidPublicState(sender);
                var receiverAt62 = await ReadArchiveCapacityBraidPublicState(receiver);
                Assert.Equal(senderAt62.Epoch, receiverAt62.Epoch);
            }
            var finalSender = finalFromReceiver ? receiver : sender;
            var finalReceiver = finalFromReceiver ? sender : receiver;
            using (var command = await CreateOwnedText(finalSender, "genuine transition to exact soft limit"))
            using (var sent = await SendOwnedMessage(finalSender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
            using (var received = await ReceiveOwnedMessage(finalReceiver, sent.ExactEnvelope.ToArray())) { }
            var floor = await ReadMessagingFloor(sender); var archive = await ReadNativeArchive(sender);
            Assert.Equal(63UL, floor.Ordinal - archive.Basis.Ordinal);
            if (finalFromReceiver)
            {
                var senderAt63 = await ReadArchiveCapacityBraidPublicState(sender);
                var receiverAt63 = await ReadArchiveCapacityBraidPublicState(receiver);
                Assert.Equal(senderAt63.Epoch, receiverAt63.Epoch);
            }
        }

        internal async Task<(byte State, ulong Epoch)> ReadArchiveCapacityBraidPublicState(Did2MessagingSessionScope scope)
        {
            var floor = await ReadMessagingFloor(scope);
            (byte State, ulong Epoch) result = default;
            await WithRouteReadSql(scope, (sql, _) =>
            {
                using var state = sql.ReadVerifiedLatest(floor);
                result = state.Use(bytes =>
                {
                    // Numeric inspection only of verified frozen TRS1/TRC1/MBM1.
                    // No private component leaves this callback.
                    Assert.True(bytes.Length >= 536 + 1060 + 16);
                    Assert.True(bytes.Slice(536, 4).SequenceEqual("TRC1"u8));
                    var braid = bytes[(536 + 1060)..];
                    Assert.True(braid[..4].SequenceEqual("MBM1"u8));
                    Assert.InRange(braid[7], (byte)1, (byte)11);
                    return (braid[7], BinaryPrimitives.ReadUInt64BigEndian(braid[8..]));
                });
            });
            return result;
        }
    }
}
