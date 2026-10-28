using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

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
        using (var reply = await fixture.SendOwnedBraid(receiver, Bytes(32, 0xe6)))
        using (var received = await fixture.ReceiveOwnedBraid(sender, reply.ExactControl.ToArray())) { }
        await fixture.FillArchiveWorkingSuffixTo63(sender, receiver);
        var before = await fixture.ReadMessagingFloor(sender); var archive = await fixture.ReadNativeArchive(sender);
        var immutable = await fixture.ReadNativeHistory(sender);
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var retry = await fixture.SendOwnedBraid(sender, originalOperation))
        {
            Assert.True(original.ExactControl.SequenceEqual(retry.ExactControl));
            Assert.Equal(0, work.MaintenanceBatches);
        }
        var operation = Bytes(32, 0xe7); var hit = false;
        using (Did2CompactionTestHooks.Push(point =>
            { if (point == Did2CompactionFailpoint.AfterStage) { hit = true; throw new IOException("Braid soft-limit prefix interrupted."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedBraid(sender, operation));
        Assert.True(hit);
        var interrupted = await fixture.ReadMessagingFloor(sender);
        Assert.True(before.Exact.Span.SequenceEqual(interrupted.Exact.Span));
        fixture.ColdReopenCompactionStorage();
        using (var work = Did2MessagingSqlJournal.NativeWork.Measure())
        using (var sent = await fixture.SendOwnedBraid(sender, operation))
        using (var received = await fixture.ReceiveOwnedBraid(receiver, sent.ExactControl.ToArray()))
            Assert.Equal(1, work.MaintenanceBatches);
        var after = await fixture.ReadNativeArchive(sender); var stable = await fixture.ReadMessagingFloor(sender);
        Assert.Equal(archive.Basis.Ordinal + 32, after.Basis.Ordinal); Assert.Equal(before.Ordinal + 1, stable.Ordinal);
        Assert.Equal(32UL, stable.Ordinal - after.Basis.Ordinal);
        var source = await fixture.ReadNativeHistory(sender); Assert.True(immutable.Exact.Span.SequenceEqual(source.Exact.Span));
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
        internal async Task FillArchiveWorkingSuffixTo63(Did2MessagingSessionScope sender, Did2MessagingSessionScope receiver)
        {
            while ((await ReadMessagingFloor(sender)).Ordinal - (await ReadNativeArchive(sender)).Basis.Ordinal < 62)
                foreach (var scope in new[] { sender, receiver })
                {
                    using var command = await CreateOwnedText(scope, "genuine indexed suffix capacity feedback");
                    using var sent = await SendOwnedMessage(scope, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span));
                    using var received = await ReceiveOwnedMessage(scope.IsInitiator ? receiver : sender, sent.ExactEnvelope.ToArray());
                }
            using (var command = await CreateOwnedText(sender, "genuine transition to exact soft limit"))
            using (var sent = await SendOwnedMessage(sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
            using (var received = await ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray())) { }
            var floor = await ReadMessagingFloor(sender); var archive = await ReadNativeArchive(sender);
            Assert.Equal(63UL, floor.Ordinal - archive.Basis.Ordinal);
        }
    }
}
