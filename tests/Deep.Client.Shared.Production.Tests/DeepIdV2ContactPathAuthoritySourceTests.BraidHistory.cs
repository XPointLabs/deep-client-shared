using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_ActualCompactionAllHandoversPreserveExactControlHistory()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        using var header = await fixture.SendOwnedBraid(alice, Bytes(32, 200));
        using (var received = await fixture.ReceiveOwnedBraid(bob, header.ExactControl.ToArray())) { }
        using var ct1 = await fixture.SendOwnedBraid(bob, Bytes(32, 201));
        using (var received = await fixture.ReceiveOwnedBraid(alice, ct1.ExactControl.ToArray())) { }
        var index = 0;
        var handovers = new[] { Did2CompactionFailpoint.AfterStage, Did2CompactionFailpoint.AfterSql,
            Did2CompactionFailpoint.AfterSqlRecorded, Did2CompactionFailpoint.AfterHistoryAdopted,
            Did2CompactionFailpoint.AfterPartsDeleted, Did2CompactionFailpoint.AfterPlanCleared };
        foreach (var point in handovers)
        {
            var floor = await fixture.ReadMessagingFloor(alice);
            var count = (await fixture.ListOwnedMessages(alice)).Count;
            var rows = index == 0 ? checked((int)floor.Ordinal) : 1;
            var hit = false;
            using (Did2CompactionTestHooks.Push(actual =>
                { if (actual == point) { hit = true; throw new IOException("Injected control history compaction handover."); } }))
                await Assert.ThrowsAsync<IOException>(() => fixture.CompactSenderPrefix(alice, rows, default));
            Assert.True(hit);
            fixture.ColdReopenCompactionStorage();
            using (var current = await fixture.ReadSenderCompactionCurrent()) Assert.NotNull(current);
            await fixture.AssertSenderCompactionIdle(alice);
            Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
            using (var retry = await fixture.SendOwnedBraid(alice, Bytes(32, 200)))
            {
                Assert.Equal(header.Ordinal, retry.Ordinal);
                Assert.True(header.ExactControl.SequenceEqual(retry.ExactControl));
            }
            using (var replay = await fixture.ReceiveOwnedBraid(alice, ct1.ExactControl.ToArray()))
            {
                Assert.Equal(ct1.ExactControl.ToArray(), replay.ExactControl.ToArray());
                Assert.Equal(4, replay.Direction);
            }
            Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
            Assert.Equal(count, (await fixture.ListOwnedMessages(alice)).Count);
            // Supply one actual working suffix for the next handover. Its
            // semantic event is separate from the unchanged control history.
            if (++index < handovers.Length)
                await SendBraidHistoryText(fixture, alice, bob, checked((byte)(210 + index)));
        }
        Assert.Equal(6, index);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task OwnedBraidRecovery_CompactedReplayAfterNativeKeyRetirementRequiresProtectedExactHistory()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (alice, bob) = await PrepareRouteFaultPair(fixture);
        byte[]? original = null;
        foreach (var (sender, recipient, id) in new[] { (alice, bob, (byte)200), (bob, alice, (byte)201),
                     (alice, bob, (byte)202), (bob, alice, (byte)203) })
        {
            using var sent = await fixture.SendOwnedBraid(sender, Bytes(32, id));
            using var received = await fixture.ReceiveOwnedBraid(recipient, sent.ExactControl.ToArray());
            if (id == 201) original = sent.ExactControl.ToArray();
        }
        Assert.NotNull(original);
        try
        {
            // Genuine data advances BOTH frontiers before any second output;
            // controls alone cannot reset freshness or retire a data link.
            await SendBraidHistoryText(fixture, alice, bob, 210);
            await SendBraidHistoryText(fixture, bob, alice, 211);
            foreach (var (sender, recipient, id) in new[] { (bob, alice, (byte)204), (alice, bob, (byte)205),
                         (bob, alice, (byte)206), (alice, bob, (byte)207) })
            {
                using var sent = await fixture.SendOwnedBraid(sender, Bytes(32, id));
                using var received = await fixture.ReceiveOwnedBraid(recipient, sent.ExactControl.ToArray());
            }
            var floor = await fixture.ReadMessagingFloor(alice);
            await fixture.WithSenderHistoryStorage(alice, (opened, _, _, _) =>
            {
                using var native = opened.Sql.ReadVerifiedLatest(floor);
                var epochs = native.Use(bytes =>
                {
                    // Test-only numeric inspection of the frozen TRS1/TRC1
                    // layout. No key or plaintext is exported or logged.
                    Assert.True(bytes.Length > 536 + 1060);
                    Assert.True(bytes.Slice(536, 4).SequenceEqual("TRC1"u8));
                    Assert.Equal((byte)2, bytes[540]);
                    var component = bytes[536..];
                    Assert.Equal((byte)2, component[392]);
                    return new[] { BinaryPrimitives.ReadUInt64BigEndian(component[360..]),
                        BinaryPrimitives.ReadUInt64BigEndian(component[400..]),
                        BinaryPrimitives.ReadUInt64BigEndian(component[728..]) };
                });
                Assert.Equal(new ulong[] { 2, 1, 2 }, epochs); // Original MAC link0 really no longer exists.
                return Task.CompletedTask;
            });
            await fixture.CompactSenderPrefix(alice, checked((int)floor.Ordinal), default);
            fixture.ColdReopenCompactionStorage();
            using (var current = await fixture.ReadSenderCompactionCurrent()) Assert.NotNull(current);
            await fixture.AssertSenderCompactionIdle(alice);
            using (var replay = await fixture.ReceiveOwnedBraid(alice, original))
                Assert.Equal(original, replay.ExactControl.ToArray());
            Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
            var changed = original.ToArray(); changed[^1] ^= 1;
            await Assert.ThrowsAsync<CryptographicException>(() => fixture.ReceiveOwnedBraid(alice, changed));
            await fixture.WithSenderHistoryStorage(alice, async (opened, secure, observer, held) =>
            {
                var root = await Did2MessagingHistoryCheckpoint.ReadRegisteredAsync(secure, alice, default);
                var empty = Did2MessagingHistoryCheckpoint.RegisteredEmpty(alice);
                Assert.True(await secure.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(alice), root.Exact, empty.Exact));
                try { Assert.Throws<CryptographicException>(() => new Did2MessagingSqlJournal(observer, alice, empty).VerifyTip()); }
                finally { Assert.True(await secure.CompareExchangeAsync(Did2MessagingHistoryCheckpoint.Slot(alice), empty.Exact, root.Exact)); }
                using (var corrupt = observer.CreateCommand())
                {
                    corrupt.CommandText = "UPDATE events SET envelope=$changed WHERE operation=$op;";
                    corrupt.Parameters.AddWithValue("$changed", changed); corrupt.Parameters.AddWithValue("$op", Bytes(32, 201));
                    Assert.Equal(1, corrupt.ExecuteNonQuery());
                }
                try
                {
                    Assert.Throws<CryptographicException>(() => opened.Sql.VerifyTip());
                    Assert.Throws<CryptographicException>(() => opened.Sql.ReadVerifiedBraidControl(floor, Bytes(32, 201)));
                }
                finally
                {
                    using var restore = observer.CreateCommand();
                    restore.CommandText = "UPDATE events SET envelope=$original WHERE operation=$op;";
                    restore.Parameters.AddWithValue("$original", original); restore.Parameters.AddWithValue("$op", Bytes(32, 201));
                    Assert.Equal(1, restore.ExecuteNonQuery());
                }
                held.RequireActive(); Assert.Equal(floor.Exact.ToArray(), opened.Sql.VerifyTip().Exact.ToArray());
            });
            using (var replay = await fixture.ReceiveOwnedBraid(alice, original))
                Assert.Equal(original, replay.ExactControl.ToArray());
            Assert.Equal(floor.Exact.ToArray(), (await fixture.ReadMessagingFloor(alice)).Exact.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(original); }
    }

    private static async Task SendBraidHistoryText(Fixture fixture, Did2MessagingSessionScope sender,
        Did2MessagingSessionScope recipient, byte id)
    {
        using var draft = await fixture.CreateOwnedText(sender, "owned control history data step");
        var op = draft.OperationId.ToArray();
        using var sent = await fixture.SendOwnedMessage(sender, op, ApplicationCoreCodec.DecodeDmc2(draft.ExactDmc2.Span));
        using var received = await fixture.ReceiveOwnedMessage(recipient, sent.ExactEnvelope.ToArray());
    }
}
