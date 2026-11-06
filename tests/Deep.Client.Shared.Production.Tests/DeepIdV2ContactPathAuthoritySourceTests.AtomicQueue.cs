using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("protected")]
    [InlineData("native")]
    [InlineData("projection")]
    [InlineData("stable")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AtomicQueue_EncryptedColdRecoveryKeepsOriginalEnvelopeAndSingleRatchetStep(string fault)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        var before = await fixture.ReadMessagingFloor(sender);
        var hit = false;
        using (Did2AtomicQueueTestHooks.Push(point =>
        {
            if (fault == "protected" && point == Did2AtomicQueueFailpoint.AfterProtectedCommit ||
                fault == "native" && point == Did2AtomicQueueFailpoint.AfterNativeCommit)
            { hit = true; throw new IOException("Injected atomic local queue interruption."); }
        }))
        using (Did2TextOutboxTestHooks.Push(point =>
        {
            if (fault == "projection" && point == Did2TextOutboxFailpoint.AfterSql ||
                fault == "stable" && point == Did2TextOutboxFailpoint.AfterStable)
            { hit = true; throw new IOException("Injected atomic queue projection interruption."); }
        }))
            await Assert.ThrowsAsync<IOException>(() => fixture.QueueNativeText(sender, "atomic original"));
        Assert.True(hit);
        var original = Assert.Single(await fixture.ListNativePendingText());
        var operation = original.LogicalOperation.ToArray();
        var envelope = await fixture.ReadAtomicQueueEnvelope(sender, operation);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, null);
        _ = await fixture.SendNativeText(sender, operation, "atomic original", grants, terminal);
        Assert.Equal(envelope, terminal.StoredEnvelope!.Ciphertext.ToArray());
        var after = await fixture.ReadMessagingFloor(sender);
        Assert.Equal(before.Ordinal + 1, after.Ordinal);
        Assert.Equal(before.RatchetGeneration + 1, after.RatchetGeneration);
        _ = await fixture.SendNativeText(sender, operation, "atomic original", grants, terminal);
        Assert.Equal(1, terminal.Calls);
        Assert.Equal(after.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        using (var received = await fixture.ReceiveOwnedMessage(receiver, envelope)) { }
        using (var replay = await fixture.ReceiveOwnedMessage(receiver, envelope)) { }
        Assert.Equal("atomic original", Assert.Single(await fixture.ListNativeApplicationMessages(receiver)).Text);
        Assert.Empty(await fixture.ListNativePendingText());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AtomicQueue_PreexistingPendingOriginalFinishesWithoutReauthoring()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using (Did2TextOutboxTestHooks.Push(point =>
        { if (point == Did2TextOutboxFailpoint.AfterPending) throw new IOException("Preexisting pending original."); }))
            await Assert.ThrowsAsync<IOException>(() => fixture.CreateOwnedText(sender, "preexisting original"));
        byte[] operation, eventHash;
        using (var journal = await fixture.ReadAuthoredTextJournalAsync(sender))
        { var pending = Assert.IsType<ProtectedDid2DirectTextJournal.Entry>(journal.Pending); operation = pending.Operation.ToArray(); eventHash = pending.EventHash.ToArray(); }
        var before = await fixture.ReadMessagingFloor(sender);
        fixture.DropNativeRuntimes(); fixture.ColdReopenCompactionStorage();
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, operation, null);
        _ = await fixture.SendNativeText(sender, operation, "preexisting original", grants, terminal);
        using var stable = await fixture.ReadAuthoredTextJournalAsync(sender);
        var entry = Assert.Single(stable.Entries.Values);
        Assert.Equal(operation, entry.Operation.ToArray()); Assert.Equal(eventHash, entry.EventHash.ToArray());
        Assert.Equal(4UL, stable.NextSequence(sender));
        Assert.Equal(before.RatchetGeneration + 1, (await fixture.ReadMessagingFloor(sender)).RatchetGeneration);
        Assert.Equal("preexisting original", Assert.Single(await fixture.ListNativeApplicationMessages(sender)).Text);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2AtomicQueue_LaterQueueCannotOvertakePreexistingUnencryptedOriginal()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var original = await fixture.CreateOwnedText(sender, "earlier original");
        var before = await fixture.ReadMessagingFloor(sender);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.QueueNativeText(sender, "later original"));
        Assert.Equal(before.Exact.ToArray(), (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(original.OperationId.ToArray(), Assert.Single(await fixture.ListNativePendingText()).LogicalOperation.ToArray());
        var grants = new OwnedGrantTransport(fixture, ownerOnPrimary: true);
        var terminal = new OwnedStoreFixture(fixture, sender, original.OperationId.ToArray(), null);
        _ = await fixture.SendNativeText(sender, original.OperationId.ToArray(), "earlier original", grants, terminal);
        _ = await fixture.QueueNativeText(sender, "later original");
        Assert.Equal(before.RatchetGeneration + 2, (await fixture.ReadMessagingFloor(sender)).RatchetGeneration);
        Assert.Equal(new[] { "earlier original", "later original" }, (await fixture.ListNativeApplicationMessages(sender)).Select(message => message.Text));
    }

    private sealed partial class Fixture
    {
        internal async Task<byte[]> ReadAtomicQueueEnvelope(Did2MessagingSessionScope scope, byte[] operation)
        {
            var floor = await ReadMessagingFloor(scope);
            if (floor.Phase == 2)
            {
                using var pending = await new Did2MessagingProtectedCheckpoint(storage, scope).ReadPendingAsync(floor, default);
                return pending.Use(bytes =>
                {
                    using var mutation = OwnedDid2MessagingMutation.RecoverProtectedPending(scope, floor, bytes);
                    Assert.Equal(operation, mutation.Operation.ToArray()); return mutation.Envelope.ToArray();
                });
            }
            byte[] envelope = [];
            await WithArchiveFixtureSql(scope, connection =>
            {
                using var query = connection.CreateCommand(); query.CommandText = "SELECT envelope FROM events WHERE operation=$operation;";
                query.Parameters.AddWithValue("$operation", operation); envelope = Assert.IsType<byte[]>(query.ExecuteScalar());
            });
            return envelope;
        }
    }
}
