using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("AfterPending")]
    [InlineData("AfterSql")]
    [InlineData("AfterStable")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CancelledDraft_PendingSqlOrStableCancelNeverEncryptsAndNextAuthorConsumesNextSequence(string authorStage)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, receiver) = await PrepareRouteFaultPair(fixture);
        var (operation, exact) = await fixture.InterruptCancelledDraftAuthor(sender, authorStage);
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var sends = await fixture.ReadSendRootForStoppedWork();
        await fixture.CancelNativeMessagingWork(sender, operation);
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await fixture.CancelNativeMessagingWork(sender, operation);
            await fixture.RequireCancelledDraftState(sender, operation, native, sends);
            await Assert.ThrowsAsync<IOException>(() => fixture.RetryOwnedText(sender, operation, "cancelled before encryption"));
            await Assert.ThrowsAsync<IOException>(() => fixture.SendOwnedMessage(sender, operation, ApplicationCoreCodec.DecodeDmc2(exact)));
            Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        }
        using var next = await fixture.CreateOwnedText(sender, "next real message after draft cancellation");
        Assert.Equal(ApplicationCoreCodec.DecodeDmc2(exact).SenderClientSequence + 1, next.SenderSequence);
        using var sent = await fixture.SendOwnedMessage(sender, next.OperationId.ToArray(), ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span));
        using var received = await fixture.ReceiveOwnedMessage(receiver, sent.ExactEnvelope.ToArray());
        foreach (var bytes in new[] { exact, native, sends }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("AfterCancelledPendingSql", false)]
    [InlineData("AfterCancelledPendingStable", false)]
    [InlineData("AfterCancelledPendingSql", true)]
    [InlineData("AfterCancelledPendingStable", true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CancelledDraft_InterruptedPendingMirrorResumesExactReservationWithoutNativeMutation(string handover, bool cancel)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var (operation, exact) = await fixture.InterruptCancelledDraftAuthor(sender, "AfterPending");
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var sends = await fixture.ReadSendRootForStoppedWork(); var hit = false;
        using var cancellation = new CancellationTokenSource();
        using (Did2TextOutboxTestHooks.Push(point =>
        {
            if (point.ToString() != handover) return;
            hit = true;
            if (cancel) { cancellation.Cancel(); cancellation.Token.ThrowIfCancellationRequested(); }
            throw new IOException("Interrupted existing pending cancellation handover.");
        }))
        {
            if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.CancelNativeMessagingWork(sender, operation, cancellation.Token));
            else await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(sender, operation));
        }
        Assert.True(hit);
        fixture.ColdReopenCompactionStorage();
        using (var state = await fixture.ReadAuthoredTextJournalAsync(sender))
        {
            var command = state.Entries[Convert.ToHexString(operation)];
            Assert.False(command.WorkStopped); Assert.Equal(SHA256.HashData(exact), command.EventHash.ToArray());
            Assert.Equal(handover == "AfterCancelledPendingSql", command.Pending);
        }
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        await fixture.CancelNativeMessagingWork(sender, operation);
        fixture.ColdReopenCompactionStorage();
        await fixture.RequireCancelledDraftState(sender, operation, native, sends);
        foreach (var bytes in new[] { exact, native, sends }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData("AfterStage")]
    [InlineData("AfterSql")]
    [InlineData("AfterSqlRecorded")]
    [InlineData("AfterHistoryAdopted")]
    [InlineData("AfterPartsDeleted")]
    [InlineData("AfterPlanCleared")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CancelledDraft_ExistingCleanupPlanColdRecoversWithoutInventingNativeHistory(string handover)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var draft = await fixture.CreateOwnedText(sender, "cancelled before encryption");
        var operation = draft.OperationId.ToArray();
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var sends = await fixture.ReadSendRootForStoppedWork(); var hit = false;
        using var expected = await fixture.ExpectedStoppedPayloadSqlSuccessor(sender, operation);
        using var capture = expected.Observe();
        using (Did2CompactionTestHooks.Push(point =>
        {
            if (point.ToString() != handover) return;
            hit = true; throw new IOException("Interrupted existing cancelled draft cleanup.");
        })) await Assert.ThrowsAsync<IOException>(() => fixture.CancelNativeMessagingWork(sender, operation));
        Assert.True(hit);
        for (var reopen = 0; reopen < 2; reopen++)
        {
            fixture.ColdReopenCompactionStorage();
            await fixture.CancelNativeMessagingWork(sender, operation);
            await fixture.RequireCancelledDraftState(sender, operation, native, sends);
            Assert.Equal(expected.After, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        }
        foreach (var bytes in new[] { native, sends }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CancelledDraft_MissingOrChangedStableSqlRejectsBeforeStopOrEncryption(bool remove)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        using var draft = await fixture.CreateOwnedText(sender, "cancelled before encryption");
        var operation = draft.OperationId.ToArray();
        var root = await fixture.ReadAuthoredRootDigestAsync();
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        await fixture.WithAuthoredApplicationConnectionAsync(sender, sql =>
        {
            using var command = sql.CreateCommand();
            command.CommandText = remove ? "DELETE FROM direct_text_outbox WHERE operation_id=$op;" :
                "UPDATE direct_text_outbox SET exact_dmc2=zeroblob(length(exact_dmc2)) WHERE operation_id=$op;";
            command.Parameters.AddWithValue("$op", operation); Assert.Equal(1, command.ExecuteNonQuery());
        });
        var damaged = await fixture.ReadCompleteOrdinaryApplicationProjection(sender);
        await Assert.ThrowsAsync<CryptographicException>(() => fixture.CancelNativeMessagingWork(sender, operation));
        Assert.Equal(root, await fixture.ReadAuthoredRootDigestAsync());
        Assert.Equal(native, (await fixture.ReadMessagingFloor(sender)).Exact.ToArray());
        Assert.Equal(damaged, await fixture.ReadCompleteOrdinaryApplicationProjection(sender));
        foreach (var bytes in new[] { root, native, damaged }) CryptographicOperations.ZeroMemory(bytes);
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2CancelledDraft_AttachmentOfferRetiresOnlyWorkingCopyNotIndependentAsset()
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true, longMailboxWindow: true);
        var (sender, _) = await PrepareRouteFaultPair(fixture);
        var assetOperation = Bytes(32, 0xb6);
        var content = System.Text.Encoding.UTF8.GetBytes("independently owned asset before draft cancellation");
        using var asset = await fixture.PrepareOwnedAsset(sender, assetOperation, content, "draft.txt", "text/plain", 1400);
        using var offer = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        var offerOperation = offer.OperationId.ToArray();
        var native = (await fixture.ReadMessagingFloor(sender)).Exact.ToArray();
        var sends = await fixture.ReadSendRootForStoppedWork();
        await fixture.CancelNativeMessagingWork(sender, offerOperation);
        fixture.ColdReopenCompactionStorage();
        await fixture.RequireCancelledDraftState(sender, offerOperation, native, sends);
        using var next = await fixture.CreateOwnedAttachmentOffer(sender, assetOperation);
        var originalMessage = ApplicationCoreCodec.DecodeDmc2(offer.ExactDmc2.Span);
        var nextMessage = ApplicationCoreCodec.DecodeDmc2(next.ExactDmc2.Span);
        using var originalManifest = Assert.IsType<AttachmentOfferDmc2Payload>(originalMessage.ParsedPayload).Manifest;
        using var nextManifest = Assert.IsType<AttachmentOfferDmc2Payload>(nextMessage.ParsedPayload).Manifest;
        Assert.Equal(originalManifest.CanonicalBytes.ToArray(), nextManifest.CanonicalBytes.ToArray());
        Assert.Equal(offer.SenderSequence + 1, next.SenderSequence);
        foreach (var bytes in new[] { content, native, sends }) CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed partial class Fixture
    {
        internal async Task<(byte[] Operation, byte[] Exact)> InterruptCancelledDraftAuthor(Did2MessagingSessionScope scope, string authorStage)
        {
            byte[] operation = [], exact = []; var hit = false;
            using (Did2TextOutboxTestHooks.Push(point =>
            {
                if (point == Did2TextOutboxFailpoint.AfterPending)
                {
                    using var root = storage.ReadOwnedAsync(ProtectedDid2DirectTextJournal.Slot).GetAwaiter().GetResult() ?? throw new InvalidDataException();
                    using var state = root.Use(bytes => ProtectedDid2DirectTextJournal.Decode(bytes, scope.Network, scope.LocalAccount, scope.Instance));
                    var pending = state.Pending ?? throw new InvalidDataException("Interrupted creation has no actual pending command.");
                    Assert.True(pending.Scope.Exact.SequenceEqual(scope.Exact));
                    operation = pending.Operation.ToArray(); exact = pending.PendingDmc2.ToArray();
                }
                if (point.ToString() != authorStage) return;
                hit = true; throw new IOException("Interrupted original draft authoring.");
            })) await Assert.ThrowsAsync<IOException>(() => CreateOwnedText(scope, "cancelled before encryption"));
            Assert.True(hit); Assert.NotEmpty(exact); Assert.Equal(32, operation.Length); return (operation, exact);
        }

        internal async Task RequireCancelledDraftState(Did2MessagingSessionScope scope, byte[] operation, byte[] native, byte[] sends)
        {
            using var journal = await ReadAuthoredTextJournalAsync(scope);
            var name = Convert.ToHexString(operation);
            Assert.False(journal.Entries.ContainsKey(name));
            var stopped = journal.TerminalAudits[name];
            Assert.Null(journal.Pending);
            Assert.Equal((byte)ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, stopped.Reason);
            Assert.Equal(native, (await ReadMessagingFloor(scope)).Exact.ToArray());
            Assert.Equal(sends, await ReadSendRootForStoppedWork());
            Assert.Empty(await ListNativePendingText()); Assert.Empty(await ListOwnedMessages(scope));
            await WithAuthoredApplicationConnectionAsync(scope, sql =>
            {
                using var read = sql.CreateCommand();
                read.CommandText = "SELECT (SELECT count(*) FROM direct_text_outbox WHERE operation_id=$op),(SELECT count(*) FROM stopped_work_audit WHERE operation_id=$op);";
                read.Parameters.AddWithValue("$op", operation); using var row = read.ExecuteReader();
                Assert.True(row.Read()); Assert.Equal(0L, row.GetInt64(0)); Assert.Equal(1L, row.GetInt64(1)); Assert.False(row.Read());
            });
            var audit = await ReadStoppedAuditRow(scope, operation);
            Assert.Equal(operation, Assert.IsType<byte[]>(audit[0]));
            Assert.Equal((long)ProtectedDid2DirectTextJournal.WorkStopReason.UserCancelled, Assert.IsType<long>(audit[1]));
        }
    }
}
