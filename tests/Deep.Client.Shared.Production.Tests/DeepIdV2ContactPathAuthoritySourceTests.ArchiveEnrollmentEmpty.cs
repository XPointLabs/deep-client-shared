using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Theory]
    [InlineData("AfterSchemaStaged")]
    [InlineData("AfterBatchProgress")]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2ArchiveEnrollment_EmptyHistoryColdResumesThroughBuildingWithoutChangingActiveSource(string cut)
    {
        await using var fixture = await Fixture.CreateAsync(withPeer: true, encryptedStorage: true);
        var pair = await fixture.PrepareArchiveEnrollmentPair(0);
        using var original = await fixture.StageActualLegacyArchiveInput([pair.Sender], archivePrefix: false);
        Assert.True(original.Floors[0].Ordinal > 2); // Genuine active native originals remain outside the empty archived prefix.
        var hit = false;
        using (Did2MessagingArchiveEnrollmentTestHooks.Push(point =>
            { if (point.ToString() == cut) { hit = true; throw new IOException("Interrupted empty archive enrollment."); } }))
            await Assert.ThrowsAsync<IOException>(() => fixture.EnrollArchiveAccount());
        Assert.True(hit);
        using (var raw = await fixture.NativeStorage(pair.Sender).ReadOwnedAsync(ProtectedDid2MessagingArchiveEnrollment.Slot))
        {
            Assert.NotNull(raw);
            var progress = raw!.Use(bytes => ProtectedDid2MessagingArchiveEnrollment.Decode(bytes, pair.Sender));
            var phase = cut == "AfterSchemaStaged" ? ProtectedDid2MessagingArchiveEnrollment.PhaseKind.SchemaStaged :
                ProtectedDid2MessagingArchiveEnrollment.PhaseKind.Building;
            Assert.Equal(phase, progress.Phase); Assert.Equal((ulong)phase, progress.Revision);
            Assert.Equal(0UL, progress.SourceHistory.HistoryCount); Assert.Equal(0UL, progress.TargetBasis.Ordinal);
            Assert.Equal(0UL, progress.Cursor); Assert.Equal(0UL, progress.Count);
            Assert.Throws<InvalidDataException>(() => progress.FinalRoot(pair.Sender));
        }
        await fixture.AssertArchiveSourceUnchanged(original);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ListOwnedMessages(pair.Sender));
        fixture.ColdReopenCompactionStorage();
        await fixture.EnrollArchiveAccount();
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(original);
        await fixture.EnrollArchiveAccount(); // The completed empty archive is an idempotent audited enrollment.
        await fixture.AssertArchiveAdoptedWithoutSourceMutation(original);
        using (var command = await fixture.CreateOwnedText(pair.Sender, "fresh work after empty archive enrollment"))
        using (var sent = await fixture.SendOwnedMessage(pair.Sender, command.OperationId, ApplicationCoreCodec.DecodeDmc2(command.ExactDmc2.Span)))
        using (var received = await fixture.ReceiveOwnedMessage(pair.Receiver, sent.ExactEnvelope.ToArray())) { }
        Assert.Equal(original.Floors[0].Ordinal + 1, (await fixture.ReadMessagingFloor(pair.Sender)).Ordinal);
    }
}
