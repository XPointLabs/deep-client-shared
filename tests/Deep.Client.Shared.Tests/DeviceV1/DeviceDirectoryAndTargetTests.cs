using Deep.Client.Shared.Domain.DeviceV1;

namespace Deep.Client.Shared.Tests.DeviceV1;

public sealed class DeviceDirectoryAndTargetTests
{
    [Fact]
    public void NextGenerationWrongPredecessor_PermanentlyForkLatches()
    {
        var active = DeviceV1Fixture.Active(0x20, 0x50);
        var genesis = DeviceV1Fixture.Directory(1, 0x40, 0x60, [active]);
        var state = DeviceDirectoryState.Start(genesis).Next;
        var wrong = DeviceV1Fixture.Directory(2, 0x41, 0x60, [active],
            DeviceDirectoryHash32.FromBytes(DeviceV1Fixture.Bytes(32, 0x77)));
        var result = state.PrepareTransition(wrong);
        Assert.Equal(DeviceDirectoryTransitionDisposition.ForkLatched, result.Disposition);
        Assert.True(result.Next.ForkLatched);
        var correct = DeviceV1Fixture.Directory(2, 0x42, 0x60, [active], genesis.DirectoryHash);
        Assert.Equal(DeviceDirectoryTransitionDisposition.ForkLatched,
            result.Next.PrepareTransition(correct).Disposition);
    }

    [Fact]
    public void FullFloor_BlocksInstallSelectEnrollAndRevalidate()
    {
        var a = DeviceV1Fixture.Active(0x20, 0x50); var revoked = DeviceV1Fixture.Active(0x21, 0x51);
        var old = DeviceV1Fixture.Directory(1, 0x40, 0x60, [a, revoked]);
        var oldState = DeviceDirectoryState.Start(old).Next;
        var stalePlan = DeviceTargetSelector.SelectExact(oldState, revoked.DeviceId);
        var currentFacts = DeviceV1Fixture.Directory(2, 0x41, 0x61, [a], old.DirectoryHash, 2);
        var current = DeviceDirectoryState.Restore(currentFacts, false, [DeviceV1Fixture.Floor(revoked.DeviceId)]);

        Assert.Equal(DeviceTargetSelectionOutcome.RevokedTarget,
            DeviceTargetSelector.SelectExact(current, revoked.DeviceId).Outcome);
        Assert.Equal(DeviceTargetSelectionOutcome.RevokedTarget,
            DeviceTargetSelector.Revalidate(stalePlan, current));
        Assert.Throws<InvalidOperationException>(() => DeviceMutationIntent.Enroll(current,
            DeviceV1Fixture.Enrollment(0x21, 0x70, 0x61, 2),
            DeviceRecoveryIntent.FromPhrase(DeviceV1Fixture.Account(), 1, revoked.DeviceId)));

        var reused = DeviceV1Fixture.Directory(3, 0x42, 0x61, [a, revoked], currentFacts.DirectoryHash, 2);
        var transition = current.PrepareTransition(reused);
        Assert.Equal(DeviceDirectoryTransitionDisposition.RevokedDeviceReuse, transition.Disposition);
        Assert.True(transition.Next.ForkLatched);
    }

    [Fact]
    public void StaleDirectoryPredatingLocalFloor_IsStaleCandidate_NotFork()
    {
        var retained = DeviceV1Fixture.Active(0x20, 0x50);
        var revoked = DeviceV1Fixture.Active(0x21, 0x51);
        var oldFacts = DeviceV1Fixture.Directory(1, 0x40, 0x60, [retained, revoked]);
        var currentFacts = DeviceV1Fixture.Directory(2, 0x41, 0x61, [retained], oldFacts.DirectoryHash, 2);
        var current = DeviceDirectoryState.Restore(currentFacts, false, [DeviceV1Fixture.Floor(revoked.DeviceId)]);

        var result = current.PrepareTransition(oldFacts);

        Assert.Equal(DeviceDirectoryTransitionDisposition.StaleCandidate, result.Disposition);
        Assert.Same(current, result.Next);
        Assert.False(result.Next.ForkLatched);
    }

    [Fact]
    public void FanoutTargetAndObservation_IncludeAccountGeneration()
    {
        var active = DeviceV1Fixture.Active(0x20, 0x50);
        var facts = DeviceV1Fixture.Directory(1, 0x40, 0x60, [active], accountGeneration: 7);
        var state = DeviceDirectoryState.Start(facts).Next;
        var plan = DeviceTargetSelector.SelectAllActive(state,
            new DeviceDirectoryObservation(facts.AccountId, 7, 1, facts.DirectoryHash));
        Assert.Equal(7UL, plan.AccountGeneration);
        Assert.Equal(7UL, Assert.Single(plan.Targets).AccountGeneration);
        var wrongGeneration = DeviceTargetSelector.SelectAllActive(state,
            new DeviceDirectoryObservation(facts.AccountId, 8, 1, facts.DirectoryHash));
        Assert.Equal(DeviceTargetSelectionOutcome.StaleDirectory, wrongGeneration.Outcome);
    }
}
