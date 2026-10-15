using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Pure arithmetic coverage. The native cancellation/cold-reopen tests cover
// actual custody; these inputs cannot create trusted time or a stop fence.
public sealed class PreSessionStopTimeProjectionTests
{
    [Theory]
    [InlineData(1_790_000_000UL, 1_015UL, 1_000UL, 1_790_000_015UL)]
    [InlineData(1_000UL, ulong.MaxValue - 100UL, ulong.MaxValue - 110UL, 1_010UL)]
    [InlineData(1_000UL, ulong.MaxValue, ulong.MaxValue, 1_000UL)]
    [InlineData(0UL, 0UL, 0UL, 0UL)]
    [InlineData(ulong.MaxValue, 0UL, 0UL, ulong.MaxValue)]
    public void ElapsedFirstProjectionPreservesTheRepresentableResult(ulong bound, ulong sample, ulong anchor, ulong expected)
        => Assert.Equal(expected, ProtectedDeepIdV2AccountOwner.ProjectPreSessionStopTime(bound, sample, anchor));

    [Fact]
    public void LargeAbsoluteCounterDoesNotCauseIntermediateOverflow()
    {
        var bound = 1_000UL; var sample = ulong.MaxValue - 100UL; var anchor = sample - 10;
        Assert.Throws<OverflowException>(() => checked(bound + sample - anchor));
        Assert.Equal(1_010UL, ProtectedDeepIdV2AccountOwner.ProjectPreSessionStopTime(bound, sample, anchor));
    }

    [Theory]
    [InlineData(1_000UL, 99UL, 100UL)]
    [InlineData(0UL, 0UL, ulong.MaxValue)]
    [InlineData(ulong.MaxValue, 1UL, 0UL)]
    [InlineData(ulong.MaxValue - 1UL, 2UL, 0UL)]
    public void BackwardsSampleAndActualResultOverflowStillReject(ulong bound, ulong sample, ulong anchor)
        => Assert.Throws<OverflowException>(() => ProtectedDeepIdV2AccountOwner.ProjectPreSessionStopTime(bound, sample, anchor));
}
