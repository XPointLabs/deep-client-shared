using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Structural metadata only, not authenticated stop/deletion/audit authority.
public sealed class Did2ControlWorkStopTests
{
    [Theory]
    [InlineData(0UL, ulong.MaxValue)] [InlineData(1UL, 1UL)] [InlineData(999UL, 1UL)]
    [InlineData(1_000UL, 1UL)] [InlineData(1_001UL, 2UL)] [InlineData(ulong.MaxValue, 18_446_744_073_709_552UL)]
    public void ExpiryProofUsesCeilingWithoutOverflowOrInventingADeadline(ulong milliseconds, ulong expected)
        => Assert.Equal(expected, Did2ControlWorkStop.ProvenExpirySecond(milliseconds));

    [Theory]
    [InlineData(0, 0, 0, false)]
    [InlineData(1, 0, 1000, false)] [InlineData(2, 0, 1000, false)]
    [InlineData(1, 1, 1000, true)] [InlineData(2, 1, 1000, true)]
    [InlineData(1, 2, 0, true)] [InlineData(2, 2, 0, true)]
    public void CanonicalTerminalMetadataDoesNotInferAnOutcome(byte reason, byte audit, ulong time, bool retired)
        => Did2ControlWorkStop.RequireCanonical(reason, audit, time, retired);

    [Theory]
    [InlineData(0, 0, 0, true)]
    [InlineData(3, 0, 1000, false)] [InlineData(1, 3, 1000, true)]
    [InlineData(0, 1, 1000, true)] [InlineData(0, 0, 1, false)]
    [InlineData(1, 0, 0, false)] [InlineData(1, 1, 1000, false)]
    [InlineData(1, 0, 1000, true)] [InlineData(1, 2, 1000, true)]
    [InlineData(1, 1, 0, true)]
    public void UnknownOrMixedTerminalStatesReject(byte reason, byte audit, ulong time, bool retired)
        => Assert.Throws<InvalidDataException>(() => Did2ControlWorkStop.RequireCanonical(reason, audit, time, retired));

    [Theory]
    [InlineData(0, false, 1000UL)] [InlineData(1, true, 1000UL)] [InlineData(2, true, 0UL)]
    public void SuccessfulControlMetadataHasAnIndependentFirstTime(byte audit, bool retired, ulong first)
        => Did2ControlWorkStop.RequireCanonical(0, audit, 0, retired, first);

    [Theory]
    [InlineData(0, false, 1UL, 1000UL)] [InlineData(1, false, 0UL, 1000UL)]
    [InlineData(0, true, 0UL, 1000UL)] [InlineData(1, true, 0UL, 0UL)]
    [InlineData(2, true, 0UL, 1000UL)] [InlineData(2, false, 0UL, 0UL)]
    [InlineData(0, false, 0UL, ulong.MaxValue)]
    public void SuccessfulControlMetadataRejectsMixedAndHostileStates(byte audit, bool retired, ulong stop, ulong first)
        => Assert.Throws<InvalidDataException>(() => Did2ControlWorkStop.RequireCanonical(0, audit, stop, retired, first));
}
