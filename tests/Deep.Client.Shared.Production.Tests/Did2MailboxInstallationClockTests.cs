using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

// Exercises the production arithmetic only. These numbers are not trusted
// time, a held lease, a route, a grant or permission to dispatch.
public sealed class Did2MailboxInstallationClockTests
{
    [Theory]
    [InlineData(1899UL, 1900UL, 0, 1900UL)]
    [InlineData(1899UL, 1900UL, 1, 1901UL)]
    [InlineData(1899UL, 1900UL, 1000, 1901UL)]
    [InlineData(1899UL, 1900UL, 2500, 1903UL)]
    [InlineData(1902UL, 1900UL, 2500, 1905UL)]
    [InlineData(1900UL, 0UL, 0, 1900UL)]
    [InlineData(1900UL, 0UL, 29999, 1930UL)]
    public void BothConservativeBoundsAgeWithoutRewindingOrRoundingDown(
        ulong sampledUpper, ulong preparedUpper, int elapsedMilliseconds, ulong expected)
        => Assert.Equal(expected, ProtectedDeepIdV2AccountOwner.MailboxInstallationUpperAtElapsed(
            sampledUpper, preparedUpper, TimeSpan.FromMilliseconds(elapsedMilliseconds)));

    [Theory]
    [InlineData(-1)] [InlineData(30000)] [InlineData(30001)]
    public void NegativeOrExpiredScopeRejectsBeforeArithmetic(int elapsedMilliseconds)
        => Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.MailboxInstallationUpperAtElapsed(
            1900, 1901, TimeSpan.FromMilliseconds(elapsedMilliseconds)));

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public void EitherConservativeBoundOverflowRejectsInsteadOfWrapping(bool preparationIsMaximum)
        => Assert.Throws<OverflowException>(() => ProtectedDeepIdV2AccountOwner.MailboxInstallationUpperAtElapsed(
            preparationIsMaximum ? 1900 : ulong.MaxValue,
            preparationIsMaximum ? ulong.MaxValue : 0, TimeSpan.FromMilliseconds(1)));

    [Fact]
    public void PreparationFloorStillReachesOriginalExpiryWhenFreshSampleIsLower()
    {
        const ulong originalExpiry = 1903;
        var upper = ProtectedDeepIdV2AccountOwner.MailboxInstallationUpperAtElapsed(
            1899, 1900, TimeSpan.FromMilliseconds(2500));
        Assert.Equal(originalExpiry, upper); // CurrentUpper rejects upper >= expiry.
    }
}
