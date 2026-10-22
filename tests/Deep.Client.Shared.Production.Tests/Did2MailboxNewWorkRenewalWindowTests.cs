using System.Security.Cryptography;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Client.Shared.Production.Tests;

public sealed class Did2MailboxNewWorkRenewalWindowTests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Retrieve, 1_024UL, false)]
    [InlineData(MailboxCapabilityDomain.Retrieve, 1_025UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_009UL, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_010UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_019UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_020UL, true)]
    public void ShortGrantRenewsBeforeTransportRetryWindowCloses(MailboxCapabilityDomain domain, ulong upper, bool due)
        => Assert.Equal(due, ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(1_000, 1_040, domain, upper));

    [Theory]
    [InlineData(3_879UL, false)] [InlineData(3_880UL, true)] [InlineData(4_600UL, true)]
    public void NormalGrantKeepsProportionalMarginAndExpiredIsDue(ulong upper, bool due)
        => Assert.Equal(due, ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(1_000, 4_600, MailboxCapabilityDomain.Retrieve, upper));

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_020UL, 1_040UL, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_039UL, 1_040UL, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_040UL, 1_040UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_041UL, 1_040UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_020UL, 1_039UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_020UL, 1_041UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_001UL, 1_039UL, true)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_001UL, 1_040UL, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, 1_001UL, 1_041UL, false)]
    [InlineData(MailboxCapabilityDomain.Retrieve, 1_030UL, 1_040UL, true)]
    public void FixedDepositCeilingSkipsOnlyLiveExactCeilingNotTightenedOrMovableLifetime(
        MailboxCapabilityDomain domain, ulong upper, ulong ceiling, bool due)
        => Assert.Equal(due, ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(
            1_000, 1_040, domain, upper, ceiling));

    [Fact]
    public void SchedulingRejectsUnknownRoleAndMalformedIntervalAndDoesNotOverflow()
    {
        Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(1_000, 4_600, (MailboxCapabilityDomain)255, 1_001));
        Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(0, 4_600, MailboxCapabilityDomain.Retrieve, 1_001));
        Assert.Throws<CryptographicException>(() => ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(1_000, 1_000, MailboxCapabilityDomain.Retrieve, 1_001));
        Assert.True(ProtectedDeepIdV2AccountOwner.IsMailboxGrantRenewalDueForNewWork(ulong.MaxValue - 3_600, ulong.MaxValue, MailboxCapabilityDomain.Retrieve, ulong.MaxValue));
    }
}
