using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class OwnedOutboxMaintenancePolicyTests
{
    [Theory]
    [InlineData(32, 32, true)]
    [InlineData(ProtectedDid2DirectTextJournal.MaximumEntries - 1, ProtectedDid2MailboxSendJournal.MaximumEntries - 1, true)]
    [InlineData(ProtectedDid2DirectTextJournal.MaximumEntries, 32, false)]
    [InlineData(32, ProtectedDid2MailboxSendJournal.MaximumEntries, false)]
    [InlineData(-1, 32, false)]
    [InlineData(32, -1, false)]
    public void OnlyUnsettledPrefixBelowBothActualHardLimitsCanDeferSoftMaintenance(int commands, int sends, bool expected) =>
        Assert.Equal(expected, ProtectedDeepIdV2AccountOwner.CanDeferPinnedOrdinaryMaintenance(
            new ProtectedDeepIdV2AccountOwner.OutboxPrefixPinnedException(), commands, sends));

    [Fact]
    public void OrdinaryIoCorruptionCancellationAndCallerErrorsCannotBeSuppressed()
    {
        Exception[] errors = [new IOException(), new InvalidDataException(), new System.Security.Cryptography.CryptographicException(),
            new OperationCanceledException(), new InvalidOperationException()];
        Assert.All(errors, error => Assert.False(ProtectedDeepIdV2AccountOwner.CanDeferPinnedOrdinaryMaintenance(error, 32, 32)));
    }
}
