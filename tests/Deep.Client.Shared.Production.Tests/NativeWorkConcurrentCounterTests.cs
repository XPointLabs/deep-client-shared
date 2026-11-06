using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed class NativeWorkConcurrentCounterTests
{
    [Fact]
    public async Task ParallelTargetObservationsKeepExactScalarTotalsAndInventoryMaxima()
    {
        // Tests observation accumulation only, not native IO, delivery or trust.
        const int targets = 4, observations = 10_000;
        using var work = Did2MessagingSqlJournal.NativeWork.Measure();
        await Task.WhenAll(Enumerable.Range(0, targets).Select(target => Task.Run(() =>
        {
            for (var index = 0; index < observations; index++)
            {
                Did2MessagingSqlJournal.NativeWork.Open();
                Did2MessagingSqlJournal.NativeWork.CipherScan();
                Did2MessagingSqlJournal.NativeWork.MetadataRow();
                Did2MessagingSqlJournal.NativeWork.SuffixRow();
                Did2MessagingSqlJournal.NativeWork.Payload();
                Did2MessagingSqlJournal.NativeWork.Audit();
                Did2MessagingSqlJournal.NativeWork.Maintenance();
                Did2MessagingSqlJournal.NativeWork.Timing(ClientPersistencePhase.StorageLoad, 1);
                var inventory = checked((ulong)(target * observations + index));
                Did2MessagingSqlJournal.NativeWork.Inventory(inventory, 2 * inventory);
            }
        })));
        var expected = (long)targets * observations;
        Assert.Equal(expected, work.Opens); Assert.Equal(expected, work.CipherScans);
        Assert.Equal(expected, work.MetadataRows); Assert.Equal(expected, work.SuffixRows);
        Assert.Equal(expected, work.Payloads); Assert.Equal(expected, work.Audits);
        Assert.Equal(expected, work.MaintenanceBatches);
        Assert.Equal((double)expected, work.Timings[(int)ClientPersistencePhase.StorageLoad]);
        Assert.Equal((ulong)(targets * observations - 1), work.WorkingCount);
        Assert.Equal(2 * work.WorkingCount, work.ArchiveCount);
    }
}
