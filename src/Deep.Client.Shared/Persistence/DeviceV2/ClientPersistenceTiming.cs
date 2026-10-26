using System.Diagnostics;
using System.Diagnostics.Tracing;

namespace Deep.Client.Shared.Persistence;

// Optional resource timing only. No slot, path, SQL, identity, state or payload
// can enter this closed event; observers cannot alter the storage result.
internal enum ClientPersistencePhase { StorageLoad = 1, GroupDecode, ApplicationOpen, ApplicationIntegrity, DeviceValidate, NativeReconcile, NativeVerify }

[EventSource(Name = "Deep-Client-Persistence")]
internal sealed class ClientPersistenceTiming : EventSource
{
    private static readonly ClientPersistenceTiming Log = new();
    internal static Measurement Measure(ClientPersistencePhase phase) => new(Log.IsEnabled() ? Stopwatch.GetTimestamp() : 0, phase);

    [Event(1, Level = EventLevel.Informational)]
    public void Completed(int phase, double milliseconds) => WriteEvent(1, phase, milliseconds);

    // Only the outer account operation publishes these facts, after private
    // SQL/state/lease disposal. Values are counts, never paths or identifiers.
    [Event(2, Level = EventLevel.Informational)]
    public void NativeCounts(long opens, long cipherScans, long metadataRows, long suffixRows,
        long payloads, long audits, long maintenanceBatches, long workingCount, long archiveCount)
        => WriteEvent(2, opens, cipherScans, metadataRows, suffixRows, payloads, audits, maintenanceBatches, workingCount, archiveCount);

    [NonEvent]
    internal static void PublishNativeCounts(DeviceV2.Did2MessagingSqlJournal.NativeWork.Counts counts)
    {
        if (!Log.IsEnabled()) return;
        try { Log.NativeCounts(counts.Opens, counts.CipherScans, counts.MetadataRows, counts.SuffixRows, counts.Payloads,
            counts.Audits, counts.MaintenanceBatches, checked((long)counts.WorkingCount), checked((long)counts.ArchiveCount)); }
        catch { /* Observation cannot replace the operation result. */ }
    }

    internal readonly struct Measurement(long started, ClientPersistencePhase phase) : IDisposable
    {
        public void Dispose()
        {
            if (started == 0) return;
            try { Log.Completed((int)phase, Stopwatch.GetElapsedTime(started).TotalMilliseconds); }
            catch { /* Optional observations never replace the original outcome. */ }
        }
    }
}
