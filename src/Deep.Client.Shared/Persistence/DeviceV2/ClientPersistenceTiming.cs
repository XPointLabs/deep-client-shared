using System.Diagnostics;
using System.Diagnostics.Tracing;

namespace Deep.Client.Shared.Persistence;

// Optional resource timing only. No slot, path, SQL, identity, state or payload
// can enter this closed event. Helpers only accumulate fixed numeric facts;
// they never dispatch an observer while SQL, keys or source loans are live.
internal enum ClientPersistencePhase { StorageLoad = 1, GroupDecode, ApplicationOpen, ApplicationIntegrity, DeviceValidate, NativeReconcile, NativeVerify }

[EventSource(Name = "Deep-Client-Persistence")]
internal sealed class ClientPersistenceTiming : EventSource
{
    // EventSource construction itself can dispatch OnEventSourceCreated. Delay
    // it until the same outer, disposed boundary as event publication.
    private static readonly Lazy<ClientPersistenceTiming> Log = new(static () => new ClientPersistenceTiming());
    internal static Measurement Measure(ClientPersistencePhase phase) => new(Stopwatch.GetTimestamp(), phase);

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
        var log = Log.Value;
        if (!log.IsEnabled()) return;
        try
        {
            for (var phase = 1; phase < counts.Timings.Length; phase++)
                if (counts.Timings[phase] != 0) log.Completed(phase, counts.Timings[phase]);
            log.NativeCounts(counts.Opens, counts.CipherScans, counts.MetadataRows, counts.SuffixRows, counts.Payloads,
            counts.Audits, counts.MaintenanceBatches, checked((long)counts.WorkingCount), checked((long)counts.ArchiveCount)); }
        catch { /* Observation cannot replace the operation result. */ }
    }

    internal readonly struct Measurement(long started, ClientPersistencePhase phase) : IDisposable
    {
        public void Dispose()
        {
            if (started == 0) return;
            // The existing outer account operation publishes aggregates only
            // after all private SQL/state/lease disposal. Standalone helpers
            // omit this optional observation when no outer scope is recording.
            try { DeviceV2.Did2MessagingSqlJournal.NativeWork.Timing(phase, Stopwatch.GetElapsedTime(started).TotalMilliseconds); }
            catch { /* Optional observations never replace the original outcome. */ }
        }
    }
}
