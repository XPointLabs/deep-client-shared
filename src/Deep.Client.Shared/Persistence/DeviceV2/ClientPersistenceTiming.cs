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
