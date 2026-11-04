namespace Deep.Client.Shared.Persistence.DeviceV2;

internal sealed partial class Did2MessagingSqlJournal
{
    // Closed runtime counters; no observer/delegate runs inside private SQL.
    internal static class NativeWork
    {
        private static readonly AsyncLocal<Counts?> Current = new();
        internal sealed class Counts : IDisposable
        {
            internal long Opens, CipherScans, MetadataRows, SuffixRows, Payloads, Audits, MaintenanceBatches;
            internal ulong WorkingCount, ArchiveCount;
            internal readonly double[] Timings = new double[8];
            public void Dispose() { if (ReferenceEquals(Current.Value, this)) Current.Value = null; }
        }
        internal static Counts Measure() { var result = new Counts(); Current.Value = result; return result; }
        internal static Counts? BeginOperation() => Current.Value is null ? Measure() : null;
        internal static void Open() { if (Current.Value is { } value) value.Opens++; }
        internal static void CipherScan() { if (Current.Value is { } value) value.CipherScans++; }
        internal static void MetadataRow() { if (Current.Value is { } value) value.MetadataRows++; }
        internal static void SuffixRow() { if (Current.Value is { } value) value.SuffixRows++; }
        internal static void Payload() { if (Current.Value is { } value) value.Payloads++; }
        internal static void Audit() { if (Current.Value is { } value) value.Audits++; }
        internal static void Maintenance() { if (Current.Value is { } value) value.MaintenanceBatches++; }
        internal static void Timing(ClientPersistencePhase phase, double milliseconds)
        { if (Current.Value is { } value) value.Timings[(int)phase] += milliseconds; }
        internal static void Inventory(ulong working, ulong archive)
        { if (Current.Value is { } value) { value.WorkingCount = working; value.ArchiveCount = archive; } }
    }
}
