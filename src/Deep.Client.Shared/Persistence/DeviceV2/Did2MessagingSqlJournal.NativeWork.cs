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
#if DEEP_TEST_INTERNALS
            internal long InitialHandoffs, PagedPeerConsentReads;
#endif
            internal ulong WorkingCount, ArchiveCount;
            internal readonly double[] Timings = new double[8];
            public void Dispose() { if (ReferenceEquals(Current.Value, this)) Current.Value = null; }
        }
        internal static Counts Measure() { var result = new Counts(); Current.Value = result; return result; }
        internal static Counts? BeginOperation() => Current.Value is null ? Measure() : null;
        internal static void Open() { if (Current.Value is { } value) Interlocked.Increment(ref value.Opens); }
#if DEEP_TEST_INTERNALS
        internal static void InitialHandoff() { if (Current.Value is { } value) Interlocked.Increment(ref value.InitialHandoffs); }
        internal static void PagedPeerConsentRead() { if (Current.Value is { } value) Interlocked.Increment(ref value.PagedPeerConsentReads); }
#endif
        internal static void CipherScan() { if (Current.Value is { } value) Interlocked.Increment(ref value.CipherScans); }
        internal static void MetadataRow() { if (Current.Value is { } value) Interlocked.Increment(ref value.MetadataRows); }
        internal static void SuffixRow() { if (Current.Value is { } value) Interlocked.Increment(ref value.SuffixRows); }
        internal static void Payload() { if (Current.Value is { } value) Interlocked.Increment(ref value.Payloads); }
        internal static void Audit() { if (Current.Value is { } value) Interlocked.Increment(ref value.Audits); }
        internal static void Maintenance() { if (Current.Value is { } value) Interlocked.Increment(ref value.MaintenanceBatches); }
        internal static void Timing(ClientPersistencePhase phase, double milliseconds)
        { if (Current.Value is { } value) lock (value) value.Timings[(int)phase] += milliseconds; }
        internal static void Inventory(ulong working, ulong archive)
        { if (Current.Value is { } value) lock (value) { value.WorkingCount = Math.Max(value.WorkingCount, working); value.ArchiveCount = Math.Max(value.ArchiveCount, archive); } }
    }
}
