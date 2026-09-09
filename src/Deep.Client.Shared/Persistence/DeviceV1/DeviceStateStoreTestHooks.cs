namespace Deep.Client.Shared.Persistence.DeviceV1;

// Internal deterministic process-loss injection for the persistence contract tests.  This models
// a stop before SQLite's commit boundary; production code never installs a callback.
internal enum DeviceStateStoreFailpoint
{
    AfterGateAcquired = 1,
    AfterHeadWritten = 2,
    AfterChildReplacement = 3,
    BeforeDedupInsert = 4,
    BeforeCommit = 5,
    BeforeAgreementAuthorizationCommit = 6
}

internal sealed class DeviceStateStoreInjectedCrashException : Exception
{
    internal DeviceStateStoreInjectedCrashException(DeviceStateStoreFailpoint point)
        : base($"Injected DeviceV1 process loss at {point}.") { }
}

internal static class DeviceStateStoreTestHooks
{
    private static readonly object Sync = new();
    private static Action<DeviceStateStoreFailpoint>? callback;

    internal static IDisposable Push(Action<DeviceStateStoreFailpoint> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        lock (Sync)
        {
            if (callback is not null) throw new InvalidOperationException("A DeviceV1 test hook is already installed.");
            callback = value; return new Reset();
        }
    }

    internal static void Hit(DeviceStateStoreFailpoint point)
    {
        Action<DeviceStateStoreFailpoint>? current;
        lock (Sync) current = callback;
        current?.Invoke(point);
    }

    private sealed class Reset : IDisposable
    {
        public void Dispose() { lock (Sync) callback = null; }
    }
}
