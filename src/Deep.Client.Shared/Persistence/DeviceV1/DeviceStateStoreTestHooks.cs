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
    BeforeAgreementAuthorizationCommit = 6,
    AfterInitialSessionPendingCheckpoint = 7,
    AfterInitialSessionSqlCommit = 8,
    AfterInitialSessionStableCheckpoint = 9
}

internal sealed class DeviceStateStoreInjectedCrashException : Exception
{
    internal DeviceStateStoreInjectedCrashException(DeviceStateStoreFailpoint point)
        : base($"Injected DeviceV1 process loss at {point}.") { }
}

internal static class DeviceStateStoreTestHooks
{
    private static readonly AsyncLocal<Action<DeviceStateStoreFailpoint>?> Callback = new();

    internal static IDisposable Push(Action<DeviceStateStoreFailpoint> value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Callback.Value is not null) throw new InvalidOperationException("A DeviceV1 test hook is already installed.");
        Callback.Value = value;
        return new Reset();
    }

    internal static void Hit(DeviceStateStoreFailpoint point) => Callback.Value?.Invoke(point);

    private sealed class Reset : IDisposable
    {
        private int disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0) Callback.Value = null;
        }
    }
}
