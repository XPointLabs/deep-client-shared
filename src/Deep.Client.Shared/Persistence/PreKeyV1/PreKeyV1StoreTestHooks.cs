namespace Deep.Client.Shared.Persistence.PreKeyV1;

internal enum PreKeyV1StoreFailpoint
{
    BeforeReserveTransaction = 1,
    AfterClaimInsert = 2,
    AfterInventoryUpdate = 3,
    BeforeReserveCommit = 4,
    AfterReserveCommit = 5,
    BeforeFinalizeCommit = 6,
    AfterFinalizeCommit = 7,
    AfterInitialSessionBindingBeforeCommit = 8,
    AfterInitialSessionBindingCommit = 9,
    AfterSessionCommitBeforeFinalize = 10,
    AfterInventorySecretsBeforePublication = 11,
    BeforeInventoryCommit = 12,
    AfterInventoryCommit = 13,
}

internal sealed class PreKeyV1InjectedCrashException(PreKeyV1StoreFailpoint point)
    : Exception($"Injected PreKeyV1 process loss at {point}.")
{
    internal PreKeyV1StoreFailpoint Point { get; } = point;
}

internal static class PreKeyV1StoreTestHooks
{
#if DEEP_TEST_INTERNALS
    private static readonly AsyncLocal<Action<PreKeyV1StoreFailpoint>?> Current = new();
    internal static IDisposable Push(Action<PreKeyV1StoreFailpoint> callback)
    {
        ArgumentNullException.ThrowIfNull(callback); var prior = Current.Value; Current.Value = callback;
        return new Restore(() => Current.Value = prior);
    }
    internal static void Hit(PreKeyV1StoreFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Restore(Action restore) : IDisposable
    {
        private Action? action = restore;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
#else
    internal static void Hit(PreKeyV1StoreFailpoint point) => _ = point;
#endif
}
