namespace Deep.Client.Shared.Persistence.MessagingCryptoV1;

internal enum MessagingCryptoV1StoreFailpoint
{
    BeforeTransaction = 1,
    AfterJournalInsert = 2,
    AfterStateUpdate = 3,
    BeforeCommit = 4,
    AfterCommit = 5,
    BeforeInitialTransaction = 6,
    AfterInitialStateInsert = 7,
    AfterInitialPreKeyConsumption = 8,
    BeforeInitialCommit = 9,
    AfterInitialCommit = 10,
    BeforeInitiatorInitialTransaction = 11,
    AfterInitiatorInitialStateInsert = 12,
    AfterInitiatorInitialOutboxInsert = 13,
    BeforeInitiatorInitialCommit = 14,
    AfterInitiatorInitialCommit = 15,
}

internal sealed class MessagingCryptoV1InjectedCrashException(MessagingCryptoV1StoreFailpoint point) :
    Exception($"Injected MessagingCryptoV1 crash at {point}.")
{
    internal MessagingCryptoV1StoreFailpoint Point { get; } = point;
}

internal static class MessagingCryptoV1StoreTestHooks
{
#if DEEP_TEST_INTERNALS
    private static readonly AsyncLocal<Action<MessagingCryptoV1StoreFailpoint>?> Current = new();
    private static readonly AsyncLocal<int?> JournalCapacity = new();

    internal static IDisposable Push(Action<MessagingCryptoV1StoreFailpoint> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        var prior = Current.Value;
        Current.Value = action;
        return new Restore(() => Current.Value = prior);
    }

    internal static void Hit(MessagingCryptoV1StoreFailpoint point) => Current.Value?.Invoke(point);

    internal static int MaximumJournalEntries =>
        JournalCapacity.Value ?? MessagingCryptoV1Limits.MaximumJournalEntries;

    internal static IDisposable PushJournalCapacity(int capacity)
    {
        if (capacity < 0 || capacity > MessagingCryptoV1Limits.MaximumJournalEntries)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        var prior = JournalCapacity.Value;
        JournalCapacity.Value = capacity;
        return new Restore(() => JournalCapacity.Value = prior);
    }

    private sealed class Restore(Action restore) : IDisposable
    {
        private Action? action = restore;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
#else
    internal static void Hit(MessagingCryptoV1StoreFailpoint point) => _ = point;
    internal static int MaximumJournalEntries => MessagingCryptoV1Limits.MaximumJournalEntries;
#endif
}
