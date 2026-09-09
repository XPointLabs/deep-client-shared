namespace Deep.Client.Shared.Persistence.AccountDirectoryV1;

internal enum AccountDirectoryStoreFailpoint { AfterHeadWrite = 1, AfterSubjectReplacement = 2, BeforeCommit = 3 }
internal sealed class AccountDirectoryStoreInjectedCrashException(AccountDirectoryStoreFailpoint point)
    : Exception($"Injected AccountDirectoryV1 crash at {point}.");

internal static class AccountDirectoryStateStoreTestHooks
{
    private static readonly AsyncLocal<Action<AccountDirectoryStoreFailpoint>?> Current = new();
    internal static IDisposable Push(Action<AccountDirectoryStoreFailpoint> callback)
    {
        var previous = Current.Value; Current.Value = callback;
        return new Scope(() => Current.Value = previous);
    }
    internal static void Hit(AccountDirectoryStoreFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Scope(Action dispose) : IDisposable
    {
        private Action? action = dispose;
        public void Dispose() => Interlocked.Exchange(ref action, null)?.Invoke();
    }
}
