#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2MessagingCommitFailpoint { AfterPending, AfterSql, AfterStable }
internal static class Did2MessagingCommitTestHooks
{
    private static readonly AsyncLocal<Action<Did2MessagingCommitFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2MessagingCommitFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2MessagingCommitFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2MessagingCommitFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
