#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2MessagingCommitFailpoint { AfterPending, AfterSql, AfterStable }
internal static class Did2MessagingCommitTestHooks
{
    private static readonly AsyncLocal<Func<Did2MessagingCommitFailpoint, ValueTask>?> Current = new();
    internal static IDisposable Push(Action<Did2MessagingCommitFailpoint> action)
        => PushAsync(point => { action(point); return ValueTask.CompletedTask; });
    internal static IDisposable PushAsync(Func<Did2MessagingCommitFailpoint, ValueTask> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static ValueTask HitAsync(Did2MessagingCommitFailpoint point) => Current.Value?.Invoke(point) ?? ValueTask.CompletedTask;
    private sealed class Reset(Func<Did2MessagingCommitFailpoint, ValueTask>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
