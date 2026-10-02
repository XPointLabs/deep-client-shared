#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2TextOutboxFailpoint { AfterPending, AfterSql, AfterStable }
internal static class Did2TextOutboxTestHooks
{
    private static readonly AsyncLocal<Action<Did2TextOutboxFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2TextOutboxFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2TextOutboxFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2TextOutboxFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
