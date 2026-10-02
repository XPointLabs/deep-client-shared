#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2MailboxSendFailpoint { BeforeSql, AfterSql, BeforeDispatch, BeforeOrdinaryCompletion, AfterOrdinaryCompletion }
internal static class Did2MailboxSendTestHooks
{
    private static readonly AsyncLocal<Action<Did2MailboxSendFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2MailboxSendFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2MailboxSendFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2MailboxSendFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
