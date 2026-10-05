#if DEEP_TEST_INTERNALS
using Deep.Client.Shared.Services.ContactV2;
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2MailboxInstallationFailpoint { BeforeSelection, BeforeSql, AfterSql, BeforeClosure, AfterClosure, BeforeLateResult, AfterLateResult, BeforeLateAdoption, AfterLateAdoption }
internal static class Did2MailboxInstallationTestHooks
{
    private static readonly AsyncLocal<Action<Did2MailboxInstallationFailpoint>?> Current = new();
    private static readonly AsyncLocal<Func<Did2OwnedMailboxTransportContext, ScopedMailboxResolvedRoute, CancellationToken, Task>?> HeldPath = new();
    internal static bool HasHeldPathCheck => HeldPath.Value is not null;
    internal static Task CheckHeldPathAsync(Did2OwnedMailboxTransportContext context, ScopedMailboxResolvedRoute route,
        CancellationToken ct) => HeldPath.Value?.Invoke(context, route, ct) ?? Task.CompletedTask;
    internal static IDisposable PushHeldPath(Func<Did2OwnedMailboxTransportContext, ScopedMailboxResolvedRoute, CancellationToken, Task> check)
    { var previous = HeldPath.Value; HeldPath.Value = check; return new ResetHeldPath(previous); }
    internal static IDisposable Push(Action<Did2MailboxInstallationFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2MailboxInstallationFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2MailboxInstallationFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
    private sealed class ResetHeldPath(Func<Did2OwnedMailboxTransportContext, ScopedMailboxResolvedRoute, CancellationToken, Task>? previous) : IDisposable
    { public void Dispose() => HeldPath.Value = previous; }
}
#endif
