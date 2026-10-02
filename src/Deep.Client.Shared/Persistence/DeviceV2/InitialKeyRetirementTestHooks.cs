namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum InitialKeyRetirementFailpoint { AfterPending, AfterPreclaim, AfterSourceDelete, AfterStable }
internal static class InitialKeyRetirementTestHooks
{
    private static readonly AsyncLocal<Action<InitialKeyRetirementFailpoint>?> Current = new();
    internal static IDisposable Push(Action<InitialKeyRetirementFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(InitialKeyRetirementFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<InitialKeyRetirementFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
