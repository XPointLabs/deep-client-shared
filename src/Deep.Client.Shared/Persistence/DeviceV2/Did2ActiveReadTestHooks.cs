#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;

// Adversarial substitution only. No shipping callback exists at this boundary.
internal static class Did2ActiveReadTestHooks
{
    private static readonly AsyncLocal<Action?> Current = new();
    internal static IDisposable Push(Action action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void BeforeSelectedPayload()
    {
        var action = Current.Value; Current.Value = null;
        if (action is not null) throw new Did2ActiveReadBoundary(action);
    }
    private sealed class Reset(Action? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
internal sealed class Did2ActiveReadBoundary(Action callback) : Exception
{
    internal void Invoke() => callback();
}
#endif
