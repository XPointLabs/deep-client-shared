#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2ContactThresholdWaitFailpoint { BeforeWait, AfterWait }
internal static class Did2ContactThresholdWaitTestHooks
{
    private static readonly AsyncLocal<Action<Did2ContactThresholdWaitFailpoint>?> Hook = new();
    internal static void Hit(Did2ContactThresholdWaitFailpoint point) => Hook.Value?.Invoke(point);
    internal static IDisposable Push(Action<Did2ContactThresholdWaitFailpoint> action)
    { var prior = Hook.Value; Hook.Value = action; return new Restore(prior); }
    private sealed class Restore(Action<Did2ContactThresholdWaitFailpoint>? prior) : IDisposable
    { public void Dispose() => Hook.Value = prior; }
}
#endif
