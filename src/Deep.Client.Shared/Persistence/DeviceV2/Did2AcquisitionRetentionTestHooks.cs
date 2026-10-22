#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2AcquisitionRetentionFailpoint { BeforeSeal, AfterSeal, BeforeRestore, AfterRestore, BeforeDelete, AfterDelete }
internal static class Did2AcquisitionRetentionTestHooks
{
    private static readonly AsyncLocal<Action<Did2AcquisitionRetentionFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2AcquisitionRetentionFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2AcquisitionRetentionFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2AcquisitionRetentionFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
