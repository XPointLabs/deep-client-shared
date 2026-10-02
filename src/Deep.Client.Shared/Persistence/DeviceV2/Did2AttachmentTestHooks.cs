#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2AttachmentFailpoint { AfterSqlBeforePending, AfterPending, AfterStable }
internal static class Did2AttachmentTestHooks
{
    private static readonly AsyncLocal<Action<Did2AttachmentFailpoint>?> Hook = new();
    internal static void Hit(Did2AttachmentFailpoint point) => Hook.Value?.Invoke(point);
    internal static IDisposable Push(Action<Did2AttachmentFailpoint> action)
    { var prior = Hook.Value; Hook.Value = action; return new Restore(prior); }
    private sealed class Restore(Action<Did2AttachmentFailpoint>? prior) : IDisposable
    { public void Dispose() => Hook.Value = prior; }
}
#endif
