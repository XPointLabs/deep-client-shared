namespace Deep.Client.Shared.Persistence.DeviceV2;

internal enum Did2AtomicQueueFailpoint { AfterProtectedCommit, AfterNativeCommit }
internal static class Did2AtomicQueueTestHooks
{
    private static readonly AsyncLocal<Action<Did2AtomicQueueFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2AtomicQueueFailpoint> action)
    { var prior = Current.Value; Current.Value = action; return new Reset(prior); }
    internal static void Hit(Did2AtomicQueueFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2AtomicQueueFailpoint>? prior) : IDisposable
    { public void Dispose() => Current.Value = prior; }
}
