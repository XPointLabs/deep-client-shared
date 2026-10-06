#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2CompactionFailpoint { AfterStage, AfterSql, AfterSqlRecorded, AfterHistoryAdopted, AfterPartsDeleted, AfterPlanCleared }
internal static class Did2CompactionTestHooks
{
    private static readonly AsyncLocal<Action<Did2CompactionFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2CompactionFailpoint> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void Hit(Did2CompactionFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2CompactionFailpoint>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
