#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2MessagingArchiveEnrollmentFailpoint
{
    AfterSourceFrozen, AfterSchemaSql, AfterSchemaStaged, AfterBatchSql,
    AfterBatchProgress, AfterFinalSql, AfterFinalReady, AfterCatalogAndRoot,
    AfterAdoptionReadback, AfterCleanup
}
internal static class Did2MessagingArchiveEnrollmentTestHooks
{
    private static readonly AsyncLocal<Action<Did2MessagingArchiveEnrollmentFailpoint>?> Current = new();
    internal static IDisposable Push(Action<Did2MessagingArchiveEnrollmentFailpoint> action)
    { var before = Current.Value; Current.Value = action; return new Reset(before); }
    internal static void Hit(Did2MessagingArchiveEnrollmentFailpoint point) => Current.Value?.Invoke(point);
    private sealed class Reset(Action<Did2MessagingArchiveEnrollmentFailpoint>? before) : IDisposable
    { public void Dispose() => Current.Value = before; }
}
#endif
