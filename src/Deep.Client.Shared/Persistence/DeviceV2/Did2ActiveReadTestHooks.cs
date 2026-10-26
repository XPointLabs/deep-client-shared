#if DEEP_TEST_INTERNALS
using Microsoft.Data.Sqlite;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Adversarial substitution only. No shipping callback exists at this boundary.
internal static class Did2ActiveReadTestHooks
{
    private static readonly AsyncLocal<Action<SqliteConnection, SqliteTransaction>?> Current = new();
    internal static IDisposable Push(Action<SqliteConnection, SqliteTransaction> action)
    { var previous = Current.Value; Current.Value = action; return new Reset(previous); }
    internal static void AfterProof(SqliteConnection connection, SqliteTransaction transaction)
    { var action = Current.Value; Current.Value = null; action?.Invoke(connection, transaction); }
    private sealed class Reset(Action<SqliteConnection, SqliteTransaction>? previous) : IDisposable
    { public void Dispose() => Current.Value = previous; }
}
#endif
