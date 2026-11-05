#if DEEP_TEST_INTERNALS
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV1;
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2MailboxInstallationFailpoint { BeforeSelection, BeforeSql, AfterSql, BeforeClosure, AfterClosure, BeforeLateResult, AfterLateResult, BeforeLateAdoption, AfterLateAdoption, BeforeReadIntent, AfterReadIntent, BeforeReadClosure, AfterReadClosure, BeforeAckClosure, AfterAckClosure, BeforeTraversalRestart, AfterTraversalRestart, AfterRetainedGrantReplyCopied }
internal static class Did2MailboxInstallationTestHooks
{
    private static readonly AsyncLocal<Action<Did2MailboxInstallationFailpoint>?> Current = new();
    private static readonly AsyncLocal<Action<CancellationTokenSource>?> RetainedGrantTransport = new();
    internal static IDisposable PushRetainedGrantTransport(Action<CancellationTokenSource> configure)
    { var previous = RetainedGrantTransport.Value; RetainedGrantTransport.Value = configure; return new ResetRetainedGrantTransport(previous); }
    internal static void ConfigureRetainedGrantTransport(CancellationTokenSource deadline) => RetainedGrantTransport.Value?.Invoke(deadline);
    private static readonly AsyncLocal<Func<Did2OwnedMailboxTransportContext, ScopedMailboxResolvedRoute, CancellationToken, Task>?> HeldPath = new();
    private static readonly AsyncLocal<Func<SqliteDeepMailboxStore, MailboxCredentialSelector, ScopedMailboxResolvedRoute,
        IMailboxOperationSigner, VerifiedOfficialMailboxAuthority, CancellationToken, Task>?> ReadPreparation = new();
    internal static IDisposable PushReadPreparation(Func<SqliteDeepMailboxStore, MailboxCredentialSelector, ScopedMailboxResolvedRoute,
        IMailboxOperationSigner, VerifiedOfficialMailboxAuthority, CancellationToken, Task> prepare)
    { var previous = ReadPreparation.Value; ReadPreparation.Value = prepare; return new ResetReadPreparation(previous); }
    internal static Task CheckReadPreparationAsync(SqliteDeepMailboxStore store, MailboxCredentialSelector selector,
        ScopedMailboxResolvedRoute route, IMailboxOperationSigner signer, VerifiedOfficialMailboxAuthority authority, CancellationToken ct) =>
        ReadPreparation.Value?.Invoke(store, selector, route, signer, authority, ct) ?? Task.CompletedTask;
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
    private sealed class ResetRetainedGrantTransport(Action<CancellationTokenSource>? previous) : IDisposable
    { public void Dispose() => RetainedGrantTransport.Value = previous; }
    private sealed class ResetHeldPath(Func<Did2OwnedMailboxTransportContext, ScopedMailboxResolvedRoute, CancellationToken, Task>? previous) : IDisposable
    { public void Dispose() => HeldPath.Value = previous; }
    private sealed class ResetReadPreparation(Func<SqliteDeepMailboxStore, MailboxCredentialSelector, ScopedMailboxResolvedRoute,
        IMailboxOperationSigner, VerifiedOfficialMailboxAuthority, CancellationToken, Task>? previous) : IDisposable
    { public void Dispose() => ReadPreparation.Value = previous; }
}
#endif
