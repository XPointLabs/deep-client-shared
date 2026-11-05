#if DEEP_TEST_INTERNALS
using Deep.Client.Shared.Services.ContactV2;

namespace Deep.Client.Shared.Persistence.DeviceV2;

// Test-only references to actual owned buffers; never copied/logged/serialized.
internal sealed record Did2StoreHandoffPrivateObservation(byte[][] GrantBuffers,
    VerifiedDeepIdV2CurrentAccount Account, object Loan, SqliteDeepMailboxStore Store,
    Did2StorePublicEvidence Evidence, Did2OwnedMailboxTransportContext Context);
internal static class Did2StoreHandoffTestHooks
{
    private static readonly AsyncLocal<Action<bool, Did2StoreHandoffPrivateObservation>?> Current = new();
    internal static IDisposable Push(Action<bool, Did2StoreHandoffPrivateObservation> action)
    { var before = Current.Value; Current.Value = action; return new Scope(before); }
    internal static void Observe(bool closed, Did2StoreHandoffPrivateObservation observation) => Current.Value?.Invoke(closed, observation);
    private sealed class Scope(Action<bool, Did2StoreHandoffPrivateObservation>? before) : IDisposable
    { public void Dispose() => Current.Value = before; }
}
#endif
