#if DEEP_TEST_INTERNALS
namespace Deep.Client.Shared.Persistence.DeviceV2;
internal enum Did2ContactRouteFailpoint { AfterProposal, AfterThreshold, AfterComplete, AfterContactObject, AfterRenewalRequest, AfterRenewalResponse, AfterRenewalPromotion }
internal static class Did2ContactRouteTestHooks
{
    private static readonly AsyncLocal<Action<Did2ContactRouteFailpoint>?> Hook = new();
    internal static void Hit(Did2ContactRouteFailpoint point) => Hook.Value?.Invoke(point);
    internal static IDisposable Push(Action<Did2ContactRouteFailpoint> action)
    { var prior = Hook.Value; Hook.Value = action; return new Restore(prior); }
    private sealed class Restore(Action<Did2ContactRouteFailpoint>? prior) : IDisposable
    { public void Dispose() => Hook.Value = prior; }
}
#endif
