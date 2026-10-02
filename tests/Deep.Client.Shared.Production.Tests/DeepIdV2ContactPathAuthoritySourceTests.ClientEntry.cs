using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Persistence.DeviceV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2PermanentClientEntry_ComposesOwnedPublicationAndReopensExactCommit()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckPermanentClientPublicationAsync();
    }

    [Fact]
    public async Task Did2PermanentClientEntry_OwnedPlanReopensAndResetChangesRetryScope()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.CheckPermanentClientPlanAsync();
    }

    [Fact]
    public void Did2PermanentClientEntry_PublicSurfaceHasNoIntentKeyTimeOrTransportCallback()
    {
        var publish = Assert.Single(typeof(DeepIdV2AccountService).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.Name == nameof(DeepIdV2AccountService.EnsureOwnPermanentContactPublishedAsync));
        Assert.Equal([typeof(DeepIdV2ContactPathAuthoritySource), typeof(CancellationToken)],
            publish.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
        var resolve = Assert.Single(typeof(DeepIdV2AccountService).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.Name == nameof(DeepIdV2AccountService.ResolvePermanentContactAsync));
        Assert.Equal([typeof(Deep.Protocol.Identity.DeepPermanentIdV2), typeof(DeepIdV2ContactPathAuthoritySource), typeof(CancellationToken)],
            resolve.GetParameters().Select(parameter => parameter.ParameterType).ToArray());
    }

    private sealed partial class Fixture
    {
        internal async Task CheckPermanentClientPublicationAsync()
        {
            var plan = await accounts.ReadOwnPermanentContactPlanAsync();
            var configuration = Did2OwnedPermanentContactPlan.Configuration();
            using var threshold = new OwnedRouteThreshold(this);
            var route = await EnsureRoute(plan.Intent.ToArray(), configuration, threshold, reopen: false);
            var publication = new OwnedPublicationSource(this, route);
            var replicas = new OwnedPublicationReplica(this, route);
            var committed = await accounts.EnsureOwnPermanentContactPublishedAsync(Source(), threshold, publication, replicas);
            Assert.Equal(0UL, committed.Generation);
            var calls = (threshold.Calls, publication.Calls, replicas.Calls);
            Assert.True(calls.Item1 > 0); Assert.True(calls.Item2 > 0); Assert.True(calls.Item3 > 0);
            var reopened = ReopenAccount();
            var exact = await reopened.EnsureOwnPermanentContactPublishedAsync(Source(reopened), threshold, publication, replicas);
            Assert.Equal(committed.ExactXpo1.ToArray(), exact.ExactXpo1.ToArray());
            Assert.Equal(calls, (threshold.Calls, publication.Calls, replicas.Calls));
            using var state = await RouteState();
            Assert.Equal((byte)7, state.Entries[Convert.ToHexString(plan.Intent.Span)].Phase);
        }

        internal async Task CheckPermanentClientPlanAsync()
        {
            var first = await accounts.ReadOwnPermanentContactPlanAsync();
            Assert.Equal("DID2 path test", first.Profile);
            var reopened = ReopenAccount();
            var again = await reopened.ReadOwnPermanentContactPlanAsync();
            Assert.True(first.Matches(again));
            Assert.Equal(first.Intent.ToArray(), again.Intent.ToArray());
            Assert.True(MemoryMarshal.TryGetArray(first.Intent, out var callerCopy));
            callerCopy.AsSpan().Clear();
            Assert.True(first.Matches(await reopened.ReadOwnPermanentContactPlanAsync()));
            var source = Source(); var before = ProofRequests;
            await Assert.ThrowsAsync<ArgumentException>(() => reopened.EnsureOwnPermanentContactPublishedAsync(source));
            var address = (await accounts.GetCurrentAsync())!.PermanentId;
            await Assert.ThrowsAsync<ArgumentException>(() => reopened.ResolvePermanentContactAsync(
                address, source));
            Assert.Equal(before, ProofRequests);
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accounts.ReadOwnPermanentContactPlanAsync(cancelled.Token));
            using (var threshold = new OwnedRouteThreshold(this))
            {
                await Assert.ThrowsAsync<CryptographicException>(() => accounts.EnsureOwnContactRouteAsync(
                    Bytes(32, 0x44), Source(), Did2OwnedPermanentContactPlan.Configuration(), threshold, bootstrap: first));
                Assert.Equal(0, threshold.Calls);
                using (var state = await RouteState()) Assert.Empty(state.Entries);
                using (Did2ContactRouteTestHooks.Push(point =>
                    { if (point == Did2ContactRouteFailpoint.AfterProposal) throw new IOException("Stop before external coordination."); }))
                    await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnContactRouteAsync(first.Intent,
                        Source(), Did2OwnedPermanentContactPlan.Configuration(), threshold, bootstrap: first));
                Assert.Equal(0, threshold.Calls);
                using var staged = await RouteState();
                Assert.Equal((byte)1, staged.Entries[Convert.ToHexString(first.Intent.Span)].Phase);
            }
            await accounts.ResetExplicitlyAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(() => accounts.ReadOwnPermanentContactPlanAsync());
            await accounts.CreateAsync("DID2 path test");
            var replaced = await accounts.ReadOwnPermanentContactPlanAsync();
            Assert.Equal(first.Profile, replaced.Profile);
            Assert.False(first.Matches(replaced));
            Assert.NotEqual(first.Intent.ToArray(), replaced.Intent.ToArray());
        }
    }
}
