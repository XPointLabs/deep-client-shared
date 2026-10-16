using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using System.Security.Cryptography;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task CoherentAcquisition_SignedViewAdvanceBetweenClosureAndProofReacquiresWithoutReset()
    {
        await using var fixture = await Fixture.CreateAsync();
        var prior = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var before = (await fixture.NetworkStore.ReadAsync(default))!;
        var fetches = fixture.NetworkClosureFetches;
        var observed = 0;
        fixture.OnClosureCapturedAsync = async token => {
            token.ThrowIfCancellationRequested(); observed++;
            await fixture.AdvanceNetworkAsync();
        };
        var current = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        current.EnsureCurrent();
        Assert.Equal(1, observed);
        Assert.Equal(fetches + 2, fixture.NetworkClosureFetches);
        Assert.Equal(prior.ProtectedLkg!.ViewGeneration + 1, current.ProtectedLkg!.ViewGeneration);
        var after = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(before.Revision + 1, after.Revision);
        Assert.False(after.ForkLatched);
        Assert.Equal(current.ProtectedLkg.ViewCoreReference.ToArray(), after.ProtectedLkg.ViewCoreReference.ToArray());
    }

    [Fact]
    public async Task CoherentAcquisition_RepeatedOlderClosureStopsAfterOneReacquisitionWithoutFloorMutation()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var before = (await fixture.NetworkStore.ReadAsync(default))!;
        var fetches = fixture.NetworkClosureFetches;
        fixture.FreezeNextDistributedClosure = true;
        fixture.OnClosureCapturedAsync = async token => {
            token.ThrowIfCancellationRequested(); await fixture.AdvanceNetworkAsync();
        };
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.Equal("dtt-binding-invalid", error.Code);
        Assert.Equal(fetches + 2, fixture.NetworkClosureFetches);
        var after = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.Equal(before.Revision, after.Revision);
        Assert.False(after.ForkLatched);
        Assert.Equal(before.ProtectedLkg.ViewCoreReference.ToArray(), after.ProtectedLkg.ViewCoreReference.ToArray());
    }

    [Fact]
    public async Task CoherentAcquisition_OtherClosureFailureDoesNotTriggerASecondAcquisition()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var before = (await fixture.NetworkStore.ReadAsync(default))!;
        var fetches = fixture.NetworkClosureFetches;
        fixture.AlterNode = true;
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.NotEqual("dtt-binding-invalid", error.Code);
        Assert.Equal(fetches + 1, fixture.NetworkClosureFetches);
        Assert.Equal(before.Revision, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task CoherentAcquisition_OriginalCancellationStopsAcquisitionWithoutAdvancingFloor()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var before = (await fixture.NetworkStore.ReadAsync(default))!;
        var fetches = fixture.NetworkClosureFetches;
        using var cancelled = new CancellationTokenSource();
        fixture.OnClosureCapturedAsync = async token => {
            token.ThrowIfCancellationRequested(); await fixture.AdvanceNetworkAsync(); cancelled.Cancel();
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network, cancelled.Token));
        Assert.Equal(fetches + 1, fixture.NetworkClosureFetches);
        Assert.Equal(before.Revision, (await fixture.NetworkStore.ReadAsync(default))!.Revision);
    }

    [Fact]
    public async Task CoherentAcquisition_ActualForkLatchChangedDuringReadCannotBeClearedByReacquisition()
    {
        await using var fixture = await Fixture.CreateAsync();
        _ = await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network);
        var before = (await fixture.NetworkStore.ReadAsync(default))!;
        fixture.OnClosureCapturedAsync = async token => {
            token.ThrowIfCancellationRequested(); await fixture.AdvanceNetworkAsync();
            _ = await fixture.NetworkStore.CompareExchangeAsync(before.Revision,
                new(before.Revision + 1, before.ProtectedLkg, true), token);
        };
        var error = await Record.ExceptionAsync(async () =>
            await fixture.Source().VerifyCurrentNetworkAsync(Fixture.Network));
        Assert.True(error is CryptographicException or IOException,
            "Changed actual protected custody must reject before releasing a network.");
        var after = (await fixture.NetworkStore.ReadAsync(default))!;
        Assert.True(after.ForkLatched);
        Assert.Equal(before.Revision + 1, after.Revision);
        Assert.Equal(before.ProtectedLkg.ViewCoreReference.ToArray(), after.ProtectedLkg.ViewCoreReference.ToArray());
    }

    private sealed partial class Fixture
    {
        internal Func<CancellationToken, Task>? OnClosureCapturedAsync;
        internal bool FreezeNextDistributedClosure;
        private DeepIdV2NetworkClosureArtifacts? frozenDistributedClosure;
    }
}
