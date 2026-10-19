using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2Groups_WorkingIdleMaintenanceDoesNotFetchWhenCurrentAndRefreshesBeforeDeadline()
    {
        await using var f = await Fixture.CreateAsync(); using var working = f.Source().OpenWorkingGroupScope();
        var first = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var count = f.ProofRequests;
        await working.Source.RefreshWorkingAuthorityAsync(default, onlyWhenDue: true);
        Assert.Equal(count, f.ProofRequests);
        f.Sample = first.Proof.FreshnessDeadlineMonotonicSeconds - 30;
        await working.Source.RefreshWorkingAuthorityAsync(default, onlyWhenDue: true);
        Assert.Equal(count + 1, f.ProofRequests);
        Assert.NotSame(first, await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
    }

    [Fact]
    public async Task Did2Groups_WorkingScopeReusesPublicAuthorityAcrossCommandsButNotIndependentAck()
    {
        await using var f = await Fixture.CreateAsync(); var parent = f.Source();
        using var working = parent.OpenWorkingGroupScope();
        var first = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var count = f.ProofRequests;
        for (var command = 0; command < 3; command++)
        {
            using var reads = working.Source.OpenCommandReadScope();
            Assert.Same(first, await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        }
        Assert.Equal(count, f.ProofRequests);
        Assert.NotSame(first, await parent.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count + 1, f.ProofRequests);
        working.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
    }

    [Fact]
    public async Task Did2Groups_WorkingRefreshIsSeparateAndNeverExtendsTheCapturedAuthority()
    {
        await using var f = await Fixture.CreateAsync(); using var working = f.Source().OpenWorkingGroupScope();
        var first = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var deadline = first.Proof.FreshnessDeadlineMonotonicSeconds; var count = f.ProofRequests;
        f.Sample++;
        await working.Source.RefreshWorkingAuthorityAsync(default);
        var next = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        Assert.NotSame(first, next); Assert.Equal(count + 1, f.ProofRequests);
        Assert.Equal(deadline, first.Proof.FreshnessDeadlineMonotonicSeconds);
        f.Sample = deadline;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await working.Source.RecheckOwnPreKeyAuthoringAsync(first, default));
    }

    [Fact]
    public async Task Did2Groups_WorkingRefreshFailureCannotFallBackToUnexpiredPreviousAuthority()
    {
        await using var f = await Fixture.CreateAsync(); using var working = f.Source().OpenWorkingGroupScope();
        _ = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var count = f.ProofRequests; f.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(() => working.Source.RefreshWorkingAuthorityAsync(default));
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count + 2, f.ProofRequests);
    }

    [Fact]
    public async Task Did2Groups_WorkingClockCannotRollBackEvenWhenStillAfterOriginalProofSample()
    {
        await using var f = await Fixture.CreateAsync(); using var working = f.Source().OpenWorkingGroupScope();
        var first = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        f.Sample += 2;
        Assert.Same(first, await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        f.Sample--; var count = f.ProofRequests;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        await Assert.ThrowsAsync<CryptographicException>(() => working.Source.RefreshWorkingAuthorityAsync(default));
        // Refresh has discarded the memo, but cannot reset its clock fence or
        // obtain a replacement proof on the rolled-back sample.
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count, f.ProofRequests);
    }

    [Fact]
    public async Task Did2Groups_WorkingScopeRejoinsActualForkFloorAndRejectsForeignAccountDirectory()
    {
        await using var f = await Fixture.CreateAsync(); await using var other = await Fixture.CreateAsync();
        using var working = f.Source().OpenWorkingGroupScope();
        var own = await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var foreign = await other.Source().VerifyForOwnPreKeyAuthoringAsync(other.Accounts, default);
        await Assert.ThrowsAsync<CryptographicException>(() => f.Accounts.RequireCurrentWorkingDirectoryAsync(
            foreign.Proof, new OnionMonotonicReading(Bytes(16, 0xf3), foreign.Proof.MonotonicSample), default));
        var floor = (await f.NetworkStore.ReadAsync(default))!;
        await f.NetworkStore.CompareExchangeAsync(floor.Revision, new(floor.Revision + 1, floor.ProtectedLkg, true), default);
        var count = f.ProofRequests;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await working.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count, f.ProofRequests);
    }
}
