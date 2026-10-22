using Deep.Client.Shared.Services.AccountDirectoryV2;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task DirectoryAvailability_EmptyCatchupStillRequiresAndAcquiresIndependentFreshProof()
    {
        await using var f = await Fixture.CreateAsync();
        var initial = await f.Source().VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var beforeProof = f.ProofRequests; var beforeHistory = f.HistoryRequests;
        f.TransientProofFailures = 1; f.TransientHistoryFailures = 1;
        var fresh = await f.Source().VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        Assert.Equal(beforeProof + 2, f.ProofRequests);
        Assert.Equal(beforeHistory + 2, f.HistoryRequests);
        Assert.NotSame(initial, fresh);
        Assert.Equal(initial.Proof.NextProtectedLkg.LogGeneration, fresh.Proof.NextProtectedLkg.LogGeneration);
        Assert.Equal(initial.Proof.NextProtectedLkg.CoreHash.ToArray(), fresh.Proof.NextProtectedLkg.CoreHash.ToArray());
    }

    [Fact]
    public async Task DirectoryAvailability_EmptyHistoryCannotReplaceUnavailableCurrentProof()
    {
        await using var f = await Fixture.CreateAsync();
        _ = await f.Source().VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var before = f.ProofRequests; var history = f.HistoryRequests;
        f.TransientProofFailures = 2;
        var refusal = await Assert.ThrowsAsync<DeepIdV2DirectoryProofUnavailableException>(async () =>
            await f.Source().VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, refusal.StatusCode);
        Assert.Equal(before + 2, f.ProofRequests); Assert.Equal(history + 1, f.HistoryRequests);
    }
}
