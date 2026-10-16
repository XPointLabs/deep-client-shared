using System.Security.Cryptography;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Protocol.ApplicationCore;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task ContactWorkflow_ReopensCommittedPrekeysAndContactWithOneFreshAcquisition()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        var backend = new RenewalBackend(fixture);
        // Explicit signed fixture phases establish the completed predecessor;
        // the public workflow below uses the real production composition.
        var expected = await fixture.Accounts.EnsureOwnPermanentContactPublishedAsync(
            fixture.Source(), backend, backend, backend);
        _ = await fixture.StageAndRecordPairAsync();
        fixture.ColdReopenCompactionStorage();
        var account = fixture.ReopenAccount();
        var source = fixture.Source(account);
        var before = fixture.ProofRequests;
        var actual = await account.EnsureOwnPermanentContactPublishedAsync(source);
        Assert.Equal(before + 1, fixture.ProofRequests);
        Assert.Equal(expected.ExactXpo1.ToArray(), actual.ExactXpo1.ToArray());
        Assert.NotNull(await account.ReadOwnPreKeyCommitPairAsync());
        var custody = await account.OpenOwnOnionClientCustodyAsync();
        Assert.Null(await custody.Guards.ReadAsync(default));
        // Current signed/native cold-reopen evidence, not socket/device E2E.
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task ContactWorkflow_InvalidPrekeyPairCannotReachOrAlterContactPublication()
    {
        await using var fixture = await Fixture.CreateAsync(encryptedStorage: true);
        _ = await fixture.StageAndRecordPairAsync(badSignature: true);
        var before = await fixture.RouteSnapshot();
        try
        {
            await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
                fixture.Accounts.EnsureOwnPermanentContactPublishedAsync(fixture.Source()));
            var after = await fixture.RouteSnapshot();
            try { Assert.Equal(before, after); }
            finally { CryptographicOperations.ZeroMemory(after); }
            var custody = await fixture.Accounts.OpenOwnOnionClientCustodyAsync();
            Assert.Null(await custody.Guards.ReadAsync(default));
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }
}
