using System.Security.Cryptography;

namespace Deep.Client.Shared.Production.Tests;

public sealed partial class DeepIdV2ContactPathAuthoritySourceTests
{
    [Fact]
    public async Task Did2MailboxAck_PhaseMemoAcquiresIndependentlyAndNeverRenewsReceive()
    {
        await using var f = await Fixture.CreateAsync();
        using var receive = f.Source().OpenWorkingGroupScope();
        var original = await receive.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var before = f.ProofRequests;
        using var ack = receive.Source.OpenIndependentCommandReadScope();
        var fresh = await ack.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        Assert.NotSame(original, fresh);
        Assert.Equal(before + 1, f.ProofRequests);
        Assert.Same(fresh, await ack.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(before + 1, f.ProofRequests);
        f.Sample = fresh.Proof.MonotonicSample - 1;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await ack.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(before + 1, f.ProofRequests);
        ack.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await ack.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
    }

    [Fact]
    public async Task Did2MailboxReceive_ReadScopeDoesNotReuseItsProofForIndependentParentAckCapture()
    {
        await using var f = await Fixture.CreateAsync(); var parent = f.Source();
        var retrieve = await parent.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        using var reads = parent.OpenCommandReadScope();
        var receive = await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var count = f.ProofRequests;
        Assert.NotSame(retrieve, receive);
        Assert.Same(receive, await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count, f.ProofRequests);
        var ack = await parent.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        Assert.NotSame(receive, ack); Assert.NotSame(retrieve, ack);
        Assert.Equal(count + 1, f.ProofRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Groups_ReadScopeEndpointAcquisitionNeverSplicesDifferentSignedViews(bool capturedOwn)
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await f.PrepareNativeHelloCompletion(Bytes(32, 0xb8));
        using var initial = await complete(f.Accounts); var scope = await f.EnsureSenderMessaging(init, hello);
        await f.CheckGroupEndpointViewAcquisition(scope, capturedOwn, groupReadScope: true);
    }

    [Fact]
    public async Task Did2Groups_ReadScopeReusesCapabilitiesOnlyInsideOneExplicitCommand()
    {
        await using var f = await Fixture.CreateAsync(); var parent = f.Source();
        using var reads = parent.OpenCommandReadScope(); var source = reads.Source;
        var first = await source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        var count = f.ProofRequests;
        Assert.Same(first, await source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        using (var nested = source.OpenCommandReadScope())
        {
            Assert.Same(source, nested.Source);
            Assert.Same(first, await nested.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        }
        Assert.Equal(count, f.ProofRequests);
        Assert.Equal(1L, source.MailboxInputDecodes);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, canceled.Token));
        reads.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count, f.ProofRequests);
        var next = await parent.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default);
        Assert.NotSame(first, next); Assert.Equal(count + 1, f.ProofRequests);
        using var other = parent.OpenCommandReadScope();
        Assert.NotSame(next, await other.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count + 2, f.ProofRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Did2Groups_ReadScopeRejectsChangedFloorAndClockRollbackWithoutReacquisition(bool clock)
    {
        await using var f = await Fixture.CreateAsync(); using var reads = f.Source().OpenCommandReadScope();
        var first = await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default); var count = f.ProofRequests;
        if (clock) f.Sample = first.Proof.MonotonicSample - 1;
        else
        {
            var floor = (await f.NetworkStore.ReadAsync(default))!;
            await f.NetworkStore.CompareExchangeAsync(floor.Revision, new(floor.Revision + 1, floor.ProtectedLkg, true), default);
        }
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count, f.ProofRequests);
        Assert.Null(await f.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    public async Task Did2Groups_ExpiredReadScopeCannotFallBackWhenFreshProofIsUnavailable()
    {
        await using var f = await Fixture.CreateAsync(); using var reads = f.Source().OpenCommandReadScope();
        var first = await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default); var count = f.ProofRequests;
        f.Sample = first.Proof.FreshnessDeadlineMonotonicSeconds; f.RejectProof = true;
        await Assert.ThrowsAnyAsync<IOException>(async () =>
            await reads.Source.VerifyForOwnPreKeyAuthoringAsync(f.Accounts, default));
        Assert.Equal(count + 1, f.ProofRequests);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reads.Source.RecheckOwnPreKeyAuthoringAsync(first, default));
        Assert.Null(await f.Accounts.ReadOwnStagedPreKeyPublicationAsync());
    }

    [Fact]
    [Trait("RequiresApprovedMlKemRuntime", "true")]
    public async Task Did2Groups_ReadScopeRechecksRealEndpointPairWithoutRepeatingProofFetches()
    {
        await using var f = await Fixture.CreateAsync(withPeer: true);
        var (complete, hello, init, _, _) = await f.PrepareNativeHelloCompletion(Bytes(32, 0xb7));
        using var initial = await complete(f.Accounts); var session = await f.EnsureSenderMessaging(init, hello);
        using var reads = f.Source().OpenCommandReadScope();
        var first = await reads.Source.VerifyForOwnMessagingAsync(f.Accounts, session, default); var count = f.ProofRequests;
        var again = await reads.Source.VerifyForOwnMessagingAsync(f.Accounts, session, default);
        Assert.Same(first.Own, again.Own); Assert.Same(first.Peer, again.Peer); Assert.Equal(count, f.ProofRequests);
        f.Sample = first.Own.Proof.MonotonicSample - 1;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await reads.Source.VerifyForOwnMessagingAsync(f.Accounts, session, default));
        Assert.Equal(count, f.ProofRequests);
    }
}
