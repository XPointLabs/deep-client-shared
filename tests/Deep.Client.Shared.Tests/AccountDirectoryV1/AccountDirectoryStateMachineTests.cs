using Deep.Client.Shared.Domain.AccountDirectoryV1;
using Deep.Client.Shared.Services.AccountDirectoryV1;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Client.Shared.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryStateMachineTests
{
    [Fact]
    public void VerifiedCapability_IsTheOnlyPublicPromotionInput_AndNoRawVerifierExistsInShared()
    {
        var method = Assert.Single(typeof(AccountDirectoryClient).GetMethods(), method => method.Name == "ApplyVerifiedAsync");
        Assert.Equal(typeof(VerifiedAccountDirectoryFreshness), method.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(typeof(AccountDirectoryClient).Assembly.GetTypes(), type =>
            type.Name.Contains("Verifier", StringComparison.Ordinal) && type.Namespace?.Contains("AccountDirectoryV1", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task RestartPath_RequiresVerifiedAuthorityAndHasNoCallerSuppliedLkgFallback()
    {
        var client = new AccountDirectoryClient(
            new Deep.Client.Shared.Persistence.AccountDirectoryV1.InMemoryAccountDirectoryStateStore());
        var error = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.RestoreProtectedLkgAsync(null!, CancellationToken.None));
        Assert.Equal("authority", error.ParamName);
        var method = Assert.Single(typeof(AccountDirectoryClient).GetMethods(),
            candidate => candidate.Name == "RestoreVerifyAndApplyAsync");
        Assert.DoesNotContain(method.GetParameters(), parameter =>
            parameter.ParameterType == typeof(AccountDirectoryProtectedLkg));
    }

    [Fact]
    public void InitialAndSuccessorProofs_MustBindExactProtectedLkg()
    {
        var firstLkg = AccountDirectoryV1Fixture.Lkg();
        var first = AccountDirectoryStateMachine.ApplyVerified(null, AccountDirectoryV1Fixture.Update(firstLkg));
        Assert.False(first.ForkLatched); Assert.Equal(AccountDirectoryClientState.Current, Assert.Single(first.Subjects).State);

        var successor = AccountDirectoryV1Fixture.Lkg(2, 2, 0x62);
        var second = AccountDirectoryStateMachine.ApplyVerified(first,
            AccountDirectoryV1Fixture.Update(successor, AccountDirectoryV1Fixture.Subject(directoryGeneration: 2), firstLkg));
        Assert.False(second.ForkLatched); Assert.Equal(2UL, second.ProtectedLkg!.LogGeneration);

        var wrongCaller = AccountDirectoryV1Fixture.Lkg(1, 1, 0x6F);
        var refresh = AccountDirectoryStateMachine.ApplyVerified(second,
            AccountDirectoryV1Fixture.Update(AccountDirectoryV1Fixture.Lkg(3, 3, 0x63), caller: wrongCaller));
        Assert.False(refresh.ForkLatched);
        Assert.All(refresh.Subjects, subject => Assert.Equal(AccountDirectoryClientState.RevocationRefreshRequired, subject.State));
    }

    [Fact]
    public void SameGenerationChange_Rollback_AndRetryAfterForkRemainBlocked()
    {
        var lkg = AccountDirectoryV1Fixture.Lkg();
        var current = AccountDirectoryV1Fixture.Snapshot(lkg: lkg);
        var changed = AccountDirectoryV1Fixture.Lkg(1, 1, 0x66);
        var fork = AccountDirectoryStateMachine.ApplyVerified(current,
            AccountDirectoryV1Fixture.Update(changed, caller: lkg));
        Assert.True(fork.ForkLatched);

        var retry = AccountDirectoryStateMachine.ApplyVerified(fork,
            AccountDirectoryV1Fixture.Update(lkg, caller: lkg));
        Assert.True(retry.ForkLatched);
        Assert.Same(fork, retry);
        Assert.Equal(AccountDirectoryClientState.DirectoryForkBlocked, Assert.Single(retry.Subjects).State);
    }

    [Fact]
    public void RevokedAuthorization_IsTerminalUnderOrdinaryFreshProof()
    {
        var lkg = AccountDirectoryV1Fixture.Lkg();
        var revoked = AccountDirectoryV1Fixture.Subject(AccountDirectoryClientState.RevokedAuthorization);
        var current = AccountDirectoryV1Fixture.Snapshot(lkg: lkg, subjects: revoked);
        var successor = AccountDirectoryV1Fixture.Lkg(2, 2, 0x62);
        var result = AccountDirectoryStateMachine.ApplyVerified(current,
            AccountDirectoryV1Fixture.Update(successor, AccountDirectoryV1Fixture.Subject(directoryGeneration: 2), lkg));
        Assert.Equal(AccountDirectoryClientState.RevokedAuthorization, Assert.Single(result.Subjects).State);
    }

    [Theory]
    [InlineData(199, true)]
    [InlineData(200, false)]
    [InlineData(201, false)]
    public void MutationFence_UsesExclusiveDeadline(ulong sample, bool allowed)
    {
        var state = AccountDirectoryV1Fixture.Snapshot();
        if (allowed)
            AccountDirectoryMutationFence.EnsureAllowed(state, AccountDirectoryV1Fixture.Leaf(),
                AccountDirectoryMutationKind.EmitOutboundEnvelope, AccountDirectoryV1Fixture.Bytes(16, 0x21), sample);
        else
            Assert.Equal(AccountDirectoryClientState.RevocationRefreshRequired,
                Assert.Throws<AccountDirectoryMutationDeniedException>(() => AccountDirectoryMutationFence.EnsureAllowed(
                    state, AccountDirectoryV1Fixture.Leaf(), AccountDirectoryMutationKind.EmitOutboundEnvelope,
                    AccountDirectoryV1Fixture.Bytes(16, 0x21), sample)).State);
    }

    [Fact]
    public void Fence_AllowsOnlySpecifiedLocalOperationsOutsideCurrent()
    {
        var refresh = AccountDirectoryV1Fixture.Snapshot(subjects: AccountDirectoryV1Fixture.Subject(
            AccountDirectoryClientState.RevocationRefreshRequired, AccountDirectoryRefreshReason.ProofUnavailable));
        foreach (var mutation in new[] { AccountDirectoryMutationKind.ReadLocalHistory,
            AccountDirectoryMutationKind.SaveLocalDraft, AccountDirectoryMutationKind.RetainCiphertextWithoutAcknowledgement })
            AccountDirectoryMutationFence.EnsureAllowed(refresh, AccountDirectoryV1Fixture.Leaf(), mutation, [], 0);
        Assert.Throws<AccountDirectoryMutationDeniedException>(() => AccountDirectoryMutationFence.EnsureAllowed(
            refresh, AccountDirectoryV1Fixture.Leaf(), AccountDirectoryMutationKind.EmitRemoteStateReceipt,
            AccountDirectoryV1Fixture.Bytes(16, 0x21), 150));
    }

    [Fact]
    public void Fence_FailsClosedAfterBootChange()
    {
        var state = AccountDirectoryV1Fixture.Snapshot();
        var denied = Assert.Throws<AccountDirectoryMutationDeniedException>(() =>
            AccountDirectoryMutationFence.EnsureAllowed(state, AccountDirectoryV1Fixture.Leaf(),
                AccountDirectoryMutationKind.EstablishPreKeyOrRatchet,
                AccountDirectoryV1Fixture.Bytes(16, 0x22), 150));
        Assert.Equal(AccountDirectoryClientState.RevocationRefreshRequired, denied.State);
    }
}
